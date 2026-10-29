"""골든셋 v1 교차 판정(#10) - 표본 36쌍 오류율(sample)과 50문항 이상 골든셋 생성(build).

판정자 A(claude-opus-5-5), B(gpt-6.1-sol)가 같은 지시문과 같은 입력을 격리된 새 컨텍스트에서 따로 받는다.
KISA 본문은 --kisa-root(KISA 캐시가 있는 체크아웃 루트)에서 fetch_kisa.load_cached_body로만 읽는다. 본문·인용은
출력 파일, 호출 캐시, 로그에 남기지 않는다(인용은 메모리에서 오프셋으로 바꾼 뒤 버린다).

    uv run python scripts/judge_golden.py sample --kisa-root <KISA 캐시가 있는 체크아웃>
    uv run python scripts/judge_golden.py build  --kisa-root <KISA 캐시가 있는 체크아웃>

호출 결과는 data/judge_cache(gitignore)에 저장해 중단 뒤 같은 명령으로 재개한다. 호출 수 상한: 판정 묶음당
판정자별 1회 + 재질의 1회, 질문 생성은 필요한 비CVE 질문 수의 2배 이하, no_answer 시도 20회 이하.
"""

import argparse
import importlib.util
import json
import re
import sys
import threading
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from krsec_rag_lab import golden, judge
from krsec_rag_lab.splits import extract_cve_ids

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = "cross-judge-v1"
STATUS = "cross_judged_not_human_verified"
MIN_VALID_SAMPLE_PAIRS = 30
PER_TYPE_TARGET = 12  # 비CVE 유형마다 만들 질문 수(최소 10 + 여유 2)
CVE_TARGET = 20  # cve_explicit 첫 묶음 크기(최소 15 + 여유 5). 채점 대상 50문항에 모자라면 CVE_MAX까지 늘린다
CVE_MAX = 30
PER_TYPE_MIN = golden.V1_MIN_PER_TYPE
NO_ANSWER_TARGET = 10
NO_ANSWER_ATTEMPT_CAP = 20
NO_ANSWER_DOCS = 5
NON_CVE_TYPES = ("product_symptom", "explanation_comparison")
NO_ANSWER_REASON = "코퍼스 공지 본문과 제목 전체에서 이 CVE ID가 기계적으로 검출되지 않는다(확인한 코퍼스 sha256은 judge_manifest.json)"

STATE_DIR_NAME = "state"
CACHE_DIR = Path("data") / "judge_cache"


# ---------------------------------------------------------------- 입력


def load_kisa_module():
    """scripts/fetch_kisa.py를 모듈로 읽는다(실행하지 않는다: load_cached_body만 쓴다). 한 번만 읽는다."""
    if "fetch_kisa" in sys.modules:
        return sys.modules["fetch_kisa"]
    spec = importlib.util.spec_from_file_location("fetch_kisa", ROOT / "scripts" / "fetch_kisa.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def kisa_body_loader(kisa_root: Path, doc_versions: Mapping[str, str]) -> Callable[[str], str]:
    """--kisa-root 아래 data/kisa에서 정규화 본문을 읽는다(해시가 manifest와 다르면 KisaError)."""
    kisa = load_kisa_module()

    def load(ntt_id: str) -> str:
        return kisa.load_cached_body(kisa_root, ntt_id, {"sha256": doc_versions[ntt_id]})

    return load


@dataclass
class Context:
    """한 번의 실행에 필요한 것. judges는 {"A": Judge, "B": Judge}."""

    root: Path
    load_body: Callable[[str], str]
    judges: Mapping[str, judge.Judge]
    cache: judge.CallCache
    state_dir: Path
    jobs: int = 4
    seed: int = golden.SEED
    notices: list[dict] = field(default_factory=list)
    doc_versions: dict[str, str] = field(default_factory=dict)
    parser_version: str = ""
    _bodies: dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self):
        self.notices = golden.load_notices(self.root / golden.KISA_METADATA)
        self.parser_version, self.doc_versions = golden.load_doc_versions(
            self.root / golden.KISA_MANIFEST
        )
        self.by_id = {str(n["nttId"]): n for n in self.notices}
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def body(self, ntt_id: str) -> str:
        with self._lock:
            if ntt_id not in self._bodies:
                self._bodies[ntt_id] = self.load_body(ntt_id)
            return self._bodies[ntt_id]

    def notice_text(self, ntt_id: str, cve_id: str | None) -> judge.NoticeText:
        meta = self.by_id[ntt_id]
        return judge.prepare_notice(ntt_id, meta["title"], meta["date"], self.body(ntt_id), cve_id)


def run_parallel(fn: Callable, items: Sequence, jobs: int) -> list:
    """items를 jobs개씩 병렬로 처리한다. 하나라도 실패하면 대기 중인 항목을 취소하고 첫 예외를 던진다."""
    if jobs <= 1 or len(items) <= 1:
        return [fn(item) for item in items]
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(fn, item) for item in items]
        results = []
        failure: BaseException | None = None
        for future in futures:
            try:
                results.append(future.result())
            except BaseException as exc:  # noqa: BLE001 - 첫 예외를 모아서 다시 던진다
                if failure is None:
                    failure = exc
                    for pending in futures:
                        pending.cancel()
        if failure is not None:
            raise failure
        return results


# ---------------------------------------------------------------- 교차 판정 실행


@dataclass(frozen=True)
class Bundle:
    """판정 묶음: 질문 1개와 공지 1~8건."""

    question_id: str
    query: str
    doc_ids: tuple[str, ...]
    task: str
    cve_id: str | None = None


def judge_bundles(ctx: Context, bundles: Sequence[Bundle]) -> dict[str, dict]:
    """묶음마다 두 판정자에게 같은 입력을 보낸다. 반환: question_id -> {"A": {doc: Judgment}, "B": ...}."""

    def work(item: tuple[Bundle, str]) -> tuple[str, str, dict]:
        bundle, name = item
        notices = [ctx.notice_text(d, bundle.cve_id) for d in bundle.doc_ids]
        result = judge.judge_bundle(
            ctx.judges[name],
            ctx.cache,
            question_id=bundle.question_id,
            question=bundle.query,
            notices=notices,
            task=bundle.task,
        )
        return bundle.question_id, name, result

    jobs = [(b, name) for b in bundles for name in judge.JUDGE_NAMES]
    results: dict[str, dict] = defaultdict(dict)
    for qid, name, judgments in run_parallel(work, jobs, ctx.jobs):
        results[qid][name] = judgments
    return results


def resolve_bundle(bundle: Bundle, judged: Mapping[str, Mapping]) -> list[judge.Resolution]:
    return [
        judge.resolve_pair(judged["A"][doc_id], judged["B"][doc_id]) for doc_id in bundle.doc_ids
    ]


def rows_of(judged: Mapping[str, Mapping[str, Mapping]]) -> dict[str, list[dict]]:
    rows: dict[str, list[dict]] = {name: [] for name in judge.JUDGE_NAMES}
    for per_judge in judged.values():
        for name in judge.JUDGE_NAMES:
            rows[name].extend(j.row() for j in per_judge[name].values())
    for name_rows in rows.values():
        name_rows.sort(key=lambda r: (r["question_id"], r["doc_id"]))
    return rows


def read_jsonl(path: Path) -> list[dict]:
    return golden._read_jsonl(path)


def write_state(ctx: Context, name: str, state: Mapping) -> None:
    path = ctx.state_dir / f"{name}.json"
    path.write_text(json.dumps(state, ensure_ascii=False, sort_keys=True), encoding="utf-8")


def limit_events_path(ctx: Context) -> Path:
    return ctx.state_dir / "limit_events.json"


def read_limit_events(ctx: Context) -> list[dict]:
    path = limit_events_path(ctx)
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else []


def record_limit_stop(ctx: Context, message: str) -> None:
    """사용량 한도로 멈춘 시각과 메시지의 재시도 시각(있으면)을 남긴다. 메시지 나머지는 버린다."""
    hint = re.search(r"try again at ([0-9:]+ ?[AP]M)", message)
    events = read_limit_events(ctx)
    events.append(
        {
            "stopped_at": judge._now(),
            "retry_hint": hint.group(1) if hint else None,
            "resumed_at": None,
        }
    )
    limit_events_path(ctx).write_text(json.dumps(events), encoding="utf-8")


def record_resume(ctx: Context) -> None:
    events = read_limit_events(ctx)
    if events and events[-1]["resumed_at"] is None:
        events[-1]["resumed_at"] = judge._now()
        limit_events_path(ctx).write_text(json.dumps(events), encoding="utf-8")


def read_state(ctx: Context, name: str) -> dict | None:
    path = ctx.state_dir / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


# ---------------------------------------------------------------- sample: 자동 라벨 오류율


def run_sample(ctx: Context) -> dict:
    """#27 표본 쌍을 판정해 오라벨률·누락률·kappa를 계산한다."""
    pairs = read_jsonl(ctx.root / golden.PAIRS_FILE)
    candidate_manifest = json.loads((ctx.root / golden.MANIFEST_FILE).read_text(encoding="utf-8"))
    by_question: dict[str, list[dict]] = defaultdict(list)
    for pair in pairs:
        by_question[pair["candidate_question_id"]].append(pair)
    bundles = [
        Bundle(
            qid,
            group[0]["candidate_query"],
            tuple(p["doc_id"] for p in group),
            "error_rate_sample",
            group[0]["cve_ids"][0],
        )
        for qid, group in by_question.items()
    ]
    judged = judge_bundles(ctx, bundles)
    resolutions = [r for b in bundles for r in resolve_bundle(b, judged[b.question_id])]
    in_candidate = {(p["candidate_question_id"], p["doc_id"]): p["in_candidate_set"] for p in pairs}
    summary = judge.summarize(resolutions)
    rates = judge.error_rate(resolutions, in_candidate)
    strata = [
        {"stratum": s["stratum"], "selected": s["selected"], "zero_reason": s["zero_reason"]}
        for s in candidate_manifest["sampling"]["strata"]
    ]
    state = {
        "rows": rows_of(judged),
        "summary": summary,
        "rates": rates,
        "strata": strata,
        "seed": candidate_manifest["seed"],
    }
    write_state(ctx, "sample", state)
    return state


def error_rates_output(state: Mapping) -> dict:
    summary = state["summary"]
    return {
        "protocol": PROTOCOL,
        "status": STATUS,
        "unit": "question-document pair",
        "definition": {
            "mislabel": "후보 집합 안 쌍 중 두 판정자가 모두 not_relevant로 일치한 비율(오라벨률)",
            "omission": "후보 집합 밖 점검 표본 쌍 중 두 판정자가 모두 relevant로 일치한 비율(누락률)",
            "denominator": "unjudged(갈림, 근거 없음, 잘린 본문의 not_relevant, 무효 응답)를 뺀 일치 쌍",
        },
        "sample": {
            "seed": state["seed"],
            "pairs_file": golden.PAIRS_FILE,
            "strata": state["strata"],
        },
        "counts": {
            "attempted_pairs": summary["n_pairs"],
            "valid_pairs": summary["n_valid_pairs"],
            "agree_pairs": summary["n_agree"],
            "disagree_pairs": summary["n_disagree"],
            "gold_pairs": summary["n_gold"],
            "not_relevant_pairs": summary["n_not_relevant"],
            "unjudged_pairs": summary["n_unjudged"],
            "unjudged_reasons": summary["unjudged_reasons"],
        },
        "mislabel": state["rates"]["mislabel"],
        "omission": state["rates"]["omission"],
        "kappa": summary["kappa"],
        "min_valid_pairs": MIN_VALID_SAMPLE_PAIRS,
        "meets_min_valid_pairs": summary["n_valid_pairs"] >= MIN_VALID_SAMPLE_PAIRS,
        "limitations": [
            "정답 판정이 사람이 아니라 두 모델(Opus, GPT)의 교차 판정이다. 두 모델이 같은 방향으로 틀린 쌍은 일치로 센다",
            "누락률은 후보 밖 점검 표본(같은 제품명 제목 공지)에서 잰 값이라 코퍼스 전체의 누락률이 아니다",
            "층 (a)는 표본이 0건이다(사유는 sample.strata의 zero_reason)",
        ],
    }


def sample_failures(state: Mapping) -> list[str]:
    errors = []
    if state["summary"]["n_valid_pairs"] < MIN_VALID_SAMPLE_PAIRS:
        errors.append(f"valid pairs {state['summary']['n_valid_pairs']} < {MIN_VALID_SAMPLE_PAIRS}")
    for name in ("mislabel", "omission"):
        if not state["rates"][name]["denominator"]:
            errors.append(f"{name} denominator is 0")
    return errors


# ---------------------------------------------------------------- build: 골든셋 레코드


def make_record(
    ctx: Context,
    *,
    question_id: str,
    query: str,
    query_type: str,
    cve_ids: Sequence[str],
    resolutions: Sequence[judge.Resolution],
) -> dict:
    """교차 판정 결과 -> 골든셋 레코드. gold가 answers, 판정 불가 문서가 unjudged, answers가 비면 excluded."""
    answers = []
    for r in resolutions:
        if r.outcome != judge.GOLD:
            continue
        evidence = [
            {"parser_version": ctx.parser_version, "start": s, "end": e, "judge": name}
            for name, j in (("A", r.a), ("B", r.b))
            for s, e in j.evidence
        ]
        answers.append(
            {
                "doc_id": r.doc_id,
                "doc_sha256": ctx.doc_versions[r.doc_id],
                "evidence": evidence,
                "reason": f"A:{r.a.reason_code} B:{r.b.reason_code}",
            }
        )
    return {
        "question_id": question_id,
        "query": query,
        "query_type": query_type,
        "cve_ids": list(cve_ids),
        "surface_cve": bool(extract_cve_ids(query)),
        "answers": answers,
        "unjudged": [r.doc_id for r in resolutions if r.outcome == judge.UNJUDGED],
        "excluded": not answers,
    }


def cve_question_order(questions: Sequence[Mapping], seed: int) -> list[Mapping]:
    """cve_explicit 후보 질문의 추출 순서: #27과 같은 공지별 균형 추출(golden.sample_balanced), seed 고정."""
    by_id = {q["candidate_question_id"]: q for q in questions}
    pairs = [
        {"candidate_pair_id": f"{qid}__{ntt}", "doc_id": ntt, "question_id": qid}
        for qid, q in by_id.items()
        for ntt in q["candidate_ntt_ids"]
    ]
    order: dict[str, None] = {}
    for pair in golden.sample_balanced(pairs, len(pairs), seed):
        order.setdefault(pair["question_id"], None)
    return [by_id[qid] for qid in order]


def run_cve_explicit(
    ctx: Context, count: int, cap: int, other_scored: int
) -> tuple[list[dict], list[Bundle], dict]:
    """cve_explicit 질문을 count개 판정하고, 채점 대상이 모자라면(유형 최소 또는 전체 50문항) cap까지 늘린다."""
    questions = read_jsonl(ctx.root / golden.QUESTIONS_FILE)
    order = cve_question_order(questions, ctx.seed)
    records: list[dict] = []
    bundles: list[Bundle] = []
    judged: dict[str, dict] = {}
    next_index = 0
    want = count
    while want > 0 and next_index < min(cap, len(order)):
        batch = order[next_index : min(next_index + want, cap)]
        next_index += len(batch)
        batch_bundles = [
            Bundle(
                f"g1-{q['candidate_question_id'].removeprefix('cq-')}",
                q["candidate_query"],
                tuple(q["candidate_ntt_ids"][: judge.MAX_BUNDLE]),
                "cve_explicit",
                q["cve_ids"][0],
            )
            for q in batch
        ]
        batch_judged = judge_bundles(ctx, batch_bundles)
        judged.update(batch_judged)
        for bundle, q in zip(batch_bundles, batch, strict=True):
            records.append(
                make_record(
                    ctx,
                    question_id=bundle.question_id,
                    query=bundle.query,
                    query_type="cve_explicit",
                    cve_ids=q["cve_ids"],
                    resolutions=resolve_bundle(bundle, batch_judged[bundle.question_id]),
                )
            )
        bundles.extend(batch_bundles)
        scored = sum(1 for r in records if not r["excluded"])
        want = max(PER_TYPE_MIN["cve_explicit"], golden.V1_MIN_SCORED - other_scored) - scored
    return records, bundles, judged


# ---- 비CVE 질문(product_symptom, explanation_comparison)


def source_order(ctx: Context, query_type: str, used: set[str]) -> list[str]:
    """질문을 만들 출처 공지 순서(seed 고정). product_symptom은 제품명 제목 공지만, 이미 쓴 공지는 뺀다."""
    ids = [d for d in ctx.by_id if d not in used]
    if query_type == "product_symptom":
        ids = [d for d in ids if golden.product_of(ctx.by_id[d]["title"])]
    return sorted(ids, key=lambda d: golden._rank(ctx.seed, f"{query_type}:{d}"))


def non_cve_bundle_docs(ctx: Context, source: str) -> tuple[str, ...]:
    """후보 묶음 = 출처 공지 + 같은 제품명 제목 공지 + 출처와 CVE를 공유하는 조인 후보(최대 8건)."""
    product = golden.product_of(ctx.by_id[source]["title"])
    same_product = sorted(
        (
            d
            for d, n in ctx.by_id.items()
            if d != source and product and golden.product_of(n["title"]) == product
        ),
        key=golden._ntt_key,
        reverse=True,
    )
    joined = golden.join_cve_to_notices(ctx.notices)
    shared: list[str] = []
    for cve_id in ctx.by_id[source]["cve_ids"]:
        shared.extend(d for d in joined.get(cve_id.upper(), ()) if d != source)
    ordered: dict[str, None] = {source: None}
    for doc_id in [*same_product, *sorted(set(shared), key=golden._ntt_key)]:
        ordered.setdefault(doc_id, None)
    return tuple(list(ordered)[: judge.MAX_BUNDLE])


def generate_question(ctx: Context, query_type: str, source: str) -> dict:
    """판정과 다른 별도 호출(판정자 A 모델, 새 컨텍스트)로 출처 공지 하나를 읽고 질문을 만든다."""
    notice = ctx.notice_text(source, None)
    body = ctx.body(source)
    payload = json.dumps(
        {
            "type": query_type,
            "notice": {"title": notice.title, "date": notice.date, "text": notice.text},
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )

    def interpret(raw: str) -> dict:
        query = judge.clean_question(raw)
        if query is None:
            return {"status": "rejected", "reason": "bad_format"}
        reason = judge.check_question(query, body)
        if reason:
            return {"status": "rejected", "reason": reason}  # 거부한 질문은 저장하지 않는다
        return {"status": "ok", "query": query}

    return judge.cached_call(
        ctx.cache,
        ctx.judges["A"],
        kind="question_generation",
        task=f"generate:{query_type}",
        instruction=judge.QUESTION_INSTRUCTION,
        payload=payload,
        schema=judge.QUESTION_SCHEMA,
        interpret=interpret,
    )


def run_non_cve(
    ctx: Context, per_type: int
) -> tuple[list[dict], list[Bundle], dict, list[dict], dict]:
    needed = per_type * len(NON_CVE_TYPES)
    budget = judge.CallBudget(cap=2 * needed)
    records: list[dict] = []
    bundles: list[Bundle] = []
    judged: dict[str, dict] = {}
    provenance: list[dict] = []
    stats = {"generated": 0, "rejected": 0, "cap": budget.cap}
    used: set[str] = set()
    serial = {t: 0 for t in NON_CVE_TYPES}
    prefix = {"product_symptom": "ps", "explanation_comparison": "ec"}
    for query_type in NON_CVE_TYPES:
        accepted = 0
        scored = 0
        while True:
            target = (
                per_type - accepted if accepted < per_type else PER_TYPE_MIN[query_type] - scored
            )
            if target <= 0:
                break
            sources = []
            for source in source_order(ctx, query_type, used):
                if len(sources) >= target:
                    break
                if budget.take():
                    sources.append(source)
            if not sources:
                break
            used.update(sources)
            made = run_parallel(
                lambda s, t=query_type: (s, generate_question(ctx, t, s)), sources, ctx.jobs
            )
            stats["generated"] += len(made)
            batch: list[Bundle] = []
            for source, result in made:
                if result["status"] != "ok":
                    stats["rejected"] += 1
                    continue
                serial[query_type] += 1
                qid = f"g1-{prefix[query_type]}-{serial[query_type]:02d}"
                batch.append(
                    Bundle(qid, result["query"], non_cve_bundle_docs(ctx, source), query_type)
                )
                provenance.append(
                    {"question_id": qid, "query_type": query_type, "source_doc_id": source}
                )
            accepted += len(batch)
            batch_judged = judge_bundles(ctx, batch)
            judged.update(batch_judged)
            for bundle in batch:
                record = make_record(
                    ctx,
                    question_id=bundle.question_id,
                    query=bundle.query,
                    query_type=query_type,
                    cve_ids=[],
                    resolutions=resolve_bundle(bundle, batch_judged[bundle.question_id]),
                )
                records.append(record)
            bundles.extend(batch)
            scored = sum(1 for r in records if r["query_type"] == query_type and not r["excluded"])
    stats["generation_calls_used"] = budget.used
    return records, bundles, judged, provenance, stats


# ---- no_answer


def corpus_cve_ids(ctx: Context) -> tuple[set[str], str]:
    """고정 코퍼스(공지 전부)의 정규화 본문 전체와 제목에서 splits.extract_cve_ids로 뽑은 집합과 코퍼스 sha256."""
    found: set[str] = set()
    for ntt_id, meta in ctx.by_id.items():
        found.update(extract_cve_ids(ctx.body(ntt_id)))
        found.update(extract_cve_ids(meta["title"]))
    digest = judge.text_sha256(
        "\n".join(
            f"{ntt}:{ctx.doc_versions[ntt]}" for ntt in sorted(ctx.by_id, key=golden._ntt_key)
        )
    )
    return found, digest


def run_no_answer(
    ctx: Context, corpus_cves: set[str]
) -> tuple[list[dict], list[Bundle], dict, dict]:
    """코퍼스에 없는 CVE ID를 묻는 질문. 5건 묶음을 A·B 둘 다 not_relevant로 판정할 때만 채택한다."""
    nvd_ids = golden.load_nvd_ids(ctx.root / golden.NVD_CVES)
    candidates = judge.absent_cve_candidates(ctx.seed, corpus_cves | nvd_ids)
    doc_pool = sorted(ctx.by_id, key=golden._ntt_key)
    records: list[dict] = []
    bundles: list[Bundle] = []
    judged: dict[str, dict] = {}
    attempts = 0
    while len(records) < NO_ANSWER_TARGET and attempts < NO_ANSWER_ATTEMPT_CAP:
        batch_size = min(NO_ANSWER_TARGET - len(records), NO_ANSWER_ATTEMPT_CAP - attempts)
        batch = []
        for _ in range(batch_size):
            cve_id = next(candidates)
            docs = sorted(doc_pool, key=lambda d: golden._rank(ctx.seed, f"no-answer:{cve_id}:{d}"))
            batch.append(
                Bundle(
                    f"g1-na-{cve_id.lower()}",
                    golden.question_text(cve_id),
                    tuple(docs[:NO_ANSWER_DOCS]),
                    "no_answer",
                    cve_id,
                )
            )
        attempts += len(batch)
        batch_judged = judge_bundles(ctx, batch)
        judged.update(batch_judged)
        bundles.extend(batch)
        for bundle in batch:
            resolutions = resolve_bundle(bundle, batch_judged[bundle.question_id])
            # 부재는 코퍼스 전체 검색으로 이미 확인했다. 판정은 둘 다 유효한 not_relevant일 때만 채택한다
            if all(
                r.valid and r.a.label() == r.b.label() == judge.NOT_RELEVANT for r in resolutions
            ):
                records.append(
                    {
                        "question_id": bundle.question_id,
                        "query": bundle.query,
                        "query_type": "no_answer",
                        "cve_ids": [bundle.cve_id],
                        "surface_cve": True,
                        "answers": [],
                        "unjudged": [],
                        "excluded": False,
                        "no_answer_reason": NO_ANSWER_REASON,
                    }
                )
    return records, bundles, judged, {"attempts": attempts, "accepted": len(records)}


# ---- build 본체


def run_build(
    ctx: Context, *, cve_count: int = CVE_TARGET, per_type: int = PER_TYPE_TARGET
) -> dict:
    non_records, non_bundles, non_judged, provenance, gen_stats = run_non_cve(ctx, per_type)
    corpus_cves, corpus_digest = corpus_cve_ids(ctx)
    na_records, na_bundles, na_judged, na_stats = run_no_answer(ctx, corpus_cves)
    other_scored = sum(1 for r in [*non_records, *na_records] if not r["excluded"])
    cve_records, cve_bundles, cve_judged = run_cve_explicit(ctx, cve_count, CVE_MAX, other_scored)

    judged = {**cve_judged, **non_judged, **na_judged}
    bundles = [*cve_bundles, *non_bundles, *na_bundles]
    order = {t: i for i, t in enumerate(golden.QUERY_TYPES)}
    records = sorted(
        [*cve_records, *non_records, *na_records],
        key=lambda r: (order[r["query_type"]], r["question_id"]),
    )
    sides = judge.assign_splits(records, ctx.notices, seed=ctx.seed)
    for record in records:
        record["split"] = sides[record["question_id"]]

    tasks = []
    for query_type in golden.QUERY_TYPES:
        resolutions = [
            r
            for b in bundles
            if b.task == query_type
            for r in resolve_bundle(b, judged[b.question_id])
        ]
        tasks.append({"task": query_type, **judge.summarize(resolutions)})
    scored = [r for r in records if not r["excluded"]]
    state = {
        "records": records,
        "rows": rows_of(judged),
        "tasks": tasks,
        "provenance": provenance,
        "generation": gen_stats,
        "no_answer": {
            **na_stats,
            "corpus_sha256": corpus_digest,
            "n_cve_ids_in_corpus": len(corpus_cves),
        },
        "counts": {
            "records": len(records),
            "scored": len(scored),
            "excluded": len(records) - len(scored),
            "by_type": [
                {"query_type": t, "n": sum(1 for r in scored if r["query_type"] == t)}
                for t in golden.QUERY_TYPES
            ],
        },
        "split": {
            "n_dev": sum(1 for r in scored if r["split"] == "dev"),
            "n_test": sum(1 for r in scored if r["split"] == "test"),
        },
    }
    write_state(ctx, "build", state)
    return state


def build_failures(ctx: Context, records: Sequence[Mapping]) -> list[str]:
    errors = golden.validate_golden(
        records,
        notices=ctx.notices,
        doc_versions=ctx.doc_versions,
        parser_version=ctx.parser_version,
    )
    return [*errors, *golden.check_golden_v1(records)]


# ---------------------------------------------------------------- 출력


def jsonl_text(rows: Sequence[Mapping]) -> str:
    return "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for row in rows
    )


def json_text(value: Mapping) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def agreement_output(sample: Mapping | None, build: Mapping | None) -> dict:
    tasks = []
    if sample:
        tasks.append({"task": "error_rate_sample", **sample["summary"]})
    if build:
        tasks.extend(build["tasks"])
    return {
        "protocol": PROTOCOL,
        "rule": (
            "일치 단위는 관련성 라벨. 둘 다 relevant(근거 있음)면 gold, 둘 다 not_relevant면 비관련, "
            "갈림·no_evidence·무효 응답·잘린 본문의 not_relevant는 unjudged"
        ),
        "kappa_basis": "과제별로 A·B 모두 유효한 이진 라벨을 낸 쌍 전체(unjudged 필터 전). 정의 불가면 value null과 사유",
        "tasks": tasks,
    }


def manifest_output(ctx: Context, sample: Mapping | None, build: Mapping | None) -> dict:
    calls = judge.count_calls(ctx.cache)
    events = read_limit_events(ctx)
    n_generation = sum(c["n"] for c in calls["by_kind"] if c["kind"] == "question_generation")
    inputs = [
        golden.KISA_METADATA,
        golden.KISA_MANIFEST,
        golden.NVD_CVES,
        golden.QUESTIONS_FILE,
        golden.PAIRS_FILE,
        golden.MANIFEST_FILE,
    ]
    manifest = {
        "protocol": PROTOCOL,
        "status": STATUS,
        "seed": ctx.seed,
        "judges": [ctx.judges[name].describe() for name in judge.JUDGE_NAMES],
        "isolation": {
            "cwd": "호출마다 빈 임시 디렉터리",
            "input": "stdin으로만 질문·공지 묶음을 전달. 지시문은 인자",
            "other_judge_output": "판정자 입력에 다른 판정자의 출력을 넣지 않는다",
            "flags_checked_with": "claude --help, codex exec --help (2026-10-29 실행 시점)",
        },
        "prompts": {
            "judge_sha256": judge.JUDGE_PROMPT_SHA256,
            "question_generation_sha256": judge.QUESTION_PROMPT_SHA256,
            "answer_schema_sha256": judge.schema_sha256(judge.ANSWER_SCHEMA),
            "question_schema_sha256": judge.schema_sha256(judge.QUESTION_SCHEMA),
        },
        "reason_codes": [
            {"code": code, "relevance": relevance, "meaning": meaning}
            for relevance, code, meaning in judge.REASON_CODES
        ],
        "bundle": {
            "max_notices": judge.MAX_BUNDLE,
            "max_chars_per_notice": judge.MAX_NOTICE_CHARS,
            "cve_window_chars": judge.CVE_WINDOW_CHARS,
            "max_retries": judge.MAX_RETRIES,
            "retry_rule": (
                "relevant인데 인용을 정규화 본문에서 못 찾았거나 응답이 무효인 공지가 있으면 그 묶음을 판정자별 "
                "최대 1회 다시 묻는다. 그래도 못 찾으면 그 판정자의 그 공지 판정은 no_evidence"
            ),
        },
        "judged_at": {"first": calls["first_at"], "last": calls["last_at"]},
        "usage_limit": {
            "stops": len(events),
            "events": events,
        },
        "inputs": [{"path": rel, "sha256": golden.file_sha256(ctx.root / rel)} for rel in inputs],
        "calls": {
            "total": calls["total"],
            "by_kind": calls["by_kind"],
            "by_task": calls["by_task"],
            "question_generation": n_generation,
            "no_answer_attempts": build["no_answer"]["attempts"] if build else 0,
            "caps": {
                "question_generation": build["generation"]["cap"] if build else None,
                "no_answer_attempts": NO_ANSWER_ATTEMPT_CAP,
            },
        },
        "limitations": [
            "정답은 사람 검수가 아니라 두 모델의 독립 교차 판정이다. 두 모델이 같은 방향으로 틀린 판정은 걸러지지 않는다",
            "product_symptom과 explanation_comparison 질문은 판정자 A와 같은 모델이 별도 호출로 쓴다. 같은 모델이 질문을 쓰고 판정하므로 A의 판정이 질문 의도와 맞아떨어지기 쉽다",
            "판정 묶음 밖의 공지는 비관련으로 간주한다(풀링 평가). 묶음에 없던 관련 공지는 골든셋에서 누락된다",
            "공지당 20,000자 상한 때문에 일부만 보낸 공지의 not_relevant는 unjudged로 처리한다",
            "no_answer는 형식상 유효한 CVE ID가 고정 코퍼스 본문과 제목에 기계적으로 없음을 확인한 질문으로 한정한다",
            "판정자, 지시문, 입력이 모두 같은 호출은 다시 부르지 않고 저장된 결과를 쓴다. 그래서 sample 표본 쌍과 입력이 같은 cve_explicit 묶음은 sample의 호출 결과를 그대로 쓰고, by_task 호출 수에는 처음 부른 과제로 잡힌다",
            "모델 응답은 결정적이지 않다. 같은 명령을 다시 실행해도 같은 결과가 나온다고 주장하지 않는다",
        ],
        "nondeterminism": "판정 시각과 호출 수는 judged_at, calls에 기록. 재실행 결과의 동일성은 보장하지 않는다",
        "reproduce": [
            "uv run python scripts/judge_golden.py sample --kisa-root <KISA 캐시가 있는 체크아웃>",
            "uv run python scripts/judge_golden.py build --kisa-root <KISA 캐시가 있는 체크아웃>",
        ],
    }
    if build:
        manifest["corpus"] = {
            "n_notices": len(ctx.notices),
            "documents_sha256": build["no_answer"]["corpus_sha256"],
            "n_cve_ids_in_corpus": build["no_answer"]["n_cve_ids_in_corpus"],
            "scan": "정규화 본문 전체와 제목에서 splits.extract_cve_ids로 뽑은 집합",
        }
        manifest["questions"] = build["provenance"]
        manifest["counts"] = build["counts"]
        manifest["split"] = {
            "method": "docs/eval-protocol.md 6절: 그룹 블록 단위, 유형별 dev 비율을 목표에 맞추는 그리디 배정, seed 고정, splits.assert_disjoint",
            "dev_share_target": 0.4,
            "dev_share": round(build["split"]["n_dev"] / max(build["counts"]["scored"], 1), 4),
            "n_dev": build["split"]["n_dev"],
            "n_test": build["split"]["n_test"],
        }
    return manifest


def emit_outputs(ctx: Context) -> dict[str, str]:
    sample, build = read_state(ctx, "sample"), read_state(ctx, "build")
    rows: dict[str, list[dict]] = {name: [] for name in judge.JUDGE_NAMES}
    for state in (sample, build):
        if state:
            for name in judge.JUDGE_NAMES:
                rows[name].extend(state["rows"][name])
    outputs = {
        golden.JUDGMENTS_A_FILE: jsonl_text(
            sorted(rows["A"], key=lambda r: (r["question_id"], r["doc_id"]))
        ),
        golden.JUDGMENTS_B_FILE: jsonl_text(
            sorted(rows["B"], key=lambda r: (r["question_id"], r["doc_id"]))
        ),
        golden.AGREEMENT_FILE: json_text(agreement_output(sample, build)),
        golden.JUDGE_MANIFEST_FILE: json_text(manifest_output(ctx, sample, build)),
    }
    if sample:
        outputs[golden.ERROR_RATES_FILE] = json_text(error_rates_output(sample))
    if build:
        outputs[golden.GOLDEN_V1_FILE] = jsonl_text(build["records"])
    return outputs


def write_outputs(ctx: Context) -> list[str]:
    outputs = emit_outputs(ctx)
    golden.write_outputs(ctx.root, outputs)
    return sorted(outputs)


# ---------------------------------------------------------------- CLI


def build_context(args: argparse.Namespace) -> Context:
    root = args.root
    _, doc_versions = golden.load_doc_versions(root / golden.KISA_MANIFEST)
    return Context(
        root=root,
        load_body=kisa_body_loader(args.kisa_root, doc_versions),
        judges={"A": judge.ClaudeJudge(), "B": judge.CodexJudge()},
        cache=judge.CallCache(args.cache_dir),
        state_dir=args.cache_dir / STATE_DIR_NAME,
        jobs=args.jobs,
    )


def main(argv: Sequence[str] | None = None, *, context: Context | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (
        ("sample", "표본 쌍을 판정해 eval/golden/error_rates.json을 만든다"),
        ("build", "골든셋 질문을 만들고 판정해 eval/golden/golden_v1.jsonl을 만든다"),
    ):
        sub = commands.add_parser(name, help=text)
        sub.add_argument("--kisa-root", type=Path, required=context is None)
        sub.add_argument("--root", type=Path, default=ROOT)
        sub.add_argument("--cache-dir", type=Path, default=ROOT / CACHE_DIR)
        sub.add_argument("--jobs", type=int, default=4)
        if name == "build":
            sub.add_argument("--cve-count", type=int, default=CVE_TARGET)
            sub.add_argument("--per-type", type=int, default=PER_TYPE_TARGET)
    args = parser.parse_args(argv)

    ctx = context or build_context(args)
    record_resume(ctx)
    try:
        if args.command == "sample":
            state = run_sample(ctx)
            failures = sample_failures(state)
        else:
            state = run_build(ctx, cve_count=args.cve_count, per_type=args.per_type)
            failures = build_failures(ctx, state["records"])
    except judge.JudgeUnavailable as exc:
        record_limit_stop(ctx, str(exc))
        print(f"STOP: judge usage limit: {exc}", file=sys.stderr)
        return 3
    except judge.JudgeError as exc:
        print(f"error: judge call failed (rerun resumes from the cache): {exc}", file=sys.stderr)
        return 2
    written = write_outputs(ctx)
    print(f"wrote {len(written)} files: {', '.join(written)}")
    for failure in failures:
        print(f"FAILED: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

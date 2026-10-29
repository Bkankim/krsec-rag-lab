"""scripts/judge_golden.py 전 경로 테스트(sample, build). 가짜 판정자와 합성 본문만 쓰고 모델은 부르지 않는다."""

import hashlib
import importlib.util
import json
import re
import sys
import time
from pathlib import Path

import pytest

from krsec_rag_lab import golden, judge
from krsec_rag_lab.golden import JUDGE_OUTPUT_FIELDS
from krsec_rag_lab.splits import extract_cve_ids

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "judge_golden.py"
SPEC = importlib.util.spec_from_file_location("judge_golden", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
jg = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = jg
SPEC.loader.exec_module(jg)

N_NOTICES = 60
N_PRODUCTS = 20


# ------------------------------------------------------------ 합성 코퍼스


def make_notices():
    rows = [
        {
            "nttId": str(90000 + i),
            "title": f"Prod{i % N_PRODUCTS} 제품 보안 업데이트 권고",
            "date": f"2026-{1 + i // 28:02d}-{1 + i % 28:02d}",
            "url": f"https://example.invalid/view?nttId={90000 + i}",
            "cve_ids": [f"CVE-2026-{1000 + 2 * i}", f"CVE-2026-{1001 + 2 * i}"],
        }
        for i in range(N_NOTICES)
    ]
    rows.append(
        {
            "nttId": "90900",
            "title": "스미싱 주의 권고",
            "date": "2026-06-01",
            "url": "https://example.invalid/view?nttId=90900",
            "cve_ids": [],
        }
    )
    return rows


def body_of(notice):
    """정규화 본문 흉내: 문단마다 한 줄. 둘째 줄이 CVE·제품 문장(판정 인용 대상)이다."""
    product = notice["title"].split()[0]
    cves = ", ".join(notice["cve_ids"]) or "해당 없음"
    return "\n".join(
        [
            f"{notice['title']} 관련 개요 문단이다.",
            f"이 공지는 {product} 제품의 {cves} 취약점 조치를 다룬다.",
            f"{notice['nttId']}번 공지의 고유한 조치 방법은 합성 문장으로만 설명한다.",
            "마무리 문단이다.",
        ]
    )


def make_root(tmp_path, notices):
    (tmp_path / "fixtures" / "kisa").mkdir(parents=True)
    (tmp_path / "fixtures" / "nvd").mkdir(parents=True)
    (tmp_path / "fixtures" / "kisa" / "metadata.jsonl").write_text(
        "".join(json.dumps(n, ensure_ascii=False) + "\n" for n in notices), encoding="utf-8"
    )
    docs = [
        {"nttId": n["nttId"], "sha256": hashlib.sha256(body_of(n).encode()).hexdigest()}
        for n in notices
    ]
    (tmp_path / "fixtures" / "kisa" / "manifest.json").write_text(
        json.dumps({"parser_version": "synthetic-v1", "documents": docs}), encoding="utf-8"
    )
    cves = sorted({c for n in notices for c in n["cve_ids"]})
    (tmp_path / "fixtures" / "nvd" / "cves.jsonl").write_text(
        "".join(
            json.dumps({"id": c, "description_en": f"synthetic NVD text {c}"}) + "\n" for c in cves
        ),
        encoding="utf-8",
    )
    golden.write_outputs(tmp_path, golden.build_outputs(tmp_path))
    return tmp_path


# ------------------------------------------------------------ 가짜 판정자


def decide(question, notice):
    """합성 규칙: CVE 질문은 본문에 그 CVE가 있으면, 제품 질문은 제목에 제품이 있으면, 설명 질문은 번호로."""
    cves = extract_cve_ids(question)
    if cves:
        return cves[0] in notice["text"]
    product = re.search(r"Prod\d+", question)
    if product:
        return product.group(0) in notice["title"]
    number = re.search(r"(\d{5})번 공지", question)
    return bool(number) and f"{number.group(1)}번 공지의 고유한" in notice["text"]


def judge_responder(name, flip=None, bad_quote=None):
    """flip(name, question, doc_id) -> True면 판정을 뒤집는다. bad_quote(question, doc_id) -> True면 첫 응답에 엉터리 인용."""
    seen_retry = set()

    def respond(instruction, payload):
        assert instruction == judge.JUDGE_INSTRUCTION
        question = payload["question"]
        entries = []
        for item in payload["notices"]:
            relevant = decide(question, item)
            if flip and flip(name, question, item["doc_id"]):
                relevant = not relevant
            quote = item["text"].split("\n")[1] if relevant else ""
            key = (question, item["doc_id"])
            if relevant and bad_quote and bad_quote(question, item["doc_id"]):
                if "retry" not in payload or key in seen_retry:
                    quote = "본문 어디에도 없는 인용 문장입니다 정말로"
                seen_retry.add(key)
            entries.append(
                {
                    "doc_id": item["doc_id"],
                    "relevance": judge.RELEVANT if relevant else judge.NOT_RELEVANT,
                    "reason_code": "cve_discussed" if relevant else "cve_absent",
                    "quote": quote,
                }
            )
        return json.dumps({"judgments": entries}, ensure_ascii=False)

    return respond


def generator(copy_first=0):
    """질문 생성 응답기. copy_first번째 호출까지는 본문 문장을 그대로 베낀 질문을 낸다."""
    state = {"n": 0}

    def generate(payload):
        state["n"] += 1
        notice = payload["notice"]
        if state["n"] <= copy_first:
            return json.dumps({"question": notice["text"].split("\n")[1]}, ensure_ascii=False)
        product = notice["title"].split()[0]
        number = re.search(r"(\d{5})번 공지", notice["text"]).group(1)
        if payload["type"] == "product_symptom":
            question = f"{product} 제품에서 {notice['date']} 무렵 보고된 문제는 어느 공지인가요?"
        else:
            question = f"{number}번 공지가 설명하는 조치 방법은 무엇인가요?"
        return json.dumps({"question": question}, ensure_ascii=False)

    return generate


def make_judge(name, flip=None, bad_quote=None, copy_first=0):
    base = judge_responder(name, flip, bad_quote)
    make_question = generator(copy_first)

    def respond(instruction, payload):
        if instruction == judge.QUESTION_INSTRUCTION:
            return make_question(payload)
        return base(instruction, payload)

    return judge.FakeJudge(name, respond)


def make_context(tmp_path, *, a=None, b=None, jobs=1, notices=None):
    notices = notices or make_notices()
    root = make_root(tmp_path / "repo", notices)
    bodies = {n["nttId"]: body_of(n) for n in notices}
    cache_dir = tmp_path / "cache"
    return jg.Context(
        root=root,
        load_body=lambda ntt_id: bodies[ntt_id],
        judges={"A": a or make_judge("A"), "B": b or make_judge("B")},
        cache=judge.CallCache(cache_dir),
        state_dir=cache_dir / "state",
        jobs=jobs,
    )


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# ------------------------------------------------------------ sample


def test_sample_judges_every_pair_and_reports_both_error_rates(tmp_path):
    ctx = make_context(tmp_path)
    assert jg.main(["sample"], context=ctx) == 0

    rates = json.loads((ctx.root / golden.ERROR_RATES_FILE).read_text(encoding="utf-8"))
    counts = rates["counts"]
    assert counts["attempted_pairs"] == counts["valid_pairs"] == 36
    assert counts["unjudged_pairs"] == 0 and counts["disagree_pairs"] == 0
    assert rates["mislabel"]["denominator"] > 0 and rates["omission"]["denominator"] > 0
    assert rates["mislabel"]["rate"] == 0.0 and rates["omission"]["rate"] == 0.0
    assert rates["meets_min_valid_pairs"] is True
    assert rates["status"] == "cross_judged_not_human_verified"
    # 0건 층의 사유는 후보 매니페스트의 문장 그대로 옮긴다
    manifest = json.loads((ctx.root / golden.MANIFEST_FILE).read_text(encoding="utf-8"))
    expected = {s["stratum"]: s["zero_reason"] for s in manifest["sampling"]["strata"]}
    assert {s["stratum"]: s["zero_reason"] for s in rates["sample"]["strata"]} == expected

    rows_a = read_jsonl(ctx.root / golden.JUDGMENTS_A_FILE)
    rows_b = read_jsonl(ctx.root / golden.JUDGMENTS_B_FILE)
    assert len(rows_a) == len(rows_b) == 36
    assert {tuple(sorted(r)) for r in rows_a} == {
        ("doc_id", "evidence", "question_id", "reason_code", "relevance", "status", "truncated")
    }


def test_sample_counts_a_wrong_candidate_as_a_mislabel_and_a_missed_one_as_an_omission(tmp_path):
    pairs = None

    def flip_on(name_unused, question, doc_id):
        return (question, doc_id) in wrong

    ctx = make_context(tmp_path, a=make_judge("A"), b=make_judge("B"))
    pairs = read_jsonl(ctx.root / golden.PAIRS_FILE)
    inside = [p for p in pairs if p["in_candidate_set"]][:3]
    outside = [p for p in pairs if not p["in_candidate_set"]][:2]
    wrong = {(p["candidate_query"], p["doc_id"]) for p in [*inside, *outside]}
    ctx.judges = {"A": make_judge("A", flip=flip_on), "B": make_judge("B", flip=flip_on)}
    assert jg.main(["sample"], context=ctx) == 0
    rates = json.loads((ctx.root / golden.ERROR_RATES_FILE).read_text(encoding="utf-8"))
    n_in = sum(1 for p in pairs if p["in_candidate_set"])
    n_out = len(pairs) - n_in
    assert rates["mislabel"] == {
        "scope": "in_candidate_set",
        "denominator": n_in,
        "n_error": 3,
        "rate": round(3 / n_in, 6),
    }
    assert rates["omission"]["n_error"] == 2
    assert rates["omission"]["denominator"] == n_out


def test_sample_disagreements_become_unjudged_and_leave_the_denominators(tmp_path):
    ctx = make_context(tmp_path)
    pairs = read_jsonl(ctx.root / golden.PAIRS_FILE)
    split_pairs = {(p["candidate_query"], p["doc_id"]) for p in pairs[:4]}
    ctx.judges["B"] = make_judge("B", flip=lambda _n, q, d: (q, d) in split_pairs)
    assert jg.main(["sample"], context=ctx) == 0
    rates = json.loads((ctx.root / golden.ERROR_RATES_FILE).read_text(encoding="utf-8"))
    assert rates["counts"]["disagree_pairs"] == 4
    assert rates["counts"]["unjudged_pairs"] == 4
    assert rates["counts"]["unjudged_reasons"] == [{"reason": "disagree", "n": 4}]
    assert rates["mislabel"]["denominator"] + rates["omission"]["denominator"] == 32
    assert rates["kappa"]["n"] == 36


def test_sample_below_thirty_valid_pairs_fails(tmp_path, capsys):
    ctx = make_context(tmp_path)
    ctx.judges["B"] = judge.FakeJudge("B", lambda _i, _p: "never valid json")
    assert jg.main(["sample"], context=ctx) == 1
    err = capsys.readouterr().err
    assert "valid pairs 0 < 30" in err and "denominator is 0" in err
    rates = json.loads((ctx.root / golden.ERROR_RATES_FILE).read_text(encoding="utf-8"))
    assert rates["meets_min_valid_pairs"] is False
    assert rates["kappa"]["value"] is None and rates["kappa"]["null_reason"]


def test_sample_uses_one_judge_call_per_question_bundle_and_each_judge(tmp_path):
    ctx = make_context(tmp_path)
    assert jg.main(["sample"], context=ctx) == 0
    questions = {p["candidate_question_id"] for p in read_jsonl(ctx.root / golden.PAIRS_FILE)}
    assert len(ctx.judges["A"].calls) == len(ctx.judges["B"].calls) == len(questions)
    for fake in ctx.judges.values():
        for call in fake.calls:
            assert set(call) == {"question", "notices"}  # 다른 판정자의 출력은 입력에 없다


# ------------------------------------------------------------ build


def run_build(ctx, **kwargs):
    code = jg.main(["build"], context=ctx)
    records = read_jsonl(ctx.root / golden.GOLDEN_V1_FILE)
    return code, records


def test_build_makes_a_valid_golden_set_with_all_four_types(tmp_path, capsys):
    ctx = make_context(tmp_path)
    code, records = run_build(ctx)
    assert code == 0, capsys.readouterr().err
    scored = [r for r in records if not r["excluded"]]
    by_type = {t: sum(1 for r in scored if r["query_type"] == t) for t in golden.QUERY_TYPES}
    assert len(scored) >= 50
    assert all(by_type[t] >= m for t, m in golden.V1_MIN_PER_TYPE.items()), by_type
    notices = golden.load_notices(ctx.root / golden.KISA_METADATA)
    _, versions = golden.load_doc_versions(ctx.root / golden.KISA_MANIFEST)
    assert (
        golden.validate_golden(
            records, notices=notices, doc_versions=versions, parser_version="synthetic-v1"
        )
        == []
    )
    assert golden.check_golden_v1(records) == []
    dev = sum(1 for r in scored if r["split"] == "dev") / len(scored)
    assert 0.3 <= dev <= 0.5
    assert [r["question_id"] for r in records] == sorted(
        [r["question_id"] for r in records],
        key=lambda q: (
            golden.QUERY_TYPES.index(
                next(r["query_type"] for r in records if r["question_id"] == q)
            ),
            q,
        ),
    )


def test_build_answers_are_the_agreed_relevant_docs_with_both_judges_spans(tmp_path):
    ctx = make_context(tmp_path)
    _, records = run_build(ctx)
    bodies = {n["nttId"]: body_of(n) for n in ctx.notices}
    cve_record = next(r for r in records if r["query_type"] == "cve_explicit" and not r["excluded"])
    assert cve_record["cve_ids"] == extract_cve_ids(cve_record["query"])
    for answer in cve_record["answers"]:
        assert answer["doc_sha256"] == ctx.doc_versions[answer["doc_id"]]
        assert {span["judge"] for span in answer["evidence"]} == {"A", "B"}
        for span in answer["evidence"]:
            # 근거 위치가 가리키는 구간은 그 문서의 CVE 문장이다(본문은 파일에 없다)
            assert cve_record["cve_ids"][0] in bodies[answer["doc_id"]][span["start"] : span["end"]]
        assert answer["reason"] == "A:cve_discussed B:cve_discussed"
    product = next(r for r in records if r["query_type"] == "product_symptom" and not r["excluded"])
    assert len(product["answers"]) > 1  # 같은 제품명 제목 공지가 묶음에 들어가 함께 정답이 된다
    assert product["cve_ids"] == [] and product["surface_cve"] is False


def test_build_no_answer_questions_ask_for_cves_absent_from_the_corpus(tmp_path):
    ctx = make_context(tmp_path)
    _, records = run_build(ctx)
    in_corpus = set()
    for notice in ctx.notices:
        in_corpus.update(extract_cve_ids(body_of(notice)))
        in_corpus.update(extract_cve_ids(notice["title"]))
    absent = [r for r in records if r["query_type"] == "no_answer"]
    assert len(absent) == 10
    for record in absent:
        assert record["answers"] == [] and record["excluded"] is False
        assert extract_cve_ids(record["query"]) == record["cve_ids"]
        assert record["cve_ids"][0] not in in_corpus
        assert record["no_answer_reason"]
    manifest = json.loads((ctx.root / golden.JUDGE_MANIFEST_FILE).read_text(encoding="utf-8"))
    assert manifest["corpus"]["n_notices"] == len(ctx.notices)
    assert re.fullmatch(r"[0-9a-f]{64}", manifest["corpus"]["documents_sha256"])


def test_build_rejects_no_answer_attempts_the_judges_do_not_agree_on(tmp_path):
    ctx = make_context(tmp_path)
    first = next(judge.absent_cve_candidates(ctx.seed, set()))
    ctx.judges["B"] = make_judge("B", flip=lambda _n, question, _d: first in question)
    code, records = run_build(ctx)
    assert code == 0
    manifest = json.loads((ctx.root / golden.JUDGE_MANIFEST_FILE).read_text(encoding="utf-8"))
    na = [r for r in records if r["query_type"] == "no_answer"]
    assert len(na) == 10
    assert manifest["calls"]["no_answer_attempts"] == 11
    assert first not in {r["cve_ids"][0] for r in na}
    # 거부된 시도의 판정도 판정 기록에 남는다
    rows = read_jsonl(ctx.root / golden.JUDGMENTS_B_FILE)
    assert any(r["question_id"] == f"g1-na-{first.lower()}" for r in rows)


def test_build_stops_after_twenty_no_answer_attempts(tmp_path, capsys):
    ctx = make_context(tmp_path)
    ctx.judges["B"] = make_judge(
        "B", flip=lambda _n, q, _d: q.startswith(("CVE-20", "CVE-")) is False and False
    )
    # B가 no_answer 묶음마다 relevant로 뒤집는다: 질문이 코퍼스에 없는 CVE일 때
    absent = {
        c for _, c in zip(range(40), judge.absent_cve_candidates(ctx.seed, set()), strict=False)
    }
    ctx.judges["B"] = make_judge("B", flip=lambda _n, q, _d: any(c in q for c in absent))
    code, records = run_build(ctx)
    assert code == 1
    assert sum(1 for r in records if r["query_type"] == "no_answer") == 0
    manifest = json.loads((ctx.root / golden.JUDGE_MANIFEST_FILE).read_text(encoding="utf-8"))
    assert manifest["calls"]["no_answer_attempts"] == 20
    assert "scored no_answer records 0 < 10" in capsys.readouterr().err


def test_build_excludes_a_question_when_no_gold_remains_and_keeps_it_out_of_the_counts(tmp_path):
    ctx = make_context(tmp_path)
    questions = read_jsonl(ctx.root / golden.QUESTIONS_FILE)
    victim = jg.cve_question_order(questions, ctx.seed)[0]
    victim_id = f"g1-{victim['candidate_question_id'].removeprefix('cq-')}"
    ctx.judges["B"] = make_judge("B", flip=lambda _n, q, _d: victim["cve_ids"][0] in q)
    code, records = run_build(ctx)
    assert code == 0
    excluded = [r for r in records if r["excluded"]]
    assert [r["question_id"] for r in excluded] == [victim_id]
    assert excluded[0]["answers"] == []
    assert excluded[0]["unjudged"] == victim["candidate_ntt_ids"]
    assert "split" in excluded[0]
    scored = [r for r in records if not r["excluded"]]
    assert len(scored) >= 50  # 채점 대상이 모자라 cve_explicit을 더 판정했다
    state = json.loads((ctx.state_dir / "build.json").read_text(encoding="utf-8"))
    assert state["counts"]["excluded"] == 1 and state["counts"]["scored"] == len(scored)


def test_build_marks_truncated_not_relevant_docs_unjudged(tmp_path):
    notices = make_notices()
    long_ntt = "90005"
    bodies = {n["nttId"]: body_of(n) for n in notices}
    bodies[long_ntt] += "\n" + "긴 본문 채움 문장이다. " * 3000
    ctx = make_context(tmp_path, notices=notices)
    ctx.load_body = lambda ntt_id: bodies[ntt_id]
    # 같은 제품 공지(90005, 90025, 90045)를 함께 묻는 제품 질문에서 긴 공지는 한쪽만 relevant여도 잘림 표시가 남는다
    judged = jg.judge_bundles(
        ctx, [jg.Bundle("probe", "Prod5 제품의 문제는?", (long_ntt, "90025"), "test")]
    )
    assert judged["probe"]["A"][long_ntt].truncated is True
    assert judged["probe"]["A"]["90025"].truncated is False
    other = jg.judge_bundles(
        ctx, [jg.Bundle("probe2", "Prod7 제품의 문제는?", (long_ntt, "90027"), "test")]
    )
    resolutions = jg.resolve_bundle(
        jg.Bundle("probe2", "", (long_ntt, "90027"), "test"), other["probe2"]
    )
    by_doc = {r.doc_id: r for r in resolutions}
    assert by_doc[long_ntt].outcome == judge.UNJUDGED
    assert by_doc[long_ntt].why == "truncated_not_relevant"
    assert by_doc["90027"].outcome == judge.GOLD


def test_build_asks_the_question_generator_with_the_a_model_only_and_caps_calls(tmp_path, capsys):
    ctx = make_context(tmp_path, a=make_judge("A", copy_first=10_000))
    code, records = run_build(ctx)
    assert code == 1
    manifest = json.loads((ctx.root / golden.JUDGE_MANIFEST_FILE).read_text(encoding="utf-8"))
    assert manifest["calls"]["question_generation"] == 48  # 필요한 비CVE 질문 24개의 2배
    assert manifest["calls"]["caps"]["question_generation"] == 48
    assert not [r for r in records if r["query_type"] in jg.NON_CVE_TYPES]
    assert "scored product_symptom records 0 < 10" in capsys.readouterr().err
    assert all(call.get("type") is None or "type" in call for call in ctx.judges["A"].calls)
    assert not [c for c in ctx.judges["B"].calls if "type" in c]


def test_build_discards_copied_questions_and_replaces_them_within_the_cap(tmp_path):
    ctx = make_context(tmp_path, a=make_judge("A", copy_first=3))
    code, records = run_build(ctx)
    assert code == 0
    manifest = json.loads((ctx.root / golden.JUDGE_MANIFEST_FILE).read_text(encoding="utf-8"))
    non_cve = [r for r in records if r["query_type"] in jg.NON_CVE_TYPES]
    assert len(non_cve) == 24
    assert manifest["calls"]["question_generation"] == 27
    bodies = {n["nttId"]: body_of(n) for n in ctx.notices}
    for record in non_cve:
        assert len(record["query"]) <= 80 and "\u2014" not in record["query"]
        assert not any(judge.copies_body(record["query"], body) for body in bodies.values())


def test_build_retries_unfindable_quotes_once_and_counts_the_calls(tmp_path):
    victim_doc = "90010"
    ctx = make_context(tmp_path)
    ctx.judges["A"] = make_judge("A", bad_quote=lambda q, d: d == victim_doc)
    code, records = run_build(ctx)
    assert code == 0
    manifest = json.loads((ctx.root / golden.JUDGE_MANIFEST_FILE).read_text(encoding="utf-8"))
    retries = {c["judge"]: c["n"] for c in manifest["calls"]["by_kind"] if c["kind"] == "retry"}
    assert retries["A"] > 0 and retries["B"] == 0
    rows = read_jsonl(ctx.root / golden.JUDGMENTS_A_FILE)
    relevant_rows = [r for r in rows if r["doc_id"] == victim_doc and r["relevance"] == "relevant"]
    assert relevant_rows and {r["status"] for r in relevant_rows} == {"no_evidence"}
    hit = [r for r in records if victim_doc in r["unjudged"]]
    assert hit and all(victim_doc not in [a["doc_id"] for a in r["answers"]] for r in hit)


def test_build_is_resumable_and_a_rerun_makes_no_model_calls(tmp_path):
    ctx = make_context(tmp_path)
    assert run_build(ctx)[0] == 0
    first = {rel: (ctx.root / rel).read_bytes() for rel in jg.emit_outputs(ctx)}
    made = [len(j.calls) for j in ctx.judges.values()]
    again = make_context(tmp_path / "again")  # 새 캐시
    again.cache = judge.CallCache(tmp_path / "cache")  # 같은 캐시를 이어 쓴다
    again.state_dir = ctx.state_dir
    assert run_build(again)[0] == 0
    assert [len(j.calls) for j in again.judges.values()] == [0, 0]
    assert made[0] > 0 and made[1] > 0
    assert first[golden.GOLDEN_V1_FILE] == (again.root / golden.GOLDEN_V1_FILE).read_bytes()


def test_build_with_parallel_jobs_gives_the_same_golden_set(tmp_path):
    serial = make_context(tmp_path / "serial", jobs=1)
    parallel = make_context(tmp_path / "parallel", jobs=4)
    assert run_build(serial)[0] == 0 and run_build(parallel)[0] == 0
    assert (serial.root / golden.GOLDEN_V1_FILE).read_bytes() == (
        parallel.root / golden.GOLDEN_V1_FILE
    ).read_bytes()


# ------------------------------------------------------------ 출력 파일 검사


def test_emitted_files_stay_on_the_allowlist_and_hold_no_body_text(tmp_path):
    ctx = make_context(tmp_path)
    assert jg.main(["sample"], context=ctx) == 0
    assert jg.main(["build"], context=ctx) == 0
    bodies = [body_of(n) for n in ctx.notices]
    lines = {line for body in bodies for line in body.split("\n")[1:3]}
    for rel in JUDGE_OUTPUT_FIELDS:
        path = ctx.root / rel
        assert golden.check_output_fields(path, JUDGE_OUTPUT_FIELDS[rel]) == [], rel
        text = path.read_text(encoding="utf-8")
        assert not [line for line in lines if line in text], rel
        assert "\u2014" not in text and "/Users/" not in text and str(tmp_path) not in text
        assert "description" not in text.lower()


def test_agreement_file_has_one_task_per_type_and_the_sample(tmp_path):
    ctx = make_context(tmp_path)
    assert jg.main(["sample"], context=ctx) == 0
    assert jg.main(["build"], context=ctx) == 0
    agreement = json.loads((ctx.root / golden.AGREEMENT_FILE).read_text(encoding="utf-8"))
    assert [t["task"] for t in agreement["tasks"]] == ["error_rate_sample", *golden.QUERY_TYPES]
    for task in agreement["tasks"]:
        assert set(task["kappa"]) == {
            "n",
            "value",
            "observed_agreement",
            "expected_agreement",
            "null_reason",
        }
    # 모든 판정이 relevant 아니면 not_relevant 한쪽으로 쏠린 과제는 kappa가 정의되지 않는다(null과 사유)
    no_answer = next(t for t in agreement["tasks"] if t["task"] == "no_answer")
    assert no_answer["kappa"]["value"] is None and no_answer["kappa"]["null_reason"]


def test_manifest_records_models_prompts_isolation_calls_and_a_placeholder_for_the_cache_root(
    tmp_path,
):
    ctx = make_context(tmp_path)
    assert jg.main(["sample"], context=ctx) == 0
    assert jg.main(["build"], context=ctx) == 0
    manifest = json.loads((ctx.root / golden.JUDGE_MANIFEST_FILE).read_text(encoding="utf-8"))
    assert manifest["prompts"]["judge_sha256"] == judge.JUDGE_PROMPT_SHA256
    assert [j["judge"] for j in manifest["judges"]] == ["A", "B"]
    assert manifest["calls"]["total"] == sum(c["n"] for c in manifest["calls"]["by_kind"])
    assert manifest["calls"]["total"] == len(ctx.cache.entries())
    assert manifest["judged_at"]["first"] <= manifest["judged_at"]["last"]
    assert {c["code"] for c in manifest["reason_codes"]} == set(judge.REASON_CODE_NAMES)
    assert all("<KISA 캐시가 있는 체크아웃>" in cmd for cmd in manifest["reproduce"])
    assert {i["path"] for i in manifest["inputs"]} >= {golden.KISA_METADATA, golden.PAIRS_FILE}
    assert any("같은 모델이 질문을 쓰고 판정" in text for text in manifest["limitations"])
    assert any("풀링 평가" in text for text in manifest["limitations"])
    assert manifest["bundle"]["max_chars_per_notice"] == 20_000
    assert manifest["split"]["n_dev"] + manifest["split"]["n_test"] == manifest["counts"]["scored"]


# ------------------------------------------------------------ 종료 코드·로더


def test_a_usage_limit_stops_the_run_with_exit_code_3(tmp_path, capsys):
    ctx = make_context(tmp_path)

    def limited(_instruction, _payload):
        raise judge.JudgeUnavailable("usage limit reached")

    ctx.judges["A"] = judge.FakeJudge("A", limited)
    assert jg.main(["sample"], context=ctx) == 3
    assert "STOP: judge usage limit" in capsys.readouterr().err
    events = jg.read_limit_events(ctx)
    assert len(events) == 1 and events[0]["resumed_at"] is None and events[0]["retry_hint"] is None


def test_a_resume_after_a_usage_limit_stop_records_the_wait_in_the_manifest(tmp_path):
    ctx = make_context(tmp_path)

    def limited(_instruction, _payload):
        raise judge.JudgeUnavailable("codex exit 1: hit your usage limit, try again at 8:38 PM")

    working = ctx.judges["A"]
    ctx.judges["A"] = judge.FakeJudge("A", limited)
    assert jg.main(["sample"], context=ctx) == 3
    ctx.judges["A"] = working
    assert jg.main(["sample"], context=ctx) == 0
    manifest = json.loads((ctx.root / golden.JUDGE_MANIFEST_FILE).read_text(encoding="utf-8"))
    (event,) = manifest["usage_limit"]["events"]
    assert manifest["usage_limit"]["stops"] == 1
    assert event["retry_hint"] == "8:38 PM" and event["resumed_at"] >= event["stopped_at"]
    assert "usage limit" not in json.dumps(manifest["usage_limit"])


def test_another_judge_failure_exits_2_and_keeps_finished_calls_for_the_resume(tmp_path, capsys):
    ctx = make_context(tmp_path)

    def broken(_instruction, _payload):
        raise judge.JudgeError("timeout")

    ctx.judges["B"] = judge.FakeJudge("B", broken)
    assert jg.main(["sample"], context=ctx) == 2
    assert "rerun resumes from the cache" in capsys.readouterr().err
    assert len(ctx.cache.entries()) > 0


def test_kisa_body_loader_reads_only_the_given_root_and_checks_the_hash(tmp_path):
    kisa = jg.load_kisa_module()
    html = (
        '<html><body><div class="b_title"><h2>합성 공지</h2><span>2026-01-02</span></div>'
        '<div class="content_html"><p>합성 본문 한 줄.</p></div></body></html>'
    ).encode()
    _, _, body = kisa.parse_detail(html)
    folder = tmp_path / "kisa-root" / "data" / "kisa" / "123"
    folder.mkdir(parents=True)
    (folder / "source.html").write_bytes(html)
    (folder / "body.txt").write_text(body, encoding="utf-8")
    load = jg.kisa_body_loader(tmp_path / "kisa-root", {"123": kisa.content_hash(body)})
    assert load("123") == body
    stale = jg.kisa_body_loader(tmp_path / "kisa-root", {"123": "0" * 64})
    with pytest.raises(kisa.KisaError, match="cache_hash_mismatch"):
        stale("123")
    missing = jg.kisa_body_loader(tmp_path / "other-root", {"123": kisa.content_hash(body)})
    with pytest.raises(kisa.KisaError, match="cache_missing"):
        missing("123")


def test_cli_requires_a_kisa_root_when_no_context_is_given():
    with pytest.raises(SystemExit):
        jg.main(["sample"])


def test_no_answer_record_lists_the_truncated_docs_as_unjudged(tmp_path):
    ctx = make_context(tmp_path)
    ctx.load_body = lambda ntt_id: (
        "긴 본문 채움 문장이다. " * 3000
    )  # 20,000자 상한을 넘겨 모두 잘린다
    records, _, _, stats = jg.run_no_answer(ctx, set())
    assert stats["accepted"] == 10
    for record in records:
        assert record["answers"] == [] and len(record["unjudged"]) == jg.NO_ANSWER_DOCS


def test_manifest_counts_only_the_calls_behind_these_outputs_not_stale_cache_entries(tmp_path):
    ctx = make_context(tmp_path)
    stale = judge.FakeJudge("A", lambda _i, _p: "x")
    ctx.cache.put(
        ctx.cache.key(stale, "old instruction", "old payload"),
        {
            "kind": "judge",
            "task": "old",
            "judge": "A",
            "model": "fake",
            "created_at": "2020-01-01T00:00:00Z",
            "result": {},
        },
    )
    assert jg.main(["sample"], context=ctx) == 0
    manifest = json.loads((ctx.root / golden.JUDGE_MANIFEST_FILE).read_text(encoding="utf-8"))
    assert manifest["calls"]["total"] == len(ctx.cache.entries()) - 1
    assert manifest["judged_at"]["first"] > "2020-01-02"
    assert [c["n"] for c in manifest["calls"]["by_kind"] if c["kind"] == "retry"] == [0, 0]


def test_run_parallel_raises_the_usage_limit_even_when_an_earlier_item_failed_otherwise():
    def work(item):
        if item == 0:
            time.sleep(0.2)  # 먼저 제출됐지만 늦게 다른 이유로 실패한다
            raise judge.JudgeError("timeout")
        if item == 1:
            raise judge.JudgeUnavailable("usage limit reached")
        return item

    with pytest.raises(judge.JudgeUnavailable):
        jg.run_parallel(work, [0, 1, 2], jobs=3)


def test_run_parallel_keeps_the_input_order_and_the_first_error_otherwise():
    assert jg.run_parallel(lambda x: x * 2, [3, 1, 2], jobs=3) == [6, 2, 4]
    with pytest.raises(ValueError, match="first"):
        jg.run_parallel(lambda x: (_ for _ in ()).throw(ValueError("first")), [1, 2], jobs=2)


def test_manifest_keeps_the_judged_input_hashes_when_an_input_file_changes_later(tmp_path):
    ctx = make_context(tmp_path)
    assert jg.main(["sample"], context=ctx) == 0
    first = json.loads((ctx.root / golden.JUDGE_MANIFEST_FILE).read_text(encoding="utf-8"))
    assert first["inputs"] == first["judged_inputs"]
    assert "같다" in first["inputs_note"]

    # 판정 뒤에 다른 티켓이 NVD fixture에 필드만 더한 상황
    nvd = ctx.root / golden.NVD_CVES
    nvd.write_text(
        nvd.read_text(encoding="utf-8").replace("}\n", ', "vendor_products": []}\n'),
        encoding="utf-8",
    )
    calls_before = len(ctx.cache.entries())
    assert jg.main(["sample"], context=ctx) == 0
    second = json.loads((ctx.root / golden.JUDGE_MANIFEST_FILE).read_text(encoding="utf-8"))
    by_path = {r["path"]: r["sha256"] for r in second["inputs"]}
    judged = {r["path"]: r["sha256"] for r in second["judged_inputs"]}
    assert second["judged_inputs"] == first["judged_inputs"]
    assert by_path[golden.NVD_CVES] == golden.file_sha256(nvd) != judged[golden.NVD_CVES]
    assert all(by_path[p] == judged[p] for p in by_path if p != golden.NVD_CVES)
    assert golden.NVD_CVES in second["inputs_note"] and "#36" in second["inputs_note"]
    assert len(ctx.cache.entries()) == calls_before  # 재생성은 모델을 부르지 않는다

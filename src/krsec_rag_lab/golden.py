"""골든셋 v1 자동 단계(#27) - 약한 라벨 후보, seed 고정 표본, 검수 양식, 오류율, 스키마 검증.

docs/eval-protocol.md 8절의 1단계(후보 생성)만 한다. 정답 단위는 문서(nttId), 후보는 문서·CVE 단위이고
청크 지정과 근거 구간은 #10 사람 검수 몫이다. 공개 메타데이터(fixtures/kisa/metadata.jsonl)와 NVD fixture의
CVE ID만 읽는다. KISA 본문은 읽지 않고, NVD 설명 필드는 열지도 않는다(조인 키 `id`만 쓴다).

출력(candidates)은 사람 검수 정답이 아니라 약한 라벨 후보다. 사람 검수 결과·오류율 수치는 여기서 만들지 않는다.
표준 라이브러리만 쓴다.
"""

import argparse
import csv
import hashlib
import io
import json
import re
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from krsec_rag_lab.splits import (
    CVE_ID_RE,
    SplitLeakError,
    assert_disjoint,
    extract_cve_ids,
    normalize_text,
)

PROTOCOL_VERSION = "eval-protocol-v1"
SEED = 27
MIN_SAMPLE_PAIRS = 30
QUERY_TYPES = ("cve_explicit", "product_symptom", "explanation_comparison", "no_answer")

# 표본 층. layer: base는 조인 후보, a/b는 이슈 #27이 요구한 점검 층. 선택 순서는 a -> b -> base다.
STRATUM_JOIN = "join_candidate"
STRATUM_A = "a_title_cve_not_in_cve_ids"
STRATUM_B = "b_outside_join_same_product"
STRATA = (
    (STRATUM_JOIN, "base", 24),
    (STRATUM_A, "a", 6),
    (STRATUM_B, "b", 12),
)
SOURCE_JOIN = "cve-join"
SOURCE_TITLE_CVE = "title-cve-id"
SOURCE_SAME_PRODUCT = "same-product-title"
SOURCES = {
    STRATUM_JOIN: SOURCE_JOIN,
    STRATUM_A: SOURCE_TITLE_CVE,
    STRATUM_B: SOURCE_SAME_PRODUCT,
}
WEAK_POSITIVE = "weak_positive"
WEAK_UNLABELED = "weak_unlabeled"

# CVE 명시 질의 템플릿. 질의 판별식(splits.extract_cve_ids)이 CVE를 읽어내는지 생성 때 검사한다.
QUERY_TEMPLATES = (
    "{cve}는 어떤 KISA 보안공지에서 다루나요?",
    "{cve}를 인용한 보안 업데이트 권고 공지를 알려주세요.",
    "{cve} 관련 KISA 보안공지가 있나요?",
)
_PRODUCT_TITLE_RE = re.compile(r"(?P<product>.+) 제품 보안 업데이트 권고")

CANDIDATES_DIR = "eval/golden/candidates"
TEMPLATES_DIR = "eval/golden/templates"
QUESTIONS_FILE = f"{CANDIDATES_DIR}/weak_label_candidates.jsonl"
PAIRS_FILE = f"{CANDIDATES_DIR}/weak_label_sample_pairs.jsonl"
MANIFEST_FILE = f"{CANDIDATES_DIR}/candidate_manifest.json"
REVIEW_TEMPLATE_FILE = f"{TEMPLATES_DIR}/review_template.csv"
REVIEW_SHEET_FILE = f"{TEMPLATES_DIR}/review_sheet_candidate_sample.csv"

KISA_METADATA = "fixtures/kisa/metadata.jsonl"
KISA_MANIFEST = "fixtures/kisa/manifest.json"
NVD_CVES = "fixtures/nvd/cves.jsonl"

# 검수 양식. 앞 8개 + 3개 보조는 (질문, 문서) 쌍에서 미리 채우고, 뒤 6개는 사람이 채운다.
REVIEW_PREFILLED = (
    "question_id",
    "query_type",
    "doc_id",
    "doc_sha256",
    "stratum",
    "in_candidate_set",
    "weak_label",
    "evidence_parser_version",
)
REVIEW_HUMAN = ("evidence_start", "evidence_end", "relevance", "reason", "error_class")
REVIEW_COLUMNS = REVIEW_PREFILLED + REVIEW_HUMAN
RELEVANCE_VALUES = ("relevant", "not_relevant")
ERROR_CLASSES = ("mislabel", "omission", "ok")

# 커밋하는 출력 파일의 필드 허용 목록. 목록에 없는 필드는 테스트가 거부한다.
QUESTION_FIELDS = frozenset(
    {
        "candidate_question_id",
        "candidate_query",
        "candidate_ntt_ids",
        "candidate_nvd_cve_ids",
        "candidate_source",
        "cve_ids",
        "query_type",
    }
)
PAIR_FIELDS = frozenset(
    {
        "candidate_pair_id",
        "candidate_question_id",
        "candidate_query",
        "candidate_source",
        "cve_ids",
        "doc_date",
        "doc_id",
        "doc_sha256",
        "doc_title",
        "doc_url",
        "in_candidate_set",
        "query_type",
        "stratum",
        "weak_label",
    }
)
MANIFEST_FIELDS = frozenset(
    {
        "excluded_content",
        "generator",
        "inputs",
        "join",
        "kisa_parser_version",
        "layer",
        "method",
        "min_pairs",
        "n_candidate_pairs",
        "n_cves_with_nvd_record",
        "n_cves_without_nvd_record",
        "n_notices",
        "n_notices_with_cve_ids",
        "n_notices_with_product_title",
        "n_notices_with_cve_in_title",
        "n_pairs",
        "n_questions",
        "n_unique_cves",
        "path",
        "per_document_policy",
        "pool_docs",
        "pool_pairs",
        "protocol_version",
        "quota",
        "query_templates",
        "ranking",
        "sampling",
        "seed",
        "selected",
        "sha256",
        "status",
        "stratum",
        "strata",
        "unit",
        "zero_reason",
    }
)
OUTPUT_FIELDS = {
    QUESTIONS_FILE: QUESTION_FIELDS,
    PAIRS_FILE: PAIR_FIELDS,
    MANIFEST_FILE: MANIFEST_FIELDS,
    REVIEW_TEMPLATE_FILE: frozenset(REVIEW_COLUMNS),
    REVIEW_SHEET_FILE: frozenset(REVIEW_COLUMNS),
}

# 교차 판정(#10) 산출물. 후보 빌더 출력(OUTPUT_FIELDS)과 별도 허용 목록이고 파일이 서로 겹치지 않는다.
JUDGE_DIR = "eval/golden"
GOLDEN_V1_FILE = f"{JUDGE_DIR}/golden_v1.jsonl"
JUDGMENTS_A_FILE = f"{JUDGE_DIR}/judgments/A.jsonl"
JUDGMENTS_B_FILE = f"{JUDGE_DIR}/judgments/B.jsonl"
AGREEMENT_FILE = f"{JUDGE_DIR}/agreement.json"
ERROR_RATES_FILE = f"{JUDGE_DIR}/error_rates.json"
JUDGE_MANIFEST_FILE = f"{JUDGE_DIR}/judge_manifest.json"

JUDGMENT_FIELDS = frozenset(
    {
        "question_id",
        "doc_id",
        "relevance",
        "reason_code",
        "evidence",
        "start",
        "end",
        "truncated",
        "status",
    }
)
KAPPA_FIELDS = frozenset(
    {"kappa", "n", "value", "observed_agreement", "expected_agreement", "null_reason"}
)
AGREEMENT_FIELDS = (
    frozenset(
        {
            "protocol",
            "rule",
            "kappa_basis",
            "tasks",
            "task",
            "n_pairs",
            "n_valid_pairs",
            "n_agree",
            "n_disagree",
            "n_gold",
            "n_not_relevant",
            "n_unjudged",
            "unjudged_reasons",
            "reason",
        }
    )
    | KAPPA_FIELDS
)
ERROR_RATES_FIELDS = (
    frozenset(
        {
            "protocol",
            "status",
            "unit",
            "definition",
            "mislabel",
            "omission",
            "denominator",
            "sample",
            "seed",
            "pairs_file",
            "strata",
            "stratum",
            "selected",
            "zero_reason",
            "counts",
            "attempted_pairs",
            "valid_pairs",
            "agree_pairs",
            "disagree_pairs",
            "gold_pairs",
            "not_relevant_pairs",
            "unjudged_pairs",
            "unjudged_reasons",
            "reason",
            "scope",
            "n_error",
            "rate",
            "min_valid_pairs",
            "meets_min_valid_pairs",
            "limitations",
        }
    )
    | KAPPA_FIELDS
)
JUDGE_MANIFEST_FIELDS = frozenset(
    {
        "protocol",
        "status",
        "seed",
        "judges",
        "judge",
        "vendor",
        "model",
        "cli",
        "cli_version",
        "flags",
        "isolation",
        "cwd",
        "input",
        "other_judge_output",
        "flags_checked_with",
        "prompts",
        "judge_sha256",
        "question_generation_sha256",
        "answer_schema_sha256",
        "question_schema_sha256",
        "reason_codes",
        "code",
        "relevance",
        "meaning",
        "bundle",
        "max_notices",
        "max_chars_per_notice",
        "cve_window_chars",
        "max_retries",
        "retry_rule",
        "judged_at",
        "first",
        "last",
        "usage_limit",
        "stops",
        "events",
        "stopped_at",
        "retry_hint",
        "resumed_at",
        "inputs",
        "path",
        "sha256",
        "corpus",
        "n_notices",
        "documents_sha256",
        "n_cve_ids_in_corpus",
        "scan",
        "calls",
        "total",
        "by_kind",
        "by_task",
        "kind",
        "task",
        "n",
        "question_generation",
        "no_answer_attempts",
        "caps",
        "questions",
        "source_doc_id",
        "question_id",
        "query_type",
        "counts",
        "records",
        "scored",
        "excluded",
        "by_type",
        "split",
        "dev_share_target",
        "dev_share",
        "n_dev",
        "n_test",
        "method",
        "limitations",
        "reproduce",
        "nondeterminism",
    }
)
JUDGE_OUTPUT_FIELDS = {
    JUDGMENTS_A_FILE: JUDGMENT_FIELDS,
    JUDGMENTS_B_FILE: JUDGMENT_FIELDS,
    AGREEMENT_FILE: AGREEMENT_FIELDS,
    ERROR_RATES_FILE: ERROR_RATES_FIELDS,
    JUDGE_MANIFEST_FILE: JUDGE_MANIFEST_FIELDS,
    # GOLDEN_V1_FILE의 허용 목록은 레코드 스키마(GOLDEN_*_FIELDS)에서 만든다. 아래 정의 뒤에 채운다.
}

# 골든셋 레코드(#10 산출물) 스키마. 본문 텍스트 필드는 이름으로도 거부한다.
GOLDEN_RECORD_FIELDS = frozenset(
    {
        "question_id",
        "query",
        "query_type",
        "split",
        "cve_ids",
        "surface_cve",
        "answers",
        "no_answer_reason",
        "unjudged",
        "excluded",
    }
)
GOLDEN_ANSWER_FIELDS = frozenset({"doc_id", "doc_sha256", "evidence", "reason"})
# eval-protocol 8절 2단계: evidence = {nttId, parser_version, start, end}. nttId는 answers[].doc_id와 같으므로 생략할 수 있다
# judge: 교차 판정에서 이 구간을 낸 판정자(A/B). 두 판정자의 구간을 모두 보존한다
GOLDEN_EVIDENCE_FIELDS = frozenset({"nttId", "parser_version", "start", "end", "judge"})
FORBIDDEN_TEXT_FIELDS = frozenset(
    {
        "abstract",
        "body",
        "chunk",
        "chunk_text",
        "content",
        "description",
        "description_en",
        "excerpt",
        "passage",
        "quote",
        "raw",
        "snippet",
        "summary",
        "text",
    }
)
MAX_TEXT_LEN = 500  # 질의·판정 이유가 이보다 길면 본문을 붙여 넣은 것으로 본다
_SHA256_RE = re.compile(r"[0-9a-f]{64}")

JUDGE_OUTPUT_FIELDS[GOLDEN_V1_FILE] = (
    GOLDEN_RECORD_FIELDS | GOLDEN_ANSWER_FIELDS | GOLDEN_EVIDENCE_FIELDS
)

# 골든셋 v1 요구(이슈 #10): 채점 대상(excluded 아님) 50문항 이상, 유형별 최소, dev 비율 30~50%
V1_MIN_SCORED = 50
V1_MIN_PER_TYPE = {
    "cve_explicit": 15,
    "product_symptom": 10,
    "explanation_comparison": 10,
    "no_answer": 10,
}
V1_DEV_SHARE_RANGE = (0.30, 0.50)


class GoldenSchemaError(ValueError):
    """골든셋 레코드가 스키마를 어긴다. errors에 위반 목록이 있다."""

    def __init__(self, errors: Sequence[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


class ReviewSheetError(ValueError):
    """채워진 검수 파일이 양식을 어기거나 모순된다."""


# ---------------------------------------------------------------- 입력 로드


def _read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_notices(path: Path) -> list[dict]:
    """공개 메타데이터 한 줄 = {"nttId", "title", "date", "url", "cve_ids"}."""
    return _read_jsonl(path)


def load_doc_versions(path: Path) -> tuple[str, dict[str, str]]:
    """KISA manifest에서 (parser_version, nttId -> sha256). 본문은 읽지 않는다."""
    manifest = json.loads(path.read_text(encoding="utf-8"))
    versions = {str(doc["nttId"]): doc["sha256"] for doc in manifest["documents"]}
    return manifest["parser_version"], versions


def load_nvd_ids(path: Path) -> set[str]:
    """NVD fixture의 조인 키 `id`만 읽는다(설명 등 다른 필드는 쓰지 않는다)."""
    return {row["id"] for row in _read_jsonl(path)}


# ---------------------------------------------------------------- 후보 생성


def _rank(seed: int, key: str) -> str:
    """seed를 섞은 sha256. 파이썬 버전과 무관하게 같은 순서를 낸다(random 모듈을 쓰지 않는다)."""
    return hashlib.sha256(f"{seed}:{key}".encode()).hexdigest()


def _ntt_key(ntt_id: str) -> tuple[int, str]:
    return (len(ntt_id), ntt_id)


def question_text(cve_id: str) -> str:
    template = QUERY_TEMPLATES[int(hashlib.sha256(cve_id.encode()).hexdigest(), 16) % 3]
    text = template.format(cve=cve_id)
    if extract_cve_ids(text) != [cve_id]:
        raise ValueError(f"query template does not expose exactly {cve_id}: {text!r}")
    return text


def product_of(title: str) -> str | None:
    """'<제품명> 제품 보안 업데이트 권고' 형식의 제목에서 정규화한 제품명. 아니면 None."""
    match = _PRODUCT_TITLE_RE.fullmatch(normalize_text(title))
    return match.group("product") if match else None


def join_cve_to_notices(notices: Iterable[Mapping]) -> dict[str, list[str]]:
    """CVE ID -> 그 CVE를 `cve_ids`에 인용한 공지 nttId 목록(정렬)."""
    joined: dict[str, list[str]] = defaultdict(list)
    for notice in notices:
        for cve_id in notice["cve_ids"]:
            joined[cve_id.upper()].append(str(notice["nttId"]))
    return {cve: sorted(set(ids), key=_ntt_key) for cve, ids in joined.items()}


def title_cve_not_cited(notices: Iterable[Mapping]) -> dict[str, list[str]]:
    """층 (a): 제목에는 있는데 `cve_ids`에는 없는 CVE ID -> 공지 nttId 목록."""
    found: dict[str, list[str]] = defaultdict(list)
    for notice in notices:
        cited = {cve.upper() for cve in notice["cve_ids"]}
        for cve_id in extract_cve_ids(notice["title"]):
            if cve_id not in cited:
                found[cve_id].append(str(notice["nttId"]))
    return {cve: sorted(set(ids), key=_ntt_key) for cve, ids in found.items()}


def build_questions(
    cve_to_ntt: Mapping[str, Sequence[str]], extra_cves: Iterable[str], nvd_ids: set[str]
) -> list[dict]:
    """CVE 명시 질의(cve_explicit) 후보. CVE마다 질문 1개, 후보 문서는 `cve_ids` 조인 결과."""
    questions = []
    for cve_id in sorted(set(cve_to_ntt) | set(extra_cves)):
        questions.append(
            {
                "candidate_question_id": f"cq-{cve_id.lower()}",
                "candidate_query": question_text(cve_id),
                "candidate_ntt_ids": list(cve_to_ntt.get(cve_id, ())),
                "candidate_nvd_cve_ids": [cve_id] if cve_id in nvd_ids else [],
                "candidate_source": SOURCE_JOIN,
                "cve_ids": [cve_id],
                "query_type": "cve_explicit",
            }
        )
    return questions


def _pair(question: Mapping, notice: Mapping, sha256: str, stratum: str) -> dict:
    ntt_id = str(notice["nttId"])
    in_set = ntt_id in question["candidate_ntt_ids"]
    return {
        "candidate_pair_id": f"{question['candidate_question_id']}__{ntt_id}",
        "candidate_question_id": question["candidate_question_id"],
        "candidate_query": question["candidate_query"],
        "candidate_source": SOURCES[stratum],
        "cve_ids": list(question["cve_ids"]),
        "doc_date": notice["date"],
        "doc_id": ntt_id,
        "doc_sha256": sha256,
        "doc_title": notice["title"],
        "doc_url": notice["url"],
        "in_candidate_set": in_set,
        "query_type": question["query_type"],
        "stratum": stratum,
        "weak_label": WEAK_POSITIVE if in_set else WEAK_UNLABELED,
    }


def build_pools(
    questions: Sequence[Mapping],
    notices: Sequence[Mapping],
    doc_versions: Mapping[str, str],
    title_hits: Mapping[str, Sequence[str]],
) -> dict[str, list[dict]]:
    """층별 (질문, 문서) 쌍 풀. 풀 안의 쌍은 pair id가 유일하다."""
    by_id = {str(n["nttId"]): n for n in notices}
    missing = sorted(set(by_id) - set(doc_versions), key=_ntt_key)
    if missing:
        raise ValueError(f"nttId without sha256 in KISA manifest: {missing}")
    products = {ntt: product_of(n["title"]) for ntt, n in by_id.items()}
    docs_by_product: dict[str, list[str]] = defaultdict(list)
    for ntt_id, product in sorted(products.items(), key=lambda kv: _ntt_key(kv[0])):
        if product:
            docs_by_product[product].append(ntt_id)

    pools: dict[str, list[dict]] = {STRATUM_JOIN: [], STRATUM_A: [], STRATUM_B: []}
    for question in questions:
        cve_id = question["cve_ids"][0]
        candidates = question["candidate_ntt_ids"]
        for ntt_id in candidates:
            pools[STRATUM_JOIN].append(
                _pair(question, by_id[ntt_id], doc_versions[ntt_id], STRATUM_JOIN)
            )
        for ntt_id in title_hits.get(cve_id, ()):
            pools[STRATUM_A].append(_pair(question, by_id[ntt_id], doc_versions[ntt_id], STRATUM_A))
        # 층 (b): 후보 문서와 같은 제품명을 제목에 가졌지만 이 CVE를 인용하지 않은 공지
        same_product = {
            ntt_id
            for candidate in candidates
            if products[candidate]
            for ntt_id in docs_by_product[products[candidate]]
        } - set(candidates)
        for ntt_id in sorted(same_product, key=_ntt_key):
            pools[STRATUM_B].append(_pair(question, by_id[ntt_id], doc_versions[ntt_id], STRATUM_B))
    return pools


def sample_balanced(pairs: Iterable[Mapping], quota: int, seed: int) -> list[dict]:
    """공지 단위로 균형을 맞춰 quota쌍을 뽑는다.

    공지를 seed 해시 순으로 세우고, 한 바퀴에 공지당 1쌍씩(해시 순으로 첫 쌍) 가져간다. 한 공지가
    인용 CVE의 대부분을 차지해도(996개) 표본이 그 공지로 쏠리지 않는다.
    """
    per_doc: dict[str, list[Mapping]] = defaultdict(list)
    for pair in pairs:
        per_doc[pair["doc_id"]].append(pair)
    queues = [
        sorted(per_doc[doc_id], key=lambda p: _rank(seed, p["candidate_pair_id"]))
        for doc_id in sorted(per_doc, key=lambda d: _rank(seed, f"doc:{d}"))
    ]
    picked: list[dict] = []
    depth = 0
    while len(picked) < quota and any(len(q) > depth for q in queues):
        for queue in queues:
            if len(picked) < quota and len(queue) > depth:
                picked.append(dict(queue[depth]))
        depth += 1
    return picked


def zero_reason(stratum: str, stats: Mapping[str, int], pool_pairs: int) -> str:
    """층에서 0건을 뽑았을 때의 사유 문장. 사유는 입력 수치에서 만들어서 입력이 바뀌면 같이 바뀐다."""
    if pool_pairs:
        return f"풀 {pool_pairs}쌍이 모두 앞 층에서 이미 뽑혀 이 층에 남은 쌍이 없다."
    if stratum == STRATUM_A:
        if stats["n_notices_with_cve_in_title"] == 0:
            return (
                f"공지 {stats['n_notices']}건 중 제목에 CVE ID가 든 공지가 0건이다. 제목은 '<제품명> 제품 보안 "
                "업데이트 권고' 같은 형식이라, 제목에는 있는데 cve_ids(본문 추출)에는 없는 공지가 생기지 않는다."
            )
        return (
            f"제목에 CVE ID가 든 공지 {stats['n_notices_with_cve_in_title']}건이 있지만 "
            "그 CVE가 모두 같은 공지의 cve_ids에도 있어 어긋나는 사례가 없다."
        )
    if stratum == STRATUM_B:
        if stats["n_notices_with_product_title"] == 0:
            return "제목에서 제품명을 뽑을 수 있는 공지가 0건이라 같은 제품명 공지 쌍이 없다."
        return (
            f"제품명 제목 공지 {stats['n_notices_with_product_title']}건이 있지만 후보 문서와 같은 제품명을 "
            "가진 다른 공지가 없다."
        )
    return "조인 후보 쌍이 없다(cve_ids를 가진 공지가 없다)."


def build_outputs(root: Path, seed: int = SEED) -> dict[str, str]:
    """root 기준 입력을 읽어 {상대 경로: 파일 내용}을 만든다. 같은 입력과 seed면 바이트까지 같다."""
    notices = load_notices(root / KISA_METADATA)
    parser_version, doc_versions = load_doc_versions(root / KISA_MANIFEST)
    nvd_ids = load_nvd_ids(root / NVD_CVES)

    cve_to_ntt = join_cve_to_notices(notices)
    title_hits = title_cve_not_cited(notices)
    questions = build_questions(cve_to_ntt, title_hits, nvd_ids)
    pools = build_pools(questions, notices, doc_versions, title_hits)

    stats = {
        "n_notices": len(notices),
        "n_notices_with_cve_ids": sum(1 for n in notices if n["cve_ids"]),
        "n_notices_with_product_title": sum(1 for n in notices if product_of(n["title"])),
        "n_notices_with_cve_in_title": sum(1 for n in notices if extract_cve_ids(n["title"])),
    }
    selected: dict[str, list[dict]] = {}
    taken: set[str] = set()
    for stratum, _layer, quota in sorted(STRATA, key=lambda s: s[1] == "base"):
        pool = [p for p in pools[stratum] if p["candidate_pair_id"] not in taken]
        selected[stratum] = sample_balanced(pool, quota, seed)
        taken.update(p["candidate_pair_id"] for p in selected[stratum])
    sample = [p for stratum, _l, _q in STRATA for p in selected[stratum]]
    if len(sample) < MIN_SAMPLE_PAIRS:
        raise ValueError(f"sample has {len(sample)} pairs, need at least {MIN_SAMPLE_PAIRS}")

    strata_manifest = []
    for stratum, layer, quota in STRATA:
        pool = pools[stratum]
        strata_manifest.append(
            {
                "stratum": stratum,
                "layer": layer,
                "quota": quota,
                "pool_pairs": len(pool),
                "pool_docs": len({p["doc_id"] for p in pool}),
                "selected": len(selected[stratum]),
                "zero_reason": (
                    zero_reason(stratum, stats, len(pool)) if not selected[stratum] else None
                ),
            }
        )
    manifest = {
        "protocol_version": PROTOCOL_VERSION,
        "status": "weak_candidate_not_human_verified",
        "generator": "scripts/build_label_candidates.py",
        "seed": seed,
        "kisa_parser_version": parser_version,
        "inputs": [
            {"path": rel, "sha256": file_sha256(root / rel)}
            for rel in (KISA_METADATA, KISA_MANIFEST, NVD_CVES)
        ],
        "excluded_content": ["kisa_body", "kisa_summary", "kisa_excerpt", "nvd_text"],
        "query_templates": list(QUERY_TEMPLATES),
        "join": {
            **stats,
            "n_unique_cves": len(cve_to_ntt),
            "n_cves_with_nvd_record": sum(1 for c in cve_to_ntt if c in nvd_ids),
            "n_cves_without_nvd_record": sum(1 for c in cve_to_ntt if c not in nvd_ids),
            "n_questions": len(questions),
            "n_candidate_pairs": len(pools[STRATUM_JOIN]),
            "method": "KISA metadata cve_ids와 NVD fixture id를 CVE ID 문자열로 조인. 질문 1개 = CVE 1개.",
        },
        "sampling": {
            "unit": "question-document pair",
            "method": (
                "층별 풀에서 공지(nttId)별 균형 추출. 선택 순서는 a, b, 조인 후보이며 앞 층에서 뽑은 쌍은 "
                "뒤 층 풀에서 뺀다. (b)는 후보 문서와 같은 제품명을 제목에 가졌지만 그 CVE를 cve_ids에 "
                "인용하지 않은 공지로, 조인이 놓친 문서를 점검하는 층이다."
            ),
            "ranking": "sha256(f'{seed}:{key}') 사전순. 공지는 key=doc:<nttId>, 쌍은 key=<pair id>",
            "per_document_policy": "한 바퀴에 공지당 1쌍을 가져가므로, 공지 하나가 둘째 쌍을 얻으려면 풀의 모든 공지가 첫 쌍을 얻어야 한다.",
            "min_pairs": MIN_SAMPLE_PAIRS,
            "n_pairs": len(sample),
            "strata": strata_manifest,
        },
    }

    review_rows = [review_row_for(pair, parser_version) for pair in sample]
    return {
        QUESTIONS_FILE: _jsonl(questions),
        PAIRS_FILE: _jsonl(sample),
        MANIFEST_FILE: json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        REVIEW_TEMPLATE_FILE: _csv([]),
        REVIEW_SHEET_FILE: _csv(review_rows),
    }


def _jsonl(rows: Iterable[Mapping]) -> str:
    return "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for row in rows
    )


def review_row_for(pair: Mapping, parser_version: str) -> dict[str, str]:
    """(질문, 문서) 쌍에서 검수 양식의 미리 채우는 칸을 만든다. 사람이 채울 칸은 비워 둔다."""
    row = {column: "" for column in REVIEW_COLUMNS}
    row.update(
        question_id=pair["candidate_question_id"],
        query_type=pair["query_type"],
        doc_id=pair["doc_id"],
        doc_sha256=pair["doc_sha256"],
        stratum=pair["stratum"],
        in_candidate_set="true" if pair["in_candidate_set"] else "false",
        weak_label=pair["weak_label"],
        evidence_parser_version=parser_version,
    )
    return row


def _csv(rows: Iterable[Mapping[str, str]]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=REVIEW_COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def write_outputs(root: Path, outputs: Mapping[str, str]) -> None:
    for rel, content in outputs.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")


def split_item(question: Mapping, split: str) -> dict:
    """후보 질문을 splits.assert_disjoint 입력(item)으로 옮긴다. 분할 배정은 #10에서 한다."""
    return {
        "id": question["candidate_question_id"],
        "split": split,
        "ntt_ids": list(question["candidate_ntt_ids"]),
        "cve_ids": list(question["cve_ids"]),
        "query": question["candidate_query"],
    }


# ---------------------------------------------------------------- 출력 필드 허용 목록


def _walk_keys(value: object) -> Iterable[str]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield key
            yield from _walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_keys(child)


def check_output_fields(path: Path, allowed: frozenset[str]) -> list[str]:
    """JSON/JSONL/CSV 출력 파일의 필드 이름이 허용 목록 안인지 본다. 위반 목록을 돌려준다."""
    if path.suffix == ".csv":
        with path.open(encoding="utf-8", newline="") as handle:
            keys = set(csv.DictReader(handle).fieldnames or ())
    elif path.suffix == ".jsonl":
        keys = {key for row in _read_jsonl(path) for key in _walk_keys(row)}
    else:
        keys = set(_walk_keys(json.loads(path.read_text(encoding="utf-8"))))
    return [f"{path.name}: field not allowed: {key}" for key in sorted(keys - allowed)]


def check_no_nvd_text(paths: Iterable[Path], cves_path: Path, min_len: int = 20) -> list[str]:
    """출력 파일에 NVD 설명 원문이 통째로 들어 있는지 본다(min_len자 이상인 설명만 비교)."""
    texts = {path: path.read_text(encoding="utf-8") for path in paths}
    errors = []
    for row in _read_jsonl(cves_path):
        snippet = row.get("description_en") or ""
        if len(snippet) < min_len:
            continue
        errors.extend(
            f"{path.name}: contains NVD text of {row['id']}"
            for path, text in texts.items()
            if snippet in text
        )
    return errors


# ---------------------------------------------------------------- 오류율 계산


def read_review_rows(path: Path) -> list[dict[str, str]]:
    # utf-8-sig: Excel이 "CSV UTF-8"로 저장하면 붙는 BOM을 헤더에서 걷어낸다
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = [c for c in REVIEW_COLUMNS if c not in (reader.fieldnames or ())]
        if missing:
            raise ReviewSheetError(f"missing columns: {missing}")
        rows = []
        for number, row in enumerate(reader, start=2):  # 헤더가 1행
            if None in row:  # 헤더보다 칸이 많다(따옴표 없는 쉼표 등)
                raise ReviewSheetError(f"row {number}: more fields than the header")
            rows.append({k: (v or "").strip() for k, v in row.items()})
        return rows


def _parse_bool(value: str, where: str) -> bool:
    """true/false를 대소문자 무시로 받는다(Excel은 TRUE/FALSE로 바꿔 저장한다)."""
    lowered = value.lower()
    if lowered not in ("true", "false"):
        raise ReviewSheetError(f"{where}: in_candidate_set must be true/false, got {value!r}")
    return lowered == "true"


def _check_sheet_consistency(
    row: Mapping[str, str], in_set: bool, seen: set[tuple[str, str]], where: str
) -> None:
    """(question_id, doc_id) 중복과 in_candidate_set이 stratum·weak_label과 모순되는 행을 거부한다."""
    key = (row["question_id"], row["doc_id"])
    if not all(key):
        raise ReviewSheetError(f"{where}: question_id and doc_id are required")
    if key in seen:
        raise ReviewSheetError(f"{where}: duplicate (question_id, doc_id) row")
    seen.add(key)
    stratum, weak_label = row["stratum"], row["weak_label"]
    if stratum:
        if stratum not in SOURCES:
            raise ReviewSheetError(f"{where}: unknown stratum {stratum!r}")
        if in_set != (stratum == STRATUM_JOIN):
            raise ReviewSheetError(
                f"{where}: in_candidate_set={str(in_set).lower()} contradicts stratum {stratum!r}"
            )
    if weak_label:
        if weak_label not in (WEAK_POSITIVE, WEAK_UNLABELED):
            raise ReviewSheetError(f"{where}: unknown weak_label {weak_label!r}")
        if in_set != (weak_label == WEAK_POSITIVE):
            raise ReviewSheetError(
                f"{where}: in_candidate_set={str(in_set).lower()} contradicts weak_label {weak_label!r}"
            )


def _expected_error_class(in_candidate_set: bool, relevant: bool) -> str:
    if in_candidate_set:
        return "ok" if relevant else "mislabel"
    return "omission" if relevant else "ok"


def _rate(n_error: int, n_reviewed: int) -> dict:
    return {
        "n_reviewed": n_reviewed,
        "n_error": n_error,
        "rate": n_error / n_reviewed if n_reviewed else None,
    }


def error_rates(rows: Iterable[Mapping[str, str]]) -> dict:
    """채워진 검수 행에서 오라벨률과 누락률을 따로 계산한다.

    - 오라벨률 = 후보 집합 안 쌍(in_candidate_set=true) 중 사람이 무관(not_relevant)으로 판정한 비율.
    - 누락률 = 후보 집합 밖 쌍(false, 층 a/b 점검 표본) 중 사람이 관련(relevant)으로 판정한 비율.
      후보 밖 표본에서 잰 값이라 코퍼스 전체 누락률이 아니다.
    판정(relevance)이 빈 행은 미검수(n_pending)로 센다. 분모가 0이면 rate는 None이다.
    판정 이유가 없거나, 관련인데 근거 위치가 없거나, 오류 구분이 판정과 모순되거나, (question_id, doc_id)가
    중복되거나, in_candidate_set이 stratum·weak_label과 모순되면 ReviewSheetError.
    """
    n_rows = n_pending = 0
    reviewed = {True: 0, False: 0}
    errors = {True: 0, False: 0}
    seen: set[tuple[str, str]] = set()
    for number, row in enumerate(rows, start=2):  # 헤더가 1행
        n_rows += 1
        where = f"row {number} ({row.get('question_id')}/{row.get('doc_id')})"
        in_set = _parse_bool(row["in_candidate_set"], where)
        _check_sheet_consistency(row, in_set, seen, where)
        relevance = row["relevance"]
        if not relevance:
            if row["error_class"]:
                raise ReviewSheetError(f"{where}: error_class without relevance")
            n_pending += 1
            continue
        if relevance not in RELEVANCE_VALUES:
            raise ReviewSheetError(f"{where}: relevance must be one of {RELEVANCE_VALUES}")
        if not row["reason"]:
            raise ReviewSheetError(f"{where}: reason is required for a reviewed row")
        relevant = relevance == "relevant"
        if relevant:
            try:
                start, end = int(row["evidence_start"]), int(row["evidence_end"])
            except ValueError:
                raise ReviewSheetError(
                    f"{where}: relevant row needs integer evidence_start/end"
                ) from None
            if not 0 <= start < end:
                raise ReviewSheetError(f"{where}: evidence must satisfy 0 <= start < end")
        expected = _expected_error_class(in_set, relevant)
        if row["error_class"] != expected:
            raise ReviewSheetError(
                f"{where}: error_class {row['error_class']!r} contradicts relevance "
                f"{relevance!r} / in_candidate_set={in_set} (expected {expected!r})"
            )
        reviewed[in_set] += 1
        errors[in_set] += expected != "ok"
    return {
        "n_rows": n_rows,
        "n_reviewed": reviewed[True] + reviewed[False],
        "n_pending": n_pending,
        "mislabel": _rate(errors[True], reviewed[True]),
        "omission": _rate(errors[False], reviewed[False]),
    }


# ---------------------------------------------------------------- 골든셋 스키마 검증


def _check_fields(obj: Mapping, allowed: frozenset[str], where: str) -> list[str]:
    errors = []
    for key in obj:
        if key in FORBIDDEN_TEXT_FIELDS:
            errors.append(f"{where}: body text field not allowed: {key}")
        elif key not in allowed:
            errors.append(f"{where}: unknown field: {key}")
    return errors


def _check_text(value: object, name: str, where: str) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return [f"{where}: {name} must be a non-empty string"]
    if len(value) > MAX_TEXT_LEN:
        return [f"{where}: {name} is longer than {MAX_TEXT_LEN} chars (body text?)"]
    return []


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_answer(
    answer: object,
    where: str,
    catalog: Mapping[str, Mapping] | None,
    doc_versions: Mapping[str, str] | None,
    parser_version: str | None,
) -> list[str]:
    if not isinstance(answer, Mapping):
        return [f"{where}: answer must be an object"]
    errors = _check_fields(answer, GOLDEN_ANSWER_FIELDS, where)
    doc_id = answer.get("doc_id")
    if not isinstance(doc_id, str) or not doc_id:
        errors.append(f"{where}: doc_id is required")
    elif catalog is not None and doc_id not in catalog:
        errors.append(f"{where}: doc_id {doc_id} not in notice catalog")
    sha = answer.get("doc_sha256")
    if not isinstance(sha, str) or not _SHA256_RE.fullmatch(sha):
        errors.append(f"{where}: doc_sha256 must be 64 lowercase hex chars")
    elif doc_versions is not None and doc_versions.get(str(doc_id)) != sha:
        errors.append(f"{where}: doc_sha256 does not match the KISA manifest for {doc_id}")
    errors.extend(_check_text(answer.get("reason"), "reason", where))
    evidence = answer.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append(f"{where}: evidence must be a non-empty list")
        return errors
    for index, span in enumerate(evidence):
        span_where = f"{where}.evidence[{index}]"
        if not isinstance(span, Mapping):
            errors.append(f"{span_where}: must be an object")
            continue
        errors.extend(_check_fields(span, GOLDEN_EVIDENCE_FIELDS, span_where))
        if "nttId" in span and str(span["nttId"]) != str(doc_id):
            errors.append(f"{span_where}: nttId {span['nttId']!r} != doc_id {doc_id!r}")
        start, end = span.get("start"), span.get("end")
        if not (_is_int(start) and _is_int(end) and 0 <= start < end):
            errors.append(f"{span_where}: start/end must be ints with 0 <= start < end")
        if "judge" in span and span["judge"] not in ("A", "B"):
            errors.append(f"{span_where}: judge must be A or B")
        version = span.get("parser_version")
        if not isinstance(version, str) or not version:
            errors.append(f"{span_where}: parser_version is required")
        elif parser_version is not None and version != parser_version:
            errors.append(f"{span_where}: parser_version {version!r} != {parser_version!r}")
    return errors


def _check_unjudged(
    unjudged: object, answer_ids: Sequence[str], catalog: Mapping[str, Mapping] | None, where: str
) -> list[str]:
    """unjudged = 판정이 갈리거나 근거가 없어 정답으로도 비관련으로도 정하지 못한 문서 ID 목록."""
    if not isinstance(unjudged, list):
        return [f"{where}: unjudged must be a list of document IDs"]
    errors = []
    for doc_id in unjudged:
        if not isinstance(doc_id, str) or not doc_id:
            errors.append(f"{where}: unjudged entries must be non-empty strings")
        elif catalog is not None and doc_id not in catalog:
            errors.append(f"{where}: unjudged doc_id {doc_id} not in notice catalog")
        elif doc_id in answer_ids:
            errors.append(f"{where}: doc_id {doc_id} is both in answers and unjudged")
    if len({d for d in unjudged if isinstance(d, str)}) != len(unjudged):
        errors.append(f"{where}: duplicate doc_id in unjudged")
    return errors


def _check_record(
    record: object,
    catalog: Mapping[str, Mapping] | None,
    doc_versions: Mapping[str, str] | None,
    parser_version: str | None,
) -> list[str]:
    if not isinstance(record, Mapping):
        return ["record must be an object"]
    where = f"record {record.get('question_id')!r}"
    errors = _check_fields(record, GOLDEN_RECORD_FIELDS, where)
    errors.extend(_check_text(record.get("question_id"), "question_id", where))
    query = record.get("query")
    errors.extend(_check_text(query, "query", where))
    query_type = record.get("query_type")
    if query_type not in QUERY_TYPES:
        errors.append(f"{where}: query_type must be one of {QUERY_TYPES}")
    for cve_id in record.get("cve_ids", ()) if isinstance(record.get("cve_ids", ()), list) else ():
        if not isinstance(cve_id, str) or not CVE_ID_RE.fullmatch(cve_id):
            errors.append(f"{where}: malformed CVE ID {cve_id!r}")
    if not isinstance(record.get("cve_ids", []), list):
        errors.append(f"{where}: cve_ids must be a list")
    if record.get("split") not in (None, "dev", "test"):
        errors.append(f"{where}: split must be dev or test")

    answers = record.get("answers")
    if not isinstance(answers, list):
        return [*errors, f"{where}: answers must be a list (empty for no_answer)"]
    for index, answer in enumerate(answers):
        errors.extend(
            _check_answer(
                answer, f"{where}.answers[{index}]", catalog, doc_versions, parser_version
            )
        )
    # 형식 오류(배열·객체 등)인 ID는 위에서 이미 보고했다. 중복 검사는 문자열 ID만 본다(unhashable 방지)
    doc_ids = [
        a["doc_id"] for a in answers if isinstance(a, Mapping) and isinstance(a.get("doc_id"), str)
    ]
    if len(set(doc_ids)) != len(doc_ids):
        errors.append(f"{where}: duplicate doc_id in answers")
    excluded = record.get("excluded", False)
    if not isinstance(excluded, bool):
        errors.append(f"{where}: excluded must be a bool")
        excluded = False
    errors.extend(_check_unjudged(record.get("unjudged", []), doc_ids, catalog, where))
    if excluded and answers:
        errors.append(f"{where}: excluded record must have empty answers")

    # 질의 유형 규칙(eval-protocol 5절): G가 비면 no_answer, 문장에 CVE가 있으면 cve_explicit
    surface_cve = isinstance(query, str) and bool(extract_cve_ids(query))
    # 5절 1항: 표면에 CVE가 있었는지는 별도 속성 surface_cve(bool)로 남긴다. 있으면 질의 문장과 일치해야 한다
    if "surface_cve" in record:
        declared = record["surface_cve"]
        if not isinstance(declared, bool):
            errors.append(f"{where}: surface_cve must be a bool")
        elif isinstance(query, str) and declared != surface_cve:
            errors.append(f"{where}: surface_cve {declared} contradicts the query text")
    if query_type == "no_answer":
        if answers:
            errors.append(f"{where}: no_answer must have empty answers")
        if excluded:
            errors.append(f"{where}: no_answer is never excluded")
        errors.extend(_check_text(record.get("no_answer_reason"), "no_answer_reason", where))
    elif query_type in QUERY_TYPES:
        if not answers and not excluded:
            errors.append(f"{where}: {query_type} needs at least one answer (empty G is no_answer)")
        if "no_answer_reason" in record:
            errors.append(f"{where}: no_answer_reason only belongs to no_answer")
        if query_type == "cve_explicit" and not surface_cve:
            errors.append(f"{where}: cve_explicit query has no CVE ID")
        if query_type != "cve_explicit" and surface_cve:
            errors.append(f"{where}: query with a CVE ID must be cve_explicit")
    return errors


def validate_golden(
    records: Sequence[object],
    *,
    notices: Sequence[Mapping] | None = None,
    doc_versions: Mapping[str, str] | None = None,
    parser_version: str | None = None,
) -> list[str]:
    """골든셋 레코드의 스키마 위반 목록(비어 있으면 통과).

    필수: 질문 ID, 질의 유형 태그, 질의 문장, 정답마다 문서 ID·버전 해시(sha256)·근거 위치(1개 이상)·판정 이유.
    본문 텍스트 필드(body, text, excerpt, summary, description 등)와 허용 목록 밖 필드는 거부한다.
    notices가 있으면 문서 ID가 카탈로그에 있는지, doc_versions가 있으면 해시가 manifest와 같은지 본다.
    레코드에 split이 하나라도 있으면 모두 있어야 하고, splits.assert_disjoint로 dev/test 누수를 검사한다.
    """
    catalog = {str(n["nttId"]): n for n in notices} if notices is not None else None
    errors: list[str] = []
    seen: set[str] = set()
    for record in records:
        errors.extend(_check_record(record, catalog, doc_versions, parser_version))
        if isinstance(record, Mapping):
            qid = record.get("question_id")
            if isinstance(qid, str) and qid in seen:
                errors.append(f"duplicate question_id: {qid!r}")
            if isinstance(qid, str):
                seen.add(qid)
    if errors:
        return errors

    splits = [r.get("split") for r in records]
    if any(splits):
        if not all(splits):
            return ["split must be set on every record or on none"]
        if notices is None:
            return ["notices are required for the dev/test split check"]
        items = [
            {
                "id": r["question_id"],
                "split": r["split"],
                "ntt_ids": [a["doc_id"] for a in r["answers"]],
                "cve_ids": r.get("cve_ids", []),
                "query": r["query"],
            }
            for r in records
        ]
        try:
            assert_disjoint(items, notices)
        except (SplitLeakError, ValueError) as exc:
            errors.append(f"split check failed: {exc}")
    return errors


def assert_valid_golden(records: Sequence[object], **kwargs) -> None:
    errors = validate_golden(records, **kwargs)
    if errors:
        raise GoldenSchemaError(errors)


def check_golden_v1(records: Sequence[Mapping]) -> list[str]:
    """골든셋 v1 요구 위반 목록(비어 있으면 통과). 스키마 검증(validate_golden)과는 따로 부른다.

    모든 레코드에 split, 채점 대상(excluded 아님) 50문항 이상, 유형별 최소 건수,
    채점 대상 기준 dev 비율 30~50%.
    """
    errors = [
        f"record {r.get('question_id')!r}: split is missing"
        for r in records
        if r.get("split") not in ("dev", "test")
    ]
    scored = [r for r in records if not r.get("excluded")]
    if len(scored) < V1_MIN_SCORED:
        errors.append(f"scored records {len(scored)} < {V1_MIN_SCORED}")
    for query_type, minimum in V1_MIN_PER_TYPE.items():
        count = sum(1 for r in scored if r.get("query_type") == query_type)
        if count < minimum:
            errors.append(f"scored {query_type} records {count} < {minimum}")
    if scored:
        share = sum(1 for r in scored if r.get("split") == "dev") / len(scored)
        low, high = V1_DEV_SHARE_RANGE
        if not low <= share <= high:
            errors.append(f"dev share {share:.3f} outside {low:.2f}..{high:.2f}")
    return errors


# ---------------------------------------------------------------- CLI


def _default_root() -> Path:
    return Path.cwd()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="krsec_rag_lab.golden", description=__doc__.splitlines()[0]
    )
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="후보·표본·검수 양식을 생성한다")
    build.add_argument("--root", type=Path, default=_default_root())
    build.add_argument("--seed", type=int, default=SEED)
    rates = commands.add_parser(
        "error-rates", help="채워진 검수 CSV에서 오라벨률·누락률을 계산한다"
    )
    rates.add_argument("review_csv", type=Path)
    check = commands.add_parser("validate", help="골든셋 JSONL을 스키마 검증기로 검사한다")
    check.add_argument("golden_jsonl", type=Path)
    check.add_argument("--root", type=Path, default=_default_root())
    args = parser.parse_args(argv)

    if args.command == "build":
        outputs = build_outputs(args.root, args.seed)
        write_outputs(args.root, outputs)
        manifest = json.loads(outputs[MANIFEST_FILE])
        pairs = manifest["sampling"]["n_pairs"]
        print(
            f"wrote {len(outputs)} files; questions={manifest['join']['n_questions']} sample_pairs={pairs}"
        )
        return 0
    try:
        if args.command == "error-rates":
            rates_result = error_rates(read_review_rows(args.review_csv))
            print(json.dumps(rates_result, ensure_ascii=False, indent=2))
            return 0
        notices = load_notices(args.root / KISA_METADATA)
        parser_version, doc_versions = load_doc_versions(args.root / KISA_MANIFEST)
        errors = validate_golden(
            _read_jsonl(args.golden_jsonl),
            notices=notices,
            doc_versions=doc_versions,
            parser_version=parser_version,
        )
    except (ValueError, OSError) as exc:
        # 사람이 채운 검수 입력의 오류는 traceback 대신 한 줄 사유와 exit 1로 알린다
        # (ReviewSheetError, 깨진 JSONL, 없는 파일 등)
        print(f"error: {' '.join(str(exc).split())}", file=sys.stderr)
        return 1
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

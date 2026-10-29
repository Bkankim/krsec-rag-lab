"""공통 채점 - docs/eval-protocol.md 1절(condensed list), 5절(유형·macro), 7절(경계조건·기권·동점).

검색기가 낸 점수 딕셔너리를 (점수 내림차순, 문서 ID 오름차순)으로 정렬해 전체 순위를 만들고(7.4),
그 질문의 `unjudged`를 순위에서 지운 목록(condensed list)의 상위 100건을 질문별 결과 레코드로 저장한다.
지표는 metrics.py를 그대로 쓰고 이 레코드(와 질의셋의 정답·유형·분할)만으로 계산한다. 그래서
`metrics.json`은 저장된 결과 파일만으로 다시 계산할 수 있다.

결과 레코드의 허용 필드(LICENSES/README.md "본문 유출 방지 점검 대상"): 질문 ID, 순위·문서 ID·점수, 지우기 전
원래 1위 점수(`top1_score_raw`), 지운 문서 수(`n_unjudged_removed`). 문서·질의 본문은 넣지 않는다.

기권(7.3)은 condensed list가 아니라 지우기 전 원래 1위 점수(`top1_score_raw`)를 쓴다. 결과가 비었으면
None이고 기권이다.
"""

import math
from collections.abc import Collection, Mapping, Sequence

from krsec_rag_lab.baselines.data import QUERY_TYPES, Question
from krsec_rag_lab.metrics import (
    abstain_rate,
    false_abstain_rate,
    hit_at_k,
    macro_mean,
    mean_defined,
    ndcg_at_k,
    recall_at_k,
    reciprocal_rank_at_k,
    sort_by_score,
)

PROTOCOL_VERSION = "eval-protocol-v2"
RESULT_TOP_N = 100
KS = (1, 5, 10)
OBSERVATION_ONLY_BELOW = 10  # 5절: n_scored < 10인 유형은 우열 판정에 쓰지 않는다
RECORD_FIELDS = frozenset({"question_id", "top1_score_raw", "n_unjudged_removed", "results"})
RESULT_FIELDS = frozenset({"doc_id", "rank", "score"})
METRIC_NAMES = (
    *(f"hit@{k}" for k in KS),
    *(f"recall@{k}" for k in KS),
    "mrr@10",
    "ndcg@10",
)


def make_record(question_id: str, scores: Mapping[str, float], unjudged: Collection[str]) -> dict:
    """점수 -> 전체 순위 -> unjudged 제거(condensed) -> 상위 100건 레코드."""
    ranking = sort_by_score(scores)
    condensed = [doc_id for doc_id in ranking if doc_id not in unjudged]
    return {
        "question_id": question_id,
        "top1_score_raw": float(scores[ranking[0]]) if ranking else None,
        "n_unjudged_removed": len(ranking) - len(condensed),
        "results": [
            {"doc_id": doc_id, "rank": rank, "score": float(scores[doc_id])}
            for rank, doc_id in enumerate(condensed[:RESULT_TOP_N], start=1)
        ],
    }


def validate_record(record: Mapping) -> None:
    """허용 필드 밖의 키, 순위·점수 순서 위반이 있으면 ValueError (본문 유출 경로 차단)."""
    if set(record) != RECORD_FIELDS:
        raise ValueError(f"record fields {sorted(record)} != allowed {sorted(RECORD_FIELDS)}")
    if not isinstance(record["question_id"], str):
        raise ValueError("question_id must be a string")  # noqa: TRY004 - 입력 오류는 ValueError로 통일
    top1 = record["top1_score_raw"]
    if top1 is not None and (not isinstance(top1, float) or not math.isfinite(top1)):
        raise ValueError("top1_score_raw must be a finite float or null")
    removed = record["n_unjudged_removed"]
    if not isinstance(removed, int) or isinstance(removed, bool) or removed < 0:
        raise ValueError("n_unjudged_removed must be a non-negative int")
    results = record["results"]
    if len(results) > RESULT_TOP_N:
        raise ValueError(f"more than {RESULT_TOP_N} results")
    previous: tuple[float, str] | None = None
    seen: set[str] = set()
    for rank, item in enumerate(results, start=1):
        if set(item) != RESULT_FIELDS:
            raise ValueError(f"result fields {sorted(item)} != allowed {sorted(RESULT_FIELDS)}")
        if item["rank"] != rank or not isinstance(item["doc_id"], str):
            raise ValueError(f"rank/doc_id malformed at position {rank}")
        if not isinstance(item["score"], float) or not math.isfinite(item["score"]):
            raise ValueError(f"score must be a finite float at rank {rank}")
        if item["doc_id"] in seen:
            raise ValueError(f"duplicate doc_id {item['doc_id']}")
        seen.add(item["doc_id"])
        key = (-item["score"], item["doc_id"])
        if previous is not None and key < previous:
            raise ValueError(f"results not sorted by (-score, doc_id) at rank {rank}")
        previous = key
    if results and top1 is None:
        raise ValueError("top1_score_raw is null but results are not empty")
    if top1 is not None and results and results[0]["score"] > top1:
        raise ValueError("condensed top score exceeds top1_score_raw")


def question_values(record: Mapping, gold: Collection[str]) -> dict[str, float | None]:
    """한 질문의 지표 값. 정답이 없는 질문(no_answer)은 전부 None이다(7.3)."""
    ranked = [item["doc_id"] for item in record["results"]]
    values: dict[str, float | None] = {}
    for k in KS:
        values[f"hit@{k}"] = hit_at_k(ranked, gold, k)
    for k in KS:
        values[f"recall@{k}"] = recall_at_k(ranked, gold, k)
    values["mrr@10"] = reciprocal_rank_at_k(ranked, gold, 10)
    values["ndcg@10"] = ndcg_at_k(ranked, gold, 10)
    return values


def tie_at_cutoff(record: Mapping, k: int) -> bool:
    """condensed list의 k위와 k+1위 점수가 같으면 True (7.4)."""
    results = record["results"]
    return len(results) > k and results[k - 1]["score"] == results[k]["score"]


def select_tau(
    no_answer_top1: Sequence[float | None], answerable_top1: Sequence[float | None]
) -> dict:
    """기권 임계값 τ를 dev의 원래 1위 점수로 고른다(검색기마다, dev에서만).

    후보 = dev 질문들의 1위 점수 값들. 기준 = abstain_rate - false_abstain_rate(Youden J)를 최대화하고,
    같으면 가장 낮은 τ(기권을 덜 하는 쪽)다. 결과가 빈 질문(None)은 τ와 무관하게 기권이다(7.3).
    두 집합 중 하나라도 비면 ValueError다. 점수 후보가 하나도 없으면 τ = 0.0이다.
    """
    if not no_answer_top1 or not answerable_top1:
        raise ValueError("tau selection needs dev no_answer and answerable questions")
    candidates = sorted({s for s in (*no_answer_top1, *answerable_top1) if s is not None})
    best: tuple[float, float] | None = None
    for tau in candidates or [0.0]:
        rate = abstain_rate(no_answer_top1, tau)
        false_rate = false_abstain_rate(answerable_top1, tau)
        assert rate is not None
        assert false_rate is not None
        j = rate - false_rate
        if best is None or j > best[0]:
            best = (j, tau)
    assert best is not None
    tau = best[1]
    return {
        "tau": tau,
        "rule": "dev에서 abstain_rate - false_abstain_rate 최대, 같으면 가장 낮은 tau",
        "dev_j": best[0],
        "dev_abstain_rate": abstain_rate(no_answer_top1, tau),
        "dev_false_abstain_rate": false_abstain_rate(answerable_top1, tau),
        "n_candidates": len(candidates),
    }


def evaluate_split(
    records: Mapping[str, Mapping],
    questions: Sequence[Question],
    split: str,
    tau: float | None,
) -> dict:
    """한 분할의 유형별 지표, macro, no_answer 표. 저장된 레코드와 질의셋 라벨만 쓴다."""
    in_split = [q for q in questions if q.split == split]
    scored = [q for q in in_split if not q.excluded]
    values: dict[str, dict[str, list[float | None]]] = {}
    top1: dict[str, list[float | None]] = {}
    ties: dict[str, dict[int, int]] = {}
    for question in scored:
        record = records[question.question_id]
        by_metric = values.setdefault(question.query_type, {m: [] for m in METRIC_NAMES})
        for metric, value in question_values(record, question.gold).items():
            by_metric[metric].append(value)
        top1.setdefault(question.query_type, []).append(record["top1_score_raw"])
        type_ties = ties.setdefault(question.query_type, dict.fromkeys(KS, 0))
        if question.gold:
            for k in KS:
                type_ties[k] += tie_at_cutoff(record, k)

    by_type: dict[str, dict] = {}
    for query_type in QUERY_TYPES:
        type_scored = [q for q in scored if q.query_type == query_type]
        n_excluded = sum(1 for q in in_split if q.excluded and q.query_type == query_type)
        if not type_scored and not n_excluded:
            continue
        metric_values = values.get(query_type, {m: [] for m in METRIC_NAMES})
        count = mean_defined(metric_values["ndcg@10"])
        by_type[query_type] = {
            "n_questions": len(type_scored),
            "n_excluded": n_excluded,
            "n_scored": count.n_scored,
            "n_skipped": count.n_skipped,
            "observation_only": 0 < count.n_scored < OBSERVATION_ONLY_BELOW,
            "metrics": {m: mean_defined(metric_values[m]).mean for m in METRIC_NAMES},
            "tie_at_cutoff": (
                {f"@{k}": ties[query_type][k] for k in KS} if count.n_scored else None
            ),
        }

    macro = {
        metric: macro_mean({t: v[metric] for t, v in values.items()}) for metric in METRIC_NAMES
    }
    answerable_top1 = [records[q.question_id]["top1_score_raw"] for q in scored if q.gold]
    no_answer_top1 = top1.get("no_answer", [])
    no_answer = {
        "n_no_answer": len(no_answer_top1),
        "n_answerable": len(answerable_top1),
        "tau": tau,
        "abstain_rate": abstain_rate(no_answer_top1, tau) if tau is not None else None,
        "false_abstain_rate": (
            false_abstain_rate(answerable_top1, tau) if tau is not None else None
        ),
    }
    return {
        "n_questions": len(scored),
        "n_excluded": len(in_split) - len(scored),
        "macro": macro,
        "macro_n_types": sum(1 for t in by_type.values() if t["n_scored"]),
        "by_type": by_type,
        "no_answer": no_answer,
    }

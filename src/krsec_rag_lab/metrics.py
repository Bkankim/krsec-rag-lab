"""검색 지표 - docs/eval-protocol.md 2~4절의 정의와 7절의 경계조건을 구현한다.

입력은 접힌 문서 순위 목록(1위부터)과 정답 집합 G뿐이다(7.1). 점수는 받지 않는다. 동점 처리와
청크 -> 문서 접기는 지표 함수 앞단(하네스)의 일이다. `sort_by_score`는 7.4의 동점 규칙
`(-score, doc_id)`을 그대로 옮긴 보조 함수다.

- 정답이 없는 질의(G가 비어 있음)는 hit·recall·RR·nDCG가 정의되지 않으므로 None을 돌려준다.
- 빈 검색 결과는 정답이 있는 질의에서 0점이다(건너뛰지 않는다).
- k <= 0, ranked 안의 중복 ID는 ValueError다.

표준 라이브러리만 쓴다.
"""

import math
from collections.abc import Hashable, Iterable, Mapping, Sequence
from dataclasses import dataclass


def _validate(ranked: Sequence[str], k: int) -> None:
    if isinstance(ranked, str | bytes):
        raise ValueError("ranked must be a sequence of ids, not a single str/bytes")  # noqa: TRY004 - 입력 오류는 ValueError로 통일(7.1)
    if k <= 0:
        raise ValueError(f"k must be positive, got {k}")
    if len(set(ranked)) != len(ranked):
        raise ValueError("ranked contains duplicate ids; fold duplicates before scoring")


def _gold_set(gold: Iterable[str]) -> set[str]:
    if isinstance(gold, str | bytes):
        raise ValueError("gold must be an iterable of ids, not a single str/bytes")  # noqa: TRY004 - 입력 오류는 ValueError로 통일(7.1)
    return set(gold)


def hit_at_k(ranked: Sequence[str], gold: Iterable[str], k: int) -> float | None:
    """top-k 안에 정답이 하나라도 있으면 1.0, 없으면 0.0. G가 비면 None."""
    _validate(ranked, k)
    gold_set = _gold_set(gold)
    if not gold_set:
        return None
    return 1.0 if gold_set.intersection(ranked[:k]) else 0.0


def recall_at_k(ranked: Sequence[str], gold: Iterable[str], k: int) -> float | None:
    """|G ∩ top_k| / |G|. 분모는 min(|G|, k)가 아니라 |G|다. G가 비면 None."""
    _validate(ranked, k)
    gold_set = _gold_set(gold)
    if not gold_set:
        return None
    return len(gold_set.intersection(ranked[:k])) / len(gold_set)


def reciprocal_rank_at_k(ranked: Sequence[str], gold: Iterable[str], k: int) -> float | None:
    """첫 정답의 순위가 k 이내이면 1/순위, 아니면 0.0. G가 비면 None. MRR@k의 한 질의 값."""
    _validate(ranked, k)
    gold_set = _gold_set(gold)
    if not gold_set:
        return None
    for rank, doc_id in enumerate(ranked[:k], start=1):
        if doc_id in gold_set:
            return 1.0 / rank
    return 0.0


def ndcg_at_k(ranked: Sequence[str], gold: Iterable[str], k: int) -> float | None:
    """이진 라벨 nDCG@k. gain = rel(0 또는 1), 할인 = 1/log2(i+1). G가 비면 None.

    IDCG는 min(|G|, k)개 항이라 정답 수가 k보다 많아도 완벽한 순위가 1.0을 받는다.
    """
    _validate(ranked, k)
    gold_set = _gold_set(gold)
    if not gold_set:
        return None
    dcg = sum(
        1.0 / math.log2(rank + 1)
        for rank, doc_id in enumerate(ranked[:k], start=1)
        if doc_id in gold_set
    )
    idcg = sum(1.0 / math.log2(rank + 1) for rank in range(1, min(len(gold_set), k) + 1))
    return dcg / idcg


@dataclass(frozen=True)
class MeanResult:
    """정의된(None이 아닌) 질의만 평균한 결과. 보고에는 n_scored와 n_skipped를 함께 적는다."""

    mean: float | None
    n_scored: int
    n_skipped: int


def mean_defined(values: Iterable[float | None]) -> MeanResult:
    """None(정답 없음)은 평균에서 제외하고, 0.0(빈 결과 포함)은 평균에 넣는다."""
    items = list(values)
    defined = [value for value in items if value is not None]
    mean = sum(defined) / len(defined) if defined else None
    return MeanResult(mean=mean, n_scored=len(defined), n_skipped=len(items) - len(defined))


def mrr_at_k(queries: Iterable[tuple[Sequence[str], Iterable[str]]], k: int) -> MeanResult:
    """MRR@k. queries는 (ranked, gold) 쌍의 목록이고 RR@k의 질의 평균을 낸다."""
    return mean_defined(reciprocal_rank_at_k(ranked, gold, k) for ranked, gold in queries)


def macro_mean(per_type: Mapping[Hashable, Iterable[float | None]]) -> float | None:
    """유형별 평균의 단순 평균(5절). 채점 질의가 0건인 유형은 빼고 분모는 남은 유형 수다."""
    type_means = [mean_defined(values).mean for values in per_type.values()]
    scored = [mean for mean in type_means if mean is not None]
    return sum(scored) / len(scored) if scored else None


def ann_recall_at_k(exact: Sequence[str], ann: Sequence[str], k: int) -> float | None:
    """|ANN_k ∩ Exact_k| / |Exact_k| (4절). ID는 청크 ID이고 relevance 라벨과 무관하다.

    분모는 전수 검색이 실제로 돌려준 개수(최대 k)다. Exact가 비어 있으면 정의되지 않아 None이다.
    """
    _validate(exact, k)
    _validate(ann, k)
    exact_k = exact[:k]
    if not exact_k:
        return None
    return len(set(exact_k).intersection(ann[:k])) / len(exact_k)


def abstain(top_score: float | None, tau: float) -> int:
    """검색 단계 기권(7.3). 결과가 비었거나 1위 점수 < tau이면 1, 같거나 높으면 0."""
    return 1 if top_score is None or top_score < tau else 0


def abstain_rate(top_scores: Iterable[float | None], tau: float) -> float | None:
    """답 없음 질의들의 abstain 평균(높을수록 좋음). top_scores는 질의별 1위 점수, 빈 결과는 None."""
    return mean_defined(float(abstain(score, tau)) for score in top_scores).mean


def false_abstain_rate(top_scores: Iterable[float | None], tau: float) -> float | None:
    """정답이 있는 질의들의 abstain 평균(낮을수록 좋음). 계산은 abstain_rate와 같고 질의 집합만 다르다."""
    return abstain_rate(top_scores, tau)


def sort_by_score(scores: Mapping[str, float]) -> list[str]:
    """문서 점수를 `(-score, doc_id)` 오름차순으로 정렬해 결정적인 순위를 만든다(7.4).

    NaN 점수는 비교가 항상 False라 입력 순서에 따라 순위가 달라지므로 ValueError다.
    """
    if any(math.isnan(score) for score in scores.values()):
        raise ValueError("scores contain NaN; the order would depend on input order")
    return sorted(scores, key=lambda doc_id: (-scores[doc_id], doc_id))

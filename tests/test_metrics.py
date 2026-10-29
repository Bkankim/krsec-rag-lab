"""지표 테스트. 입력은 전부 합성이다(d1~d9는 가짜 문서 ID).

기대값은 docs/eval-protocol.md 7절의 표를 그대로 옮겼다. 케이스 id는 표의 행 ID(B1, N1, A1, T1, R1 ...)와
같다. 표의 값은 소수 4자리 반올림이므로 허용오차는 abs=1e-4다.
"""

import math

import pytest

from krsec_rag_lab.metrics import (
    abstain,
    ann_recall_at_k,
    hit_at_k,
    macro_mean,
    mean_defined,
    mrr_at_k,
    ndcg_at_k,
    recall_at_k,
    reciprocal_rank_at_k,
    sort_by_score,
)

TOL = 1e-4


def all_four(ranked, gold, k):
    return (
        hit_at_k(ranked, gold, k),
        recall_at_k(ranked, gold, k),
        reciprocal_rank_at_k(ranked, gold, k),
        ndcg_at_k(ranked, gold, k),
    )


# --- 수계산 예제 3건 ---------------------------------------------------------------------------
# 할인 계수: 1/log2(i+1) -> 1위 1.0, 2위 0.6309, 3위 0.5, 4위 0.4307, 5위 0.3869


def test_hand_example_1_partial_recall_in_the_middle():
    # ranked d3 d1 d5 d2 d8, G = {d1, d2, d9}, k = 5
    # top_5 안의 정답: d1(2위), d2(4위). d9는 목록에 없다.
    # hit    = 1 (정답이 하나 이상)
    # recall = 2 / 3 = 0.6667
    # RR     = 1 / 2 = 0.5 (첫 정답이 2위)
    # DCG    = 1/log2(3) + 1/log2(5) = 0.6309 + 0.4307 = 1.0616
    # IDCG   = min(3, 5) = 3개 항 = 1 + 0.6309 + 0.5 = 2.1309
    # nDCG   = 1.0616 / 2.1309 = 0.4982
    hit, recall, rr, ndcg = all_four(["d3", "d1", "d5", "d2", "d8"], {"d1", "d2", "d9"}, 5)
    assert hit == 1
    assert recall == pytest.approx(2 / 3, abs=TOL)
    assert rr == pytest.approx(0.5, abs=TOL)
    assert ndcg == pytest.approx(0.4982, abs=TOL)


def test_hand_example_2_mrr_over_four_queries_with_empty_result_and_no_answer():
    # k = 10, 질의 네 개
    #   q1: ranked d4 d1,        G = {d4}  -> RR = 1 / 1 = 1.0
    #   q2: ranked d5 d6 d7 d1,  G = {d1}  -> RR = 1 / 4 = 0.25
    #   q3: ranked (빈 목록),     G = {d1}  -> RR = 0.0 (빈 결과는 0점으로 평균에 포함)
    #   q4: ranked d1 d2,        G = {}    -> 정의되지 않음, 평균에서 제외
    # MRR@10 = (1.0 + 0.25 + 0.0) / 3 = 0.4167, n_scored = 3, n_skipped = 1
    queries = [
        (["d4", "d1"], {"d4"}),
        (["d5", "d6", "d7", "d1"], {"d1"}),
        ([], {"d1"}),
        (["d1", "d2"], set()),
    ]
    result = mrr_at_k(queries, 10)
    assert result.mean == pytest.approx(0.4167, abs=TOL)
    assert (result.n_scored, result.n_skipped) == (3, 1)
    # 같은 질의를 k = 3으로 자르면 q2의 정답(4위)이 밖으로 나가 RR = 0 -> (1 + 0 + 0) / 3
    assert mrr_at_k(queries, 3).mean == pytest.approx(1 / 3, abs=TOL)


def test_hand_example_3_ndcg_when_gold_is_larger_than_k():
    # ranked d1 d9 d2 d8, G = {d1, d2, d3, d4, d5}, k = 4
    # DCG    = 1 (1위) + 1/log2(4) (3위) = 1 + 0.5 = 1.5
    # IDCG   = min(5, 4) = 4개 항 = 1 + 0.6309 + 0.5 + 0.4307 = 2.5616
    # nDCG   = 1.5 / 2.5616 = 0.5856
    # recall = 2 / 5 = 0.4 (분모는 min(|G|, k)가 아니라 |G|), hit = 1, RR = 1.0
    hit, recall, rr, ndcg = all_four(["d1", "d9", "d2", "d8"], {"d1", "d2", "d3", "d4", "d5"}, 4)
    assert hit == 1
    assert recall == pytest.approx(0.4, abs=TOL)
    assert rr == pytest.approx(1.0, abs=TOL)
    assert ndcg == pytest.approx(0.5856, abs=TOL)


# --- 7.2 answerable 질의 (B1~B8) ---------------------------------------------------------------

ANSWERABLE = [
    pytest.param(["d2", "d7", "d9"], {"d2"}, 3, 1, 1.0, 1.0, 1.0, id="B1"),
    pytest.param(["d7", "d9", "d2"], {"d2"}, 3, 1, 1.0, 0.3333, 0.5, id="B2"),
    pytest.param(["d7", "d2", "d9"], {"d2", "d4"}, 3, 1, 0.5, 0.5, 0.3869, id="B3"),
    pytest.param(["d4", "d2", "d9"], {"d2", "d4"}, 3, 1, 1.0, 1.0, 1.0, id="B4"),
    pytest.param(["d7", "d4", "d2"], {"d2", "d4"}, 3, 1, 1.0, 0.5, 0.6934, id="B4b"),
    pytest.param(["d1", "d2", "d3"], {"d1", "d2", "d3", "d4"}, 3, 1, 0.75, 1.0, 1.0, id="B5"),
    pytest.param(["d7", "d8", "d9", "d2"], {"d2"}, 3, 0, 0.0, 0.0, 0.0, id="B6"),
    pytest.param(["d7", "d8", "d9", "d2"], {"d2"}, 4, 1, 1.0, 0.25, 0.4307, id="B6b"),
    pytest.param(["d7", "d2"], {"d2"}, 5, 1, 1.0, 0.5, 0.6309, id="B7"),
    pytest.param([], {"d2"}, 3, 0, 0.0, 0.0, 0.0, id="B8"),
]


@pytest.mark.parametrize(("ranked", "gold", "k", "hit", "recall", "rr", "ndcg"), ANSWERABLE)
def test_answerable_boundary_rows(ranked, gold, k, hit, recall, rr, ndcg):
    got_hit, got_recall, got_rr, got_ndcg = all_four(ranked, gold, k)
    assert got_hit == hit
    assert got_recall == pytest.approx(recall, abs=TOL)
    assert got_rr == pytest.approx(rr, abs=TOL)
    assert got_ndcg == pytest.approx(ndcg, abs=TOL)


# --- 7.3 답 없음 질의 (N1, N2) 와 abstain (A1~A3) ----------------------------------------------


@pytest.mark.parametrize(
    ("ranked", "k"),
    [
        pytest.param(["d7", "d2"], 3, id="N1"),
        pytest.param([], 3, id="N2"),
    ],
)
def test_no_answer_rows_are_undefined(ranked, k):
    assert all_four(ranked, set(), k) == (None, None, None, None)
    # None은 평균에서 제외된다(0으로도 1로도 세지 않는다)
    result = mean_defined([ndcg_at_k(ranked, set(), k)])
    assert (result.mean, result.n_scored, result.n_skipped) == (None, 0, 1)


@pytest.mark.parametrize(
    ("top_score", "tau", "expected"),
    [
        pytest.param(0.42, 0.5, 1, id="A1"),
        pytest.param(0.50, 0.5, 0, id="A2"),
        pytest.param(None, 0.5, 1, id="A3"),
    ],
)
def test_abstain_rows(top_score, tau, expected):
    assert abstain(top_score, tau) == expected


# --- 7.4 동점 순위 (T1~T3) ---------------------------------------------------------------------

TIES = [
    pytest.param(
        {"d2": 0.8, "d7": 0.8, "d9": 0.5}, {"d2"}, 3, ["d2", "d7", "d9"], 1, 1.0, 1.0, id="T1"
    ),
    pytest.param(
        {"d2": 0.8, "d7": 0.8, "d9": 0.5}, {"d7"}, 3, ["d2", "d7", "d9"], 1, 0.5, 0.6309, id="T2"
    ),
    pytest.param({"d2": 0.8, "d7": 0.8}, {"d7"}, 1, ["d2", "d7"], 0, 0.0, 0.0, id="T3"),
]


@pytest.mark.parametrize(("scores", "gold", "k", "ranked", "hit", "rr", "ndcg"), TIES)
def test_tie_rows(scores, gold, k, ranked, hit, rr, ndcg):
    got_ranked = sort_by_score(scores)
    assert got_ranked == ranked  # 하네스가 전체 목록을 만들고, 자르는 일은 지표 함수가 한다
    assert hit_at_k(got_ranked, gold, k) == hit
    assert reciprocal_rank_at_k(got_ranked, gold, k) == pytest.approx(rr, abs=TOL)
    assert ndcg_at_k(got_ranked, gold, k) == pytest.approx(ndcg, abs=TOL)


def test_sort_by_score_is_independent_of_input_order():
    forward = {"d9": 0.5, "d7": 0.8, "d2": 0.8}
    backward = {"d2": 0.8, "d7": 0.8, "d9": 0.5}
    assert sort_by_score(forward) == sort_by_score(backward) == ["d2", "d7", "d9"]


# --- 7.5 ANN recall (R1~R4) ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exact", "ann", "k", "expected"),
    [
        pytest.param(["c1", "c2", "c3"], ["c1", "c3", "c9"], 3, 0.6667, id="R1"),
        pytest.param(["c1", "c2", "c3"], ["c1"], 3, 0.3333, id="R2"),
        pytest.param(["c1", "c2", "c3"], [], 3, 0.0, id="R3"),
        pytest.param(["c1", "c2"], ["c1", "c2"], 3, 1.0, id="R4"),
    ],
)
def test_ann_recall_rows(exact, ann, k, expected):
    assert ann_recall_at_k(exact, ann, k) == pytest.approx(expected, abs=TOL)


def test_ann_recall_is_undefined_when_exact_is_empty():
    # 규약에 없는 경우(빈 코퍼스). 0으로 세지 않고 None으로 둔다.
    assert ann_recall_at_k([], ["c1"], 3) is None


# --- 7.6 평균 계산 -------------------------------------------------------------------------------


def test_mean_rule_skips_undefined_and_counts_empty_result_as_zero():
    result = mean_defined([1.0, None, 0.0])
    assert (result.mean, result.n_scored, result.n_skipped) == (0.5, 2, 1)


def test_mean_example_ndcg_with_empty_result_and_no_answer():
    # nDCG@10이 1.0, 0.5, 빈 결과, 답 없음 4질의 -> (1.0 + 0.5 + 0.0) / 3 = 0.5, n_scored=3, n_skipped=1
    values = [
        1.0,
        0.5,
        ndcg_at_k([], {"d2"}, 10),  # 빈 결과: 0.0
        ndcg_at_k(["d7"], set(), 10),  # 답 없음: None
    ]
    result = mean_defined(values)
    assert result.mean == pytest.approx(0.5, abs=TOL)
    assert (result.n_scored, result.n_skipped) == (3, 1)


def test_macro_vs_query_weighted_mean():
    # 유형별 평균 1.0(n=2), 0.4(n=5), 0.2(n=3) -> macro = 0.5333, 질의 수 가중 = 0.46
    per_type = {"a": [1.0] * 2, "b": [0.4] * 5, "c": [0.2] * 3}
    assert macro_mean(per_type) == pytest.approx(0.5333, abs=TOL)
    flat = [value for values in per_type.values() for value in values]
    assert mean_defined(flat).mean == pytest.approx(0.46, abs=TOL)


def test_macro_drops_types_without_scored_queries():
    # 유형별 평균 1.0(n=2), 0.4(n=5), (n=0) -> (1.0 + 0.4) / 2 = 0.7
    per_type = {"a": [1.0] * 2, "b": [0.4] * 5, "c": []}
    assert macro_mean(per_type) == pytest.approx(0.7, abs=TOL)
    # 채점 질의가 없다는 것은 값이 전부 None인 경우도 같다
    assert macro_mean({**per_type, "c": [None, None]}) == pytest.approx(0.7, abs=TOL)
    assert macro_mean({"c": []}) is None


# --- 7.1 입력 규칙 -------------------------------------------------------------------------------

METRICS = [
    pytest.param(hit_at_k, id="hit"),
    pytest.param(recall_at_k, id="recall"),
    pytest.param(reciprocal_rank_at_k, id="rr"),
    pytest.param(ndcg_at_k, id="ndcg"),
]


@pytest.mark.parametrize("metric", METRICS)
@pytest.mark.parametrize("k", [0, -1])
def test_non_positive_k_raises(metric, k):
    with pytest.raises(ValueError, match="k must be positive"):
        metric(["d1"], {"d1"}, k)


@pytest.mark.parametrize("metric", METRICS)
def test_duplicate_ids_in_ranked_raise(metric):
    with pytest.raises(ValueError, match="duplicate"):
        metric(["d1", "d2", "d1"], {"d1"}, 3)


@pytest.mark.parametrize("metric", METRICS)
def test_invalid_input_raises_even_when_gold_is_empty(metric):
    with pytest.raises(ValueError):
        metric(["d1"], set(), 0)
    with pytest.raises(ValueError):
        metric(["d1", "d1"], set(), 3)


def test_gold_is_a_set_so_duplicates_are_ignored():
    assert recall_at_k(["d2", "d7"], ["d2", "d2", "d4"], 2) == pytest.approx(0.5)
    assert ndcg_at_k(["d2", "d4"], ["d2", "d2", "d4"], 2) == pytest.approx(1.0)


def test_duplicate_beyond_k_still_raises():
    # 중복은 자르기 전의 전체 목록 기준으로 검사한다(하네스가 먼저 접어야 한다)
    with pytest.raises(ValueError, match="duplicate"):
        hit_at_k(["d1", "d2", "d1"], {"d1"}, 1)


def test_discount_is_one_over_log2_i_plus_one():
    # 1위 할인이 1이다: 정답이 1위에만 있고 |G| = 1이면 nDCG = 1.0, 2위면 1/log2(3)
    assert ndcg_at_k(["d1"], {"d1"}, 1) == 1.0
    assert ndcg_at_k(["d9", "d1"], {"d1"}, 2) == pytest.approx(1 / math.log2(3))

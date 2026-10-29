"""공통 채점 테스트 - condensed list(unjudged 제거 전후), tie_at_cutoff, 기권 τ, 결과 레코드 허용 필드.

합성 입력만 쓴다.
"""

import copy
import math

import pytest

from krsec_rag_lab.baselines import scoring
from krsec_rag_lab.baselines.data import Question
from krsec_rag_lab.metrics import abstain_rate, false_abstain_rate, ndcg_at_k


def question(qid, query_type="product_symptom", split="dev", gold=(), unjudged=(), excluded=False):
    return Question(
        question_id=qid,
        query="합성 질의",
        query_type=query_type,
        split=split,
        gold=frozenset(gold),
        unjudged=frozenset(unjudged),
        excluded=excluded,
    )


# ------------------------------------------------------------ 순위·condensed list


def test_make_record_orders_by_score_then_doc_id():
    record = scoring.make_record("q", {"d9": 0.5, "d2": 0.8, "d7": 0.8}, unjudged=())
    assert [(r["doc_id"], r["rank"]) for r in record["results"]] == [
        ("d2", 1),
        ("d7", 2),
        ("d9", 3),
    ]
    assert record["top1_score_raw"] == 0.8
    assert record["n_unjudged_removed"] == 0
    scoring.validate_record(record)


def test_make_record_condensed_list_removes_unjudged_and_pulls_up_followers():
    scores = {"u1": 0.9, "g1": 0.8, "x1": 0.7, "u2": 0.6, "x2": 0.5}
    record = scoring.make_record("q", scores, unjudged={"u1", "u2"})
    assert [(r["doc_id"], r["rank"]) for r in record["results"]] == [
        ("g1", 1),
        ("x1", 2),
        ("x2", 3),
    ]
    assert record["n_unjudged_removed"] == 2
    # 기권용 원래 1위 점수는 지우기 전 값이다(7.3, 1절)
    assert record["top1_score_raw"] == 0.9
    assert record["results"][0]["score"] == 0.8


def test_unjudged_removal_changes_metrics_before_and_after():
    scores = {"u1": 0.9, "g1": 0.8, "x1": 0.7}
    gold = {"g1"}
    without_removal = scoring.make_record("q", scores, unjudged=())
    with_removal = scoring.make_record("q", scores, unjudged={"u1"})
    before = scoring.question_values(without_removal, gold)
    after = scoring.question_values(with_removal, gold)
    assert before["hit@1"] == 0.0
    assert before["ndcg@10"] == pytest.approx(1 / math.log2(3), abs=1e-12)
    assert before["mrr@10"] == 0.5
    assert after["hit@1"] == 1.0
    assert after["ndcg@10"] == 1.0
    assert after["mrr@10"] == 1.0


def test_empty_result_scores_zero_for_answerable_and_none_for_no_answer():
    record = scoring.make_record("q", {}, unjudged=())
    assert record["top1_score_raw"] is None
    assert record["results"] == []
    assert scoring.question_values(record, {"g"})["ndcg@10"] == 0.0
    assert scoring.question_values(record, set())["ndcg@10"] is None


def test_record_keeps_only_top_100():
    scores = {f"d{i:03d}": 1000.0 - i for i in range(150)}
    record = scoring.make_record("q", scores, unjudged=())
    assert len(record["results"]) == scoring.RESULT_TOP_N == 100
    assert record["results"][-1]["rank"] == 100
    scoring.validate_record(record)


def test_make_record_rejects_nan_scores():
    with pytest.raises(ValueError, match="NaN"):
        scoring.make_record("q", {"a": float("nan")}, unjudged=())


@pytest.mark.parametrize(
    ("scores_by_rank", "expected"),
    [
        ([0.9, 0.8, 0.7], {1: False, 5: False, 10: False}),
        ([0.9, 0.9, 0.7], {1: True, 5: False, 10: False}),  # 7절 T3
        ([10, 9, 8, 7, 6, 6, 4, 3, 2, 1.5, 1.2, 1.0], {1: False, 5: True, 10: False}),
        ([10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1, 0.5], {1: False, 5: False, 10: True}),
        ([0.9], {1: False, 5: False, 10: False}),  # k+1위가 없으면 동점이 아니다
    ],
)
def test_tie_at_cutoff_uses_ranks_k_and_k_plus_1(scores_by_rank, expected):
    scores = {f"d{index:02d}": score for index, score in enumerate(scores_by_rank)}
    record = scoring.make_record("q", scores, unjudged=())
    assert {k: scoring.tie_at_cutoff(record, k) for k in scoring.KS} == expected


def test_tie_at_cutoff_is_computed_on_the_condensed_list():
    # 원래 1·2위(0.9, 0.8)는 동점이 아니지만 unjudged를 지우면 1·2위가 0.7·0.7이 된다
    scores = {"u1": 0.9, "u2": 0.8, "a": 0.7, "b": 0.7}
    record = scoring.make_record("q", scores, unjudged={"u1", "u2"})
    assert scoring.tie_at_cutoff(record, 1) is True


# ------------------------------------------------------------ 허용 필드


def good_record():
    return scoring.make_record("q", {"d1": 0.9, "d2": 0.5}, unjudged=())


def test_validate_record_accepts_generated_records():
    scoring.validate_record(good_record())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(text="공지 본문 일부"),
        lambda r: r.update(query="질의 원문"),
        lambda r: r["results"][0].update(snippet="발췌"),
        lambda r: r["results"][0].update(rank=2),
        lambda r: r["results"][0].update(score=0.1),  # 정렬 위반
        lambda r: r["results"][0].update(doc_id=r["results"][1]["doc_id"]),  # 중복
        lambda r: r.update(n_unjudged_removed=-1),
        lambda r: r.update(n_unjudged_removed=True),
        lambda r: r.update(top1_score_raw=0.1),  # condensed 1위가 원래 1위보다 높음
        lambda r: r.update(top1_score_raw="0.9"),
        lambda r: r.update(results=[r["results"][0]] * 101),
        lambda r: r.pop("top1_score_raw"),
        lambda r: r["results"][1].update(score=float("nan")),
    ],
)
def test_validate_record_rejects_disallowed_shape(mutate):
    record = copy.deepcopy(good_record())
    mutate(record)
    with pytest.raises(ValueError):
        scoring.validate_record(record)


# ------------------------------------------------------------ 기권 τ


def test_select_tau_maximizes_youden_j_and_ties_pick_lowest():
    no_answer = [0.2, 0.3, 0.9]
    answerable = [0.5, 0.8, 0.95]
    info = scoring.select_tau(no_answer, answerable)
    # τ=0.5: 기권 {0.2, 0.3} = 2/3, 오기권 0 -> J 0.667이 최대. τ=0.8은 J 0.333, τ=0.95는 0.333
    assert info["tau"] == 0.5
    assert info["dev_abstain_rate"] == pytest.approx(2 / 3)
    assert info["dev_false_abstain_rate"] == 0.0
    # 같은 데이터로 계산한 J와 일치
    assert info["dev_j"] == pytest.approx(
        abstain_rate(no_answer, 0.5) - false_abstain_rate(answerable, 0.5)
    )


def test_select_tau_boundary_is_strictly_less_than():
    info = scoring.select_tau([0.4], [0.5])
    assert info["tau"] == 0.5  # 점수 0.5가 τ와 같으면 기권하지 않는다(A2)
    assert info["dev_abstain_rate"] == 1.0
    assert info["dev_false_abstain_rate"] == 0.0


def test_select_tau_empty_results_always_abstain():
    info = scoring.select_tau([None, None], [1.0, 1.0])
    assert info["tau"] == 1.0
    assert info["dev_abstain_rate"] == 1.0
    assert info["dev_false_abstain_rate"] == 0.0
    info = scoring.select_tau([None], [None])
    assert info["tau"] == 0.0  # 점수 후보가 없다
    assert info["dev_j"] == 0.0


@pytest.mark.parametrize(("no_answer", "answerable"), [([], [0.5]), ([0.5], []), ([], [])])
def test_select_tau_needs_both_groups(no_answer, answerable):
    with pytest.raises(ValueError, match="needs"):
        scoring.select_tau(no_answer, answerable)


# ------------------------------------------------------------ 분할 집계


def make_records(spec):
    """spec: question_id -> (top1_score_raw, [(doc_id, score)...]) -> 레코드."""
    records = {}
    for qid, (top1, results) in spec.items():
        records[qid] = {
            "question_id": qid,
            "top1_score_raw": top1,
            "n_unjudged_removed": 0,
            "results": [
                {"doc_id": doc_id, "rank": rank, "score": score}
                for rank, (doc_id, score) in enumerate(results, start=1)
            ],
        }
    return records


def test_evaluate_split_per_type_macro_excluded_and_no_answer():
    questions = [
        question("c1", "cve_explicit", gold={"a"}),
        question("c2", "cve_explicit", gold={"b"}),
        question("p1", "product_symptom", gold={"p"}),
        question("e1", "explanation_comparison", gold=set(), excluded=True),
        question("n1", "no_answer"),
        question("n2", "no_answer"),
        question("t1", "cve_explicit", split="test", gold={"a"}),
    ]
    records = make_records(
        {
            "c1": (3.0, [("a", 3.0)]),
            "c2": (2.0, [("x", 2.0), ("b", 1.0)]),
            "p1": (None, []),
            "n1": (0.4, [("z", 0.4)]),
            "n2": (None, []),
            "t1": (3.0, [("a", 3.0)]),
        }
    )
    block = scoring.evaluate_split(records, questions, "dev", tau=1.0)
    assert block["n_questions"] == 5  # excluded 제외, test 질문 제외
    assert block["n_excluded"] == 1
    cve = block["by_type"]["cve_explicit"]
    assert (cve["n_scored"], cve["n_skipped"]) == (2, 0)
    assert cve["metrics"]["ndcg@10"] == pytest.approx((1.0 + 1 / math.log2(3)) / 2)
    assert cve["metrics"]["hit@1"] == 0.5
    assert cve["observation_only"] is True  # n < 10
    assert block["by_type"]["product_symptom"]["metrics"]["ndcg@10"] == 0.0  # 빈 결과는 0점
    assert block["by_type"]["explanation_comparison"]["n_scored"] == 0
    assert block["by_type"]["explanation_comparison"]["n_excluded"] == 1
    na = block["by_type"]["no_answer"]
    assert (na["n_scored"], na["n_skipped"]) == (0, 2)
    assert na["metrics"]["ndcg@10"] is None
    # macro = 정답이 있는 유형의 단순 평균(채점 0건인 유형은 분모에서 뺀다)
    assert block["macro"]["ndcg@10"] == pytest.approx((cve["metrics"]["ndcg@10"] + 0.0) / 2)
    assert block["macro_n_types"] == 2
    # 기권: n1은 0.4 < 1.0 기권, n2는 빈 결과 기권. 정답 있는 질의 중 점수 3.0·2.0은 기권 안 함, 빈 결과는 기권
    assert block["no_answer"]["abstain_rate"] == 1.0
    assert block["no_answer"]["false_abstain_rate"] == pytest.approx(1 / 3)
    assert block["no_answer"]["tau"] == 1.0
    assert block["no_answer"]["n_no_answer"] == 2
    assert block["no_answer"]["n_answerable"] == 3


def test_abstention_uses_raw_top1_not_condensed_top1():
    # 원래 1위(unjudged, 점수 5.0)를 지우면 condensed 1위는 0.2다. 기권은 5.0 기준이어야 한다
    questions = [question("q", gold={"g"}, unjudged={"u"})]
    record = scoring.make_record("q", {"u": 5.0, "g": 0.2}, unjudged={"u"})
    block = scoring.evaluate_split({"q": record}, questions, "dev", tau=1.0)
    assert block["no_answer"]["false_abstain_rate"] == 0.0  # 5.0 >= 1.0
    assert record["results"][0]["score"] == 0.2


def test_evaluate_split_ndcg_matches_metrics_module_on_condensed_list():
    questions = [question("q", gold={"g1", "g2"}, unjudged={"u"})]
    scores = {"u": 9.0, "g2": 8.0, "x": 7.0, "g1": 6.0}
    record = scoring.make_record("q", scores, unjudged={"u"})
    block = scoring.evaluate_split({"q": record}, questions, "dev", tau=None)
    expected = ndcg_at_k(["g2", "x", "g1"], {"g1", "g2"}, 10)
    assert block["by_type"]["product_symptom"]["metrics"]["ndcg@10"] == pytest.approx(expected)
    assert block["no_answer"]["abstain_rate"] is None  # τ 없음


def test_observation_only_flag_threshold():
    questions = [question(f"q{i}", gold={"a"}) for i in range(10)]
    records = make_records({f"q{i}": (1.0, [("a", 1.0)]) for i in range(10)})
    block = scoring.evaluate_split(records, questions, "dev", tau=None)
    assert block["by_type"]["product_symptom"]["observation_only"] is False  # n_scored 10
    block = scoring.evaluate_split(records, questions[:9], "dev", tau=None)
    assert block["by_type"]["product_symptom"]["observation_only"] is True  # n_scored 9

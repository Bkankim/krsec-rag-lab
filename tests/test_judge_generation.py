"""생성 평가 교차 판정(#66) 테스트 - 가짜 판정자와 합성 데이터만 쓴다. 네트워크·모델·API·KISA 캐시를 쓰지 않는다.

확인하는 것: 응답 해석(고정 라벨·코드), 일치·불일치·무효 확정 규칙, kappa(정의 안 되는 경우 포함), 기권·파싱 실패·문맥 초과
제외와 no_answer 비기권 답의 faithfulness 전용 판정, 호출 캐시 재사용, 사용량 한도 뒤 재개, 형식 오류 재질의 1회,
두 판정자가 같은 입력만 받는 것, 출력 허용 필드(자유 서술·인용·답변 원문 없음), 문맥 재구성 불일치 실패,
KISA 정답 자료(근거 구간 합집합), 로컬 캐시 대조, 집계 분모, 완료 조건(90%·20건), 저장본 검사(`--summary-only`).
"""

import importlib.util
import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

from krsec_rag_lab import judge
from krsec_rag_lab.baselines import data
from krsec_rag_lab.generation import judge_gen as jg
from krsec_rag_lab.generation import pipeline

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "judge_generation.py"
SPEC = importlib.util.spec_from_file_location("judge_generation", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
judge_generation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = judge_generation
SPEC.loader.exec_module(judge_generation)

# ------------------------------------------------------------ 합성 데이터

TEXTS = {"D1": "D1 첫 번째 문서 본문", "D2": "D2 두 번째 문서 본문", "D3": "D3 세 번째 문서 본문"}
ANSWER_TEXT = "합성 답변 원문 ZZZ-ANSWER"


def reply(f_label="supported", f_code=None, c_label="correct", c_code=None):
    f_code = f_code or jg.REASON_CODES[jg.FAITHFULNESS][f_label][0]
    c_code = c_code or jg.REASON_CODES[jg.CORRECTNESS][c_label][0]
    return json.dumps(
        {
            "faithfulness": {"label": f_label, "reason_code": f_code},
            "correctness": {"label": c_label, "reason_code": c_code},
        }
    )


GOOD = reply()


def question(qid, query_type="cve_explicit", split="test", gold=("D1",)):
    gold = frozenset() if query_type == "no_answer" else frozenset(gold)
    return data.Question(qid, f"질문 {qid}", query_type, split, gold, frozenset(), False)


def gen_row(
    qid, query_type="cve_explicit", split="test", status="ok", abstain=False, k_docs=("D1",)
):
    context, truncated = pipeline.build_context("public", list(k_docs), TEXTS.__getitem__)
    return {
        "question_id": qid,
        "split": split,
        "query_type": query_type,
        "k": 3,
        "status": status,
        "abstain": abstain,
        "citations": [] if status != "ok" or abstain else list(k_docs[:1]),
        "n_invalid_citations": 0,
        "retrieved": list(k_docs),
        "truncated": truncated,
        "n_retrieved": len(k_docs),
        "prompt_tokens": 10,
        "completion_tokens": 5,
        "latency_ms": 1.0,
        "context_sha256": pipeline.sha256_text(context),
        "n_attempts": 1,
        "context_chars": len(context),
        "answer": ANSWER_TEXT,
    }


def plan(rows, questions, track="public"):
    qmap = {q.question_id: q for q in questions}
    return jg.plan_items(
        track,
        rows,
        qmap,
        TEXTS.__getitem__,
        lambda q: [{"doc_id": "D1", "text": "정답 자료 ZZZ-REF"}],
        lambda row: ANSWER_TEXT,
    )


def fake(name, responder):
    return judge.FakeJudge(name, responder, model=f"fake-{name}")


def basic_plan(n=3):
    qs = [question(f"q{i}") for i in range(n)]
    return plan([gen_row(q.question_id) for q in qs], qs)


def tasks_of(items):
    return {i.question_id: i.task for i in items if i.task is not None}


def pair(a_reply, b_reply, items=None):
    items = items or basic_plan(1)
    judges = {"A": fake("A", lambda *_: a_reply), "B": fake("B", lambda *_: b_reply)}
    results = jg.run_all_judges(judges, judge.CallCache(), tasks_of(items), jg.LimitLog(None))
    return jg.build_rows(items, results)


# ------------------------------------------------------------ 응답 해석


@pytest.mark.parametrize(
    "raw",
    [
        GOOD,
        f"```json\n{GOOD}\n```",
        f"판정 결과입니다.\n{GOOD}\n끝.",
    ],
)
def test_valid_reply_is_read_with_fenced_or_chatty_wrapping(raw):
    result = jg.interpret_reply(raw, True)
    assert result["faithfulness"] == {"label": "supported", "reason_code": "all_claims_in_context"}
    assert result["correctness"] == {"label": "correct", "reason_code": "matches_reference"}


@pytest.mark.parametrize(
    ("raw", "faithfulness_ok", "correctness_ok"),
    [
        ("not json at all", False, False),
        ("[]", False, False),
        (
            json.dumps(
                {"faithfulness": {"label": "supported", "reason_code": "all_claims_in_context"}}
            ),
            True,
            False,
        ),
        (
            json.dumps({"correctness": {"label": "correct", "reason_code": "matches_reference"}}),
            False,
            True,
        ),
        (reply("supported", "contradicts_context"), False, True),  # 라벨에 없는 코드
        (reply(c_label="correct", c_code="contradicts_reference"), True, False),
        (reply("maybe", "all_claims_in_context"), False, True),  # 고정 라벨 밖
        (
            json.dumps(
                {
                    "faithfulness": {"label": 1, "reason_code": "all_claims_in_context"},
                    "correctness": {"label": "correct", "reason_code": ["matches_reference"]},
                }
            ),
            False,
            False,
        ),
        (
            reply(c_label="not_applicable"),
            True,
            False,
        ),  # 정답 자료가 있으면 not_applicable은 형식 오류
    ],
)
def test_invalid_axes_become_none_independently(raw, faithfulness_ok, correctness_ok):
    result = jg.interpret_reply(raw, True)
    assert (result["faithfulness"] is not None) is faithfulness_ok
    assert (result["correctness"] is not None) is correctness_ok


def test_free_text_in_the_reply_is_dropped_not_stored():
    raw = json.dumps(
        {
            "faithfulness": {
                "label": "supported",
                "reason_code": "all_claims_in_context",
                "explanation": "인용 ZZZ-QUOTE",
            },
            "correctness": {"label": "correct", "reason_code": "matches_reference"},
            "notes": "자유 서술 ZZZ-NOTE",
        }
    )
    result = jg.interpret_reply(raw, True)
    assert "ZZZ" not in json.dumps(result, ensure_ascii=False)
    assert set(result["faithfulness"]) == {"label", "reason_code"}


def test_no_reference_question_ignores_the_correctness_reply():
    result = jg.interpret_reply(reply(c_label="incorrect"), False)
    assert result["correctness"] == {"label": "not_applicable", "reason_code": "no_reference"}
    assert jg.interpret_reply("garbage", False)["faithfulness"] is None


def test_schema_and_instruction_list_exactly_the_fixed_codes():
    schema = jg.ANSWER_SCHEMA
    assert schema["additionalProperties"] is False and schema["required"] == [
        "faithfulness",
        "correctness",
    ]
    for axis in jg.AXES:
        props = schema["properties"][axis]["properties"]
        assert props["label"]["enum"] == list(jg.LABELS[axis])
        assert props["reason_code"]["enum"] == jg.ALL_CODES[axis]
        for code in jg.ALL_CODES[axis]:
            assert code in jg.JUDGE_INSTRUCTION
    assert jg.INSTRUCTION_SHA256 == judge.text_sha256(jg.JUDGE_INSTRUCTION)


# ------------------------------------------------------------ 확정 규칙


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("supported", "supported", "supported"),
        ("unsupported", "unsupported", "unsupported"),
        ("supported", "partially_supported", "disagree"),
        ("supported", "unsupported", "disagree"),
        (None, "supported", "invalid"),
        ("supported", None, "invalid"),
        (None, None, "invalid"),
    ],
)
def test_confirmation_needs_both_valid_and_equal(a, b, expected):
    assert jg.confirm(a, b) == expected


def test_rows_apply_the_rule_per_axis_and_keep_each_judges_reason_code():
    rows = pair(
        reply("supported", c_label="correct"),
        reply("supported", c_label="partially_correct"),
    )
    row = rows[0]
    assert row["faithfulness"] == "supported" and row["correctness"] == "disagree"
    assert row["correctness_A"] == "correct" and row["correctness_B"] == "partially_correct"
    assert row["correctness_reason_A"] == "matches_reference"
    assert row["correctness_reason_B"] == "covers_part_of_reference"
    assert tuple(row) == jg.ROW_KEYS


def test_malformed_axis_after_retry_is_null_while_status_stays_judged():
    rows = pair(GOOD, reply("supported", c_label="correct", c_code="contradicts_reference"))
    row = rows[0]
    assert row["status"] == "judged"
    assert row["correctness_B"] is None and row["correctness_reason_B"] is None
    assert row["faithfulness_B"] == "supported"
    assert row["correctness"] == "invalid" and row["faithfulness"] == "supported"


# ------------------------------------------------------------ kappa


def kappa_of(pairs):
    return judge.cohen_kappa(
        (
            judge.RELEVANT if a == "supported" else judge.NOT_RELEVANT,
            judge.RELEVANT if b == "supported" else judge.NOT_RELEVANT,
        )
        for a, b in pairs
    )


def stat_rows(pairs, axis="faithfulness"):
    return [
        {
            f"{axis}_A": a,
            f"{axis}_B": b,
            axis: jg.confirm(a, b),
        }
        for a, b in pairs
    ]


def test_kappa_is_binarized_positive_vs_rest_over_both_valid_rows():
    pairs = [
        ("supported", "supported"),
        ("supported", "partially_supported"),
        ("unsupported", "partially_supported"),  # 둘 다 비positive -> 이진 일치
        ("unsupported", "unsupported"),
        (None, "supported"),  # 무효 -> 분모 밖
    ]
    stats = jg.axis_stats(stat_rows(pairs), jg.FAITHFULNESS)
    assert stats["n"] == 5 and stats["n_both_valid"] == 4 and stats["n_invalid"] == 1
    assert stats["n_agree"] == 2 and stats["n_disagree"] == 2  # 일치율은 정확히 같은 라벨
    assert stats["agreement_rate"] == 0.5 and stats["disagreement_rate"] == 0.5
    assert stats["kappa"]["n"] == 4
    assert stats["kappa"]["value"] == 0.5  # 이진화한 관측 0.75, 기대 0.5
    assert stats["confirmed_positive_rate"] == 1 / 5  # 분모는 판정 대상 전부


@pytest.mark.parametrize(
    ("pairs", "reason"),
    [
        ([("supported", "supported")] * 3, "single label"),  # 한 라벨만 -> 기대 일치 1
        ([("unsupported", "partially_supported")] * 2, "single label"),
        ([(None, "supported"), ("supported", None)], "no valid label pairs"),
        ([], "no valid label pairs"),
    ],
)
def test_undefined_kappa_is_null_with_a_reason(pairs, reason):
    kappa = jg.axis_stats(stat_rows(pairs), jg.FAITHFULNESS)["kappa"]
    assert kappa["value"] is None and reason in kappa["null_reason"]


def test_perfect_agreement_with_both_labels_gives_kappa_one():
    kappa = jg.axis_stats(
        stat_rows([("supported", "supported"), ("unsupported", "unsupported")]), jg.FAITHFULNESS
    )["kappa"]
    assert kappa["value"] == 1.0


# ------------------------------------------------------------ 제외 규칙


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        ({"status": "ok", "abstain": False}, "judged"),
        ({"status": "ok", "abstain": True}, "skipped_abstain"),
        ({"status": "context_overflow", "abstain": False}, "skipped_context_overflow"),
        ({"status": "parse_failed:not_json", "abstain": False}, "skipped_parse_failed"),
        ({"status": "parse_failed:bad_citations", "abstain": False}, "skipped_parse_failed"),
    ],
)
def test_row_status_matrix(row, expected):
    assert jg.row_status(row) == expected


def test_skipped_rows_are_counted_not_judged_and_carry_no_labels():
    qs = [question(f"q{i}") for i in range(4)]
    rows = [
        gen_row("q0"),
        gen_row("q1", abstain=True),
        gen_row("q2", status="parse_failed:empty"),
        gen_row("q3", status="context_overflow"),
    ]
    items = plan(rows, qs)
    assert [i.status for i in items] == [
        "judged",
        "skipped_abstain",
        "skipped_parse_failed",
        "skipped_context_overflow",
    ]
    assert [i.task is not None for i in items] == [True, False, False, False]
    fake_a = fake("A", lambda *_: GOOD)
    judges = {"A": fake_a, "B": fake("B", lambda *_: GOOD)}
    results = jg.run_all_judges(judges, judge.CallCache(), tasks_of(items), jg.LimitLog(None))
    assert len(fake_a.calls) == 1  # 건너뛴 행은 호출하지 않는다
    built = jg.build_rows(items, results)
    for row in built[1:]:
        assert all(row[key] is None for key in jg.ROW_KEYS[4:])
        jg.validate_row(row)
    summary = jg.compute_summary({"public": built}, topk_stub(built))
    all_cell = next(c for c in summary["cells"] if c["query_type"] == "all")
    assert (
        all_cell["n_rows"],
        all_cell["n_judged"],
        all_cell["n_skipped_abstain"],
        all_cell["n_skipped_parse_failed"],
        all_cell["n_skipped_context_overflow"],
    ) == (4, 1, 1, 1, 1)
    assert all_cell["faithfulness"]["n"] == 1  # 분모는 judged만


def test_no_answer_question_with_a_non_abstain_answer_is_judged_on_faithfulness_only():
    qs = [question("n1", "no_answer")]
    items = plan([gen_row("n1", "no_answer", abstain=False)], qs)
    assert items[0].status == "judged" and items[0].task.has_reference is False
    sent = json.loads(items[0].task.payload)
    assert sent["reference"] is None
    rows = pair(reply("unsupported", c_label="incorrect"), reply("unsupported"), items)
    row = rows[0]
    assert row["faithfulness"] == "unsupported"
    assert row["correctness"] == row["correctness_A"] == row["correctness_B"] == "not_applicable"
    assert row["correctness_reason_A"] == row["correctness_reason_B"] == "no_reference"
    summary = jg.compute_summary({"public": rows}, topk_stub(rows))
    cell = next(c for c in summary["cells"] if c["query_type"] == "no_answer")
    assert cell["faithfulness"]["n"] == 1 and cell["correctness"]["n"] == 0
    assert cell["n_correctness_not_applicable"] == 1


def test_no_answer_abstain_is_skipped():
    items = plan([gen_row("n1", "no_answer", abstain=True)], [question("n1", "no_answer")])
    assert items[0].status == "skipped_abstain" and items[0].task is None


def test_only_the_scoped_splits_are_planned_for_the_public_track():
    qs = [question("t", split="test"), question("d", split="dev")]
    items = plan([gen_row("t"), gen_row("d", split="dev")], qs, track="public")
    assert [i.question_id for i in items] == ["t"]


@pytest.mark.parametrize("limit", [1, 2, 5])
def test_sample_picks_judged_rows_across_query_types(limit):
    qs = [question(f"a{i}") for i in range(3)] + [
        question(f"p{i}", "product_symptom") for i in range(3)
    ]
    qs.append(question("x", "no_answer"))
    rows = [gen_row(q.question_id, q.query_type, abstain=q.question_id == "a0") for q in qs]
    items = plan(rows, qs)
    sampled = jg.sample_items(items, limit)
    judged = [i for i in sampled if i.status == "judged"]
    assert len(judged) == min(limit, 6) and all(i.status == "judged" for i in sampled)
    if limit >= 2:
        assert len({i.query_type for i in judged}) >= 2
    with pytest.raises(ValueError):
        jg.sample_items(items, 0)


# ------------------------------------------------------------ 문맥 재구성


@pytest.mark.parametrize(
    "tamper",
    [
        lambda r: r.update(context_sha256="0" * 64),
        lambda r: r.update(truncated=["D1"]),
        lambda r: r.update(context_chars=r["context_chars"] + 1),
        lambda r: r.update(retrieved=["D2"]),
    ],
)
def test_rebuilt_context_that_differs_from_the_row_fails(tamper):
    row = gen_row("q0")
    tamper(row)
    with pytest.raises(jg.InputMismatch):
        plan([row], [question("q0")])


def test_context_with_truncated_documents_is_rebuilt_with_the_same_cap():
    long_texts = {"D1": "가" * (pipeline.DOC_CHAR_CAP + 50)}
    context, truncated = pipeline.build_context("public", ["D1"], long_texts.__getitem__)
    row = gen_row("q0")
    row.update(
        retrieved=["D1"],
        truncated=truncated,
        context_sha256=pipeline.sha256_text(context),
        context_chars=len(context),
    )
    items = jg.plan_items(
        "public",
        [row],
        {"q0": question("q0")},
        long_texts.__getitem__,
        lambda q: [{"doc_id": "D1", "text": "r"}],
        lambda r: "답",
    )
    assert json.loads(items[0].task.payload)["context"] == context


# ------------------------------------------------------------ 호출 캐시·재질의·독립성


def test_the_two_judges_get_identical_inputs_and_never_each_others_results():
    items = basic_plan(2)
    a = fake("A", lambda *_: reply("supported"))
    b = fake("B", lambda *_: reply("unsupported", c_label="incorrect"))
    jg.run_all_judges({"A": a, "B": b}, judge.CallCache(), tasks_of(items), jg.LimitLog(None))
    assert sorted(json.dumps(c, sort_keys=True) for c in a.calls) == sorted(
        json.dumps(c, sort_keys=True) for c in b.calls
    )
    for call in a.calls + b.calls:
        assert set(call) == {"question", "context", "answer", "reference"}
        assert "A" not in call and "B" not in call
    assert a.calls and all(
        "all_claims_in_context" not in json.dumps(c) and "contradicts" not in json.dumps(c)
        for c in b.calls
    )


def test_second_run_reuses_the_call_cache_and_makes_no_new_calls(tmp_path):
    items = basic_plan(3)
    cache = judge.CallCache(tmp_path / "cache")
    a, b = fake("A", lambda *_: GOOD), fake("B", lambda *_: GOOD)
    jg.run_all_judges({"A": a, "B": b}, cache, tasks_of(items), jg.LimitLog(None))
    assert len(a.calls) == len(b.calls) == 3
    again_a, again_b = fake("A", lambda *_: GOOD), fake("B", lambda *_: GOOD)
    reused = judge.CallCache(tmp_path / "cache")  # 디스크에서 다시 읽는다
    jg.run_all_judges({"A": again_a, "B": again_b}, reused, tasks_of(items), jg.LimitLog(None))
    assert again_a.calls == [] and again_b.calls == []
    counts = jg.count_calls(reused)
    assert counts["total"] == 6
    assert {(e["judge"], e["kind"]): e["n"] for e in counts["by_judge_kind"]} == {
        ("A", "judge"): 3,
        ("A", "retry"): 0,
        ("B", "judge"): 3,
        ("B", "retry"): 0,
    }


def test_format_error_is_asked_again_exactly_once_and_the_retry_can_fix_it():
    items = basic_plan(1)
    queue = ["totally not json", GOOD, GOOD]
    a = fake("A", lambda *_: queue.pop(0))
    cache = judge.CallCache()
    result = jg.judge_task(a, cache, "q0", items[0].task)
    assert (
        len(a.calls) == 2 and "retry" not in a.calls[0] and a.calls[1]["retry"] == jg.RETRY_NOTICE
    )
    assert all(result[axis] is not None for axis in jg.AXES)
    assert {e["kind"] for e in cache.entries()} == {"judge", "retry"}


def test_still_malformed_after_the_retry_is_not_asked_a_third_time():
    items = basic_plan(1)
    a = fake("A", lambda *_: "nope")
    result = jg.judge_task(a, judge.CallCache(), "q0", items[0].task)
    assert len(a.calls) == 2
    assert result == {"faithfulness": None, "correctness": None}


def test_retry_keeps_the_axes_that_were_already_valid():
    items = basic_plan(1)
    first = reply("partially_supported", c_label="correct", c_code="contradicts_reference")
    queue = [first, reply("supported", c_label="incorrect")]
    a = fake("A", lambda *_: queue.pop(0))
    result = jg.judge_task(a, judge.CallCache(), "q0", items[0].task)
    assert result["faithfulness"]["label"] == "partially_supported"  # 첫 응답의 유효 축 유지
    assert result["correctness"]["label"] == "incorrect"  # 재질의가 고친 축


def test_no_reference_question_with_valid_faithfulness_needs_no_retry():
    items = plan([gen_row("n1", "no_answer")], [question("n1", "no_answer")])
    a = fake(
        "A",
        lambda *_: json.dumps(
            {"faithfulness": {"label": "supported", "reason_code": "all_claims_in_context"}}
        ),
    )
    jg.judge_task(a, judge.CallCache(), "n1", items[0].task)
    assert len(a.calls) == 1


# ------------------------------------------------------------ 한도 대기·재개


LIMIT_MESSAGE = "codex exit 1: usage limit, try again at 3:41 PM"


@pytest.mark.parametrize(
    ("hint", "now", "expected"),
    [
        ("3:41 PM", datetime(2026, 10, 30, 14, 0), 101 * 60 + jg.LIMIT_WAIT_MARGIN_SECONDS),
        ("3:41 PM", datetime(2026, 10, 30, 16, 0), jg.MAX_LIMIT_WAIT_SECONDS),  # 내일 시각이면 상한
        ("12:05 AM", datetime(2026, 10, 30, 23, 50), 15 * 60 + jg.LIMIT_WAIT_MARGIN_SECONDS),
        ("12:30 PM", datetime(2026, 10, 30, 12, 0), 30 * 60 + jg.LIMIT_WAIT_MARGIN_SECONDS),
        (None, datetime(2026, 10, 30, 12, 0), jg.DEFAULT_LIMIT_WAIT_SECONDS),
        ("soon", datetime(2026, 10, 30, 12, 0), jg.DEFAULT_LIMIT_WAIT_SECONDS),
        ("13:99 PM", datetime(2026, 10, 30, 12, 0), jg.DEFAULT_LIMIT_WAIT_SECONDS),
    ],
)
def test_wait_seconds_follows_the_retry_hint_or_falls_back(hint, now, expected):
    assert jg.wait_seconds(hint, now) == expected


class LimitedJudge(judge.FakeJudge):
    """처음 `fail_times`번 호출은 사용량 한도 오류를 던지는 판정자."""

    def __init__(self, name, fail_times, responder=lambda *_: GOOD):
        super().__init__(name, responder, model=f"fake-{name}")
        self.fail_times = fail_times
        self.attempts = 0

    def ask(self, instruction, payload, schema):
        self.attempts += 1
        if self.attempts <= self.fail_times:
            raise judge.JudgeUnavailable(LIMIT_MESSAGE)
        return super().ask(instruction, payload, schema)


def test_usage_limit_saves_state_waits_and_resumes_from_the_cache(tmp_path):
    items = basic_plan(4)
    cache = judge.CallCache(tmp_path / "cache")
    log = jg.LimitLog(tmp_path / "state" / "limit_events.json")
    slept, notified = [], []
    b = LimitedJudge("B", fail_times=2)
    results = jg.run_judge(
        b,
        cache,
        tasks_of(items),
        log,
        jobs=1,
        sleep=slept.append,
        now=lambda: datetime(2026, 10, 30, 15, 0),
        on_wait=lambda name, seconds: notified.append((name, seconds)),
    )
    assert set(results) == {"q0", "q1", "q2", "q3"}
    assert len(b.calls) == 4  # 한도로 실패한 호출은 캐시에 없고, 재개 뒤 4건만 성공
    assert len(slept) == 2 and slept == [seconds for _, seconds in notified]
    assert slept[0] == 41 * 60 + jg.LIMIT_WAIT_MARGIN_SECONDS
    events = log.events()
    assert len(events) == 2 and all(e["judge"] == "B" and e["resumed_at"] for e in events)
    saved = json.loads((tmp_path / "state" / "limit_events.json").read_text(encoding="utf-8"))
    assert saved[0]["retry_hint"] == "3:41 PM"
    assert "usage limit" not in json.dumps(saved)  # 메시지 본문은 남기지 않는다
    waits = jg.limit_waits(events)
    assert waits["n_events"] == 2 and waits["total_wait_seconds"] >= 0


def test_resume_does_not_repeat_calls_that_already_succeeded(tmp_path):
    items = basic_plan(3)
    cache = judge.CallCache(tmp_path / "cache")
    first = fake("A", lambda *_: GOOD)
    jg.run_judge(first, cache, tasks_of(items), jg.LimitLog(None), jobs=1)
    limited = LimitedJudge("A", fail_times=10)  # 캐시가 다 있으면 한도 오류도 안 나야 한다
    jg.run_judge(limited, cache, tasks_of(items), jg.LimitLog(None), jobs=1, sleep=lambda s: None)
    assert limited.attempts == 0 and limited.calls == []


def test_the_other_judge_keeps_going_while_one_waits(tmp_path):
    items = basic_plan(3)
    a = fake("A", lambda *_: GOOD)
    b = LimitedJudge("B", fail_times=1)
    results = jg.run_all_judges(
        {"A": a, "B": b},
        judge.CallCache(),
        tasks_of(items),
        jg.LimitLog(None),
        jobs=1,
        sleep=lambda s: None,
    )
    assert len(a.calls) == 3 and set(results) == {"A", "B"}
    assert {k: v for k, v in results["B"].items()}.keys() == {"q0", "q1", "q2"}


def test_too_many_limit_waits_raise_so_the_caller_can_exit_and_resume(tmp_path):
    items = basic_plan(1)
    b = LimitedJudge("B", fail_times=99)
    with pytest.raises(judge.JudgeUnavailable):
        jg.run_judge(
            b,
            judge.CallCache(),
            tasks_of(items),
            jg.LimitLog(None),
            jobs=1,
            sleep=lambda s: None,
            max_waits=2,
        )
    assert b.attempts == 3


def test_an_interrupted_wait_is_closed_when_the_log_is_reopened(tmp_path):
    path = tmp_path / "limit_events.json"
    log = jg.LimitLog(path)
    log.stop("B", LIMIT_MESSAGE)  # 대기 중에 프로세스가 끊겼다
    reopened = jg.LimitLog(path)
    event = reopened.events()[0]
    assert event["resumed_at"] is not None and event["waited_seconds"] >= 0


def test_other_judge_errors_are_not_treated_as_a_usage_limit():
    items = basic_plan(1)

    def boom(*_):
        raise judge.JudgeError("claude exit 1: error response omitted (3 chars)")

    with pytest.raises(judge.JudgeError) as caught:
        jg.run_judge(fake("A", boom), judge.CallCache(), tasks_of(items), jg.LimitLog(None), jobs=1)
    assert not isinstance(caught.value, judge.JudgeUnavailable)


# ------------------------------------------------------------ 출력 허용 필드


def test_cache_entries_and_rows_hold_only_labels_codes_and_ids(tmp_path):
    items = basic_plan(2)
    cache = judge.CallCache(tmp_path / "cache")
    noisy = json.dumps(
        {
            "faithfulness": {
                "label": "supported",
                "reason_code": "all_claims_in_context",
                "why": "ZZZ-FREE",
            },
            "correctness": {"label": "correct", "reason_code": "matches_reference"},
            "quote": "ZZZ-QUOTE",
        }
    )
    judges = {"A": fake("A", lambda *_: noisy), "B": fake("B", lambda *_: noisy)}
    results = jg.run_all_judges(judges, cache, tasks_of(items), jg.LimitLog(None))
    rows = jg.build_rows(items, results)
    on_disk = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "cache").glob("*.json"))
    on_disk += jg.jsonl_text(rows)
    for forbidden in ("ZZZ", "첫 번째 문서", "정답 자료", "질문 q0"):
        assert forbidden not in on_disk
    for entry in cache.entries():
        assert set(entry) == {"kind", "task", "judge", "model", "created_at", "result"}
        assert set(entry["result"]) == {"faithfulness", "correctness"}
        for axis in entry["result"].values():
            assert set(axis) == {"label", "reason_code"}
    for row in rows:
        assert tuple(row) == jg.ROW_KEYS


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(extra="x"),
        lambda r: r.pop("faithfulness_B"),
        lambda r: r.update(faithfulness_reason_A="free text"),
        lambda r: r.update(
            faithfulness="supported" if r["faithfulness"] != "supported" else "disagree"
        ),
        lambda r: r.update(status="skipped_other"),
        lambda r: r.update(correctness_A=None),
        lambda r: r.update(query_type="no_answer"),  # 정답성 적용 여부와 유형 불일치
    ],
)
def test_validate_row_rejects_unexpected_keys_values_and_inconsistencies(mutate):
    row = pair(GOOD, GOOD)[0]
    jg.validate_row(row)
    mutate(row)
    with pytest.raises(ValueError):
        jg.validate_row(row)


def test_skipped_row_with_labels_is_rejected():
    row = jg.build_row(basic_plan(1)[0], None)
    row["status"] = "skipped_abstain"
    row["faithfulness_A"] = "supported"
    with pytest.raises(ValueError):
        jg.validate_row(row)


# ------------------------------------------------------------ 정답 자료


def test_merge_spans_unions_overlapping_and_touching_intervals():
    assert jg.merge_spans([(10, 20), (0, 5), (15, 30), (30, 35), (50, 60)]) == [
        (0, 5),
        (10, 35),
        (50, 60),
    ]
    assert jg.merge_spans([]) == []


def evidence(start, end, judge_name="A", parser="kisa-html-v1"):
    return {"start": start, "end": end, "judge": judge_name, "parser_version": parser}


BODIES = {"70001": "0123456789" * 10, "70002": "abcdefghij" * 10}


def golden(answers):
    return {"question_id": "g1", "answers": answers}


def test_kisa_reference_is_the_union_of_a_and_b_spans_per_doc_in_doc_id_order():
    row = golden(
        [
            {"doc_id": "70002", "evidence": [evidence(0, 5, "A"), evidence(3, 8, "B")]},
            {"doc_id": "70001", "evidence": [evidence(10, 20, "A"), evidence(40, 45, "B")]},
        ]
    )
    parts = jg.kisa_reference(row, BODIES.__getitem__, "kisa-html-v1")
    assert [p["doc_id"] for p in parts] == ["70001", "70002"]
    assert parts[0]["text"] == BODIES["70001"][10:20] + "\n" + BODIES["70001"][40:45]
    assert parts[1]["text"] == BODIES["70002"][0:8]


@pytest.mark.parametrize(
    "bad",
    [
        evidence(0, 5, parser="kisa-html-v0"),
        evidence(90, 101),
        evidence(5, 5),
        evidence(-1, 5),
    ],
)
def test_kisa_reference_with_stale_or_out_of_range_evidence_fails(bad):
    row = golden([{"doc_id": "70001", "evidence": [bad]}])
    with pytest.raises(jg.InputMismatch) as caught:
        jg.kisa_reference(row, BODIES.__getitem__, "kisa-html-v1")
    assert BODIES["70001"][:10] not in str(caught.value)


def test_public_reference_lists_gold_descriptions_in_id_order():
    parts = jg.public_reference({"CVE-2", "CVE-1"}, {"CVE-1": "one", "CVE-2": "two"})
    assert parts == [{"doc_id": "CVE-1", "text": "one"}, {"doc_id": "CVE-2", "text": "two"}]


# ------------------------------------------------------------ 로컬 캐시 대조(KISA 답변 원문)


def kisa_cache(tmp_path, committed, run_id="run-1", mutate=None):
    rows = []
    for row in committed:
        cached = {**row, "answer": ANSWER_TEXT, "run_id": run_id}
        if mutate:
            mutate(cached)
        rows.append(cached)
    path = tmp_path / "data/m5/generation/kisa_k3.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text(jg.jsonl_text(rows), encoding="utf-8")
    return path


def committed_rows():
    return [{k: v for k, v in gen_row(q).items() if k != "answer"} for q in ("q0", "q1")]


def test_kisa_answers_come_from_the_local_cache_when_the_run_and_rows_match(tmp_path):
    committed = committed_rows()
    kisa_cache(tmp_path, committed)
    answers = jg.kisa_answers(tmp_path, committed, "run-1")
    assert answers == {"q0": ANSWER_TEXT, "q1": ANSWER_TEXT}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.update(run_id="other-run"),
        lambda c: c.update(context_sha256="1" * 64),
        lambda c: c.update(abstain=True),
        lambda c: c.pop("answer"),
        lambda c: c.update(answer=3),
    ],
)
def test_kisa_cache_that_differs_from_the_committed_run_fails_without_leaking_the_answer(
    tmp_path, mutate
):
    committed = committed_rows()
    kisa_cache(
        tmp_path, committed, mutate=lambda c: mutate(c) if c["question_id"] == "q1" else None
    )
    with pytest.raises(jg.InputMismatch) as caught:
        jg.kisa_answers(tmp_path, committed, "run-1")
    assert ANSWER_TEXT not in str(caught.value)


def test_kisa_cache_with_missing_or_extra_questions_fails(tmp_path):
    committed = committed_rows()
    kisa_cache(tmp_path, committed[:1])
    with pytest.raises(jg.InputMismatch):
        jg.kisa_answers(tmp_path, committed, "run-1")
    with pytest.raises(jg.InputMismatch):
        jg.kisa_answers(tmp_path / "nowhere", committed, "run-1")


# ------------------------------------------------------------ 집계·완료 조건


def topk_stub(rows, track="public"):
    """행 묶음에 맞는 가짜 topk.json(k=3): 칸마다 n_questions만 맞춘다."""
    cells = []
    for split in ("dev", "test", "all"):
        for query_type in (*data.QUERY_TYPES, "macro", "all"):
            subset = [
                r
                for r in rows
                if (split == "all" or r["split"] == split)
                and (query_type in ("all", "macro") or r["query_type"] == query_type)
            ]
            cells.append(
                {
                    "track": track,
                    "k": 3,
                    "split": split,
                    "query_type": query_type,
                    "n_questions": len(subset),
                    "n_no_answer": 0,
                    "n_answerable": len(subset),
                    "n_cited_answers": len(subset),
                    "correct_abstain_rate": None,
                    "false_abstain_rate": 0.25,
                    "citation_hit_rate": 0.75,
                }
            )
    return {"schema": "m5-topk-v1", "cells": cells}


def synthetic_rows(n_good=4, n_disagree=1, n_invalid=1):
    qs = [question(f"q{i}") for i in range(n_good + n_disagree + n_invalid)]
    items = plan([gen_row(q.question_id) for q in qs], qs)
    replies = [(GOOD, GOOD)] * n_good + [
        (GOOD, reply("unsupported", c_label="incorrect"))
    ] * n_disagree
    replies += [(GOOD, "garbage")] * n_invalid
    a_by_q = {q.question_id: a for q, (a, _) in zip(qs, replies)}
    b_by_q = {q.question_id: b for q, (_, b) in zip(qs, replies)}
    judges = {
        "A": fake("A", lambda _i, p: a_by_q[p["question"].removeprefix("질문 ")]),
        "B": fake("B", lambda _i, p: b_by_q[p["question"].removeprefix("질문 ")]),
    }
    results = jg.run_all_judges(judges, judge.CallCache(), tasks_of(items), jg.LimitLog(None))
    return jg.build_rows(items, results)


def test_summary_denominators_agreement_and_machine_axes():
    rows = synthetic_rows()
    topk = topk_stub(rows)
    summary = jg.compute_summary({"public": rows}, topk)
    assert summary["k"] == 3
    cell = next(c for c in summary["cells"] if (c["split"], c["query_type"]) == ("test", "all"))
    f, c = cell["faithfulness"], cell["correctness"]
    assert f["n"] == 6 and f["n_both_valid"] == 5  # 마지막 행은 B의 두 축이 모두 무효
    assert f["confirmed_counts"]["supported"] == 4 and f["n_disagree"] == 1 and f["n_invalid"] == 1
    assert f["confirmed_positive_rate"] == 4 / 6
    assert c["n"] == 6 and c["n_disagree"] == 1 and c["n_invalid"] == 1
    assert (
        cell["machine"]["false_abstain_rate"] == 0.25
        and cell["machine"]["citation_hit_rate"] == 0.75
    )
    assert not any(c["split"] == "all" for c in summary["cells"])  # 공개 트랙은 test만
    track = summary["tracks"]["public"]
    assert track["n_judged"] == 6 and track["n_valid_both"] == 5
    assert track["valid_rate"] == pytest.approx(5 / 6)
    assert track["n_valid_A"] == 6 and track["n_valid_B"] == 5


def test_kisa_summary_has_dev_test_and_all_splits_with_matching_machine_cells():
    qs = [question("a", split="dev"), question("b", split="test")]
    items = plan([gen_row("a", split="dev"), gen_row("b")], qs, track="kisa")
    judges = {"A": fake("A", lambda *_: GOOD), "B": fake("B", lambda *_: GOOD)}
    rows = jg.build_rows(
        items, jg.run_all_judges(judges, judge.CallCache(), tasks_of(items), jg.LimitLog(None))
    )
    summary = jg.compute_summary({"kisa": rows}, topk_stub(rows, "kisa"))
    assert [
        (c["split"], c["query_type"]) for c in summary["cells"] if c["query_type"] == "all"
    ] == [
        ("dev", "all"),
        ("test", "all"),
        ("all", "all"),
    ]


def make_summary(n_judged, valid):
    return {
        "tracks": {
            "public": {"n_judged": n_judged, "valid_rate": valid},
        }
    }


@pytest.mark.parametrize(
    ("n_judged", "valid", "expected"),
    [
        (63, 1.0, []),
        (63, 0.9, []),  # 90% 이상이면 통과(경계)
        (100, 0.89, ["both-valid rate"]),
        (19, 1.0, ["< 20"]),
        (20, 1.0, []),
        (0, None, ["< 20"]),
    ],
)
def test_completion_gate_needs_20_targets_and_90_percent_both_valid(n_judged, valid, expected):
    problems = jg.gate_problems(make_summary(n_judged, valid))
    assert len(problems) == len(expected)
    for needle, problem in zip(expected, problems):
        assert needle in problem


def test_compare_json_tolerates_float_noise_but_not_value_changes():
    assert jg.compare_json({"a": [1.0, {"b": 0.5}]}, {"a": [1.0 + 1e-12, {"b": 0.5}]}) == []
    assert jg.compare_json({"a": 1}, {"a": 2}) == ["/a: 1 != 2"]
    assert jg.compare_json({"a": 1}, {"b": 1})


# ------------------------------------------------------------ 저장본 검사(--summary-only)


def write_synthetic_repo(tmp_path, rows_spec=None):
    """생성 산출물(manifest, topk, public_k3) + 판정 산출물을 임시 루트에 쓴다."""
    qs = [question(f"q{i}") for i in range(6)]
    gen_rows = [gen_row(q.question_id) for q in qs]
    gen_rows[5] = gen_row("q5", abstain=True)
    gen_dir = tmp_path / jg.GENERATION_DIR
    gen_dir.mkdir(parents=True)
    (gen_dir / "manifest.json").write_text(
        json.dumps({"run_id": "run-1", "model": {"name": "m"}}), encoding="utf-8"
    )
    (gen_dir / "public_k3.jsonl").write_text(jg.jsonl_text(gen_rows), encoding="utf-8")
    items = plan(gen_rows, qs)
    judges = {"A": fake("A", lambda *_: GOOD), "B": fake("B", lambda *_: GOOD)}
    cache = judge.CallCache()
    log = jg.LimitLog(None)
    rows = jg.build_rows(items, jg.run_all_judges(judges, cache, tasks_of(items), log))
    topk = topk_stub(rows)
    (gen_dir / "topk.json").write_text(json.dumps(topk), encoding="utf-8")
    summary = jg.compute_summary({"public": rows}, topk)
    manifest = jg.new_manifest(
        judges=judges,
        generation_manifest={"run_id": "run-1", "model": {"name": "m"}},
        generation_dir=jg.GENERATION_DIR,
        root=tmp_path,
        rows_by_track={"public": rows},
        cache=cache,
        events=log.events(),
        problems=[],
        sample=True,
    )
    out = tmp_path / jg.JUDGMENT_DIR
    jg.write_outputs(out, {"public": rows}, summary, manifest)
    return out


def test_stored_outputs_pass_the_check_and_a_tampered_summary_fails(tmp_path):
    out = write_synthetic_repo(tmp_path)
    assert jg.check_stored(tmp_path, out) == []
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    summary["cells"][0]["faithfulness"]["n_agree"] += 1
    (out / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    problems = jg.check_stored(tmp_path, out)
    assert problems and "n_agree" in problems[0]


@pytest.mark.parametrize("what", ["row", "manifest_hash", "run_id", "topk", "missing_manifest"])
def test_stored_outputs_that_drift_from_the_manifest_or_generation_fail(tmp_path, what):
    out = write_synthetic_repo(tmp_path)
    if what == "row":
        lines = (out / "public.jsonl").read_text(encoding="utf-8").splitlines()
        row = json.loads(lines[0])
        row["faithfulness_A"] = "unsupported"
        row["faithfulness_reason_A"] = "claims_not_in_context"
        lines[0] = json.dumps(row)
        (out / "public.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    elif what == "manifest_hash":
        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        manifest["tracks"]["public"]["sha256"] = "0" * 64
        (out / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    elif what == "run_id":
        gen = tmp_path / jg.GENERATION_DIR / "manifest.json"
        gen.write_text(json.dumps({"run_id": "run-2", "model": {"name": "m"}}), encoding="utf-8")
    elif what == "topk":
        topk_path = tmp_path / jg.GENERATION_DIR / "topk.json"
        topk = json.loads(topk_path.read_text(encoding="utf-8"))
        topk["cells"][0]["false_abstain_rate"] = 0.99
        topk_path.write_text(json.dumps(topk), encoding="utf-8")
    else:
        (out / "manifest.json").unlink()
    assert jg.check_stored(tmp_path, out)


def test_rows_not_matching_the_generation_rows_fail_the_check(tmp_path):
    out = write_synthetic_repo(tmp_path)
    gen_path = tmp_path / jg.GENERATION_DIR / "public_k3.jsonl"
    rows = [json.loads(line) for line in gen_path.read_text(encoding="utf-8").splitlines()]
    rows[0]["abstain"] = True  # 생성 행의 기권 여부가 바뀌면 status 대응이 깨진다
    gen_path.write_text(jg.jsonl_text(rows), encoding="utf-8")
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    manifest["generation"]["rows"]["public"] = data.file_sha256(gen_path)
    (out / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert any("status" in p or "differ" in p for p in jg.check_stored(tmp_path, out))


# ------------------------------------------------------------ CLI (공개 트랙 + 가짜 판정자)


def cli_judges(responder=lambda *_: GOOD):
    return {"A": fake("A", responder), "B": fake("B", responder)}


def test_cli_public_sample_runs_with_fake_judges_and_writes_a_sample_manifest(tmp_path, capsys):
    out = tmp_path / "out"
    code = judge_generation.main(
        [
            "--track",
            "public",
            "--limit",
            "3",
            "--out-dir",
            str(out),
            "--cache-dir",
            str(tmp_path / "c"),
        ],
        judges=cli_judges(),
    )
    assert code == 0
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "sample" and manifest["calls"]["total"] == 6
    rows = [
        json.loads(line) for line in (out / "public.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len(rows) == 3 and all(r["status"] == "judged" for r in rows)
    assert json.loads(capsys.readouterr().out)["calls"] == 6


def test_cli_full_public_run_with_fake_judges_passes_the_gate_and_summary_only_matches(tmp_path):
    out = tmp_path / "out"
    cache = str(tmp_path / "c")
    assert (
        judge_generation.main(
            ["--track", "public", "--out-dir", str(out), "--cache-dir", cache], judges=cli_judges()
        )
        == 0
    )
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "complete" and manifest["problems"] == []
    assert manifest["tracks"]["public"]["n_judged"] >= jg.MIN_TARGETS
    assert judge_generation.main(["--summary-only", "--out-dir", str(out)]) == 0


def test_cli_exits_one_when_fewer_than_90_percent_are_valid_for_both_judges(tmp_path):
    out = tmp_path / "out"
    code = judge_generation.main(
        ["--track", "public", "--out-dir", str(out), "--cache-dir", str(tmp_path / "c")],
        judges={"A": fake("A", lambda *_: GOOD), "B": fake("B", lambda *_: "garbage")},
    )
    assert code == 1
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "incomplete" and manifest["problems"]
    retries = {(e["judge"], e["kind"]): e["n"] for e in manifest["calls"]["by_judge_kind"]}
    assert retries[("B", "retry")] == retries[("B", "judge")] > 0  # 질문마다 재질의 1회


def test_cli_exit_codes_for_usage_limit_and_judge_errors(tmp_path):
    def limit(*_):
        raise judge.JudgeUnavailable(LIMIT_MESSAGE)

    def broken(*_):
        raise judge.JudgeError("claude exit 1: error response omitted (3 chars)")

    base = ["--track", "public", "--limit", "1", "--jobs", "1", "--max-limit-waits", "0"]

    def out(name):
        return ["--out-dir", str(tmp_path / name), "--cache-dir", str(tmp_path / f"c-{name}")]

    assert judge_generation.main([*base, *out("a")], judges=cli_judges(limit)) == 3
    assert judge_generation.main([*base, *out("b")], judges=cli_judges(broken)) == 2


def test_cli_argument_errors(tmp_path):
    with pytest.raises(SystemExit):
        judge_generation.main(["--track", "public", "--limit", "3"])  # --out-dir 없음
    with pytest.raises(SystemExit):
        judge_generation.main(["--track", "kisa", "--out-dir", str(tmp_path)])  # --kisa-root 없음
    with pytest.raises(SystemExit):
        judge_generation.main(["--track", "public", "--limit", "0", "--out-dir", str(tmp_path)])


# ------------------------------------------------------------ 커밋된 산출물


def test_committed_judgments_pass_the_stored_check_when_present():
    out = ROOT / jg.JUDGMENT_DIR
    if not (out / "manifest.json").is_file():
        pytest.skip("results/m5/judgments is not committed yet")
    assert jg.check_stored(ROOT, out) == []
    assert judge_generation.main(["--summary-only"]) == 0
    for track in ("public", "kisa"):
        for line in (out / f"{track}.jsonl").read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            assert tuple(row) == jg.ROW_KEYS
            jg.validate_row(row)
    leaked = [
        p.name
        for p in out.iterdir()
        if p.suffix in (".json", ".jsonl") and "/Users" in p.read_text(encoding="utf-8")
    ]
    assert leaked == []

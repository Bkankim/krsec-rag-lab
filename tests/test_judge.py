"""교차 판정 도구 테스트. 모델은 부르지 않는다: 가짜 판정자와 합성 본문만 쓴다(KISA 본문 없음)."""

import json

import pytest

from krsec_rag_lab import judge
from krsec_rag_lab.judge import (
    GOLD,
    NONRELEVANT,
    NOT_RELEVANT,
    RELEVANT,
    UNJUDGED,
    CallCache,
    FakeJudge,
    Judgment,
    NoticeText,
)

BODY = "서론 문장이다. Acme Widget 1.2 이하에서 CVE-2099-0001 원격 코드 실행 취약점이 발견되었다. 결론 문장이다."
QUOTE = "Acme Widget 1.2 이하에서 CVE-2099-0001 원격 코드 실행 취약점이 발견되었다."


def notice(doc_id="1", text=BODY, base=0, truncated=False):
    return NoticeText(doc_id, f"제목 {doc_id}", "2026-01-01", text, base, truncated)


def answer(*entries):
    return json.dumps({"judgments": [dict(e) for e in entries]}, ensure_ascii=False)


def entry(doc_id="1", relevance=RELEVANT, code="cve_discussed", quote=QUOTE):
    return {"doc_id": doc_id, "relevance": relevance, "reason_code": code, "quote": quote}


# ------------------------------------------------------------ 본문 준비·인용 -> 오프셋


def test_short_notice_is_sent_whole_and_not_truncated():
    sent = judge.prepare_notice("1", "t", "d", "짧은 본문", "CVE-2099-0001")
    assert (sent.text, sent.base, sent.truncated) == ("짧은 본문", 0, False)


def test_long_notice_with_the_cve_sends_a_window_around_the_first_occurrence():
    body = "가" * 30_000 + " CVE-2099-0001은 여기 " + "나" * 30_000 + " CVE-2099-0001 다시"
    sent = judge.prepare_notice("1", "t", "d", body, "CVE-2099-0001")
    first = body.index("CVE-2099-0001")
    assert sent.truncated
    assert sent.base == first - 4_000
    assert sent.text == body[first - 4_000 : first + len("CVE-2099-0001") + 4_000]
    assert body.index(sent.text) == sent.base


def test_window_is_clipped_at_the_start_of_the_body():
    body = "CVE-2099-0001 시작" + "가" * 30_000
    sent = judge.prepare_notice("1", "t", "d", body, "CVE-2099-0001")
    assert sent.base == 0
    assert sent.text == body[: len("CVE-2099-0001") + 4_000]
    assert sent.truncated


@pytest.mark.parametrize(
    "cve_id",
    [None, "CVE-2099-0002"],
    ids=["no-cve-given", "cve-not-in-body"],
)
def test_long_notice_without_the_cve_sends_the_head_up_to_the_cap(cve_id):
    body = "다" * 25_000
    sent = judge.prepare_notice("1", "t", "d", body, cve_id)
    assert (len(sent.text), sent.base, sent.truncated) == (20_000, 0, True)
    assert sent.text == body[:20_000]


def test_window_search_respects_cve_boundaries():
    # CVE-2099-00011은 CVE-2099-0001이 아니다. 한글 조사가 붙은 CVE-2099-0001을은 맞다
    body = "가" * 30_000 + "CVE-2099-00011 " + "나" * 30_000 + "CVE-2099-0001을 본다"
    sent = judge.prepare_notice("1", "t", "d", body, "CVE-2099-0001")
    assert body.index("CVE-2099-0001을") - 4_000 == sent.base


def test_quote_becomes_offsets_into_the_normalized_body():
    start, end = judge.locate_quote(notice(), QUOTE)
    assert BODY[start:end] == QUOTE


def test_quote_offsets_add_the_window_base():
    sent = notice(text=BODY[5:], base=5, truncated=True)
    start, end = judge.locate_quote(sent, QUOTE)
    assert BODY[start:end] == QUOTE


@pytest.mark.parametrize(
    ("quote", "found"),
    [
        (f"  {QUOTE}\n", True),  # 앞뒤 공백은 걷는다
        (QUOTE.replace(" ", "  "), True),  # 연속 공백 차이만 허용한다
        ("본문에 없는 문장 전혀 다른 내용", False),
        ("짧은 인용", False),  # 8자 미만
        ("", False),
    ],
)
def test_locate_quote_tolerates_only_whitespace_differences(quote, found):
    assert (judge.locate_quote(notice(), quote) is not None) is found


def test_whitespace_tolerant_match_returns_the_span_of_the_original_text():
    body = "앞 문장. 첫째 줄입니다.\n  둘째 줄입니다. 뒷 문장."
    start, end = judge.locate_quote(notice(text=body), "첫째 줄입니다. 둘째 줄입니다.")
    assert body[start:end] == "첫째 줄입니다.\n  둘째 줄입니다."


# ------------------------------------------------------------ 응답 해석


def test_interpret_answer_drops_the_quote_and_keeps_offsets():
    result = judge.interpret_answer(answer(entry()), [notice()])
    start, end = judge.locate_quote(notice(), QUOTE)
    assert result == {
        "valid": True,
        "docs": {
            "1": {"relevance": RELEVANT, "reason_code": "cve_discussed", "evidence": [[start, end]]}
        },
    }
    assert QUOTE not in json.dumps(result, ensure_ascii=False)


def test_interpret_answer_marks_a_relevant_doc_with_an_unfindable_quote():
    result = judge.interpret_answer(answer(entry(quote="본문에 없는 인용 문장입니다")), [notice()])
    assert result["docs"]["1"]["evidence"] is None


def test_interpret_answer_accepts_code_fences_and_chatter():
    raw = (
        "결과입니다\n```json\n"
        + answer(entry(relevance=NOT_RELEVANT, code="cve_absent", quote=""))
        + "\n```"
    )
    result = judge.interpret_answer(raw, [notice()])
    assert result["docs"]["1"] == {
        "relevance": NOT_RELEVANT,
        "reason_code": "cve_absent",
        "evidence": [],
    }


@pytest.mark.parametrize(
    "raw",
    [
        "not json at all",
        json.dumps({"other": []}),
        json.dumps({"judgments": "x"}),
        "",
    ],
)
def test_interpret_answer_flags_unusable_responses(raw):
    assert judge.interpret_answer(raw, [notice()]) == {"valid": False, "docs": {}}


def test_interpret_answer_ignores_unknown_docs_bad_codes_and_repeats():
    raw = answer(
        entry(doc_id="9"),
        entry(code="made_up_code"),
        entry(relevance="maybe"),
        entry(doc_id="2", relevance=NOT_RELEVANT, code="cve_absent", quote=""),
        entry(doc_id="2", relevance=RELEVANT),
    )
    result = judge.interpret_answer(raw, [notice("1"), notice("2")])
    assert list(result["docs"]) == ["2"]
    assert result["docs"]["2"]["relevance"] == NOT_RELEVANT


def test_payload_has_only_the_question_the_notices_and_the_retry_ids():
    payload = json.loads(judge.build_payload("질문", [notice("1"), notice("2")], ["2"]))
    assert set(payload) == {"question", "notices", "retry"}
    assert set(payload["notices"][0]) == {"doc_id", "title", "date", "partial", "text"}


@pytest.mark.parametrize("count", [0, 9])
def test_payload_rejects_bundles_outside_one_to_eight(count):
    with pytest.raises(ValueError, match="1..8"):
        judge.build_payload("q", [notice(str(i)) for i in range(count)])


# ------------------------------------------------------------ 묶음 판정: 재질의와 no_evidence


def responder_from(*answers):
    """호출 순서대로 미리 정한 응답을 돌려주는 응답기."""
    queue = list(answers)
    return lambda _instruction, _payload: queue.pop(0)


def run_bundle(fake, notices=None, cache=None):
    return judge.judge_bundle(
        fake,
        cache or CallCache(),
        question_id="q1",
        question="CVE-2099-0001 관련 공지가 있나요?",
        notices=notices or [notice("1"), notice("2")],
        task="test",
    )


def test_quotes_found_on_the_first_call_need_one_call():
    fake = FakeJudge(
        "A",
        responder_from(answer(entry(), entry("2", NOT_RELEVANT, "cve_absent", ""))),
    )
    result = run_bundle(fake)
    assert len(fake.calls) == 1
    assert result["1"].status == "ok" and result["1"].label() == RELEVANT
    start, end = result["1"].evidence[0]
    assert BODY[start:end] == QUOTE
    assert result["2"].label() == NOT_RELEVANT and result["2"].evidence == ()


def test_unfindable_quote_is_asked_again_once_and_the_retry_can_fix_it():
    fake = FakeJudge(
        "A",
        responder_from(
            answer(
                entry(quote="본문에 없는 인용 문장입니다"),
                entry("2", NOT_RELEVANT, "cve_absent", ""),
            ),
            answer(entry(), entry("2", NOT_RELEVANT, "cve_absent", "")),
        ),
    )
    result = run_bundle(fake)
    assert len(fake.calls) == 2
    assert fake.calls[1]["retry"] == ["1"]
    assert "retry" not in fake.calls[0]
    assert result["1"].status == "ok" and result["1"].evidence


def test_quote_still_unfindable_after_the_retry_is_no_evidence_and_not_asked_a_third_time():
    bad = answer(
        entry(quote="본문에 없는 인용 문장입니다"), entry("2", NOT_RELEVANT, "cve_absent", "")
    )
    fake = FakeJudge("A", responder_from(bad, bad, bad))
    result = run_bundle(fake)
    assert len(fake.calls) == 2
    assert result["1"].status == "no_evidence" and result["1"].label() is None
    assert result["1"].relevance == RELEVANT and result["1"].evidence == ()
    assert result["2"].status == "ok"


def test_only_the_unresolved_docs_take_their_answer_from_the_retry():
    first = answer(
        entry(quote="본문에 없는 인용 문장입니다"), entry("2", NOT_RELEVANT, "cve_absent", "")
    )
    second = answer(entry(), entry("2", RELEVANT, "cve_discussed", QUOTE))
    result = run_bundle(FakeJudge("A", responder_from(first, second)))
    assert result["1"].status == "ok"
    assert result["2"].relevance == NOT_RELEVANT  # 첫 응답에서 이미 확정, 재질의 답은 쓰지 않는다


def test_unusable_responses_are_retried_once_then_invalid():
    fake = FakeJudge("A", responder_from("garbage", "still garbage"))
    result = run_bundle(fake)
    assert len(fake.calls) == 2
    assert {j.status for j in result.values()} == {"invalid"}
    assert all(j.relevance is None and j.label() is None for j in result.values())


def test_unusable_first_response_recovers_on_the_retry():
    fake = FakeJudge(
        "A", responder_from("garbage", answer(entry(), entry("2", NOT_RELEVANT, "cve_absent", "")))
    )
    assert {j.status for j in run_bundle(fake).values()} == {"ok"}


def test_a_doc_missing_from_the_answer_is_invalid():
    fake = FakeJudge("A", responder_from(answer(entry()), answer(entry())))
    result = run_bundle(fake)
    assert result["1"].status == "ok" and result["2"].status == "invalid"


def test_truncation_flag_is_recorded_per_notice():
    fake = FakeJudge(
        "A", responder_from(answer(entry(), entry("2", NOT_RELEVANT, "cve_absent", "")))
    )
    result = run_bundle(fake, [notice("1"), notice("2", truncated=True)])
    assert (result["1"].truncated, result["2"].truncated) == (False, True)


def test_cached_calls_are_not_repeated_and_the_cache_keeps_no_text(tmp_path):
    cache = CallCache(tmp_path / "cache")
    fake = FakeJudge(
        "A", responder_from(answer(entry(), entry("2", NOT_RELEVANT, "cve_absent", "")))
    )
    first = run_bundle(fake, cache=cache)
    resumed = FakeJudge("A", responder_from())  # 응답이 비어 있어 부르면 실패한다
    again = run_bundle(resumed, cache=CallCache(tmp_path / "cache"))
    assert resumed.calls == [] and again == first
    stored = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "cache").glob("*.json"))
    assert QUOTE not in stored and BODY not in stored


def test_judges_do_not_share_cache_entries():
    cache = CallCache()
    one = FakeJudge(
        "A", responder_from(answer(entry(), entry("2", NOT_RELEVANT, "cve_absent", "")))
    )
    two = FakeJudge(
        "B", responder_from(answer(entry(), entry("2", NOT_RELEVANT, "cve_absent", "")))
    )
    run_bundle(one, cache=cache)
    run_bundle(two, cache=cache)
    assert len(one.calls) == len(two.calls) == 1


def test_count_calls_separates_judge_retry_and_generation_calls():
    cache = CallCache()
    bad = answer(
        entry(quote="본문에 없는 인용 문장입니다"), entry("2", NOT_RELEVANT, "cve_absent", "")
    )
    run_bundle(FakeJudge("A", responder_from(bad, bad)), cache=cache)
    counts = judge.count_calls(cache)
    assert counts["total"] == 2
    assert counts["by_kind"] == [
        {"kind": "judge", "judge": "A", "n": 1},
        {"kind": "retry", "judge": "A", "n": 1},
    ]
    assert counts["first_at"] <= counts["last_at"]


# ------------------------------------------------------------ 일치 규칙


def judgment(label, status="ok", truncated=False, doc_id="1", code=None):
    evidence = ((3, 9),) if label == RELEVANT and status == "ok" else ()
    code = code or ("cve_discussed" if label == RELEVANT else "cve_absent")
    return Judgment("q1", doc_id, label, code, evidence, truncated, status)


@pytest.mark.parametrize(
    ("a", "b", "outcome", "why"),
    [
        (judgment(RELEVANT), judgment(RELEVANT), GOLD, "agree_relevant"),
        (judgment(NOT_RELEVANT), judgment(NOT_RELEVANT), NONRELEVANT, "agree_not_relevant"),
        (judgment(RELEVANT), judgment(NOT_RELEVANT), UNJUDGED, "disagree"),
        (judgment(NOT_RELEVANT), judgment(RELEVANT), UNJUDGED, "disagree"),
        (judgment(RELEVANT, "no_evidence"), judgment(RELEVANT), UNJUDGED, "no_evidence"),
        (judgment(RELEVANT), judgment(RELEVANT, "no_evidence"), UNJUDGED, "no_evidence"),
        (judgment(None, "invalid"), judgment(RELEVANT), UNJUDGED, "invalid"),
        (
            judgment(NOT_RELEVANT, truncated=True),
            judgment(NOT_RELEVANT, truncated=True),
            UNJUDGED,
            "truncated_not_relevant",
        ),
        (
            judgment(NOT_RELEVANT, truncated=True),
            judgment(NOT_RELEVANT),
            UNJUDGED,
            "truncated_not_relevant",
        ),
        # 잘린 공지라도 둘 다 relevant(근거 있음)이면 gold다
        (
            judgment(RELEVANT, truncated=True),
            judgment(RELEVANT, truncated=True),
            GOLD,
            "agree_relevant",
        ),
    ],
)
def test_resolve_pair(a, b, outcome, why):
    resolution = judge.resolve_pair(a, b)
    assert (resolution.outcome, resolution.why) == (outcome, why)


def test_gold_keeps_both_judges_evidence_spans():
    a = Judgment("q1", "1", RELEVANT, "cve_discussed", ((3, 9),), False, "ok")
    b = Judgment("q1", "1", RELEVANT, "product_matches", ((5, 20),), False, "ok")
    resolution = judge.resolve_pair(a, b)
    assert (resolution.a.evidence, resolution.b.evidence) == (((3, 9),), ((5, 20),))


def test_resolve_pair_rejects_judgments_of_different_pairs():
    with pytest.raises(ValueError, match="different pairs"):
        judge.resolve_pair(judgment(RELEVANT, doc_id="1"), judgment(RELEVANT, doc_id="2"))


# ------------------------------------------------------------ kappa


def labels(rr=0, rn=0, nr=0, nn=0):
    return (
        [(RELEVANT, RELEVANT)] * rr
        + [(RELEVANT, NOT_RELEVANT)] * rn
        + [(NOT_RELEVANT, RELEVANT)] * nr
        + [(NOT_RELEVANT, NOT_RELEVANT)] * nn
    )


def test_kappa_hand_calculation():
    # 10쌍: 둘 다 relevant 4, A만 relevant 1, B만 relevant 1, 둘 다 not 4
    # po = 8/10, A relevant 비율 = 5/10, B = 5/10, pe = .25 + .25 = .5, kappa = (.8 - .5) / .5 = .6
    result = judge.cohen_kappa(labels(rr=4, rn=1, nr=1, nn=4))
    assert result == {
        "n": 10,
        "value": 0.6,
        "observed_agreement": 0.8,
        "expected_agreement": 0.5,
        "null_reason": None,
    }


def test_kappa_second_hand_calculation_with_unequal_marginals():
    # 20쌍: rr 9, rn 3, nr 2, nn 6. po = 15/20 = .75, A relevant = 12/20 = .6, B = 11/20 = .55
    # pe = .6 * .55 + .4 * .45 = .33 + .18 = .51, kappa = (.75 - .51) / .49 = 0.489796
    result = judge.cohen_kappa(labels(rr=9, rn=3, nr=2, nn=6))
    assert result["value"] == pytest.approx(0.24 / 0.49, abs=1e-6)
    assert result["expected_agreement"] == pytest.approx(0.51)


def test_kappa_is_one_for_perfect_agreement_with_both_labels():
    assert judge.cohen_kappa(labels(rr=3, nn=2))["value"] == 1.0


def test_kappa_is_minus_one_for_complete_disagreement():
    assert judge.cohen_kappa(labels(rn=2, nr=2))["value"] == -1.0


@pytest.mark.parametrize(
    ("pairs", "reason"),
    [
        ([], "no valid label pairs"),
        (labels(nn=7), "single label"),
        (labels(rr=7), "single label"),
    ],
    ids=["empty", "all-not-relevant", "all-relevant"],
)
def test_kappa_is_null_with_a_reason_when_undefined(pairs, reason):
    result = judge.cohen_kappa(pairs)
    assert result["value"] is None
    assert reason in result["null_reason"]
    assert result["n"] == len(pairs)


def test_kappa_uses_only_pairs_where_both_judges_have_a_valid_label():
    resolutions = [
        judge.resolve_pair(judgment(RELEVANT, doc_id="1"), judgment(RELEVANT, doc_id="1")),
        judge.resolve_pair(judgment(NOT_RELEVANT, doc_id="2"), judgment(NOT_RELEVANT, doc_id="2")),
        judge.resolve_pair(
            judgment(NOT_RELEVANT, truncated=True, doc_id="3"),
            judgment(NOT_RELEVANT, truncated=True, doc_id="3"),
        ),  # unjudged지만 kappa에는 들어간다(필터 전)
        judge.resolve_pair(
            judgment(RELEVANT, "no_evidence", doc_id="4"), judgment(RELEVANT, doc_id="4")
        ),
        judge.resolve_pair(
            judgment(None, "invalid", doc_id="5"), judgment(NOT_RELEVANT, doc_id="5")
        ),
    ]
    summary = judge.summarize(resolutions)
    assert summary["kappa"]["n"] == 3
    assert (summary["n_pairs"], summary["n_valid_pairs"]) == (5, 3)
    assert (summary["n_gold"], summary["n_not_relevant"], summary["n_unjudged"]) == (1, 1, 3)
    assert summary["unjudged_reasons"] == [
        {"reason": "invalid", "n": 1},
        {"reason": "no_evidence", "n": 1},
        {"reason": "truncated_not_relevant", "n": 1},
    ]


def test_summary_counts_agree_and_disagree_among_valid_pairs():
    resolutions = [
        judge.resolve_pair(judgment(RELEVANT, doc_id="1"), judgment(RELEVANT, doc_id="1")),
        judge.resolve_pair(judgment(RELEVANT, doc_id="2"), judgment(NOT_RELEVANT, doc_id="2")),
        judge.resolve_pair(judgment(NOT_RELEVANT, doc_id="3"), judgment(RELEVANT, doc_id="3")),
    ]
    summary = judge.summarize(resolutions)
    assert (summary["n_agree"], summary["n_disagree"]) == (1, 2)


# ------------------------------------------------------------ 오류율


def test_error_rates_use_agreed_pairs_without_unjudged_as_the_denominator():
    def pair(doc_id, a, b, truncated=False):
        return judge.resolve_pair(
            judgment(a, truncated=truncated, doc_id=doc_id),
            judgment(b, truncated=truncated, doc_id=doc_id),
        )

    resolutions = [
        pair("1", RELEVANT, RELEVANT),  # 후보 안, gold
        pair("2", NOT_RELEVANT, NOT_RELEVANT),  # 후보 안, 오라벨
        pair("3", NOT_RELEVANT, NOT_RELEVANT),  # 후보 안, 오라벨
        pair("4", RELEVANT, NOT_RELEVANT),  # 후보 안, 갈림 -> 분모 제외
        pair("5", NOT_RELEVANT, NOT_RELEVANT, truncated=True),  # 후보 안, 잘림 -> 분모 제외
        pair("6", RELEVANT, RELEVANT),  # 후보 밖, 누락
        pair("7", NOT_RELEVANT, NOT_RELEVANT),  # 후보 밖, 정상
        pair("8", NOT_RELEVANT, NOT_RELEVANT),  # 후보 밖, 정상
        pair("9", NOT_RELEVANT, RELEVANT),  # 후보 밖, 갈림 -> 분모 제외
    ]
    inside = {"1", "2", "3", "4", "5"}
    in_candidate = {("q1", r.doc_id): r.doc_id in inside for r in resolutions}
    rates = judge.error_rate(resolutions, in_candidate)
    assert rates["mislabel"] == {
        "scope": "in_candidate_set",
        "denominator": 3,
        "n_error": 2,
        "rate": round(2 / 3, 6),
    }
    assert rates["omission"] == {
        "scope": "outside_candidate_set",
        "denominator": 3,
        "n_error": 1,
        "rate": round(1 / 3, 6),
    }


def test_error_rate_is_null_when_a_denominator_is_empty():
    resolutions = [judge.resolve_pair(judgment(RELEVANT), judgment(RELEVANT))]
    rates = judge.error_rate(resolutions, {("q1", "1"): True})
    assert rates["omission"]["denominator"] == 0 and rates["omission"]["rate"] is None


# ------------------------------------------------------------ 질문 복사 검사


BODY_FOR_COPY = "관리자 페이지의 인증 우회 취약점을 통해 원격 공격자가 임의 명령을 실행할 수 있다. 패치를 적용한다."


@pytest.mark.parametrize(
    ("query", "copies"),
    [
        ("관리자 페이지의 인증 우회 취약점을 통해 무엇이 가능한가요?", True),  # 15자 이상 연속 겹침
        ("관리자  페이지의 인증 우회 취약점을 통해 어떻게 되나요", True),  # 공백 차이는 무시
        ("원격 공격자가 임의 명령을 실행할 수 있다", True),
        ("인증을 우회해서 명령을 실행하는 문제는 어느 공지인가요?", False),
        ("어떤 제품의 취약점인가요?", False),
    ],
)
def test_copies_body(query, copies):
    assert judge.copies_body(query, BODY_FOR_COPY) is copies


def test_copies_body_catches_a_whole_sentence_shorter_than_the_overlap_window():
    body = "보안 패치를 즉시 적용 바랍니다. 추가 안내는 공지 참조."
    assert judge.copies_body("보안 패치를 즉시 적용 바랍니다라고 하는데 무슨 뜻인가요?", body)
    assert not judge.copies_body("패치 적용 시점이 언제까지인가요?", body)


def test_copies_body_boundary_is_fifteen_characters():
    body = "가나다라마바사아자차카타파하거너더러머버서어저처커터퍼허"
    assert judge.copies_body("가나다라마바사아자차카타파하거", body)  # 15자
    assert not judge.copies_body("가나다라마바사아자차카타파하", body)  # 14자


def test_a_fake_model_that_copies_the_body_gets_its_question_rejected():
    copied = json.dumps(
        {"question": "관리자 페이지의 인증 우회 취약점을 통해 뭐가 되나요?"}, ensure_ascii=False
    )
    query = judge.clean_question(copied)
    assert judge.check_question(query, BODY_FOR_COPY) == "copies_body"


def test_clean_question_replaces_em_dash_with_a_hyphen_and_squeezes_spaces():
    raw = json.dumps({"question": "제품 A \u2014  버전 2에서 오류가 나요"}, ensure_ascii=False)
    assert judge.clean_question(raw) == "제품 A - 버전 2에서 오류가 나요"


@pytest.mark.parametrize(
    "raw", ["", "no json", json.dumps({"question": 3}), json.dumps({"question": "  "})]
)
def test_clean_question_rejects_unusable_answers(raw):
    assert judge.clean_question(raw) is None


@pytest.mark.parametrize(
    ("query", "reason"),
    [
        ("가" * 81, "too_long"),
        ("가" * 80, None),
        ("English only question", "not_korean"),
        ("CVE-2099-0001 취약점은 무엇인가요", "has_cve_id"),
        ("어떤 제품의 취약점인가요?", None),
    ],
)
def test_check_question(query, reason):
    assert judge.check_question(query, "무관한 본문") == reason


# ------------------------------------------------------------ 분할


def record(qid, query_type, doc_ids, cve_ids=(), query=None, excluded=False):
    return {
        "question_id": qid,
        "query": query or f"{qid} 질문입니다",
        "query_type": query_type,
        "cve_ids": list(cve_ids),
        "answers": [{"doc_id": d} for d in doc_ids],
        "excluded": excluded,
    }


def catalog(n):
    return [
        {
            "nttId": str(100 + i),
            "title": f"공지 {i}번",
            "date": f"2026-0{1 + i % 9}-01",
            "cve_ids": [f"CVE-2026-{1000 + i}"],
        }
        for i in range(n)
    ]


def test_assign_splits_keeps_groups_together_and_reaches_the_target_share():
    notices = catalog(30)
    # 질문 둘이 같은 공지를 공유하는 블록 4개 + 단독 질문 12개
    records = [record(f"s{i}", "product_symptom", [str(100 + i // 2)]) for i in range(8)]
    records += [record(f"e{i}", "explanation_comparison", [str(110 + i)]) for i in range(12)]
    sides = judge.assign_splits(records, notices, seed=27)
    from krsec_rag_lab.splits import assert_disjoint

    items = [
        {
            "id": r["question_id"],
            "split": sides[r["question_id"]],
            "ntt_ids": [a["doc_id"] for a in r["answers"]],
            "cve_ids": r["cve_ids"],
            "query": r["query"],
        }
        for r in records
    ]
    assert_disjoint(items, notices)
    for i in range(0, 8, 2):
        assert sides[f"s{i}"] == sides[f"s{i + 1}"]
    dev = sum(1 for side in sides.values() if side == "dev")
    assert 0.3 <= dev / len(records) <= 0.5


def test_assign_splits_is_deterministic_for_a_seed():
    notices = catalog(20)
    records = [record(f"q{i}", "explanation_comparison", [str(100 + i)]) for i in range(20)]
    assert judge.assign_splits(records, notices, seed=27) == judge.assign_splits(
        records, notices, seed=27
    )


def test_assign_splits_does_not_count_excluded_records_in_the_share():
    notices = catalog(20)
    records = [record(f"q{i}", "explanation_comparison", [str(100 + i)]) for i in range(10)]
    records += [
        record(f"x{i}", "explanation_comparison", [], excluded=True, query=f"제외 질문 {i}번")
        for i in range(6)
    ]
    sides = judge.assign_splits(records, notices, seed=27)
    scored_dev = sum(1 for r in records if not r["excluded"] and sides[r["question_id"]] == "dev")
    assert scored_dev == 4


def test_shared_cve_through_different_notices_makes_one_block():
    notices = catalog(4)
    notices[1]["cve_ids"] = [*notices[1]["cve_ids"], notices[0]["cve_ids"][0]]
    records = [
        record("a", "product_symptom", ["100"]),
        record("b", "product_symptom", ["101"]),
        record("c", "product_symptom", ["102"]),
    ]
    sides = judge.assign_splits(records, notices, seed=27)
    assert sides["a"] == sides["b"]


# ------------------------------------------------------------ 무답 CVE


def test_absent_cve_candidates_are_valid_deterministic_and_skip_excluded():
    from krsec_rag_lab.splits import CVE_ID_RE

    first = [c for _, c in zip(range(30), judge.absent_cve_candidates(27, set()), strict=False)]
    assert first == [
        c for _, c in zip(range(30), judge.absent_cve_candidates(27, set()), strict=False)
    ]
    assert all(CVE_ID_RE.fullmatch(c) for c in first) and len(set(first)) == 30
    skipping = [
        c
        for _, c in zip(
            range(30), judge.absent_cve_candidates(27, {first[0], first[3]}), strict=False
        )
    ]
    assert first[0] not in skipping and first[3] not in skipping


def test_call_budget_stops_at_the_cap():
    budget = judge.CallBudget(cap=3)
    assert [budget.take() for _ in range(5)] == [True, True, True, False, False]
    assert budget.used == 3


# ------------------------------------------------------------ 실제 판정자의 호출 형식(프로세스를 띄우지 않는다)


def test_claude_command_isolates_the_judge():
    command = judge.ClaudeJudge().command("INSTRUCTION")
    assert command[:3] == ["claude", "-p", "INSTRUCTION"]
    for flag in (
        "--safe-mode",
        "--tools=",
        "--no-session-persistence",
        "--strict-mcp-config",
        "--output-format",
    ):
        assert flag in command
    assert command[command.index("--model") + 1] == "claude-opus-5-5"


def test_codex_command_is_read_only_ephemeral_and_schema_bound(tmp_path):
    command = judge.CodexJudge().command("INSTRUCTION", tmp_path / "schema.json")
    assert command[:2] == ["codex", "exec"] and command[-1] == "INSTRUCTION"
    assert command[command.index("-s") + 1] == "read-only"
    assert command[command.index("-m") + 1] == "gpt-6.1-sol"
    for flag in (
        "--ephemeral",
        "--json",
        "--skip-git-repo-check",
        "--ignore-user-config",
        "--output-schema",
    ):
        assert flag in command


def test_answer_schema_lists_exactly_the_fixed_reason_codes():
    items = judge.ANSWER_SCHEMA["properties"]["judgments"]["items"]
    assert items["properties"]["reason_code"]["enum"] == list(judge.REASON_CODE_NAMES)
    assert set(items["required"]) == set(items["properties"])
    assert len(set(judge.REASON_CODE_NAMES)) == len(judge.REASON_CODES)

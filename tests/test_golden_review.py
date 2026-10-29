"""오류율 계산기와 골든셋 스키마 검증기 테스트. 검수 입력과 골든셋 레코드는 전부 합성이다."""

import copy
import csv
import itertools
import json
from pathlib import Path

import pytest

from krsec_rag_lab import golden
from krsec_rag_lab.golden import (
    FORBIDDEN_TEXT_FIELDS,
    REVIEW_COLUMNS,
    REVIEW_HUMAN,
    REVIEW_SHEET_FILE,
    REVIEW_TEMPLATE_FILE,
    GoldenSchemaError,
    ReviewSheetError,
    assert_valid_golden,
    error_rates,
    read_review_rows,
    validate_golden,
)

ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------ 오류율


_ROW_IDS = itertools.count(1)  # 행마다 doc_id가 달라야 중복 행 검사에 걸리지 않는다


def review_row(in_set, relevance="", error_class="", reason="synthetic reason", **overrides):
    row = dict.fromkeys(REVIEW_COLUMNS, "")
    row.update(
        question_id="cq-synthetic",
        doc_id=str(next(_ROW_IDS)),
        in_candidate_set="true" if in_set else "false",
        relevance=relevance,
        error_class=error_class,
        reason=reason if relevance else "",
        evidence_start="10" if relevance == "relevant" else "",
        evidence_end="40" if relevance == "relevant" else "",
    )
    row.update(overrides)
    return row


C_OK = ("candidate", "relevant", "ok")
C_MIS = ("candidate", "not_relevant", "mislabel")
O_OK = ("outside", "not_relevant", "ok")
O_OMIT = ("outside", "relevant", "omission")


def rows_of(*specs):
    return [
        review_row(kind == "candidate", relevance, error_class)
        for kind, relevance, error_class in specs
    ]


@pytest.mark.parametrize(
    ("rows", "n_pending", "mislabel", "omission"),
    [
        # 후보 5쌍 중 오라벨 1, 후보 밖 3쌍 중 누락 1
        (
            rows_of(C_OK, C_OK, C_OK, C_OK, C_MIS, O_OK, O_OK, O_OMIT),
            0,
            (5, 1, 0.2),
            (3, 1, 1 / 3),
        ),
        # 오류 없음
        (rows_of(C_OK, C_OK, O_OK, O_OK), 0, (2, 0, 0.0), (2, 0, 0.0)),
        # 전부 오류
        (rows_of(C_MIS, C_MIS, O_OMIT), 0, (2, 2, 1.0), (1, 1, 1.0)),
        # 후보 밖 행이 없으면 누락률은 정의되지 않는다
        (rows_of(C_OK, C_MIS), 0, (2, 1, 0.5), (0, 0, None)),
        # 후보 행이 없으면 오라벨률은 정의되지 않는다
        (rows_of(O_OK, O_OMIT), 0, (0, 0, None), (2, 1, 0.5)),
        # 미검수 행은 분모에서 빠진다
        (
            [*rows_of(C_OK, C_MIS, O_OMIT), review_row(True), review_row(False)],
            2,
            (2, 1, 0.5),
            (1, 1, 1.0),
        ),
        # 전부 미검수
        ([review_row(True), review_row(False)], 2, (0, 0, None), (0, 0, None)),
        ([], 0, (0, 0, None), (0, 0, None)),
    ],
)
def test_error_rates_matrix(rows, n_pending, mislabel, omission):
    result = error_rates(rows)
    assert result["n_rows"] == len(rows)
    assert result["n_pending"] == n_pending
    assert result["n_reviewed"] == len(rows) - n_pending
    for key, (n_reviewed, n_error, rate) in (("mislabel", mislabel), ("omission", omission)):
        assert result[key]["n_reviewed"] == n_reviewed
        assert result[key]["n_error"] == n_error
        assert (
            result[key]["rate"] == pytest.approx(rate)
            if rate is not None
            else result[key]["rate"] is None
        )


def test_mislabel_and_omission_are_computed_separately():
    # 오라벨 1/2와 누락 1/4가 서로의 분모에 섞이지 않는다
    result = error_rates(rows_of(C_OK, C_MIS, O_OK, O_OK, O_OK, O_OMIT))
    assert result["mislabel"]["rate"] == 0.5
    assert result["omission"]["rate"] == 0.25


@pytest.mark.parametrize(
    ("row", "message"),
    [
        (review_row(True, "relevant", "mislabel"), "contradicts"),
        (review_row(True, "not_relevant", "ok"), "contradicts"),
        (review_row(False, "relevant", "ok"), "contradicts"),
        (review_row(False, "not_relevant", "omission"), "contradicts"),
        (review_row(True, "relevant", ""), "contradicts"),
        (review_row(True, "maybe", "ok"), "relevance must be one of"),
        (review_row(True, "relevant", "ok", reason=""), "reason is required"),
        (
            review_row(True, "relevant", "ok", reason="synthetic", evidence_start=""),
            "integer evidence",
        ),
        (review_row(True, "relevant", "ok", evidence_start="abc"), "integer evidence"),
        (review_row(True, "relevant", "ok", evidence_start="40", evidence_end="40"), "start < end"),
        (review_row(True, "relevant", "ok", evidence_start="-1"), "start < end"),
        (review_row(True, "", "ok"), "error_class without relevance"),
        (review_row(True, "relevant", "ok", in_candidate_set="yes"), "must be true/false"),
    ],
)
def test_error_rates_rejects_inconsistent_rows(row, message):
    with pytest.raises(ReviewSheetError, match=message):
        error_rates([row])


def write_sheet(path, rows, columns=REVIEW_COLUMNS):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=columns, lineterminator="\n", extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(rows)


def test_error_rates_from_a_csv_file_via_cli(tmp_path, capsys):
    sheet = tmp_path / "review_synthetic_filled.csv"
    write_sheet(sheet, rows_of(C_OK, C_MIS, O_OK, O_OMIT))
    assert golden.main(["error-rates", str(sheet)]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["mislabel"] == {"n_reviewed": 2, "n_error": 1, "rate": 0.5}
    assert printed["omission"] == {"n_reviewed": 2, "n_error": 1, "rate": 0.5}


def test_read_review_rows_rejects_a_sheet_missing_columns(tmp_path):
    sheet = tmp_path / "review_synthetic_short.csv"
    write_sheet(sheet, [], columns=[c for c in REVIEW_COLUMNS if c != "error_class"])
    with pytest.raises(ReviewSheetError, match="missing columns"):
        read_review_rows(sheet)


def test_committed_review_files_hold_no_human_results():
    template = read_review_rows(ROOT / REVIEW_TEMPLATE_FILE)
    sheet = read_review_rows(ROOT / REVIEW_SHEET_FILE)
    assert template == []
    assert len(sheet) >= golden.MIN_SAMPLE_PAIRS
    assert all(not row[column] for row in sheet for column in REVIEW_HUMAN)
    result = error_rates(sheet)
    assert result["n_pending"] == len(sheet)
    assert result["mislabel"]["rate"] is None and result["omission"]["rate"] is None


# ------------------------------------------------------------ 골든셋 스키마 검증기

SHA_72 = "a" * 64
SHA_73 = "b" * 64
NOTICES = [
    {
        "nttId": "72",
        "title": "Alpha 제품 보안 업데이트 권고",
        "date": "2026-01-01",
        "cve_ids": ["CVE-2026-0001"],
    },
    {
        "nttId": "73",
        "title": "Beta 제품 보안 업데이트 권고",
        "date": "2026-03-01",
        "cve_ids": ["CVE-2026-0002"],
    },
    {"nttId": "74", "title": "명절 사이버사기 주의", "date": "2026-05-01", "cve_ids": []},
]
VERSIONS = {"72": SHA_72, "73": SHA_73, "74": "c" * 64}


def answer(doc_id="72", sha=SHA_72):
    return {
        "doc_id": doc_id,
        "doc_sha256": sha,
        "evidence": [{"parser_version": "synthetic-v1", "start": 10, "end": 40}],
        "reason": "synthetic reason without any quoted text",
    }


def record(
    question_id="g1", query_type="cve_explicit", query="CVE-2026-0001는 어느 공지인가요?", **extra
):
    base = {
        "question_id": question_id,
        "query": query,
        "query_type": query_type,
        "answers": [answer()],
    }
    base.update(extra)
    return base


def validate(records, **kwargs):
    kwargs.setdefault("notices", NOTICES)
    kwargs.setdefault("doc_versions", VERSIONS)
    kwargs.setdefault("parser_version", "synthetic-v1")
    return validate_golden(records, **kwargs)


VALID_RECORDS = {
    "cve_explicit": record(),
    "product_symptom": record(
        query_type="product_symptom", query="Alpha 제품의 인증 우회는 어느 공지인가요?"
    ),
    "explanation_comparison": record(
        query_type="explanation_comparison", query="Alpha 공지의 권고 조치는 무엇인가요?"
    ),
    "no_answer": {
        "question_id": "g4",
        "query": "존재하지 않는 제품의 취약점은 무엇인가요?",
        "query_type": "no_answer",
        "answers": [],
        "no_answer_reason": "synthetic reason: no notice covers this",
    },
}


@pytest.mark.parametrize("query_type", sorted(VALID_RECORDS))
def test_valid_records_pass(query_type):
    assert validate([VALID_RECORDS[query_type]]) == []


def test_valid_records_pass_together_and_assert_valid_golden_does_not_raise():
    records = [dict(r, question_id=f"g-{t}") for t, r in VALID_RECORDS.items()]
    assert_valid_golden(
        records, notices=NOTICES, doc_versions=VERSIONS, parser_version="synthetic-v1"
    )


def without(obj, key):
    return {k: v for k, v in obj.items() if k != key}


def with_answer(**changes):
    base = answer()
    return record(answers=[{**base, **changes}])


def missing_answer_key(key):
    return record(answers=[without(answer(), key)])


@pytest.mark.parametrize(
    ("bad", "message"),
    [
        # 필수 필드가 빠졌다
        (without(record(), "question_id"), "question_id must be a non-empty string"),
        (without(record(), "query"), "query must be a non-empty string"),
        (without(record(), "query_type"), "query_type must be one of"),
        (without(record(), "answers"), "answers must be a list"),
        (missing_answer_key("doc_id"), "doc_id is required"),
        (missing_answer_key("doc_sha256"), "doc_sha256 must be 64 lowercase hex"),
        (missing_answer_key("evidence"), "evidence must be a non-empty list"),
        (missing_answer_key("reason"), "reason must be a non-empty string"),
        (with_answer(evidence=[]), "evidence must be a non-empty list"),
        (with_answer(reason="  "), "reason must be a non-empty string"),
        # 값이 틀렸다
        (record(query_type="keyword"), "query_type must be one of"),
        (with_answer(doc_sha256="A" * 64), "64 lowercase hex"),
        (with_answer(doc_sha256="a" * 63), "64 lowercase hex"),
        (with_answer(doc_sha256=SHA_73), "does not match the KISA manifest"),
        (with_answer(doc_id="999"), "not in notice catalog"),
        (
            with_answer(evidence=[{"parser_version": "synthetic-v1", "start": 40, "end": 40}]),
            "0 <= start < end",
        ),
        (
            with_answer(evidence=[{"parser_version": "synthetic-v1", "start": -1, "end": 5}]),
            "0 <= start < end",
        ),
        (
            with_answer(evidence=[{"parser_version": "synthetic-v1", "start": True, "end": 5}]),
            "0 <= start < end",
        ),
        (
            with_answer(evidence=[{"parser_version": "synthetic-v1", "start": "1", "end": 5}]),
            "0 <= start < end",
        ),
        (with_answer(evidence=[{"start": 1, "end": 5}]), "parser_version is required"),
        (
            with_answer(evidence=[{"parser_version": "other-v9", "start": 1, "end": 5}]),
            "parser_version 'other-v9'",
        ),
        (with_answer(reason="x" * 501), "longer than 500"),
        (record(cve_ids=["CVE-26-1"]), "malformed CVE ID"),
        (record(cve_ids="CVE-2026-0001"), "cve_ids must be a list"),
        (record(split="train"), "split must be dev or test"),
        (record(answers=[answer(), answer()]), "duplicate doc_id"),
        # 질의 유형 규칙(eval-protocol 5절)
        (record(query="Alpha 공지는 무엇인가요?"), "cve_explicit query has no CVE ID"),
        (
            record(query_type="product_symptom", query="CVE-2026-0001 영향 제품은?"),
            "must be cve_explicit",
        ),
        (
            record(query_type="explanation_comparison", query="CVE-2026-0001이 왜 위험한가요?"),
            "must be cve_explicit",
        ),
        (record(answers=[]), "needs at least one answer"),
        (dict(VALID_RECORDS["no_answer"], answers=[answer()]), "no_answer must have empty answers"),
        (
            without(VALID_RECORDS["no_answer"], "no_answer_reason"),
            "no_answer_reason must be a non-empty string",
        ),
        (record(no_answer_reason="synthetic"), "no_answer_reason only belongs to no_answer"),
        ("not an object", "record must be an object"),
    ],
)
def test_schema_validator_rejects(bad, message):
    errors = validate([bad])
    assert errors, "validator accepted an invalid record"
    assert any(message in e for e in errors), errors


@pytest.mark.parametrize("field", sorted(FORBIDDEN_TEXT_FIELDS))
@pytest.mark.parametrize("level", ["record", "answer", "evidence"])
def test_schema_validator_rejects_body_text_fields(field, level):
    bad = copy.deepcopy(record())
    target = {
        "record": bad,
        "answer": bad["answers"][0],
        "evidence": bad["answers"][0]["evidence"][0],
    }[level]
    target[field] = "synthetic text standing in for a body"
    errors = validate([bad])
    assert any(f"body text field not allowed: {field}" in e for e in errors), errors


def test_schema_validator_rejects_unknown_fields():
    errors = validate([record(notes="free form")])
    assert any("unknown field: notes" in e for e in errors)


def test_schema_validator_rejects_duplicate_question_ids():
    errors = validate([record(), record()])
    assert any("duplicate question_id" in e for e in errors)


def test_assert_valid_golden_raises_with_all_errors():
    with pytest.raises(GoldenSchemaError) as caught:
        assert_valid_golden(
            [without(record(), "query_type"), with_answer(doc_id="999")], notices=NOTICES
        )
    assert len(caught.value.errors) >= 2


def test_validator_without_catalog_skips_catalog_checks():
    assert validate_golden([with_answer(doc_id="999")]) == []


# ------------------------------------------------------------ dev/test 분할 검사 호출


def split_records(second_doc="72", second_split="test"):
    first = record("g1", split="dev", cve_ids=["CVE-2026-0001"])
    second = record(
        "g2",
        query_type="explanation_comparison",
        query="Alpha 공지의 권고 조치는 무엇인가요?",
        split=second_split,
        answers=[answer(second_doc, VERSIONS[second_doc])],
    )
    return [first, second]


def test_split_check_rejects_the_same_notice_in_dev_and_test():
    errors = validate(split_records())
    assert any("split check failed" in e and "notice=72" in e for e in errors), errors


def test_split_check_rejects_a_shared_cve_across_different_notices():
    # 73이 인용한 CVE-2026-0002를 dev 질의가 직접 적었다
    records = split_records(second_doc="73")
    records[0]["cve_ids"] = ["CVE-2026-0001", "CVE-2026-0002"]
    errors = validate(records)
    assert any("split check failed" in e and "cve=CVE-2026-0002" in e for e in errors), errors


def test_split_check_accepts_disjoint_groups():
    assert validate(split_records(second_doc="73")) == []


def test_split_check_accepts_same_split_even_when_sharing_a_notice():
    assert validate(split_records(second_split="dev")) == []


def test_split_must_be_set_on_every_record_or_none():
    records = split_records(second_doc="73")
    del records[1]["split"]
    assert validate(records) == ["split must be set on every record or on none"]


def test_split_check_needs_the_notice_catalog():
    records = split_records(second_doc="73")
    assert validate(records, notices=None) == ["notices are required for the dev/test split check"]


# ------------------------------------------------------------ validate 명령(실제 KISA manifest 사용)


def real_golden_line(**changes):
    """공개 manifest의 nttId·sha256과 합성 근거 위치로 만든 레코드. 본문은 없다."""
    notices = golden.load_notices(ROOT / golden.KISA_METADATA)
    parser_version, versions = golden.load_doc_versions(ROOT / golden.KISA_MANIFEST)
    ntt_id = notices[0]["nttId"]
    base = record(
        "g-synthetic",
        query=f"{notices[0]['cve_ids'][0]}는 어느 공지에서 다루나요?",
        answers=[
            {
                "doc_id": ntt_id,
                "doc_sha256": versions[ntt_id],
                "evidence": [{"parser_version": parser_version, "start": 0, "end": 10}],
                "reason": "synthetic reason",
            }
        ],
    )
    return {**base, **changes}


def test_validate_command_accepts_a_synthetic_record_built_from_public_metadata(tmp_path):
    path = tmp_path / "golden_synthetic.jsonl"
    path.write_text(json.dumps(real_golden_line(), ensure_ascii=False) + "\n", encoding="utf-8")
    assert golden.main(["validate", str(path), "--root", str(ROOT)]) == 0


def test_validate_command_rejects_a_body_text_field(tmp_path, capsys):
    path = tmp_path / "golden_synthetic_bad.jsonl"
    path.write_text(json.dumps(real_golden_line(body="synthetic")) + "\n", encoding="utf-8")
    assert golden.main(["validate", str(path), "--root", str(ROOT)]) == 1
    assert "body text field not allowed: body" in capsys.readouterr().err


# ------------------------------------------------------------ surface_cve (eval-protocol 5절 1항)


def test_no_answer_about_an_unknown_cve_keeps_surface_cve():
    bad_target = dict(
        VALID_RECORDS["no_answer"],
        query="CVE-2099-0001은 어느 공지에서 다루나요?",
        surface_cve=True,
    )
    assert validate([bad_target]) == []


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"surface_cve": "true"}, "surface_cve must be a bool"),
        ({"surface_cve": 1}, "surface_cve must be a bool"),
        ({"surface_cve": False}, "contradicts the query text"),
    ],
)
def test_surface_cve_must_be_a_bool_matching_the_query(changes, message):
    errors = validate([record(**changes)])  # query에 CVE ID가 있다
    assert any(message in e for e in errors), errors


def test_surface_cve_false_matches_a_query_without_cve():
    ok = record(query_type="product_symptom", query="Alpha 제품의 인증 우회는?", surface_cve=False)
    assert validate([ok]) == []


# ------------------------------------------------------------ evidence.nttId (eval-protocol 8절 2단계)


def evidence_with(**span):
    base = {"parser_version": "synthetic-v1", "start": 10, "end": 40}
    return record(answers=[{**answer(), "evidence": [{**base, **span}]}])


@pytest.mark.parametrize("ntt_id", ["72", 72])
def test_evidence_may_carry_the_protocol_nttid(ntt_id):
    assert validate([evidence_with(nttId=ntt_id)]) == []


def test_evidence_nttid_must_match_the_answer_doc_id():
    errors = validate([evidence_with(nttId="73")])
    assert any("nttId '73' != doc_id '72'" in e for e in errors), errors


# ------------------------------------------------------------ 형식이 틀린 ID는 예외가 아니라 오류 목록으로


@pytest.mark.parametrize("bad_id", [["q1"], {"id": "q1"}, 7, None])
def test_unhashable_or_non_string_question_id_is_reported_not_raised(bad_id):
    errors = validate([record(question_id=bad_id), record(question_id=bad_id)])
    assert any("question_id must be a non-empty string" in e for e in errors), errors


@pytest.mark.parametrize("bad_id", [["72"], {"id": "72"}, 72])
def test_unhashable_or_non_string_doc_id_is_reported_not_raised(bad_id):
    bad = record(answers=[{**answer(), "doc_id": bad_id}, answer()])
    errors = validate([bad])
    assert any("doc_id is required" in e for e in errors), errors


def test_read_review_rows_rejects_a_row_with_extra_fields(tmp_path):
    sheet = tmp_path / "review_synthetic_extra.csv"
    write_sheet(sheet, rows_of(C_OK))
    with sheet.open("a", encoding="utf-8") as handle:
        handle.write(",".join(["x"] * (len(REVIEW_COLUMNS) + 1)) + "\n")
    with pytest.raises(ReviewSheetError, match="row 3: more fields than the header"):
        read_review_rows(sheet)


# ------------------------------------------------------------ 검수 CSV 입력 오류와 Excel 저장본


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig"])
@pytest.mark.parametrize(
    ("true_text", "false_text"), [("true", "false"), ("TRUE", "FALSE"), ("True", "False")]
)
def test_read_review_rows_accepts_excel_bom_and_uppercase_booleans(
    tmp_path, encoding, true_text, false_text
):
    rows = rows_of(C_OK, C_MIS, O_OK, O_OMIT)
    for row in rows:
        row["in_candidate_set"] = true_text if row["in_candidate_set"] == "true" else false_text
    sheet = tmp_path / "review_synthetic_excel.csv"
    with sheet.open("w", encoding=encoding, newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=REVIEW_COLUMNS, lineterminator="\r\n")
        writer.writeheader()
        writer.writerows(rows)
    result = error_rates(read_review_rows(sheet))
    assert result["mislabel"] == {"n_reviewed": 2, "n_error": 1, "rate": 0.5}
    assert result["omission"] == {"n_reviewed": 2, "n_error": 1, "rate": 0.5}


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"stratum": "b_outside_join_same_product"}, "contradicts stratum"),
        ({"stratum": "a_title_cve_not_in_cube"}, "unknown stratum"),
        ({"weak_label": "weak_unlabeled"}, "contradicts weak_label"),
        ({"weak_label": "positive"}, "unknown weak_label"),
        ({"question_id": ""}, "question_id and doc_id are required"),
        ({"doc_id": ""}, "question_id and doc_id are required"),
    ],
)
def test_error_rates_rejects_sheet_rows_that_contradict_the_prefilled_columns(overrides, message):
    # in_candidate_set=true인 후보 행에 후보 밖 stratum/weak_label 등을 섞는다
    row = review_row(True, "relevant", "ok", **overrides)
    with pytest.raises(ReviewSheetError, match=message):
        error_rates([row])


@pytest.mark.parametrize(
    ("in_set", "stratum", "weak_label"),
    [
        (True, "join_candidate", "weak_positive"),
        (False, "a_title_cve_not_in_cve_ids", "weak_unlabeled"),
        (False, "b_outside_join_same_product", "weak_unlabeled"),
        (True, "", ""),
        (False, "", "weak_unlabeled"),
    ],
)
def test_error_rates_accepts_consistent_prefilled_columns(in_set, stratum, weak_label):
    row = review_row(in_set, "", "", stratum=stratum, weak_label=weak_label)
    assert error_rates([row])["n_pending"] == 1


def test_error_rates_rejects_a_duplicated_question_doc_row_even_when_pending():
    first = review_row(True, "", "", question_id="cq-x", doc_id="9")
    second = review_row(True, "relevant", "ok", question_id="cq-x", doc_id="9")
    with pytest.raises(ReviewSheetError, match="duplicate"):
        error_rates([first, second])


def test_error_rates_allows_the_same_question_with_different_documents():
    rows = [
        review_row(True, "", "", question_id="cq-x", doc_id="9"),
        review_row(False, "", "", question_id="cq-x", doc_id="10"),
    ]
    assert error_rates(rows)["n_rows"] == 2


def test_cli_reports_review_sheet_errors_as_one_line_and_exit_1(tmp_path, capsys):
    sheet = tmp_path / "review_synthetic_extra.csv"
    write_sheet(sheet, rows_of(C_OK))
    with sheet.open("a", encoding="utf-8") as handle:
        handle.write(",".join(["x"] * (len(REVIEW_COLUMNS) + 1)) + "\n")
    assert golden.main(["error-rates", str(sheet)]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: row 3: more fields than the header\n"


@pytest.mark.parametrize("target", ["missing.csv", "golden_synthetic_broken.jsonl"])
def test_cli_reports_unreadable_inputs_without_a_traceback(tmp_path, capsys, target):
    path = tmp_path / target
    if target.endswith(".jsonl"):
        path.write_text("{not json}\n", encoding="utf-8")
        argv = ["validate", str(path), "--root", str(ROOT)]
    else:
        argv = ["error-rates", str(path)]
    assert golden.main(argv) == 1
    lines = capsys.readouterr().err.splitlines()
    assert len(lines) == 1 and lines[0].startswith("error: ")

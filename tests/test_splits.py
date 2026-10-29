"""분할 검사 테스트. 공지 데이터는 전부 합성이다(KISA 본문 없음)."""

import json
from pathlib import Path

import pytest

from krsec_rag_lab.splits import (
    SplitLeakError,
    assert_disjoint,
    extract_cve_ids,
    find_overlaps,
    near_dup_groups,
)

TITLE_A = "Alpha 제품 보안 업데이트 권고"


def notice(ntt_id, title, published, cve_ids=()):
    return {"nttId": ntt_id, "title": title, "date": published, "cve_ids": list(cve_ids)}


CATALOG = [
    notice("1", TITLE_A, "2026-01-01", ["CVE-2026-0001"]),
    notice("2", TITLE_A, "2026-01-10", ["CVE-2026-0002"]),  # 1과 9일 간격: 근접중복
    notice("3", TITLE_A, "2026-03-01", ["CVE-2026-0003"]),  # 같은 제목이지만 한참 뒤: 별개
    notice("4", "Beta 제품 보안 업데이트 권고", "2026-01-02", ["CVE-2026-0004", "CVE-2026-0005"]),
    notice("5", "Gamma 제품 보안 업데이트 권고", "2026-01-03", ["CVE-2026-0005"]),  # 4와 CVE 공유
    notice("6", "명절 사이버사기 주의", "2026-01-04"),
    notice(
        "7", "  ALPHA 제품   보안 업데이트 권고 ", "2026-01-12", ["CVE-2026-0007"]
    ),  # 정규화 후 동일
    notice("8", "Eps 제품 보안 업데이트 권고", "2026-02-01", ["CVE-2026-0008"]),
    notice("9", "Eps 제품 보안 업데이트 권고", "2026-02-14", ["CVE-2026-0009"]),  # 8과 13일
    notice(
        "10", "Eps 제품 보안 업데이트 권고", "2026-02-27", ["CVE-2026-0010"]
    ),  # 9와 13일, 8과 26일
]


def item(item_id, split, ntt_ids=(), cve_ids=(), query=None):
    row = {"id": item_id, "split": split, "ntt_ids": list(ntt_ids), "cve_ids": list(cve_ids)}
    if query is not None:
        row["query"] = query
    return row


@pytest.mark.parametrize(
    ("left", "right", "same_group"),
    [
        pytest.param("1", "2", True, id="gap-9-days"),
        pytest.param("1", "7", True, id="gap-11-days-title-normalized"),
        pytest.param("2", "7", True, id="gap-2-days"),
        pytest.param("8", "9", True, id="gap-13-days"),
        pytest.param("8", "10", True, id="transitive-chain-26-days"),
        pytest.param("1", "3", False, id="same-title-gap-too-long"),
        pytest.param("1", "4", False, id="different-title"),
        pytest.param("4", "5", False, id="shared-cve-is-not-near-dup"),
    ],
)
def test_near_dup_groups(left, right, same_group):
    groups = near_dup_groups(CATALOG)
    assert (groups[left] == groups[right]) is same_group


def test_near_dup_window_boundary_is_14_days_inclusive():
    day14 = [notice("1", "T", "2026-01-01"), notice("2", "T", "2026-01-15")]
    day15 = [notice("1", "T", "2026-01-01"), notice("2", "T", "2026-01-16")]
    assert near_dup_groups(day14)["1"] == near_dup_groups(day14)["2"]
    assert near_dup_groups(day15)["1"] != near_dup_groups(day15)["2"]


def test_near_dup_group_id_is_smallest_member():
    groups = near_dup_groups(CATALOG)
    assert groups["7"] == groups["2"] == groups["1"] == "1"
    assert groups["3"] == "3"


PASSING = [
    pytest.param(
        [
            item("q1", "dev", ["1"]),
            item("q2", "dev", ["4"]),
            item("q3", "test", ["6"]),
            item("q4", "test", ["8"]),
        ],
        id="disjoint-notices",
    ),
    pytest.param(
        [item("q1", "dev", ["1"]), item("q2", "test", ["3"])],
        id="same-title-beyond-window",
    ),
    pytest.param(
        [
            item("q1", "dev", cve_ids=["CVE-2026-0099"], query="CVE-2026-0099 패치"),
            item("q2", "test", query="존재하지 않는 제품의 취약점"),
            item("q3", "test", query="다른 제품의 설정 방법"),
        ],
        id="answerless-queries-with-different-text",
    ),
    pytest.param(
        [item("q1", "dev", ["1"]), item("q2", "dev", ["1"])], id="same-notice-in-dev-only"
    ),
    pytest.param([], id="empty"),
]


@pytest.mark.parametrize("items", PASSING)
def test_clean_split_passes(items):
    assert find_overlaps(items, CATALOG) == []
    assert_disjoint(items, CATALOG)


FAILING = [
    pytest.param(
        [item("q1", "dev", ["6"]), item("q2", "test", ["6"])],
        {"notice"},
        id="notice-same-notice",
    ),
    pytest.param(
        [
            item("q1", "dev", cve_ids=["CVE-2026-0099"]),
            item("q2", "test", cve_ids=["cve-2026-0099"]),
        ],
        {"cve"},
        id="cve-same-explicit-cve",
    ),
    pytest.param(
        [item("q1", "dev", ["4"]), item("q2", "test", ["5"])],
        {"cve"},
        id="cve-shared-through-gold-notices",
    ),
    pytest.param(
        [item("q1", "dev", cve_ids=["CVE-2026-0005"]), item("q2", "test", ["4"])],
        {"cve"},
        id="cve-explicit-vs-gold-notice",
    ),
    pytest.param(
        [item("q1", "dev", ["1"]), item("q2", "test", ["2"])],
        {"near_dup"},
        id="near-dup-recurring-advisory",
    ),
    pytest.param(
        [item("q1", "dev", ["8"]), item("q2", "test", ["10"])],
        {"near_dup"},
        id="near-dup-transitive-chain",
    ),
    pytest.param(
        [item("q1", "dev", ["1"]), item("q2", "test", ["7"])],
        {"near_dup"},
        id="near-dup-title-normalized",
    ),
    pytest.param(
        [
            item("q1", "dev", query="  제품 X의   취약점이 있나요? "),
            item("q2", "test", query="제품 x의 취약점이 있나요?"),
        ],
        {"near_dup"},
        id="near-dup-same-query-text",
    ),
    pytest.param(
        [item("q1", "dev", ["4", "6"]), item("q2", "test", ["5"])],
        {"cve"},
        id="partial-overlap-multi-gold",
    ),
    pytest.param(
        [
            item("q1", "dev", query="CVE-2026-0099 패치는?"),
            item("q2", "test", query="CVE-2026-0099를 설명해줘"),
        ],
        {"cve"},
        id="cve-only-in-query-text",
    ),
    pytest.param(
        [
            item("q1", "dev", query="CVE-2026-0099² 패치는?"),
            item("q2", "test", query="CVE-2026-0099 영향은?"),
        ],
        {"cve"},
        id="cve-superscript-after-id-does-not-glue",
    ),
]


@pytest.mark.parametrize(("items", "expected_kinds"), FAILING)
def test_leaky_split_is_detected(items, expected_kinds):
    overlaps = find_overlaps(items, CATALOG)
    assert {overlap.kind for overlap in overlaps} == expected_kinds
    with pytest.raises(SplitLeakError) as excinfo:
        assert_disjoint(items, CATALOG)
    assert excinfo.value.overlaps == overlaps


def test_overlap_reports_both_sides():
    (overlap,) = find_overlaps([item("q1", "dev", ["6"]), item("q2", "test", ["6"])], CATALOG)
    assert (overlap.kind, overlap.key) == ("notice", "6")
    assert overlap.dev_items == ("q1",) and overlap.test_items == ("q2",)


def test_notice_plus_cve_leak_reports_each_kind():
    items = [item("q1", "dev", ["4"]), item("q2", "test", ["4"])]
    assert {overlap.kind for overlap in find_overlaps(items, CATALOG)} == {"notice", "cve"}


@pytest.mark.parametrize(
    ("items", "catalog", "message"),
    [
        pytest.param([item("q1", "train", ["1"])], CATALOG, "split must be", id="bad-split"),
        pytest.param(
            [item("q1", "dev", ["1"]), item("q1", "test", ["3"])],
            CATALOG,
            "duplicate item id",
            id="duplicate-item-id",
        ),
        pytest.param(
            [item("q1", "dev", ["999"])], CATALOG, "not in notice catalog", id="unknown-ntt"
        ),
        pytest.param(
            [item("q1", "dev", cve_ids=["CVE-26-1"])], CATALOG, "malformed CVE", id="bad-cve"
        ),
        pytest.param(
            [item("q1", "dev", cve_ids=["CVE-２０２６-０００５"])],
            CATALOG,
            "malformed CVE",
            id="fullwidth-digit-cve",
        ),
        pytest.param(
            [{"id": "q1", "split": "dev", "ntt_ids": None}],
            CATALOG,
            "ntt_ids must be a list",
            id="null-ntt-ids",
        ),
        pytest.param(
            [{"id": "q1", "split": "dev", "cve_ids": None}],
            CATALOG,
            "cve_ids must be a list",
            id="null-cve-ids",
        ),
        pytest.param(
            [{"id": "q1", "split": "dev", "ntt_ids": "72193"}],
            CATALOG,
            "ntt_ids must be a list",
            id="bare-string-ntt-ids",
        ),
        pytest.param(
            [{"id": "q1", "split": "dev", "query": None}],
            CATALOG,
            "query must be a string",
            id="null-query",
        ),
        pytest.param(
            [item("q1", "dev", ["1"])],
            [notice("1", "T", "2026-01-01"), notice("1", "T", "2026-01-02")],
            "duplicate nttId",
            id="duplicate-catalog-ntt",
        ),
    ],
)
def test_malformed_input_fails_closed(items, catalog, message):
    with pytest.raises(ValueError, match=message):
        find_overlaps(items, catalog)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param("CVE-2026-12345를 설명해줘", ["CVE-2026-12345"], id="korean-particle-after"),
        pytest.param("취약점CVE-2026-1234", ["CVE-2026-1234"], id="korean-before"),
        pytest.param("cve-2026-1234와 CVE-2026-1234", ["CVE-2026-1234"], id="dedup-and-uppercase"),
        pytest.param(
            "(CVE-2026-0001, CVE-2025-99999)", ["CVE-2026-0001", "CVE-2025-99999"], id="list"
        ),
        pytest.param("CVE-2026-123 은 자리수 부족", [], id="three-digit-sequence"),
        pytest.param("CVE-２０２６-１２３４를", [], id="fullwidth-digits-not-recognized"),
        pytest.param("CVE-2026-1234²", ["CVE-2026-1234"], id="superscript-does-not-glue"),
        pytest.param("CVE-٢٠٢٦-١٢٣٤", [], id="non-ascii-unicode-digits-not-recognized"),
        pytest.param("XCVE-2026-1234", [], id="ascii-prefix-glued"),
        pytest.param("제품 보안 업데이트", [], id="none"),
    ],
)
def test_extract_cve_ids(text, expected):
    assert extract_cve_ids(text) == expected


def test_public_metadata_fixture_is_a_valid_catalog():
    path = Path(__file__).resolve().parents[1] / "fixtures" / "kisa" / "metadata.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    groups = near_dup_groups(rows)
    assert set(groups) == {str(row["nttId"]) for row in rows}
    assert find_overlaps([item("q", "dev", [rows[0]["nttId"]])], rows) == []

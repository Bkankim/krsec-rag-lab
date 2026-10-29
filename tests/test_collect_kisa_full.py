"""전체 수집기 테스트: 합성 HTML과 가짜 Client만 쓴다(네트워크·KISA 캐시 없음)."""

import json
from collections import Counter
from urllib.parse import parse_qs, urlsplit

import pytest

from krsec_rag_lab.corpus import collect

kisa = collect.kisa
SENTINEL = "Synthetic sentinel body text"


def list_html(entries, total=None, structure=True):
    rows = "".join(
        '<tr><td class="sbj"><a href="/kr/bbs/view.do?bbsId=B0000133&amp;menuNo=205020'
        f'&amp;nttId={ntt_id}">{title}</a></td><td class="date">{date}</td></tr>'
        for ntt_id, title, date in entries
    )
    count = f'<p class="total">총 게시물 {total}건</p>' if total is not None else ""
    paging = '<div class="paging"><a>1</a></div>' if structure else ""
    return f"<html><body>{count}<table><tbody>{rows}</tbody></table>{paging}</body></html>".encode()


def detail_html(ntt_id, body=None, title=None, date="2026-01-02"):
    body = body if body is not None else f"{SENTINEL} {ntt_id} CVE-2099-{int(ntt_id):05d}."
    return (
        f'<html><body><div class="b_title"><h2>{title or f"Invented notice {ntt_id}"}</h2>'
        f'<span>{date}</span></div><div class="content_html"><p>{body}</p></div></body></html>'
    ).encode()


def rss_xml(ids):
    items = "".join(
        f"<item><title>Invented {i}</title>"
        f"<link>https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000133&amp;nttId={i}</link>"
        f"<pubDate>Fri, 02 Jan 2026 12:00:00 +0900</pubDate></item>"
        for i in ids
    )
    return f'<?xml version="1.0"?><rss version="2.0"><channel>{items}</channel></rss>'.encode()


class FakeClient:
    """URL 종류별 응답표. 값은 bytes, 예외 인스턴스, 또는 순서대로 소비되는 리스트다."""

    def __init__(self, ids, per_page=2, details=None, pages=None, rss="all", total=None):
        self.robots = object()
        self.calls = []
        self.details = {i: detail_html(i) for i in ids} | (details or {})
        ordered = sorted(ids, key=int, reverse=True)
        self.pages = {
            n + 1: list_html(
                [
                    (i, f"Invented notice {i}", "2026-01-02")
                    for i in ordered[n * per_page :][:per_page]
                ],
                total=total,
            )
            for n in range(-(-len(ordered) // per_page))
        } | (pages or {})
        self.rss = rss_xml(ids) if rss == "all" else rss

    def get(self, url):
        self.calls.append(url)
        parts = urlsplit(url)
        query = parse_qs(parts.query)
        if parts.path.endswith("rss.do"):
            value = self.rss
        elif parts.path.endswith("list.do"):
            value = self.pages.get(int(query["pageIndex"][0]), list_html([]))
        else:
            value = self.details[query["nttId"][0]]
        if isinstance(value, list):
            value = value.pop(0) if len(value) > 1 else value[0]
        if isinstance(value, Exception):
            raise value
        return value

    def kinds(self):
        names = {"rss.do": "rss", "list.do": "list", "view.do": "detail"}
        return Counter(names[urlsplit(u).path.rsplit("/", 1)[-1]] for u in self.calls)

    def detail_ids(self):
        return [parse_qs(urlsplit(u).query)["nttId"][0] for u in self.calls if "view.do" in u]


IDS = ["9001", "9002", "9003", "9004", "9005"]


def go(tmp_path, client, retry_failed=False):
    return collect.collect(
        tmp_path / "root",
        tmp_path / "fx",
        tmp_path / "res",
        tmp_path / "fixed.json",
        client,
        retry_failed,
        log=lambda message: None,
    )


def manifest_of(tmp_path):
    return json.loads((tmp_path / "fx" / "manifest.json").read_text(encoding="utf-8"))


def report_of(tmp_path):
    return json.loads((tmp_path / "res" / "report.json").read_text(encoding="utf-8"))


def metadata_of(tmp_path):
    path = tmp_path / "fx" / "metadata.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def stable(manifest):
    """수집 시각을 뺀 manifest."""
    manifest = {k: v for k, v in manifest.items() if k not in {"started_at", "finished_at"}}
    manifest["documents"] = [
        {k: v for k, v in doc.items() if k != "collected_at"} for doc in manifest["documents"]
    ]
    return manifest


def write_fixed(tmp_path, entries):
    (tmp_path / "fixed.json").write_text(
        json.dumps(
            {
                "target_ids": [i for i, _ in entries],
                "documents": [{"nttId": i, "sha256": h} for i, h in entries],
            }
        ),
        encoding="utf-8",
    )


# --- 발견: 페이지 끝 판정 -------------------------------------------------------------------


def test_discovery_stops_at_empty_page_and_freezes_ids(tmp_path):
    client = FakeClient(IDS, per_page=2)

    assert go(tmp_path, client) == 0

    manifest = manifest_of(tmp_path)
    assert manifest["discovery_complete"] is True and manifest["complete"] is True
    assert manifest["target_ids"] == IDS
    assert manifest["parser_version"] == kisa.PARSER_VERSION
    # 1~3쪽에 5건, 4쪽이 빈 목록(끝 신호, 실패로 세지 않는다)
    assert client.kinds()["list"] == 4
    assert report_of(tmp_path)["list_pages"] == 4
    assert report_of(tmp_path)["list_pages_with_rows"] == 3


def test_discovery_stops_after_two_consecutive_pages_without_new_ids(tmp_path):
    same = list_html([("9002", "Invented notice 9002", "2026-01-02")])
    client = FakeClient(
        ["9001", "9002"],
        per_page=1,
        pages={3: same, 4: same, 5: list_html([("9999", "x", "2026-01-02")])},
    )

    assert go(tmp_path, client) == 0

    # 3쪽(새 ID 0건)과 4쪽(새 ID 0건)에서 끝나므로 5쪽은 요청하지 않는다
    assert client.kinds()["list"] == 4
    assert manifest_of(tmp_path)["target_ids"] == ["9001", "9002"]


def test_one_page_without_new_ids_does_not_end_discovery(tmp_path):
    same = list_html([("9002", "Invented notice 9002", "2026-01-02")])
    new = list_html([("9001", "Invented notice 9001", "2026-01-02")])
    client = FakeClient(["9001", "9002"], per_page=1, pages={1: same, 2: same, 3: new})
    client.details["9002"] = detail_html("9002")

    assert go(tmp_path, client) == 0

    # 2쪽만 새 ID가 없었으므로 3쪽까지 간다
    assert manifest_of(tmp_path)["target_ids"] == ["9001", "9002"]


@pytest.mark.parametrize(
    "page",
    [
        b"<html><body><p>Service unavailable</p></body></html>",
        b"<html><body><table><tbody></tbody></table></body></html>",
        b'<html><body><div class="paging"><a>1</a></div></body></html>',
        list_html([], structure=False),
        b"\xff\xfe\x00broken",
        b'<html><body><table><tr><td class="sbj">no link</td></tr></table></body></html>',
    ],
    ids=["no-structure", "table-only", "paging-only", "empty-no-paging", "bad-encoding", "bad-row"],
)
def test_unstructured_or_broken_list_page_leaves_discovery_incomplete(tmp_path, page):
    client = FakeClient(["9001", "9002"], per_page=1, pages={2: page})

    assert go(tmp_path, client) == 1

    manifest = manifest_of(tmp_path)
    assert manifest["discovery_complete"] is False and manifest["complete"] is False
    assert manifest["target_ids"] == []
    assert client.kinds()["detail"] == 0
    assert report_of(tmp_path)["discovery_error"]


# --- 계측: 목록 중복(원시 행)과 내용 중복 -----------------------------------------------------


def test_in_page_duplicate_rows_are_counted_with_conflicting_titles(tmp_path):
    page = list_html(
        [
            ("9001", "First title", "2026-01-02"),
            ("9001", "Different title", "2026-01-02"),
            ("9002", "Other", "2026-01-03"),
        ]
    )
    # parse_list는 같은 nttId를 접어 2건만 돌려준다 - 원시 행 3건과의 차이가 페이지 안 중복이다
    assert len(kisa.parse_list(page)) == 2
    assert len(collect.raw_list_rows(page)) == 3
    client = FakeClient(["9001", "9002"], pages={1: page})

    assert go(tmp_path, client) == 0

    report = report_of(tmp_path)
    assert report["list_rows"] == 3
    assert report["list_duplicate_in_page"] == 1
    assert report["list_duplicate_across_pages"] == 0
    assert report["list_duplicate_ids"] == ["9001"]
    assert report["list_conflict_ids"] == ["9001"]
    assert report["discovered_ids"] == 2


def test_pinned_notice_repeated_across_pages_is_counted(tmp_path):
    pinned = ("9100", "Pinned notice", "2026-01-01")
    pages = {
        1: list_html([pinned, ("9003", "Invented notice 9003", "2026-01-02")]),
        2: list_html([pinned, ("9002", "Invented notice 9002", "2026-01-02")]),
        3: list_html([pinned, ("9001", "Invented notice 9001", "2026-01-02")]),
    }
    client = FakeClient(["9100", "9003", "9002", "9001"], pages=pages)

    assert go(tmp_path, client) == 0

    report = report_of(tmp_path)
    assert report["list_duplicate_across_pages"] == 2
    assert report["list_duplicate_in_page"] == 0
    assert report["list_duplicate_ids"] == ["9100"]
    assert report["list_conflict_ids"] == []


def test_content_duplicate_groups_by_body_hash(tmp_path):
    same = f"{SENTINEL} shared"
    client = FakeClient(
        IDS, details={"9001": detail_html("9001", same), "9003": detail_html("9003", same)}
    )

    assert go(tmp_path, client) == 0

    report = report_of(tmp_path)
    assert report["content_duplicate_group_count"] == 1
    assert report["content_duplicate_doc_count"] == 2
    group = report["content_duplicate_groups"][0]
    assert group["ids"] == ["9001", "9003"]
    assert group["sha256"] == kisa.content_hash(same)


def test_missing_ids_and_displayed_total_gap(tmp_path):
    client = FakeClient(
        IDS,
        total=7,
        details={
            "9002": kisa.FetchError("http_404"),
            "9004": b"<html><body>layout changed</body></html>",
        },
    )

    assert go(tmp_path, client) == 0

    report = report_of(tmp_path)
    assert report["displayed_total"] == 7
    assert report["discovered_ids"] == 5
    assert report["displayed_total_gap"] == 2
    assert report["missing_ids"] == ["9002", "9004"]
    assert report["detail_ok"] == 3
    assert report["detail_failed"] == {"fetch_failed:http_404": 1}
    assert report["parse_failed"] == {"parse_failed:article_structure_changed": 1}
    assert report["failed_ids"]["parse_failed:article_structure_changed"] == ["9004"]


def test_displayed_total_is_null_when_page_does_not_show_it(tmp_path):
    assert go(tmp_path, FakeClient(IDS)) == 0
    report = report_of(tmp_path)
    assert report["displayed_total"] is None and report["displayed_total_gap"] is None


def test_rss_only_ids_are_counted_but_not_collected(tmp_path):
    client = FakeClient(IDS, rss=rss_xml(["9005", "9006", "9007"]))

    assert go(tmp_path, client) == 0

    report = report_of(tmp_path)
    assert report["rss_ids"] == 3
    assert report["rss_only_ids"] == ["9006", "9007"]
    assert "9006" not in client.detail_ids()


def test_rss_failure_is_recorded_without_stopping_collection(tmp_path):
    client = FakeClient(IDS, rss=kisa.FetchError("network_error"))

    assert go(tmp_path, client) == 0

    report = report_of(tmp_path)
    assert report["rss_ids"] is None and report["rss_error"] == "network_error"
    assert report["detail_ok"] == 5


@pytest.mark.parametrize(
    ("fixed", "present", "matched", "missing", "mismatched"),
    [
        (["9001", "9002"], 2, 2, [], []),
        (["9001", "9002", "9777"], 2, 2, ["9777"], []),
        (["9001", "9002"], 2, 1, [], ["9002"]),
    ],
    ids=["all-match", "missing-id", "hash-mismatch"],
)
def test_fixed_set_presence_and_hash_match(tmp_path, fixed, present, matched, missing, mismatched):
    entries = [(i, kisa.content_hash(f"{SENTINEL} {i} CVE-2099-{int(i):05d}.")) for i in fixed]
    if mismatched:
        entries[1] = (entries[1][0], "0" * 64)
    write_fixed(tmp_path, entries)

    assert go(tmp_path, FakeClient(IDS)) == 0

    report = report_of(tmp_path)
    assert report["fixed_expected"] == len(fixed)
    assert report["fixed_present"] == present
    assert report["fixed_hash_match"] == matched
    assert report["fixed_missing_ids"] == missing
    assert report["fixed_hash_mismatch_ids"] == mismatched


# --- 중단과 재개 -----------------------------------------------------------------------------


@pytest.mark.parametrize("code", ["http_403", "http_429", "robots_disallow", "http_401"])
def test_access_denied_in_detail_stops_immediately_then_resume_finishes(tmp_path, code):
    client = FakeClient(IDS, details={"9003": kisa.AccessDenied(code)})

    assert go(tmp_path, client) == 1

    assert client.detail_ids() == ["9001", "9002", "9003"]  # 차단 뒤 요청 없음
    manifest = manifest_of(tmp_path)
    assert [d["nttId"] for d in manifest["documents"]] == ["9001", "9002"]
    assert manifest["complete"] is False and manifest["discovery_complete"] is True
    assert report_of(tmp_path)["aborted"] == code
    assert [row["nttId"] for row in metadata_of(tmp_path)] == ["9001", "9002"]

    resumed = FakeClient(IDS)
    assert go(tmp_path, resumed) == 0
    assert resumed.detail_ids() == ["9003", "9004", "9005"]
    assert manifest_of(tmp_path)["complete"] is True
    assert report_of(tmp_path)["resumed"] is True


@pytest.mark.parametrize("code", ["http_403", "http_429", "robots_disallow"])
def test_access_denied_on_last_id_still_exits_1(tmp_path, code):
    client = FakeClient(IDS, details={"9005": kisa.AccessDenied(code)})

    assert go(tmp_path, client) == 1

    assert manifest_of(tmp_path)["complete"] is False
    assert report_of(tmp_path)["aborted"] == code


@pytest.mark.parametrize("code", ["http_403", "http_429", "robots_disallow"])
def test_access_denied_in_list_stops_before_any_detail(tmp_path, code):
    client = FakeClient(IDS, pages={2: kisa.AccessDenied(code)})

    assert go(tmp_path, client) == 1

    assert client.kinds()["detail"] == 0
    manifest = manifest_of(tmp_path)
    assert manifest["discovery_complete"] is False and manifest["target_ids"] == []
    assert report_of(tmp_path)["aborted"] == code


@pytest.mark.parametrize("code", ["http_403", "robots_disallow"])
def test_access_denied_on_rss_stops_before_freezing(tmp_path, code):
    client = FakeClient(IDS, rss=kisa.AccessDenied(code))

    assert go(tmp_path, client) == 1

    assert client.kinds()["detail"] == 0
    assert manifest_of(tmp_path)["discovery_complete"] is False


@pytest.mark.parametrize(
    "errors",
    [
        ["network_error"] * 3,
        ["http_500", "http_502", "http_503"],
        ["network_error", "http_500", "http_404"],
        ["http_404", "http_410", "http_404"],
    ],
    ids=["network", "5xx", "mixed", "permanent-4xx"],
)
def test_three_consecutive_fetch_failures_stop_and_save(tmp_path, errors):
    details = {i: kisa.FetchError(e) for i, e in zip(["9002", "9003", "9004"], errors, strict=True)}
    client = FakeClient(IDS, details=details)

    assert go(tmp_path, client) == 1

    assert client.detail_ids() == ["9001", "9002", "9003", "9004"]  # 9005는 요청하지 않는다
    assert report_of(tmp_path)["aborted"] == "three_consecutive_failures"
    assert manifest_of(tmp_path)["complete"] is False
    assert [row["nttId"] for row in metadata_of(tmp_path)] == ["9001"]


def test_three_failures_on_the_last_ids_exit_1_even_when_all_ids_are_terminal(tmp_path):
    details = {i: kisa.FetchError("http_404") for i in ["9003", "9004", "9005"]}

    assert go(tmp_path, FakeClient(IDS, details=details)) == 1

    assert manifest_of(tmp_path)["complete"] is True
    assert report_of(tmp_path)["aborted"] == "three_consecutive_failures"


def test_success_resets_the_consecutive_failure_count(tmp_path):
    details = {
        "9001": kisa.FetchError("network_error"),
        "9002": kisa.FetchError("network_error"),
        "9004": kisa.FetchError("http_500"),
        "9005": kisa.FetchError("http_500"),
    }
    client = FakeClient(IDS, details=details)

    assert go(tmp_path, client) == 1  # 4건이 미처리로 남아 complete가 아니다

    assert report_of(tmp_path)["aborted"] is None
    assert client.detail_ids() == IDS
    assert report_of(tmp_path)["detail_pending"] == 4


def test_transient_failures_stay_pending_and_are_retried_on_resume(tmp_path):
    client = FakeClient(IDS, details={"9002": kisa.FetchError("http_503")})

    assert go(tmp_path, client) == 1

    manifest = manifest_of(tmp_path)
    assert manifest["complete"] is False
    assert "9002" not in {d["nttId"] for d in manifest["documents"]}
    assert report_of(tmp_path)["detail_pending"] == 1

    resumed = FakeClient(IDS)
    assert go(tmp_path, resumed) == 0
    assert resumed.detail_ids() == ["9002"]


def test_permanent_http_failure_is_terminal_and_not_retried(tmp_path):
    assert go(tmp_path, FakeClient(IDS, details={"9002": kisa.FetchError("http_404")})) == 0
    manifest = manifest_of(tmp_path)
    assert manifest["complete"] is True
    entry = next(d for d in manifest["documents"] if d["nttId"] == "9002")
    assert entry["result"] == "fetch_failed:http_404" and entry["sha256"] is None

    resumed = FakeClient(IDS)
    assert go(tmp_path, resumed) == 0
    assert resumed.detail_ids() == []
    assert go(tmp_path, FakeClient(IDS), retry_failed=True) == 0
    assert (
        next(d for d in manifest_of(tmp_path)["documents"] if d["nttId"] == "9002")["result"]
        == "ok"
    )


def test_parse_failures_are_terminal_do_not_abort_and_exit_0(tmp_path):
    broken = b"<html><body>layout changed</body></html>"
    details = {i: broken for i in ["9001", "9002", "9003", "9004"]}
    client = FakeClient(IDS, details=details)

    assert go(tmp_path, client) == 0  # 파싱 실패 4건이 연속이어도 중단하지 않는다

    assert client.detail_ids() == IDS
    manifest = manifest_of(tmp_path)
    assert manifest["complete"] is True
    assert [d["result"] for d in manifest["documents"]].count(
        "parse_failed:article_structure_changed"
    ) == 4
    assert [row["nttId"] for row in metadata_of(tmp_path)] == ["9005"]

    resumed = FakeClient(IDS, details=details)
    assert go(tmp_path, resumed) == 0
    assert resumed.detail_ids() == []

    retried = FakeClient(IDS)
    assert go(tmp_path, retried, retry_failed=True) == 0
    assert retried.detail_ids() == ["9001", "9002", "9003", "9004"]
    assert len(metadata_of(tmp_path)) == 5


def test_periodic_save_keeps_progress_when_run_is_interrupted(tmp_path, monkeypatch):
    monkeypatch.setattr(collect, "SAVE_EVERY", 2)
    ids = [str(9000 + n) for n in range(1, 8)]
    client = FakeClient(ids, details={"9006": RuntimeError("interrupted")})

    with pytest.raises(RuntimeError):
        go(tmp_path, client)

    assert [d["nttId"] for d in manifest_of(tmp_path)["documents"]] == ids[:5]
    resumed = FakeClient(ids)
    assert go(tmp_path, resumed) == 0
    assert resumed.detail_ids() == ids[5:]


# --- 캐시 재사용과 멱등성 ---------------------------------------------------------------------


def test_rerun_makes_no_detail_requests_and_keeps_outputs_identical(tmp_path):
    first = FakeClient(IDS)
    assert go(tmp_path, first) == 0
    before = (stable(manifest_of(tmp_path)), metadata_of(tmp_path))

    second = FakeClient(IDS)
    assert go(tmp_path, second) == 0

    assert second.kinds()["detail"] == 0
    assert second.kinds()["list"] == 1  # 목록 재확인은 첫 페이지에서 끝난다
    assert (stable(manifest_of(tmp_path)), metadata_of(tmp_path)) == before
    assert report_of(tmp_path)["requests"]["detail"] == 0


@pytest.mark.parametrize(
    "damage", ["body_changed", "body_missing", "source_missing", "html_changed"]
)
def test_cache_that_does_not_match_the_hash_is_fetched_again(tmp_path, damage):
    assert go(tmp_path, FakeClient(IDS)) == 0
    before = (stable(manifest_of(tmp_path)), metadata_of(tmp_path))
    folder = tmp_path / "root" / "data" / "kisa_full" / "9003"
    if damage == "body_changed":
        (folder / "body.txt").write_text("tampered", encoding="utf-8")
    elif damage == "body_missing":
        (folder / "body.txt").unlink()
    elif damage == "source_missing":
        (folder / "source.html").unlink()
    else:
        (folder / "source.html").write_bytes(detail_html("9003", "another body"))

    resumed = FakeClient(IDS)
    assert go(tmp_path, resumed) == 0

    assert resumed.detail_ids() == ["9003"]
    assert (stable(manifest_of(tmp_path)), metadata_of(tmp_path)) == before
    assert (folder / "body.txt").read_text(encoding="utf-8").endswith("CVE-2099-09003.")


def test_new_id_after_freeze_is_reported_but_not_collected(tmp_path):
    assert go(tmp_path, FakeClient(IDS)) == 0
    before = (stable(manifest_of(tmp_path)), metadata_of(tmp_path))

    later = FakeClient([*IDS, "9006"])
    assert go(tmp_path, later) == 0

    assert later.detail_ids() == []
    report = report_of(tmp_path)
    assert report["new_since_freeze"] == ["9006"]
    assert report["rediscovery_pages"] >= 1
    assert (stable(manifest_of(tmp_path)), metadata_of(tmp_path)) == before
    assert "new_since_freeze" not in manifest_of(tmp_path)


def test_rerun_with_unfinished_discovery_starts_over(tmp_path):
    first = FakeClient(IDS, pages={2: b"<html><body>maintenance</body></html>"})
    assert go(tmp_path, first) == 1

    assert go(tmp_path, FakeClient(IDS)) == 0
    assert manifest_of(tmp_path)["target_ids"] == IDS


# --- 출력 ------------------------------------------------------------------------------------


def all_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from all_strings(key)
            yield from all_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from all_strings(item)


def test_outputs_have_only_allowed_fields_and_no_body_or_paths(tmp_path):
    client = FakeClient(IDS, details={"9002": b"<html><body>layout changed</body></html>"})
    write_fixed(tmp_path, [("9001", "0" * 64)])
    assert go(tmp_path, client) == 0

    rows = metadata_of(tmp_path)
    assert rows and all(tuple(row) == collect.METADATA_KEYS for row in rows)
    assert [row["nttId"] for row in rows] == sorted((row["nttId"] for row in rows), key=int)
    assert rows[0]["cve_ids"] == ["CVE-2099-09001"]
    manifest, report = manifest_of(tmp_path), report_of(tmp_path)
    assert all(
        set(doc) == {"nttId", "collected_at", "sha256", "result"} for doc in manifest["documents"]
    )
    for name in ("manifest.json", "metadata.jsonl"):
        assert SENTINEL not in (tmp_path / "fx" / name).read_text(encoding="utf-8")
    assert SENTINEL not in (tmp_path / "res" / "report.json").read_text(encoding="utf-8")
    for value in (*all_strings(manifest), *all_strings(report)):
        assert not value.startswith("/") and len(value) <= 500
        assert str(tmp_path) not in value


def test_report_matches_metadata_and_manifest(tmp_path):
    same = f"{SENTINEL} shared"
    details = {"9001": detail_html("9001", same), "9002": detail_html("9002", same)}
    details["9004"] = kisa.FetchError("http_404")
    assert go(tmp_path, FakeClient(IDS, details=details)) == 0

    manifest, report, rows = manifest_of(tmp_path), report_of(tmp_path), metadata_of(tmp_path)
    ok = [d for d in manifest["documents"] if d["result"] == "ok"]
    assert report["detail_ok"] == len(ok) == len(rows) == 4
    assert report["discovered_ids"] == len(manifest["target_ids"]) == 5
    assert {row["nttId"] for row in rows} == {d["nttId"] for d in ok}
    groups = Counter(d["sha256"] for d in ok)
    assert report["content_duplicate_group_count"] == sum(c > 1 for c in groups.values()) == 1
    assert report["missing_ids"] == sorted(set(manifest["target_ids"]) - {d["nttId"] for d in ok})
    assert report["complete"] is manifest["complete"] is True
    assert report["requests"]["total"] == sum(
        report["requests"][k] for k in ("rss", "list", "detail", "robots")
    )
    assert report["requests"]["detail"] == 5 and report["elapsed_seconds"] >= 0


@pytest.mark.parametrize(
    ("code", "permanent"),
    [
        ("http_404", True),
        ("http_410", True),
        ("http_400", True),
        ("http_403", False),
        ("http_429", False),
        ("http_500", False),
        ("http_503", False),
        ("network_error", False),
    ],
)
def test_permanent_http_classification(code, permanent):
    assert collect.permanent_http(code) is permanent


def test_cli_requires_cache_root_and_valid_delay(capsys):
    with pytest.raises(SystemExit):
        collect.main([])
    with pytest.raises(SystemExit):
        collect.main(["--cache-root", "x", "--delay", "5"])
    capsys.readouterr()


def test_invalid_existing_manifest_is_rejected_without_requests(tmp_path):
    (tmp_path / "fx").mkdir()
    (tmp_path / "fx" / "manifest.json").write_text('{"schema_version": 9}', encoding="utf-8")
    client = FakeClient(IDS)

    with pytest.raises(kisa.KisaError, match="invalid_manifest"):
        go(tmp_path, client)

    assert client.calls == []


# --- 커밋된 실제 산출물 대조(본문 없이 manifest·metadata·report끼리만) -----------------------------

COMMITTED = collect.ROOT / "fixtures" / "kisa_full"
COMMITTED_REPORT = collect.ROOT / "results" / "m4" / "collection" / "report.json"


def committed():
    manifest = json.loads((COMMITTED / "manifest.json").read_text(encoding="utf-8"))
    lines = (COMMITTED / "metadata.jsonl").read_text(encoding="utf-8").splitlines()
    report = json.loads(COMMITTED_REPORT.read_text(encoding="utf-8"))
    return manifest, [json.loads(line) for line in lines], report


def test_committed_report_matches_committed_metadata_and_manifest():
    manifest, rows, report = committed()
    ok = {d["nttId"]: d for d in manifest["documents"] if d["result"] == "ok"}
    assert manifest["complete"] is manifest["discovery_complete"] is True
    assert report["detail_ok"] == len(ok) == len(rows)
    assert report["discovered_ids"] == len(manifest["target_ids"])
    assert [row["nttId"] for row in rows] == sorted(ok, key=int)
    assert all(tuple(row) == collect.METADATA_KEYS for row in rows)
    assert {d["nttId"] for d in manifest["documents"]} == set(manifest["target_ids"])
    assert report["missing_ids"] == sorted(set(manifest["target_ids"]) - set(ok), key=int)
    groups = Counter(d["sha256"] for d in ok.values())
    duplicated = [h for h, count in groups.items() if count > 1]
    assert report["content_duplicate_group_count"] == len(duplicated)
    assert report["content_duplicate_doc_count"] == sum(groups[h] for h in duplicated)
    failed = Counter(d["result"] for d in manifest["documents"] if d["result"] != "ok")
    reported = report["detail_failed"] | report["parse_failed"]
    assert reported == dict(failed)
    assert report["detail_pending"] == 0
    assert manifest["parser_version"] == report["parser_version"] == kisa.PARSER_VERSION


def test_committed_report_fixed_set_matches_the_fixed_manifest():
    manifest, _, report = committed()
    fixed = json.loads((collect.ROOT / "fixtures/kisa/manifest.json").read_text(encoding="utf-8"))
    expected = {d["nttId"]: d["sha256"] for d in fixed["documents"]}
    ok = {d["nttId"]: d["sha256"] for d in manifest["documents"] if d["result"] == "ok"}
    present = [i for i in expected if i in ok]
    assert report["fixed_expected"] == len(fixed["target_ids"])
    assert report["fixed_present"] == len(present)
    assert report["fixed_hash_match"] == sum(ok[i] == expected[i] for i in present)
    assert report["fixed_missing_ids"] == sorted(set(expected) - set(present), key=int)


def test_committed_outputs_have_no_paths_and_bounded_strings():
    manifest, rows, report = committed()
    for value in (*all_strings(manifest), *all_strings(report)):
        assert not value.startswith("/") and len(value) <= 500
        assert "/Users" not in value
    assert not any("body" in row for row in rows)

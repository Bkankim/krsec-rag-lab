"""Offline tests use invented notices only; never read the local KISA cache."""

import importlib.util
import json
import sys
from argparse import Namespace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fetch_kisa.py"
SPEC = importlib.util.spec_from_file_location("fetch_kisa", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
kisa = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = kisa
SPEC.loader.exec_module(kisa)


def detail_html(body: str = "Synthetic body CVE-2099-12345.") -> bytes:
    return (
        '<html><body><div class="b_title"><h2>Invented test notice</h2>'
        "<span>2026-01-02</span></div>"
        '<div class="content_html">'
        f"<p>{body}</p>"
        "</div></body></html>"
    ).encode()


def test_rss_extracts_only_allowed_metadata():
    rss = b"""<?xml version="1.0" encoding="utf-8"?>
    <rss version="2.0"><channel><title>Invented feed</title><item>
      <title>Invented test notice</title>
      <link>https://www.boho.or.kr/kr/bbs/view.do?bbsId=B0000133&amp;nttId=900001</link>
      <pubDate>Fri, 02 Jan 2026 12:00:00 +0900</pubDate>
      <description>Private synthetic description must not enter metadata.</description>
    </item></channel></rss>"""

    rows = kisa.parse_rss(rss)

    assert len(rows) == 1
    assert set(rows[0]) == {"url", "title", "date", "nttId"}
    assert str(rows[0]["nttId"]) == "900001"
    assert rows[0]["title"] == "Invented test notice"
    assert rows[0]["date"] == "2026-01-02"
    assert "description" not in str(rows)


def test_detail_isolates_article_from_navigation_and_executable_text():
    page = (
        detail_html("Alpha<br>Beta &amp; Gamma")
        .replace(b"<body>", b"<body><nav>Navigation must stay outside article.</nav>")
        .replace(
            b"</div></body>",
            b"<script>Executable text must stay outside article.</script>"
            b"<style>Style text must stay outside article.</style></div></body>",
        )
    )

    title, date, body = kisa.parse_detail(page)

    assert title == "Invented test notice"
    assert date == "2026-01-02"
    assert "Alpha" in body
    assert "Beta & Gamma" in body
    assert "AlphaBeta" not in body
    assert "Navigation" not in body
    assert "Executable" not in body
    assert "Style" not in body


def test_content_hash_is_sha256_and_detects_body_change():
    assert kisa.content_hash("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert kisa.content_hash("Invented body A") != kisa.content_hash("Invented body B")


def test_detail_preserves_cve_boundary_before_block_tail():
    raw = detail_html("<p>CVE-2099-12345</p>Invented follow-up text")

    _, _, body = kisa.parse_detail(raw)

    assert kisa.CVE.findall(body) == ["CVE-2099-12345"]


IDS = [str(value) for value in range(900001, 900051)]
SYNTHETIC_BODY = (
    "Invented fixture body: CVE-2099-12345, cve-2099-12345 and CVE-2099-678901. "
    "Invalid tokens CVE-2099-123 and XCVE-2099-4321 must not be extracted."
)


def rss_html(ids):
    items = "".join(
        "<item><title>Invented test notice</title>"
        f"<link>{kisa.canonical_url(ntt_id).replace('&', '&amp;')}</link>"
        "<pubDate>Fri, 02 Jan 2026 12:00:00 +0900</pubDate>"
        "<description>Invented private feed description</description></item>"
        for ntt_id in ids
    )
    return f"<rss><channel>{items}</channel></rss>".encode()


def list_html(ids):
    rows = "".join(
        '<tr><td class="sbj">'
        f'<a href="{kisa.canonical_url(ntt_id).replace("&", "&amp;")}">'
        'Invented test notice</a></td><td class="date">2026-01-02</td></tr>'
        for ntt_id in ids
    )
    return (
        "<table><tr><th>Invented heading</th></tr>" + rows + "</table>"
        '<nav><a href="?pageIndex=3">Next</a></nav>'
    ).encode()


class FakeClient:
    """Every response is generated here, without touching a real cache or network."""

    def __init__(self, overrides=None):
        self.calls = []
        self.overrides = overrides or {}

    def get(self, url):
        self.calls.append(url)
        if url in self.overrides:
            response = self.overrides[url]
            if isinstance(response, Exception):
                raise response
            return response
        if url == kisa.RSS_URL:
            return rss_html(IDS[:5] + IDS[:1])
        if "list.do" in url:
            page = parse_qs(urlsplit(url).query)["pageIndex"][0]
            if page == "1":
                return list_html(IDS[:30])
            if page == "2":
                return list_html(IDS[24:])
            raise AssertionError("Discovery exceeded the two synthetic pages")
        if "view.do" in url:
            return detail_html(SYNTHETIC_BODY)
        raise AssertionError("Unexpected synthetic client URL")


def args():
    return Namespace(limit=50, delay=1.5, refresh=False, check_cache=False)


def committed_bytes(root):
    fixture = root / "fixtures/kisa"
    return {name: (fixture / name).read_bytes() for name in ("metadata.jsonl", "manifest.json")}


def assert_report(capsys, **counts):
    output = capsys.readouterr().out
    report = [line for line in output.splitlines() if line.startswith("report ")]
    assert len(report) == 1
    values = dict(field.split("=", 1) for field in report[0].split()[1:])
    for key, value in counts.items():
        assert int(values[key]) == value
    assert SYNTHETIC_BODY not in output
    return output


@pytest.fixture
def snapshot(tmp_path, capsys):
    client = FakeClient()
    assert kisa.run(args(), root=tmp_path, client=client) == 0
    assert_report(capsys, success=50, failed=0, parse_failed=0, new=50, pending=0)
    return tmp_path


def test_initial_collection_combines_sources_and_deduplicates_ids(tmp_path, capsys):
    client = FakeClient()

    assert kisa.run(args(), root=tmp_path, client=client) == 0

    assert_report(capsys, success=50, failed=0, parse_failed=0, new=50, pending=0)
    assert len(client.calls) == 53
    assert client.calls[:3] == [
        kisa.RSS_URL,
        kisa.LIST_URL + "&pageIndex=1",
        kisa.LIST_URL + "&pageIndex=2",
    ]
    assert len(set(client.calls[3:])) == 50
    fixture = tmp_path / "fixtures/kisa"
    metadata = [json.loads(line) for line in (fixture / "metadata.jsonl").read_text().splitlines()]
    assert len(metadata) == 50
    assert {row["nttId"] for row in metadata} == set(IDS)
    for row in metadata:
        assert set(row) == {"url", "title", "date", "nttId", "cve_ids"}
        assert row["cve_ids"] == ["CVE-2099-12345", "CVE-2099-678901"]
    manifest = json.loads((fixture / "manifest.json").read_text())
    assert len(manifest["target_ids"]) == len(set(manifest["target_ids"])) == 50
    assert manifest["parser_version"] == kisa.PARSER_VERSION
    assert len(manifest["documents"]) == 50
    for document in manifest["documents"]:
        assert set(document) == {"nttId", "collected_at", "sha256", "parser_version"}
        assert document["sha256"] == kisa.content_hash(SYNTHETIC_BODY)
        assert document["parser_version"] == kisa.PARSER_VERSION
        assert document["collected_at"]


def test_frozen_rerun_uses_no_network_and_preserves_manifest(snapshot, capsys):
    before = committed_bytes(snapshot)
    client = FakeClient()

    assert kisa.run(args(), root=snapshot, client=client) == 0

    assert client.calls == []
    assert committed_bytes(snapshot) == before
    assert_report(capsys, success=0, failed=0, parse_failed=0, new=0, cached=50)


def test_unchanged_refresh_preserves_frozen_metadata_and_timestamps(snapshot, capsys):
    before = committed_bytes(snapshot)
    client = FakeClient()
    options = args()
    options.refresh = True

    assert kisa.run(options, root=snapshot, client=client) == 0

    assert len(client.calls) == 50
    assert all("view.do" in url for url in client.calls)
    assert committed_bytes(snapshot) == before
    assert_report(capsys, success=50, failed=0, parse_failed=0, new=0, unchanged=50, changed=0)


def test_refresh_detects_body_drift_without_replacing_baseline(snapshot, capsys):
    before = committed_bytes(snapshot)
    ntt_id = IDS[-1]
    cache = snapshot / "data/kisa" / ntt_id
    cached_before = (cache / "body.txt").read_bytes()
    raw_before = (cache / "source.html").read_bytes()
    client = FakeClient({kisa.canonical_url(ntt_id): detail_html("Invented changed body")})
    options = args()
    options.refresh = True

    assert kisa.run(options, root=snapshot, client=client) == 1

    assert len(client.calls) == 50
    assert all("view.do" in url for url in client.calls)
    assert committed_bytes(snapshot) == before
    assert (cache / "body.txt").read_bytes() == cached_before
    assert (cache / "source.html").read_bytes() == raw_before
    output = assert_report(capsys, success=49, new=0, changed=1, unchanged=49)
    assert "change_detected" in output
    assert "Invented changed body" not in output


def test_refresh_detects_metadata_only_drift(snapshot, capsys):
    before = committed_bytes(snapshot)
    changed = detail_html(SYNTHETIC_BODY).replace(
        b"Invented test notice", b"Invented revised title"
    )
    client = FakeClient({kisa.canonical_url(IDS[-1]): changed})
    options = args()
    options.refresh = True

    assert kisa.run(options, root=snapshot, client=client) == 1

    assert committed_bytes(snapshot) == before
    assert_report(capsys, success=49, new=0, changed=0, metadata_changed=1, unchanged=49)


def test_hydration_rejects_drift_when_original_cache_is_missing(snapshot, capsys):
    before = committed_bytes(snapshot)
    ntt_id = IDS[-1]
    body_path = snapshot / "data/kisa" / ntt_id / "body.txt"
    body_path.unlink()
    client = FakeClient({kisa.canonical_url(ntt_id): detail_html("Invented changed hydration")})

    assert kisa.run(args(), root=snapshot, client=client) == 1

    assert committed_bytes(snapshot) == before
    assert not body_path.exists()
    assert client.calls == [kisa.canonical_url(ntt_id)]
    assert_report(capsys, success=0, new=0, changed=1, cached=49)


def test_missing_cache_preflight_gives_separate_evaluation_guidance(snapshot, capsys):
    (snapshot / "data/kisa" / IDS[-1] / "body.txt").unlink()
    client = FakeClient()
    options = args()
    options.check_cache = True

    assert kisa.run(options, root=snapshot, client=client) == 1

    assert client.calls == []
    output = assert_report(capsys, failed=1, new=0)
    assert "uv run python scripts/fetch_kisa.py" in output
    assert "separate local cache" in output


@pytest.mark.parametrize("filename", ["body.txt", "source.html"])
def test_offline_preflight_rejects_corrupt_cached_content(snapshot, capsys, filename):
    before = committed_bytes(snapshot)
    cache_path = snapshot / "data/kisa" / IDS[-1] / filename
    corrupt = "Invented corrupted local content"
    cache_path.write_bytes(detail_html(corrupt) if filename == "source.html" else corrupt.encode())
    client = FakeClient()
    options = args()
    options.check_cache = True

    assert kisa.run(options, root=snapshot, client=client) == 1

    assert client.calls == []
    assert committed_bytes(snapshot) == before
    output = assert_report(capsys, failed=1, new=0)
    assert "cache_hash_mismatch" in output
    assert "--refresh" in output
    assert corrupt not in output


def test_matching_hydration_restores_cache_without_changing_manifest(snapshot, capsys):
    before = committed_bytes(snapshot)
    (snapshot / "data/kisa" / IDS[-1] / "body.txt").unlink()
    client = FakeClient()

    assert kisa.run(args(), root=snapshot, client=client) == 0

    assert client.calls == [kisa.canonical_url(IDS[-1])]
    assert committed_bytes(snapshot) == before
    assert_report(capsys, success=1, new=0, restored=1, cached=49)


def test_article_failures_are_counted_and_resume_only_missing_ids(tmp_path, capsys):
    overrides = {
        kisa.canonical_url(IDS[-1]): kisa.FetchError("network_error"),
        kisa.canonical_url(IDS[-2]): b"<html>Invented broken article structure</html>",
    }
    assert kisa.run(args(), root=tmp_path, client=FakeClient(overrides)) == 1
    assert_report(capsys, success=48, new=48, failed=1, parse_failed=1, pending=2)
    client = FakeClient()

    assert kisa.run(args(), root=tmp_path, client=client) == 0

    assert client.calls == [kisa.canonical_url(IDS[-1]), kisa.canonical_url(IDS[-2])]
    assert_report(capsys, success=2, new=2, failed=0, parse_failed=0, cached=48, pending=0)


def test_three_article_failures_stop_even_when_successes_intervene(tmp_path, capsys):
    failed_ids = [IDS[-1], IDS[-3], IDS[-5]]
    client = FakeClient(
        {kisa.canonical_url(i): b"<html>Invented parse failure</html>" for i in failed_ids}
    )

    assert kisa.run(args(), root=tmp_path, client=client) == 1

    assert len(client.calls) == 8
    output = assert_report(capsys, success=2, new=2, parse_failed=3)
    assert "three_" in output and "failures" in output
    assert "Invented parse failure" not in output


def test_access_denial_stops_without_trying_other_discovery_sources(tmp_path, capsys):
    client = FakeClient({kisa.RSS_URL: kisa.AccessDenied("http_403")})

    assert kisa.run(args(), root=tmp_path, client=client) == 1

    assert client.calls == [kisa.RSS_URL]
    assert not (tmp_path / "fixtures/kisa/manifest.json").exists()
    output = assert_report(capsys, success=0, failed=1, parse_failed=0, new=0)
    assert "http_403" in output


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self):
        return self.payload


def test_transport_sets_user_agent_and_delays_after_robots(monkeypatch):
    calls, sleeps = [], []
    now = [0.0]

    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            assert timeout == 30
            return FakeResponse(b"User-agent: *\nAllow: /\n")

    monkeypatch.setattr(kisa.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(kisa.time, "sleep", sleep)
    client = kisa.Client(1.5)
    client.opener = Opener()

    client.get(kisa.RSS_URL)

    assert [request.full_url for request in calls] == [kisa.BASE + "/robots.txt", kisa.RSS_URL]
    assert all(request.get_header("User-agent") == kisa.USER_AGENT for request in calls)
    assert sleeps == [1.5]


def test_robots_denial_prevents_any_article_request():
    requests = []

    class Opener:
        def open(self, request, timeout):
            requests.append(request.full_url)
            return FakeResponse(b"User-agent: *\nDisallow: /\n")

    client = kisa.Client(1.5)
    client.opener = Opener()

    with pytest.raises(kisa.AccessDenied, match="robots_disallow"):
        client.get(kisa.RSS_URL)

    assert requests == [kisa.BASE + "/robots.txt"]


@pytest.mark.parametrize("delay", [0, 0.9, 2.1])
def test_transport_rejects_out_of_bounds_delay(delay):
    with pytest.raises(kisa.KisaError, match="delay_must_be_1_to_2_seconds"):
        kisa.Client(delay)

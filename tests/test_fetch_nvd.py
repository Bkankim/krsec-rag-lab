"""Offline tests: invented CVE records and a fake HTTP opener, no network."""

import email.message
import gzip
import importlib.util
import io
import itertools
import json
import sys
import urllib.request
import urllib.response
import zlib
from argparse import Namespace
from http.client import BadStatusLine, IncompleteRead
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "fetch_nvd.py"
SPEC = importlib.util.spec_from_file_location("fetch_nvd", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
nvd = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = nvd
SPEC.loader.exec_module(nvd)

DATE = "Thu, 29 Oct 2026 07:52:48 GMT"
SYNTHETIC_KEY = "synthetic-key-0000"
FEED_ID = "CVE-2098-0001"
FEED_IDS = ["CVE-2098-0001", "CVE-2098-0002", "CVE-2098-0003"]
API_IDS = ["CVE-2097-0001", "CVE-2097-0002"]
MISSING_FROM_FEED = "CVE-2098-0003"
MISSING_FROM_API = "CVE-2097-0002"
KEV_ID = "CVE-2098-0001"


class FakeClock:
    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


class FakeResponse:
    def __init__(self, body):
        self.body = body
        self.headers = {"Date": DATE}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self.body


class FakeOpener:
    """Routes by URL; `deny` maps a URL substring to an HTTP error code."""

    def __init__(self, clock, world, deny=None):
        self.clock = clock
        self.world = world
        self.deny = deny or {}
        self.calls = []

    def open(self, request, timeout=None):
        url = request.full_url
        headers = {k.lower(): v for k, v in request.header_items()}
        self.calls.append({"url": url, "headers": headers, "at": self.clock.now})
        for marker, code in self.deny.items():
            if marker in url:
                raise HTTPError(url, code, "denied", {}, None)
        return FakeResponse(self.world(url))


def cve_object(cve_id, **extra):
    base = {
        "id": cve_id,
        "published": "2026-01-02T03:04:05.000",
        "lastModified": "2026-02-03T04:05:06.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "es", "value": "descripcion sintetica"},
            {"lang": "en", "value": f"Synthetic description for {cve_id}."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                }
            ],
            "cvssMetricV2": [{"source": "nvd@nist.gov", "cvssData": {"baseScore": 7.5}}],
        },
        "weaknesses": [
            {"source": "nvd@nist.gov", "description": [{"lang": "en", "value": "CWE-79"}]}
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:invented:widget:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.0",
                                "versionEndExcluding": "1.5",
                                "matchCriteriaId": "ignored-id",
                            },
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:o:invented:os:1.0:*:*:*:*:*:*:*",
                            },
                        ],
                    }
                ]
            }
        ],
        "references": [{"url": "https://example.invalid/ignored"}],
    }
    base.update(extra)
    return base


def synthetic_world(changes=None, kev_ids=(KEV_ID,)):
    """`changes` maps a CVE id to cve_object overrides, or to None to drop it from the source."""
    changes = changes or {}

    def make(cve_id):
        return (
            None
            if changes.get(cve_id, {}) is None
            else cve_object(cve_id, **changes.get(cve_id, {}))
        )

    feed_objects = [make(c) for c in FEED_IDS if c != MISSING_FROM_FEED]
    feed_objects = [c for c in feed_objects if c]
    feed_objects.append(cve_object("CVE-2098-9999"))
    feed = {
        "resultsPerPage": len(feed_objects),
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-10-29T07:00:00.000",
        "vulnerabilities": [{"cve": c} for c in feed_objects],
    }
    kev = {
        "title": "Invented catalog",
        "catalogVersion": "2026.10.28",
        "dateReleased": "2026-10-28T19:00:04.8077Z",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": kev_id,
                "vendorProject": "Invented",
                "product": "Widget",
                "vulnerabilityName": "Invented Widget flaw",
                "dateAdded": "2026-10-01",
                "shortDescription": "must not be copied",
                "requiredAction": "must not be copied",
                "dueDate": "2026-10-22",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "must not be copied",
            }
            for kev_id in kev_ids
        ]
        + [{"cveID": "CVE-2000-0001", "vendorProject": "Elsewhere"}],
    }

    def world(url):
        if url == nvd.KEV_URL:
            return json.dumps(kev).encode()
        if url == nvd.FEED_URL.format(year="2098"):
            return gzip.compress(json.dumps(feed, indent=1).encode())
        if url.startswith("https://services.nvd.nist.gov/"):
            cve_id = url.rsplit("=", 1)[1]
            if cve_id == MISSING_FROM_API:
                return json.dumps({"totalResults": 0, "vulnerabilities": []}).encode()
            made = make(cve_id)
            return json.dumps({"vulnerabilities": [{"cve": made}] if made else []}).encode()
        raise AssertionError(f"unexpected url {url}")

    return world


@pytest.fixture
def setup(tmp_path, monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(nvd, "time", SimpleNamespace(sleep=clock.sleep, monotonic=clock.monotonic))
    monkeypatch.setattr(nvd, "FEED_MIN_CVES", 3)
    kisa = tmp_path / "fixtures" / "kisa"
    kisa.mkdir(parents=True)
    rows = [
        {"nttId": "1", "cve_ids": FEED_IDS[:2] + API_IDS[:1]},
        {"nttId": "2", "cve_ids": [FEED_IDS[2], *API_IDS, FEED_IDS[0]]},
    ]
    (kisa / "metadata.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))

    def start(deny=None, **world):
        opener = FakeOpener(clock, synthetic_world(**world), deny)
        monkeypatch.setattr(nvd, "build_opener", lambda *handlers: opener)
        return opener

    return Namespace(root=tmp_path, clock=clock, start=start)


def args(**kw):
    return Namespace(refresh=False, report=False, **kw)


def tree_hashes(directory):
    return {
        str(p.relative_to(directory)): nvd.sha256(p.read_bytes())
        for p in sorted(directory.rglob("*"))
        if p.is_file()
    }


@pytest.mark.parametrize(
    ("key", "interval", "window_limit"),
    [(None, nvd.KEYLESS_API_INTERVAL, 5), (SYNTHETIC_KEY, nvd.KEYED_API_INTERVAL, 50)],
    ids=["keyless", "keyed"],
)
def test_api_requests_are_spaced_below_the_public_limit(setup, key, interval, window_limit):
    opener = setup.start()
    client = nvd.Client(api_key=key)
    for number in range(60):
        client.get(nvd.API_URL.format(cve=f"CVE-2097-{number + 1:04d}"))

    starts = [call["at"] for call in opener.calls]
    gaps = [b - a for a, b in itertools.pairwise(starts)]
    assert min(gaps) >= interval
    # No rolling 30 s window may hold more requests than the documented limit.
    busiest = max(sum(1 for t in starts if s <= t < s + 30) for s in starts)
    assert busiest <= window_limit


def test_other_hosts_are_not_throttled_by_the_api_interval(setup):
    opener = setup.start()
    client = nvd.Client()
    client.get(nvd.KEV_URL)
    client.get(nvd.FEED_URL.format(year="2098"))
    client.get(nvd.API_URL.format(cve="CVE-2097-0001"))  # first API call: no wait

    assert setup.clock.sleeps == [] or max(setup.clock.sleeps) < nvd.KEYLESS_API_INTERVAL
    assert len(opener.calls) == 3


@pytest.mark.parametrize("stage", ["kev", "feed", "api"])
@pytest.mark.parametrize("code", [403, 429])
def test_blocked_response_stops_at_once_and_writes_nothing(setup, capsys, stage, code):
    marker = {
        "kev": "cisa.gov",
        "feed": "nvd.nist.gov/feeds",
        "api": "services.nvd.nist.gov",
    }[stage]
    opener = setup.start({marker: code})

    status = nvd.run(args(), root=setup.root, env={})

    assert status == 2
    # kev is the first request; feed comes after kev; api after kev and feed.
    expected = {"kev": 1, "feed": 2, "api": 3}[stage]
    assert len(opener.calls) == expected
    assert f"reason=http_{code}" in capsys.readouterr().out
    assert not (setup.root / "fixtures" / "nvd").exists()
    assert not (setup.root / "data/nvd/api").exists() or not any(
        (setup.root / "data/nvd/api").iterdir()
    )


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_redirect_is_treated_as_a_block(monkeypatch, code):
    """Go through the real NoRedirect handler: a 30x answer must stop, not be followed."""

    class Redirecting(urllib.request.HTTPSHandler):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def https_open(self, req):
            self.calls += 1
            headers = email.message.Message()
            headers["Location"] = "https://mirror.invalid/elsewhere"
            response = urllib.response.addinfourl(io.BytesIO(b""), headers, req.full_url, code)
            response.msg = "Redirect"
            return response

    fake = Redirecting()
    monkeypatch.setattr(nvd, "build_opener", lambda *h: urllib.request.build_opener(*h, fake))

    client = nvd.Client()
    with pytest.raises(nvd.AccessDenied, match="redirect_requires_inspection"):
        client.get(nvd.KEV_URL)
    assert fake.calls == 1  # the Location target was never requested


@pytest.mark.parametrize(
    "error",
    [IncompleteRead(b"partial"), BadStatusLine("x"), TimeoutError(), OSError("reset")],
    ids=["incomplete-read", "bad-status-line", "timeout", "os-error"],
)
def test_dropped_connection_is_a_fetch_error_not_a_traceback(setup, error):
    class Dropping:
        def open(self, request, timeout=None):
            raise error

    client = nvd.Client(opener=Dropping())
    with pytest.raises(nvd.FetchError, match="network_error"):
        client.get(nvd.KEV_URL)


@pytest.mark.parametrize(
    ("env", "has_key"),
    [
        ({}, False),
        ({"NVD_API_KEY": ""}, False),
        ({"NVD_API_KEY": "   "}, False),
        ({"NVD_API_KEY": SYNTHETIC_KEY}, True),
    ],
    ids=["unset", "empty", "blank", "set"],
)
def test_api_key_path(setup, capsys, env, has_key):
    opener = setup.start()

    assert nvd.run(args(), root=setup.root, env=env) == 0

    by_kind = {}
    for call in opener.calls:
        kind = "api" if "services.nvd.nist.gov" in call["url"] else "other"
        by_kind.setdefault(kind, []).append(call)
    assert all(("apikey" in c["headers"]) is has_key for c in by_kind["api"])
    assert all("apikey" not in c["headers"] for c in by_kind["other"])
    assert all(c["headers"]["user-agent"] == nvd.USER_AGENT for c in opener.calls)
    api_gaps = [b["at"] - a["at"] for a, b in itertools.pairwise(by_kind["api"])]
    expected = nvd.KEYED_API_INTERVAL if has_key else nvd.KEYLESS_API_INTERVAL
    assert api_gaps and min(api_gaps) >= expected
    shown = capsys.readouterr()
    assert SYNTHETIC_KEY not in shown.out + shown.err
    assert f"api_key={'set' if has_key else 'unset'}" in shown.out
    written = "".join(p.read_text() for p in (setup.root / "fixtures/nvd").glob("*"))
    assert SYNTHETIC_KEY not in written


def test_rerun_reuses_cache_and_fixtures_are_byte_identical(setup):
    opener = setup.start()
    assert nvd.run(args(), root=setup.root, env={}) == 0
    first_calls = len(opener.calls)
    before = tree_hashes(setup.root / "fixtures/nvd")

    setup.clock.now += 86400  # a later "now" must not leak into the manifest
    assert nvd.run(args(), root=setup.root, env={}) == 0

    assert len(opener.calls) == first_calls
    assert tree_hashes(setup.root / "fixtures/nvd") == before
    manifest = json.loads((setup.root / "fixtures/nvd/manifest.json").read_text())
    assert manifest["collected_at"] == "2026-10-29T07:52:48+00:00"


def test_refresh_refetches_and_corrupt_cache_is_replaced(setup):
    opener = setup.start()
    nvd.run(args(), root=setup.root, env={})
    first_calls = len(opener.calls)
    victim = setup.root / "data/nvd" / f"api/{API_IDS[0]}.json"
    victim.write_bytes(b"corrupted")

    nvd.run(args(), root=setup.root, env={})
    assert len(opener.calls) == first_calls + 1  # only the corrupted entry

    nvd.run(Namespace(refresh=True, report=False), root=setup.root, env={})
    assert len(opener.calls) == first_calls + 1 + first_calls


def test_fixture_contents_selected_fields_manifest_and_coverage(setup, capsys):
    setup.start()
    nvd.run(args(), root=setup.root, env={})
    fixture = setup.root / "fixtures/nvd"

    rows = {}
    for line in (fixture / "cves.jsonl").read_text().splitlines():
        row = json.loads(line)
        rows[row["id"]] = row
    targets = nvd.load_targets(setup.root)
    assert sorted(rows) == [c for c in targets if c not in {MISSING_FROM_FEED, MISSING_FROM_API}]
    assert "CVE-2098-9999" not in rows  # feed rows outside the target set stay out

    row = rows[KEV_ID]
    assert set(row) == {
        "id", "published", "last_modified", "vuln_status", "description_en",
        "cvss", "cwe", "cpe_total", "cpe", "kev", "vendor_products", "vendor_products_status",
    }  # fmt: skip
    assert row["description_en"] == f"Synthetic description for {KEV_ID}."
    assert row["cvss"] == [
        {
            "version": "3.1",
            "source": "nvd@nist.gov",
            "type": "Primary",
            "base_score": 9.8,
            "severity": "CRITICAL",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    ]
    assert row["cwe"] == ["CWE-79"]
    assert row["cpe_total"] == 1  # the non-vulnerable CPE is dropped
    assert row["cpe"] == [
        {
            "criteria": "cpe:2.3:a:invented:widget:*:*:*:*:*:*:*:*",
            "version_start_including": "1.0",
            "version_end_excluding": "1.5",
        }
    ]
    assert row["kev"] is True
    assert rows[FEED_IDS[1]]["kev"] is False
    assert row["vendor_products"] == ["invented:widget"]  # invented:os is not vulnerable
    assert row["vendor_products_status"] == "ok"

    kev = json.loads((fixture / "kev.json").read_text())
    assert [e["cve_id"] for e in kev["entries"]] == [KEV_ID]  # CVE-2000-0001 is not cited
    assert set(kev["entries"][0]) == {"cve_id", *(new for _, new in nvd.KEV_KEYS)}
    assert "must not be copied" not in (fixture / "kev.json").read_text()

    manifest = json.loads((fixture / "manifest.json").read_text())
    assert manifest["target_cve_ids"] == targets
    assert manifest["not_found"] == {
        MISSING_FROM_FEED: "absent_from_nvd-feed-2098",
        MISSING_FROM_API: "absent_from_nvd-api-2.0",
    }
    assert manifest["coverage"] == {
        "kisa_unique_cves": len(targets),
        "found_in_nvd": len(rows),
        "kev_intersection": 1,
    }
    assert manifest["files"]["cves.jsonl"] == nvd.sha256((fixture / "cves.jsonl").read_bytes())
    assert manifest["files"]["kev.json"] == nvd.sha256((fixture / "kev.json").read_bytes())
    lines = (fixture / "cves.jsonl").read_text().splitlines()
    for cve_id, line in zip(sorted(rows), lines, strict=True):
        assert manifest["records"][cve_id]["sha256"] == nvd.sha256(line.encode())
    assert manifest["records"][KEV_ID]["source"] == "nvd-feed-2098"
    assert manifest["records"][API_IDS[0]]["source"] == "nvd-api-2.0"
    assert {s["name"] for s in manifest["sources"]} == {"cisa-kev", "nvd-feed-2098", "nvd-api-2.0"}
    assert all(len(s["raw_sha256"]) == 64 and s["fetched_at"] for s in manifest["sources"])

    capsys.readouterr()
    assert nvd.run(Namespace(refresh=False, report=True), root=setup.root, env={}) == 0
    assert (
        f"report kisa_unique_cves={len(targets)} found_in_nvd={len(rows)} kev_intersection=1"
        in capsys.readouterr().out
    )


@pytest.mark.parametrize(
    ("is_kev", "cap"), [(False, nvd.CPE_CAP), (True, nvd.CPE_CAP_KEV)], ids=["plain", "kev"]
)
def test_cpe_list_is_capped_but_total_is_kept(is_kev, cap):
    matches = [
        {"vulnerable": True, "criteria": f"cpe:2.3:a:invented:p{n:03d}:*:*:*:*:*:*:*:*"}
        for n in reversed(range(cap + 7))
    ]
    cve = cve_object("CVE-2098-0100", configurations=[{"nodes": [{"cpeMatch": matches}]}])

    row = nvd.select_record(cve, {"CVE-2098-0100"} if is_kev else set())

    assert row["cpe_total"] == cap + 7
    assert len(row["cpe"]) == cap
    assert row["cpe"] == sorted(row["cpe"], key=lambda m: m["criteria"])
    assert row["kev"] is is_kev


def test_cve_without_metrics_or_configurations_still_projects():
    row = nvd.select_record({"id": "CVE-2098-0200", "vulnStatus": "Awaiting Analysis"}, set())

    assert row["cvss"] == [] and row["cpe"] == [] and row["cwe"] == []
    assert row["description_en"] == "" and row["cpe_total"] == 0


@pytest.mark.parametrize("chunk", [7, 64, 1 << 20])
def test_feed_stream_is_independent_of_read_chunk_size(tmp_path, chunk):
    objects = [cve_object(f"CVE-2098-{n:04d}") for n in range(5)]
    feed = {
        "format": "NVD_CVE",
        "timestamp": "t0",
        "vulnerabilities": [{"cve": c} for c in objects],
    }
    path = tmp_path / "feed.json.gz"
    path.write_bytes(gzip.compress(json.dumps(feed, indent=2).encode()))

    stream = nvd.iter_feed(path, chunk=chunk)
    header = next(stream)

    assert header["timestamp"] == "t0"
    assert [c["id"] for c in stream] == [c["id"] for c in objects]


def test_truncated_feed_is_an_error(tmp_path):
    raw = json.dumps({"vulnerabilities": [{"cve": cve_object("CVE-2098-0001")}]}).encode()
    path = tmp_path / "feed.json.gz"
    path.write_bytes(gzip.compress(raw[:-40]))

    stream = nvd.iter_feed(path)
    next(stream)
    with pytest.raises((nvd.NvdError, EOFError)):
        list(stream)


@pytest.mark.parametrize(
    "bad_body",
    [b"<html>challenge page</html>", gzip.compress(b'{"vulnerabilities": [{"cve": {"id"')[:-6]],
    ids=["not-gzip", "truncated-gzip"],
)
def test_unreadable_feed_is_a_reported_failure_not_a_traceback(setup, capsys, bad_body):
    opener = setup.start()
    good = opener.world
    opener.world = lambda url: bad_body if "nvd.nist.gov/feeds" in url else good(url)

    status = nvd.run(args(), root=setup.root, env={})

    assert status == 1
    assert "failed reason=invalid_cached_feed" in capsys.readouterr().out
    assert not (setup.root / "fixtures" / "nvd").exists()


def test_gzip_corrupted_mid_stream_is_a_reported_failure(setup, capsys):
    opener = setup.start()
    good = opener.world
    feed_url = nvd.FEED_URL.format(year="2098")
    payload = bytearray(good(feed_url))
    middle = len(payload) // 2
    payload[middle : middle + 8] = bytes(b ^ 0xFF for b in payload[middle : middle + 8])
    with pytest.raises(zlib.error):  # guard: this corruption really is a zlib error
        gzip.decompress(bytes(payload))
    opener.world = lambda url: bytes(payload) if url == feed_url else good(url)

    status = nvd.run(args(), root=setup.root, env={})

    assert status == 1
    assert "failed reason=invalid_cached_feed" in capsys.readouterr().out
    assert not (setup.root / "fixtures" / "nvd").exists()


def test_metadata_with_malformed_cve_id_is_rejected(tmp_path):
    kisa = tmp_path / "fixtures" / "kisa"
    kisa.mkdir(parents=True)
    (kisa / "metadata.jsonl").write_text(json.dumps({"cve_ids": ["CVE-2098-12"]}) + "\n")

    with pytest.raises(nvd.NvdError):
        nvd.load_targets(tmp_path)


def vulnerable(*criteria):
    return [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": c} for c in criteria]}]}]


def cpe(vendor, product, version="*"):
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def test_vendor_products_are_untruncated_unique_sorted_and_vulnerable_only():
    matches = [{"vulnerable": True, "criteria": cpe("v", f"p{n:03d}")} for n in range(40)]
    matches += [{"vulnerable": True, "criteria": cpe("v", "p000", "2.0")}]  # same product twice
    matches += [{"vulnerable": False, "criteria": cpe("running-on", "os")}]
    cve = cve_object("CVE-2098-0100", configurations=[{"nodes": [{"cpeMatch": matches}]}])

    row = nvd.merge_record(cve, set(), None)

    assert row["vendor_products"] == [f"v:p{n:03d}" for n in range(40)]
    assert len(row["cpe"]) == nvd.CPE_CAP and row["cpe_total"] == 41  # existing fields unchanged
    assert row["vendor_products_status"] == "ok"


@pytest.mark.parametrize(
    ("criteria", "expected"),
    [
        (cpe("acme", "widget", "1.0"), "acme:widget"),
        ("cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*", "linux:linux_kernel"),
        (cpe("a\\:b", "c"), "a\\:b:c"),
    ],
    ids=["plain", "os-part", "escaped-colon"],
)
def test_vendor_product_split(criteria, expected):
    assert nvd.vendor_product(criteria) == expected


@pytest.mark.parametrize(
    "criteria", ["", "cpe:2.3:a:only", "cpe:/a:acme:widget:1.0", "x:2.3:a:b:c"]
)
def test_malformed_cpe_is_a_reported_error(criteria):
    with pytest.raises(nvd.NvdError, match="malformed_cpe_criteria"):
        nvd.vendor_product(criteria)


def old_row(**extra):
    cve = cve_object("CVE-2098-0300", configurations=vulnerable(cpe("a", "one"), cpe("b", "two")))
    return nvd.select_record(cve, set()) | extra


@pytest.mark.parametrize(
    ("name", "new", "old", "status", "products"),
    [
        ("same", {}, {}, "ok", ["a:one", "b:two"]),
        ("description", {"descriptions": []}, {}, "drifted", ["a:one", "b:two"]),
        ("kev-flag", {}, {"kev": True}, "drifted", ["a:one", "b:two"]),
        # the new source dropped every vulnerable match: drifted wins over no_configurations
        ("gone-configs", {"configurations": []}, {}, "drifted", ["a:one", "b:two"]),
        (
            "other-products",
            {"configurations": vulnerable(cpe("c", "three"))},
            {},
            "drifted",
            ["a:one", "b:two", "c:three"],
        ),
        ("missing-from-source", None, {}, "drifted", ["a:one", "b:two"]),
    ],
)
def test_merge_with_committed_row(name, new, old, status, products):
    committed = old_row(**old)
    cve = (
        None
        if new is None
        else cve_object(
            "CVE-2098-0300",
            **{"configurations": vulnerable(cpe("a", "one"), cpe("b", "two"))} | new,
        )
    )

    row = nvd.merge_record(cve, set(), committed)

    assert {k: v for k, v in row.items() if k not in nvd.ADDED_KEYS} == committed
    assert row["vendor_products_status"] == status
    assert row["vendor_products"] == products
    assert {nvd.vendor_product(m["criteria"]) for m in committed["cpe"]} <= set(
        row["vendor_products"]
    )


@pytest.mark.parametrize(
    "configurations",
    [
        [],
        vulnerable(),
        [{"nodes": [{"cpeMatch": [{"vulnerable": False, "criteria": cpe("x", "y")}]}]}],
    ],
    ids=["none", "empty-nodes", "only-non-vulnerable"],
)
def test_no_vulnerable_match_is_no_configurations(configurations):
    cve = cve_object("CVE-2098-0301", configurations=configurations)
    fresh = nvd.merge_record(cve, set(), None)
    assert fresh["vendor_products"] == [] and fresh["vendor_products_status"] == "no_configurations"

    committed = nvd.select_record(cve, set())  # old cpe is empty too, nothing differs
    again = nvd.merge_record(cve, set(), committed)
    assert again["vendor_products"] == [] and again["vendor_products_status"] == "no_configurations"


def fixture_state(root):
    fixture = root / "fixtures/nvd"
    manifest = json.loads((fixture / "manifest.json").read_text())
    rows = {r["id"]: r for r in map(json.loads, (fixture / "cves.jsonl").read_text().splitlines())}
    return fixture, manifest, rows


def test_first_collection_marks_every_record_and_counts_statuses(setup):
    setup.start(changes={API_IDS[0]: {"configurations": []}})
    assert nvd.run(args(), root=setup.root, env={}) == 0

    _, manifest, rows = fixture_state(setup.root)
    assert rows[API_IDS[0]]["vendor_products_status"] == "no_configurations"
    assert rows[KEV_ID]["vendor_products_status"] == "ok"
    assert manifest["vendor_products_status_counts"] == {
        "ok": 2, "no_configurations": 1, "drifted": 0
    }  # fmt: skip
    assert manifest["vendor_products_drifted_ids"] == []
    assert manifest["base_sources"] == manifest["sources"]


@pytest.mark.parametrize(
    ("changes", "kev_ids", "drifted"),
    [
        ({FEED_IDS[1]: {"vulnStatus": "Modified"}}, (KEV_ID,), FEED_IDS[1]),
        ({FEED_IDS[1]: {"configurations": []}}, (KEV_ID,), FEED_IDS[1]),
        ({FEED_IDS[1]: None}, (KEV_ID,), FEED_IDS[1]),
        ({API_IDS[0]: {"descriptions": []}}, (KEV_ID,), API_IDS[0]),
        ({}, (), KEV_ID),
    ],
    ids=["field-changed", "configs-vanished", "dropped-from-feed", "api-record", "kev-flag-flips"],
)
def test_new_source_drift_keeps_committed_fields(setup, changes, kev_ids, drifted):
    setup.start()
    assert nvd.run(args(), root=setup.root, env={}) == 0
    fixture, before, rows_before = fixture_state(setup.root)
    kev_bytes = (fixture / "kev.json").read_bytes()
    stripped = {
        i: {k: v for k, v in r.items() if k not in nvd.ADDED_KEYS} for i, r in rows_before.items()
    }

    setup.start(changes=changes, kev_ids=kev_ids)
    assert nvd.run(Namespace(refresh=True, report=False), root=setup.root, env={}) == 0

    fixture, after, rows = fixture_state(setup.root)
    assert {
        i: {k: v for k, v in r.items() if k not in nvd.ADDED_KEYS} for i, r in rows.items()
    } == stripped
    assert (fixture / "kev.json").read_bytes() == kev_bytes
    assert after["coverage"] == before["coverage"] and after["not_found"] == before["not_found"]
    assert after["vendor_products_drifted_ids"] == [drifted]
    assert rows[drifted]["vendor_products_status"] == "drifted"
    assert set(rows[drifted]["vendor_products"]) >= {
        nvd.vendor_product(m["criteria"]) for m in rows[drifted]["cpe"]
    }
    assert sum(after["vendor_products_status_counts"].values()) == len(rows)
    assert after["vendor_products_status_counts"]["drifted"] == 1
    assert after["base_sources"] == before["sources"]
    assert after["sources"] != before["sources"]  # the refreshed raw responses are new
    assert after["files"]["cves.jsonl"] == nvd.sha256((fixture / "cves.jsonl").read_bytes())


def test_committed_fixture_without_new_keys_is_upgraded_and_then_stable(setup):
    """The pre-#36 fixture shape (no vendor_products, no base_sources) merges, then reruns clean."""
    opener = setup.start()
    assert nvd.run(args(), root=setup.root, env={}) == 0
    fixture, manifest, rows = fixture_state(setup.root)
    legacy = {i: {k: v for k, v in r.items() if k not in nvd.ADDED_KEYS} for i, r in rows.items()}
    (fixture / "cves.jsonl").write_text(
        "".join(nvd.canonical(legacy[i]) + "\n" for i in sorted(legacy))
    )
    for key in ("base_sources", "vendor_products_status_counts", "vendor_products_drifted_ids"):
        del manifest[key]
    (fixture / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    calls = len(opener.calls)

    assert nvd.run(args(), root=setup.root, env={}) == 0
    upgraded = tree_hashes(fixture)
    assert len(opener.calls) == calls  # cache only
    _, after, new_rows = fixture_state(setup.root)
    assert after["base_sources"] == manifest["sources"]
    assert new_rows == rows  # same data, nothing drifted

    assert nvd.run(args(), root=setup.root, env={}) == 0
    assert tree_hashes(fixture) == upgraded
    assert len(opener.calls) == calls


def test_incomplete_committed_fixture_is_a_reported_failure(setup, capsys):
    setup.start()
    fixture = setup.root / "fixtures/nvd"
    fixture.mkdir(parents=True)
    (fixture / "cves.jsonl").write_text("{}\n")  # no id, no kev.json, no manifest.json

    assert nvd.run(args(), root=setup.root, env={}) == 1
    assert "failed reason=unreadable_committed_fixture" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("criteria", "expected"),
    [
        (
            "cpe:2.3:a:foo\\\\:bar:1.0:*:*:*:*:*:*:*",
            "foo\\\\:bar",
        ),  # vendor 'foo\\', then separator
        (
            "cpe:2.3:a:foo\\\\\\:bar:baz:*:*:*:*:*:*:*",
            "foo\\\\\\:bar:baz",
        ),  # escaped backslash + colon
        ("cpe:2.3:a:a\\:b:c:1.0:*:*:*:*:*:*:*", "a\\:b:c"),
    ],
    ids=["escaped-backslash-then-separator", "escaped-backslash-and-colon", "escaped-colon"],
)
def test_vendor_product_handles_escaped_backslashes(criteria, expected):
    assert nvd.vendor_product(criteria) == expected


def test_malformed_cpe_in_the_source_is_a_reported_failure(setup, capsys):
    setup.start(changes={FEED_IDS[1]: {"configurations": vulnerable("cpe:2.3")}})

    assert nvd.run(args(), root=setup.root, env={}) == 1

    assert "failed reason=malformed_cpe_criteria" in capsys.readouterr().out
    assert not (setup.root / "fixtures" / "nvd").exists()


def test_committed_row_without_a_manifest_record_is_a_reported_failure(setup, capsys):
    setup.start()
    assert nvd.run(args(), root=setup.root, env={}) == 0
    fixture, manifest, _ = fixture_state(setup.root)
    del manifest["records"][FEED_IDS[1]]
    (fixture / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    before = tree_hashes(fixture)
    capsys.readouterr()

    assert nvd.run(args(), root=setup.root, env={}) == 1

    assert "failed reason=unreadable_committed_fixture" in capsys.readouterr().out
    assert tree_hashes(fixture) == before


def test_run_summary_matches_the_written_manifest_when_a_base_exists(setup, capsys):
    setup.start()
    assert nvd.run(args(), root=setup.root, env={}) == 0
    _, before, _ = fixture_state(setup.root)
    capsys.readouterr()

    # The refreshed source loses the KEV entry and one record: the committed numbers stay.
    setup.start(changes={FEED_IDS[1]: None}, kev_ids=())
    assert nvd.run(Namespace(refresh=True, report=False), root=setup.root, env={}) == 0

    summary = capsys.readouterr().out
    assert before["coverage"]["kev_intersection"] == 1
    assert f"not_found={len(before['not_found'])} " in summary
    assert f"kev_intersection={before['coverage']['kev_intersection']} " in summary


CHECK_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_nvd_fields.py"
CHECK_SPEC = importlib.util.spec_from_file_location("check_nvd_fields", CHECK_SCRIPT)
assert CHECK_SPEC is not None and CHECK_SPEC.loader is not None
check = importlib.util.module_from_spec(CHECK_SPEC)
CHECK_SPEC.loader.exec_module(check)


def lines_of(rows):
    return "".join(nvd.canonical(r) + "\n" for r in rows)


@pytest.mark.parametrize(
    ("mutate", "failure"),
    [
        (lambda rows: rows, None),
        (lambda rows: rows + [rows[0]], "duplicate id in cves.jsonl"),
        (lambda rows: [rows[0] | {"stray": 1}, *rows[1:]], "unexpected keys stray"),
        (lambda rows: [rows[0] | {"cpe_total": 99}, *rows[1:]], "changed cpe_total"),
        (
            lambda rows: [{k: v for k, v in rows[0].items() if k != "vendor_products"}, *rows[1:]],
            "added fields missing",
        ),
    ],
    ids=["clean", "duplicate-id", "extra-key", "changed-field", "missing-added-key"],
)
def test_check_nvd_fields_flags_what_it_promises(tmp_path, monkeypatch, capsys, mutate, failure):
    base_rows = [nvd.select_record(cve_object(f"CVE-2098-{n:04d}"), set()) for n in range(1, 4)]
    now_rows = [
        r | {"vendor_products": ["invented:widget"], "vendor_products_status": "ok"}
        for r in base_rows
    ]
    fixture = tmp_path / "fixtures/nvd"
    fixture.mkdir(parents=True)
    (fixture / "cves.jsonl").write_text(lines_of(mutate(now_rows)))
    (fixture / "kev.json").write_bytes(b"{}\n")
    manifest = {"coverage": {"a": 1}, "not_found": {}}
    (fixture / "manifest.json").write_text(json.dumps(manifest))
    committed = {
        "fixtures/nvd/cves.jsonl": lines_of(base_rows).encode(),
        "fixtures/nvd/kev.json": b"{}\n",
        "fixtures/nvd/manifest.json": json.dumps(manifest).encode(),
    }
    monkeypatch.setattr(check, "ROOT", tmp_path)
    monkeypatch.setattr(check, "git_show", lambda base, path: committed[path])

    status = check.main(["check_nvd_fields.py", "base"])

    out = capsys.readouterr().out
    assert (status == 0) is (failure is None)
    assert failure is None or failure in out

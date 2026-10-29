"""Opt-in NVD / CISA KEV fixture builder for the KISA-cited CVE set.

Only official sources are used: NVD API 2.0, NVD yearly JSON feeds, CISA KEV JSON.
Raw responses are cached under data/nvd (gitignored); fixtures/nvd holds selected fields only.
When fixtures/nvd/cves.jsonl is already committed it is the source of the existing fields:
only vendor_products / vendor_products_status come from the fresh source (see build()).
The only KISA input is the public cve_ids column of fixtures/kisa/metadata.jsonl.
Never print the API key or response bodies.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import time
import zlib
from collections import Counter
from datetime import UTC
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
USER_AGENT = "krsec-rag-lab/0.1 (+https://github.com/Bkankim/krsec-rag-lab; research fixture)"
API_HOST = "services.nvd.nist.gov"
API_URL = "https://" + API_HOST + "/rest/json/cves/2.0?cveId={cve}"
FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SELECTION_VERSION = "nvd-select-v1"
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}")
# NVD public limit: 5 requests / rolling 30 s without key, 50 with key. Spacing is the limit
# divided by the window plus a margin, so no 30 s window can ever hold more than the limit.
KEYLESS_API_INTERVAL = 6.5
KEYED_API_INTERVAL = 0.7
OTHER_INTERVAL = 2.0
# A year with at least this many target CVEs is read from the yearly feed (one download),
# fewer are fetched one by one through the API (a few requests).
FEED_MIN_CVES = 25
# Per-record CPE cap keeps fixtures/nvd under 3 MB; KEV records get a higher cap, cpe_total is kept.
CPE_CAP = 3
CPE_CAP_KEV = 25
CVSS_KEYS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"))
RANGE_KEYS = (
    ("versionStartIncluding", "version_start_including"),
    ("versionStartExcluding", "version_start_excluding"),
    ("versionEndIncluding", "version_end_including"),
    ("versionEndExcluding", "version_end_excluding"),
)
ADDED_KEYS = ("vendor_products", "vendor_products_status")
STATUSES = ("ok", "no_configurations", "drifted")
KEV_KEYS = (
    ("vendorProject", "vendor_project"),
    ("product", "product"),
    ("vulnerabilityName", "vulnerability_name"),
    ("dateAdded", "date_added"),
    ("dueDate", "due_date"),
    ("knownRansomwareCampaignUse", "known_ransomware_campaign_use"),
)


class NvdError(Exception):
    """Only fixed, body-free reason codes belong in this exception."""


class FetchError(NvdError):
    pass


class AccessDenied(FetchError):
    """401/403/429/redirect: stop at once, never retry or route around."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AccessDenied("redirect_requires_inspection")


def api_key_from(env):
    """The key comes from the environment only; blank counts as unset."""
    return (env.get("NVD_API_KEY") or "").strip() or None


def interval_for(host, has_key):
    if host == API_HOST:
        return KEYED_API_INTERVAL if has_key else KEYLESS_API_INTERVAL
    return OTHER_INTERVAL


class Client:
    def __init__(self, api_key=None, opener=None):
        self.api_key = api_key
        self.opener = opener or build_opener(NoRedirect())
        self.clock = time.monotonic
        self.sleep = time.sleep
        self.last_start = {}
        self.requests = 0

    def get(self, url):
        """Return (body, http_date). Raises AccessDenied on 401/403/429/redirect."""
        host = urlsplit(url).hostname
        headers = {"User-Agent": USER_AGENT}
        if self.api_key and host == API_HOST:
            headers["apiKey"] = self.api_key
        last = self.last_start.get(host)
        if last is not None:
            self.sleep(max(0, interval_for(host, bool(self.api_key)) - (self.clock() - last)))
        self.last_start[host] = self.clock()
        self.requests += 1
        try:
            with self.opener.open(Request(url, headers=headers), timeout=120) as response:
                body = response.read()
                date = response.headers.get("Date")
        except HTTPError as error:
            if error.code in {401, 403, 429}:
                raise AccessDenied(f"http_{error.code}") from None
            raise FetchError(f"http_{error.code}") from None
        except (URLError, TimeoutError, OSError, HTTPException):
            raise FetchError("network_error") from None
        try:
            fetched_at = parsedate_to_datetime(date).astimezone(UTC).isoformat(timespec="seconds")
        except (TypeError, ValueError):
            raise FetchError("missing_date_header") from None
        return body, fetched_at


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def write_file(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_bytes(data)
    temp.replace(path)


def load_targets(root):
    ids = set()
    for line in (root / "fixtures/kisa/metadata.jsonl").read_text(encoding="utf-8").splitlines():
        for cve in json.loads(line)["cve_ids"]:
            if not CVE_ID.fullmatch(cve):
                raise NvdError("invalid_cve_id_in_metadata")
            ids.add(cve)
    return sorted(ids)


class Cache:
    """Raw-response cache under data/nvd. The index records when each response was fetched."""

    def __init__(self, directory):
        self.directory = directory
        self.index_path = directory / "cache.json"
        try:
            self.index = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.index = {}

    def get(self, client, name, url, refresh=False):
        """Return (path, entry); fetch only when missing, corrupt, or refresh is requested."""
        path = self.directory / name
        entry = self.index.get(name)
        if (
            not refresh
            and entry
            and path.is_file()
            and sha256(path.read_bytes()) == entry["sha256"]
        ):
            return path, entry
        body, fetched_at = client.get(url)
        write_file(path, body)
        entry = {"url": url, "fetched_at": fetched_at, "sha256": sha256(body), "bytes": len(body)}
        self.index[name] = entry
        write_file(
            self.index_path, (json.dumps(self.index, indent=2, sort_keys=True) + "\n").encode()
        )
        return path, entry


def iter_feed(path, chunk=1 << 20):
    """Stream (header, cve dicts) out of a gzip NVD 2.0 feed without loading it whole."""
    decoder = json.JSONDecoder()
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        buf = ""
        eof = False

        def fill():
            nonlocal buf, eof
            data = handle.read(chunk)
            if data:
                buf += data
            else:
                eof = True

        while True:
            marker = re.search(r'"vulnerabilities"\s*:\s*\[', buf)
            if marker:
                break
            if eof:
                raise NvdError("feed_without_vulnerabilities")
            fill()
        head = buf[: marker.start()].rstrip().rstrip(",") + "}"
        header = json.loads(head)
        buf = buf[marker.end() :]
        yield header
        while True:
            stripped = buf.lstrip(" \t\r\n,")
            if stripped.startswith("]"):
                return
            buf = stripped
            if not buf:
                if eof:
                    raise NvdError("feed_truncated")
                fill()
                continue
            try:
                item, end = decoder.raw_decode(buf)
            except ValueError:
                if eof:
                    raise NvdError("feed_truncated") from None
                fill()
                continue
            buf = buf[end:]
            yield item["cve"]


def english(descriptions):
    for item in descriptions or []:
        if item.get("lang") == "en":
            return item.get("value", "")
    return ""


def vulnerable_matches(cve):
    """Unique `vulnerable: true` cpeMatch rows of one CVE, sorted by their canonical JSON."""
    matches = {}
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                row = {"criteria": match["criteria"]}
                row.update({new: match[old] for old, new in RANGE_KEYS if match.get(old)})
                matches[canonical(row)] = row
    return [matches[key] for key in sorted(matches)]


def vendor_product(criteria):
    """`vendor:product` of a CPE 2.3 formatted string (escaped colons stay inside a field)."""
    parts = re.split(r"(?<!\\):", criteria)
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        raise NvdError("malformed_cpe_criteria")
    return f"{parts[3]}:{parts[4]}"


def vendor_products_of(matches):
    return sorted({vendor_product(m["criteria"]) for m in matches})


def select_record(cve, kev_ids):
    """Project one NVD 2.0 CVE object onto the committed field set."""
    cvss = []
    metrics = cve.get("metrics") or {}
    for key, version in CVSS_KEYS:
        for metric in metrics.get(key) or []:
            data = metric["cvssData"]
            cvss.append(
                {
                    "version": version,
                    "source": metric.get("source"),
                    "type": metric.get("type"),
                    "base_score": data.get("baseScore"),
                    "severity": data.get("baseSeverity") or metric.get("baseSeverity"),
                    "vector": data.get("vectorString"),
                }
            )
    cwe = sorted(
        {
            d["value"]
            for w in cve.get("weaknesses") or []
            for d in w.get("description") or []
            if d.get("lang") == "en" and d.get("value")
        }
    )
    ordered = vulnerable_matches(cve)
    is_kev = cve["id"] in kev_ids
    return {
        "id": cve["id"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "description_en": english(cve.get("descriptions")),
        "cvss": cvss,
        "cwe": cwe,
        "cpe_total": len(ordered),
        "cpe": ordered[: CPE_CAP_KEV if is_kev else CPE_CAP],
        "kev": is_kev,
    }


def parse_api(body, cve_id):
    """Return the CVE object, or None when NVD reports no such CVE."""
    try:
        data = json.loads(body)
        found = [v["cve"] for v in data["vulnerabilities"] if v["cve"]["id"] == cve_id]
    except (ValueError, KeyError, TypeError):
        raise NvdError("unexpected_api_response") from None
    return found[0] if found else None


def read_kev(path):
    try:
        data = json.loads(path.read_bytes())
        return {
            "catalog_version": data["catalogVersion"],
            "date_released": data["dateReleased"],
            "count": data["count"],
            "entries": {row["cveID"]: row for row in data["vulnerabilities"]},
        }
    except (OSError, ValueError, KeyError, TypeError):
        raise NvdError("unexpected_kev_response") from None


def collect(targets, cache, client, refresh):
    """Fetch (or reuse) raw responses; return ({id: cve object}, kev, sources, not_found)."""
    kev_path, kev_entry = cache.get(
        client, "kev/known_exploited_vulnerabilities.json", KEV_URL, refresh
    )
    kev = read_kev(kev_path)
    by_year = {}
    for cve in targets:
        by_year.setdefault(cve.split("-")[1], []).append(cve)
    found, not_found, sources = {}, {}, []
    sources.append(
        {
            "name": "cisa-kev",
            "url": KEV_URL,
            "version": kev["catalog_version"],
            "date_released": kev["date_released"],
            "fetched_at": kev_entry["fetched_at"],
            "raw_sha256": kev_entry["sha256"],
            "raw_bytes": kev_entry["bytes"],
        }
    )
    api_ids = []
    for year in sorted(by_year):
        ids = by_year[year]
        if len(ids) < FEED_MIN_CVES:
            api_ids.extend(ids)
            continue
        name = f"nvd-feed-{year}"
        path, entry = cache.get(
            client, f"feeds/nvdcve-2.0-{year}.json.gz", FEED_URL.format(year=year), refresh
        )
        wanted = set(ids)
        try:
            stream = iter_feed(path)
            header = next(stream)
            for cve in stream:
                if cve["id"] in wanted:
                    found[cve["id"]] = (cve, name)
        except (EOFError, OSError, ValueError, KeyError, TypeError, zlib.error):
            raise NvdError("invalid_cached_feed_rerun_with_refresh") from None
        for cve_id in ids:
            if cve_id not in found:
                not_found[cve_id] = f"absent_from_{name}"
        sources.append(
            {
                "name": name,
                "url": entry["url"],
                "version": f"NVD_CVE {header.get('version')} feed timestamp {header.get('timestamp')}",
                "fetched_at": entry["fetched_at"],
                "raw_sha256": entry["sha256"],
                "raw_bytes": entry["bytes"],
            }
        )
    api_entries = []
    for cve_id in api_ids:
        path, entry = cache.get(
            client, f"api/{cve_id}.json", API_URL.format(cve=quote(cve_id)), refresh
        )
        cve = parse_api(path.read_bytes(), cve_id)
        if cve is None:
            not_found[cve_id] = "absent_from_nvd-api-2.0"
        else:
            found[cve_id] = (cve, "nvd-api-2.0")
        api_entries.append((cve_id, entry))
    if api_entries:
        sources.append(
            {
                "name": "nvd-api-2.0",
                "url": API_URL.replace("{cve}", "<CVE-ID>"),
                "version": "2.0",
                "fetched_at": max(e["fetched_at"] for _, e in api_entries),
                "raw_sha256": sha256(
                    "".join(f"{i} {e['sha256']}\n" for i, e in api_entries).encode()
                ),
                "raw_bytes": sum(e["bytes"] for _, e in api_entries),
            }
        )
    return found, kev, sources, not_found


def merge_record(cve, kev_ids, old):
    """One fixture row and its vendor_products_status.

    `old` is the committed row (or None on a first collection), `cve` the freshly fetched NVD
    object (or None when the source no longer has it). Existing fields always come from `old`
    when there is one; only vendor_products / vendor_products_status come from `cve`.
    """
    if old is None:
        row = select_record(cve, kev_ids)
        products = vendor_products_of(vulnerable_matches(cve))
        return row | {
            "vendor_products": products,
            "vendor_products_status": "ok" if products else "no_configurations",
        }
    fields = {k: v for k, v in old.items() if k not in ADDED_KEYS}
    kept = vendor_products_of(fields.get("cpe") or [])
    if cve is None:
        products, drifted = kept, True
    else:
        fresh = select_record(cve, kev_ids)
        products = vendor_products_of(vulnerable_matches(cve))
        drifted = fresh != fields
        if drifted:  # the committed cpe products must survive whatever the new source says
            products = sorted(set(products) | set(kept))
    if drifted:
        status = "drifted"
    else:
        status = "ok" if products else "no_configurations"
    return fields | {"vendor_products": products, "vendor_products_status": status}


def load_base(root):
    """The committed fixture as the source of existing fields; None when there is none yet."""
    fixture = root / "fixtures/nvd"
    if not (fixture / "cves.jsonl").is_file():
        return None
    try:
        rows = [
            json.loads(line)
            for line in (fixture / "cves.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        kev_bytes = (fixture / "kev.json").read_bytes()
        manifest = json.loads((fixture / "manifest.json").read_text(encoding="utf-8"))
        return {
            "rows": {row["id"]: row for row in rows},
            "kev_bytes": kev_bytes,
            "manifest": manifest,
            "record_sources": {i: r["source"] for i, r in manifest["records"].items()},
            "coverage": manifest["coverage"],
            "not_found": manifest["not_found"],
            "base_sources": manifest.get("base_sources") or manifest["sources"],
        }
    except (OSError, ValueError, KeyError, TypeError):
        raise NvdError("unreadable_committed_fixture") from None


def build(targets, found, kev, sources, not_found, base=None):
    """Pure projection: same inputs always give byte-identical fixture files.

    With `base` (see load_base) the existing row fields, kev.json bytes, coverage and not_found
    are carried over from the committed fixture unchanged; a row the new source disagrees with
    (or no longer has) is marked drifted.
    """
    kev_ids = set(kev["entries"])
    ids = sorted(found) if base is None else sorted(set(found) | set(base["rows"]))
    records = {
        cve_id: merge_record(
            found[cve_id][0] if cve_id in found else None,
            kev_ids,
            base["rows"].get(cve_id) if base else None,
        )
        for cve_id in ids
    }
    lines = [canonical(records[cve_id]) for cve_id in records]
    cves_bytes = ("".join(line + "\n" for line in lines)).encode()
    intersection = sorted(kev_ids.intersection(targets))
    if base:
        kev_bytes = base["kev_bytes"]
    else:
        kev_doc = {
            "source_url": KEV_URL,
            "catalog_version": kev["catalog_version"],
            "date_released": kev["date_released"],
            "catalog_count": kev["count"],
            "license": "CC0 1.0 https://www.cisa.gov/sites/default/files/licenses/kev/license.txt",
            "selection": "entries whose CVE is cited by fixtures/kisa/metadata.jsonl",
            "entries": [
                {"cve_id": cve_id} | {new: kev["entries"][cve_id].get(old) for old, new in KEV_KEYS}
                for cve_id in intersection
            ],
        }
        kev_bytes = (
            json.dumps(kev_doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode()
    statuses = Counter(row["vendor_products_status"] for row in records.values())
    manifest = {
        "schema_version": 1,
        "selection_version": SELECTION_VERSION,
        "collected_at": max(s["fetched_at"] for s in sources),
        "user_agent": USER_AGENT,
        "sources": sources,
        "base_sources": base["base_sources"] if base else sources,
        "target_cve_ids": list(targets),
        "not_found": base["not_found"] if base else dict(sorted(not_found.items())),
        "coverage": base["coverage"]
        if base
        else {
            "kisa_unique_cves": len(targets),
            "found_in_nvd": len(found),
            "kev_intersection": len(intersection),
        },
        "vendor_products_status_counts": {s: statuses[s] for s in STATUSES},
        "vendor_products_drifted_ids": [
            cve_id for cve_id, row in records.items() if row["vendor_products_status"] == "drifted"
        ],
        "files": {"cves.jsonl": sha256(cves_bytes), "kev.json": sha256(kev_bytes)},
        "records": {
            cve_id: {
                "sha256": sha256(line.encode()),
                "source": found[cve_id][1] if cve_id in found else base["record_sources"][cve_id],
            }
            for cve_id, line in zip(records, lines, strict=True)
        },
        "notice": "NOTICE.md",
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode()
    return {"cves.jsonl": cves_bytes, "kev.json": kev_bytes, "manifest.json": manifest_bytes}


def report_from_fixture(root):
    """Recompute the three coverage numbers from committed files only (no network)."""
    fixture = root / "fixtures/nvd"
    targets = load_targets(root)
    ids = [
        json.loads(line)["id"]
        for line in (fixture / "cves.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    kev = {
        e["cve_id"]
        for e in json.loads((fixture / "kev.json").read_text(encoding="utf-8"))["entries"]
    }
    return {
        "kisa_unique_cves": len(targets),
        "found_in_nvd": len(set(ids) & set(targets)),
        "kev_intersection": len(kev & set(targets)),
    }


def run(args, root=ROOT, client=None, env=None):
    env = os.environ if env is None else env
    if args.report:
        print("report " + " ".join(f"{k}={v}" for k, v in report_from_fixture(root).items()))
        return 0
    key = api_key_from(env)
    client = client or Client(api_key=key)
    targets = load_targets(root)
    cache = Cache(root / "data/nvd")
    print(f"targets={len(targets)} api_key={'set' if key else 'unset'}")
    try:
        base = load_base(root)
        found, kev, sources, not_found = collect(targets, cache, client, args.refresh)
    except AccessDenied as error:
        print(f"stopped reason={error} requests={client.requests}")
        return 2
    except NvdError as error:
        print(f"failed reason={error} requests={client.requests}")
        return 1
    files = build(targets, found, kev, sources, not_found, base)
    for name, data in files.items():
        write_file(root / "fixtures/nvd" / name, data)
    counts = Counter(name for _, name in found.values())
    print(
        f"requests={client.requests} found={len(found)} not_found={len(not_found)} "
        f"kev_intersection={len(kev['entries'].keys() & set(targets))} sources={dict(counts)}"
    )
    status = json.loads(files["manifest.json"])["vendor_products_status_counts"]
    print(f"vendor_products_status={status} base={'committed' if base else 'none'}")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true", help="ignore data/nvd cache and refetch")
    parser.add_argument(
        "--report", action="store_true", help="offline: recompute coverage from fixtures/nvd"
    )
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())

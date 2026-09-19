"""Opt-in KISA fixture acquisition. Never print response or article text."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.robotparser import RobotFileParser

BASE = "https://www.boho.or.kr"
RSS_URL = BASE + "/kr/rss.do?bbsId=B0000133"
LIST_URL = BASE + "/kr/bbs/list.do?bbsId=B0000133&menuNo=205020"
PARSER_VERSION = "kisa-html-v1"
USER_AGENT = "krsec-rag-lab/0.1 (+https://github.com/Bkankim/krsec-rag-lab; research fixture)"
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
ROOT = Path(__file__).resolve().parents[1]
VOID = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}
BLOCK = {"br", "div", "p", "li", "tr", "td", "th", "h1", "h2", "h3", "h4"}


class KisaError(Exception):
    """Only fixed, body-free reason codes belong in this exception."""


class ParseError(KisaError):
    pass


class FetchError(KisaError):
    pass


class AccessDenied(FetchError):
    pass


@dataclass
class Node:
    tag: str
    attrs: dict = field(default_factory=dict)
    children: list = field(default_factory=list)

    def find(self, *, tag=None, cls=None):
        found = []
        if (tag is None or self.tag == tag) and (
            cls is None or cls in self.attrs.get("class", "").split()
        ):
            found.append(self)
        for child in self.children:
            if isinstance(child, Node):
                found.extend(child.find(tag=tag, cls=cls))
        return found

    def text(self):
        if self.tag in {"script", "style", "noscript"}:
            return ""
        parts = [c.text() if isinstance(c, Node) else c for c in self.children]
        boundary = "\n" if self.tag in BLOCK else ""
        return boundary + "".join(parts) + boundary


class Tree(HTMLParser):
    def __init__(self, raw):
        super().__init__(convert_charrefs=True)
        self.root = Node("root")
        self.stack = [self.root]
        try:
            self.feed(raw.decode("utf-8-sig"))
            self.close()
        except (UnicodeError, ValueError):
            raise ParseError("invalid_html_encoding") from None

    def handle_starttag(self, tag, attrs):
        node = Node(tag, dict(attrs))
        self.stack[-1].children.append(node)
        if tag not in VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        self.stack[-1].children.append(data)


def normalize(text):
    return "\n".join(line for part in text.splitlines() if (line := " ".join(part.split())))


def content_hash(body):
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def canonical_url(ntt_id):
    if not re.fullmatch(r"[0-9]+", str(ntt_id)):
        raise ParseError("invalid_id")
    return (
        BASE
        + "/kr/bbs/view.do?"
        + urlencode({"bbsId": "B0000133", "menuNo": "205020", "nttId": str(ntt_id)})
    )


def link_id(link):
    url = urlsplit(urljoin(BASE, link.strip()))
    query = parse_qs(url.query)
    if (
        url.scheme != "https"
        or url.netloc != "www.boho.or.kr"
        or url.path != "/kr/bbs/view.do"
        or query.get("bbsId") != ["B0000133"]
    ):
        raise ParseError("unexpected_article_link")
    values = query.get("nttId", [])
    if len(values) != 1:
        raise ParseError("missing_id")
    canonical_url(values[0])
    return values[0]


def iso_date(value):
    value = value.strip()
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError:
        try:
            return parsedate_to_datetime(value).date().isoformat()
        except (ValueError, TypeError, OverflowError):
            raise ParseError("invalid_date") from None


def metadata(ntt_id, title, published):
    title = " ".join(title.split())
    if not title:
        raise ParseError("missing_title")
    return {
        "url": canonical_url(ntt_id),
        "title": title,
        "date": iso_date(published),
        "nttId": ntt_id,
    }


def parse_rss(raw):
    try:
        tree = ET.fromstring(raw)
    except ET.ParseError:
        raise ParseError("invalid_rss") from None
    records = {}
    for item in tree.findall("./channel/item"):
        ntt_id = link_id(item.findtext("link", ""))
        records[ntt_id] = metadata(ntt_id, item.findtext("title", ""), item.findtext("pubDate", ""))
    if not records:
        raise ParseError("empty_rss")
    return list(records.values())


def parse_list(raw):
    records = {}
    for row in Tree(raw).root.find(tag="tr"):
        subject = row.find(tag="td", cls="sbj")
        if not subject:
            continue
        links = subject[0].find(tag="a")
        dates = row.find(tag="td", cls="date")
        if len(links) != 1 or len(dates) != 1:
            raise ParseError("invalid_list_row")
        ntt_id = link_id(links[0].attrs.get("href", ""))
        records[ntt_id] = metadata(ntt_id, links[0].text(), dates[0].text())
    if not records:
        raise ParseError("empty_list")
    return list(records.values())


def parse_detail(raw):
    tree = Tree(raw).root
    titles = tree.find(cls="b_title")
    bodies = tree.find(cls="content_html")
    if len(titles) != 1 or len(bodies) != 1:
        raise ParseError("article_structure_changed")
    headings, dates = titles[0].find(tag="h2"), titles[0].find(tag="span")
    if len(headings) != 1 or len(dates) != 1:
        raise ParseError("article_metadata_changed")
    title = " ".join(headings[0].text().split())
    body = normalize(bodies[0].text())
    if not title or not body:
        raise ParseError("empty_article")
    return title, iso_date(dates[0].text()), body


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A login/challenge/host move needs human inspection, never automatic bypass.
        raise AccessDenied("redirect_requires_inspection")


class Client:
    def __init__(self, delay=1.5):
        if not 1 <= delay <= 2:
            raise KisaError("delay_must_be_1_to_2_seconds")
        self.delay = delay
        self.last_finished = None
        self.robots = None
        self.opener = build_opener(NoRedirect())

    def get(self, url):
        if self.robots is None:
            raw = self._request(BASE + "/robots.txt")
            self.robots = RobotFileParser()
            self.robots.parse(raw.decode("utf-8").splitlines())
        if not self.robots.can_fetch(USER_AGENT, url):
            raise AccessDenied("robots_disallow")
        requested_delay = self.robots.crawl_delay(USER_AGENT)
        rate = self.robots.request_rate(USER_AGENT)
        self.delay = max(
            self.delay, requested_delay or 0, rate.seconds / rate.requests if rate else 0
        )
        return self._request(url)

    def _request(self, url):
        if self.last_finished is not None:
            time.sleep(max(0, self.delay - (time.monotonic() - self.last_finished)))
        try:
            with self.opener.open(
                Request(url, headers={"User-Agent": USER_AGENT}), timeout=30
            ) as response:
                return response.read()
        except HTTPError as error:
            if error.code in {401, 403, 429}:
                raise AccessDenied(f"http_{error.code}") from None
            raise FetchError(f"http_{error.code}") from None
        except (URLError, TimeoutError, OSError):
            raise FetchError("network_error") from None
        finally:
            self.last_finished = time.monotonic()


def utc_now():
    return datetime.now(UTC).isoformat(timespec="seconds")


def write_file(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_bytes(data)
    temp.replace(path)


def write_json(path, data):
    write_file(path, (json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode())


def read_snapshot(root):
    fixture = root / "fixtures/kisa"
    manifest_path = fixture / "manifest.json"
    if not manifest_path.exists():
        if (fixture / "metadata.jsonl").exists():
            raise KisaError("metadata_without_manifest")
        return None, {}
    try:
        manifest = json.loads(manifest_path.read_text())
        records = [
            json.loads(line) for line in (fixture / "metadata.jsonl").read_text().splitlines()
        ]
        ids = manifest["target_ids"]
        docs = manifest["documents"]
        if (
            manifest["schema_version"] != 1
            or manifest["parser_version"] != PARSER_VERSION
            or not 50 <= len(ids) <= 100
            or len(set(ids)) != len(ids)
        ):
            raise ValueError
        for ntt_id in ids:
            canonical_url(ntt_id)
        if len(records) != len({r["nttId"] for r in records}):
            raise ValueError
        for row in records:
            if (
                set(row) != {"url", "title", "date", "nttId", "cve_ids"}
                or row["nttId"] not in ids
                or row["url"] != canonical_url(row["nttId"])
                or not row["title"]
                or iso_date(row["date"]) != row["date"]
                or not isinstance(row["cve_ids"], list)
                or any(not CVE.fullmatch(c) for c in row["cve_ids"])
            ):
                raise ValueError
        if {r["nttId"] for r in records} != {d["nttId"] for d in docs} or len(docs) != len(records):
            raise ValueError
        for doc in docs:
            if (
                set(doc) != {"nttId", "collected_at", "sha256", "parser_version"}
                or doc["parser_version"] != PARSER_VERSION
                or not re.fullmatch(r"[0-9a-f]{64}", doc["sha256"])
            ):
                raise ValueError
            datetime.fromisoformat(doc["collected_at"])
        return manifest, {r["nttId"]: r for r in records}
    except (OSError, ValueError, KeyError, TypeError, KisaError):
        raise KisaError("invalid_snapshot_or_parser_version") from None


def save_snapshot(root, manifest, records):
    fixture = root / "fixtures/kisa"
    rows = [records[i] for i in manifest["target_ids"] if i in records]
    write_file(
        fixture / "metadata.jsonl",
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows).encode(),
    )
    write_json(fixture / "manifest.json", manifest)


def load_cached_body(root, ntt_id, document):
    """Opt-in evaluation boundary: no network fallback and no body in errors."""
    canonical_url(ntt_id)
    path = root / "data/kisa" / ntt_id
    if not (path / "body.txt").is_file() or not (path / "source.html").is_file():
        raise KisaError(
            "cache_missing: run uv run python scripts/fetch_kisa.py --refresh; "
            "KISA evaluation requires a separate local cache"
        )
    try:
        body = (path / "body.txt").read_text(encoding="utf-8")
        _, _, reparsed = parse_detail((path / "source.html").read_bytes())
    except (OSError, UnicodeError, ParseError):
        raise KisaError("cache_invalid: restore with --refresh") from None
    if content_hash(body) != document["sha256"] or reparsed != body:
        raise KisaError("cache_hash_mismatch: restore with --refresh")
    return body


def discover(client, limit, report):
    records = {}
    # Always consult both sources; repeated pinned rows are de-duplicated by ID.
    sources = [("rss", RSS_URL, parse_rss)]
    sources += [
        (f"list_{page}", LIST_URL + f"&pageIndex={page}", parse_list) for page in range(1, 21)
    ]
    for name, url, parser in sources:
        try:
            rows = parser(client.get(url))
        except AccessDenied:
            report["failed"] += 1
            raise
        except (FetchError, ParseError) as error:
            report["parse_failed" if isinstance(error, ParseError) else "failed"] += 1
            print(f"discovery={name} error={error}")
            if report["failed"] + report["parse_failed"] >= 3:
                raise KisaError("three_acquisition_failures") from None
            continue
        before = len(records)
        records.update({row["nttId"]: row for row in rows})
        print(f"discovery={name} records={len(rows)} added={len(records) - before}")
        if name != "rss" and len(records) >= limit:
            return sorted(records, key=lambda i: (records[i]["date"], int(i)), reverse=True)[:limit]
    raise KisaError("insufficient_discovery_ids")


def run(args, root=ROOT, client=None):
    report = {
        "success": 0,
        "failed": 0,
        "parse_failed": 0,
        "new": 0,
        "cached": 0,
        "restored": 0,
        "unchanged": 0,
        "changed": 0,
        "metadata_changed": 0,
        "pending": 0,
    }
    exit_code = 0
    manifest, documents = None, {}
    try:
        manifest, records = read_snapshot(root)
        if manifest is None:
            if args.check_cache:
                raise KisaError("snapshot_missing: run uv run python scripts/fetch_kisa.py")
            client = client or Client(args.delay)
            ids = discover(client, args.limit, report)
            manifest = {
                "schema_version": 1,
                "parser_version": PARSER_VERSION,
                "collected_at": utc_now(),
                "target_ids": ids,
                "documents": [],
            }
            save_snapshot(root, manifest, records)
        documents = {d["nttId"]: d for d in manifest["documents"]}
        for ntt_id in manifest["target_ids"]:
            old = documents.get(ntt_id)
            cache = root / "data/kisa" / ntt_id
            try:
                if args.check_cache:
                    if old is None:
                        raise KisaError(
                            "incomplete_snapshot: run uv run python scripts/fetch_kisa.py"
                        )
                    load_cached_body(root, ntt_id, old)
                    report["cached"] += 1
                    continue
                if old and not args.refresh and (cache / "body.txt").exists():
                    load_cached_body(root, ntt_id, old)
                    report["cached"] += 1
                    continue
                client = client or Client(args.delay)
                raw = client.get(canonical_url(ntt_id))
                title, published, body = parse_detail(raw)
                digest = content_hash(body)
                row = metadata(ntt_id, title, published) | {
                    "cve_ids": sorted(set(CVE.findall(body.upper())))
                }
                if old and (digest != old["sha256"] or row != records[ntt_id]):
                    report["changed" if digest != old["sha256"] else "metadata_changed"] += 1
                    write_file(cache / "observed.html", raw)
                    write_file(cache / "observed.txt", body.encode())
                    print(
                        f"nttId={ntt_id} change_detected old_sha256={old['sha256']} new_sha256={digest}"
                    )
                    exit_code = 1
                    continue
                existed = (cache / "body.txt").exists()
                write_file(cache / "source.html", raw)
                write_file(cache / "body.txt", body.encode())
                if old:
                    report["unchanged" if existed else "restored"] += 1
                else:
                    report["new"] += 1
                    documents[ntt_id] = {
                        "nttId": ntt_id,
                        "collected_at": utc_now(),
                        "sha256": digest,
                        "parser_version": PARSER_VERSION,
                    }
                    records[ntt_id] = row
                    manifest["documents"] = [
                        documents[i] for i in manifest["target_ids"] if i in documents
                    ]
                    save_snapshot(root, manifest, records)
                report["success"] += 1
            except AccessDenied:
                report["failed"] += 1
                raise
            except (ParseError, FetchError) as error:
                report["parse_failed" if isinstance(error, ParseError) else "failed"] += 1
                print(f"nttId={ntt_id} error={error}")
                exit_code = 1
                if report["failed"] + report["parse_failed"] >= 3:
                    raise KisaError("three_acquisition_failures") from None
            except KisaError:
                report["failed"] += 1
                raise
        report["pending"] = len(manifest["target_ids"]) - len(documents)
    except (KisaError, OSError, UnicodeError) as error:
        # Never interpolate arbitrary exception details, which can contain response data.
        print(f"error={error if isinstance(error, KisaError) else type(error).__name__}")
        if not report["failed"] and not report["parse_failed"]:
            report["failed"] += 1
        exit_code = 1
    finally:
        if manifest is not None:
            report["pending"] = len(manifest["target_ids"]) - len(documents)
        print("report " + " ".join(f"{key}={value}" for key, value in report.items()))
    return exit_code or int(bool(report["failed"] or report["parse_failed"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--limit",
        type=int,
        choices=range(50, 101),
        default=50,
        metavar="50..100",
        help="initial discovery only; existing manifest freezes IDs",
    )
    parser.add_argument("--delay", type=float, default=1.5, help="1 to 2 seconds between requests")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--refresh", action="store_true", help="re-fetch frozen IDs; reject drift")
    mode.add_argument(
        "--check-cache", action="store_true", help="offline KISA evaluation preflight"
    )
    args = parser.parse_args()
    if not 1 <= args.delay <= 2:
        parser.error("--delay must be between 1 and 2 seconds")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())

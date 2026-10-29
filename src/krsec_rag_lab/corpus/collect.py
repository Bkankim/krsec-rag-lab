"""KISA 보안공지 게시판 전체 수집기와 계측. 응답·본문 텍스트는 어디에도 출력하지 않는다.

요청은 전부 `scripts/fetch_kisa.py`의 `Client`(robots, 1~2초 간격, 리다이렉트 거부)로만 보낸다.
본문은 `<cache-root>/data/kisa_full/<nttId>/{source.html,body.txt}`에만 쓰고, 커밋 대상은
메타데이터 인덱스·manifest·보고서다. 규칙의 정본은 이슈 #58과 docs/m4-collection.md다.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SCHEMA_VERSION = 1
CACHE_SUBDIR = Path("data/kisa_full")
CONSECUTIVE_LIMIT = 3
MAX_LIST_PAGES = 5000
SAVE_EVERY = 25
PROGRESS_EVERY = 100
# 목록 끝 판정에 쓰는 "정상 게시판 목록 구조": 목록 표와 페이지 영역이 모두 있어야 한다.
PAGING_CLASSES = {"pagination", "paging"}
TOTAL_PATTERN = re.compile(r"총\s*(?:게시물\s*)?(?:수\s*)?[:：]?\s*([0-9][0-9,]*)\s*건")
METADATA_KEYS = ("url", "title", "date", "nttId", "cve_ids")
TERMINAL_PREFIXES = ("parse_failed:", "fetch_failed:")


def load_kisa_module():
    """scripts/fetch_kisa.py를 모듈로 읽는다(실행하지 않는다)."""
    if "fetch_kisa" in sys.modules:
        return sys.modules["fetch_kisa"]
    spec = importlib.util.spec_from_file_location("fetch_kisa", ROOT / "scripts" / "fetch_kisa.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


kisa = load_kisa_module()


class Aborted(Exception):
    """수집을 즉시 멈춘다. 메시지는 고정 reason code만 담는다."""


@dataclass
class Discovery:
    ids: set = field(default_factory=set)
    pages: int = 0
    pages_with_rows: int = 0
    rows: int = 0
    in_page_duplicates: int = 0
    page_hits: Counter = field(default_factory=Counter)
    row_hits: Counter = field(default_factory=Counter)
    variants: dict = field(default_factory=dict)
    displayed_total: int | None = None
    complete: bool = False
    error: str | None = None


class Fetcher:
    """Client 요청을 종류별로 센다."""

    def __init__(self, client):
        self.client = client
        self.counts = Counter()

    def __call__(self, kind, url):
        self.counts[kind] += 1
        return self.client.get(url)

    def requests(self):
        robots = 1 if getattr(self.client, "robots", None) is not None else 0
        counts = {kind: self.counts[kind] for kind in ("rss", "list", "detail")}
        counts["robots"] = robots
        counts["total"] = sum(counts.values())
        return counts


def by_id(ids):
    return sorted(ids, key=int)


def raw_list_rows(raw):
    """페이지의 원시 `td.sbj` 행을 접지 않고 (nttId, 제목, 날짜) 순서대로 돌려준다.

    `parse_list`는 같은 nttId를 dict로 접어 페이지 안 중복을 지우므로 중복 계측은 이 함수로 한다.
    """
    rows = []
    for row in kisa.Tree(raw).root.find(tag="tr"):
        subject = row.find(tag="td", cls="sbj")
        if not subject:
            continue
        links = subject[0].find(tag="a")
        dates = row.find(tag="td", cls="date")
        if len(links) != 1 or len(dates) != 1:
            raise kisa.ParseError("invalid_list_row")
        ntt_id = kisa.link_id(links[0].attrs.get("href", ""))
        rows.append((ntt_id, " ".join(links[0].text().split()), dates[0].text().strip()))
    return rows


def has_board_structure(raw):
    root = kisa.Tree(raw).root
    paging = any(
        PAGING_CLASSES & set((node.attrs.get("class") or "").split()) for node in root.find()
    )
    return bool(root.find(tag="table")) and paging


def displayed_total(raw):
    match = TOTAL_PATTERN.search(kisa.Tree(raw).root.text())
    return int(match.group(1).replace(",", "")) if match else None


def list_url(page):
    return f"{kisa.LIST_URL}&pageIndex={page}"


def walk_list(fetch, frozen=None):
    """목록을 1쪽부터 넘기며 nttId를 모은다.

    끝 조건: 정상 구조의 빈 목록, 새 ID 0건 페이지가 연속 2쪽. `frozen`(이미 고정된 ID 집합)을 주면
    고정 집합 안의 ID만 있는 첫 페이지에서 끝낸다(새 글은 앞쪽 페이지에 나온다).
    """
    found = Discovery()
    stale = failures = 0
    page = 1
    while page <= MAX_LIST_PAGES:
        try:
            raw = fetch("list", list_url(page))
        except kisa.AccessDenied:
            raise
        except kisa.FetchError:
            failures += 1
            if failures >= CONSECUTIVE_LIMIT:
                raise Aborted("three_consecutive_failures") from None
            continue
        failures = 0
        found.pages += 1
        try:
            parsed = kisa.parse_list(raw)
            rows = raw_list_rows(raw)
        except kisa.ParseError as error:
            if str(error) != "empty_list":
                found.error = str(error)
            elif has_board_structure(raw):
                found.complete = True
            else:
                found.error = "list_structure_missing"
            return found
        if page == 1:
            found.displayed_total = displayed_total(raw)
        page_ids = {row["nttId"] for row in parsed}
        found.pages_with_rows += 1
        found.rows += len(rows)
        found.in_page_duplicates += len(rows) - len(page_ids)
        for ntt_id, title, date in rows:
            found.row_hits[ntt_id] += 1
            found.variants.setdefault(ntt_id, set()).add((title, date))
        for ntt_id in page_ids:
            found.page_hits[ntt_id] += 1
        new = page_ids - found.ids
        found.ids |= page_ids
        stale = 0 if new else stale + 1
        if (frozen is not None and page_ids <= frozen) or stale >= 2:
            found.complete = True
            return found
        page += 1
    found.error = "page_limit"
    return found


def read_rss(fetch):
    try:
        ids = [row["nttId"] for row in kisa.parse_rss(fetch("rss", kisa.RSS_URL))]
    except kisa.AccessDenied:
        raise
    except (kisa.FetchError, kisa.ParseError) as error:
        return None, str(error)
    return ids, None


def discovery_stats(found, rss_ids, rss_error):
    rss_only = by_id(set(rss_ids or []) - found.ids)
    across = sum(count - 1 for count in found.page_hits.values())
    return {
        "list_pages": found.pages,
        "list_pages_with_rows": found.pages_with_rows,
        "list_rows": found.rows,
        "displayed_total": found.displayed_total,
        "list_duplicate_in_page": found.in_page_duplicates,
        "list_duplicate_across_pages": across,
        "list_duplicate_ids": by_id(i for i, count in found.row_hits.items() if count > 1),
        "list_conflict_ids": by_id(i for i, seen in found.variants.items() if len(seen) > 1),
        "rss_ids": None if rss_ids is None else len(rss_ids),
        "rss_only_ids": rss_only,
        "rss_error": rss_error,
    }


def row_from(ntt_id, title, published, body):
    return kisa.metadata(ntt_id, title, published) | {
        "cve_ids": sorted(set(kisa.CVE.findall(body.upper())))
    }


def read_cache(cache, ntt_id, sha256):
    """캐시가 있고 해시·재파싱이 맞을 때만 메타데이터 행을 돌려준다(아니면 None)."""
    path = cache / ntt_id
    try:
        body = (path / "body.txt").read_text(encoding="utf-8")
        title, published, reparsed = kisa.parse_detail((path / "source.html").read_bytes())
        if kisa.content_hash(body) != sha256 or reparsed != body:
            return None
        return row_from(ntt_id, title, published, body)
    except (OSError, UnicodeError, kisa.ParseError):
        return None


def permanent_http(code):
    return bool(re.fullmatch(r"http_4[0-9]{2}", code)) and code not in {"http_403", "http_429"}


def new_manifest(started):
    return {
        "schema_version": SCHEMA_VERSION,
        "parser_version": kisa.PARSER_VERSION,
        "started_at": started,
        "finished_at": started,
        "discovery_complete": False,
        "complete": False,
        "target_ids": [],
        "discovery": {},
        "documents": [],
    }


def load_manifest(fixtures_dir):
    path = fixtures_dir / "manifest.json"
    if not path.exists():
        return None
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if (
            manifest["schema_version"] != SCHEMA_VERSION
            or manifest["parser_version"] != kisa.PARSER_VERSION
            or not isinstance(manifest["target_ids"], list)
            or not isinstance(manifest["documents"], list)
            or not isinstance(manifest["discovery"], dict)
        ):
            raise ValueError
        for doc in manifest["documents"]:
            kisa.canonical_url(doc["nttId"])
            if doc["result"] != "ok" and not doc["result"].startswith(TERMINAL_PREFIXES):
                raise ValueError
        return manifest
    except (OSError, ValueError, KeyError, TypeError, AttributeError, kisa.KisaError):
        raise kisa.KisaError("invalid_manifest") from None


def load_metadata(fixtures_dir):
    path = fixtures_dir / "metadata.jsonl"
    if not path.exists():
        return {}
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        return {row["nttId"]: row for row in rows}
    except (OSError, ValueError, KeyError, TypeError):
        raise kisa.KisaError("invalid_metadata") from None


def save_outputs(fixtures_dir, manifest, docs, rows):
    manifest["documents"] = [docs[i] for i in by_id(docs)]
    ok_rows = [rows[i] for i in by_id(docs) if docs[i]["result"] == "ok" and i in rows]
    kisa.write_file(
        fixtures_dir / "metadata.jsonl",
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in ok_rows).encode(),
    )
    kisa.write_json(fixtures_dir / "manifest.json", manifest)


def failure_entry(ntt_id, result):
    return {"nttId": ntt_id, "collected_at": kisa.utc_now(), "sha256": None, "result": result}


def collect_details(fetch, cache, manifest, docs, rows, save, retry_failed, log):
    consecutive = since_save = handled = 0
    if retry_failed:
        for ntt_id in [i for i, doc in docs.items() if doc["result"] != "ok"]:
            del docs[ntt_id]
    total = len(manifest["target_ids"])
    for index, ntt_id in enumerate(manifest["target_ids"], 1):
        old = docs.get(ntt_id)
        if old is not None:
            if old["result"] != "ok":
                continue  # 종결 결과: --retry-failed 없이는 다시 받지 않는다
            row = read_cache(cache, ntt_id, old["sha256"])
            if row is not None:
                rows[ntt_id] = row
                continue
            docs.pop(ntt_id)  # 캐시 없음·해시 불일치: 다시 받아 복구한다
            rows.pop(ntt_id, None)
        try:
            raw = fetch("detail", kisa.canonical_url(ntt_id))
        except kisa.AccessDenied:
            raise
        except kisa.FetchError as error:
            code = str(error)
            consecutive += 1
            log(f"detail nttId={ntt_id} fetch_error={code}")
            if permanent_http(code):
                docs[ntt_id] = failure_entry(ntt_id, f"fetch_failed:{code}")
            if consecutive >= CONSECUTIVE_LIMIT:
                raise Aborted("three_consecutive_failures") from None
            continue
        consecutive = 0
        try:
            title, published, body = kisa.parse_detail(raw)
            row = row_from(ntt_id, title, published, body)
        except kisa.ParseError as error:
            docs[ntt_id] = failure_entry(ntt_id, f"parse_failed:{error}")
            log(f"detail nttId={ntt_id} parse_error={error}")
            continue
        digest = kisa.content_hash(body)
        kisa.write_file(cache / ntt_id / "source.html", raw)
        kisa.write_file(cache / ntt_id / "body.txt", body.encode())
        docs[ntt_id] = {
            "nttId": ntt_id,
            "collected_at": kisa.utc_now(),
            "sha256": digest,
            "result": "ok",
        }
        rows[ntt_id] = row
        handled += 1
        since_save += 1
        if since_save >= SAVE_EVERY:
            save()
            since_save = 0
        if handled % PROGRESS_EVERY == 0:
            log(f"progress detail={index}/{total} fetched={handled}")


def build_report(manifest, docs, run_info, fixed_manifest, extra):
    target = list(manifest["target_ids"])
    stats = manifest["discovery"]
    ok = {i: d for i, d in docs.items() if d["result"] == "ok"}
    failed = Counter()
    failed_ids = {}
    for ntt_id in by_id(docs):
        result = docs[ntt_id]["result"]
        if result != "ok":
            failed[result] += 1
            failed_ids.setdefault(result, []).append(ntt_id)
    groups = {}
    for ntt_id in by_id(ok):
        groups.setdefault(ok[ntt_id]["sha256"], []).append(ntt_id)
    duplicate_groups = [{"sha256": h, "ids": ids} for h, ids in groups.items() if len(ids) > 1]
    duplicate_groups.sort(key=lambda g: int(g["ids"][0]))
    gap = None
    if stats.get("displayed_total") is not None:
        gap = stats["displayed_total"] - len(target)
    report = {
        "schema_version": SCHEMA_VERSION,
        "parser_version": kisa.PARSER_VERSION,
        "discovery_complete": manifest["discovery_complete"],
        "complete": manifest["complete"],
        "discovered_ids": len(target),
        "list_pages": stats.get("list_pages"),
        "list_pages_with_rows": stats.get("list_pages_with_rows"),
        "list_rows": stats.get("list_rows"),
        "displayed_total": stats.get("displayed_total"),
        "displayed_total_gap": gap,
        "rss_ids": stats.get("rss_ids"),
        "rss_only_ids": stats.get("rss_only_ids", []),
        "rss_error": stats.get("rss_error"),
        "discovery_error": stats.get("error"),
        "list_duplicate_in_page": stats.get("list_duplicate_in_page"),
        "list_duplicate_across_pages": stats.get("list_duplicate_across_pages"),
        "list_duplicate_ids": stats.get("list_duplicate_ids", []),
        "list_conflict_ids": stats.get("list_conflict_ids", []),
        "detail_ok": len(ok),
        "detail_failed": {k: v for k, v in failed.items() if k.startswith("fetch_failed:")},
        "parse_failed": {k: v for k, v in failed.items() if k.startswith("parse_failed:")},
        "failed_ids": failed_ids,
        "detail_pending": len(target) - len(docs),
        "missing_ids": by_id(set(target) - set(ok)),
        "content_duplicate_group_count": len(duplicate_groups),
        "content_duplicate_doc_count": sum(len(g["ids"]) for g in duplicate_groups),
        "content_duplicate_groups": duplicate_groups,
    }
    report.update(fixed_report(fixed_manifest, ok))
    report.update(extra)
    report.update(run_info)
    return report


def fixed_report(path, ok):
    """고정 50건이 전체 코퍼스에 모두 있고 본문 sha256이 고정 manifest와 같은지 대조한다."""
    try:
        fixed = json.loads(path.read_text(encoding="utf-8"))
        expected = {d["nttId"]: d["sha256"] for d in fixed["documents"]}
        ids = [str(i) for i in fixed["target_ids"]]
    except (OSError, ValueError, KeyError, TypeError):
        return {
            "fixed_expected": None,
            "fixed_present": None,
            "fixed_missing_ids": None,
            "fixed_hash_match": None,
            "fixed_hash_mismatch_ids": None,
        }
    present = [i for i in ids if i in ok]
    return {
        "fixed_expected": len(ids),
        "fixed_present": len(present),
        "fixed_missing_ids": by_id(set(ids) - set(present)),
        "fixed_hash_match": sum(ok[i]["sha256"] == expected.get(i) for i in present),
        "fixed_hash_mismatch_ids": by_id(i for i in present if ok[i]["sha256"] != expected.get(i)),
    }


def collect(
    cache_root, fixtures_dir, results_dir, fixed_manifest, client, retry_failed=False, log=print
):
    """수집 1회(또는 재개/재실행). exit code를 돌려준다."""
    clock = time.monotonic()
    started = kisa.utc_now()
    fetch = Fetcher(client)
    cache = cache_root / CACHE_SUBDIR
    manifest = load_manifest(fixtures_dir)
    resumed = manifest is not None
    rows = load_metadata(fixtures_dir)
    docs = {d["nttId"]: d for d in manifest["documents"]} if manifest else {}
    abort = None
    extra = {"new_since_freeze": [], "rediscovery_pages": None, "rediscovery_complete": None}
    if manifest is None:
        manifest = new_manifest(started)
    elif not manifest["discovery_complete"]:
        manifest = new_manifest(manifest["started_at"])
        docs = {}

    def save():
        save_outputs(fixtures_dir, manifest, docs, rows)

    try:
        if not manifest["discovery_complete"]:
            found = walk_list(fetch)
            rss_ids, rss_error = read_rss(fetch) if found.complete else (None, None)
            stats = discovery_stats(found, rss_ids, rss_error)
            stats["error"] = found.error
            manifest["discovery"] = stats
            if found.complete:
                manifest["discovery_complete"] = True
                manifest["target_ids"] = by_id(found.ids)
            log(f"discovery pages={found.pages} ids={len(found.ids)} complete={found.complete}")
            save()
        else:
            known = set(manifest["target_ids"])
            found = walk_list(fetch, known)
            extra["new_since_freeze"] = by_id(found.ids - known)
            extra["rediscovery_pages"] = found.pages
            extra["rediscovery_complete"] = found.complete
            log(f"rediscovery pages={found.pages} new={len(extra['new_since_freeze'])}")
        if manifest["discovery_complete"]:
            collect_details(fetch, cache, manifest, docs, rows, save, retry_failed, log)
    except kisa.AccessDenied as error:
        abort = str(error)
    except Aborted as error:
        abort = str(error)
    finally:
        done = manifest["discovery_complete"] and all(i in docs for i in manifest["target_ids"])
        manifest["complete"] = bool(done)
        manifest["finished_at"] = kisa.utc_now()
        save()
        run_info = {
            "aborted": abort,
            "resumed": resumed,
            "retry_failed": retry_failed,
            "requests": fetch.requests(),
            "elapsed_seconds": round(time.monotonic() - clock, 1),
        }
        report = build_report(manifest, docs, run_info, fixed_manifest, extra)
        kisa.write_json(results_dir / "report.json", report)
    log(
        f"done complete={manifest['complete']} ok={report['detail_ok']} "
        f"requests={report['requests']['total']} aborted={abort}"
    )
    return 0 if manifest["complete"] and abort is None else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cache-root",
        type=Path,
        required=True,
        help="본문 캐시 루트. 캐시는 <cache-root>/data/kisa_full/ 아래에만 쓴다",
    )
    parser.add_argument("--delay", type=float, default=1.5, help="요청 간격 1~2초")
    parser.add_argument(
        "--retry-failed", action="store_true", help="기록된 파싱·영구 HTTP 실패 ID를 다시 받는다"
    )
    parser.add_argument("--fixtures-dir", type=Path, default=ROOT / "fixtures/kisa_full")
    parser.add_argument("--results-dir", type=Path, default=ROOT / "results/m4/collection")
    parser.add_argument("--fixed-manifest", type=Path, default=ROOT / "fixtures/kisa/manifest.json")
    args = parser.parse_args(argv)
    if not 1 <= args.delay <= 2:
        parser.error("--delay must be between 1 and 2 seconds")
    try:
        return collect(
            args.cache_root,
            args.fixtures_dir,
            args.results_dir,
            args.fixed_manifest,
            kisa.Client(args.delay),
            args.retry_failed,
            log=lambda message: print(message, flush=True),
        )
    except (kisa.KisaError, OSError, UnicodeError) as error:
        # 임의 예외 문자열에는 응답·경로가 섞일 수 있다.
        print(f"error={error if isinstance(error, kisa.KisaError) else type(error).__name__}")
        return 1

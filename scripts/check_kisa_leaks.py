"""Audit cached KISA body samples without displaying restricted text.

Patterns reach ``git grep -I -F`` only through stdin. Its ``-c -h`` output
contains counts, never matching lines or filenames. The report includes only
pattern hashes. This is a sample-based check, not proof against every possible
transformation or excerpt of a cached body.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

METADATA_FIELDS = {"url", "title", "date", "nttId", "cve_ids"}
CACHE_PATH = "data/kisa"
METADATA_PATH = "fixtures/kisa/metadata.jsonl"
MIN_PATTERN_LENGTH = 32


class AuditError(Exception):
    """An error whose fixed message is safe to display."""


def git(repo: Path, *arguments: str, input_text: str | None = None) -> subprocess.CompletedProcess:
    # Never use check=True: CalledProcessError can expose command arguments.
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        input=input_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode not in (0, 1):
        raise AuditError("git_command_failed")
    return result


def metadata_values(repo: Path) -> list[str]:
    path = repo / METADATA_PATH
    if not path.is_file():
        raise AuditError("metadata_missing")
    values: list[str] = []
    rows = path.read_text(encoding="utf-8").splitlines()
    if not rows:
        raise AuditError("metadata_empty")
    for line in rows:
        record = json.loads(line)
        if not isinstance(record, dict) or set(record) != METADATA_FIELDS:
            raise AuditError("metadata_fields_not_allowlisted")
        for key in ("url", "title", "date", "nttId"):
            value = record[key]
            if key == "nttId" and isinstance(value, int):
                value = str(value)
            if not isinstance(value, str):
                raise AuditError("metadata_value_invalid")
            values.append(value)
        if not isinstance(record["cve_ids"], list) or not all(
            isinstance(value, str) for value in record["cve_ids"]
        ):
            raise AuditError("metadata_value_invalid")
        values.extend(record["cve_ids"])
    return values


def candidates(body: str):
    """Yield exact single-line spans, longer spans first, with no normalization."""
    for length in (64, MIN_PATTERN_LENGTH):
        for line in body.splitlines():
            if len(line) < length or re.match(r"\s*https?://", line):
                continue
            for start in range(0, len(line) - length + 1, 8):
                candidate = line[start : start + length]
                if "\x00" not in candidate and sum(char.isalpha() for char in candidate) >= 12:
                    yield candidate


def select_patterns(bodies: list[str], allowed: list[str]) -> list[str]:
    """Select at most one body-only span from each distinct document."""
    patterns: list[str] = []
    for body in bodies:
        for candidate in candidates(body):
            if any(candidate in value for value in allowed):
                continue
            if sum(candidate in other for other in bodies) != 1:
                continue
            patterns.append(candidate)
            break
    if len(patterns) < 3:
        raise AuditError("fewer_than_three_distinct_body_only_patterns")
    return patterns


def match_count(repo: Path, pattern: str, *, cached: bool) -> int:
    arguments = ["grep", "-I", "-F", "-c", "-h", "--no-color"]
    if cached:
        arguments.append("--cached")
    result = git(repo, *arguments, "-f", "-", "--", ".", input_text=pattern + "\n")
    # -c -h emits only an integer per matching file, not the matched text.
    counts = result.stdout.splitlines()
    if any(not value.isascii() or not value.isdigit() for value in counts):
        raise AuditError("git_count_output_invalid")
    total = sum(int(value) for value in counts)
    if (result.returncode == 0) != (total > 0):
        raise AuditError("git_count_status_invalid")
    return total


def pattern_variants(pattern: str) -> set[str]:
    # Notebook/JSON outputs may encode Korean as Unicode escapes, or escape quotes.
    # Search those exact serializations as well as the literal cached body span.
    return {
        pattern,
        json.dumps(pattern, ensure_ascii=True)[1:-1],
        json.dumps(pattern, ensure_ascii=False)[1:-1],
    }


def audit(repo: Path) -> dict:
    tracked = git(repo, "ls-files", "-z", "--", CACHE_PATH)
    if tracked.returncode != 0:
        raise AuditError("cache_tracking_check_failed")
    if tracked.stdout:
        raise AuditError("cache_is_tracked")
    cache = repo / CACHE_PATH
    paths = sorted(path for path in cache.glob("*/body.txt") if path.parent.name.isdecimal())
    if not paths:
        raise AuditError("cache_missing_run_fetch_kisa_separately")
    for path in paths:
        ignored = git(repo, "check-ignore", "-q", "--", path.relative_to(repo).as_posix())
        if ignored.returncode != 0:
            raise AuditError("cache_not_ignored")
    status = git(repo, "status", "--short", "--ignored", "--", CACHE_PATH)
    expected_status = f"!! {CACHE_PATH}/"
    if status.returncode != 0 or status.stdout.strip() != expected_status:
        raise AuditError("cache_ignore_status_unexpected")
    allowed = metadata_values(repo)
    bodies = [path.read_text(encoding="utf-8") for path in paths]
    patterns = select_patterns(bodies, allowed)
    checks = []
    for pattern in patterns:
        checks.append(
            {
                "pattern_sha256": hashlib.sha256(pattern.encode("utf-8")).hexdigest(),
                "tracked_matches": sum(
                    match_count(repo, variant, cached=False)
                    for variant in pattern_variants(pattern)
                ),
                "staged_matches": sum(
                    match_count(repo, variant, cached=True) for variant in pattern_variants(pattern)
                ),
            }
        )
    total = sum(check["tracked_matches"] + check["staged_matches"] for check in checks)
    return {
        "audit": "pass" if total == 0 else "fail",
        "scope": "distinctive_body_samples_in_tracked_worktree_and_index",
        "cache_documents": len(bodies),
        "sampled_documents": len(patterns),
        "cache_git_status": expected_status,
        "cache_tracked_files": 0,
        "checks": checks,
        "total_matches": total,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        report = audit(args.repo.resolve())
    except AuditError as exc:
        report = {"audit": "fail", "error": str(exc)}
    except (OSError, ValueError, TypeError):
        # Parsing/IO exceptions can embed body text, paths, or offending input.
        report = {"audit": "fail", "error": "input_or_process_error"}
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if report["audit"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())

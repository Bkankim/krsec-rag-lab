"""Offline check that fixtures/nvd kept every pre-existing field of a base commit unchanged.

Usage: uv run python scripts/check_nvd_fields.py <base-commit>

Compares fixtures/nvd/cves.jsonl in the working tree with `git show <base>:fixtures/nvd/cves.jsonl`
record by record (every key the base record had must have the same value), then checks that
kev.json is byte-identical and manifest coverage / not_found are unchanged. Needs full git
history of <base>, so it is not part of pytest (CI clones shallow). Exit 0 only when all match.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADDED_KEYS = ("vendor_products", "vendor_products_status")


def git_show(base, path):
    result = subprocess.run(
        ["git", "show", f"{base}:{path}"], cwd=ROOT, capture_output=True, check=False
    )
    if result.returncode:
        raise SystemExit(f"git show {base}:{path} failed (exit {result.returncode})")
    return result.stdout


def rows_of(data):
    return {row["id"]: row for row in map(json.loads, data.decode("utf-8").splitlines())}


def main(argv):
    if len(argv) != 2:
        raise SystemExit("usage: check_nvd_fields.py <base-commit>")
    base = argv[1]
    old = rows_of(git_show(base, "fixtures/nvd/cves.jsonl"))
    new = rows_of((ROOT / "fixtures/nvd/cves.jsonl").read_bytes())
    problems = []
    if set(old) != set(new):
        problems.append(
            f"ids: only_base={len(set(old) - set(new))} only_now={len(set(new) - set(old))}"
        )
    changed = 0
    for cve_id in sorted(set(old) & set(new)):
        diff = sorted(k for k, v in old[cve_id].items() if new[cve_id].get(k, KeyError) != v)
        if diff:
            changed += 1
            problems.append(f"{cve_id}: changed {','.join(diff)}")
    added = sum(all(k in row for k in ADDED_KEYS) for row in new.values())
    if added != len(new):
        problems.append(f"added fields missing on {len(new) - added} records")
    fixture = ROOT / "fixtures/nvd"
    if git_show(base, "fixtures/nvd/kev.json") != (fixture / "kev.json").read_bytes():
        problems.append("kev.json differs from base")
    old_manifest = json.loads(git_show(base, "fixtures/nvd/manifest.json"))
    manifest = json.loads((fixture / "manifest.json").read_text(encoding="utf-8"))
    for key in ("coverage", "not_found"):
        if old_manifest[key] != manifest[key]:
            problems.append(f"manifest {key} differs from base")
    print(
        f"base={base} base_records={len(old)} records={len(new)} "
        f"existing_fields_changed={changed} records_with_added_fields={added} "
        f"kev_json_identical={'kev.json differs from base' not in problems} "
        f"manifest_coverage_not_found_identical="
        f"{not any(p.startswith('manifest') for p in problems)}"
    )
    for problem in problems:
        print(f"FAIL {problem}")
    print("OK" if not problems else "FAILED")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

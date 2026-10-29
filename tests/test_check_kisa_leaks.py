"""Leak-audit integration tests use authored synthetic text only."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_kisa_leaks.py"
SYNTHETIC_BODIES = [
    "Synthetic amber observatory calibration passage created solely for a local audit test.",
    "Synthetic blue marmalade inventory passage created solely for a local audit test.",
    "Synthetic copper telescope alignment passage created solely for a local audit test.",
]


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("/data/*\n", encoding="utf-8")
    metadata = tmp_path / "fixtures" / "kisa" / "metadata.jsonl"
    metadata.parent.mkdir(parents=True)
    rows = []
    for index, body in enumerate(SYNTHETIC_BODIES, 1):
        folder = tmp_path / "data" / "kisa" / str(index)
        folder.mkdir(parents=True)
        (folder / "body.txt").write_text(body, encoding="utf-8")
        (folder / "source.html").write_text("<p>" + body + "</p>", encoding="utf-8")
        rows.append(
            {
                "url": f"https://example.invalid/notice/{index}",
                "title": f"Synthetic fixture {index}",
                "date": "2026-01-01",
                "nttId": str(index),
                "cve_ids": [],
            }
        )
    metadata.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    (tmp_path / "notes.txt").write_text("Clean synthetic test notes.\n", encoding="utf-8")
    git(tmp_path, "add", ".gitignore", "fixtures", "notes.txt")
    return tmp_path


def run_audit(repo: Path, *extra: str):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--repo", str(repo), *extra],
        capture_output=True,
        text=True,
        check=False,
    )
    # The script must never reveal a sampled body, including on its failure path.
    for body in SYNTHETIC_BODIES:
        assert body[:32] not in result.stdout + result.stderr
    assert result.stderr == ""
    return result.returncode, json.loads(result.stdout)


def test_clean_cache_is_ignored_and_checks_both_git_views(repo):
    code, report = run_audit(repo)
    assert code == 0
    assert report["audit"] == "pass"
    assert report["cache_documents"] == report["sampled_documents"] == 3
    assert report["cache_git_status"] == "!! data/kisa/"
    assert report["cache_tracked_files"] == report["total_matches"] == 0
    assert len({check["pattern_sha256"] for check in report["checks"]}) == 3
    assert all(len(check["pattern_sha256"]) == 64 for check in report["checks"])


@pytest.mark.parametrize("staged", [False, True])
def test_reports_worktree_and_staged_only_leaks_without_showing_text(repo, staged):
    notes = repo / "notes.txt"
    notes.write_text(SYNTHETIC_BODIES[0], encoding="utf-8")
    if staged:
        git(repo, "add", "notes.txt")
        notes.write_text("Clean working tree but leaked text remains staged.\n", encoding="utf-8")
    code, report = run_audit(repo)
    assert code == 1
    assert report["audit"] == "fail"
    assert report["total_matches"] == 1
    assert report["checks"][0]["staged_matches" if staged else "tracked_matches"] == 1


def test_rejects_tracked_cache(repo):
    git(repo, "add", "-f", "data/kisa/1/body.txt")
    code, report = run_audit(repo)
    assert code == 1
    assert report["error"] == "cache_is_tracked"


def test_rejects_missing_cache(repo):
    for path in (repo / "data" / "kisa").glob("*/body.txt"):
        path.unlink()
    code, report = run_audit(repo)
    assert code == 1
    assert report["error"] == "cache_missing_run_fetch_kisa_separately"


def test_rejects_cache_that_is_not_ignored(repo):
    (repo / ".gitignore").write_text("", encoding="utf-8")
    code, report = run_audit(repo)
    assert code == 1
    assert report["error"] == "cache_not_ignored"


def test_does_not_select_allowed_title_text_as_body_evidence(repo):
    path = repo / "fixtures" / "kisa" / "metadata.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    for row, body in zip(rows, SYNTHETIC_BODIES, strict=True):
        row["title"] = body
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    code, report = run_audit(repo)
    assert code == 1
    assert report["error"] == "fewer_than_three_distinct_body_only_patterns"


def test_rejects_metadata_with_body_field_without_echoing_it(repo):
    path = repo / "fixtures" / "kisa" / "metadata.jsonl"
    row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    row["body"] = SYNTHETIC_BODIES[0]
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    code, report = run_audit(repo)
    assert code == 1
    assert report["error"] == "metadata_fields_not_allowlisted"


def test_malformed_json_error_does_not_echo_input(repo):
    path = repo / "fixtures" / "kisa" / "metadata.jsonl"
    path.write_text(SYNTHETIC_BODIES[0], encoding="utf-8")
    code, report = run_audit(repo)
    assert code == 1
    assert report["error"] == "input_or_process_error"


def test_discovery_probe_is_not_treated_as_a_document(repo):
    probe = repo / "data" / "kisa" / "probe"
    probe.mkdir()
    (probe / "body.txt").write_text(SYNTHETIC_BODIES[0], encoding="utf-8")
    code, report = run_audit(repo)
    assert code == 0
    assert report["cache_documents"] == 3


def test_detects_json_escaped_korean_in_notebook_output(repo):
    # Authored synthetic Korean content, not copied from any KISA document.
    body = "이 문장은 보안 공지와 관계없는 합성 검사 자료이며 자주색 우주 정거장의 푸딩 재고를 설명합니다."
    (repo / "data" / "kisa" / "1" / "body.txt").write_text(body, encoding="utf-8")
    notebook = repo / "synthetic.ipynb"
    notebook.write_text(json.dumps({"cells": [{"outputs": [{"text": [body]}]}]}), encoding="utf-8")
    git(repo, "add", "synthetic.ipynb")
    code, report = run_audit(repo)
    assert code == 1
    assert report["audit"] == "fail"
    assert report["checks"][0]["tracked_matches"] == 1
    assert report["checks"][0]["staged_matches"] == 1
    assert body[:32] not in json.dumps(report, ensure_ascii=False)


FULL_ARGS = ("--cache", "data/kisa_full", "--metadata", "fixtures/kisa_full/metadata.jsonl")
FULL_BODIES = [
    "Synthetic violet lighthouse registry passage created solely for a local audit test.",
    "Synthetic yellow glacier ledger passage created solely for a local audit test.",
    "Synthetic green harbor almanac passage created solely for a local audit test.",
    "Synthetic silver canyon tideline passage created solely for a local audit test.",
]


def full_rows(count):
    return [
        {
            "url": f"https://example.invalid/notice/{index}",
            "title": f"Synthetic full corpus {index}",
            "date": "2026-01-01",
            "nttId": str(index),
            "cve_ids": [],
        }
        for index in range(1, count + 1)
    ]


@pytest.fixture
def full_repo(repo):
    """기본 repo에 전체 코퍼스 캐시(data/kisa_full)와 메타데이터를 더한다."""
    for index, body in enumerate(FULL_BODIES, 1):
        folder = repo / "data" / "kisa_full" / str(index)
        folder.mkdir(parents=True)
        (folder / "body.txt").write_text(body, encoding="utf-8")
    metadata = repo / "fixtures" / "kisa_full" / "metadata.jsonl"
    metadata.parent.mkdir(parents=True)
    metadata.write_text(
        "".join(json.dumps(row) + "\n" for row in full_rows(len(FULL_BODIES))), encoding="utf-8"
    )
    git(repo, "add", "fixtures")
    return repo


def test_new_options_audit_the_full_corpus_cache(full_repo):
    code, report = run_audit(full_repo, *FULL_ARGS)
    assert code == 0
    assert report["audit"] == "pass"
    assert report["cache_documents"] == report["sampled_documents"] == len(FULL_BODIES)
    assert report["cache_git_status"] == "!! data/kisa_full/"
    assert report["cache_tracked_files"] == report["total_matches"] == 0


@pytest.mark.parametrize("staged", [False, True])
def test_new_options_report_full_corpus_leaks_without_showing_text(full_repo, staged):
    notes = full_repo / "notes.txt"
    notes.write_text(FULL_BODIES[0], encoding="utf-8")
    if staged:
        git(full_repo, "add", "notes.txt")
        notes.write_text("Clean working tree but leaked text remains staged.\n", encoding="utf-8")
    code, report = run_audit(full_repo, *FULL_ARGS)
    assert code == 1
    assert report["audit"] == "fail"
    assert report["total_matches"] == 1
    assert report["checks"][0]["staged_matches" if staged else "tracked_matches"] == 1
    for body in FULL_BODIES:
        assert body[:32] not in json.dumps(report, ensure_ascii=False)


def test_new_options_do_not_read_the_default_cache(full_repo):
    for path in (full_repo / "data" / "kisa").glob("*/body.txt"):
        path.write_text(
            "Cache body that must be ignored by the full corpus audit.", encoding="utf-8"
        )
    code, report = run_audit(full_repo, *FULL_ARGS)
    assert code == 0
    assert report["cache_documents"] == len(FULL_BODIES)


def test_new_options_reject_tracked_or_unignored_full_cache(full_repo):
    git(full_repo, "add", "-f", "data/kisa_full/1/body.txt")
    code, report = run_audit(full_repo, *FULL_ARGS)
    assert (code, report["error"]) == (1, "cache_is_tracked")
    git(full_repo, "rm", "-q", "--cached", "data/kisa_full/1/body.txt")
    (full_repo / ".gitignore").write_text("", encoding="utf-8")
    code, report = run_audit(full_repo, *FULL_ARGS)
    assert (code, report["error"]) == (1, "cache_not_ignored")


def test_new_options_reject_missing_cache_and_metadata(full_repo):
    code, report = run_audit(full_repo, "--cache", "data/kisa_other", *FULL_ARGS[2:])
    assert (code, report["error"]) == (1, "cache_missing_run_fetch_kisa_separately")
    code, report = run_audit(full_repo, "--cache", "data/kisa_full", "--metadata", "no/such.jsonl")
    assert (code, report["error"]) == (1, "metadata_missing")


@pytest.mark.parametrize(
    "flag, value",
    [
        ("--cache", "/tmp/kisa"),
        ("--cache", "../kisa"),
        ("--cache", ""),
        ("--metadata", "/tmp/metadata.jsonl"),
        ("--metadata", "fixtures/../../metadata.jsonl"),
    ],
)
def test_new_options_reject_paths_outside_the_repo(repo, flag, value):
    code, report = run_audit(repo, flag, value)
    assert (code, report["error"]) == (1, "path_not_repo_relative")


def test_default_run_also_allows_full_corpus_metadata_values(full_repo):
    # 전체 코퍼스 메타데이터가 있으면 기본 점검도 그 값을 면제 목록에 더한다.
    path = full_repo / "fixtures" / "kisa_full" / "metadata.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    for row, body in zip(rows, SYNTHETIC_BODIES, strict=False):
        row["title"] = body
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    code, report = run_audit(full_repo)
    assert code == 1
    assert report["error"] == "fewer_than_three_distinct_body_only_patterns"


def test_default_output_is_unchanged_when_full_metadata_is_unrelated(full_repo):
    code, report = run_audit(full_repo)
    assert code == 0
    assert report["cache_git_status"] == "!! data/kisa/"
    assert report["cache_documents"] == report["sampled_documents"] == 3
    assert set(report) == {
        "audit",
        "scope",
        "cache_documents",
        "sampled_documents",
        "cache_git_status",
        "cache_tracked_files",
        "checks",
        "total_matches",
    }


def test_default_run_rejects_full_metadata_with_body_field(full_repo):
    path = full_repo / "fixtures" / "kisa_full" / "metadata.jsonl"
    row = full_rows(1)[0] | {"body": FULL_BODIES[0]}
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    code, report = run_audit(full_repo)
    assert code == 1
    assert report["error"] == "metadata_fields_not_allowlisted"

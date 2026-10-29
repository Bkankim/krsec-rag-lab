"""check_release.py 테스트 - asset 목록 검사(존재·필수·sha256·허용 필드·README 재계산)와 재현 결과 비교.

합성 리포에서 변조 행렬을 돌리고, 커밋된 리포의 릴리스 노트도 그대로 검사한다.
"""

import json
import re
import shutil

import pytest
from test_release_support import (
    ROOT,
    build_repo,
    read_jsonl,
    release,
    write_jsonl,
    write_note,
)

RESULTS = "results/baselines"


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    return build_repo(tmp_path_factory.mktemp("built"))


@pytest.fixture
def repo(built, tmp_path):
    copy = tmp_path / "repo"
    shutil.copytree(built, copy)
    return copy


def run(capsys, *args):
    code = release.main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def failed_checks(out):
    return {line[5:] for line in out.splitlines() if line.startswith("FAIL ")}


# ------------------------------------------------------------ 커밋된 리포


def test_committed_release_note_passes(capsys):
    code, out, _ = run(capsys)
    assert code == 0, out
    assert out.rstrip().endswith("check_release: OK")
    assert "FAIL" not in out


def test_committed_note_lists_every_allowed_asset_with_current_sha256():
    note = (ROOT / release.NOTE_PATH).read_text(encoding="utf-8")
    listed = release.parse_asset_table(note)
    expected = release.render_asset_table(ROOT, release.default_assets(ROOT))
    assert [r["path"] for r in listed] == [p for p in release.default_assets(ROOT)]
    assert note.count(expected.strip()) == 1


def test_committed_note_names_the_required_sections():
    note = (ROOT / release.NOTE_PATH).read_text(encoding="utf-8")
    assert re.search(r"^## 한계$", note, re.MULTILINE)
    assert re.search(r"^## asset$", note, re.MULTILINE)
    assert "LICENSES/README.md" in note and "check_kisa_leaks" in note
    for word in ("kappa", "unjudged", "excluded", "로컬 캐시", "교차 언어", "미검증"):
        assert word in note


def test_committed_docs_have_no_motive_words_or_dashes_or_personal_paths():
    for relative in ("README.md", "docs/release-v0.1.md"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert not re.search(r"면접|학습 목적|interview", text), relative
        assert "\u2014" not in text, relative  # em dash
        assert "/Users/" not in text, relative
    assert "단독 프로젝트" in (ROOT / "README.md").read_text(encoding="utf-8")


def test_readme_links_resolve():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for target in re.findall(r"\]\(((?:docs|eval|LICENSES|scripts)[^)#]*)", readme):
        assert (ROOT / target).exists(), target
    note = (ROOT / release.NOTE_PATH).read_text(encoding="utf-8")
    assert "docs/release-v0.1.md#한계" in readme
    assert "docs/baselines.md#6-해석할-때의-한계" in readme
    assert re.search(
        r"^## 6\. 해석할 때의 한계$", (ROOT / "docs/baselines.md").read_text("utf-8"), re.MULTILINE
    )
    assert "eval/golden/judge_manifest.json" in readme and "## 한계" in note


# ------------------------------------------------------------ 합성 리포: 통과


def test_synthetic_repo_passes(repo, capsys):
    code, out, _ = run(capsys, "--root", str(repo))
    assert code == 0, out
    assert out.count("OK  ") == 6


def test_print_assets_lists_files_in_path_order(repo, capsys):
    code, out, _ = run(capsys, "--root", str(repo), "--print-assets")
    rows = release.parse_asset_table(f"{release.BEGIN}\n{out}{release.END}")
    assert code == 0
    assert [r["path"] for r in rows] == sorted(r["path"] for r in rows)
    assert {r["name"] for r in rows} == {r["path"].replace("/", "__") for r in rows}
    assert "results__baselines__public__bm25.jsonl" in {r["name"] for r in rows}


# ------------------------------------------------------------ 합성 리포: 목록 변조


def note_text(repo):
    return (repo / release.NOTE_PATH).read_text(encoding="utf-8")


def edit_note(repo, change):
    path = repo / release.NOTE_PATH
    path.write_text(change(path.read_text(encoding="utf-8")), encoding="utf-8")


def row_of(repo, path):
    return next(line for line in note_text(repo).splitlines() if f"| `{path}` |" in line)


def drop_row(path):
    return lambda repo: edit_note(repo, lambda t: t.replace(row_of(repo, path) + "\n", ""))


def add_row(path):
    def add(repo):
        extra = row_of(repo, "eval/public/queries.jsonl").replace("eval/public/queries.jsonl", path)
        edit_note(repo, lambda t: t.replace(release.END, extra + "\n" + release.END))

    return add


def rename_asset(repo):
    row = row_of(repo, "eval/public/queries.jsonl")
    edit_note(
        repo, lambda t: t.replace(row, row.replace("`eval__public__queries.jsonl`", "`q.jsonl`"))
    )


def duplicate_row(repo):
    row = row_of(repo, "eval/public/queries.jsonl")
    edit_note(repo, lambda t: t.replace(row, row + "\n" + row))


def wrong_sha(repo):
    row = row_of(repo, "eval/public/queries.jsonl")
    sha = re.search(r"`([0-9a-f]{64})`", row).group(1)
    edit_note(repo, lambda t: t.replace(sha, "0" * 64))


def wrong_size(repo):
    row = row_of(repo, "eval/public/queries.jsonl")
    edit_note(repo, lambda t: t.replace(row, re.sub(r"\| \d+ \|", "| 1 |", row, count=1)))


def delete_listed_file(repo):
    (repo / "eval/public/manifest.json").unlink()


def change_file_after_listing(repo):
    with (repo / "eval/golden/agreement.json").open("a", encoding="utf-8") as handle:
        handle.write("\n")


LIST_TAMPER = {
    "file missing": (delete_listed_file, "listed assets exist and are allowed"),
    "path not allowed (README)": (add_row("README.md"), "listed assets exist and are allowed"),
    "path not allowed (cache)": (
        add_row("data/kisa/90001/body.txt"),
        "listed assets exist and are allowed",
    ),
    "path not allowed (judgments)": (
        add_row("eval/golden/judgments/A.jsonl"),
        "listed assets exist and are allowed",
    ),
    "asset name differs from path": (rename_asset, "listed assets exist and are allowed"),
    "duplicate row": (duplicate_row, "listed assets exist and are allowed"),
    "result file not listed": (
        drop_row("results/baselines/public/bm25.jsonl"),
        "manifest-required files are listed",
    ),
    "kisa result not listed": (
        drop_row("results/baselines/kisa/exact.jsonl"),
        "manifest-required files are listed",
    ),
    "queries not listed": (
        drop_row("eval/golden/golden_v1.jsonl"),
        "manifest-required files are listed",
    ),
    "manifest.json not listed": (
        drop_row("results/baselines/manifest.json"),
        "manifest-required files are listed",
    ),
    "listed sha256 wrong": (wrong_sha, "asset sha256 matches the repo files and manifest inputs"),
    "listed size wrong": (wrong_size, "asset sha256 matches the repo files and manifest inputs"),
    "repo file changed after listing": (
        change_file_after_listing,
        "asset sha256 matches the repo files and manifest inputs",
    ),
    "asset list markers removed": (
        lambda repo: edit_note(repo, lambda t: t.replace(release.BEGIN, "")),
        "asset list parses",
    ),
    "empty asset list": (
        lambda repo: edit_note(
            repo, lambda t: t[: t.index(release.BEGIN) + len(release.BEGIN)] + "\n" + release.END
        ),
        "asset list parses",
    ),
    "malformed row": (
        lambda repo: edit_note(
            repo, lambda t: t.replace(release.END, "| broken |\n" + release.END)
        ),
        "asset list parses",
    ),
}


@pytest.mark.parametrize(("tamper", "check"), LIST_TAMPER.values(), ids=LIST_TAMPER.keys())
def test_asset_list_problem_is_exit_1(repo, capsys, tamper, check):
    tamper(repo)
    code, out, _ = run(capsys, "--root", str(repo))
    assert code == 1
    assert check in failed_checks(out)
    assert out.rstrip().endswith("check_release: FAILED")


def test_manifest_input_hash_differing_from_repo_file_is_exit_1(repo, capsys):
    path = repo / RESULTS / "manifest.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["runs"]["public/exact"]["inputs"]["corpus"]["sha256"] = "0" * 64
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", "utf-8"
    )
    write_note(repo)
    code, out, _ = run(capsys, "--root", str(repo))
    assert code == 1
    assert "asset sha256 matches the repo files and manifest inputs" in failed_checks(out)


# ------------------------------------------------------------ 합성 리포: 허용 필드


def mutate_rows(relative, change):
    def apply(repo):
        path = repo / relative
        rows = read_jsonl(path)
        change(rows)
        write_jsonl(path, rows)
        write_note(repo)  # 목록의 sha256을 맞춰 두어 필드 검사만 실패하게 한다

    return apply


def set_key(key, value):
    return lambda rows: rows[0].__setitem__(key, value)


def set_answer_key(rows):
    next(r for r in rows if r["answers"])["answers"][0]["quote"] = "x"


def set_evidence_key(rows):
    next(r for r in rows if r["answers"])["answers"][0]["evidence"][0]["text"] = "x"


def set_reason(rows):
    next(r for r in rows if r["answers"])["answers"][0]["reason"] = (
        "공지 본문에 따르면 패치를 권고한다"
    )


def drop_result_field(rows):
    del rows[0]["top1_score_raw"]


def add_result_item_field(rows):
    rows[0]["results"][0]["snippet"] = "body"


def long_query(rows):
    rows[0]["query"] = "가" * 600


def long_title(rows):
    rows[0]["title"] = "나" * 600


FIELD_TAMPER = {
    "result record gets a text field": mutate_rows(
        f"{RESULTS}/public/bm25.jsonl", set_key("text", "body")
    ),
    "result record loses a field": mutate_rows(f"{RESULTS}/kisa/exact.jsonl", drop_result_field),
    "result item gets a snippet": mutate_rows(f"{RESULTS}/kisa/bm25.jsonl", add_result_item_field),
    "queries get a body field": mutate_rows("eval/public/queries.jsonl", set_key("body", "x")),
    "queries get a very long query": mutate_rows("eval/public/queries.jsonl", long_query),
    "golden gets a body field": mutate_rows("eval/golden/golden_v1.jsonl", set_key("body", "x")),
    "golden answer gets a quote": mutate_rows("eval/golden/golden_v1.jsonl", set_answer_key),
    "golden evidence gets a text": mutate_rows("eval/golden/golden_v1.jsonl", set_evidence_key),
    "golden reason is free text": mutate_rows("eval/golden/golden_v1.jsonl", set_reason),
    "metadata gets a body field": mutate_rows("fixtures/kisa/metadata.jsonl", set_key("body", "x")),
    "metadata gets a very long title": mutate_rows("fixtures/kisa/metadata.jsonl", long_title),
}


@pytest.mark.parametrize("tamper", FIELD_TAMPER.values(), ids=FIELD_TAMPER.keys())
def test_disallowed_field_is_exit_1(repo, capsys, tamper):
    tamper(repo)
    code, out, _ = run(capsys, "--root", str(repo))
    assert code == 1
    assert "only allowed fields" in failed_checks(out)


def test_json_asset_with_a_pasted_passage_is_exit_1(repo, capsys):
    path = repo / "eval/golden/agreement.json"
    path.write_text(json.dumps({"note": "본문 " * 300}) + "\n", encoding="utf-8")
    write_note(repo)
    code, out, _ = run(capsys, "--root", str(repo))
    assert code == 1 and "only allowed fields" in failed_checks(out)


def test_non_object_json_asset_is_exit_1(repo, capsys):
    (repo / "eval/golden/error_rates.json").write_text("[1, 2]\n", encoding="utf-8")
    write_note(repo)
    code, out, _ = run(capsys, "--root", str(repo))
    assert code == 1 and "only allowed fields" in failed_checks(out)


# ------------------------------------------------------------ 합성 리포: 사본으로 README 재계산


def test_readme_not_matching_asset_copies_is_exit_1(repo, capsys):
    path = repo / "README.md"
    text = path.read_text(encoding="utf-8")
    row = next(
        line for line in text.splitlines() if line.startswith("| exact | dev | cve_explicit")
    )
    path.write_text(text.replace(row, row.replace("1.0000", "0.5000", 1), 1), encoding="utf-8")
    code, out, _ = run(capsys, "--root", str(repo))
    assert code == 1
    assert failed_checks(out) == {"README tables rebuilt from the asset copies match"}


def test_metrics_json_not_matching_raw_results_is_exit_1(repo, capsys):
    path = repo / RESULTS / "metrics.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["runs"]["public/bm25"]["test"]["macro"]["ndcg@10"] += 0.01
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", "utf-8"
    )
    write_note(repo)
    code, out, _ = run(capsys, "--root", str(repo))
    assert code == 1
    assert failed_checks(out) == {"README tables rebuilt from the asset copies match"}


# ------------------------------------------------------------ 재현 결과 비교


@pytest.fixture
def rerun(repo, tmp_path):
    """run_baselines.py --out-dir로 다시 돌린 결과 디렉터리(여기서는 커밋된 결과의 사본)."""
    out = tmp_path / "rerun"
    shutil.copytree(repo / RESULTS, out)
    return out


def compare(capsys, repo, out, *extra):
    return run(capsys, "--root", str(repo), "--compare-results", str(out), *extra)


def test_compare_identical_results_is_exit_0(repo, rerun, capsys):
    code, out, err = compare(capsys, repo, rerun)
    assert (code, err) == (0, "")
    assert "public/exact, public/bm25" in out


def test_compare_ignores_manifest_metadata(repo, rerun, capsys):
    """실행 시각·소요 시간은 비교 대상이 아니다."""
    path = rerun / "manifest.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    for entry in payload["runs"].values():
        entry["created_at"] = "2030-01-01T00:00:00+00:00"
        entry["timing"]["index_seconds"] = 99.0
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert compare(capsys, repo, rerun)[0] == 0


def nudge_score(delta):
    def change(rows):
        row = next(r for r in rows if r["results"])
        row["results"][0]["score"] += delta
        row["top1_score_raw"] += delta

    return change


def swap_docs(rows):
    row = next(r for r in rows if len(r["results"]) >= 2)
    a, b = row["results"][0], row["results"][1]
    a["doc_id"], b["doc_id"] = b["doc_id"], a["doc_id"]


def change_doc(rows):
    row = next(r for r in rows if r["results"])
    row["results"][0]["doc_id"] = "CVE-2026-9999"


def drop_question(rows):
    rows.pop()


def extra_question(rows):
    rows.append({**rows[0], "question_id": "q-extra"})


def dup_question(rows):
    rows.append(dict(rows[0]))


def change_removed_count(rows):
    rows[0]["n_unjudged_removed"] += 1


COMPARE_FAIL = {
    "score off by 1e-8": nudge_score(1e-8),
    "doc ids swapped": swap_docs,
    "doc id changed": change_doc,
    "question missing": drop_question,
    "question added": extra_question,
    "question duplicated": dup_question,
    "n_unjudged_removed differs": change_removed_count,
}


COMPARE_CASES = [
    (retriever, name, change)
    for retriever in ("exact", "bm25")
    for name, change in COMPARE_FAIL.items()
    if not (
        retriever == "exact" and change is swap_docs
    )  # exact 결과는 질문당 1건이라 바꿀 순위가 없다
]


@pytest.mark.parametrize(
    ("retriever", "change"),
    [(r, c) for r, _, c in COMPARE_CASES],
    ids=[f"{r}-{n}" for r, n, _ in COMPARE_CASES],
)
def test_compare_difference_is_exit_1(repo, rerun, capsys, retriever, change):
    path = rerun / "public" / f"{retriever}.jsonl"
    rows = read_jsonl(path)
    change(rows)
    write_jsonl(path, rows)
    code, _, err = compare(capsys, repo, rerun)
    assert code == 1 and f"public/{retriever}.jsonl" in err


def test_compare_score_within_atol_is_exit_0(repo, rerun, capsys):
    path = rerun / "public" / "bm25.jsonl"
    rows = read_jsonl(path)
    nudge_score(1e-10)(rows)
    write_jsonl(path, rows)
    assert compare(capsys, repo, rerun)[0] == 0


def test_compare_atol_option_widens_the_score_tolerance(repo, rerun, capsys):
    path = rerun / "public" / "bm25.jsonl"
    rows = read_jsonl(path)
    nudge_score(1e-8)(rows)
    write_jsonl(path, rows)
    assert compare(capsys, repo, rerun)[0] == 1
    assert compare(capsys, repo, rerun, "--atol", "1e-6")[0] == 0


def test_compare_missing_or_empty_rerun_file_is_exit_1(repo, rerun, capsys):
    (rerun / "public" / "exact.jsonl").unlink()
    assert compare(capsys, repo, rerun)[0] == 1
    (rerun / "public" / "exact.jsonl").write_text("", encoding="utf-8")
    code, _, err = compare(capsys, repo, rerun)
    assert code == 1 and "empty results" in err


def test_compare_only_the_requested_track_and_retrievers(repo, rerun, capsys):
    (rerun / "public" / "bm25.jsonl").unlink()
    assert compare(capsys, repo, rerun)[0] == 1
    assert compare(capsys, repo, rerun, "--retrievers", "exact")[0] == 0
    assert compare(capsys, repo, rerun, "--track", "kisa")[0] == 0
    assert compare(capsys, repo, rerun, "--retrievers", "")[0] == 1

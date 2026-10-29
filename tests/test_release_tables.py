"""make_readme_tables.py 테스트 - 일치 0, 불일치 1, 누락·빈 입력·질문 ID 오류 1.

합성 리포(KISA 캐시·모델 없음)에서 변조 행렬을 돌리고, 커밋된 리포의 README도 `--check`로 확인한다.
"""

import json
import re
import shutil

import pytest
from test_release_support import (
    ROOT,
    build_repo,
    read_jsonl,
    tables,
    write_jsonl,
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


def run_check(repo, capsys, *extra):
    code = tables.main(["--check", "--root", str(repo), *extra])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def edit_json(path, change):
    payload = json.loads(path.read_text(encoding="utf-8"))
    change(payload)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", "utf-8"
    )


def edit_rows(path, change):
    rows = read_jsonl(path)
    change(rows)
    write_jsonl(path, rows)


def edit_readme_table(repo, old, new):
    path = repo / "README.md"
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# ------------------------------------------------------------ 일치 -> 0


def test_synthetic_repo_matches(repo, capsys):
    code, out, err = run_check(repo, capsys)
    assert (code, err) == (0, "")
    assert out.startswith("OK: 4 runs")


def test_committed_repo_readme_matches_raw_results(capsys):
    """리포의 README 표와 metrics.json이 질문별 원시 결과에서 다시 계산한 값과 같다."""
    code = tables.main(["--check"])
    captured = capsys.readouterr()
    assert (code, captured.err) == (0, "")
    assert "6 runs" in captured.out


def test_write_mode_fills_markers_and_then_check_passes(repo, capsys):
    path = repo / "README.md"
    path.write_text(f"intro\n{tables.BEGIN}\nstale\n{tables.END}\noutro\n", encoding="utf-8")
    assert tables.main(["--root", str(repo)]) == 0
    text = path.read_text(encoding="utf-8")
    assert text.startswith("intro\n") and text.endswith("outro\n") and "stale" not in text
    assert run_check(repo, capsys)[0] == 0


def test_tables_have_dev_test_types_and_no_answer(repo):
    text = (repo / "README.md").read_text(encoding="utf-8")
    block = text[text.index(tables.BEGIN) : text.index(tables.END)]
    for track in ("공개 트랙", "KISA 트랙"):
        assert track in block
    for retriever in ("exact", "bm25"):
        for split in ("dev", "test"):
            assert re.search(rf"\| {retriever} \| {split} \| cve_explicit \|", block)
            assert re.search(
                rf"\| {retriever} \| {split} \| \d+ \| [0-9.]+ \| [0-9.]+ \| \d+ \|", block
            )
    assert block.count("no_answer (기권)") == 2
    assert "†" in block  # 합성 KISA 유형은 n_scored < 10
    assert "/Users/" not in block


def test_readme_outside_markers_is_untouched_by_write(repo):
    path = repo / "README.md"
    before = path.read_text(encoding="utf-8")
    assert tables.main(["--root", str(repo)]) == 0
    assert path.read_text(encoding="utf-8") == before


def exclude_kisa_test_split(root):
    path = root / "eval/golden/golden_v1.jsonl"
    rows = read_jsonl(path)
    for row in rows:
        if row["split"] == "test":
            row["excluded"], row["answers"] = True, []
    write_jsonl(path, rows)


def test_split_whose_questions_are_all_excluded_is_not_a_mismatch(tmp_path, capsys):
    """runner.compute_run_metrics는 채점할 질문이 없는 분할을 metrics.json에 쓰지 않는다. --check도 같은 분할만 본다."""
    root = build_repo(tmp_path / "repo", exclude_kisa_test_split)
    metrics = json.loads((root / RESULTS / "metrics.json").read_text(encoding="utf-8"))
    assert set(metrics["runs"]["kisa/bm25"]) == {"dev"}
    assert run_check(root, capsys)[0] == 0
    assert "| bm25 | test | 3 |" not in (root / "README.md").read_text(encoding="utf-8")


# ------------------------------------------------------------ 불일치 -> 1


def bump_metric(payload):
    payload["runs"]["public/bm25"]["test"]["macro"]["ndcg@10"] += 0.01


def bump_tau(payload):
    payload["runs"]["kisa/exact"]["dev"]["no_answer"]["tau"] += 1


def drop_run(payload):
    del payload["runs"]["kisa/bm25"]


def drop_split(payload):
    del payload["runs"]["public/exact"]["test"]


def tiny_drift(payload):  # abs 1e-9 밖
    payload["runs"]["public/bm25"]["dev"]["macro"]["hit@10"] += 1e-6


METRICS_TAMPER = {
    "macro value": bump_metric,
    "tau": bump_tau,
    "run removed": drop_run,
    "split removed": drop_split,
    "drift above atol": tiny_drift,
}


@pytest.mark.parametrize("change", METRICS_TAMPER.values(), ids=METRICS_TAMPER.keys())
def test_metrics_json_mismatch_is_exit_1(repo, capsys, change):
    edit_json(repo / RESULTS / "metrics.json", change)
    code, _, err = run_check(repo, capsys)
    assert code == 1
    assert "MISMATCH metrics.json" in err


def test_metrics_json_drift_below_atol_is_still_equal(repo, capsys):
    def nudge(payload):
        payload["runs"]["public/bm25"]["dev"]["macro"]["hit@10"] += 1e-12

    edit_json(repo / RESULTS / "metrics.json", nudge)
    assert run_check(repo, capsys)[0] == 0


def first_table_row(repo):
    text = (repo / "README.md").read_text(encoding="utf-8")
    return next(
        line for line in text.splitlines() if line.startswith("| bm25 | test | cve_explicit")
    )


README_TAMPER = {
    "cell edited": lambda repo: edit_readme_table(
        repo, first_table_row(repo), first_table_row(repo).replace("1.0000", "0.9999", 1)
    ),
    "row added": lambda repo: edit_readme_table(
        repo, first_table_row(repo), first_table_row(repo) + "\n" + first_table_row(repo)
    ),
    "row removed": lambda repo: edit_readme_table(repo, first_table_row(repo) + "\n", ""),
    "note line edited": lambda repo: edit_readme_table(repo, "손으로 고치지 않는다", "고쳐도 된다"),
}


@pytest.mark.parametrize("tamper", README_TAMPER.values(), ids=README_TAMPER.keys())
def test_readme_table_mismatch_is_exit_1(repo, capsys, tamper):
    tamper(repo)
    code, _, err = run_check(repo, capsys)
    assert code == 1
    assert "MISMATCH README.md" in err


def test_stale_readme_after_metrics_recompute_is_exit_1(repo, capsys):
    """원시 결과를 바꾸고 metrics.json까지 맞춰도 README 표가 그대로면 실패한다."""

    def swap_gold_doc(rows):
        row = next(r for r in rows if r["question_id"] == "q-cve-1")
        row["results"][0]["doc_id"] = "CVE-2026-0002"

    edit_rows(repo / RESULTS / "public" / "exact.jsonl", swap_gold_doc)
    code, _, err = run_check(repo, capsys)
    assert code == 1
    assert "MISMATCH metrics.json" in err and "MISMATCH README.md" in err


def test_manifest_tau_change_is_exit_1(repo, capsys):
    def change(payload):
        payload["runs"]["public/bm25"]["selected"]["tau"] = 0.0

    edit_json(repo / RESULTS / "manifest.json", change)
    assert run_check(repo, capsys)[0] == 1


def test_write_mode_refuses_when_metrics_json_differs(repo, capsys):
    edit_json(repo / RESULTS / "metrics.json", bump_metric)
    before = (repo / "README.md").read_text(encoding="utf-8")
    assert tables.main(["--root", str(repo)]) == 1
    assert (repo / "README.md").read_text(encoding="utf-8") == before
    assert "README untouched" in capsys.readouterr().err


# ------------------------------------------------------------ 누락 -> 1

REQUIRED_FILES = [
    "results/baselines/manifest.json",
    "results/baselines/metrics.json",
    "results/baselines/public/exact.jsonl",
    "results/baselines/public/bm25.jsonl",
    "results/baselines/kisa/exact.jsonl",
    "results/baselines/kisa/bm25.jsonl",
    "eval/public/queries.jsonl",
    "eval/golden/golden_v1.jsonl",
    "fixtures/kisa/manifest.json",
    "README.md",
]


@pytest.mark.parametrize("relative", REQUIRED_FILES)
def test_missing_required_file_is_exit_1(repo, capsys, relative):
    (repo / relative).unlink()
    code, out, err = run_check(repo, capsys)
    assert code == 1
    assert err.startswith("error: missing required file")
    assert "MISMATCH" not in err and out == ""


MARKER_BROKEN = {
    "no markers": lambda text: text.replace(tables.BEGIN, "").replace(tables.END, ""),
    "begin only": lambda text: text.replace(tables.END, ""),
    "end only": lambda text: text.replace(tables.BEGIN, ""),
    "reversed": lambda text: text.replace(tables.BEGIN, "@@").replace(tables.END, tables.BEGIN).replace("@@", tables.END),
    "duplicated": lambda text: text + f"\n{tables.BEGIN}\n{tables.END}\n",
}  # fmt: skip


@pytest.mark.parametrize("broken", MARKER_BROKEN.values(), ids=MARKER_BROKEN.keys())
def test_readme_marker_problem_is_exit_1(repo, capsys, broken):
    path = repo / "README.md"
    path.write_text(broken(path.read_text(encoding="utf-8")), encoding="utf-8")
    code, _, err = run_check(repo, capsys)
    assert code == 1 and "marker" in err


# ------------------------------------------------------------ 빈 입력 -> 1

EMPTY_INPUTS = {
    "empty public results": lambda r: (r / RESULTS / "public/bm25.jsonl").write_text(""),
    "empty kisa results": lambda r: (r / RESULTS / "kisa/exact.jsonl").write_text("\n"),
    "empty public queries": lambda r: (r / "eval/public/queries.jsonl").write_text(""),
    "empty golden": lambda r: (r / "eval/golden/golden_v1.jsonl").write_text(""),
    "manifest without runs": lambda r: edit_json(
        r / RESULTS / "manifest.json", lambda p: p.update(runs={})
    ),
    "empty manifest": lambda r: (r / RESULTS / "manifest.json").write_text("{}"),
    "empty metrics": lambda r: (r / RESULTS / "metrics.json").write_text("{}"),
    "unparsable metrics": lambda r: (r / RESULTS / "metrics.json").write_text("not json"),
}


@pytest.mark.parametrize("empty", EMPTY_INPUTS.values(), ids=EMPTY_INPUTS.keys())
def test_empty_input_is_exit_1_before_comparing(repo, capsys, empty):
    empty(repo)
    code, out, err = run_check(repo, capsys)
    assert code == 1
    assert err.startswith("error:") and "MISMATCH" not in err and out == ""


# ------------------------------------------------------------ 질문 ID 누락·중복·초과 -> 1


def duplicate_first(rows):
    rows.append(dict(rows[0]))


def drop_last(rows):
    rows.pop()


def rename_first(rows):
    rows[0]["question_id"] = "q-unknown"


def append_unknown(rows):
    rows.append({**rows[0], "question_id": "q-unknown"})


def add_unjudged_doc(rows):
    row = next(r for r in rows if r["question_id"] == "q-prod-1")
    last = row["results"][-1]
    row["results"].append(
        {"doc_id": "CVE-2026-0004", "rank": last["rank"] + 1, "score": last["score"] - 0.001}
    )


QUESTION_ID_CASES = {
    "duplicate id in results": ("public/bm25.jsonl", duplicate_first, "duplicate question id"),
    "missing id in results": ("public/bm25.jsonl", drop_last, "missing question ids"),
    "renamed id in results": ("public/exact.jsonl", rename_first, "missing question ids"),
    "unknown id appended": ("public/exact.jsonl", append_unknown, "unknown question ids"),
    "duplicate id in kisa results": ("kisa/bm25.jsonl", duplicate_first, "duplicate question id"),
    "missing id in kisa results": ("kisa/exact.jsonl", drop_last, "missing question ids"),
    "unjudged doc kept in results": ("public/bm25.jsonl", add_unjudged_doc, "condensed list"),
}


@pytest.mark.parametrize(
    ("name", "change", "message"), QUESTION_ID_CASES.values(), ids=QUESTION_ID_CASES.keys()
)
def test_question_id_problem_is_exit_1(repo, capsys, name, change, message):
    edit_rows(repo / RESULTS / name, change)
    code, out, err = run_check(repo, capsys)
    assert code == 1 and message in err and out == ""


def test_duplicate_question_id_in_query_set_is_exit_1(repo, capsys):
    edit_rows(repo / "eval/public/queries.jsonl", duplicate_first)
    code, _, err = run_check(repo, capsys)
    assert code == 1 and "duplicate question ids" in err


def test_query_set_change_without_manifest_hash_is_exit_1(repo, capsys):
    """질의셋 파일이 manifest가 기록한 해시와 다르면 비교 전에 멈춘다(내용이 같아도 바이트가 다르면)."""
    with (repo / "eval/public/queries.jsonl").open("a", encoding="utf-8") as handle:
        handle.write("\n")
    code, _, err = run_check(repo, capsys)
    assert code == 1 and "input sha256 differs" in err


def test_result_record_with_extra_field_is_exit_1(repo, capsys):
    def add_field(rows):
        rows[0]["text"] = "body"

    edit_rows(repo / RESULTS / "kisa/bm25.jsonl", add_field)
    code, _, err = run_check(repo, capsys)
    assert code == 1 and "invalid record" in err


MALFORMED_MANIFEST = {
    "run entry is a string": lambda p: p["runs"].__setitem__("public/bm25", "x"),
    "stored_results is null": lambda p: p["runs"]["public/bm25"].__setitem__("stored_results", None),
    "stored_results is a string": lambda p: p["runs"]["public/bm25"].__setitem__("stored_results", "x"),
    "inputs item is a string": lambda p: p["runs"]["kisa/exact"]["inputs"].__setitem__("queries", "x"),
    "inputs is a list": lambda p: p["runs"]["kisa/exact"].__setitem__("inputs", []),
    "selected is a string": lambda p: p["runs"]["public/exact"].__setitem__("selected", "x"),
}  # fmt: skip


@pytest.mark.parametrize("change", MALFORMED_MANIFEST.values(), ids=MALFORMED_MANIFEST.keys())
def test_malformed_manifest_is_exit_1_not_a_traceback(repo, capsys, change):
    edit_json(repo / RESULTS / "manifest.json", change)
    code, _, err = run_check(repo, capsys)
    assert code == 1 and err.startswith("error:")


def test_unknown_run_key_is_exit_1(repo, capsys):
    def rename(payload):
        payload["runs"]["web/bm25"] = payload["runs"].pop("public/bm25")

    edit_json(repo / RESULTS / "manifest.json", rename)
    code, _, err = run_check(repo, capsys)
    assert code == 1 and "unknown run key" in err


# ------------------------------------------------------------ 값 비교


@pytest.mark.parametrize(
    ("expected", "actual", "equal"),
    [
        (0.5, 0.5, True),
        (0.5, 0.5 + 1e-10, True),
        (0.5, 0.5 + 1e-8, False),
        (1, 1.0, True),
        (None, None, True),
        (None, 0.0, False),
        (True, 1, False),
        ("a", "a", True),
        ("a", "b", False),
        ({"x": 1}, {"x": 1, "y": 2}, False),
        ({"x": 1, "y": 2}, {"x": 1}, False),
    ],
)
def test_diff_values(expected, actual, equal):
    assert (tables.diff_values(expected, actual) == []) is equal


def test_committed_files_have_no_personal_paths():
    for relative in ("README.md", "docs/release-v0.1.md"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert "/Users/" not in text, relative

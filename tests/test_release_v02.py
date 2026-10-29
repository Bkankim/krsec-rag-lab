"""v0.2 릴리스 검사 테스트 - M3 판정 표·summary·노트 구간, v0.2 asset 허용·거부, 저장본 재계산 대조.

커밋된 `results/experiments/**`와 문서를 임시 디렉터리로 복사해(릴리스 asset 사본과 같이 NVD 코퍼스 파일 없이)
변조 행렬을 돌린다. 모델·KISA 캐시·네트워크를 쓰지 않는다. 베이스라인(v0.1) 쪽 검사는 test_release_check.py,
test_release_tables.py가 합성 리포로 이미 본다.
"""

import json
import re
import shutil
from pathlib import Path

import pytest
from test_release_support import ROOT, read_jsonl, release, tables, write_jsonl

from krsec_rag_lab.experiments import compare as cmp

NOTE = "docs/release-v0.2.md"
SUMMARY = "docs/experiments/summary.md"
README = "README.md"
EXPERIMENTS = tables.EXPERIMENTS
CHECK_M3 = "M3 metrics, comparison and tables rebuilt from the asset copies match"
CHECK_FIELDS = "only allowed fields"
CHECK_LISTED = "manifest-required files are listed"
CHECK_ALLOWED = "listed assets exist and are allowed"
CHECK_SHA = "asset sha256 matches the repo files and manifest inputs"
CHECK_README = "README tables rebuilt from the asset copies match"
V02_ONLY = [
    path for path in release.required_paths(ROOT, "v0.2") if path.startswith("results/experiments/")
]
STORED_RESULTS = [
    path for path in V02_ONLY if re.fullmatch(r".*/(public|kisa)/[a-z0-9_]+\.jsonl", path)
]
RANGES = {
    "README": (README, tables.README_M3),
    "summary": (SUMMARY, tables.SUMMARY_RANGE),
    "note": (NOTE, tables.NOTE_RANGE),
}


@pytest.fixture(scope="module", autouse=True)
def memoized_bootstrap():
    """같은 입력의 bootstrap(순수 함수, 시드 고정)은 한 번만 계산한다. 변조된 입력은 캐시에 없어 그대로 다시 계산된다."""
    original = cmp.bootstrap_macro_delta
    cache: dict[str, dict] = {}

    def memoized(delta_by_type, *args, **kwargs):
        key = json.dumps([delta_by_type, args, kwargs], sort_keys=True)
        if key not in cache:
            cache[key] = original(delta_by_type, *args, **kwargs)
        return dict(cache[key])

    cmp.bootstrap_macro_delta = memoized
    yield
    cmp.bootstrap_macro_delta = original


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    """릴리스 asset 사본과 같은 파일 + README·summary·노트. NVD 코퍼스 파일은 없다."""
    root = tmp_path_factory.mktemp("v02")
    for relative in (*release.default_assets(ROOT, "v0.2"), README, SUMMARY, NOTE):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    return root


@pytest.fixture
def repo(built, tmp_path):
    copy = tmp_path / "repo"
    shutil.copytree(built, copy)
    return copy


def run_release(capsys, repo, *args, note=NOTE):
    code = release.main(["--root", str(repo), "--note", str(repo / note), *args])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def run_tables(capsys, repo, *args):
    code = tables.main(["--root", str(repo), *args])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def failed_checks(out):
    return {line[5:] for line in out.splitlines() if line.startswith("FAIL ")}


def rewrite_assets(repo):
    """파일을 바꾼 뒤 노트의 asset 표(크기·sha256)를 현재 상태로 다시 쓴다(실패가 필드 검사 때문이도록)."""
    path = repo / NOTE
    text = path.read_text(encoding="utf-8")
    listed = [row["path"] for row in release.parse_asset_table(text)]
    table = release.render_asset_table(repo, listed)
    start = text.index(release.BEGIN) + len(release.BEGIN)
    path.write_text(
        text[:start] + "\n\n" + table + "\n" + text[text.index(release.END) :], encoding="utf-8"
    )


def edit_json(path, change):
    payload = json.loads(path.read_text(encoding="utf-8"))
    result = change(payload)
    path.write_text(
        json.dumps(payload if result is None else result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def edit_text(path, change):
    path.write_text(change(path.read_text(encoding="utf-8")), encoding="utf-8")


def edit_range(repo, key, change):
    relative, (begin, end) = RANGES[key]

    def apply(text):
        start, stop = text.index(begin) + len(begin), text.index(end)
        return text[:start] + change(text[start:stop]) + text[stop:]

    edit_text(repo / relative, apply)


def comparison_of(root, name):
    return json.loads((root / "results/experiments" / name / "comparison.json").read_text("utf-8"))


# ------------------------------------------------------------ 커밋된 리포


def test_committed_v02_note_passes(capsys):
    code, out, _ = run_release(capsys, ROOT)
    assert code == 0, out
    assert out.count("OK  ") == 7 and "FAIL" not in out
    assert out.rstrip().endswith("check_release: OK")


def test_committed_repo_check_covers_baseline_and_m3(capsys):
    code, out, err = run_tables(capsys, ROOT, "--check")
    assert code == 0, err
    assert "5 experiments" in out


def test_committed_v01_note_still_passes_and_has_six_checks(capsys):
    code = release.main(["--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0 and out.count("OK  ") == 6 and "FAIL" not in out


def test_committed_note_lists_every_allowed_asset_with_current_sha256():
    note = (ROOT / NOTE).read_text(encoding="utf-8")
    listed = release.parse_asset_table(note)
    expected = release.render_asset_table(ROOT, release.default_assets(ROOT, "v0.2"))
    assert [r["path"] for r in listed] == release.default_assets(ROOT, "v0.2")
    assert note.count(expected.strip()) == 1


def test_print_assets_for_the_v02_note_is_what_the_note_lists(capsys):
    code = release.main(["--root", str(ROOT), "--print-assets", "--note", NOTE])
    out = capsys.readouterr().out
    assert code == 0
    assert (ROOT / NOTE).read_text(encoding="utf-8").count(out.strip()) == 1
    assert out.count("results__experiments__") == len(V02_ONLY)


def test_v02_assets_contain_every_experiment_file_and_the_baseline_set():
    listed = set(release.default_assets(ROOT, "v0.2"))
    assert set(release.default_assets(ROOT)) <= listed
    assert set(V02_ONLY) <= listed
    assert "results/experiments/crossling/translations.jsonl" in listed
    for name in EXPERIMENTS:
        for filename in ("manifest", "metrics", "comparison"):
            assert f"results/experiments/{name}/{filename}.json" in listed
    runs = 0
    for name in EXPERIMENTS:
        manifest = json.loads(
            (ROOT / f"results/experiments/{name}/manifest.json").read_text("utf-8")
        )
        runs += len(manifest["runs"])
    assert len(STORED_RESULTS) == runs == 9


def test_committed_note_names_the_required_sections():
    note = (ROOT / NOTE).read_text(encoding="utf-8")
    for heading in ("무엇이 들어 있나", "재현", "데이터와 모델", "asset", "한계"):
        assert re.search(rf"^## {heading}$", note, re.MULTILINE), heading
    for word in (
        "모델·KISA 캐시 없이",
        "모델이 필요한 것",
        "KISA 캐시가 필요한 것",
        "run_experiment.py",
        "--compare",
        "--assets-dir",
        "LICENSES/README.md",
        "check_kisa_leaks",
        "translations.jsonl",
    ):
        assert word in note, word
    for name in EXPERIMENTS:
        assert f"experiments/{name}.md" in note, name


def test_committed_docs_have_no_motive_words_or_dashes_or_personal_paths():
    for relative in (README, SUMMARY, NOTE):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert not re.search(r"면접|학습용|학습 목적|interview", text), relative
        assert "\u2014" not in text, relative  # em dash
        assert "/Users/" not in text, relative
    assert "단독 프로젝트" in (ROOT / README).read_text(encoding="utf-8")


def test_committed_docs_links_resolve():
    for relative in (README, SUMMARY, NOTE):
        text = (ROOT / relative).read_text(encoding="utf-8")
        base = (ROOT / relative).parent
        for target in re.findall(r"\]\(((?!https?:|\.\./\.\./)[^)#\s]+)", text):
            assert (base / target).resolve().exists(), (relative, target)
    readme = (ROOT / README).read_text(encoding="utf-8")
    for name in EXPERIMENTS:
        assert f"](docs/experiments/{name}.md)" in readme, name
    assert "](docs/experiments/summary.md)" in readme and "](docs/release-v0.2.md)" in readme


def test_readme_status_is_m3_complete_and_keeps_the_baseline_range():
    readme = (ROOT / README).read_text(encoding="utf-8")
    status = readme[readme.index("## 상태") : readme.index("## 평가 트랙과 재현")]
    assert "M3 완료" in status and "v0.2" in status and "M2 완료, v0.1" in status
    assert readme.count(tables.BEGIN) == 1 and readme.count(tables.README_M3[0]) == 1
    assert readme.index(tables.END) < readme.index(tables.README_M3[0])


def test_committed_note_model_revisions_match_the_manifests():
    note = (ROOT / NOTE).read_text(encoding="utf-8")
    manifests = "".join(
        (ROOT / f"results/experiments/{n}/manifest.json").read_text("utf-8") for n in EXPERIMENTS
    )
    pairs = re.findall(r"`([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)` revision `([0-9a-f]{40})`", note)
    assert {name for name, _ in pairs} == {
        "BAAI/bge-m3",
        "BAAI/bge-reranker-v2-m3",
        "Helsinki-NLP/opus-mt-ko-en",
        "intfloat/multilingual-e5-large",
    }
    for name, revision in pairs:
        assert f'"{name}"' in manifests and revision in manifests, name


# ------------------------------------------------------------ 표 값은 comparison.json과 같다(독립 서식으로 대조)


def cells(line):
    return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip())[1:-1]]


def section_rows(path, markers):
    text = Path(path).read_text(encoding="utf-8")
    block = text[text.index(markers[0]) : text.index(markers[1])]
    return [cells(line) for line in block.splitlines() if line.startswith("| ")]


def signed(value):
    return f"{value:+.4f}"


def cve_cell(block):
    cve = block["cve_explicit"]
    return f"{'예' if cve['regression'] else '아니오'} ({signed(cve['delta_ndcg@10'])})"


def test_summary_primary_table_matches_the_five_comparison_files():
    rows = [r for r in section_rows(ROOT / SUMMARY, tables.SUMMARY_RANGE) if r[0].startswith("[")]
    assert [r[0] for r in rows] == [f"[{n}]({n}.md)" for n in EXPERIMENTS]
    for name, row in zip(EXPERIMENTS, rows, strict=True):
        comparison = comparison_of(ROOT, name)
        primary = comparison["primary"]
        block = comparison["comparisons"][f"{primary['track']}/{primary['variant']}"]
        secondary = "<br>".join(
            f"{s['track']}/{s['variant']}: `{s['verdict']}`" for s in comparison["secondary"]
        )
        assert row[1:] == [
            comparison["hypothesis"],
            f"{primary['track']} ({primary['variant']})",
            primary["baseline"],
            str(block["n_test_questions"]),
            f"{block['baseline_macro']:.4f}",
            f"{block['experiment_macro']:.4f}",
            signed(block["delta"]),
            f"[{signed(block['ci95']['low'])}, {signed(block['ci95']['high'])}]",
            f"`{primary['verdict']}`",
            secondary or "-",
            cve_cell(block),
        ], name


def test_summary_secondary_table_matches_the_comparison_files():
    rows = [r for r in section_rows(ROOT / SUMMARY, tables.SUMMARY_RANGE) if r[0] in EXPERIMENTS]
    expected = []
    for name in EXPERIMENTS:
        comparison = comparison_of(ROOT, name)
        for ref in comparison["secondary"]:
            key = f"{ref['track']}/{ref['variant']}"
            block = comparison["comparisons"][key]
            expected.append(
                [
                    name,
                    key,
                    block["baseline"],
                    str(block["n_test_questions"]),
                    f"{block['baseline_macro']:.4f}",
                    f"{block['experiment_macro']:.4f}",
                    signed(block["delta"]),
                    f"[{signed(block['ci95']['low'])}, {signed(block['ci95']['high'])}]",
                    f"`{block['verdict']}`",
                    cve_cell(block),
                ]
            )
    assert rows == expected and len(rows) == 4


@pytest.mark.parametrize(
    ("document", "markers", "prefix"),
    [
        (README, tables.README_M3, "docs/experiments/"),
        (NOTE, tables.NOTE_RANGE, "experiments/"),
    ],
    ids=["README", "note"],
)
def test_readme_and_note_verdict_tables_match_the_comparison_files(document, markers, prefix):
    rows = [r for r in section_rows(ROOT / document, markers) if r[0].startswith("[")]
    assert [r[0] for r in rows] == [f"[{n}]({prefix}{n}.md)" for n in EXPERIMENTS]
    for name, row in zip(EXPERIMENTS, rows, strict=True):
        comparison = comparison_of(ROOT, name)
        primary = comparison["primary"]
        block = comparison["comparisons"][f"{primary['track']}/{primary['variant']}"]
        assert row[1:] == [
            f"{primary['track']} ({primary['variant']})",
            primary["baseline"],
            str(block["n_test_questions"]),
            f"{block['baseline_macro']:.4f}",
            f"{block['experiment_macro']:.4f}",
            signed(block["delta"]),
            f"[{signed(block['ci95']['low'])}, {signed(block['ci95']['high'])}]",
            f"`{primary['verdict']}`",
        ], name


def test_every_experiment_label_source_is_the_primary_field():
    """이슈 라벨의 근거는 comparison.json 최상위 `primary.verdict`다. 표의 판정이 그 값이다."""
    for name in EXPERIMENTS:
        comparison = comparison_of(ROOT, name)
        assert comparison["primary"]["verdict"] in ("hypothesis-confirmed", "hypothesis-rejected")
        assert comparison["primary"]["verdict"] == "hypothesis-rejected"
    text = (ROOT / README).read_text(encoding="utf-8")
    assert "hypothesis-confirmed 0, hypothesis-rejected 5" in text


def test_summary_has_next_experiment_candidates_without_a_verdict():
    text = (ROOT / SUMMARY).read_text(encoding="utf-8")
    assert re.search(r"^## 다음 실험 후보 \(판정 없음\)$", text, re.MULTILINE)
    section = text[text.index("## 다음 실험 후보") : text.index("## 한계")]
    assert "누적 조합" in section and "hypothesis-" not in section
    assert re.search(r"^## 한계$", text, re.MULTILINE)


# ------------------------------------------------------------ 복사본: 통과


def test_synthetic_copy_passes_both_checks(repo, capsys):
    code, out, _ = run_release(capsys, repo)
    assert code == 0, out
    assert out.count("OK  ") == 7
    assert run_tables(capsys, repo, "--check")[0] == 0


def test_check_without_experiments_dir_and_without_m3_markers_is_baseline_only(repo, capsys):
    shutil.rmtree(repo / "results/experiments")
    begin, end = tables.README_M3
    edit_text(repo / README, lambda t: t.replace(begin, "").replace(end, ""))
    code, out, err = run_tables(capsys, repo, "--check")
    assert code == 0, err
    assert "experiments" not in out


def test_missing_experiments_dir_with_m3_markers_in_the_readme_is_exit_1(repo, capsys):
    """README에 M3 구간이 있는데 원시 결과 디렉터리가 사라지면 조용히 통과하지 않는다."""
    shutil.rmtree(repo / "results/experiments")
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "missing required file" in err


def test_asset_tree_without_docs_is_checked_with_explicit_summary_and_note(repo, tmp_path, capsys):
    """문서가 없는 asset 사본(`--root`)도 --summary·--note로 문서 경로를 주면 검증된다."""
    docs = tmp_path / "docs"
    docs.mkdir()
    shutil.move(repo / SUMMARY, docs / "summary.md")
    shutil.move(repo / NOTE, docs / "note.md")
    assert run_tables(capsys, repo, "--check")[0] == 1
    code, _, err = run_tables(
        capsys,
        repo,
        "--check",
        "--summary",
        str(docs / "summary.md"),
        "--note",
        str(docs / "note.md"),
    )
    assert code == 0, err


def test_v01_note_does_not_allow_experiment_assets(repo, capsys):
    """v0.2 표를 v0.1 이름의 노트에 넣으면 실험 asset은 허용 목록 밖이다."""
    shutil.copyfile(repo / NOTE, repo / "docs/release-v0.1.md")
    code, out, _ = run_release(capsys, repo, note="docs/release-v0.1.md")
    assert code == 1
    assert CHECK_ALLOWED in failed_checks(out)
    assert "not an allowed asset" in out


@pytest.mark.parametrize(
    ("name", "profile"),
    [
        ("release-v0.1.md", "v0.1"),
        ("release-v0.2.md", "v0.2"),
        ("note.md", "v0.1"),
        ("release-v0.2.md.bak", "v0.1"),
    ],
)
def test_profile_comes_from_the_note_file_name(name, profile):
    assert release.profile_of(Path("docs") / name) == profile


def test_unknown_release_profile_is_a_failed_check(repo, capsys):
    shutil.copyfile(repo / NOTE, repo / "docs/release-v0.9.md")
    code, out, _ = run_release(capsys, repo, note="docs/release-v0.9.md")
    assert code == 1 and "FAIL release profile" in out and out.rstrip().endswith("FAILED")
    code = release.main(["--root", str(repo), "--print-assets", "--note", "docs/release-v0.9.md"])
    assert code == 1 and "unknown release profile" in capsys.readouterr().err


# ------------------------------------------------------------ 목록: 허용 밖, 빠진 필수 asset


def add_row(path):
    def add(repo):
        row = next(
            line
            for line in (repo / NOTE).read_text("utf-8").splitlines()
            if "| `results/experiments/hybrid/manifest.json` |" in line
        )
        extra = row.replace("results/experiments/hybrid/manifest.json", path).replace(
            "results__experiments__hybrid__manifest.json", path.replace("/", "__")
        )
        edit_text(repo / NOTE, lambda t: t.replace(release.END, extra + "\n" + release.END))

    return add


def drop_rows(*paths):
    def drop(repo):
        lines = (repo / NOTE).read_text("utf-8").splitlines(keepends=True)
        kept = [ln for ln in lines if not any(f"| `{p}` |" in ln for p in paths)]
        assert len(kept) < len(lines)
        (repo / NOTE).write_text("".join(kept), encoding="utf-8")

    return drop


NOT_ALLOWED = [
    "results/experiments/hybrid/notes.txt",
    "results/experiments/hybrid/public/rrf.json",
    "results/experiments/rogue/manifest.json",
    "results/experiments/hybrid/extra/comparison.json",
    "results/experiments/hybrid/public/sub/rrf.jsonl",
    "results/experiments/rerank/translations.jsonl",
    "fixtures/nvd/cves.jsonl",
    "README.md",
    "data/kisa/90001/body.txt",
    "eval/golden/judgments/A.jsonl",
]


@pytest.mark.parametrize("path", NOT_ALLOWED)
def test_v02_asset_outside_the_allow_list_is_exit_1(repo, capsys, path):
    add_row(path)(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_ALLOWED in failed_checks(out)
    assert out.rstrip().endswith("check_release: FAILED")


@pytest.mark.parametrize("path", V02_ONLY)
def test_note_missing_a_required_experiment_asset_is_exit_1(repo, capsys, path):
    drop_rows(path)(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_LISTED in failed_checks(out)
    assert f"{path}: required by manifest.json but not listed" in out


@pytest.mark.parametrize("name", EXPERIMENTS)
def test_note_missing_a_whole_experiment_is_exit_1(repo, capsys, name):
    drop_rows(*[p for p in V02_ONLY if p.startswith(f"results/experiments/{name}/")])(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1 and CHECK_LISTED in failed_checks(out)


def test_note_listing_only_baseline_assets_is_exit_1(repo, capsys):
    drop_rows(*V02_ONLY)(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert out.count("required by manifest.json but not listed") == len(V02_ONLY)


def test_required_set_comes_from_the_experiment_manifests(repo):
    """저장 결과 경로와 재현 입력이 manifest에서 나온다: manifest가 가리키는 경로가 필수에 들어간다."""
    path = repo / "results/experiments/rerank/manifest.json"
    edit_json(
        path,
        lambda p: p["runs"]["public/rerank"]["stored_results"].__setitem__(
            "path", "results/experiments/rerank/public/moved.jsonl"
        ),
    )
    assert "results/experiments/rerank/public/moved.jsonl" in release.required_paths(repo, "v0.2")
    assert "results/experiments/rerank/public/rerank.jsonl" not in release.required_paths(
        repo, "v0.2"
    )
    assert "results/experiments/crossling/translations.jsonl" in release.required_paths(
        repo, "v0.2"
    )


# ------------------------------------------------------------ 허용 필드


def mutate_rows(relative, change):
    def apply(repo):
        rows = read_jsonl(repo / relative)
        change(rows)
        write_jsonl(repo / relative, rows)

    return apply


def mutate_json(relative, change):
    return lambda repo: edit_json(repo / relative, change)


EXP_RESULT = "results/experiments/hybrid/public/rrf.jsonl"
TRANSLATIONS = "results/experiments/crossling/translations.jsonl"
EXP_COMPARISON = "results/experiments/embedding/comparison.json"
EXP_MANIFEST = "results/experiments/chunking/manifest.json"
EXP_METRICS = "results/experiments/rerank/metrics.json"


def set_translation_key(rows):
    rows[0]["body"] = "x"


def drop_translation_key(rows):
    del rows[0]["revision"]


FIELD_TAMPER = {
    "result row gets an extra key": mutate_rows(EXP_RESULT, lambda r: r[0].__setitem__("body", "x")),
    "result item gets an extra key": mutate_rows(EXP_RESULT, lambda r: r[0]["results"][0].__setitem__("text", "x")),
    "result row loses a key": mutate_rows(EXP_RESULT, lambda r: r[0].pop("top1_score_raw")),
    "result doc id is a long passage": mutate_rows(EXP_RESULT, lambda r: r[0]["results"][0].__setitem__("doc_id", "x" * 600)),
    "translations row gets an extra key": mutate_rows(TRANSLATIONS, set_translation_key),
    "translations row loses a key": mutate_rows(TRANSLATIONS, drop_translation_key),
    "translation is a long passage": mutate_rows(TRANSLATIONS, lambda r: r[0].__setitem__("translation", "x" * 600)),
    "manifest has a long string": mutate_json(EXP_MANIFEST, lambda p: p.__setitem__("note", "x" * 600)),
    "comparison has a long string": mutate_json(EXP_COMPARISON, lambda p: p.__setitem__("note", "x" * 600)),
    "metrics has a long string in a list": mutate_json(EXP_METRICS, lambda p: p.__setitem__("note", ["x" * 600])),
    "comparison is a json list": mutate_json(EXP_COMPARISON, lambda p: []),
    "comparison path /Users/": mutate_json(EXP_COMPARISON, lambda p: p.__setitem__("where", "/Users/someone/cache")),
    "comparison path /home/": mutate_json(EXP_COMPARISON, lambda p: p.__setitem__("where", "/home/someone/cache")),
    "comparison path /private/": mutate_json(EXP_COMPARISON, lambda p: p.__setitem__("where", "/private/tmp/x")),
    "comparison path /var/folders/": mutate_json(EXP_COMPARISON, lambda p: p.__setitem__("where", "/var/folders/ab/cd")),
    "manifest key is an absolute path": mutate_json(EXP_MANIFEST, lambda p: p.__setitem__("cache", {"/Users/x/.cache/model": "0" * 64})),
    "comparison key is a long passage": mutate_json(EXP_COMPARISON, lambda p: p.__setitem__("x" * 600, 1)),
    "manifest nested path /Users/": mutate_json(EXP_MANIFEST, lambda p: p.__setitem__("where", {"deep": ["/Users/x"]})),
    "metrics path /home/": mutate_json(EXP_METRICS, lambda p: p.__setitem__("where", "/home/x")),
}  # fmt: skip


@pytest.mark.parametrize("tamper", FIELD_TAMPER.values(), ids=FIELD_TAMPER.keys())
def test_disallowed_experiment_field_is_exit_1(repo, capsys, tamper):
    tamper(repo)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_FIELDS in failed_checks(out)


@pytest.mark.parametrize(
    ("value", "count"),
    [
        ("/Users/x/y", 1),
        ("/home/x", 1),
        ("/private/var/x", 1),
        ("/var/folders/ab", 1),
        ("see /Users/x", 0),
        ("relative/Users/x", 0),
        ("results/experiments/hybrid", 0),
        ("/usr/bin", 0),
        ({"a": ["/home/x", "ok", {"b": "/Users/y"}]}, 2),
        (12, 0),
    ],
)
def test_absolute_path_detection_is_by_prefix(value, count):
    assert release._absolute_paths(value) == count


def test_real_experiment_files_have_no_absolute_paths_or_long_strings():
    for path in V02_ONLY:
        kind = release.asset_kind(path, "v0.2")
        assert kind in ("result", "exp_json", "translations"), path
        assert release.check_fields(kind, ROOT / path) == [], path


# ------------------------------------------------------------ 저장본만 바꾸면 --check 실패


def permute_doc_ids(rows):
    """질문 하나씩의 순위 목록을 질문 순서를 뒤집어 서로 바꾼다(각 레코드는 형식이 유효하고 지표만 달라진다)."""
    swapped = [(row["results"], row["top1_score_raw"]) for row in reversed(rows)]
    for row, (results, top1) in zip(rows, swapped, strict=True):
        row["results"], row["top1_score_raw"] = results, top1


@pytest.mark.parametrize("stored", STORED_RESULTS)
def test_changing_only_a_raw_result_file_fails_check(repo, capsys, stored):
    """원시 결과만 바꾸고 metrics·comparison·README·summary·노트를 그대로 두면 검증이 실패한다."""
    mutate_rows(stored, permute_doc_ids)(repo)
    code, _, err = run_tables(capsys, repo, "--check")
    name = stored.split("/")[2]
    assert code == 1
    assert f"MISMATCH results/experiments/{name}/" in err


@pytest.mark.parametrize("name", EXPERIMENTS)
def test_changing_only_a_raw_result_fails_the_release_check_even_with_a_fresh_asset_table(
    repo, capsys, name
):
    stored = next(p for p in STORED_RESULTS if f"/{name}/" in p)
    mutate_rows(stored, permute_doc_ids)(repo)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_M3 in failed_checks(out)
    assert CHECK_SHA not in failed_checks(out)


def bump_comparison(payload):
    block = next(iter(payload["comparisons"].values()))
    block["delta"] += 0.001


def flip_primary(payload):
    payload["primary"]["verdict"] = "hypothesis-confirmed"


def bump_metrics(payload):
    run = next(iter(payload["runs"].values()))
    run["test"]["macro"]["ndcg@10"] += 0.01


def drift_below_atol(payload):
    block = next(iter(payload["comparisons"].values()))
    block["delta"] += 1e-12


JSON_TAMPER = {
    **{f"{name} comparison number": (name, "comparison", bump_comparison) for name in EXPERIMENTS},
    **{f"{name} metrics number": (name, "metrics", bump_metrics) for name in EXPERIMENTS},
    **{f"{name} primary verdict": (name, "comparison", flip_primary) for name in EXPERIMENTS},
}


@pytest.mark.parametrize(
    ("name", "filename", "change"), JSON_TAMPER.values(), ids=JSON_TAMPER.keys()
)
def test_metrics_or_comparison_json_mismatch_is_exit_1(repo, capsys, name, filename, change):
    path = f"results/experiments/{name}/{filename}.json"
    edit_json(repo / path, change)
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1
    assert f"MISMATCH {path} " in err


@pytest.mark.parametrize("name", EXPERIMENTS)
def test_json_mismatch_fails_the_release_check_with_a_fresh_asset_table(repo, capsys, name):
    edit_json(repo / f"results/experiments/{name}/comparison.json", bump_comparison)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1 and CHECK_M3 in failed_checks(out)
    assert CHECK_SHA not in failed_checks(out)


def test_json_drift_below_atol_is_still_equal(repo, capsys):
    edit_json(repo / "results/experiments/hybrid/comparison.json", drift_below_atol)
    assert run_tables(capsys, repo, "--check")[0] == 0


def test_tampered_manifest_hash_is_exit_1(repo, capsys):
    edit_json(
        repo / "results/experiments/hybrid/manifest.json",
        lambda p: p["runs"]["public/rrf"]["test"].__setitem__("config_hash", "0" * 64),
    )
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "config_hash" in err


def test_translations_changed_after_the_test_lock_is_exit_1(repo, capsys):
    mutate_rows(TRANSLATIONS, lambda r: r[0].__setitem__("translation", "changed"))(repo)
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "crossling" in err


@pytest.mark.parametrize(
    "relative",
    [
        "results/experiments/hybrid/manifest.json",
        "results/experiments/hybrid/metrics.json",
        "results/experiments/hybrid/comparison.json",
        "results/experiments/crossling/translations.jsonl",
        "results/experiments/crossling/public/dense_ko2en.jsonl",
        "results/baselines/public/bm25.jsonl",
        SUMMARY,
        NOTE,
        README,
    ],
)
def test_missing_required_file_is_exit_1(repo, capsys, relative):
    (repo / relative).unlink()
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and err.startswith(("error:", "MISMATCH"))


# ------------------------------------------------------------ 생성 구간(README·summary·노트) 불일치 감지


def first_row(text, name):
    return next(
        line for line in text.splitlines() if line.startswith((f"| [{name}]", f"| {name} |"))
    )


def change_number(text):
    row = first_row(text, "hybrid")
    return text.replace(row, row.replace("0.8551", "0.8552", 1))


def flip_verdict(text):
    row = first_row(text, "hybrid")
    return text.replace(row, row.replace("hypothesis-rejected", "hypothesis-confirmed"))


def delete_row(text):
    return text.replace(first_row(text, "rerank") + "\n", "")


def duplicate_row(text):
    row = first_row(text, "rerank")
    return text.replace(row, row + "\n" + row)


def swap_rows(text):
    a, b = first_row(text, "hybrid"), first_row(text, "rerank")
    return text.replace(a, "@@a").replace(b, a).replace("@@a", b)


def empty_range(text):
    return "\n"


def change_note_sentence(text):
    return text.replace("10000회", "5000회", 1)


def append_line(text):
    return text.rstrip("\n") + "\n\n손으로 쓴 줄\n"


RANGE_TAMPER = {
    "number changed": change_number,
    "verdict flipped": flip_verdict,
    "row deleted": delete_row,
    "row duplicated": duplicate_row,
    "rows swapped": swap_rows,
    "range emptied": empty_range,
    "sentence changed": change_note_sentence,
    "hand-written line appended": append_line,
}


@pytest.mark.parametrize("document", RANGES, ids=RANGES.keys())
@pytest.mark.parametrize("tamper", RANGE_TAMPER.values(), ids=RANGE_TAMPER.keys())
def test_generated_range_mismatch_is_exit_1(repo, capsys, document, tamper):
    edit_range(repo, document, tamper)
    code, _, err = run_tables(capsys, repo, "--check")
    relative = RANGES[document][0]
    assert code == 1
    assert f"MISMATCH {Path(relative).name}: M3 generated range differs" in err


@pytest.mark.parametrize("document", RANGES, ids=RANGES.keys())
def test_generated_range_mismatch_fails_the_release_check(repo, capsys, document):
    edit_range(repo, document, change_number)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1 and CHECK_M3 in failed_checks(out)
    assert CHECK_README not in failed_checks(out)


def drop_begin(text, markers):
    return text.replace(markers[0], "", 1)


def drop_end(text, markers):
    return text.replace(markers[1], "", 1)


def duplicate_pair(text, markers):
    return text.replace(markers[1], markers[1] + "\n" + markers[0] + "\n" + markers[1], 1)


def reversed_pair(text, markers):
    return (
        text.replace(markers[0], "@@b").replace(markers[1], markers[0]).replace("@@b", markers[1])
    )


MARKER_BROKEN = {
    "BEGIN removed": drop_begin,
    "END removed": drop_end,
    "pair duplicated": duplicate_pair,
    "END before BEGIN": reversed_pair,
}


@pytest.mark.parametrize("document", RANGES, ids=RANGES.keys())
@pytest.mark.parametrize("broken", MARKER_BROKEN.values(), ids=MARKER_BROKEN.keys())
def test_m3_marker_problem_is_exit_1(repo, capsys, document, broken):
    relative, markers = RANGES[document]
    edit_text(repo / relative, lambda t: broken(t, markers))
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "marker" in err


def test_baseline_range_is_still_checked_when_m3_is_present(repo, capsys):
    edit_text(
        repo / README,
        lambda t: t.replace(
            "| bm25 | test | 86 | 0 | 0.8551 ", "| bm25 | test | 86 | 0 | 0.8552 ", 1
        ),
    )
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "generated tables differ" in err


# ------------------------------------------------------------ 쓰기 모드


def test_write_mode_fills_the_three_ranges_and_check_passes(repo, capsys):
    original = {key: (repo / RANGES[key][0]).read_text("utf-8") for key in RANGES}
    for key in RANGES:
        edit_range(repo, key, empty_range)
    assert run_tables(capsys, repo, "--check")[0] == 1
    code, out, _ = run_tables(capsys, repo)
    assert code == 0 and "updated" in out
    assert run_tables(capsys, repo, "--check")[0] == 0
    for key, text in original.items():
        assert (repo / RANGES[key][0]).read_text("utf-8") == text, key


def test_write_mode_leaves_text_outside_the_ranges_alone(repo, capsys):
    edit_text(repo / README, lambda t: t.replace("## 한계", "## 한계 (손으로 쓴 제목)", 1))
    edit_range(repo, "README", change_number)
    assert run_tables(capsys, repo)[0] == 0
    text = (repo / README).read_text("utf-8")
    assert "## 한계 (손으로 쓴 제목)" in text
    assert run_tables(capsys, repo, "--check")[0] == 0


@pytest.mark.parametrize(
    ("name", "filename", "change"),
    [("hybrid", "comparison", bump_comparison), ("rerank", "metrics", bump_metrics)],
    ids=["comparison", "metrics"],
)
def test_write_mode_refuses_when_a_stored_m3_file_differs(repo, capsys, name, filename, change):
    edit_json(repo / f"results/experiments/{name}/{filename}.json", change)
    before = {key: (repo / RANGES[key][0]).read_bytes() for key in RANGES}
    code, _, err = run_tables(capsys, repo)
    assert code == 1 and "README untouched" in err
    assert before == {key: (repo / RANGES[key][0]).read_bytes() for key in RANGES}


# ------------------------------------------------------------ 내려받은 asset 검사 (--assets-dir)


@pytest.fixture
def downloaded(repo, tmp_path):
    out = tmp_path / "downloaded"
    out.mkdir()
    for row in release.parse_asset_table((repo / NOTE).read_text("utf-8")):
        shutil.copyfile(repo / row["path"], out / row["name"])
    return out


def run_assets(capsys, repo, directory):
    return run_release(capsys, repo, "--assets-dir", str(directory))


def asset(directory, path):
    return directory / path.replace("/", "__")


def test_downloaded_v02_assets_pass(repo, downloaded, capsys):
    code, out, _ = run_assets(capsys, repo, downloaded)
    assert code == 0, out
    assert out.count("OK  ") == 7
    assert len(list(downloaded.iterdir())) == len(release.default_assets(repo, "v0.2"))


def tamper_experiment_result(directory):
    path = asset(directory, "results/experiments/hybrid/public/rrf.jsonl")
    rows = read_jsonl(path)
    permute_doc_ids(rows)
    write_jsonl(path, rows)


def tamper_experiment_field(directory):
    path = asset(directory, "results/experiments/rerank/public/rerank.jsonl")
    rows = read_jsonl(path)
    rows[0]["body"] = "x"
    write_jsonl(path, rows)


def tamper_absolute_path(directory):
    path = asset(directory, "results/experiments/embedding/manifest.json")
    payload = json.loads(path.read_text("utf-8"))
    payload["where"] = "/Users/someone/cache"
    path.write_text(json.dumps(payload), encoding="utf-8")


def tamper_translation_key(directory):
    path = asset(directory, TRANSLATIONS)
    rows = read_jsonl(path)
    rows[0]["body"] = "x"
    write_jsonl(path, rows)


def append_byte(directory):
    with asset(directory, "results/experiments/chunking/metrics.json").open(
        "a", encoding="utf-8"
    ) as handle:
        handle.write("\n")


ASSET_TAMPER = {
    "experiment result changed": (tamper_experiment_result, {CHECK_SHA, CHECK_M3}),
    "experiment result gets an extra field": (tamper_experiment_field, {CHECK_FIELDS}),
    "manifest gets an absolute path": (tamper_absolute_path, {CHECK_FIELDS}),
    "translations get an extra key": (tamper_translation_key, {CHECK_FIELDS}),
    "one byte appended to metrics.json": (append_byte, {CHECK_SHA}),
    "baseline result changed": (
        lambda d: asset(d, "results/baselines/public/bm25.jsonl").write_bytes(b"{}\n"),
        {CHECK_SHA},
    ),
    "translations file missing": (lambda d: asset(d, TRANSLATIONS).unlink(), {CHECK_ALLOWED}),
    "experiment manifest missing": (
        lambda d: asset(d, "results/experiments/rerank/manifest.json").unlink(),
        {CHECK_ALLOWED},
    ),
    "experiment result file missing": (
        lambda d: asset(d, "results/experiments/chunking/kisa/chunk_max.jsonl").unlink(),
        {CHECK_ALLOWED},
    ),
    "comparison.json missing": (
        lambda d: asset(d, "results/experiments/embedding/comparison.json").unlink(),
        {CHECK_ALLOWED},
    ),
    "unlisted file uploaded": (lambda d: (d / "notes.txt").write_text("x"), {CHECK_ALLOWED}),
}


@pytest.mark.parametrize(("tamper", "expected"), ASSET_TAMPER.values(), ids=ASSET_TAMPER.keys())
def test_tampered_downloaded_v02_assets_fail(repo, downloaded, capsys, tamper, expected):
    tamper(downloaded)
    code, out, _ = run_assets(capsys, repo, downloaded)
    assert code == 1
    assert expected <= failed_checks(out)
    assert out.rstrip().endswith("check_release: FAILED")


def test_downloaded_asset_is_checked_even_when_the_repo_file_is_fine(repo, downloaded, capsys):
    tamper_experiment_result(downloaded)
    assert run_release(capsys, repo)[0] == 0
    assert run_assets(capsys, repo, downloaded)[0] == 1

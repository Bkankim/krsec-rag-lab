"""v1.0 릴리스 검사 테스트 - M5 표(README·노트 구간), 생성·판정 저장본 검사, v1.0 asset 허용·거부, 허용 필드, 내려받은 asset.

커밋된 `results/m5/**`와 문서를 임시 디렉터리로 복사해(릴리스 asset 사본과 같이 NVD 코퍼스 파일 없이) 변조 행렬을 돌린다.
모델·Ollama·Docker·외부 API·KISA 캐시·네트워크를 쓰지 않는다. v0.1~v0.3 범위는 test_release_check.py,
test_release_tables.py, test_release_v02.py, test_release_v03.py가 이미 본다. 여기서는 v1.0이 그 검사를 물려받는지만 대표 행으로 본다.
"""

import json
import re
import shutil
from pathlib import Path

import pytest
from test_release_support import ROOT, read_jsonl, release, tables, write_jsonl
from test_release_v02 import (  # noqa: F401  (memoized_bootstrap은 autouse 픽스처다)
    edit_json,
    edit_text,
    memoized_bootstrap,
)

from krsec_rag_lab.generation import judge_gen, pipeline

NOTE = "docs/release-v1.0.md"
NOTE_V03 = "docs/release-v0.3.md"
NOTE_V02 = "docs/release-v0.2.md"
NOTE_V01 = "docs/release-v0.1.md"
SUMMARY = "docs/experiments/summary.md"
README = "README.md"
PLAN = "PLAN.md"
GEN = "results/m5/generation"
JUD = "results/m5/judgments"
# 고정 목록(코드의 상수를 가져오지 않고 이슈 본문 그대로 적는다)
M5_FILES = (
    f"{GEN}/manifest.json",
    f"{GEN}/topk.json",
    f"{GEN}/public_k1.jsonl",
    f"{GEN}/public_k3.jsonl",
    f"{GEN}/public_k5.jsonl",
    f"{GEN}/kisa_k1.jsonl",
    f"{GEN}/kisa_k3.jsonl",
    f"{GEN}/kisa_k5.jsonl",
    f"{JUD}/manifest.json",
    f"{JUD}/summary.json",
    f"{JUD}/public.jsonl",
    f"{JUD}/kisa.jsonl",
)
M5_JSON = tuple(p for p in M5_FILES if p.endswith(".json"))
M5_JSONL = tuple(p for p in M5_FILES if p.endswith(".jsonl"))
GEN_MANIFEST = f"{GEN}/manifest.json"
TOPK = f"{GEN}/topk.json"
JUD_MANIFEST = f"{JUD}/manifest.json"
SUMMARY_JSON = f"{JUD}/summary.json"
PUBLIC_K3 = f"{GEN}/public_k3.jsonl"
KISA_K3 = f"{GEN}/kisa_k3.jsonl"
KISA_K1 = f"{GEN}/kisa_k1.jsonl"
KISA_JUDGE = f"{JUD}/kisa.jsonl"
PUBLIC_JUDGE = f"{JUD}/public.jsonl"
CHECK_M3 = "M3 metrics, comparison and tables rebuilt from the asset copies match"
CHECK_M4 = "M4 reports, manifest and tables rebuilt from the asset copies match"
CHECK_M5 = "M5 generation, judgments and tables rebuilt from the asset copies match"
CHECK_FIELDS = "only allowed fields"
CHECK_LISTED = "manifest-required files are listed"
CHECK_ALLOWED = "listed assets exist and are allowed"
CHECK_SHA = "asset sha256 matches the repo files and manifest inputs"
CHECK_README = "README tables rebuilt from the asset copies match"
M5_RANGES = {
    "README": (README, tables.README_M5),
    "note": (NOTE, tables.NOTE_M5_RANGE),
}
M3_RANGES = {
    "README": (README, tables.README_M3),
    "summary": (SUMMARY, tables.SUMMARY_RANGE),
    "v0.2 note": (NOTE_V02, tables.NOTE_RANGE),
    "v0.3 note": (NOTE_V03, tables.NOTE_RANGE),
    "v1.0 note": (NOTE, tables.NOTE_RANGE),
}
M4_RANGES = {
    "README": (README, tables.README_M4),
    "v0.3 note": (NOTE_V03, tables.NOTE_M4_RANGE),
    "v1.0 note": (NOTE, tables.NOTE_M4_RANGE),
}
MOTIVE = re.compile(r"면접|학습|공부|포트폴리오|interview|learning|portfolio")


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    """릴리스 asset 사본과 같은 파일 + README·summary·v0.2/v0.3/v1.0 노트. NVD 코퍼스 파일은 없다."""
    root = tmp_path_factory.mktemp("v10")
    for relative in (
        *release.default_assets(ROOT, "v1.0"),
        README,
        SUMMARY,
        NOTE_V02,
        NOTE_V03,
        NOTE,
    ):
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
    """파일을 바꾼 뒤 v1.0 노트의 asset 표(크기·sha256)를 현재 상태로 다시 쓴다(실패가 내용 검사 때문이도록)."""
    path = repo / NOTE
    text = path.read_text(encoding="utf-8")
    listed = [row["path"] for row in release.parse_asset_table(text)]
    table = release.render_asset_table(repo, listed)
    start = text.index(release.BEGIN) + len(release.BEGIN)
    path.write_text(
        text[:start] + "\n\n" + table + "\n" + text[text.index(release.END) :], encoding="utf-8"
    )


def edit_range(repo, ranges, key, change):
    relative, (begin, end) = ranges[key]

    def apply(text):
        start, stop = text.index(begin) + len(begin), text.index(end)
        return text[:start] + change(text[start:stop]) + text[stop:]

    edit_text(repo / relative, apply)


def load(repo, relative):
    return json.loads((repo / relative).read_text(encoding="utf-8"))


def mutate_rows(relative, change):
    def apply(repo):
        rows = read_jsonl(repo / relative)
        change(rows)
        write_jsonl(repo / relative, rows)

    return apply


def mutate_json(relative, change):
    return lambda repo: edit_json(repo / relative, change)


def add_row(path):
    """v1.0 노트에 허용 목록 밖(또는 다른 범위)의 asset 행을 하나 더한다."""

    def add(repo):
        row = next(
            line
            for line in (repo / NOTE).read_text("utf-8").splitlines()
            if "| `results/m4/collection/report.json` |" in line
        )
        extra = row.replace("results/m4/collection/report.json", path).replace(
            "results__m4__collection__report.json", path.replace("/", "__")
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


# ------------------------------------------------------------ 커밋된 리포


def test_committed_v10_note_passes_with_nine_checks(capsys):
    code, out, _ = run_release(capsys, ROOT)
    assert code == 0, out
    assert out.count("OK  ") == 9 and "FAIL" not in out
    assert out.rstrip().endswith("check_release: OK")


@pytest.mark.parametrize(
    ("note", "n_checks"),
    [(NOTE_V03, 8), (NOTE_V02, 7), (NOTE_V01, 6)],
    ids=["v0.3", "v0.2", "v0.1"],
)
def test_committed_older_notes_still_pass_with_their_own_checks(capsys, note, n_checks):
    code, out, _ = run_release(capsys, ROOT, note=note)
    assert code == 0 and out.count("OK  ") == n_checks and "M5" not in out


def test_default_note_is_still_the_v01_note(capsys):
    code = release.main(["--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0 and out.count("OK  ") == 6 and "M5" not in out


def test_committed_check_covers_baseline_m3_m4_and_m5(capsys):
    code, out, err = run_tables(capsys, ROOT, "--check")
    assert code == 0, err
    assert "5 experiments" in out
    m5_line = next(line for line in out.splitlines() if line.startswith("OK: M5 "))
    assert "match" in m5_line and "2 tracks x 3 k" in m5_line and "102 judged rows" in m5_line
    m4_line = next(line for line in out.splitlines() if line.startswith("OK: M4 "))
    assert "release-v0.3" in m4_line and "release-v1.0" in m4_line


def test_committed_note_lists_every_allowed_asset_with_current_sha256():
    note = (ROOT / NOTE).read_text(encoding="utf-8")
    listed = release.parse_asset_table(note)
    expected = release.render_asset_table(ROOT, release.default_assets(ROOT, "v1.0"))
    assert [r["path"] for r in listed] == release.default_assets(ROOT, "v1.0")
    assert note.count(expected.strip()) == 1


def test_print_assets_for_the_v10_note_is_what_the_note_lists(capsys):
    code = release.main(["--root", str(ROOT), "--print-assets", "--note", NOTE])
    out = capsys.readouterr().out
    assert code == 0
    assert (ROOT / NOTE).read_text(encoding="utf-8").count(out.strip()) == 1
    assert "results__m5__generation__public_k3.jsonl" in out


def test_v10_assets_are_the_v03_assets_plus_exactly_the_twelve_m5_files():
    v10 = set(release.default_assets(ROOT, "v1.0"))
    v03 = set(release.default_assets(ROOT, "v0.3"))
    assert v03 < v10
    assert v10 - v03 == set(M5_FILES) and len(M5_FILES) == 12
    assert set(M5_FILES) <= set(release.required_paths(ROOT, "v1.0"))
    for profile in ("v0.3", "v0.2", "v0.1"):
        assert not set(M5_FILES) & set(release.required_paths(ROOT, profile)), profile
        assert not set(M5_FILES) & set(release.default_assets(ROOT, profile)), profile
    assert set(release.required_paths(ROOT, "v1.0")) - set(
        release.required_paths(ROOT, "v0.3")
    ) == set(M5_FILES)


def test_the_fixed_lists_in_the_scripts_are_the_issue_list():
    assert sorted(release.M5_ASSETS) == sorted(M5_FILES)
    assert sorted(p.as_posix() for p in tables.M5_FILES) == sorted(M5_FILES)


def test_the_allowed_row_keys_are_exactly_the_generation_and_judgment_keys():
    assert release.M5_GENERATION_KEYS == set(pipeline.ROW_KEYS)
    assert release.M5_JUDGMENT_KEYS == set(judge_gen.ROW_KEYS)
    assert len(release.M5_GENERATION_KEYS) == 17 and len(release.M5_JUDGMENT_KEYS) == 14
    assert set(pipeline.PUBLIC_ROW_KEYS) - set(pipeline.ROW_KEYS) == {"answer"}


def test_committed_note_names_the_required_sections_and_commands():
    note = (ROOT / NOTE).read_text(encoding="utf-8")
    for heading in (
        "무엇이 들어 있나",
        "M0~M5 요약",
        "M3 판정",
        "M4 결과",
        "M5 결과",
        "재현",
        "데이터와 모델",
        "asset",
        "한계",
    ):
        assert re.search(rf"^## {heading}$", note, re.MULTILINE), heading
    for heading in (
        "새 클론에서 모델·네트워크·KISA 캐시 없이 되는 것",
        "KISA 사이트 접근이 필요한 것: 전체 수집 \\(M4\\)",
        "Docker와 모델이 필요한 것: 동기화와 멱등성 검증 \\(M4\\)",
        "로컬 Ollama가 필요한 것: 생성 \\(M5\\)",
        "외부 모델 API 2종이 필요한 것: 판정 \\(M5\\)",
        "langchain 그룹이 필요한 것: 통합 \\(M5\\)",
    ):
        assert re.search(rf"^### {heading}$", note, re.MULTILINE), heading
    for word in (
        "scripts/collect_kisa_full.py --cache-root <KISA-ROOT>",
        "--verify-idempotency",
        "ollama pull qwen3:8b",
        "scripts/run_generation.py --track kisa --kisa-root <KISA-ROOT>",
        "scripts/judge_generation.py --kisa-root <KISA-ROOT>",
        "--metrics-only",
        "--summary-only",
        "uv sync --locked --group langchain",
        "scripts/run_langgraph.py --compare",
        "make_readme_tables.py --check",
        "check_release.py --note docs/release-v1.0.md",
        "check_release.py --note docs/release-v0.3.md",
        "--assets-dir",
        "check_kisa_leaks",
        "LICENSES/README.md",
        "KISA 공지 본문과 KISA 트랙의",
    ):
        assert word in note, word
    for name in ("m5-generation.md", "m5-generation-eval.md", "m5-integration.md"):
        assert f"]({name})" in note, name


def test_committed_note_milestone_table_covers_m0_to_m5():
    note = (ROOT / NOTE).read_text(encoding="utf-8")
    section = note[note.index("## M0~M5 요약") : note.index("## M3 판정")]
    for milestone, release_name in (
        ("M0", "-"),
        ("M1", "-"),
        ("M2", "v0.1"),
        ("M3", "v0.2"),
        ("M4", "v0.3"),
        ("M5", "v1.0"),
    ):
        assert re.search(
            rf"^\| {milestone} \|.*\| {re.escape(release_name)} \|", section, re.MULTILINE
        )


def test_committed_docs_have_no_motive_words_or_dashes_or_personal_paths():
    for relative in (README, PLAN, NOTE):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert not MOTIVE.search(text), relative
        assert "—" not in text, relative  # em dash
        assert "/Users" not in text, relative
    assert "단독 프로젝트" in (ROOT / README).read_text(encoding="utf-8")
    assert "단독 프로젝트" in (ROOT / NOTE).read_text(encoding="utf-8")


def test_committed_docs_links_resolve():
    for relative in (README, NOTE):
        text = (ROOT / relative).read_text(encoding="utf-8")
        base = (ROOT / relative).parent
        for target in re.findall(r"\]\(((?!https?:|\.\./\.\./)[^)#\s]+)", text):
            assert (base / target).resolve().exists(), (relative, target)
    readme = (ROOT / README).read_text(encoding="utf-8")
    for link in (
        "docs/release-v1.0.md",
        "docs/m5-generation.md",
        "docs/m5-generation-eval.md",
        "docs/m5-integration.md",
        "docs/release-v0.3.md",
    ):
        assert f"]({link})" in readme, link


def test_readme_status_is_m0_to_m5_complete_v10_and_keeps_the_older_lines():
    readme = (ROOT / README).read_text(encoding="utf-8")
    status = readme[readme.index("## 상태") : readme.index("## 평가 트랙과 재현")]
    assert "**M0~M5 완료, v1.0.**" in status and "M6" in status and "제외" in status
    for older in ("M5 완료, v1.0", "M4 완료, v0.3", "M3 완료, v0.2", "M2 완료, v0.1"):
        assert older in status, older
    assert "진행 중" not in status and "예정" not in status
    markers = (tables.BEGIN, tables.END, *tables.README_M3, *tables.README_M4, *tables.README_M5)
    for marker in markers:
        assert readme.count(marker) == 1, marker
    assert (
        readme.index(tables.END)
        < readme.index(tables.README_M3[0])
        < readme.index(tables.README_M4[0])
        < readme.index(tables.README_M5[0])
    )
    assert re.search(r"^## M5 결과$", readme, re.MULTILINE)


def test_readme_has_no_stale_forward_looking_sentences():
    readme = (ROOT / README).read_text(encoding="utf-8")
    assert "M5 이후의 로드맵" not in readme
    assert "VRAM" not in readme  # VRAM 실측은 M6(제외)의 일이다
    assert "(M4)" not in readme.split("## 상태")[1].split("## 평가 트랙과 재현")[0]


def test_plan_milestone_table_marks_m0_to_m5_complete_and_m6_excluded():
    plan = (ROOT / PLAN).read_text(encoding="utf-8")
    rows = {
        line.split("|")[1].strip(): line.split("|")[-2].strip()
        for line in plan.splitlines()
        if re.match(r"^\| M\d", line)
    }
    assert rows == {
        "M0": "완료",
        "M1": "완료",
        "M2": "완료, v0.1",
        "M3": "완료, v0.2",
        "M4": "완료, v0.3",
        "M5": "완료, v1.0",
        "M6 (선택)": "제외 (이 범위에 넣지 않았다)",
    }
    assert "## 설계 원칙" in plan and "## 목적" in plan


def test_committed_note_model_judges_and_prompt_match_the_manifests():
    note = (ROOT / NOTE).read_text(encoding="utf-8")
    gen, jud = load(ROOT, GEN_MANIFEST), load(ROOT, JUD_MANIFEST)
    model = gen["model"]
    assert f"`{model['name']}`" in note and f"digest `{model['digest']}`" in note
    assert f"서버 {model['ollama_version']}" in note and model["license"] in note
    options = gen["request"]["options"]
    for key in ("temperature", "seed", "num_ctx", "num_predict"):
        assert f"`{key} {options[key]}`" in note, key
    assert f"sha256 `{gen['prompt']['sha256']}`" in note
    assert (
        f"A `{jud['judges']['A']['model']}`" in note
        and f"B `{jud['judges']['B']['model']}`" in note
    )
    assert f"유효율 {jud['rules']['min_both_valid_rate']:.0%} 하한" in note
    assert f"성공률 하한 {gen['output_contract']['success_floor']:.0%}" in note


def test_real_m5_files_pass_the_field_checks():
    for path in M5_JSON:
        assert release.check_fields("m5_json", ROOT / path) == [], path
        assert release.asset_kind(path, "v1.0") == "m5_json", path
    kinds = {
        **{f"{GEN}/public_k{k}.jsonl": "m5_gen_public" for k in (1, 3, 5)},
        **{f"{GEN}/kisa_k{k}.jsonl": "m5_gen_kisa" for k in (1, 3, 5)},
        PUBLIC_JUDGE: "m5_judge",
        KISA_JUDGE: "m5_judge",
    }
    for path, kind in kinds.items():
        assert release.asset_kind(path, "v1.0") == kind, path
        assert release.check_fields(kind, ROOT / path) == [], path
    for path in M5_FILES:
        for profile in ("v0.3", "v0.2", "v0.1"):
            assert release.asset_kind(path, profile) is None, (path, profile)


# ------------------------------------------------------------ 복사본: 통과와 M5 켜짐 조건


def test_synthetic_copy_passes_both_checks(repo, capsys):
    code, out, _ = run_release(capsys, repo)
    assert code == 0, out
    assert out.count("OK  ") == 9
    code, out, err = run_tables(capsys, repo, "--check")
    assert code == 0, err
    assert "OK: M5 " in out and "OK: M4 " in out


def test_m5_is_off_without_the_results_dir_and_without_the_readme_markers(repo, capsys):
    """과거 범위(M5 구간이 없는 README, results/m5 없음)는 M5를 보지 않고 v1.0 노트도 읽지 않는다."""
    shutil.rmtree(repo / "results/m5")
    (repo / NOTE).unlink()
    begin, end = tables.README_M5
    edit_text(repo / README, lambda t: t[: t.index(begin)] + t[t.index(end) + len(end) :])
    code, out, err = run_tables(capsys, repo, "--check")
    assert code == 0, err
    assert "M5" not in out and "OK: M4 " in out and "5 experiments" in out


def test_results_dir_without_the_readme_markers_turns_m5_on_and_fails(repo, capsys):
    begin, end = tables.README_M5
    edit_text(repo / README, lambda t: t.replace(begin, "").replace(end, ""))
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "marker" in err


def test_readme_markers_without_the_results_dir_turn_m5_on_and_fail(repo, capsys):
    shutil.rmtree(repo / "results/m5")
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "missing required file: results/m5/" in err


def test_removing_the_m5_markers_from_a_copy_without_the_results_dir_still_passes_m4(repo, capsys):
    shutil.rmtree(repo / "results/m5")
    begin, end = tables.README_M5
    edit_text(repo / README, lambda t: t[: t.index(begin)] + t[t.index(end) + len(end) :])
    assert run_tables(capsys, repo, "--check")[0] == 0


@pytest.mark.parametrize("relative", M5_FILES)
def test_missing_m5_input_is_exit_1(repo, capsys, relative):
    (repo / relative).unlink()
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and f"missing required file: {relative}" in err
    assert "Traceback" not in err


@pytest.mark.parametrize("relative", [NOTE, README])
def test_missing_m5_document_is_exit_1(repo, capsys, relative):
    (repo / relative).unlink()
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "missing required file" in err


def test_the_v10_note_path_can_be_given_explicitly(repo, tmp_path, capsys):
    """문서가 없는 asset 사본(`--root`)도 --note-v10으로 노트 경로를 주면 검증된다."""
    docs = tmp_path / "docs"
    docs.mkdir()
    shutil.move(repo / NOTE, docs / "v10.md")
    assert run_tables(capsys, repo, "--check")[0] == 1
    code, out, err = run_tables(capsys, repo, "--check", "--note-v10", str(docs / "v10.md"))
    assert code == 0, err
    assert "OK: M5 " in out


# ------------------------------------------------------------ 생성 구간(README·노트) 불일치 감지


def first_line(text, needle):
    return next(line for line in text.splitlines() if needle in line)


def change_config_number(text):
    row = first_line(text, "| 생성 질문 수 |")
    return text.replace(row, row.replace("144", "145", 1))


def change_topk_number(text):
    row = first_line(text, "| 1 | 1.000 | 0 | 0 | 1.000 | 0.142 |")
    return text.replace(row, row.replace("0.142", "0.143", 1))


def change_kisa_topk_tokens(text):
    row = first_line(text, "| 5 | 1.000 | 0 | 0 | 1.000 | 0.048 |")
    return text.replace(row, row.replace("4824", "4825", 1))


def change_faithfulness_row(text):
    row = first_line(text, "| public (test) | cve_explicit | 35 | 0.600 |")
    return text.replace(row, row.replace("0.600", "0.601", 1))


def change_correctness_row(text):
    row = first_line(text, "| kisa (all) | all | 39 | 0.821 |")
    return text.replace(row, row.replace("0.821", "0.822", 1))


def change_abstain_row(text):
    row = first_line(text, "| public (test) | no_answer | 12 |")
    return text.replace(row, row.replace("| 1.000 |", "| 0.999 |", 1))


def change_disagreement_row(text):
    row = first_line(text, "| public | correctness |")
    return text.replace(row, row.replace("| 7 |", "| 6 |", 1))


def change_digest(text):
    row = first_line(text, "| 모델 digest |")
    return text.replace(row, row.replace("500a1f067a9f", "500a1f067a9e", 1))


def change_judge_model(text):
    return text.replace("`gpt-6.1-sol`", "`gpt-6.1-luna`", 1)


def delete_row(text):
    return text.replace(first_line(text, "| 판정자 호출 |") + "\n", "")


def duplicate_row(text):
    row = first_line(text, "| 판정자 호출 |")
    return text.replace(row, row + "\n" + row)


def swap_rows(text):
    a, b = first_line(text, "| 생성 모델 |"), first_line(text, "| 모델 digest |")
    return text.replace(a, "@@a").replace(b, a).replace("@@a", b)


def empty_range(text):
    return "\n"


def change_sentence(text):
    return text.replace("손으로 고치지 않는다", "손으로 고쳐도 된다", 1)


def append_line(text):
    return text.rstrip("\n") + "\n\n손으로 쓴 줄\n"


M5_RANGE_TAMPER = {
    "config number changed": change_config_number,
    "top-k public number changed": change_topk_number,
    "top-k kisa number changed": change_kisa_topk_tokens,
    "faithfulness row changed": change_faithfulness_row,
    "correctness row changed": change_correctness_row,
    "abstain row changed": change_abstain_row,
    "disagreement row changed": change_disagreement_row,
    "model digest changed": change_digest,
    "judge model changed": change_judge_model,
    "row deleted": delete_row,
    "row duplicated": duplicate_row,
    "rows swapped": swap_rows,
    "range emptied": empty_range,
    "sentence changed": change_sentence,
    "hand-written line appended": append_line,
}


@pytest.mark.parametrize("document", M5_RANGES, ids=M5_RANGES.keys())
@pytest.mark.parametrize("tamper", M5_RANGE_TAMPER.values(), ids=M5_RANGE_TAMPER.keys())
def test_m5_generated_range_mismatch_is_exit_1(repo, capsys, document, tamper):
    edit_range(repo, M5_RANGES, document, tamper)
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1
    assert f"MISMATCH {Path(M5_RANGES[document][0]).name}: M5 generated range differs" in err


@pytest.mark.parametrize("document", M5_RANGES, ids=M5_RANGES.keys())
@pytest.mark.parametrize("tamper", M5_RANGE_TAMPER.values(), ids=M5_RANGE_TAMPER.keys())
def test_m5_generated_range_mismatch_fails_the_release_check(repo, capsys, document, tamper):
    edit_range(repo, M5_RANGES, document, tamper)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_M5 in failed_checks(out)
    assert not {CHECK_README, CHECK_M3, CHECK_M4, CHECK_SHA, CHECK_FIELDS} & failed_checks(out)


def test_changing_only_a_number_in_the_note_m5_range_is_caught_by_both_checks(repo, capsys):
    """README는 그대로 두고 노트의 M5 수치 하나만 바꾼 변조는 --check와 v1.0 릴리스 검사가 둘 다 잡는다."""
    edit_range(repo, M5_RANGES, "note", change_faithfulness_row)
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "release-v1.0.md: M5 generated range differs" in err
    assert "README.md" not in err
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1 and failed_checks(out) == {CHECK_M5}


def first_row(text, name):
    return next(
        line for line in text.splitlines() if line.startswith((f"| [{name}]", f"| {name} |"))
    )


def change_m3_number(text):
    row = first_row(text, "hybrid")
    return text.replace(row, row.replace("0.8551", "0.8552", 1))


def delete_m3_row(text):
    return text.replace(first_row(text, "rerank") + "\n", "")


def change_m3_sentence(text):
    return text.replace("10000회", "5000회", 1)


M3_RANGE_TAMPER = {
    "number changed": change_m3_number,
    "row deleted": delete_m3_row,
    "range emptied": empty_range,
    "sentence changed": change_m3_sentence,
    "hand-written line appended": append_line,
}


@pytest.mark.parametrize("document", M3_RANGES, ids=M3_RANGES.keys())
@pytest.mark.parametrize("tamper", M3_RANGE_TAMPER.values(), ids=M3_RANGE_TAMPER.keys())
def test_m3_range_mismatch_is_caught_in_every_document_with_m5_on(repo, capsys, document, tamper):
    """M5가 켜지면 --check는 v0.2, v0.3, v1.0 노트의 M3 구간을 모두 본다."""
    edit_range(repo, M3_RANGES, document, tamper)
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1
    assert f"MISMATCH {Path(M3_RANGES[document][0]).name}: M3 generated range differs" in err


@pytest.mark.parametrize("document", ["README", "summary", "v1.0 note"])
@pytest.mark.parametrize("tamper", M3_RANGE_TAMPER.values(), ids=M3_RANGE_TAMPER.keys())
def test_m3_range_mismatch_fails_the_v10_release_check(repo, capsys, document, tamper):
    edit_range(repo, M3_RANGES, document, tamper)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_M3 in failed_checks(out)
    assert CHECK_M5 not in failed_checks(out)


def change_m4_number(text):
    row = first_line(text, "| 상세 성공 |")
    return text.replace(row, row.replace("2590", "2591", 1))


def delete_m4_row(text):
    return text.replace(first_line(text, "| 누락 (") + "\n", "")


def flip_m4_verdict(text):
    return text.replace("검증 통과", "검증 실패", 1)


M4_RANGE_TAMPER = {
    "number changed": change_m4_number,
    "row deleted": delete_m4_row,
    "verdict flipped": flip_m4_verdict,
    "range emptied": empty_range,
    "hand-written line appended": append_line,
}


@pytest.mark.parametrize("document", M4_RANGES, ids=M4_RANGES.keys())
@pytest.mark.parametrize("tamper", M4_RANGE_TAMPER.values(), ids=M4_RANGE_TAMPER.keys())
def test_m4_range_mismatch_is_caught_in_every_document_with_m5_on(repo, capsys, document, tamper):
    edit_range(repo, M4_RANGES, document, tamper)
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1
    assert f"MISMATCH {Path(M4_RANGES[document][0]).name}: M4 generated range differs" in err


@pytest.mark.parametrize("tamper", M4_RANGE_TAMPER.values(), ids=M4_RANGE_TAMPER.keys())
def test_m4_range_mismatch_in_the_v10_note_fails_the_v10_release_check(repo, capsys, tamper):
    edit_range(repo, M4_RANGES, "v1.0 note", tamper)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1 and CHECK_M4 in failed_checks(out) and CHECK_M5 not in failed_checks(out)


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


@pytest.mark.parametrize("document", M5_RANGES, ids=M5_RANGES.keys())
@pytest.mark.parametrize("broken", MARKER_BROKEN.values(), ids=MARKER_BROKEN.keys())
def test_m5_marker_problem_is_exit_1(repo, capsys, document, broken):
    relative, markers = M5_RANGES[document]
    edit_text(repo / relative, lambda t: broken(t, markers))
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "marker" in err


@pytest.mark.parametrize("document", M5_RANGES, ids=M5_RANGES.keys())
def test_m5_marker_problem_fails_the_release_check(repo, capsys, document):
    relative, markers = M5_RANGES[document]
    edit_text(repo / relative, lambda t: drop_begin(t, markers))
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1 and CHECK_M5 in failed_checks(out)


def test_readme_without_the_m5_range_fails_the_release_check_even_though_older_notes_pass(
    repo, capsys
):
    begin, end = tables.README_M5
    edit_text(repo / README, lambda t: t[: t.index(begin)] + t[t.index(end) + len(end) :])
    code, out, _ = run_release(capsys, repo)
    assert code == 1 and CHECK_M5 in failed_checks(out)
    assert run_release(capsys, repo, note=NOTE_V03)[0] == 0


def test_baseline_m3_and_m4_ranges_are_still_checked_when_m5_is_present(repo, capsys):
    edit_text(
        repo / README,
        lambda t: t.replace(
            "| bm25 | test | 86 | 0 | 0.8551 ", "| bm25 | test | 86 | 0 | 0.8552 ", 1
        ),
    )
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "generated tables differ" in err


# ------------------------------------------------------------ M5 저장본 자체가 바뀌었을 때


def set_in(container_path, value):
    def change(payload):
        node = payload
        for key in container_path[:-1]:
            node = node[key]
        node[container_path[-1]] = value

    return change


def first_cell(payload, **where):
    return next(c for c in payload["cells"] if all(c[k] == v for k, v in where.items()))


def change_topk_cell(payload):
    first_cell(payload, track="public", k=3, split="all", query_type="all")[
        "parse_success_rate"
    ] = 0.5


def change_summary_cell(payload):
    first_cell(payload, track="kisa", split="all", query_type="all")["n_judged"] += 1


def flip_abstain(rows):
    rows[0]["abstain"] = not rows[0]["abstain"]


def add_answer(rows):
    rows[0]["answer"] = "합성 답"


def drop_last_row(rows):
    rows.pop()


def duplicate_first_row(rows):
    rows.append(dict(rows[0]))


def change_label(rows):
    row = next(r for r in rows if r["status"] == "judged")
    row["faithfulness_A"] = "unsupported"
    row["faithfulness_reason_A"] = "claims_not_in_context"


def change_k(rows):
    rows[0]["k"] = 99


SOURCE_TAMPER = {
    "topk.json cell value": mutate_json(TOPK, change_topk_cell),
    "summary.json cell value": mutate_json(SUMMARY_JSON, change_summary_cell),
    "generation run_id": mutate_json(GEN_MANIFEST, set_in(["run_id"], "0" * 16)),
    "generation model digest": mutate_json(GEN_MANIFEST, set_in(["model", "digest"], "0" * 64)),
    "judgments manifest status": mutate_json(JUD_MANIFEST, set_in(["status"], "partial")),
    "judgments topk_sha256": mutate_json(
        JUD_MANIFEST, set_in(["generation", "topk_sha256"], "0" * 64)
    ),
    "public k3 abstain flipped": mutate_rows(PUBLIC_K3, flip_abstain),
    "public k1 row dropped": mutate_rows(f"{GEN}/public_k1.jsonl", drop_last_row),
    "kisa k3 row duplicated": mutate_rows(KISA_K3, duplicate_first_row),
    "kisa k5 k changed": mutate_rows(f"{GEN}/kisa_k5.jsonl", change_k),
    "kisa k1 answer added": mutate_rows(KISA_K1, add_answer),
    "kisa judgment label changed": mutate_rows(KISA_JUDGE, change_label),
    "public judgment row dropped": mutate_rows(PUBLIC_JUDGE, drop_last_row),
}


@pytest.mark.parametrize("tamper", SOURCE_TAMPER.values(), ids=SOURCE_TAMPER.keys())
def test_changing_only_an_m5_input_is_exit_1(repo, capsys, tamper):
    """저장본만 바꾸고 문서·manifest를 그대로 두면 문서와 비교하기 전에 저장본 검사로 실패한다."""
    tamper(repo)
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "MISMATCH results/m5:" in err
    assert "Traceback" not in err


@pytest.mark.parametrize("tamper", SOURCE_TAMPER.values(), ids=SOURCE_TAMPER.keys())
def test_changing_an_m5_input_fails_the_release_check_with_a_fresh_asset_table(
    repo, capsys, tamper
):
    tamper(repo)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1 and CHECK_M5 in failed_checks(out)
    assert out.rstrip().endswith("check_release: FAILED")


@pytest.mark.parametrize("tamper", SOURCE_TAMPER.values(), ids=SOURCE_TAMPER.keys())
def test_write_mode_refuses_when_m5_inputs_disagree(repo, capsys, tamper):
    tamper(repo)
    before = (repo / README).read_text(encoding="utf-8")
    code, _, err = run_tables(capsys, repo)
    assert code == 1 and "README untouched" in err
    assert (repo / README).read_text(encoding="utf-8") == before


MALFORMED_FILES = {
    "generation manifest is not an object": (GEN_MANIFEST, "[]"),
    "generation manifest is empty": (GEN_MANIFEST, "{}"),
    "generation manifest is not json": (GEN_MANIFEST, "{"),
    "judgments manifest is not an object": (JUD_MANIFEST, "[1]"),
    "judgments manifest is not json": (JUD_MANIFEST, "not json"),
    "topk.json is empty": (TOPK, "{}"),
    "topk.json is not json": (TOPK, "{"),
    "summary.json is not an object": (SUMMARY_JSON, "[]"),
    "public judgments are not json": (PUBLIC_JUDGE, "{\n"),
    "kisa generation rows are not json": (KISA_K3, "{\n"),
    "public generation rows are empty": (f"{GEN}/public_k5.jsonl", ""),
}


@pytest.mark.parametrize(("relative", "text"), MALFORMED_FILES.values(), ids=MALFORMED_FILES.keys())
def test_a_malformed_m5_file_is_exit_1_not_a_traceback(repo, capsys, relative, text):
    (repo / relative).write_text(text, encoding="utf-8")
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and err.startswith(("error: ", "MISMATCH"))
    assert "Traceback" not in err


@pytest.mark.parametrize(("relative", "text"), MALFORMED_FILES.values(), ids=MALFORMED_FILES.keys())
def test_a_malformed_m5_file_fails_the_release_check_without_a_traceback(
    repo, capsys, relative, text
):
    (repo / relative).write_text(text, encoding="utf-8")
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1 and CHECK_M5 in failed_checks(out)
    assert out.rstrip().endswith("check_release: FAILED")


def test_write_mode_fills_the_m5_ranges_and_check_passes(repo, capsys):
    for key in M5_RANGES:
        edit_range(repo, M5_RANGES, key, empty_range)
    assert run_tables(capsys, repo, "--check")[0] == 1
    code, _out, err = run_tables(capsys, repo)
    assert code == 0, err
    assert (repo / README).read_text("utf-8") == (ROOT / README).read_text("utf-8")
    assert (repo / NOTE).read_text("utf-8") == (ROOT / NOTE).read_text("utf-8")
    assert run_tables(capsys, repo, "--check")[0] == 0


def test_write_mode_leaves_text_outside_the_ranges_alone(repo, capsys):
    edit_text(repo / NOTE, lambda t: t.replace("## 한계", "## 한계 (손으로 쓴 제목)", 1))
    edit_text(repo / README, lambda t: t.replace("## M5 결과", "## M5 결과 (손으로 쓴 제목)", 1))
    edit_range(repo, M5_RANGES, "note", change_digest)
    assert run_tables(capsys, repo)[0] == 0
    assert "## 한계 (손으로 쓴 제목)" in (repo / NOTE).read_text("utf-8")
    assert "## M5 결과 (손으로 쓴 제목)" in (repo / README).read_text("utf-8")
    assert run_tables(capsys, repo, "--check")[0] == 0


# ------------------------------------------------------------ v1.0 asset 허용·거부, 필수 asset


def test_a_later_unknown_release_profile_is_still_a_failed_check(repo, capsys):
    shutil.copyfile(repo / NOTE, repo / "docs/release-v1.1.md")
    code, out, _ = run_release(capsys, repo, note="docs/release-v1.1.md")
    assert code == 1 and "FAIL release profile" in out and out.rstrip().endswith("FAILED")


@pytest.mark.parametrize(
    ("name", "profile"),
    [
        ("release-v0.1.md", "v0.1"),
        ("release-v0.3.md", "v0.3"),
        ("release-v1.0.md", "v1.0"),
        ("release-v1.0.md.bak", "v0.1"),
    ],
)
def test_profile_comes_from_the_note_file_name(name, profile):
    assert release.profile_of(Path("docs") / name) == profile


@pytest.mark.parametrize("old_note", [NOTE_V03, NOTE_V02, NOTE_V01])
def test_older_notes_do_not_allow_the_m5_assets(repo, capsys, old_note):
    shutil.copyfile(repo / NOTE, repo / old_note)
    code, out, _ = run_release(capsys, repo, note=old_note)
    assert code == 1
    assert CHECK_ALLOWED in failed_checks(out)
    for path in M5_FILES:
        assert f"{path}: not an allowed asset" in out, path


NOT_ALLOWED = [
    "results/m5/generation/public_k2.jsonl",
    "results/m5/generation/public_k7.jsonl",
    "results/m5/generation/kisa_k3.json",
    "results/m5/generation/extra.json",
    "results/m5/generation/kisa_answers_k3.jsonl",
    "results/m5/judgments/limit_events.json",
    "results/m5/judgments/other.jsonl",
    "results/m5/judgments/public_k3.jsonl",
    "results/m5/other/manifest.json",
    "data/m5/generation/kisa_k3.jsonl",
    "data/m5/judgments/cache/x.json",
    "src/krsec_rag_lab/generation/pipeline.py",
    "results/m4/collection/extra.json",
    "fixtures/nvd/cves.jsonl",
    "README.md",
    "docs/m5-generation.md",
]


@pytest.mark.parametrize("path", NOT_ALLOWED)
def test_v10_asset_outside_the_allow_list_is_exit_1(repo, capsys, path):
    add_row(path)(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_ALLOWED in failed_checks(out)
    assert out.rstrip().endswith("check_release: FAILED")


@pytest.mark.parametrize("path", M5_FILES)
def test_note_missing_an_m5_asset_is_exit_1(repo, capsys, path):
    drop_rows(path)(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_LISTED in failed_checks(out)
    assert f"{path}: required by manifest.json but not listed" in out
    assert out.rstrip().endswith("check_release: FAILED")


@pytest.mark.parametrize("path", M5_FILES)
def test_deleting_an_m5_file_together_with_its_note_row_still_fails(repo, capsys, path):
    """파일과 노트 행을 함께 지워도 고정 목록이 요구하므로 실패한다."""
    drop_rows(path)(repo)
    (repo / path).unlink()
    code, out, _ = run_release(capsys, repo)
    assert code == 1 and CHECK_LISTED in failed_checks(out)
    assert f"{path}: required by manifest.json but not listed" in out


@pytest.mark.parametrize("path", M5_FILES)
def test_deleting_only_an_m5_file_fails_the_release_check(repo, capsys, path):
    (repo / path).unlink()
    code, out, _ = run_release(capsys, repo)
    assert code == 1 and CHECK_ALLOWED in failed_checks(out)
    assert f"{path}: file not found" in out


def test_note_missing_all_m5_assets_is_exit_1(repo, capsys):
    drop_rows(*M5_FILES)(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert out.count("required by manifest.json but not listed") == len(M5_FILES)


REQUIRED_V03 = release.required_paths(ROOT, "v0.3")


@pytest.mark.parametrize("path", REQUIRED_V03)
def test_note_missing_a_v03_asset_is_exit_1(repo, capsys, path):
    """v1.0은 v0.3의 필수 파일 검사를 모두 물려받는다: 베이스라인·M3·M4 asset이 빠져도 실패한다."""
    drop_rows(path)(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_LISTED in failed_checks(out)
    assert f"{path}: required by manifest.json but not listed" in out


def test_the_v03_required_list_is_what_the_matrix_covers():
    assert set(REQUIRED_V03) <= set(release.required_paths(ROOT, "v1.0"))
    assert len(REQUIRED_V03) > len(M5_FILES)


# ------------------------------------------------------------ 허용 필드 (필드 검사 함수를 직접 부른다)


def first_committed_row(relative):
    return read_jsonl(ROOT / relative)[0]


KISA_ROW = first_committed_row(KISA_K3)
PUBLIC_ROW = first_committed_row(PUBLIC_K3)
JUDGE_ROW = next(r for r in read_jsonl(ROOT / KISA_JUDGE) if r["status"] == "judged")


def with_key(row, key, value):
    return {**row, key: value}


def without_key(row, key):
    return {k: v for k, v in row.items() if k != key}


def check_rows(tmp_path, kind, rows):
    path = tmp_path / "rows.jsonl"
    write_jsonl(path, rows)
    return release.check_fields(kind, path)


ROW_CASES = {
    "kisa generation row with answer": (
        "m5_gen_kisa",
        with_key(KISA_ROW, "answer", "합성 답"),
        "keys ['answer']",
    ),
    "kisa generation row with empty answer": (
        "m5_gen_kisa",
        with_key(KISA_ROW, "answer", ""),
        "keys ['answer']",
    ),
    "kisa generation row with unknown text key": (
        "m5_gen_kisa",
        with_key(KISA_ROW, "note", "합성 메모"),
        "keys ['note']",
    ),
    "kisa generation row with run_id": (
        "m5_gen_kisa",
        with_key(KISA_ROW, "run_id", "8a7c1c6b2f8bf06b"),
        "keys ['run_id']",
    ),
    "kisa generation row without latency_ms": (
        "m5_gen_kisa",
        without_key(KISA_ROW, "latency_ms"),
        "keys ['latency_ms']",
    ),
    "kisa generation row with a long question id": (
        "m5_gen_kisa",
        with_key(KISA_ROW, "question_id", "q" * 600),
        "longer than 500",
    ),
    "kisa generation row with a long retrieved id": (
        "m5_gen_kisa",
        with_key(KISA_ROW, "retrieved", ["9" * 600]),
        "longer than 500",
    ),
    "kisa generation row with an absolute citation": (
        "m5_gen_kisa",
        with_key(KISA_ROW, "citations", ["/etc/x"]),
        "starting with '/'",
    ),
    "kisa generation row with a free text status": (
        "m5_gen_kisa",
        with_key(KISA_ROW, "status", "공지 본문 일부"),
        "bad status",
    ),
    "public generation row with unknown text key": (
        "m5_gen_public",
        with_key(PUBLIC_ROW, "context", "문맥"),
        "keys ['context']",
    ),
    "public generation row without answer": (
        "m5_gen_public",
        without_key(PUBLIC_ROW, "answer"),
        "keys ['answer']",
    ),
    "public generation row with a long truncated id": (
        "m5_gen_public",
        with_key(PUBLIC_ROW, "truncated", ["x" * 600]),
        "longer than 500",
    ),
    "public generation row with a long question id": (
        "m5_gen_public",
        with_key(PUBLIC_ROW, "question_id", "q" * 600),
        "longer than 500",
    ),
    "public generation row with an answer starting with a slash": (
        "m5_gen_public",
        with_key(PUBLIC_ROW, "answer", "/etc/passwd 파일"),
        "starting with '/'",
    ),
    "public generation row with a non-string answer": (
        "m5_gen_public",
        with_key(PUBLIC_ROW, "answer", ["x"]),
        "answer must be a string",
    ),
    "judgment row with unknown text key": (
        "m5_judge",
        with_key(JUDGE_ROW, "note", "합성 메모"),
        "keys ['note']",
    ),
    "judgment row with answer": (
        "m5_judge",
        with_key(JUDGE_ROW, "answer", "합성 답"),
        "keys ['answer']",
    ),
    "judgment row without correctness": (
        "m5_judge",
        without_key(JUDGE_ROW, "correctness"),
        "keys ['correctness']",
    ),
    "judgment row with a free text reason": (
        "m5_judge",
        with_key(JUDGE_ROW, "faithfulness_reason_A", "공지에 이런 말이 있다"),
        "not allowed",
    ),
    "judgment row with a free text label": (
        "m5_judge",
        with_key(JUDGE_ROW, "correctness_B", "대체로 맞음"),
        "not allowed",
    ),
    "judgment row with a long question id": (
        "m5_judge",
        with_key(JUDGE_ROW, "question_id", "q" * 600),
        "longer than 500",
    ),
    "judgment row with an unknown status": (
        "m5_judge",
        with_key(JUDGE_ROW, "status", "skipped_other"),
        "bad status",
    ),
}


@pytest.mark.parametrize(("kind", "row", "needle"), ROW_CASES.values(), ids=ROW_CASES.keys())
def test_a_disallowed_m5_row_is_rejected_by_the_field_check(tmp_path, kind, row, needle):
    problems = check_rows(tmp_path, kind, [row])
    assert problems and any(needle in p for p in problems), problems
    assert release.m5_row_problems(kind, row) and any(
        needle in p for p in release.m5_row_problems(kind, row)
    )


def test_the_committed_first_rows_pass_the_direct_field_check(tmp_path):
    assert check_rows(tmp_path, "m5_gen_kisa", [KISA_ROW]) == []
    assert check_rows(tmp_path, "m5_gen_public", [PUBLIC_ROW]) == []
    assert check_rows(tmp_path, "m5_judge", [JUDGE_ROW]) == []


def test_a_public_answer_longer_than_500_chars_is_the_only_length_exception(tmp_path):
    long_answer = with_key(PUBLIC_ROW, "answer", "가" * 900)
    assert check_rows(tmp_path, "m5_gen_public", [long_answer]) == []
    assert any(
        "longer than 500" in p
        for p in check_rows(
            tmp_path, "m5_gen_public", [with_key(long_answer, "question_id", "q" * 600)]
        )
    )
    # KISA 생성 행에는 answer 자체가 없어야 한다: 짧은 값이어도 거부
    assert check_rows(tmp_path, "m5_gen_kisa", [with_key(KISA_ROW, "answer", "가")])


@pytest.mark.parametrize("bad", ["not a dict", 3, None, ["x"]])
def test_a_non_object_row_is_rejected(bad):
    for kind in release.M5_ROW_KINDS:
        assert release.m5_row_problems(kind, bad) == ["row: not a json object"]


def test_an_empty_m5_row_file_is_rejected(tmp_path):
    for kind in release.M5_ROW_KINDS:
        path = tmp_path / f"{kind}.jsonl"
        path.write_text("", encoding="utf-8")
        assert release.check_fields(kind, path) == ["empty file"]


def write_json_asset(tmp_path, payload):
    path = tmp_path / "x.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


JSON_CASES = {
    "long string": ({"note": "x" * 600}, "longer than 500"),
    "nested long string": ({"a": {"b": ["x" * 600]}}, "longer than 500"),
    "absolute path value": ({"where": "/mnt/cache"}, "starting with '/'"),
    "absolute path in a list": ({"where": ["data", "/mnt/cache"]}, "starting with '/'"),
    "absolute path key": ({"/mnt/cache": 1}, "starting with '/'"),
    "not an object": ([1, 2], "not a json object"),
}


@pytest.mark.parametrize(("payload", "needle"), JSON_CASES.values(), ids=JSON_CASES.keys())
def test_a_disallowed_m5_json_is_rejected_by_the_field_check(tmp_path, payload, needle):
    problems = release.check_fields("m5_json", write_json_asset(tmp_path, payload))
    assert any(needle in p for p in problems), problems


def test_benign_strings_with_inner_slashes_pass_the_m5_json_check(tmp_path):
    payload = {"retrieval": "results/baselines/manifest.json", "ratio": "1/2", "note": "a/b"}
    assert release.check_fields("m5_json", write_json_asset(tmp_path, payload)) == []


# ------------------------------------------------------------ 허용 필드 (릴리스 검사 전체 경로)


def inject_answer(relative):
    return mutate_rows(relative, add_answer)


FIELD_TAMPER = {
    **{
        f"{path} gets an answer": (inject_answer(path), {CHECK_FIELDS})
        for path in (KISA_K1, KISA_K3, f"{GEN}/kisa_k5.jsonl")
    },
    "kisa generation row gets an unknown key": (
        mutate_rows(KISA_K3, lambda rows: rows[0].update(note="x")),
        {CHECK_FIELDS},
    ),
    "public generation row gets an unknown key": (
        mutate_rows(PUBLIC_K3, lambda rows: rows[0].update(context="x")),
        {CHECK_FIELDS},
    ),
    "public generation row gets a long id": (
        mutate_rows(PUBLIC_K3, lambda rows: rows[0].update(question_id="q" * 600)),
        {CHECK_FIELDS},
    ),
    "judgment row gets an unknown key": (
        mutate_rows(KISA_JUDGE, lambda rows: rows[0].update(note="x")),
        {CHECK_FIELDS},
    ),
    "judgment row gets a free text reason": (
        mutate_rows(
            PUBLIC_JUDGE,
            lambda rows: next(r for r in rows if r["status"] == "judged").update(
                faithfulness_reason_A="free text"
            ),
        ),
        {CHECK_FIELDS},
    ),
    **{
        f"{path} gets an absolute path": (
            mutate_json(path, set_in(["where"], "/mnt/cache")),
            {CHECK_FIELDS},
        )
        for path in M5_JSON
    },
    **{
        f"{path} gets a long string": (
            mutate_json(path, set_in(["note"], "x" * 600)),
            {CHECK_FIELDS},
        )
        for path in M5_JSON
    },
}


@pytest.mark.parametrize(("tamper", "expected"), FIELD_TAMPER.values(), ids=FIELD_TAMPER.keys())
def test_disallowed_m5_field_is_exit_1_with_a_fresh_asset_table(repo, capsys, tamper, expected):
    tamper(repo)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert expected <= failed_checks(out)
    assert out.rstrip().endswith("check_release: FAILED")


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


def test_downloaded_v10_assets_pass(repo, downloaded, capsys):
    code, out, _ = run_assets(capsys, repo, downloaded)
    assert code == 0, out
    assert out.count("OK  ") == 9 and out.rstrip().endswith("check_release: OK")
    assert len(list(downloaded.iterdir())) == len(release.default_assets(repo, "v1.0"))
    assert all(asset(downloaded, path).is_file() for path in M5_FILES)


def append_byte(path):
    def change(directory):
        with asset(directory, path).open("a", encoding="utf-8") as handle:
            handle.write("\n")

    return change


def set_asset_json(path, change):
    def apply(directory):
        target = asset(directory, path)
        payload = json.loads(target.read_text("utf-8"))
        change(payload)
        target.write_text(json.dumps(payload), encoding="utf-8")

    return apply


def set_asset_rows(path, change):
    def apply(directory):
        target = asset(directory, path)
        rows = read_jsonl(target)
        change(rows)
        write_jsonl(target, rows)

    return apply


ASSET_TAMPER = {
    **{
        f"{path} missing": (lambda d, p=path: asset(d, p).unlink(), {CHECK_ALLOWED})
        for path in M5_FILES
    },
    **{f"{path} one byte appended": (append_byte(path), {CHECK_SHA}) for path in M5_FILES},
    "kisa k3 row gets an answer": (set_asset_rows(KISA_K3, add_answer), {CHECK_FIELDS}),
    "kisa k1 row gets an answer": (set_asset_rows(KISA_K1, add_answer), {CHECK_FIELDS}),
    "judgment row gets an unknown key": (
        set_asset_rows(KISA_JUDGE, lambda rows: rows[0].update(note="x")),
        {CHECK_FIELDS},
    ),
    "generation manifest gets an absolute path": (
        set_asset_json(GEN_MANIFEST, set_in(["where"], "/mnt/cache")),
        {CHECK_FIELDS},
    ),
    "summary value changed": (
        set_asset_json(SUMMARY_JSON, change_summary_cell),
        {CHECK_SHA, CHECK_M5},
    ),
    "topk value changed": (set_asset_json(TOPK, change_topk_cell), {CHECK_SHA, CHECK_M5}),
    "M4 report missing": (
        lambda d: asset(d, "results/m4/collection/report.json").unlink(),
        {CHECK_ALLOWED},
    ),
    "M3 comparison.json missing": (
        lambda d: asset(d, "results/experiments/embedding/comparison.json").unlink(),
        {CHECK_ALLOWED},
    ),
    "baseline result changed": (
        lambda d: asset(d, "results/baselines/public/bm25.jsonl").write_bytes(b"{}\n"),
        {CHECK_SHA},
    ),
    "unlisted file uploaded": (lambda d: (d / "notes.txt").write_text("x"), {CHECK_ALLOWED}),
    "unlisted local kisa answer cache uploaded": (
        lambda d: (d / "data__m5__generation__kisa_k3.jsonl").write_text("x"),
        {CHECK_ALLOWED},
    ),
}


@pytest.mark.parametrize(("tamper", "expected"), ASSET_TAMPER.values(), ids=ASSET_TAMPER.keys())
def test_tampered_downloaded_v10_assets_fail(repo, downloaded, capsys, tamper, expected):
    tamper(downloaded)
    code, out, _ = run_assets(capsys, repo, downloaded)
    assert code == 1
    assert expected <= failed_checks(out)
    assert out.rstrip().endswith("check_release: FAILED")


@pytest.mark.parametrize("path", M5_FILES)
def test_downloaded_asset_is_checked_even_when_the_repo_file_is_fine(
    repo, downloaded, capsys, path
):
    append_byte(path)(downloaded)
    assert run_release(capsys, repo)[0] == 0
    assert run_assets(capsys, repo, downloaded)[0] == 1

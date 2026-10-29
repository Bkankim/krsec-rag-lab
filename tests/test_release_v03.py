"""v0.3 릴리스 검사 테스트 - M4 표(README·노트 구간), 보고서·manifest 대조, v0.3 asset 허용·거부, 내려받은 asset.

커밋된 `results/m4/**`, `fixtures/kisa_full/**`와 문서를 임시 디렉터리로 복사해(릴리스 asset 사본과 같이 NVD 코퍼스 파일 없이)
변조 행렬을 돌린다. 모델·Docker·KISA 캐시·네트워크를 쓰지 않는다. v0.1·v0.2 범위는 test_release_check.py,
test_release_tables.py, test_release_v02.py가 이미 본다. 여기서는 v0.3이 그 검사를 물려받는지만 대표 행으로 본다.
"""

import json
import re
import shutil
from pathlib import Path

import pytest
from test_release_support import ROOT, read_jsonl, release, tables, write_jsonl
from test_release_v02 import (  # noqa: F401  (memoized_bootstrap은 autouse 픽스처다)
    V02_ONLY,
    edit_json,
    edit_text,
    memoized_bootstrap,
    section_rows,
)

NOTE = "docs/release-v0.3.md"
NOTE_V02 = "docs/release-v0.2.md"
SUMMARY = "docs/experiments/summary.md"
README = "README.md"
COLLECTION = "results/m4/collection/report.json"
IDEMPOTENCY = "results/m4/idempotency/report.json"
MANIFEST = "fixtures/kisa_full/manifest.json"
METADATA = "fixtures/kisa_full/metadata.jsonl"
M4_FILES = (METADATA, MANIFEST, COLLECTION, IDEMPOTENCY)
M4_JSON = (MANIFEST, COLLECTION, IDEMPOTENCY)
CHECK_M3 = "M3 metrics, comparison and tables rebuilt from the asset copies match"
CHECK_M4 = "M4 reports, manifest and tables rebuilt from the asset copies match"
CHECK_FIELDS = "only allowed fields"
CHECK_LISTED = "manifest-required files are listed"
CHECK_ALLOWED = "listed assets exist and are allowed"
CHECK_SHA = "asset sha256 matches the repo files and manifest inputs"
CHECK_README = "README tables rebuilt from the asset copies match"
M4_RANGES = {
    "README": (README, tables.README_M4),
    "note": (NOTE, tables.NOTE_M4_RANGE),
}
M3_RANGES = {
    "README": (README, tables.README_M3),
    "summary": (SUMMARY, tables.SUMMARY_RANGE),
    "v0.2 note": (NOTE_V02, tables.NOTE_RANGE),
    "v0.3 note": (NOTE, tables.NOTE_RANGE),
}
REQUIRED_V02 = release.required_paths(ROOT, "v0.2")


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    """릴리스 asset 사본과 같은 파일 + README·summary·v0.2 노트·v0.3 노트. NVD 코퍼스 파일은 없다."""
    root = tmp_path_factory.mktemp("v03")
    for relative in (*release.default_assets(ROOT, "v0.3"), README, SUMMARY, NOTE_V02, NOTE):
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
    """파일을 바꾼 뒤 v0.3 노트의 asset 표(크기·sha256)를 현재 상태로 다시 쓴다(실패가 내용 검사 때문이도록)."""
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


# ------------------------------------------------------------ 커밋된 리포


def test_committed_v03_note_passes_with_eight_checks(capsys):
    code, out, _ = run_release(capsys, ROOT)
    assert code == 0, out
    assert out.count("OK  ") == 8 and "FAIL" not in out
    assert out.rstrip().endswith("check_release: OK")


def test_committed_older_notes_still_pass_with_their_own_checks(capsys):
    code, out, _ = run_release(capsys, ROOT, note=NOTE_V02)
    assert code == 0 and out.count("OK  ") == 7 and "M4" not in out
    code = release.main(["--root", str(ROOT)])
    out = capsys.readouterr().out
    assert code == 0 and out.count("OK  ") == 6 and "M4" not in out


def test_committed_repo_check_covers_baseline_m3_and_m4(capsys):
    code, out, err = run_tables(capsys, ROOT, "--check")
    assert code == 0, err
    assert "5 experiments" in out
    m4_line = next(line for line in out.splitlines() if line.startswith("OK: M4 "))
    assert "match" in m4_line and "2592 target ids" in m4_line


def test_committed_note_lists_every_allowed_asset_with_current_sha256():
    note = (ROOT / NOTE).read_text(encoding="utf-8")
    listed = release.parse_asset_table(note)
    expected = release.render_asset_table(ROOT, release.default_assets(ROOT, "v0.3"))
    assert [r["path"] for r in listed] == release.default_assets(ROOT, "v0.3")
    assert note.count(expected.strip()) == 1


def test_print_assets_for_the_v03_note_is_what_the_note_lists(capsys):
    code = release.main(["--root", str(ROOT), "--print-assets", "--note", NOTE])
    out = capsys.readouterr().out
    assert code == 0
    assert (ROOT / NOTE).read_text(encoding="utf-8").count(out.strip()) == 1
    assert "fixtures__kisa_full__metadata.jsonl" in out


def test_v03_assets_are_the_v02_assets_plus_exactly_the_four_m4_files():
    v03 = set(release.default_assets(ROOT, "v0.3"))
    v02 = set(release.default_assets(ROOT, "v0.2"))
    assert v02 < v03
    assert v03 - v02 == set(M4_FILES)
    assert set(M4_FILES) <= set(release.required_paths(ROOT, "v0.3"))
    assert not set(M4_FILES) & set(release.required_paths(ROOT, "v0.2"))
    assert not set(M4_FILES) & set(release.default_assets(ROOT))


def test_committed_note_names_the_required_sections_and_commands():
    note = (ROOT / NOTE).read_text(encoding="utf-8")
    for heading in (
        "무엇이 들어 있나",
        "M3 판정",
        "M4 결과",
        "재현",
        "데이터와 모델",
        "asset",
        "한계",
    ):
        assert re.search(rf"^## {heading}$", note, re.MULTILINE), heading
    for heading in (
        "새 클론에서 모델·네트워크·KISA 캐시 없이 되는 것",
        "KISA 사이트 접근이 필요한 것: 전체 수집",
        "Docker와 모델이 필요한 것: 동기화와 멱등성 검증",
    ):
        assert re.search(rf"^### {heading}$", note, re.MULTILINE), heading
    for word in (
        "scripts/collect_kisa_full.py --cache-root <KISA-ROOT>",
        "scripts/sync_index.py --cache-root <KISA-ROOT> --dry-run",
        "--verify-idempotency",
        "robots.txt",
        "1.5초",
        "make_readme_tables.py --check",
        "check_release.py --note docs/release-v0.3.md",
        "--assets-dir",
        "check_kisa_leaks",
        "LICENSES/README.md",
        "KISA 공지 본문은 배포하지 않는다",
    ):
        assert word in note, word
    for name in ("m4-collection.md", "m4-idempotency.md"):
        assert f"]({name})" in note, name


def test_committed_docs_have_no_motive_words_or_dashes_or_personal_paths():
    for relative in (README, NOTE):
        text = (ROOT / relative).read_text(encoding="utf-8")
        assert not re.search(r"면접|학습용|학습 목적|interview", text), relative
        assert "\u2014" not in text, relative  # em dash
        assert "/Users/" not in text, relative
    assert "단독 프로젝트" in (ROOT / README).read_text(encoding="utf-8")
    assert "단독 프로젝트" in (ROOT / NOTE).read_text(encoding="utf-8")


def test_committed_docs_links_resolve():
    for relative in (README, NOTE):
        text = (ROOT / relative).read_text(encoding="utf-8")
        base = (ROOT / relative).parent
        for target in re.findall(r"\]\(((?!https?:|\.\./\.\./)[^)#\s]+)", text):
            assert (base / target).resolve().exists(), (relative, target)
    readme = (ROOT / README).read_text(encoding="utf-8")
    for link in ("docs/release-v0.3.md", "docs/m4-collection.md", "docs/m4-idempotency.md"):
        assert f"]({link})" in readme, link


def test_readme_status_is_m4_complete_and_keeps_the_older_ranges():
    readme = (ROOT / README).read_text(encoding="utf-8")
    status = readme[readme.index("## 상태") : readme.index("## 평가 트랙과 재현")]
    assert "M4 완료, v0.3" in status
    assert "M3 완료, v0.2" in status and "M2 완료, v0.1" in status
    for markers in (tables.BEGIN, tables.END, *tables.README_M3, *tables.README_M4):
        assert readme.count(markers) == 1, markers
    assert (
        readme.index(tables.END)
        < readme.index(tables.README_M3[0])
        < readme.index(tables.README_M4[0])
    )
    assert re.search(r"^## M4 결과$", readme, re.MULTILINE)


def test_committed_note_model_and_image_match_the_idempotency_report():
    note = (ROOT / NOTE).read_text(encoding="utf-8")
    report = load(ROOT, IDEMPOTENCY)
    model, qdrant = report["model"], report["qdrant"]
    assert f"`{model['name']}` revision `{model['revision']}`" in note
    assert f"`{qdrant['image']}`" in note and f"서버 {qdrant['version']}" in note
    assert f"`max_seq_length` {model['max_seq_length']}" in note
    assert f"OMP_NUM_THREADS={report['environment']['omp_num_threads']}" in note
    assert f"batch_size {model['batch_size']}" in note


def test_real_m4_files_pass_the_field_checks():
    assert release.check_fields("metadata", ROOT / METADATA) == []
    for path in M4_JSON:
        assert release.check_fields("m4_json", ROOT / path) == [], path
    for path in M4_FILES:
        assert release.asset_kind(path, "v0.3") in ("metadata", "m4_json"), path
        assert release.asset_kind(path, "v0.2") is None, path
        assert release.asset_kind(path, "v0.1") is None, path


# ------------------------------------------------------------ M4 표 값은 보고서와 같다(독립 서식으로 대조)


@pytest.mark.parametrize("document", M4_RANGES, ids=M4_RANGES.keys())
def test_m4_collection_table_matches_the_reports(document):
    relative, markers = M4_RANGES[document]
    rows = {r[0]: r[1] for r in section_rows(ROOT / relative, markers) if len(r) == 2}
    c = load(ROOT, COLLECTION)
    manifest = load(ROOT, MANIFEST)
    metadata = read_jsonl(ROOT / METADATA)
    parse_failed = c["failed_ids"]["parse_failed:empty_article"]
    assert (
        rows["발견 ID (고정 대상)"] == str(c["discovered_ids"]) == str(len(manifest["target_ids"]))
    )
    assert rows["게시판 표시 총수 / 차이"] == f"{c['displayed_total']} / {c['displayed_total_gap']}"
    assert rows["상세 성공"] == str(c["detail_ok"])
    assert rows["상세 실패 (fetch_failed)"] == str(sum(c["detail_failed"].values()))
    assert rows["파싱 실패"] == (
        f"{c['parse_failed']['parse_failed:empty_article']} "
        f"(`parse_failed:empty_article`: {', '.join(parse_failed)})"
    )
    assert rows["미처리"] == str(c["detail_pending"])
    assert (
        rows["누락 (발견했지만 `ok` 아님)"]
        == f"{len(c['missing_ids'])} ({', '.join(c['missing_ids'])})"
    )
    assert rows["목록 페이지 / 원시 행"] == f"{c['list_pages']} / {c['list_rows']}"
    assert rows["목록 중복: 페이지 안 / 페이지 사이"] == (
        f"{c['list_duplicate_in_page']} / {c['list_duplicate_across_pages']}"
    )
    assert rows["내용 중복 (본문 sha256이 같은 묶음 / 문서)"] == (
        f"{c['content_duplicate_group_count']} / {c['content_duplicate_doc_count']}"
    )
    assert rows["고정 50건 포함 / 본문 sha256 일치"] == (
        f"{c['fixed_present']} / {c['fixed_hash_match']} (기대 {c['fixed_expected']})"
    )
    with_cve = sum(1 for row in metadata if row["cve_ids"])
    distinct = len({cve for row in metadata for cve in row["cve_ids"]})
    assert rows["메타데이터 행 / CVE ID가 있는 행 / 서로 다른 CVE ID"] == (
        f"{len(metadata)} / {with_cve} / {distinct}"
    )
    ok_documents = sum(1 for d in manifest["documents"] if d["result"] == "ok")
    assert ok_documents == c["detail_ok"] == len(metadata)
    assert rows["요청 수"].startswith(f"{c['requests']['total']} (")
    assert rows["소요 시간 (초)"] == f"{c['elapsed_seconds']:.1f}"


@pytest.mark.parametrize("document", M4_RANGES, ids=M4_RANGES.keys())
def test_m4_idempotency_table_matches_the_report(document):
    relative, markers = M4_RANGES[document]
    table = section_rows(ROOT / relative, markers)
    report = load(ROOT, IDEMPOTENCY)
    steps = [r for r in table if len(r) == 9 and r[0].isdigit()]
    assert len(steps) == len(report["steps"]) == 5
    for cell, step in zip(steps, report["steps"], strict=True):
        plan, writes = step["plan"], step["writes"]
        assert cell[:7] == [
            str(step["step"]),
            f"`{step['name']}`",
            f"{plan['add']}/{plan['update']}/{plan['delete']}",
            str(step["points"]),
            str(step["encoded_texts"]),
            f"{writes['upsert']}/{writes['payload_update']}/{writes['delete']}",
            cell[6],
        ]
        assert cell[7:] == ["예" if step["passed"] else "아니오", f"{step['elapsed_seconds']:.1f}"]
    rows = {r[0]: r[1] for r in table if len(r) == 2}
    corpus = report["corpus"]
    assert rows["스냅샷"] == (
        f"대상 ID {corpus['target_ids']}, `ok` {corpus['ok_docs']}, "
        f"파싱 실패 {corpus['unresolved_ids']}, 기준 스냅샷 {corpus['baseline_docs']}"
    )
    assert rows["pooling / dtype / 차원"] == (
        f"{report['model']['pooling']} / {report['model']['dtype']} / {report['model']['dimension']}"
    )
    assert rows["환경"] == (
        f"{report['environment']['system']} {report['environment']['machine']}, "
        f"코어 {report['environment']['cpu_count']}, "
        f"`OMP_NUM_THREADS={report['environment']['omp_num_threads']}`"
    )
    text = (ROOT / relative).read_text(encoding="utf-8")
    assert f"검증 {'통과' if report['passed'] else '실패'} (" in text


def test_the_idempotency_steps_in_the_report_are_the_documented_scenario():
    """단계 표의 계획이 docs/m4-idempotency.md의 검증 시나리오(0, 0, 5/5/5, 처음부터, 5/5/5)와 같다."""
    report = load(ROOT, IDEMPOTENCY)
    k = report["k"]
    plans = [tuple(s["plan"][key] for key in ("add", "update", "delete")) for s in report["steps"]]
    baseline = report["corpus"]["baseline_docs"]
    assert plans == [(baseline, 0, 0), (0, 0, 0), (k, k, k), (baseline, 0, 0), (k, k, k)]
    assert [s["encoded_texts"] for s in report["steps"]] == [baseline, 0, 2 * k, baseline, 2 * k]
    assert [s["writes"]["delete"] for s in report["steps"]] == [0, 0, k, 0, k]
    assert report["passed"] is True and report["failed_step"] is None


# ------------------------------------------------------------ 복사본: 통과와 M4 켜짐 조건


def test_synthetic_copy_passes_both_checks(repo, capsys):
    code, out, _ = run_release(capsys, repo)
    assert code == 0, out
    assert out.count("OK  ") == 8
    code, out, err = run_tables(capsys, repo, "--check")
    assert code == 0, err
    assert "OK: M4 " in out


def test_m4_is_off_without_the_results_dir_and_without_the_readme_markers(repo, capsys):
    """과거 범위(M4 구간이 없는 README, results/m4 없음)는 M4를 보지 않고 v0.3 노트도 읽지 않는다."""
    shutil.rmtree(repo / "results/m4")
    (repo / NOTE).unlink()
    begin, end = tables.README_M4
    edit_text(repo / README, lambda t: t[: t.index(begin)] + t[t.index(end) + len(end) :])
    code, out, err = run_tables(capsys, repo, "--check")
    assert code == 0, err
    assert "M4" not in out and "5 experiments" in out


def test_results_dir_without_the_readme_markers_turns_m4_on_and_fails(repo, capsys):
    begin, end = tables.README_M4
    edit_text(repo / README, lambda t: t.replace(begin, "").replace(end, ""))
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "marker" in err


def test_readme_markers_without_the_results_dir_turn_m4_on_and_fail(repo, capsys):
    shutil.rmtree(repo / "results/m4")
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "missing required file" in err


@pytest.mark.parametrize("relative", M4_FILES)
def test_missing_m4_input_is_exit_1(repo, capsys, relative):
    (repo / relative).unlink()
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and f"missing required file: {relative}" in err


@pytest.mark.parametrize("relative", [NOTE, README])
def test_missing_m4_document_is_exit_1(repo, capsys, relative):
    (repo / relative).unlink()
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "missing required file" in err


def test_the_v03_note_path_can_be_given_explicitly(repo, tmp_path, capsys):
    """문서가 없는 asset 사본(`--root`)도 --note-v03으로 노트 경로를 주면 검증된다."""
    docs = tmp_path / "docs"
    docs.mkdir()
    shutil.move(repo / NOTE, docs / "v03.md")
    assert run_tables(capsys, repo, "--check")[0] == 1
    code, out, err = run_tables(capsys, repo, "--check", "--note-v03", str(docs / "v03.md"))
    assert code == 0, err
    assert "OK: M4 " in out


# ------------------------------------------------------------ 생성 구간(README·노트) 불일치 감지


def first_line(text, needle):
    return next(line for line in text.splitlines() if needle in line)


def change_number(text):
    row = first_line(text, "| 상세 성공 |")
    return text.replace(row, row.replace("2590", "2591", 1))


def flip_verdict(text):
    return text.replace("검증 통과", "검증 실패", 1)


def change_step_row(text):
    row = first_line(text, "| 3 | `incremental_variant` |")
    return text.replace(row, row.replace("10/0/5", "10/0/6", 1))


def delete_row(text):
    return text.replace(first_line(text, "| 누락 (") + "\n", "")


def duplicate_row(text):
    row = first_line(text, "| 누락 (")
    return text.replace(row, row + "\n" + row)


def swap_rows(text):
    a, b = first_line(text, "| 발견 ID ("), first_line(text, "| 상세 성공 |")
    return text.replace(a, "@@a").replace(b, a).replace("@@a", b)


def empty_range(text):
    return "\n"


def change_note_sentence(text):
    return text.replace("손으로 고치지 않는다", "손으로 고쳐도 된다", 1)


def append_line(text):
    return text.rstrip("\n") + "\n\n손으로 쓴 줄\n"


M4_RANGE_TAMPER = {
    "number changed": change_number,
    "verdict flipped": flip_verdict,
    "step row changed": change_step_row,
    "row deleted": delete_row,
    "row duplicated": duplicate_row,
    "rows swapped": swap_rows,
    "range emptied": empty_range,
    "sentence changed": change_note_sentence,
    "hand-written line appended": append_line,
}


@pytest.mark.parametrize("document", M4_RANGES, ids=M4_RANGES.keys())
@pytest.mark.parametrize("tamper", M4_RANGE_TAMPER.values(), ids=M4_RANGE_TAMPER.keys())
def test_m4_generated_range_mismatch_is_exit_1(repo, capsys, document, tamper):
    edit_range(repo, M4_RANGES, document, tamper)
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1
    assert f"MISMATCH {Path(M4_RANGES[document][0]).name}: M4 generated range differs" in err


@pytest.mark.parametrize("document", M4_RANGES, ids=M4_RANGES.keys())
@pytest.mark.parametrize("tamper", M4_RANGE_TAMPER.values(), ids=M4_RANGE_TAMPER.keys())
def test_m4_generated_range_mismatch_fails_the_release_check(repo, capsys, document, tamper):
    edit_range(repo, M4_RANGES, document, tamper)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_M4 in failed_checks(out)
    assert not {CHECK_README, CHECK_M3, CHECK_SHA, CHECK_FIELDS} & failed_checks(out)


def first_row(text, name):
    return next(
        line for line in text.splitlines() if line.startswith((f"| [{name}]", f"| {name} |"))
    )


def change_m3_number(text):
    row = first_row(text, "hybrid")
    return text.replace(row, row.replace("0.8551", "0.8552", 1))


def flip_m3_verdict(text):
    row = first_row(text, "hybrid")
    return text.replace(row, row.replace("hypothesis-rejected", "hypothesis-confirmed"))


def delete_m3_row(text):
    return text.replace(first_row(text, "rerank") + "\n", "")


def change_m3_sentence(text):
    return text.replace("10000회", "5000회", 1)


M3_RANGE_TAMPER = {
    "number changed": change_m3_number,
    "verdict flipped": flip_m3_verdict,
    "row deleted": delete_m3_row,
    "range emptied": empty_range,
    "sentence changed": change_m3_sentence,
    "hand-written line appended": append_line,
}


@pytest.mark.parametrize("document", M3_RANGES, ids=M3_RANGES.keys())
@pytest.mark.parametrize("tamper", M3_RANGE_TAMPER.values(), ids=M3_RANGE_TAMPER.keys())
def test_m3_range_mismatch_is_caught_in_every_document_with_m4_on(repo, capsys, document, tamper):
    """M4가 켜지면 --check는 v0.2 노트와 v0.3 노트의 M3 구간을 모두 본다(노트 수치만 바꿔도 걸린다)."""
    edit_range(repo, M3_RANGES, document, tamper)
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1
    assert f"MISMATCH {Path(M3_RANGES[document][0]).name}: M3 generated range differs" in err


@pytest.mark.parametrize("document", ["README", "summary", "v0.3 note"])
@pytest.mark.parametrize("tamper", M3_RANGE_TAMPER.values(), ids=M3_RANGE_TAMPER.keys())
def test_m3_range_mismatch_fails_the_v03_release_check(repo, capsys, document, tamper):
    edit_range(repo, M3_RANGES, document, tamper)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_M3 in failed_checks(out)
    assert CHECK_M4 not in failed_checks(out)


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


@pytest.mark.parametrize("document", M4_RANGES, ids=M4_RANGES.keys())
@pytest.mark.parametrize("broken", MARKER_BROKEN.values(), ids=MARKER_BROKEN.keys())
def test_m4_marker_problem_is_exit_1(repo, capsys, document, broken):
    relative, markers = M4_RANGES[document]
    edit_text(repo / relative, lambda t: broken(t, markers))
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "marker" in err


@pytest.mark.parametrize("document", M4_RANGES, ids=M4_RANGES.keys())
def test_m4_marker_problem_fails_the_release_check(repo, capsys, document):
    relative, markers = M4_RANGES[document]
    edit_text(repo / relative, lambda t: drop_begin(t, markers))
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1 and CHECK_M4 in failed_checks(out)


def test_baseline_and_m3_ranges_are_still_checked_when_m4_is_present(repo, capsys):
    edit_text(
        repo / README,
        lambda t: t.replace(
            "| bm25 | test | 86 | 0 | 0.8551 ", "| bm25 | test | 86 | 0 | 0.8552 ", 1
        ),
    )
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "generated tables differ" in err


# ------------------------------------------------------------ 보고서·manifest·메타데이터끼리의 대조


def mutate(relative, change):
    return lambda repo: edit_json(repo / relative, change)


def mutate_metadata(change):
    def apply(repo):
        rows = read_jsonl(repo / METADATA)
        change(rows)
        write_jsonl(repo / METADATA, rows)

    return apply


def set_value(container_path, value):
    """JSON 객체의 중첩 위치(키/인덱스 열)에 값을 넣는 변경 함수."""

    def change(payload):
        node = payload
        for key in container_path[:-1]:
            node = node[key]
        node[container_path[-1]] = value

    return change


def flip_one_result(payload):
    next(d for d in payload["documents"] if d["result"] == "ok")["result"] = "parse_failed:x"


def drop_one_document(payload):
    payload["documents"].pop()


def drop_one_target(payload):
    payload["target_ids"].pop()


def bump_ok_docs(payload):
    payload["corpus"]["ok_docs"] += 1


def bump_detail_ok(payload):
    payload["detail_ok"] += 1


def add_failed_reason(payload):
    payload["failed_ids"]["fetch_failed:http_404"] = ["1"]


def add_missing(payload):
    payload["missing_ids"].append("1")


def bump_parse_failed(payload):
    payload["parse_failed"]["parse_failed:empty_article"] += 1


def bump_gap(payload):
    payload["displayed_total_gap"] += 1


def bump_discovered(payload):
    payload["discovered_ids"] += 1


def bump_pending(payload):
    payload["detail_pending"] += 1


def renumber_step(payload):
    payload["steps"][0]["step"] = 9


def fail_step_three(payload):
    payload["steps"][2]["passed"] = False


def set_passed_false(payload):
    payload["passed"] = False


def set_failed_step(payload):
    payload["failed_step"] = 3


def bump_k(payload):
    payload["k"] += 1


def bump_unresolved(payload):
    payload["corpus"]["unresolved_ids"] += 1


def bump_baseline_docs(payload):
    payload["corpus"]["baseline_docs"] += 1


def bump_corpus_targets(payload):
    payload["corpus"]["target_ids"] += 1


def drop_first_metadata_row(rows):
    rows.pop(0)


def add_metadata_row(rows):
    rows.append({**rows[-1], "nttId": "99999999"})


def swap_metadata_id(rows):
    rows[0]["nttId"] = "99999999"


def clear_one_cve(rows):
    next(row for row in rows if row["cve_ids"])["cve_ids"] = []


# 보고서·manifest·메타데이터가 서로 어긋난 변조. "results/m4:" 대조에서 걸린다.
CROSS_TAMPER = {
    "collection detail_ok": (mutate(COLLECTION, bump_detail_ok), "detail_ok"),
    "collection discovered_ids": (mutate(COLLECTION, bump_discovered), "discovered_ids"),
    "collection failed_ids gets a reason": (mutate(COLLECTION, add_failed_reason), "failed_ids"),
    "collection missing_ids": (mutate(COLLECTION, add_missing), "missing_ids"),
    "collection parse_failed count": (mutate(COLLECTION, bump_parse_failed), "parse_failed"),
    "collection displayed_total_gap": (mutate(COLLECTION, bump_gap), "displayed_total_gap"),
    "collection detail_pending": (mutate(COLLECTION, bump_pending), "detail_pending"),
    "collection complete": (mutate(COLLECTION, set_value(["complete"], False)), "complete"),
    "collection parser_version": (
        mutate(COLLECTION, set_value(["parser_version"], "x")),
        "parser_version",
    ),
    "collection list_pages vs manifest discovery": (
        mutate(COLLECTION, set_value(["list_pages"], 1)),
        "list_pages",
    ),
    "collection discovery_error vs manifest": (
        mutate(COLLECTION, set_value(["discovery_error"], "x")),
        "discovery_error",
    ),
    "manifest document result": (mutate(MANIFEST, flip_one_result), "results/m4:"),
    "manifest loses a document": (mutate(MANIFEST, drop_one_document), "results/m4:"),
    "manifest loses a target id": (mutate(MANIFEST, drop_one_target), "results/m4:"),
    "manifest discovery list_rows": (
        mutate(MANIFEST, set_value(["discovery", "list_rows"], 1)),
        "list_rows",
    ),
    "manifest complete": (mutate(MANIFEST, set_value(["complete"], False)), "complete"),
    "idempotency corpus ok_docs": (mutate(IDEMPOTENCY, bump_ok_docs), "ok_docs"),
    "idempotency corpus target_ids": (mutate(IDEMPOTENCY, bump_corpus_targets), "target_ids"),
    "idempotency corpus unresolved_ids": (mutate(IDEMPOTENCY, bump_unresolved), "unresolved_ids"),
    "idempotency corpus baseline_docs": (mutate(IDEMPOTENCY, bump_baseline_docs), "baseline_docs"),
    "idempotency k": (mutate(IDEMPOTENCY, bump_k), "baseline_docs"),
    "idempotency step number": (mutate(IDEMPOTENCY, renumber_step), "step numbers"),
    "idempotency step failed but passed true": (mutate(IDEMPOTENCY, fail_step_three), "passed"),
    "idempotency passed false": (mutate(IDEMPOTENCY, set_passed_false), "passed"),
    "idempotency failed_step set": (mutate(IDEMPOTENCY, set_failed_step), "failed_step"),
    "metadata loses a row": (mutate_metadata(drop_first_metadata_row), "metadata nttIds"),
    "metadata gets a row": (mutate_metadata(add_metadata_row), "metadata nttIds"),
    "metadata id changed": (mutate_metadata(swap_metadata_id), "metadata nttIds"),
}
# 값만 바뀌어 대조는 통과하지만 표가 달라지는 변조. 문서 구간 대조에서 걸린다.
VALUE_TAMPER = {
    "collection elapsed_seconds": (mutate(COLLECTION, set_value(["elapsed_seconds"], 1.0)), "range differs"),
    "collection requests total": (mutate(COLLECTION, set_value(["requests", "total"], 1)), "range differs"),
    "collection rss_ids": (mutate(COLLECTION, set_value(["rss_ids"], 11)), "rss_ids"),
    "collection list_duplicate_ids": (mutate(COLLECTION, set_value(["list_duplicate_ids"], ["1"])), "list_duplicate_ids"),
    "idempotency elapsed_seconds": (mutate(IDEMPOTENCY, set_value(["elapsed_seconds"], 1.0)), "range differs"),
    "idempotency model revision": (mutate(IDEMPOTENCY, set_value(["model", "revision"], "0" * 40)), "range differs"),
    "idempotency step elapsed": (mutate(IDEMPOTENCY, set_value(["steps", 1, "elapsed_seconds"], 9.9)), "range differs"),
    "idempotency step writes": (mutate(IDEMPOTENCY, set_value(["steps", 2, "writes", "delete"], 4)), "range differs"),
    "idempotency vector diff": (mutate(IDEMPOTENCY, set_value(["steps", 3, "comparison", "vectors_max_abs_diff"], 0.5)), "range differs"),
    "idempotency omp threads": (mutate(IDEMPOTENCY, set_value(["environment", "omp_num_threads"], "4")), "range differs"),
    "metadata cve cleared": (mutate_metadata(clear_one_cve), "range differs"),
}  # fmt: skip
SOURCE_TAMPER = {**CROSS_TAMPER, **VALUE_TAMPER}


@pytest.mark.parametrize(("tamper", "expected"), SOURCE_TAMPER.values(), ids=SOURCE_TAMPER.keys())
def test_changing_only_an_m4_input_is_exit_1(repo, capsys, tamper, expected):
    """보고서·manifest·메타데이터만 바꾸고 문서 구간은 그대로 두면 검증이 실패한다."""
    tamper(repo)
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1
    assert "MISMATCH" in err and expected in err


@pytest.mark.parametrize("tamper", [t for t, _ in CROSS_TAMPER.values()], ids=CROSS_TAMPER.keys())
def test_inconsistent_m4_inputs_are_reported_before_the_documents(repo, capsys, tamper):
    tamper(repo)
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "MISMATCH results/m4:" in err


@pytest.mark.parametrize("tamper", [t for t, _ in SOURCE_TAMPER.values()], ids=SOURCE_TAMPER.keys())
def test_changing_an_m4_input_fails_the_release_check_with_a_fresh_asset_table(
    repo, capsys, tamper
):
    tamper(repo)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_M4 in failed_checks(out)
    assert CHECK_SHA not in failed_checks(out)


@pytest.mark.parametrize("relative", [COLLECTION, IDEMPOTENCY])
def test_every_documented_report_key_is_required(repo, capsys, relative):
    keys = tables.COLLECTION_KEYS if relative == COLLECTION else tables.IDEMPOTENCY_KEYS
    saved = load(ROOT, relative)
    assert set(keys) <= set(saved)
    for key in keys:
        payload = {name: value for name, value in saved.items() if name != key}
        (repo / relative).write_text(json.dumps(payload), encoding="utf-8")
        code, _, err = run_tables(capsys, repo, "--check")
        assert code == 1 and "missing keys" in err and key in err, key


def test_the_documented_key_lists_are_the_committed_report_keys():
    assert sorted(tables.COLLECTION_KEYS) == sorted(load(ROOT, COLLECTION))
    assert sorted(tables.IDEMPOTENCY_KEYS) == sorted(load(ROOT, IDEMPOTENCY))
    assert sorted(f"{k}" for k in tables.DISCOVERY_KEYS) == sorted(
        k for k in load(ROOT, MANIFEST)["discovery"] if k != "error"
    )


@pytest.mark.parametrize("relative", M4_JSON)
def test_m4_json_that_is_not_an_object_or_empty_is_exit_1(repo, capsys, relative):
    (repo / relative).write_text("[]", encoding="utf-8")
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "empty or non-object json" in err


def test_empty_metadata_is_exit_1(repo, capsys):
    (repo / METADATA).write_text("", encoding="utf-8")
    code, _, err = run_tables(capsys, repo, "--check")
    assert code == 1 and "empty input" in err


# ------------------------------------------------------------ 쓰기 모드


def test_write_mode_fills_the_m4_and_note_ranges_and_check_passes(repo, capsys):
    watched = [(README, M4_RANGES, "README"), (NOTE, M4_RANGES, "note")]
    original = {
        relative: (repo / relative).read_text("utf-8") for relative in (README, NOTE, NOTE_V02)
    }
    for _, ranges, key in watched:
        edit_range(repo, ranges, key, empty_range)
    edit_range(repo, M3_RANGES, "v0.3 note", empty_range)
    assert run_tables(capsys, repo, "--check")[0] == 1
    code, out, _ = run_tables(capsys, repo)
    assert code == 0 and "updated" in out
    assert run_tables(capsys, repo, "--check")[0] == 0
    for relative, text in original.items():
        assert (repo / relative).read_text("utf-8") == text, relative


def test_write_mode_leaves_text_outside_the_ranges_alone(repo, capsys):
    edit_text(repo / README, lambda t: t.replace("## M4 결과", "## M4 결과 (손으로 쓴 제목)", 1))
    edit_text(repo / NOTE, lambda t: t.replace("## 재현", "## 재현 (손으로 쓴 제목)", 1))
    edit_range(repo, M4_RANGES, "README", change_number)
    assert run_tables(capsys, repo)[0] == 0
    assert "## M4 결과 (손으로 쓴 제목)" in (repo / README).read_text("utf-8")
    assert "## 재현 (손으로 쓴 제목)" in (repo / NOTE).read_text("utf-8")
    assert run_tables(capsys, repo, "--check")[0] == 0


@pytest.mark.parametrize("tamper", [t for t, _ in CROSS_TAMPER.values()], ids=CROSS_TAMPER.keys())
def test_write_mode_refuses_when_m4_inputs_disagree(repo, capsys, tamper):
    tamper(repo)
    documents = (README, NOTE, NOTE_V02, SUMMARY)
    before = {relative: (repo / relative).read_bytes() for relative in documents}
    code, _, err = run_tables(capsys, repo)
    assert code == 1 and "README untouched" in err
    assert before == {relative: (repo / relative).read_bytes() for relative in documents}


# ------------------------------------------------------------ v0.3 노트: 프로필, 허용 asset, 필수 asset


def add_row(path):
    def add(repo):
        row = next(
            line
            for line in (repo / NOTE).read_text("utf-8").splitlines()
            if "| `fixtures/kisa_full/manifest.json` |" in line
        )
        extra = row.replace("fixtures/kisa_full/manifest.json", path).replace(
            "fixtures__kisa_full__manifest.json", path.replace("/", "__")
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


@pytest.mark.parametrize(
    ("name", "profile"),
    [
        ("release-v0.1.md", "v0.1"),
        ("release-v0.2.md", "v0.2"),
        ("release-v0.3.md", "v0.3"),
        ("note.md", "v0.1"),
        ("release-v0.3.md.bak", "v0.1"),
    ],
)
def test_profile_comes_from_the_note_file_name(name, profile):
    assert release.profile_of(Path("docs") / name) == profile


def test_a_later_unknown_release_profile_is_still_a_failed_check(repo, capsys):
    shutil.copyfile(repo / NOTE, repo / "docs/release-v0.4.md")
    code, out, _ = run_release(capsys, repo, note="docs/release-v0.4.md")
    assert code == 1 and "FAIL release profile" in out and out.rstrip().endswith("FAILED")


@pytest.mark.parametrize("old_note", ["docs/release-v0.2.md", "docs/release-v0.1.md"])
def test_older_notes_do_not_allow_the_m4_assets(repo, capsys, old_note):
    shutil.copyfile(repo / NOTE, repo / old_note)
    code, out, _ = run_release(capsys, repo, note=old_note)
    assert code == 1
    assert CHECK_ALLOWED in failed_checks(out)
    for path in M4_FILES:
        assert f"{path}: not an allowed asset" in out, path


NOT_ALLOWED = [
    "results/m4/collection/extra.json",
    "results/m4/other/report.json",
    "results/m4/idempotency/report.jsonl",
    "fixtures/kisa_full/cache.json",
    "fixtures/kisa_full/body.txt",
    "fixtures/kisa_full/extra/manifest.json",
    "data/kisa_full/11/body.txt",
    "data/kisa_full/11/source.html",
    "results/experiments/hybrid/notes.txt",
    "results/experiments/rogue/manifest.json",
    "fixtures/nvd/cves.jsonl",
    "README.md",
    "eval/golden/judgments/A.jsonl",
]


@pytest.mark.parametrize("path", NOT_ALLOWED)
def test_v03_asset_outside_the_allow_list_is_exit_1(repo, capsys, path):
    add_row(path)(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_ALLOWED in failed_checks(out)
    assert out.rstrip().endswith("check_release: FAILED")


@pytest.mark.parametrize("path", M4_FILES)
def test_note_missing_an_m4_asset_is_exit_1(repo, capsys, path):
    drop_rows(path)(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_LISTED in failed_checks(out)
    assert f"{path}: required by manifest.json but not listed" in out
    assert out.rstrip().endswith("check_release: FAILED")


def test_note_missing_all_m4_assets_is_exit_1(repo, capsys):
    drop_rows(*M4_FILES)(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert out.count("required by manifest.json but not listed") == len(M4_FILES)


@pytest.mark.parametrize("path", REQUIRED_V02)
def test_note_missing_a_m3_or_baseline_asset_is_exit_1(repo, capsys, path):
    """v0.3은 v0.2의 필수 파일 검사를 물려받는다: M3·베이스라인 asset이 빠져도 실패한다."""
    drop_rows(path)(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_LISTED in failed_checks(out)
    assert f"{path}: required by manifest.json but not listed" in out


def test_the_v02_required_list_is_what_the_matrix_covers():
    assert set(V02_ONLY) <= set(REQUIRED_V02)
    assert set(REQUIRED_V02) <= set(release.required_paths(ROOT, "v0.3"))
    assert sorted(set(release.required_paths(ROOT, "v0.3")) - set(REQUIRED_V02)) == sorted(M4_FILES)


# ------------------------------------------------------------ 허용 필드


def mutate_rows(relative, change):
    def apply(repo):
        rows = read_jsonl(repo / relative)
        change(rows)
        write_jsonl(repo / relative, rows)

    return apply


def drop_cve_key(rows):
    del rows[0]["cve_ids"]


METADATA_TAMPER = {
    "metadata row gets an extra key": mutate_rows(METADATA, lambda r: r[0].__setitem__("body", "x")),
    "metadata row gets a summary key": mutate_rows(METADATA, lambda r: r[0].__setitem__("summary", "x")),
    "metadata row gets an author key": mutate_rows(METADATA, lambda r: r[0].__setitem__("author", "x")),
    "metadata row loses cve_ids": mutate_rows(METADATA, drop_cve_key),
    "metadata row loses url": mutate_rows(METADATA, lambda r: r[0].pop("url")),
    "metadata title is a long passage": mutate_rows(METADATA, lambda r: r[0].__setitem__("title", "x" * 600)),
    "metadata cve list holds a long passage": mutate_rows(METADATA, lambda r: r[0].__setitem__("cve_ids", ["x" * 600])),
    "metadata file is empty": lambda repo: (repo / METADATA).write_text("", encoding="utf-8"),
}  # fmt: skip


@pytest.mark.parametrize("tamper", METADATA_TAMPER.values(), ids=METADATA_TAMPER.keys())
def test_disallowed_kisa_full_metadata_field_is_exit_1(repo, capsys, tamper):
    tamper(repo)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_FIELDS in failed_checks(out)


def set_top(key, value):
    return lambda payload: payload.__setitem__(key, value)


JSON_FIELD_CASES = {
    "long string": set_top("note", "x" * 600),
    "long string in a list": set_top("note", ["x" * 600]),
    "long string nested": set_top("note", {"deep": [{"x": "x" * 600}]}),
    "long key": set_top("x" * 600, 1),
    "json list": lambda payload: [],
    "abs path /Users/": set_top("where", "/Users/someone/cache"),
    "abs path /home/": set_top("where", "/home/someone/cache"),
    "abs path /private/": set_top("where", "/private/tmp/x"),
    "abs path /var/folders/": set_top("where", "/var/folders/ab/cd"),
    "abs path /tmp/": set_top("where", "/tmp/x"),
    "abs path /opt/": set_top("where", "/opt/models"),
    "abs path /mnt/": set_top("where", "/mnt/data/kisa_full"),
    "abs path /srv/": set_top("where", "/srv/cache"),
    "abs path /usr/": set_top("where", "/usr/bin"),
    "abs path /": set_top("where", "/"),
    "abs path /data/": set_top("where", "/data/kisa_full"),
    "abs path in a list": set_top("where", ["ok", "/mnt/x"]),
    "abs path nested": set_top("where", {"deep": ["/Users/x"]}),
    "abs path deep in dicts and lists": set_top("where", [{"a": {"b": ["/opt/x"]}}]),
    "abs path as a key": set_top("cache", {"/mnt/cache": "0" * 64}),
    "abs path as a nested key": set_top("cache", [{"/Users/x/.cache/model": 1}]),
    "relative-looking key with a leading slash": set_top("/relative", 1),
}


@pytest.mark.parametrize("relative", M4_JSON)
@pytest.mark.parametrize("change", JSON_FIELD_CASES.values(), ids=JSON_FIELD_CASES.keys())
def test_disallowed_m4_json_field_is_exit_1(repo, capsys, relative, change):
    edit_json(repo / relative, change)
    rewrite_assets(repo)
    code, out, _ = run_release(capsys, repo)
    assert code == 1
    assert CHECK_FIELDS in failed_checks(out)


@pytest.mark.parametrize(
    ("value", "count"),
    [
        ("/Users/x/y", 1),
        ("/mnt/x", 1),
        ("/", 1),
        ({"a": ["/home/x", "ok", {"b": "/opt/y"}]}, 2),
        ({"/key": "/value"}, 2),
        ({"ok": {"/nested": [1]}}, 1),
        ("see /Users/x", 0),
        ("relative/Users/x", 0),
        ("qdrant/qdrant:v1.19.2", 0),
        ("https://www.boho.or.kr/kr/bbs/view.do", 0),
        ("results/m4/collection/report.json", 0),
        ("", 0),
        (12, 0),
        (None, 0),
        (["a", 1, None], 0),
    ],
)
def test_slash_prefix_detection(value, count):
    assert release._slash_strings(value) == count


def test_benign_strings_with_inner_slashes_pass_the_m4_json_check(repo):
    edit_json(
        repo / IDEMPOTENCY,
        lambda p: p["qdrant"].__setitem__("image", "qdrant/qdrant:v1.19.2"),
    )
    edit_json(
        repo / MANIFEST, set_top("url", "https://www.boho.or.kr/kr/bbs/list.do?bbsId=B0000133")
    )
    for relative in M4_JSON:
        assert release.check_fields("m4_json", repo / relative) == [], relative


def test_older_profiles_keep_their_own_absolute_path_rule():
    """v0.2의 exp_json은 접두 목록 방식 그대로다: `/opt/`는 거르지 않는다(과거 프로필 동작은 바뀌지 않았다)."""
    assert release._absolute_paths("/opt/x") == 0
    assert release._absolute_paths("/Users/x") == 1
    assert release._slash_strings("/opt/x") == 1


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


def test_downloaded_v03_assets_pass(repo, downloaded, capsys):
    code, out, _ = run_assets(capsys, repo, downloaded)
    assert code == 0, out
    assert out.count("OK  ") == 8 and out.rstrip().endswith("check_release: OK")
    assert len(list(downloaded.iterdir())) == len(release.default_assets(repo, "v0.3"))
    assert all(asset(downloaded, path).is_file() for path in M4_FILES)


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


def set_asset_metadata_key(directory):
    target = asset(directory, METADATA)
    rows = read_jsonl(target)
    rows[0]["body"] = "x"
    write_jsonl(target, rows)


ASSET_TAMPER = {
    **{
        f"{path} missing": (lambda d, p=path: asset(d, p).unlink(), {CHECK_ALLOWED})
        for path in M4_FILES
    },
    **{f"{path} one byte appended": (append_byte(path), {CHECK_SHA}) for path in M4_FILES},
    "metadata gets an extra key": (set_asset_metadata_key, {CHECK_FIELDS}),
    **{
        f"{path} gets an absolute path": (
            set_asset_json(path, set_top("where", "/mnt/cache")),
            {CHECK_FIELDS},
        )
        for path in M4_JSON
    },
    **{
        f"{path} gets a long string": (
            set_asset_json(path, set_top("note", "x" * 600)),
            {CHECK_FIELDS},
        )
        for path in M4_JSON
    },
    "collection report value changed": (
        set_asset_json(COLLECTION, set_top("detail_ok", 1)),
        {CHECK_SHA, CHECK_M4},
    ),
    "idempotency report value changed": (
        set_asset_json(IDEMPOTENCY, set_top("passed", False)),
        {CHECK_SHA, CHECK_M4},
    ),
    "manifest value changed": (
        set_asset_json(MANIFEST, set_top("complete", False)),
        {CHECK_SHA, CHECK_M4},
    ),
    "M3 comparison.json missing": (
        lambda d: asset(d, "results/experiments/embedding/comparison.json").unlink(),
        {CHECK_ALLOWED},
    ),
    "M3 translations missing": (
        lambda d: asset(d, "results/experiments/crossling/translations.jsonl").unlink(),
        {CHECK_ALLOWED},
    ),
    "baseline result changed": (
        lambda d: asset(d, "results/baselines/public/bm25.jsonl").write_bytes(b"{}\n"),
        {CHECK_SHA},
    ),
    "unlisted file uploaded": (lambda d: (d / "notes.txt").write_text("x"), {CHECK_ALLOWED}),
    "unlisted cache body uploaded": (
        lambda d: (d / "data__kisa_full__11__body.txt").write_text("x"),
        {CHECK_ALLOWED},
    ),
}


@pytest.mark.parametrize(("tamper", "expected"), ASSET_TAMPER.values(), ids=ASSET_TAMPER.keys())
def test_tampered_downloaded_v03_assets_fail(repo, downloaded, capsys, tamper, expected):
    tamper(downloaded)
    code, out, _ = run_assets(capsys, repo, downloaded)
    assert code == 1
    assert expected <= failed_checks(out)
    assert out.rstrip().endswith("check_release: FAILED")


@pytest.mark.parametrize("path", M4_FILES)
def test_downloaded_asset_is_checked_even_when_the_repo_file_is_fine(
    repo, downloaded, capsys, path
):
    append_byte(path)(downloaded)
    assert run_release(capsys, repo)[0] == 0
    assert run_assets(capsys, repo, downloaded)[0] == 1

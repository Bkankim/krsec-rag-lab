"""약한 라벨 후보 생성·표본·출력 허용 목록 테스트. 합성 입력과 커밋된 fixture만 쓴다(KISA 본문 없음)."""

import csv
import hashlib
import json
from pathlib import Path

import pytest

from krsec_rag_lab import golden
from krsec_rag_lab.golden import (
    MANIFEST_FILE,
    MIN_SAMPLE_PAIRS,
    OUTPUT_FIELDS,
    PAIRS_FILE,
    QUERY_TEMPLATES,
    QUESTIONS_FILE,
    REVIEW_COLUMNS,
    STRATUM_A,
    STRATUM_B,
    STRATUM_JOIN,
)
from krsec_rag_lab.splits import SplitLeakError, assert_disjoint, extract_cve_ids

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_DIR = ROOT / "eval" / "golden"


def notice(ntt_id, title, cve_ids=(), published="2026-01-01"):
    return {
        "nttId": ntt_id,
        "title": title,
        "date": published,
        "url": f"https://example.invalid/view?nttId={ntt_id}",
        "cve_ids": list(cve_ids),
    }


def synthetic_catalog(n_notices=40, n_products=8, title_cve_notice=False):
    """제품 n_products개를 돌려 쓰는 합성 공지 목록. 공지마다 합성 CVE 2개를 인용한다."""
    rows = [
        notice(
            str(90000 + i),
            f"Prod{i % n_products} 제품 보안 업데이트 권고",
            [f"CVE-2026-{1000 + 2 * i}", f"CVE-2026-{1001 + 2 * i}"],
            published=f"2026-01-{1 + i % 28:02d}",
        )
        for i in range(n_notices)
    ]
    rows.append(notice("90500", "공지 제목 주의", []))
    if title_cve_notice:
        # 제목에는 CVE가 있는데 cve_ids(본문 추출)에는 없다 -> 층 (a)
        rows.append(notice("90501", "Prod0 CVE-2026-9000 긴급 권고", ["CVE-2026-1000"]))
    return rows


def make_root(tmp_path, notices, extra_nvd=()):
    """합성 fixture 루트. NVD 행은 조인 키 id와 합성 설명 필드를 가진다."""
    (tmp_path / "fixtures" / "kisa").mkdir(parents=True)
    (tmp_path / "fixtures" / "nvd").mkdir(parents=True)
    (tmp_path / "fixtures" / "kisa" / "metadata.jsonl").write_text(
        "".join(json.dumps(n, ensure_ascii=False) + "\n" for n in notices), encoding="utf-8"
    )
    docs = [
        {"nttId": n["nttId"], "sha256": hashlib.sha256(n["nttId"].encode()).hexdigest()}
        for n in notices
    ]
    (tmp_path / "fixtures" / "kisa" / "manifest.json").write_text(
        json.dumps({"parser_version": "synthetic-v1", "documents": docs}), encoding="utf-8"
    )
    cves = sorted({c for n in notices for c in n["cve_ids"]} | set(extra_nvd))
    (tmp_path / "fixtures" / "nvd" / "cves.jsonl").write_text(
        "".join(
            json.dumps({"id": c, "description_en": f"synthetic NVD text for {c} only"}) + "\n"
            for c in cves
        ),
        encoding="utf-8",
    )
    return tmp_path


def tree_hashes(root):
    return {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# ------------------------------------------------------------ 질문·조인


@pytest.mark.parametrize("cve_id", ["CVE-2026-0001", "CVE-2025-68686", "CVE-2021-1234567"])
def test_question_text_exposes_exactly_the_cve(cve_id):
    assert extract_cve_ids(golden.question_text(cve_id)) == [cve_id]


def test_every_query_template_is_used_and_exposes_a_single_cve():
    used = {golden.question_text(f"CVE-2026-{n:04d}") for n in range(1, 60)}
    for template in QUERY_TEMPLATES:
        prefix = template.split("{cve}")[0]
        matching = [
            t for t in used if t.startswith(prefix) and t.endswith(template.split("{cve}")[1])
        ]
        assert matching, template
        assert all(len(extract_cve_ids(t)) == 1 for t in matching)


@pytest.mark.parametrize(
    ("title", "product"),
    [
        ("Cisco 제품 보안 업데이트 권고", "cisco"),
        ("  Check  Point 제품 보안 업데이트 권고 ", "check point"),
        ("MS 9월 보안 위협에 따른 정기 보안 업데이트 권고", None),
        ("추석 명절 연휴기간 스미싱, 피싱 등 사이버사기 주의", None),
    ],
)
def test_product_of(title, product):
    assert golden.product_of(title) == product


def test_join_lists_every_citing_notice_for_a_shared_cve():
    notices = [
        notice("2", "A", ["CVE-2026-0001", "cve-2026-0002"]),
        notice("10", "B", ["CVE-2026-0001"]),
        notice("3", "C"),
    ]
    joined = golden.join_cve_to_notices(notices)
    assert joined == {"CVE-2026-0001": ["2", "10"], "CVE-2026-0002": ["2"]}


@pytest.mark.parametrize(
    ("title", "cited", "expected"),
    [
        ("Alpha 제품 보안 업데이트 권고", [], {}),
        ("Alpha CVE-2026-0001 권고", ["CVE-2026-0001"], {}),
        ("Alpha CVE-2026-0001 권고", [], {"CVE-2026-0001": ["1"]}),
        ("Alpha cve-2026-0001를 포함", ["CVE-2026-0002"], {"CVE-2026-0001": ["1"]}),
        ("Alpha CVE-2026-0001, CVE-2026-0002", ["CVE-2026-0002"], {"CVE-2026-0001": ["1"]}),
    ],
)
def test_title_cve_not_cited(title, cited, expected):
    assert golden.title_cve_not_cited([notice("1", title, cited)]) == expected


def test_questions_carry_the_join_result_and_nvd_presence():
    questions = golden.build_questions(
        {"CVE-2026-0001": ["1", "2"]}, ["CVE-2026-0009"], nvd_ids={"CVE-2026-0001"}
    )
    first, second = questions
    assert first["candidate_question_id"] == "cq-cve-2026-0001"
    assert first["candidate_ntt_ids"] == ["1", "2"]
    assert first["candidate_nvd_cve_ids"] == ["CVE-2026-0001"]
    assert first["query_type"] == "cve_explicit"
    assert second["candidate_ntt_ids"] == []
    assert second["candidate_nvd_cve_ids"] == []


# ------------------------------------------------------------ 표본


def fake_pairs(doc_counts):
    return [
        {"doc_id": doc, "candidate_pair_id": f"q{i}__{doc}"}
        for doc, count in doc_counts.items()
        for i in range(count)
    ]


def test_sample_balanced_does_not_let_one_document_dominate():
    pairs = fake_pairs({"big": 100, "a": 1, "b": 1, "c": 1, "d": 1, "e": 1})
    picked = golden.sample_balanced(pairs, 6, seed=27)
    assert sorted(p["doc_id"] for p in picked) == ["a", "b", "big", "c", "d", "e"]


def test_sample_balanced_takes_more_rounds_when_quota_exceeds_documents():
    picked = golden.sample_balanced(fake_pairs({"x": 5, "y": 5}), 4, seed=27)
    assert [p["doc_id"] for p in picked].count("x") == 2
    assert len({p["candidate_pair_id"] for p in picked}) == 4


def test_sample_balanced_is_deterministic_and_depends_on_seed():
    pairs = fake_pairs({f"d{i}": 3 for i in range(20)})
    first = golden.sample_balanced(pairs, 8, seed=27)
    assert first == golden.sample_balanced(list(reversed(pairs)), 8, seed=27)
    assert first != golden.sample_balanced(pairs, 8, seed=28)


def test_sample_balanced_returns_all_when_quota_exceeds_pool():
    assert len(golden.sample_balanced(fake_pairs({"x": 2}), 10, seed=1)) == 2


# ------------------------------------------------------------ 합성 입력으로 전체 생성


def test_build_outputs_synthetic_has_both_check_strata(tmp_path):
    root = make_root(
        tmp_path, synthetic_catalog(title_cve_notice=True), extra_nvd=["CVE-2026-9000"]
    )
    outputs = golden.build_outputs(root)
    pairs = [json.loads(line) for line in outputs[PAIRS_FILE].splitlines()]
    manifest = json.loads(outputs[MANIFEST_FILE])
    strata = {s["stratum"]: s for s in manifest["sampling"]["strata"]}

    assert len(pairs) >= MIN_SAMPLE_PAIRS == manifest["sampling"]["min_pairs"]
    assert len({p["candidate_pair_id"] for p in pairs}) == len(pairs)
    assert strata[STRATUM_A]["selected"] == 1
    assert strata[STRATUM_A]["zero_reason"] is None
    assert strata[STRATUM_B]["selected"] == 12
    assert {s: sum(1 for p in pairs if p["stratum"] == s) for s in strata} == {
        s: strata[s]["selected"] for s in strata
    }
    for pair in pairs:
        assert pair["in_candidate_set"] == (pair["stratum"] == STRATUM_JOIN)
        assert pair["weak_label"] == (
            "weak_positive" if pair["in_candidate_set"] else "weak_unlabeled"
        )
    by_stratum_a = next(p for p in pairs if p["stratum"] == STRATUM_A)
    assert by_stratum_a["doc_id"] == "90501"
    assert by_stratum_a["cve_ids"] == ["CVE-2026-9000"]
    # (b)는 같은 제품명 공지이고 그 CVE를 인용하지 않는다
    catalog = {n["nttId"]: n for n in synthetic_catalog(title_cve_notice=True)}
    for pair in (p for p in pairs if p["stratum"] == STRATUM_B):
        assert pair["cve_ids"][0] not in catalog[pair["doc_id"]]["cve_ids"]
        assert golden.product_of(pair["doc_title"]) is not None


def test_build_outputs_synthetic_without_title_cve_records_zero_reason(tmp_path):
    outputs = golden.build_outputs(make_root(tmp_path, synthetic_catalog()))
    manifest = json.loads(outputs[MANIFEST_FILE])
    stratum_a = next(s for s in manifest["sampling"]["strata"] if s["stratum"] == STRATUM_A)
    assert (stratum_a["pool_pairs"], stratum_a["selected"]) == (0, 0)
    assert "제목에 CVE ID가 든 공지가 0건" in stratum_a["zero_reason"]
    assert manifest["join"]["n_notices_with_cve_in_title"] == 0


def test_build_outputs_rejects_a_sample_below_the_minimum(tmp_path):
    root = make_root(tmp_path, synthetic_catalog(n_notices=3, n_products=3))
    with pytest.raises(ValueError, match="need at least 30"):
        golden.build_outputs(root)


def test_build_outputs_rejects_notice_missing_from_kisa_manifest(tmp_path):
    root = make_root(tmp_path, synthetic_catalog())
    manifest_path = root / "fixtures" / "kisa" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["documents"].pop()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="without sha256"):
        golden.build_outputs(root)


def test_main_build_is_idempotent_on_synthetic_root(tmp_path):
    root = make_root(tmp_path, synthetic_catalog())

    def eval_tree():
        return {k: v for k, v in tree_hashes(root).items() if k.startswith("eval/")}

    assert golden.main(["build", "--root", str(root)]) == 0
    first = eval_tree()
    assert set(first) == set(OUTPUT_FIELDS)
    assert golden.main(["build", "--root", str(root)]) == 0
    assert eval_tree() == first


# ------------------------------------------------------------ 커밋된 fixture와 출력


def test_build_twice_on_real_fixtures_gives_identical_bytes():
    assert golden.build_outputs(ROOT) == golden.build_outputs(ROOT)


def test_committed_outputs_match_a_fresh_build():
    fresh = golden.build_outputs(ROOT)
    for rel, content in fresh.items():
        assert (ROOT / rel).read_text(encoding="utf-8") == content, f"{rel} is stale"


def test_committed_manifest_records_method_seed_and_strata():
    manifest = json.loads((ROOT / MANIFEST_FILE).read_text(encoding="utf-8"))
    sampling = manifest["sampling"]
    strata = {s["stratum"]: s for s in sampling["strata"]}
    pairs = read_jsonl(ROOT / PAIRS_FILE)

    assert manifest["protocol_version"] == "eval-protocol-v1"
    assert manifest["status"] == "weak_candidate_not_human_verified"
    assert manifest["seed"] == golden.SEED
    assert sampling["method"] and sampling["ranking"] and sampling["unit"]
    assert sampling["n_pairs"] == len(pairs) >= MIN_SAMPLE_PAIRS
    assert set(strata) == {STRATUM_JOIN, STRATUM_A, STRATUM_B}
    for name, entry in strata.items():
        assert entry["selected"] == sum(1 for p in pairs if p["stratum"] == name)
        if entry["selected"] == 0:
            assert entry["zero_reason"], f"{name}: zero stratum needs a reason"
    # 현재 metadata에는 제목에 CVE ID가 든 공지가 없으므로 (a)는 0건이고 사유가 적혀 있다
    assert strata[STRATUM_A]["selected"] == 0
    assert "제목에 CVE ID가 든 공지가 0건" in strata[STRATUM_A]["zero_reason"]
    assert strata[STRATUM_B]["selected"] > 0
    assert manifest["join"]["n_cves_without_nvd_record"] == 0


def test_committed_candidates_are_cve_explicit_and_use_the_protocol_type_name():
    questions = read_jsonl(ROOT / QUESTIONS_FILE)
    assert len(questions) == 1560
    for q in questions:
        assert q["query_type"] == "cve_explicit"
        assert extract_cve_ids(q["candidate_query"]) == q["cve_ids"]
        assert q["candidate_ntt_ids"], "every KISA-cited CVE has at least one candidate notice"


def test_candidate_records_feed_the_split_check():
    notices = golden.load_notices(ROOT / golden.KISA_METADATA)
    questions = {q["candidate_question_id"]: q for q in read_jsonl(ROOT / QUESTIONS_FILE)}
    same_notice = [q for q in questions.values() if q["candidate_ntt_ids"] == ["72193"]]
    assert len(same_notice) >= 2
    leaking = [golden.split_item(same_notice[0], "dev"), golden.split_item(same_notice[1], "test")]
    with pytest.raises(SplitLeakError):
        assert_disjoint(leaking, notices)
    assert_disjoint(
        [golden.split_item(same_notice[0], "dev"), golden.split_item(same_notice[1], "dev")],
        notices,
    )


# ------------------------------------------------------------ 출력 필드 허용 목록


def committed_files():
    return sorted(p for p in GOLDEN_DIR.rglob("*") if p.is_file())


def test_every_committed_data_file_has_an_allowlist():
    data_files = {p.relative_to(ROOT).as_posix() for p in committed_files() if p.suffix != ".md"}
    assert data_files == set(OUTPUT_FIELDS)


@pytest.mark.parametrize("rel", sorted(OUTPUT_FIELDS))
def test_committed_output_fields_are_on_the_allowlist(rel):
    assert golden.check_output_fields(ROOT / rel, OUTPUT_FIELDS[rel]) == []


def test_committed_output_has_no_nvd_text_and_no_kisa_text_fields():
    paths = committed_files()
    assert golden.check_no_nvd_text(paths, ROOT / golden.NVD_CVES) == []
    assert not golden.FORBIDDEN_TEXT_FIELDS & set().union(*OUTPUT_FIELDS.values())
    assert [p.name for p in paths if "description" in p.read_text(encoding="utf-8").lower()] == []


def test_committed_outputs_have_no_personal_paths_or_dashes():
    for path in committed_files():
        text = path.read_text(encoding="utf-8")
        assert "/Users/" not in text, path.name
        assert "\u2014" not in text, path.name


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("questions.jsonl", {"candidate_question_id": "x", "body": "kisa text"}),
        ("questions.jsonl", {"candidate_question_id": "x", "kisa_summary": "s"}),
        ("manifest.json", {"seed": 1, "nested": {"description_en": "d"}}),
    ],
)
def test_check_output_fields_rejects_unlisted_fields(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(json.dumps(content) + "\n", encoding="utf-8")
    errors = golden.check_output_fields(path, golden.QUESTION_FIELDS | {"seed", "nested"})
    assert errors and all("field not allowed" in e for e in errors)


def test_check_output_fields_rejects_an_extra_csv_column(tmp_path):
    path = tmp_path / "sheet.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow([*REVIEW_COLUMNS, "excerpt"])
    assert golden.check_output_fields(path, frozenset(REVIEW_COLUMNS)) == [
        "sheet.csv: field not allowed: excerpt"
    ]


def test_check_no_nvd_text_detects_a_copied_description(tmp_path):
    root = make_root(tmp_path, [notice("1", "T", ["CVE-2026-0001"])])
    leaked = tmp_path / "leak.jsonl"
    leaked.write_text(
        json.dumps({"candidate_query": "prefix synthetic NVD text for CVE-2026-0001 only suffix"}),
        encoding="utf-8",
    )
    clean = tmp_path / "clean.jsonl"
    clean.write_text(json.dumps({"candidate_query": "CVE-2026-0001는?"}), encoding="utf-8")
    cves = root / "fixtures" / "nvd" / "cves.jsonl"
    assert golden.check_no_nvd_text([clean], cves) == []
    assert golden.check_no_nvd_text([leaked], cves) == [
        "leak.jsonl: contains NVD text of CVE-2026-0001"
    ]

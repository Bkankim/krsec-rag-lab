"""한영 교차 실험 테스트 - 합성 번역 파일과 가짜 dense 인덱스만 쓰고 번역 모델을 내려받지 않는다.

확인하는 것: 번역 파일 로딩(누락·중복·초과·낡은 번역·다른 모델·허용 필드·빈 번역)과 검색기(BM25와 가짜
dense)가 질문 ID에 맞는 번역문을 실제로 받아 원문과 다른 결과를 내는지, 번역문만 바꾸면 test 잠금이
깨지는지, CVE ID 보존 계수, 하네스를 거친 end-to-end(변형별 기준선), 모델 패키지 비접촉, 커밋된
results/experiments/crossling의 정합성과 `--compare`와 보고서 표 일치.
"""

import json
import shutil
from pathlib import Path
from typing import ClassVar

import pytest
from test_baselines_runner import FakeDense
from test_experiments_harness import QUERIES, run_experiment, write_fixture

from krsec_rag_lab.baselines import data, runner, scoring
from krsec_rag_lab.baselines.bm25 import BM25Index
from krsec_rag_lab.experiments import ComparisonError, ContractError, LockError, harness
from krsec_rag_lab.experiments import crossling as cl
from krsec_rag_lab.metrics import sort_by_score

ROOT = Path(__file__).resolve().parents[1]
OUT = Path("results/experiments")
CROSSLING_DIR = ROOT / OUT / "crossling"
COMMITTED = (CROSSLING_DIR / "comparison.json").exists()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------ 합성 번역
# 합성 어려운 질문 `zzqx{i} 질문`은 코퍼스에 없는 낱말이라 한국어 그대로는 아무 문서도 못 찾는다. 번역문은
# 문서 i의 낱말 `gadget{i}`를 담아 영어 쪽에서만 정답을 찾게 한다. 쉬운 질문의 번역은 CVE ID를 지킨다.


def synthetic_translation(row):
    query = row["query"]
    if query.startswith("zzqx"):
        return f"gadget{query.split()[0].removeprefix('zzqx')} vulnerability"
    return query.replace("취약점 설명", "vulnerability description").replace("찾아줘", "find")


def translation_row(question_id, text, query, **overrides):
    row = {
        "question_id": question_id,
        "translation": text,
        "source_sha256": cl.source_sha256(query),
        "model": cl.MODEL_NAME,
        "revision": cl.MODEL_REVISION,
    }
    return row | overrides


def synthetic_rows():
    return [translation_row(q["id"], synthetic_translation(q), q["query"]) for q in QUERIES]


def write_translations(root, rows):
    cl.write_translations(root / cl.TRANSLATIONS_PATH, rows)


class RecordingDense(FakeDense):
    """질의 문자열을 기록하는 가짜 dense. 어떤 질의가 들어왔는지 본다."""

    seen: ClassVar[list[str]] = []

    def score(self, query):
        RecordingDense.seen.append(query)
        return super().score(query)


@pytest.fixture
def root(tmp_path):
    write_fixture(tmp_path)
    runner.run_baseline("public", "bm25", tmp_path)
    runner.run_baseline("public", "dense", tmp_path, dense_factory=FakeDense)
    write_translations(tmp_path, synthetic_rows())
    RecordingDense.seen = []
    return tmp_path


def run_crossling(root, split="all", **kwargs):
    return harness.run_experiment(
        "crossling", "public", root, split=split, dense_factory=RecordingDense, **kwargs
    )


def questions_of(root):
    return data.load_questions("public", root)


# ------------------------------------------------------------ 사전 등록 상수


def test_preregistered_constants():
    assert cl.NAME == "crossling"
    assert cl.PRIMARY == ("public", "bm25_ko2en")
    assert cl.VARIANTS == {"public": ("bm25_ko2en", "dense_ko2en")}
    assert cl.BASELINES == {"public": {"bm25_ko2en": "bm25", "dense_ko2en": "dense"}}
    assert cl.grid("public", "bm25_ko2en") == [{}]
    assert cl.grid("public", "dense_ko2en") == [{}]
    assert "KO->EN" in cl.HYPOTHESIS
    assert (cl.MODEL_NAME, cl.MODEL_REVISION) == (
        "Helsinki-NLP/opus-mt-ko-en",
        "e42d1f41b66194e6d10512f8a27bebc1f4f5097e",
    )
    assert cl.DECODING["do_sample"] is False
    assert cl.reproduction_inputs("public", "bm25_ko2en") == {
        "translations": "results/experiments/crossling/translations.jsonl"
    }


def test_fixed_config_takes_bm25_settings_from_the_baseline_and_names_the_translation_model(root):
    manifest = read_json(root / "results/baselines/manifest.json")
    selected = manifest["runs"]["public/bm25"]["selected"]
    bm25 = cl.fixed_config("public", "bm25_ko2en", manifest)
    assert bm25["bm25"] == {"k1": selected["k1"], "b": selected["b"], "tokenizer": "bm25-tok-v1"}
    assert "dense" not in bm25
    assert bm25["translation"]["model"] == cl.MODEL_NAME
    assert bm25["translation"]["revision"] == cl.MODEL_REVISION
    dense = cl.fixed_config("public", "dense_ko2en", manifest)
    assert dense["dense"] == {
        "name": "BAAI/bge-m3",
        "revision": "5617a9f61b028005a4858fdac845db406aefb181",
    }
    assert "bm25" not in dense
    manifest["runs"]["public/bm25"]["config"]["tokenizer"]["id"] = "other"
    with pytest.raises(ContractError, match="tokenizer"):
        cl.fixed_config("public", "bm25_ko2en", manifest)


# ------------------------------------------------------------ 번역 파일 로딩


def test_load_translations_returns_the_text_by_question_id(root):
    translations = cl.load_translations(root / cl.TRANSLATIONS_PATH, questions_of(root))
    assert translations["d-prod-1"] == "gadget2 vulnerability"
    assert translations["d-cve-1"] == "CVE-2026-1000 vulnerability description"
    assert set(translations) == {q["id"] for q in QUERIES}


def mutate(rows, edit):
    rows = [dict(row) for row in rows]
    edit(rows)
    return rows


BROKEN = {
    "missing question": (lambda rows: rows.pop(0), "missing for 1 question"),
    "many missing": (lambda rows: rows.__delitem__(slice(0, 3)), "missing for 3 question"),
    "duplicate id": (lambda rows: rows.append(dict(rows[0])), "duplicate question id"),
    "unknown question": (
        lambda rows: rows.append(rows[0] | {"question_id": "nope-1"}),
        "unknown question",
    ),
    "stale source": (
        lambda rows: rows[0].update(source_sha256=cl.source_sha256("다른 질문")),
        "stale for 1 question",
    ),
    "other model": (lambda rows: rows[1].update(model="other/model"), "another model"),
    "other revision": (lambda rows: rows[1].update(revision="0" * 40), "another model"),
    "extra field": (lambda rows: rows[2].update(query="원문"), "fields"),
    "missing field": (lambda rows: rows[2].pop("revision"), "fields"),
    "empty translation": (lambda rows: rows[3].update(translation="  "), "empty translation"),
    "non-string translation": (lambda rows: rows[3].update(translation=None), "empty translation"),
}


@pytest.mark.parametrize("name", sorted(BROKEN))
def test_load_translations_rejects_a_broken_file(root, name):
    edit, message = BROKEN[name]
    write_translations(root, mutate(synthetic_rows(), edit))
    with pytest.raises(ContractError, match=message):
        cl.load_translations(root / cl.TRANSLATIONS_PATH, questions_of(root))


def test_load_translations_fails_when_the_file_is_missing(root):
    (root / cl.TRANSLATIONS_PATH).unlink()
    with pytest.raises(ContractError, match="missing"):
        cl.load_translations(root / cl.TRANSLATIONS_PATH, questions_of(root))


def test_a_changed_question_text_makes_its_translation_stale(root):
    queries = [dict(q) for q in QUERIES]
    queries[2]["query"] += " 추가"
    write_fixture(root, queries)
    with pytest.raises(ContractError, match="stale"):
        cl.load_translations(root / cl.TRANSLATIONS_PATH, questions_of(root))


def test_translations_are_written_sorted_and_without_non_ascii_escapes(tmp_path):
    cl.write_translations(tmp_path / "t.jsonl", [translation_row("q1", "café title", "질문")])
    line = (tmp_path / "t.jsonl").read_text("utf-8").splitlines()[0]
    assert "café" in line
    assert list(json.loads(line)) == sorted(cl.TRANSLATION_FIELDS)


# ------------------------------------------------------------ CVE ID 보존 계수


def q(question_id, query, split="dev", excluded=False, query_type="cve_explicit"):
    return data.Question(
        question_id, query, query_type, split, frozenset({"d"}), frozenset(), excluded
    )


def test_cve_preservation_counts_lost_altered_and_added_ids():
    questions = [
        q("kept", "CVE-2026-0001 이 뭔가요?"),
        q("kept-lower", "CVE-2026-0002 이 뭔가요?"),
        q("lost", "CVE-2026-0003 이 뭔가요?"),
        q("altered", "CVE-2026-0004 이 뭔가요?", split="test"),
        q("added", "제품 취약점", split="test", query_type="product_symptom"),
        q("none", "제품 취약점 2", split="test", query_type="product_symptom"),
        q("excluded", "CVE-2026-0005", split="test", excluded=True),
        q("two-ids", "CVE-2026-0006 과 CVE-2026-0007 비교", split="test"),
    ]
    translations = {
        "kept": "What is CVE-2026-0001?",
        "kept-lower": "what is cve-2026-0002",  # 소문자도 같은 ID로 센다
        "lost": "What is that vulnerability?",
        "altered": "What is CVE-2026-0044?",
        "added": "Vulnerabilities of CVE-2026-0099",
        "none": "Product vulnerabilities",
        "excluded": "nothing",
        "two-ids": "Compare CVE-2026-0006",
    }
    result = cl.cve_preservation(questions, translations)
    assert result["all"] == {
        "n_questions": 7,  # 제외 질문은 세지 않는다
        "n_with_cve_id": 5,
        "n_changed": 4,
        "n_lost": 3,
        "n_added": 2,
        "changed_question_ids": ["added", "altered", "lost", "two-ids"],
    }
    assert result["dev"] == {
        "n_questions": 3,
        "n_with_cve_id": 3,
        "n_changed": 1,
        "n_lost": 1,
        "n_added": 0,
        "changed_question_ids": ["lost"],
    }
    assert result["test"]["n_changed"] == 3
    assert result["test"]["changed_question_ids"] == ["added", "altered", "two-ids"]
    assert (
        result["all"]["n_questions"] == result["dev"]["n_questions"] + result["test"]["n_questions"]
    )


def test_cve_preservation_with_unchanged_translations_counts_nothing():
    questions = [q("a", "CVE-2026-0001 이 뭔가요?"), q("b", "제품 취약점", split="test")]
    same = {question.question_id: question.query for question in questions}
    result = cl.cve_preservation(questions, same)
    assert result["all"]["n_changed"] == 0
    assert result["all"]["changed_question_ids"] == []


# ------------------------------------------------------------ 검색기가 질문 ID에 맞는 번역문을 받는다


def make_state(root, variant):
    questions = questions_of(root)
    ctx = harness.Context(
        root=root,
        track="public",
        variant=variant,
        corpus=data.load_public_corpus(root),
        questions=questions,
        baselines_manifest=read_json(root / "results/baselines/manifest.json"),
        fixed={},
        dense_factory=RecordingDense,
    )
    return cl.setup(ctx), {question.question_id: question for question in questions}


def test_bm25_scorer_uses_the_translation_of_that_question_and_differs_from_the_original(root):
    state, by_id = make_state(root, "bm25_ko2en")
    scorer = cl.make_scorer(state, {})
    selected = read_json(root / "results/baselines/manifest.json")["runs"]["public/bm25"][
        "selected"
    ]
    original = BM25Index(data.load_public_corpus(root).texts, k1=selected["k1"], b=selected["b"])
    for question_id in ("d-prod-1", "d-prod-2", "t-prod-05", "t-exp-1"):
        question = by_id[question_id]
        scores = scorer(question)
        translated = state.translations[question_id]
        # 점수 함수는 번역문으로 검색한 결과와 같고, 번역문이 정답 문서를 1위로 만든다
        assert scores == state.bm25.score(translated)
        assert sort_by_score(scores)[0] in question.gold
        # 원문(한국어) 질의는 이 합성 문서와 낱말이 겹치지 않아 아무것도 못 찾는다
        assert original.score(question.query) == {}
        assert scores != original.score(question.query)


def test_translations_go_to_the_right_questions_not_to_a_neighbour(root):
    state, by_id = make_state(root, "bm25_ko2en")
    scorer = cl.make_scorer(state, {})
    top = {qid: sort_by_score(scorer(by_id[qid]))[0] for qid in ("d-prod-1", "d-prod-2", "d-exp-1")}
    assert top == {
        "d-prod-1": "CVE-2026-1002",
        "d-prod-2": "CVE-2026-1003",
        "d-exp-1": "CVE-2026-1004",
    }


def test_dense_scorer_receives_the_translation_not_the_korean_query(root):
    state, by_id = make_state(root, "dense_ko2en")
    scorer = cl.make_scorer(state, {})
    RecordingDense.seen = []
    scores = scorer(by_id["d-prod-1"])
    assert RecordingDense.seen == ["gadget2 vulnerability"]
    assert max(scores, key=scores.get) == "CVE-2026-1002"
    assert state.dense.score(by_id["d-prod-1"].query) != scores  # 원문 질의는 다른 점수


def test_setup_fails_without_a_translation_for_every_question(root):
    write_translations(root, synthetic_rows()[:-1])
    with pytest.raises(ContractError, match="missing for 1 question"):
        make_state(root, "bm25_ko2en")


# ------------------------------------------------------------ 하네스 end-to-end


def test_end_to_end_runs_both_variants_with_their_own_baselines(root):
    comparison = run_crossling(root)
    assert comparison["primary"] == {
        "track": "public",
        "variant": "bm25_ko2en",
        "baseline": "bm25",
        "verdict": "hypothesis-confirmed",
    }
    assert comparison["secondary"] == [
        {
            "track": "public",
            "variant": "dense_ko2en",
            "baseline": "dense",
            "verdict": comparison["comparisons"]["public/dense_ko2en"]["verdict"],
        }
    ]
    primary = comparison["comparisons"]["public/bm25_ko2en"]
    assert primary["delta"] > 0
    assert primary["ci95"]["low"] > 0
    directory = root / OUT / "crossling"
    for name in (
        "public/bm25_ko2en.jsonl",
        "public/dense_ko2en.jsonl",
        "manifest.json",
        "metrics.json",
        "comparison.json",
        "translations.jsonl",
    ):
        assert (directory / name).exists()
    assert harness.verify_outputs(harness.load_experiment("crossling"), root, OUT) == []
    manifest = read_json(directory / "manifest.json")["runs"]
    assert manifest["public/bm25_ko2en"]["baseline"]["retriever"] == "bm25"
    assert manifest["public/dense_ko2en"]["baseline"]["retriever"] == "dense"
    for entry in manifest.values():
        assert entry["reproduction_inputs"]["translations"]["path"] == cl.TRANSLATIONS_PATH
        assert entry["selected"]["config"] == {}
        assert entry["selected"]["selected_on"] == "dev"
        assert entry["test"]["config_hash"] == harness.entry_hash("crossling", entry)
        assert entry["description"]["translation"]["revision"] == cl.MODEL_REVISION


def test_stored_bm25_results_equal_a_hand_computed_search_over_the_translations(root):
    run_crossling(root)
    entry = read_json(root / OUT / "crossling/manifest.json")["runs"]["public/bm25_ko2en"]
    selected = read_json(root / "results/baselines/manifest.json")["runs"]["public/bm25"][
        "selected"
    ]
    bm25 = BM25Index(data.load_public_corpus(root).texts, k1=selected["k1"], b=selected["b"])
    stored = {
        r["question_id"]: r
        for r in data.read_jsonl(root / OUT / "crossling/public/bm25_ko2en.jsonl")
    }
    translations = cl.load_translations(root / cl.TRANSLATIONS_PATH, questions_of(root))
    assert entry["fixed"]["bm25"]["k1"] == selected["k1"]
    for question in questions_of(root):
        if question.excluded:
            continue
        expected = scoring.make_record(
            question.question_id, bm25.score(translations[question.question_id]), question.unjudged
        )
        assert stored[question.question_id] == json.loads(json.dumps(expected))


def test_manifest_cve_counts_match_the_recomputation(root):
    run_crossling(root)
    entry = read_json(root / OUT / "crossling/manifest.json")["runs"]["public/bm25_ko2en"]
    translations = cl.load_translations(root / cl.TRANSLATIONS_PATH, questions_of(root))
    assert entry["description"]["cve_id_preservation"] == cl.cve_preservation(
        questions_of(root), translations
    )


def test_changing_only_the_translations_after_test_fails_the_lock(root):
    run_crossling(root)
    directory = root / OUT / "crossling"
    before = {p: p.read_bytes() for p in directory.rglob("*") if p.is_file()}
    rows = synthetic_rows()
    rows[2] = rows[2] | {"translation": rows[2]["translation"] + " changed"}
    write_translations(root, rows)
    changed_translations = (root / cl.TRANSLATIONS_PATH).read_bytes()
    for split in ("test", "all", "dev"):
        with pytest.raises(LockError):
            run_crossling(root, split=split)
    # 어떤 실행도 결과를 바꾸지 않았다(번역 파일은 우리가 바꾼 그대로)
    after = {p: p.read_bytes() for p in directory.rglob("*") if p.is_file()}
    assert after.pop(directory / "translations.jsonl") == changed_translations
    before.pop(directory / "translations.jsonl")
    assert after == before
    # --compare도 번역 파일이 manifest의 sha256과 다르다고 실패한다
    with pytest.raises(ComparisonError, match="translations"):
        harness.verify_outputs(harness.load_experiment("crossling"), root, OUT)


def test_a_reproduction_run_with_unchanged_translations_is_allowed_and_identical(root):
    run_crossling(root)
    first = (root / OUT / "crossling/public/bm25_ko2en.jsonl").read_bytes()
    manifest = read_json(root / OUT / "crossling/manifest.json")["runs"]["public/bm25_ko2en"]
    again = harness.run_experiment(
        "crossling", "public", root, variants=["bm25_ko2en"], dense_factory=RecordingDense
    )
    assert again["primary"]["verdict"] == "hypothesis-confirmed"
    assert (root / OUT / "crossling/public/bm25_ko2en.jsonl").read_bytes() == first
    again_entry = read_json(root / OUT / "crossling/manifest.json")["runs"]["public/bm25_ko2en"]
    assert again_entry["test"] == manifest["test"]
    # 빈 --out-dir로 BM25 변형만 다시 돌려도(번역 모델·dense 없이) 같은 저장본이 나온다
    harness.run_experiment(
        "crossling", "public", root, variants=["bm25_ko2en"], out_dir=Path("fresh")
    )
    assert (root / "fresh/crossling/public/bm25_ko2en.jsonl").read_bytes() == first


def test_a_missing_translation_fails_the_run_before_any_file_is_written(root):
    write_translations(root, synthetic_rows()[1:])
    before = {p for p in (root / OUT).rglob("*") if p.is_file()}
    with pytest.raises(ContractError, match="missing"):
        run_crossling(root)
    assert {p for p in (root / OUT).rglob("*") if p.is_file()} == before
    assert not (root / OUT / "crossling/manifest.json").exists()


def test_bm25_variant_runs_without_a_dense_factory_or_model(root):
    def no_dense(texts):
        raise AssertionError("dense index must not be built for the BM25 variant")

    comparison = harness.run_experiment(
        "crossling", "public", root, variants=["bm25_ko2en"], dense_factory=no_dense
    )
    assert comparison["primary"]["variant"] == "bm25_ko2en"
    assert comparison["secondary"] == []


def test_results_have_only_allowed_fields_and_no_question_or_translation_text(root):
    run_crossling(root)
    directory = root / OUT / "crossling"
    for variant in cl.VARIANTS["public"]:
        for row in data.read_jsonl(directory / f"public/{variant}.jsonl"):
            scoring.validate_record(row)
    shipped = "".join(
        (directory / name).read_text("utf-8")
        for name in ("manifest.json", "metrics.json", "comparison.json")
    ) + "".join(p.read_text("utf-8") for p in (directory / "public").iterdir())
    assert str(root) not in shipped
    for question in QUERIES:
        assert question["query"] not in shipped
    for name in ("manifest.json", "metrics.json", "comparison.json"):
        assert harness.find_absolute_paths(read_json(directory / name)) == []


def test_module_has_no_top_level_model_imports(tmp_path):
    import subprocess
    import sys

    code = (
        "import sys\n"
        "import krsec_rag_lab.experiments.crossling\n"
        "bad = [m for m in ('numpy', 'torch', 'sentence_transformers', 'transformers', 'sentencepiece')"
        " if m in sys.modules]\n"
        "assert not bad, bad\n"
    )
    done = subprocess.run(
        [sys.executable, "-I", "-c", code], check=False, capture_output=True, text=True
    )
    assert done.returncode == 0, done.stderr
    source = (ROOT / "src/krsec_rag_lab/experiments/crossling.py").read_text("utf-8")
    for package in ("numpy", "torch", "sentence_transformers", "transformers"):
        top_level = [line for line in source.splitlines() if line.startswith(f"import {package}")]
        assert top_level == []


# ------------------------------------------------------------ 커밋된 결과 (모델·KISA 캐시 없이)


@pytest.fixture
def committed_cli(monkeypatch):
    monkeypatch.setattr(run_experiment, "ROOT", ROOT)
    return run_experiment.main


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/crossling not committed yet")
def test_committed_results_pass_the_compare(committed_cli, capsys):
    assert committed_cli(["--exp", "crossling", "--compare"]) == 0
    assert "compare OK" in capsys.readouterr().out


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/crossling not committed yet")
@pytest.mark.parametrize(
    ("filename", "path"),
    [
        ("metrics.json", ("runs", "public/bm25_ko2en", "test", "macro", "ndcg@10")),
        ("comparison.json", ("comparisons", "public/bm25_ko2en", "delta")),
        ("comparison.json", ("comparisons", "public/dense_ko2en", "ci95", "high")),
    ],
)
def test_a_copy_with_one_number_changed_fails_the_compare(
    committed_cli, capsys, tmp_path, filename, path
):
    copy_dir = tmp_path / "crossling"
    shutil.copytree(CROSSLING_DIR, copy_dir)
    assert committed_cli(["--exp", "crossling", "--compare", "--out-dir", str(tmp_path)]) == 0
    target = copy_dir / filename
    payload = read_json(target)
    node = payload
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] += 1e-6
    target.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", "utf-8"
    )
    capsys.readouterr()
    assert committed_cli(["--exp", "crossling", "--compare", "--out-dir", str(tmp_path)]) == 1
    assert "compare FAILED" in capsys.readouterr().err


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/crossling not committed yet")
def test_committed_comparison_fields_and_lock():
    comparison = read_json(CROSSLING_DIR / "comparison.json")
    assert comparison["hypothesis"] == cl.HYPOTHESIS
    assert comparison["primary"]["track"] == "public"
    assert comparison["primary"]["variant"] == "bm25_ko2en"
    assert comparison["primary"]["baseline"] == "bm25"
    assert [(s["variant"], s["baseline"]) for s in comparison["secondary"]] == [
        ("dense_ko2en", "dense")
    ]
    for key in ("public/bm25_ko2en", "public/dense_ko2en"):
        block = comparison["comparisons"][key]
        assert block["verdict"] in ("hypothesis-confirmed", "hypothesis-rejected")
        assert block["ci95"]["low"] <= block["ci95"]["high"]
        assert {"degraded", "improved_top10", "by_type", "cve_explicit"} <= set(block)
    manifest = read_json(CROSSLING_DIR / "manifest.json")
    assert set(manifest["runs"]) == {"public/bm25_ko2en", "public/dense_ko2en"}
    translations_sha = data.file_sha256(CROSSLING_DIR / "translations.jsonl")
    for entry in manifest["runs"].values():
        assert entry["test"]["config_hash"] == harness.entry_hash("crossling", entry)
        assert entry["selected"]["selected_on"] == "dev"
        assert entry["reproduction_inputs"]["translations"] == {
            "path": cl.TRANSLATIONS_PATH,
            "sha256": translations_sha,
        }
        assert entry["fixed"]["translation"] == cl.TRANSLATION_DESCRIPTION
        assert entry["stored_results"]["path"].startswith("results/experiments/crossling/")


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/crossling not committed yet")
def test_committed_translations_cover_the_real_questions_and_keep_the_cve_counts():
    questions = data.load_questions("public", ROOT)
    translations = cl.load_translations(ROOT / cl.TRANSLATIONS_PATH, questions)
    assert len(translations) == len(questions)
    manifest = read_json(CROSSLING_DIR / "manifest.json")
    counts = cl.cve_preservation(questions, translations)
    for entry in manifest["runs"].values():
        assert entry["description"]["cve_id_preservation"] == counts


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/crossling not committed yet")
def test_committed_files_have_only_allowed_fields_and_no_absolute_paths():
    for variant in cl.VARIANTS["public"]:
        for row in data.read_jsonl(CROSSLING_DIR / f"public/{variant}.jsonl"):
            scoring.validate_record(row)
    text = ""
    for path in sorted(CROSSLING_DIR.rglob("*")):
        if path.is_file():
            text += path.read_text("utf-8")
    assert "/Users" not in text
    for filename in ("manifest.json", "metrics.json", "comparison.json"):
        assert harness.find_absolute_paths(read_json(CROSSLING_DIR / filename)) == []
    # 질문 문장은 번역 파일에도 없다(번역 파일은 질문 ID와 번역문, 원문의 sha256만 가진다)
    translation_text = (CROSSLING_DIR / "translations.jsonl").read_text("utf-8")
    for question in data.load_questions("public", ROOT):
        assert question.query not in text.replace(translation_text, "")


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/crossling not committed yet")
def test_committed_results_use_the_stored_baselines_and_the_report_matches_comparison():
    comparison = read_json(CROSSLING_DIR / "comparison.json")
    report = (ROOT / "docs/experiments/crossling.md").read_text("utf-8")
    for key, block in comparison["comparisons"].items():
        assert block["verdict"] in report
        for value in (block["experiment_macro"], block["baseline_macro"]):
            assert f"{value:.4f}" in report, (key, value)
        assert f"{block['delta']:+.4f}" in report, key
        assert f"{block['ci95']['low']:+.4f}" in report, key
        assert f"{block['ci95']['high']:+.4f}" in report, key
        for item in block["degraded"]:
            assert item["question_id"] in report, (key, item["question_id"])
        for item in block["improved_top10"]:
            assert item["question_id"] in report, (key, item["question_id"])
    manifest = read_json(CROSSLING_DIR / "manifest.json")
    cve = manifest["runs"]["public/bm25_ko2en"]["description"]["cve_id_preservation"]
    for label in ("all", "dev", "test"):
        assert str(cve[label]["n_changed"]) in report

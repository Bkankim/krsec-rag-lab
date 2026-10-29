"""하이브리드+RRF 실험 테스트 - 합성 코퍼스·가짜 dense 인덱스만 쓰고 모델·KISA 캐시를 쓰지 않는다.

확인하는 것: RRF 계산식과 동점 처리, k 선택 규칙(최댓값 동점 사례 포함), BM25 설정을 기준선 manifest에서
가져오는지, 하네스를 거친 end-to-end(합성 두 트랙), 모델 패키지 비접촉, 커밋된 results/experiments/hybrid의
정합성과 `--compare`(수치 하나를 바꾼 사본은 exit 1)와 보고서 표 일치.
"""

import json
import shutil
from pathlib import Path

import pytest
from test_baselines_runner import KISA_QUESTIONS, fake_body_loader, write_kisa_fixture
from test_experiments_harness import QUERIES, run_experiment, write_fixture

from krsec_rag_lab.baselines import data, runner, scoring
from krsec_rag_lab.baselines.bm25 import BM25Index
from krsec_rag_lab.experiments import ContractError, LockError, harness
from krsec_rag_lab.experiments import hybrid as hy
from krsec_rag_lab.metrics import sort_by_score

ROOT = Path(__file__).resolve().parents[1]
OUT = Path("results/experiments")
HYBRID_DIR = ROOT / OUT / "hybrid"
GOLD_BY_QUERY = {q["query"]: set(q["gold"]) for q in QUERIES}

# ------------------------------------------------------------ RRF 계산식과 동점


def test_rrf_scores_match_the_formula():
    k = 10
    scores = hy.rrf_fuse([["a", "b", "c"], ["b", "c", "d"]], k)
    assert scores == {
        "a": pytest.approx(1 / 11),
        "b": pytest.approx(1 / 12 + 1 / 11),
        "c": pytest.approx(1 / 13 + 1 / 12),
        "d": pytest.approx(1 / 13),
    }


@pytest.mark.parametrize("k", [10, 30, 60, 100])
def test_rrf_documents_missing_from_a_ranking_get_no_term(k):
    # BM25가 일치 문서를 못 찾은 질의: 빈 순위는 항이 없고 dense 항만 남는다
    scores = hy.rrf_fuse([[], ["x", "y"]], k)
    assert scores == {"x": pytest.approx(1 / (k + 1)), "y": pytest.approx(1 / (k + 2))}
    assert hy.rrf_fuse([], k) == {}


def test_rrf_symmetric_ranks_tie_exactly_and_break_by_doc_id():
    scores = hy.rrf_fuse([["x", "y"], ["y", "x"]], 60)
    assert scores["x"] == scores["y"]  # 부동소수점도 정확히 같다(두 항의 덧셈은 교환법칙)
    record = scoring.make_record("q", scores, frozenset())
    assert [item["doc_id"] for item in record["results"]] == ["x", "y"]
    swapped = scoring.make_record("q", hy.rrf_fuse([["y", "x"], ["x", "y"]], 60), frozenset())
    assert [item["doc_id"] for item in swapped["results"]] == ["x", "y"]  # 문서 ID 오름차순


def test_rrf_uses_full_rankings_before_unjudged_removal():
    scores = hy.rrf_fuse([["a", "u", "b"], ["u", "b", "a"]], 10)
    record = scoring.make_record("q", scores, frozenset({"u"}))
    assert record["n_unjudged_removed"] == 1
    assert "u" not in [item["doc_id"] for item in record["results"]]
    # u가 순위를 차지한 채로 계산했으므로 b의 점수는 (3위 + 2위) 항이다
    by_doc = {item["doc_id"]: item["score"] for item in record["results"]}
    assert by_doc["b"] == pytest.approx(1 / 13 + 1 / 12)
    assert record["top1_score_raw"] == scores[sort_by_score(scores)[0]]


# ------------------------------------------------------------ k 선택 규칙


def rows_for(macros):
    return [
        {"config": {"k": k}, "dev_macro_ndcg@10": macro}
        for k, macro in zip(hy.K_GRID, macros, strict=True)
    ]


def chosen_k(macros):
    rows = rows_for(macros)
    return rows[hy.select(rows)]["config"]["k"]


@pytest.mark.parametrize(
    ("macros", "expected", "why"),
    [
        ((0.5, 0.5, 0.5, 0.5), 60, "네 값이 모두 같으면 60"),
        ((0.5, 0.7, 0.6, 0.4), 30, "최댓값이 하나면 그 값"),
        ((0.7, 0.5, 0.6, 0.4), 10, "최댓값이 하나면 그 값(가장 작은 k라도)"),
        ((0.5, 0.5, 0.6, 0.6), 60, "60과 100이 같은 최댓값이면 60"),
        ((0.5, 0.7, 0.7, 0.4), 60, "30과 60이 같은 최댓값이면 60"),
        ((0.7, 0.6, 0.6, 0.7), 10, "10과 100이 같은 최댓값이고 60이 아니면 가장 작은 k"),
        ((0.7, 0.7, 0.6, 0.7), 10, "10, 30, 100이 같은 최댓값이고 60이 낮으면 가장 작은 k"),
        ((0.5, 0.7, 0.6, 0.7), 30, "30과 100이 같은 최댓값이면 가장 작은 k"),
        ((0.6, 0.7, 0.7, 0.7), 60, "30, 60, 100이 같은 최댓값이면 60"),
        ((0.5, 0.5, 0.5, 0.6), 100, "최댓값이 100 하나면 100"),
    ],
)
def test_k_selection_rule_including_ties(macros, expected, why):
    assert chosen_k(macros) == expected, why


def test_k_selection_treats_float_noise_as_a_tie_but_not_real_differences():
    assert chosen_k((0.7, 0.7 + 1e-14, 0.6, 0.7 - 1e-14)) == 10  # 60이 아닌 동점 -> 가장 작은 k
    assert chosen_k((0.5, 0.5, 0.7, 0.7 - 1e-13)) == 60
    assert chosen_k((0.5, 0.5, 0.7 - 1e-6, 0.7)) == 100  # 1e-6 차이는 동점이 아니다


def test_grid_and_selection_rule_are_the_preregistered_ones():
    assert hy.K_GRID == (10, 30, 60, 100)
    assert [c["k"] for c in hy.grid("public", "rrf")] == [10, 30, 60, 100]
    assert hy.grid("kisa", "rrf") == hy.grid("public", "rrf")
    assert hy.DEFAULT_K == 60
    assert hy.PRIMARY == ("public", "rrf")
    assert hy.BASELINES == {"public": "bm25", "kisa": "bm25"}
    assert "dev" in hy.SELECTION_RULE


# ------------------------------------------------------------ 가짜 dense와 end-to-end


class OracleDense:
    """가짜 dense 인덱스: 질의의 정답 문서에 1.0, 나머지에 0.0을 준다. 모델을 부르지 않는다."""

    def __init__(self, texts):
        self.texts = texts
        self.meta = {
            "model": {"name": "fake", "revision": "fake", "n_truncated_docs": 0},
            "runtime": {"python": "fake"},
            "doc_encode_seconds": 0.0,
        }

    def score(self, query):
        gold = GOLD_BY_QUERY.get(query, set())
        return {doc_id: 1.0 if doc_id in gold else 0.0 for doc_id in self.texts}


@pytest.fixture
def root(tmp_path):
    write_fixture(tmp_path)
    runner.run_baseline("public", "bm25", tmp_path)
    return tmp_path


def run_hybrid(root, split="all", **kwargs):
    return harness.run_experiment(
        "hybrid", "public", root, split=split, dense_factory=OracleDense, **kwargs
    )


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_hybrid_end_to_end_on_the_synthetic_public_track(root):
    comparison = run_hybrid(root)
    assert comparison["primary"] == {
        "track": "public",
        "variant": "rrf",
        "baseline": "bm25",
        "verdict": "hypothesis-confirmed",
    }
    assert comparison["secondary"] == []
    block = comparison["comparisons"]["public/rrf"]
    assert block["delta"] == pytest.approx(2 / 3)  # 쉬운 유형 0, 어려운 두 유형 +1
    assert block["ci95"]["low"] > 0
    directory = root / OUT / "hybrid"
    for name in ("public/rrf.jsonl", "manifest.json", "metrics.json", "comparison.json"):
        assert (directory / name).exists()
    # 같은 저장본에서 --compare가 일치한다
    assert harness.verify_outputs(harness.load_experiment("hybrid"), root, OUT) == []


def test_manifest_records_grid_selection_and_baseline_bm25_settings(root):
    run_hybrid(root)
    entry = read_json(root / OUT / "hybrid/manifest.json")["runs"]["public/rrf"]
    rows = entry["grid"]["rows"]
    assert [row["config"]["k"] for row in rows] == [10, 30, 60, 100]
    assert entry["grid"]["selection_rule"] == hy.SELECTION_RULE
    assert entry["selected"]["config"]["k"] == rows[hy.select(rows)]["config"]["k"]
    assert entry["selected"]["selected_on"] == "dev"
    baseline = read_json(root / "results/baselines/manifest.json")["runs"]["public/bm25"][
        "selected"
    ]
    assert entry["fixed"]["bm25"] == {
        "k1": baseline["k1"],
        "b": baseline["b"],
        "tokenizer": "bm25-tok-v1",
    }
    assert entry["fixed"]["dense"] == {
        "name": "BAAI/bge-m3",
        "revision": "5617a9f61b028005a4858fdac845db406aefb181",
    }
    assert entry["description"]["bm25"]["k1"] == baseline["k1"]
    assert entry["baseline"]["retriever"] == "bm25"
    assert entry["test"]["config"] == entry["selected"]["config"]


def test_stored_results_equal_a_hand_computed_rrf_with_the_selected_k(root):
    run_hybrid(root)
    entry = read_json(root / OUT / "hybrid/manifest.json")["runs"]["public/rrf"]
    k = entry["selected"]["config"]["k"]
    baseline = read_json(root / "results/baselines/manifest.json")["runs"]["public/bm25"][
        "selected"
    ]
    corpus = data.load_public_corpus(root)
    bm25 = BM25Index(corpus.texts, k1=baseline["k1"], b=baseline["b"])
    dense = OracleDense(corpus.texts)
    stored = {r["question_id"]: r for r in data.read_jsonl(root / OUT / "hybrid/public/rrf.jsonl")}
    for question in data.load_questions("public", root):
        if question.excluded:
            continue
        rankings = [
            sort_by_score(bm25.score(question.query)),
            sort_by_score(dense.score(question.query)),
        ]
        expected = scoring.make_record(
            question.question_id, hy.rrf_fuse(rankings, k), question.unjudged
        )
        assert stored[question.question_id] == json.loads(json.dumps(expected))


def test_tau_is_selected_on_dev_top1_of_the_fused_scores(root):
    run_hybrid(root)
    entry = read_json(root / OUT / "hybrid/manifest.json")["runs"]["public/rrf"]
    questions = data.load_questions("public", root)
    stored = {r["question_id"]: r for r in data.read_jsonl(root / OUT / "hybrid/public/rrf.jsonl")}
    dev = [q for q in questions if q.split == "dev" and not q.excluded]
    expected = scoring.select_tau(
        [stored[q.question_id]["top1_score_raw"] for q in dev if not q.gold],
        [stored[q.question_id]["top1_score_raw"] for q in dev if q.gold],
    )
    assert entry["selected"]["tau"] == expected["tau"]


def test_hybrid_test_is_locked_after_one_run(root, monkeypatch):
    run_hybrid(root)
    before = {p: p.read_bytes() for p in (root / OUT / "hybrid").rglob("*") if p.is_file()}
    monkeypatch.setattr(hy, "K_GRID", (10, 30))  # 격자(= 사전 등록 설정)를 바꿔 다시 고르게 한다
    changed = [c for c in hy.grid("public", "rrf")]
    assert changed == [{"k": 10}, {"k": 30}]
    with pytest.raises(LockError):
        run_hybrid(root)
    with pytest.raises(LockError):
        run_hybrid(root, split="dev")
    after = {p: p.read_bytes() for p in (root / OUT / "hybrid").rglob("*") if p.is_file()}
    assert after == before


def test_changed_baseline_bm25_settings_lock_the_test_config(root):
    run_hybrid(root)
    manifest_path = root / "results/baselines/manifest.json"
    manifest = read_json(manifest_path)
    manifest["runs"]["public/bm25"]["selected"]["k1"] = 9.9
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    with pytest.raises(LockError):
        run_hybrid(root, split="test")


def test_tokenizer_mismatch_with_the_baseline_is_a_contract_error():
    manifest = {"runs": {"public/bm25": {"config": {"tokenizer": {"id": "other"}}, "selected": {}}}}
    with pytest.raises(ContractError, match="tokenizer"):
        hy.fixed_config("public", "rrf", manifest)


def test_hybrid_kisa_track_with_a_fake_body_loader(tmp_path):
    write_fixture(tmp_path)
    runner.run_baseline("public", "bm25", tmp_path)
    write_kisa_fixture(tmp_path)
    runner.run_baseline("kisa", "bm25", tmp_path, load_body=fake_body_loader)
    comparison = harness.run_experiment(
        "hybrid",
        "kisa",
        tmp_path,
        load_body=fake_body_loader,
        dense_factory=OracleDense,
    )
    assert comparison["primary"] is None  # 주 트랙(public)은 아직 안 돌렸다
    assert [s["track"] for s in comparison["secondary"]] == ["kisa"]
    out_dir = tmp_path / OUT / "hybrid"
    rows = data.read_jsonl(out_dir / "kisa/rrf.jsonl")
    assert {r["question_id"] for r in rows} == {
        q["question_id"] for q in KISA_QUESTIONS if not q["excluded"]
    }
    text = "".join(p.read_text("utf-8") for p in out_dir.rglob("*") if p.is_file())
    assert "라우터 보안 업데이트" not in text  # 본문 비유출
    assert str(tmp_path) not in text
    # 두 트랙을 모두 돌리면 primary(공개)와 secondary(KISA)가 채워진다
    both = harness.run_experiment("hybrid", "public", tmp_path, dense_factory=OracleDense)
    assert both["primary"]["track"] == "public"
    assert [s["track"] for s in both["secondary"]] == ["kisa"]


def test_hybrid_module_has_no_top_level_model_imports():
    source = (ROOT / "src/krsec_rag_lab/experiments/hybrid.py").read_text("utf-8")
    for package in ("numpy", "torch", "sentence_transformers"):
        assert f"import {package}" not in source


# ------------------------------------------------------------ 커밋된 결과 (model·KISA 캐시 없이)

COMMITTED = (HYBRID_DIR / "comparison.json").exists()


@pytest.fixture
def committed_cli(monkeypatch):
    monkeypatch.setattr(run_experiment, "ROOT", ROOT)
    return run_experiment.main


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/hybrid not committed yet")
def test_committed_results_pass_the_compare(committed_cli, capsys):
    assert committed_cli(["--exp", "hybrid", "--compare"]) == 0
    assert "compare OK" in capsys.readouterr().out


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/hybrid not committed yet")
@pytest.mark.parametrize(
    ("filename", "path"),
    [
        ("metrics.json", ("runs", "public/rrf", "test", "macro", "ndcg@10")),
        ("metrics.json", ("runs", "kisa/rrf", "test", "macro", "ndcg@10")),
        ("comparison.json", ("comparisons", "public/rrf", "delta")),
        ("comparison.json", ("comparisons", "kisa/rrf", "ci95", "high")),
    ],
)
def test_a_copy_with_one_number_changed_fails_the_compare(
    committed_cli, capsys, tmp_path, filename, path
):
    copy_dir = tmp_path / "hybrid"
    shutil.copytree(HYBRID_DIR, copy_dir)
    assert committed_cli(["--exp", "hybrid", "--compare", "--out-dir", str(tmp_path)]) == 0
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
    assert committed_cli(["--exp", "hybrid", "--compare", "--out-dir", str(tmp_path)]) == 1
    assert "compare FAILED" in capsys.readouterr().err


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/hybrid not committed yet")
def test_committed_comparison_fields_and_lock():
    comparison = read_json(HYBRID_DIR / "comparison.json")
    assert comparison["primary"]["track"] == "public"
    assert comparison["primary"]["variant"] == "rrf"
    assert comparison["primary"]["baseline"] == "bm25"
    assert [s["track"] for s in comparison["secondary"]] == ["kisa"]
    for key in ("public/rrf", "kisa/rrf"):
        block = comparison["comparisons"][key]
        assert block["verdict"] in ("hypothesis-confirmed", "hypothesis-rejected")
        assert block["ci95"]["low"] <= block["ci95"]["high"]
        assert {"degraded", "improved_top10", "by_type", "cve_explicit"} <= set(block)
        assert len(block["improved_top10"]) <= 10
    manifest = read_json(HYBRID_DIR / "manifest.json")
    for entry in manifest["runs"].values():
        assert entry["test"]["config_hash"] == harness.entry_hash("hybrid", entry)
        assert entry["selected"]["config"]["k"] in hy.K_GRID
        assert entry["selected"]["selected_on"] == "dev"
        assert entry["stored_results"]["path"].startswith("results/experiments/hybrid/")


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/hybrid not committed yet")
def test_committed_files_have_only_allowed_fields_and_no_absolute_paths():
    for path in (HYBRID_DIR / "public/rrf.jsonl", HYBRID_DIR / "kisa/rrf.jsonl"):
        for row in data.read_jsonl(path):
            scoring.validate_record(row)
    text = ""
    for path in sorted(HYBRID_DIR.rglob("*")):
        if path.is_file():
            text += path.read_text("utf-8")
    assert "/Users" not in text
    for filename in ("manifest.json", "metrics.json", "comparison.json"):
        assert harness.find_absolute_paths(read_json(HYBRID_DIR / filename)) == []
    # 질문 문장·문서 본문 조각이 없다(합성이 아닌 실제 입력과 대조: 질문 텍스트가 결과에 없어야 한다)
    for question in data.load_questions("public", ROOT):
        assert question.query not in text


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/hybrid not committed yet")
def test_committed_results_use_the_stored_baseline_and_the_report_matches_comparison():
    comparison = read_json(HYBRID_DIR / "comparison.json")
    report = (ROOT / "docs/experiments/hybrid.md").read_text("utf-8")
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

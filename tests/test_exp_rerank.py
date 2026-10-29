"""리랭커 실험 테스트 - 합성 코퍼스·가짜 리랭커만 쓰고 모델·KISA 캐시를 쓰지 않는다.

확인하는 것: 점수 합성(후보 원점수 + N 밖 BM25 순서 꼬리), BM25 순서와 반대인 합성 리랭커 점수를 실제 실험
경로(하네스 -> setup -> make_scorer -> 공통 채점)에 주입했을 때 후보 안 순서가 뒤집히는지, 후보 점수가 꼬리
BM25 점수보다 작아도 연결 순위가 유지되는지, 동일 후보군 성질(후보 집합 불변, N 밖 순서 보존, 후보 < N),
N 선택 규칙(같으면 작은 N), 기준선 BM25 설정 사용, 모델 패키지 비접촉, 커밋된 results/experiments/rerank의
정합성과 `--compare`(수치 하나를 바꾼 사본은 exit 1), 허용 필드, 보고서 표 일치.
"""

import json
import shutil
from pathlib import Path

import pytest
from test_baselines_runner import fake_body_loader, write_kisa_fixture
from test_experiments_harness import public_query, run_experiment, write_jsonl

from krsec_rag_lab.baselines import data, runner, scoring
from krsec_rag_lab.baselines.bm25 import BM25Index
from krsec_rag_lab.experiments import ContractError, LockError, harness
from krsec_rag_lab.experiments import rerank as rr
from krsec_rag_lab.metrics import recall_at_k, sort_by_score

ROOT = Path(__file__).resolve().parents[1]
OUT = Path("results/experiments")
RERANK_DIR = ROOT / OUT / "rerank"

# ------------------------------------------------------------ 점수 합성


def ranking_of(n_docs):
    return [f"d{i:03d}" for i in range(n_docs)]


def test_combine_scores_reversed_reranker_flips_candidates_and_keeps_the_tail_order():
    ranking = ranking_of(8)
    n = 5
    raw = [1.0, 2.0, 3.0, 4.0, 5.0]  # BM25 순서(d000 1위)와 반대: 마지막 후보가 1위
    scores = rr.combine_scores(ranking, raw, n)
    assert sort_by_score(scores)[:n] == ["d004", "d003", "d002", "d001", "d000"]
    assert sort_by_score(scores)[n:] == ranking[n:]  # N 밖은 BM25 순서 그대로
    assert {doc: scores[doc] for doc in ranking[:n]} == dict(zip(ranking[:n], raw, strict=True))


@pytest.mark.parametrize(
    "raw",
    [
        [-50.0, -40.0, -30.0],  # 후보 점수가 꼬리 BM25 점수(양수)보다 훨씬 작다
        [-1e6, -2e6, -3e6],
        [0.0, 0.0, 0.0],
        [5.0, 5.0, 5.0],
        [1e-9, -1e-9, 0.0],
    ],
)
def test_combine_scores_tail_stays_below_every_candidate_even_when_candidates_score_low(raw):
    ranking = ranking_of(10)
    scores = rr.combine_scores(ranking, raw, 3)
    candidate_min = min(raw)
    tail = [scores[doc] for doc in ranking[3:]]
    assert all(score < candidate_min for score in tail)  # 모든 후보보다 엄격히 작다
    assert tail == sorted(tail, reverse=True)  # 꼬리 점수는 BM25 순서대로 줄어든다
    assert len(set(tail)) == len(tail)
    order = sort_by_score(scores)
    assert set(order[:3]) == set(ranking[:3])  # 후보 집합은 그대로 앞에 온다
    assert order[3:] == ranking[3:]


@pytest.mark.parametrize("n_docs", [0, 1, 5, 19, 20, 21, 49, 50, 51, 100, 101, 250])
@pytest.mark.parametrize("n", rr.N_GRID)
def test_combine_scores_candidate_set_is_the_bm25_top_n_for_any_size(n, n_docs):
    ranking = ranking_of(n_docs)
    n_candidates = min(n, n_docs)
    raw = [float(-i) for i in range(n_candidates)][::-1]  # 반대 순서
    scores = rr.combine_scores(ranking, raw, n)
    assert set(scores) == set(ranking)  # 후보를 더하거나 빼지 않는다
    order = sort_by_score(scores)
    assert set(order[:n_candidates]) == set(ranking[:n_candidates])
    assert order[n_candidates:] == ranking[n_candidates:]
    if n_candidates:
        assert order[:n_candidates] == ranking[:n_candidates][::-1]


def test_combine_scores_empty_ranking_and_length_mismatch():
    assert rr.combine_scores([], [], 20) == {}
    with pytest.raises(ContractError, match="scores"):
        rr.combine_scores(ranking_of(5), [1.0, 2.0], 3)


def test_combine_scores_top1_raw_is_the_reranker_top_score():
    scores = rr.combine_scores(ranking_of(6), [0.5, 7.5, -2.0], 3)
    record = scoring.make_record("q", scores, frozenset())
    assert record["top1_score_raw"] == 7.5
    assert [item["doc_id"] for item in record["results"]][:3] == ["d001", "d000", "d002"]


# ------------------------------------------------------------ 사전 등록 값


def test_preregistered_constants():
    assert rr.NAME == "rerank"
    assert rr.PRIMARY == ("public", "rerank")
    assert rr.VARIANTS == {"public": ("rerank",), "kisa": ("rerank",)}
    assert rr.BASELINES == {"public": "bm25", "kisa": "bm25"}
    assert rr.N_GRID == (20, 50, 100)
    assert [c["n"] for c in rr.grid("public", "rerank")] == [20, 50, 100]
    assert rr.grid("kisa", "rerank") == rr.grid("public", "rerank")
    assert rr.MODEL_NAME == "BAAI/bge-reranker-v2-m3"
    assert len(rr.MODEL_REVISION) == 40
    assert rr.MAX_LENGTH == 512
    assert "dev" in rr.SELECTION_RULE and "작은 N" in rr.SELECTION_RULE


def test_default_select_prefers_the_smaller_n_on_ties():
    rows = [{"config": {"n": n}, "dev_macro_ndcg@10": m} for n, m in zip(rr.N_GRID, (0.5,) * 3)]
    assert harness.default_select(rows) == 0
    rows[1]["dev_macro_ndcg@10"] = rows[2]["dev_macro_ndcg@10"] = 0.6
    assert harness.default_select(rows) == 1  # 50과 100이 같은 최댓값이면 작은 50


def test_tokenizer_mismatch_with_the_baseline_is_a_contract_error():
    manifest = {"runs": {"public/bm25": {"config": {"tokenizer": {"id": "other"}}, "selected": {}}}}
    with pytest.raises(ContractError, match="tokenizer"):
        rr.fixed_config("public", "rerank", manifest)


def test_module_has_no_top_level_model_imports_and_never_reads_labels():
    import inspect

    source = (ROOT / "src/krsec_rag_lab/experiments/rerank.py").read_text("utf-8")
    top_level = [line for line in source.splitlines() if line.startswith(("import ", "from "))]
    for package in ("numpy", "torch", "sentence_transformers", "transformers"):
        assert not any(package in line for line in top_level), package
    scorer_source = inspect.getsource(rr.make_scorer)
    for label in ("gold", "unjudged", "split", "query_type", "excluded"):
        assert label not in scorer_source, label


# ------------------------------------------------------------ 합성 코퍼스와 가짜 리랭커
# 120개 문서는 길이가 같아 "common" 질의에서 BM25 점수가 모두 같고 순위는 문서 ID 오름차순이다: 문서 i = BM25 (i+1)위.
# 문서 0..6은 "rare"를 갖고 있어 "rare" 질의의 후보는 7건(< N)이다.

N_DOCS = 120
N_RARE = 7


def doc_id(i):
    return f"CVE-2026-{2000 + i}"


def doc_text(i):
    return "common rare" if i < N_RARE else f"common gadget{i}"


def build_queries(gold_rank):
    gold = doc_id(gold_rank - 1)
    queries = []
    for n in range(3):
        queries.append(
            public_query(f"d-prod-{n}", f"common qd{n}", "product_symptom", "dev", [gold])
        )
    queries.append(
        public_query("d-rare-1", "rare qd", "explanation_comparison", "dev", [doc_id(3)])
    )
    queries.append(public_query("d-na-1", "zzqx unknown", "no_answer", "dev"))
    for n in range(4):
        queries.append(
            public_query(f"t-prod-{n}", f"common qt{n}", "product_symptom", "test", [gold])
        )
    queries.append(
        public_query("t-rare-1", "rare qt", "explanation_comparison", "test", [doc_id(4)])
    )
    queries.append(public_query("t-na-1", "zzqx unknown2", "no_answer", "test"))
    return queries


def write_world(root, gold_rank):
    rows = [{"id": doc_id(i), "description_en": doc_text(i)} for i in range(N_DOCS)]
    write_jsonl(root / data.PUBLIC_CORPUS, rows)
    write_jsonl(root / data.PUBLIC_QUERIES, build_queries(gold_rank))
    runner.run_baseline("public", "bm25", root)


class FakeReranker:
    """모델을 부르지 않는 가짜 리랭커. 호출 기록(질의, 문서 ID 목록, 문서 본문)을 남긴다."""

    def __init__(self, texts, mode):
        self.texts = texts
        self.mode = mode
        self.calls = []
        self.meta = {"runtime": {"python": "fake"}, "n_docs": len(texts)}

    def score(self, query, doc_ids):
        self.calls.append((query, tuple(doc_ids), tuple(self.texts[d] for d in doc_ids)))
        if self.mode == "reverse":  # BM25 순서(앞이 1위)와 반대: 뒤쪽 후보일수록 높다
            return [float(i) - 100.0 for i in range(len(doc_ids))], 0
        gold = {  # oracle: 질문의 정답 문서에 높은 점수. 질의 문자열로 정답을 찾는다
            q["query"]: set(q["gold"]) for q in self.golds
        }.get(query, set())
        return [5.0 if d in gold else -5.0 for d in doc_ids], 0


@pytest.fixture
def fake_reranker(monkeypatch):
    """`build_reranker`를 가짜로 바꾼다. 만들어진 가짜 객체를 `made` 목록에 남긴다."""
    made = []
    state = {"mode": "reverse", "golds": []}

    def build(texts):
        fake = FakeReranker(texts, state["mode"])
        fake.golds = state["golds"]
        made.append(fake)
        return fake

    monkeypatch.setattr(rr, "build_reranker", build)
    return made, state


def run_rerank(root, **kwargs):
    return harness.run_experiment("rerank", "public", root, **kwargs)


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def stored_rows(root, track="public"):
    return {
        r["question_id"]: r for r in data.read_jsonl(root / OUT / f"rerank/{track}/rerank.jsonl")
    }


def bm25_full_ranking(root, query):
    params = read_json(root / "results/baselines/manifest.json")["runs"]["public/bm25"]["selected"]
    corpus = data.load_public_corpus(root)
    return sort_by_score(BM25Index(corpus.texts, k1=params["k1"], b=params["b"]).score(query))


# ------------------------------------------------------------ 실제 실험 경로에 합성 리랭커 주입


@pytest.fixture
def reversed_world(tmp_path, fake_reranker):
    write_world(tmp_path, gold_rank=30)
    return tmp_path


def test_reverse_reranker_through_the_real_experiment_path_flips_order_inside_the_candidates(
    reversed_world, fake_reranker
):
    root = reversed_world
    comparison = run_rerank(root)
    n = read_json(root / OUT / "rerank/manifest.json")["runs"]["public/rerank"]["selected"][
        "config"
    ]["n"]
    stored = stored_rows(root)
    for question in data.load_questions("public", root):
        if question.excluded:
            continue
        ranking = bm25_full_ranking(root, question.query)
        candidates = ranking[:n]
        expected = candidates[::-1] + ranking[n:]
        got = [item["doc_id"] for item in stored[question.question_id]["results"]]
        assert got == expected[: len(got)], question.question_id
        if candidates:
            assert got[0] == candidates[-1]  # 후보 안 BM25 꼴찌가 리랭커 1위
    assert comparison["primary"]["variant"] == "rerank"


def test_reranker_receives_exactly_the_bm25_top_n_in_bm25_order_with_the_indexed_text(
    reversed_world, fake_reranker
):
    made, _ = fake_reranker
    root = reversed_world
    run_rerank(root)
    n = read_json(root / OUT / "rerank/manifest.json")["runs"]["public/rerank"]["selected"][
        "config"
    ]["n"]
    corpus = data.load_public_corpus(root)
    assert len(made) == 1  # 모델(가짜)은 실행 하나에 한 번만 만든다
    fake = made[0]
    assert fake.calls
    for query, doc_ids, texts in fake.calls:
        ranking = bm25_full_ranking(root, query)
        assert list(doc_ids) in (ranking[:20], ranking[:50], ranking[:100]), query
        assert texts == tuple(corpus.texts[d] for d in doc_ids)  # 색인 텍스트 그대로
        assert query in {q.query for q in data.load_questions("public", root)}  # 질의 그대로
    assert n in rr.N_GRID


def test_candidates_fewer_than_n_rerank_only_what_bm25_found(reversed_world, fake_reranker):
    made, _ = fake_reranker
    root = reversed_world
    run_rerank(root)
    rare_calls = [call for call in made[0].calls if call[0].startswith("rare")]
    assert rare_calls
    for _, doc_ids, _ in rare_calls:
        assert len(doc_ids) == N_RARE  # N(20, 50, 100)보다 적은 후보는 그만큼만
        assert set(doc_ids) == {doc_id(i) for i in range(N_RARE)}
    stored = stored_rows(root)
    assert [item["doc_id"] for item in stored["t-rare-1"]["results"]] == [
        doc_id(i) for i in reversed(range(N_RARE))
    ]  # 7건 모두 뒤집히고 문서를 더하지 않는다
    assert len(stored["t-rare-1"]["results"]) == N_RARE


def test_recall_at_n_equals_the_baseline_and_only_the_order_changes(reversed_world, fake_reranker):
    root = reversed_world
    run_rerank(root)
    n = read_json(root / OUT / "rerank/manifest.json")["runs"]["public/rerank"]["selected"][
        "config"
    ]["n"]
    stored = stored_rows(root)
    baseline = {
        r["question_id"]: r for r in data.read_jsonl(root / "results/baselines/public/bm25.jsonl")
    }
    for question in data.load_questions("public", root):
        if question.excluded or not question.gold:
            continue
        new = [item["doc_id"] for item in stored[question.question_id]["results"]]
        old = [item["doc_id"] for item in baseline[question.question_id]["results"]]
        assert set(new) == set(old)  # 검색된 문서 집합 불변
        assert new[n:] == old[n:]  # N 밖 순서 보존
        assert set(new[:n]) == set(old[:n])  # 후보 집합 불변
        assert recall_at_k(new, question.gold, n) == recall_at_k(old, question.gold, n)


@pytest.mark.parametrize(
    ("gold_rank", "expected_n"),
    [(10, 20), (30, 50), (60, 100)],  # 모든 N이 같으면 20, 정답이 30위면 50부터, 60위면 100만
)
def test_n_is_chosen_on_dev_and_ties_go_to_the_smaller_n(
    tmp_path, fake_reranker, gold_rank, expected_n
):
    _, state = fake_reranker
    state["mode"] = "oracle"
    state["golds"] = build_queries(gold_rank)
    write_world(tmp_path, gold_rank)
    run_rerank(tmp_path)
    entry = read_json(tmp_path / OUT / "rerank/manifest.json")["runs"]["public/rerank"]
    rows = entry["grid"]["rows"]
    assert [row["config"]["n"] for row in rows] == [20, 50, 100]
    assert entry["grid"]["selection_rule"] == rr.SELECTION_RULE
    assert entry["selected"]["config"] == {"n": expected_n}
    assert entry["selected"]["selected_on"] == "dev"
    assert entry["test"]["config"] == {"n": expected_n}
    macros = {row["config"]["n"]: row["dev_macro_ndcg@10"] for row in rows}
    best = max(macros.values())
    assert macros[expected_n] == best
    assert all(macros[n] < best for n in macros if n < expected_n)  # 더 작은 N은 엄밀히 낮다


def test_oracle_reranker_moves_gold_from_the_bm25_tail_into_rank_one_when_n_reaches_it(
    tmp_path, fake_reranker
):
    _, state = fake_reranker
    state["mode"] = "oracle"
    state["golds"] = build_queries(60)
    write_world(tmp_path, 60)
    comparison = run_rerank(tmp_path)
    block = comparison["comparisons"]["public/rerank"]
    assert block["verdict"] == "hypothesis-confirmed"
    assert block["delta"] > 0 and block["ci95"]["low"] > 0
    stored = stored_rows(tmp_path)
    assert stored["t-prod-0"]["results"][0]["doc_id"] == doc_id(59)  # BM25 60위 -> 리랭커 1위
    assert stored["t-prod-0"]["top1_score_raw"] == 5.0  # 리랭커 원점수 1위
    assert harness.verify_outputs(harness.load_experiment("rerank"), tmp_path, OUT) == []


def test_manifest_records_baseline_bm25_settings_model_and_usage(reversed_world, fake_reranker):
    root = reversed_world
    run_rerank(root)
    entry = read_json(root / OUT / "rerank/manifest.json")["runs"]["public/rerank"]
    baseline = read_json(root / "results/baselines/manifest.json")["runs"]["public/bm25"][
        "selected"
    ]
    assert entry["fixed"]["bm25"] == {
        "k1": baseline["k1"],
        "b": baseline["b"],
        "tokenizer": "bm25-tok-v1",
    }
    assert entry["fixed"]["reranker"]["name"] == "BAAI/bge-reranker-v2-m3"
    assert entry["fixed"]["reranker"]["revision"] == rr.MODEL_REVISION
    assert entry["fixed"]["reranker"]["max_length"] == 512
    assert entry["description"]["bm25"]["k1"] == baseline["k1"]
    assert entry["description"]["reranker"]["revision"] == rr.MODEL_REVISION
    usage = entry["description"]["selected_n_usage"]
    assert usage["questions"] > 0 and usage["pairs"] > 0 and usage["truncated_pairs"] == 0
    assert entry["baseline"]["retriever"] == "bm25"
    assert entry["test"]["config_hash"] == harness.entry_hash("rerank", entry)


def test_rerank_test_is_locked_after_one_run(reversed_world, monkeypatch):
    root = reversed_world
    run_rerank(root)
    before = {p: p.read_bytes() for p in (root / OUT / "rerank").rglob("*") if p.is_file()}
    monkeypatch.setattr(rr, "N_GRID", (50, 100))  # 격자(= 사전 등록 설정)를 바꿔 다시 고르게 한다
    with pytest.raises(LockError):
        run_rerank(root)
    with pytest.raises(LockError):
        run_rerank(root, split="dev")
    after = {p: p.read_bytes() for p in (root / OUT / "rerank").rglob("*") if p.is_file()}
    assert after == before


def test_changed_baseline_bm25_settings_lock_the_test_config(reversed_world):
    root = reversed_world
    run_rerank(root)
    manifest_path = root / "results/baselines/manifest.json"
    manifest = read_json(manifest_path)
    manifest["runs"]["public/bm25"]["selected"]["k1"] = 9.9
    manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    with pytest.raises(LockError):
        run_rerank(root, split="test")


def test_stored_files_only_have_allowed_fields_and_no_text(reversed_world):
    root = reversed_world
    run_rerank(root)
    for row in data.read_jsonl(root / OUT / "rerank/public/rerank.jsonl"):
        scoring.validate_record(row)
    text = "".join(p.read_text("utf-8") for p in (root / OUT / "rerank").rglob("*") if p.is_file())
    assert str(root) not in text
    for query in build_queries(30):
        assert query["query"] not in text  # 질문 문장은 결과에 없다


def test_kisa_track_with_fake_loader_and_fake_reranker(tmp_path, fake_reranker):
    made, _ = fake_reranker
    write_world(tmp_path, 30)
    write_kisa_fixture(tmp_path)
    runner.run_baseline("kisa", "bm25", tmp_path, load_body=fake_body_loader)
    comparison = harness.run_experiment("rerank", "kisa", tmp_path, load_body=fake_body_loader)
    assert comparison["primary"] is None  # 주 트랙(public)은 아직 안 돌렸다
    assert [s["track"] for s in comparison["secondary"]] == ["kisa"]
    out_dir = tmp_path / OUT / "rerank"
    text = "".join(p.read_text("utf-8") for p in out_dir.rglob("*") if p.is_file())
    assert "라우터 보안 업데이트" not in text  # 본문 비유출
    assert str(tmp_path) not in text
    baseline = {
        r["question_id"]: r for r in data.read_jsonl(tmp_path / "results/baselines/kisa/bm25.jsonl")
    }
    for row in data.read_jsonl(out_dir / "kisa/rerank.jsonl"):
        old = baseline[row["question_id"]]
        assert {i["doc_id"] for i in row["results"]} == {i["doc_id"] for i in old["results"]}
    both = harness.run_experiment("rerank", "public", tmp_path)
    assert both["primary"]["track"] == "public"
    assert [s["track"] for s in both["secondary"]] == ["kisa"]
    assert len(made) == 2


# ------------------------------------------------------------ 커밋된 결과 (모델·KISA 캐시 없이)

COMMITTED = (RERANK_DIR / "comparison.json").exists()
needs_results = pytest.mark.skipif(not COMMITTED, reason="results/experiments/rerank not committed")


@pytest.fixture
def committed_cli(monkeypatch):
    monkeypatch.setattr(run_experiment, "ROOT", ROOT)
    return run_experiment.main


@needs_results
def test_committed_results_pass_the_compare(committed_cli, capsys):
    assert committed_cli(["--exp", "rerank", "--compare"]) == 0
    assert "compare OK" in capsys.readouterr().out


@needs_results
@pytest.mark.parametrize(
    ("filename", "path"),
    [
        ("metrics.json", ("runs", "public/rerank", "test", "macro", "ndcg@10")),
        ("metrics.json", ("runs", "kisa/rerank", "test", "macro", "ndcg@10")),
        ("comparison.json", ("comparisons", "public/rerank", "delta")),
        ("comparison.json", ("comparisons", "kisa/rerank", "ci95", "high")),
    ],
)
def test_a_copy_with_one_number_changed_fails_the_compare(
    committed_cli, capsys, tmp_path, filename, path
):
    copy_dir = tmp_path / "rerank"
    shutil.copytree(RERANK_DIR, copy_dir)
    assert committed_cli(["--exp", "rerank", "--compare", "--out-dir", str(tmp_path)]) == 0
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
    assert committed_cli(["--exp", "rerank", "--compare", "--out-dir", str(tmp_path)]) == 1
    assert "compare FAILED" in capsys.readouterr().err


@needs_results
def test_committed_comparison_fields_primary_and_lock():
    comparison = read_json(RERANK_DIR / "comparison.json")
    assert comparison["hypothesis"] == rr.HYPOTHESIS
    assert comparison["primary"]["track"] == "public"
    assert comparison["primary"]["variant"] == "rerank"
    assert comparison["primary"]["baseline"] == "bm25"
    assert [s["track"] for s in comparison["secondary"]] == ["kisa"]
    assert comparison["secondary"][0]["baseline"] == "bm25"
    for key in ("public/rerank", "kisa/rerank"):
        block = comparison["comparisons"][key]
        assert block["verdict"] in ("hypothesis-confirmed", "hypothesis-rejected")
        assert block["ci95"]["low"] <= block["ci95"]["high"]
        assert {"degraded", "improved_top10", "by_type", "cve_explicit"} <= set(block)
        assert len(block["improved_top10"]) <= 10
    manifest = read_json(RERANK_DIR / "manifest.json")
    for entry in manifest["runs"].values():
        assert entry["test"]["config_hash"] == harness.entry_hash("rerank", entry)
        assert entry["selected"]["config"]["n"] in rr.N_GRID
        assert entry["selected"]["selected_on"] == "dev"
        assert entry["stored_results"]["path"].startswith("results/experiments/rerank/")
        assert entry["fixed"]["reranker"]["revision"] == rr.MODEL_REVISION
        assert entry["fixed"]["reranker"]["max_length"] == 512
        assert entry["description"]["reranker"]["revision"] == rr.MODEL_REVISION
        assert entry["description"]["reranker"]["n_docs_truncated_even_with_empty_query"] >= 0
        rows = entry["grid"]["rows"]
        assert [row["config"]["n"] for row in rows] == list(rr.N_GRID)
        best = max(row["dev_macro_ndcg@10"] for row in rows)
        first_best = next(row["config"]["n"] for row in rows if row["dev_macro_ndcg@10"] == best)
        assert entry["selected"]["config"]["n"] == first_best  # 같으면 작은 N


@needs_results
def test_committed_files_have_only_allowed_fields_and_no_absolute_paths():
    for path in (RERANK_DIR / "public/rerank.jsonl", RERANK_DIR / "kisa/rerank.jsonl"):
        for row in data.read_jsonl(path):
            scoring.validate_record(row)
    text = ""
    for path in sorted(RERANK_DIR.rglob("*")):
        if path.is_file():
            text += path.read_text("utf-8")
    assert "/Users" not in text
    for filename in ("manifest.json", "metrics.json", "comparison.json"):
        assert harness.find_absolute_paths(read_json(RERANK_DIR / filename)) == []
    for question in data.load_questions("public", ROOT):
        assert question.query not in text


@needs_results
def test_committed_public_results_keep_the_bm25_candidate_set_and_the_tail_order():
    entry = read_json(RERANK_DIR / "manifest.json")["runs"]["public/rerank"]
    n = entry["selected"]["config"]["n"]
    params = read_json(ROOT / "results/baselines/manifest.json")["runs"]["public/bm25"]["selected"]
    corpus = data.load_public_corpus(ROOT)
    index = BM25Index(corpus.texts, k1=params["k1"], b=params["b"])
    stored = {r["question_id"]: r for r in data.read_jsonl(RERANK_DIR / "public/rerank.jsonl")}
    baseline = {
        r["question_id"]: r for r in data.read_jsonl(ROOT / "results/baselines/public/bm25.jsonl")
    }
    checked = 0
    for question in data.load_questions("public", ROOT):
        if question.excluded:
            continue
        ranking = sort_by_score(index.score(question.query))
        judged = [d for d in ranking if d not in question.unjudged]
        top = [d for d in ranking[:n] if d not in question.unjudged]
        got = [item["doc_id"] for item in stored[question.question_id]["results"]]
        assert [i["doc_id"] for i in baseline[question.question_id]["results"]] == judged[:100]
        assert set(got[: len(top)]) == set(top), question.question_id  # 후보 집합 불변
        assert got[len(top) :] == judged[len(top) : 100], question.question_id  # N 밖 순서 보존
        checked += 1
    assert checked == sum(1 for q in data.load_questions("public", ROOT) if not q.excluded)


@needs_results
def test_committed_kisa_results_keep_the_baseline_document_set():
    stored = {r["question_id"]: r for r in data.read_jsonl(RERANK_DIR / "kisa/rerank.jsonl")}
    baseline = {
        r["question_id"]: r for r in data.read_jsonl(ROOT / "results/baselines/kisa/bm25.jsonl")
    }
    assert set(stored) == set(baseline)
    for question_id, row in stored.items():
        old = baseline[question_id]
        assert {i["doc_id"] for i in row["results"]} == {i["doc_id"] for i in old["results"]}


@needs_results
def test_committed_report_matches_comparison():
    comparison = read_json(RERANK_DIR / "comparison.json")
    report = (ROOT / "docs/experiments/rerank.md").read_text("utf-8")
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
    assert "<KISA-ROOT>" in report
    assert "/Users" not in report

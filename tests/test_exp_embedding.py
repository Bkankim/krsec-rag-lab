"""임베딩 교체 실험 테스트 - 합성 코퍼스·가짜 인코더(호출 기록)만 쓰고 모델 내려받기·KISA 캐시를 쓰지 않는다.

확인하는 것: 모델별 접두사, 후보 선택 규칙(동점 처리), KISA 트랙이 공개 트랙 dev의 선택에 고정되는지, 선택 확정
전에 test 질의가 인코딩되지 않고 탈락 후보가 test를 돌지 않는지, test 라벨을 바꿔도 선택 모델·τ가 그대로인지,
L2 정규화 검사, 결과 파일 허용 필드·비유출, 모델 패키지 비접촉, 커밋된 results/experiments/embedding의 정합성과
`--compare`(수치 하나를 바꾼 사본은 exit 1)와 보고서 표 일치.
numpy가 필요한 `build_candidate_index` 테스트는 `embed` 그룹이 없는 환경(CI)에서 건너뛴다.
"""

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_baselines_runner import KISA_QUESTIONS, FakeDense, fake_body_loader, write_kisa_fixture
from test_experiments_harness import QUERIES, run_experiment, write_fixture

from krsec_rag_lab.baselines import data, dense, runner, scoring
from krsec_rag_lab.experiments import ContractError, LockError, harness
from krsec_rag_lab.experiments import embedding as emb

ROOT = Path(__file__).resolve().parents[1]
OUT = Path("results/experiments")
EMBEDDING_DIR = ROOT / OUT / "embedding"
KEY = f"public/{emb.VARIANT}"
KISA_KEY = f"kisa/{emb.VARIANT}"

# ------------------------------------------------------------ 접두사 (모델 카드의 정해진 사용법)


@pytest.mark.parametrize(
    ("name", "query_prefix", "document_prefix"),
    [
        ("intfloat/multilingual-e5-large", "query: ", "passage: "),
        (
            "Qwen/Qwen3-Embedding-0.6B",
            "Instruct: Given a web search query, retrieve relevant passages that answer the query\nQuery:",
            "",
        ),
    ],
)
def test_prefixes_follow_each_model_card(name, query_prefix, document_prefix):
    candidate = emb.candidate_named(name)
    assert candidate.query_prefix == query_prefix
    assert candidate.document_prefix == document_prefix
    assert emb.format_query(candidate, "라우터 취약점") == query_prefix + "라우터 취약점"
    assert emb.format_document(candidate, "CVE-1 text") == document_prefix + "CVE-1 text"


def test_registered_candidates_are_at_most_two_pinned_and_distinct():
    assert 1 <= len(emb.CANDIDATES) <= 2
    assert len({c.name for c in emb.CANDIDATES}) == len(emb.CANDIDATES)
    for candidate in emb.CANDIDATES:
        assert len(candidate.revision) == 40
        assert candidate.max_seq_length == min(candidate.model_max_seq_length, 8192)
    assert emb.candidate_named("Qwen/Qwen3-Embedding-0.6B").max_seq_length == 8192
    assert emb.candidate_named("intfloat/multilingual-e5-large").max_seq_length == 512
    assert [e["name"] for e in emb.EXCLUDED] == ["google/embeddinggemma-2"]
    assert emb.EXCLUDED[0]["reason"]
    with pytest.raises(ContractError):
        emb.candidate_named("BAAI/bge-m3")


def test_pure_helpers_unit_norm_and_truncation():
    assert emb.unit_norm_deviation([[1.0, 0.0], [0.6, 0.8]]) == pytest.approx(0.0)
    assert emb.unit_norm_deviation([[1.0, 0.0], [1.0, 1.0]]) == pytest.approx(2**0.5 - 1)
    assert emb.unit_norm_deviation([]) == 0.0
    assert emb.truncated_count([10, 512, 513, 9000], 512) == 2
    assert emb.truncated_count([8192, 8193], 8192) == 1


# ------------------------------------------------------------ 후보 선택 규칙 (동점 처리)


def rows_for(*triples):
    return [
        {"config": {"model": model, "parameters": parameters}, "dev_macro_ndcg@10": macro}
        for model, parameters, macro in triples
    ]


def chosen(*triples):
    rows = rows_for(*triples)
    return rows[emb.select(rows)]["config"]["model"]


@pytest.mark.parametrize(
    ("triples", "expected", "why"),
    [
        ((("a/x", 200, 0.5), ("b/y", 100, 0.6)), "b/y", "dev macro가 높은 쪽(파라미터가 많아도)"),
        ((("a/x", 100, 0.7), ("b/y", 200, 0.6)), "a/x", "dev macro가 높은 쪽(앞 행이라도)"),
        ((("a/x", 200, 0.5), ("b/y", 100, 0.5)), "b/y", "같으면 파라미터가 적은 쪽"),
        ((("a/x", 100, 0.5), ("b/y", 200, 0.5)), "a/x", "같으면 파라미터가 적은 쪽(앞 행)"),
        ((("b/y", 100, 0.5), ("a/x", 100, 0.5)), "a/x", "파라미터도 같으면 모델 ID 사전순(뒤 행)"),
        ((("a/x", 100, 0.5), ("b/y", 100, 0.5)), "a/x", "파라미터도 같으면 모델 ID 사전순(앞 행)"),
        ((("a/x", 100, 0.5 + 1e-14), ("b/y", 50, 0.5)), "b/y", "1e-12 이내 차이는 동점으로 본다"),
        ((("a/x", 100, 0.5 + 1e-6), ("b/y", 50, 0.5)), "a/x", "1e-6 차이는 동점이 아니다"),
        ((("a/x", 100, 0.0), ("b/y", 50, 0.0)), "b/y", "둘 다 0이어도 같은 규칙"),
        ((("only/one", 100, 0.3),), "only/one", "후보가 하나면 그 행(KISA 트랙)"),
    ],
)
def test_candidate_selection_rule_including_ties(triples, expected, why):
    assert chosen(*triples) == expected, why


def test_registered_selection_rule_is_documented_and_grid_is_the_two_candidates():
    assert "dev" in emb.SELECTION_RULE and "파라미터" in emb.SELECTION_RULE
    configs = emb.grid("public", emb.VARIANT)
    assert [c["model"] for c in configs] == [c.name for c in emb.CANDIDATES]
    assert all(set(c) == {"model", "revision", "parameters"} for c in configs)
    assert emb.PRIMARY == ("public", "swap")
    assert emb.BASELINES == {"public": "dense", "kisa": "dense"}
    assert "dense 베이스라인보다 test macro nDCG@10이 높다" in emb.HYPOTHESIS


# ------------------------------------------------------------ 가짜 인코더와 end-to-end


def fake_candidate(name, parameters, query_prefix="", document_prefix=""):
    return emb.Candidate(
        name=name,
        revision="0" * 40,
        parameters=parameters,
        pooling="mean",
        model_max_seq_length=512,
        query_prefix=query_prefix,
        document_prefix=document_prefix,
    )


STRONG = fake_candidate("fake/strong", 300_000_000, "q: ", "d: ")
WEAK = fake_candidate("fake/weak", 100_000_000, "w: ", "")


class FakeIndex:
    """가짜 인덱스: strong은 정답 문서에 1.0을 주고 weak은 모두 0.0을 준다. 질의 인코딩을 로그에 남긴다."""

    def __init__(self, candidate, texts, log, gold_by_query):
        self.candidate = candidate
        self.texts = texts
        self.log = log
        self.gold_by_query = gold_by_query
        self.meta = {
            "model": {
                "name": candidate.name,
                "revision": candidate.revision,
                "parameters": candidate.parameters,
                "n_truncated_docs": 0,
            },
            "runtime": {"python": "fake"},
            "doc_encode_seconds": 0.0,
        }

    def score(self, query):
        self.log.append(("query", self.candidate.name, query))
        gold = self.gold_by_query.get(query, set()) if self.candidate is STRONG else set()
        return {doc_id: 1.0 if doc_id in gold else 0.0 for doc_id in self.texts}


class Factory:
    """`dense_factory` 대용: 후보마다 가짜 인덱스를 만들고 호출을 기록한다."""

    def __init__(self, root, track="public"):
        questions = data.load_questions(track, root)
        self.gold_by_query = {q.query: set(q.gold) for q in questions}
        self.log = []

    def __call__(self, candidate, texts):
        self.log.append(("index", candidate.name, len(texts)))
        return FakeIndex(candidate, texts, self.log, self.gold_by_query)

    def queries(self, name):
        return [q for kind, model, q in self.log if kind == "query" and model == name]


@pytest.fixture
def candidates(monkeypatch):
    monkeypatch.setattr(emb, "CANDIDATES", (STRONG, WEAK))
    return (STRONG, WEAK)


@pytest.fixture
def root(tmp_path, monkeypatch, candidates):
    write_fixture(tmp_path)
    runner.run_baseline("public", "dense", tmp_path, dense_factory=FakeDense)
    monkeypatch.setattr(emb, "REPO_ROOT", tmp_path)  # KISA 트랙이 읽는 공개 트랙 선택
    return tmp_path


def run_embedding(root, factory=None, track="public", split="all", **kwargs):
    factory = factory or Factory(root, track)
    return harness.run_experiment(
        "embedding", track, root, split=split, dense_factory=factory, **kwargs
    )


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def manifest_of(root):
    return read_json(root / OUT / "embedding/manifest.json")


def test_end_to_end_selects_the_stronger_candidate_on_dev_and_judges_on_test(root):
    comparison = run_embedding(root)
    assert comparison["primary"]["track"] == "public"
    assert comparison["primary"]["variant"] == "swap"
    assert comparison["primary"]["baseline"] == "dense"
    assert comparison["primary"]["verdict"] == "hypothesis-confirmed"
    entry = manifest_of(root)["runs"][KEY]
    assert entry["selected"]["config"] == STRONG.config()
    assert entry["selected"]["selected_on"] == "dev"
    assert entry["grid"]["selection_rule"] == emb.SELECTION_RULE
    # 후보별 dev 수치와 파라미터·revision이 manifest에 있다
    by_model = {row["config"]["model"]: row for row in entry["grid"]["rows"]}
    assert set(by_model) == {"fake/strong", "fake/weak"}
    assert by_model["fake/strong"]["dev_macro_ndcg@10"] > by_model["fake/weak"]["dev_macro_ndcg@10"]
    assert by_model["fake/weak"]["config"]["parameters"] == 100_000_000
    assert [m["name"] for m in entry["description"]["models_loaded"]] == [
        "fake/strong",
        "fake/weak",
    ]
    assert entry["description"]["excluded_candidates"][0]["name"] == "google/embeddinggemma-2"
    assert entry["baseline"]["retriever"] == "dense"
    assert entry["test"]["config"] == entry["selected"]["config"]
    assert harness.verify_outputs(harness.load_experiment("embedding"), root, OUT) == []


def test_test_queries_are_encoded_only_after_selection_and_only_by_the_selected_model(root):
    factory = Factory(root)
    run_embedding(root, factory)
    questions = [q for q in data.load_questions("public", root) if not q.excluded]
    all_dev = {q.query for q in questions if q.split == "dev"}
    all_test = {q.query for q in questions if q.split == "test"}
    # 합성 코퍼스에서는 기권 질문 문장이 두 분할에 같다: 분할 하나에만 있는 문장만 분할 증거로 쓴다
    dev, test = all_dev - all_test, all_test - all_dev
    assert dev and test
    encoded = [(model, query) for kind, model, query in factory.log if kind == "query"]
    last_dev = max(i for i, (_, query) in enumerate(encoded) if query in dev)
    test_positions = [i for i, (_, query) in enumerate(encoded) if query in test]
    assert test_positions and min(test_positions) > last_dev  # 선택 확정 전에는 test 질의가 없다
    assert {encoded[i][0] for i in test_positions} == {
        "fake/strong"
    }  # 탈락 후보는 test를 돌지 않는다
    assert set(factory.queries("fake/weak")) <= all_dev
    assert set(factory.queries("fake/strong")) >= test | dev  # 선택 후보는 dev와 test 모두
    assert not set(factory.queries("fake/weak")) & test


def test_split_dev_never_encodes_a_test_query(root):
    factory = Factory(root)
    run_embedding(root, factory, split="dev")
    questions = data.load_questions("public", root)
    dev = {q.query for q in questions if q.split == "dev"}
    test = {q.query for q in questions if q.split == "test"} - dev
    assert test
    assert not (set(factory.queries("fake/strong")) | set(factory.queries("fake/weak"))) & test
    assert "test" not in manifest_of(root)["runs"][KEY]


def test_changing_test_labels_keeps_the_selected_model_and_tau(tmp_path, monkeypatch, candidates):
    selected = []
    for label, shuffled in (("base", False), ("changed", True)):
        base = tmp_path / label
        queries = [dict(q) for q in QUERIES]
        if shuffled:  # test 정답을 다른 문서로 바꾼다
            for q in queries:
                if q["split"] == "test" and q["gold"]:
                    q["gold"] = [f"CVE-2026-{1000 + (int(q['gold'][0][-4:]) - 1000 + 7) % 40}"]
        write_fixture(base, queries)
        runner.run_baseline("public", "dense", base, dense_factory=FakeDense)
        monkeypatch.setattr(emb, "REPO_ROOT", base)
        run_embedding(base)
        selected.append(manifest_of(base)["runs"][KEY]["selected"])
    assert selected[0] == selected[1]


def test_tie_between_candidates_picks_the_one_with_fewer_parameters(root, monkeypatch):
    class Tie(Factory):
        def __call__(self, candidate, texts):
            index = super().__call__(candidate, texts)
            index.candidate = STRONG  # 두 후보가 같은 점수를 낸다
            return index

    run_embedding(root, Tie(root))
    assert manifest_of(root)["runs"][KEY]["selected"]["config"] == WEAK.config()


def test_stored_results_have_only_allowed_fields_and_no_paths_or_bodies(root):
    run_embedding(root)
    directory = root / OUT / "embedding"
    for row in data.read_jsonl(directory / "public" / "swap.jsonl"):
        scoring.validate_record(row)
    text = "".join(p.read_text("utf-8") for p in directory.rglob("*") if p.is_file())
    assert str(root) not in text
    assert harness.find_absolute_paths(read_json(directory / "manifest.json")) == []
    for q in data.load_questions("public", root):
        assert q.query not in text


def test_test_is_locked_after_one_run_and_prefix_changes_invalidate_the_lock(root, monkeypatch):
    run_embedding(root)
    before = {p: p.read_bytes() for p in (root / OUT / "embedding").rglob("*") if p.is_file()}
    changed = fake_candidate("fake/strong", 300_000_000, "other: ", "d: ")
    monkeypatch.setattr(emb, "CANDIDATES", (changed, WEAK))
    with pytest.raises(LockError):
        run_embedding(root, split="test")
    with pytest.raises(LockError):
        run_embedding(root, split="dev")
    after = {p: p.read_bytes() for p in (root / OUT / "embedding").rglob("*") if p.is_file()}
    assert after == before


def test_default_dense_factory_is_replaced_by_the_candidate_builder(root, monkeypatch):
    built = []

    def fake_builder(candidate, texts):
        built.append(candidate.name)
        return FakeIndex(candidate, texts, [], {})

    monkeypatch.setattr(emb, "build_candidate_index", fake_builder)
    harness.run_experiment("embedding", "public", root, split="dev")  # dense_factory 기본값
    assert built == ["fake/strong", "fake/weak"]


# ------------------------------------------------------------ KISA 트랙: 공개 트랙 dev의 선택에 고정


@pytest.fixture
def kisa_root(root):
    write_kisa_fixture(root)
    runner.run_baseline("kisa", "dense", root, load_body=fake_body_loader, dense_factory=FakeDense)
    return root


def test_kisa_track_needs_the_public_selection_first(kisa_root):
    with pytest.raises(ContractError, match="public"):
        run_embedding(kisa_root, track="kisa", load_body=fake_body_loader)
    assert not (kisa_root / OUT / "embedding").exists()


def test_kisa_track_is_fixed_to_the_model_chosen_on_public_dev(kisa_root):
    run_embedding(kisa_root)  # 공개 트랙: strong 선택
    factory = Factory(kisa_root, "kisa")
    comparison = run_embedding(kisa_root, factory, track="kisa", load_body=fake_body_loader)
    assert [s["track"] for s in comparison["secondary"]] == ["kisa"]
    assert comparison["primary"]["track"] == "public"
    entry = manifest_of(kisa_root)["runs"][KISA_KEY]
    assert entry["grid"]["rows"] == [
        {"config": STRONG.config(), "dev_macro_ndcg@10": entry["selected"]["dev_macro_ndcg@10"]}
    ]
    assert entry["selected"]["config"] == STRONG.config()
    # 탈락 후보는 KISA 트랙에서 인덱스도 질의도 만들지 않는다
    assert [e[1] for e in factory.log if e[0] == "index"] == ["fake/strong"]
    assert factory.queries("fake/weak") == []
    assert entry["selected"]["tau_selection"]["rule"]  # τ는 KISA dev에서 따로 고른다
    out = kisa_root / OUT / "embedding"
    text = "".join(p.read_text("utf-8") for p in out.rglob("*") if p.is_file())
    assert "라우터 보안 업데이트" not in text  # 본문 비유출
    assert str(kisa_root) not in text
    rows = data.read_jsonl(out / "kisa/swap.jsonl")
    assert {r["question_id"] for r in rows} == {
        q["question_id"] for q in KISA_QUESTIONS if not q["excluded"]
    }


def test_kisa_grid_rejects_a_selection_that_is_not_a_registered_candidate(root, monkeypatch):
    run_embedding(root)
    path = root / OUT / "embedding/manifest.json"
    manifest = read_json(path)
    manifest["runs"][KEY]["selected"]["config"]["parameters"] += 1
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ContractError, match="registered"):
        emb.grid("kisa", emb.VARIANT)


def test_fixed_config_records_the_encoding_rules_candidates_and_baseline_model(root):
    manifest = harness.read_baselines_manifest(root)
    fixed = emb.fixed_config("public", emb.VARIANT, manifest)
    assert fixed["encoding"]["normalized"] is True
    assert fixed["encoding"]["dtype"] == "float32"
    assert fixed["encoding"]["device"] == "cpu"
    assert [c["name"] for c in fixed["candidates"]] == ["fake/strong", "fake/weak"]
    assert fixed["candidates"][0]["query_prefix"] == "q: "
    assert fixed["baseline_dense"] == {"name": "fake", "revision": "fake"}


# ------------------------------------------------------------ build_candidate_index (numpy 필요)


class FakeSentenceModel:
    """sentence-transformers를 흉내 낸다: 인코딩 입력과 옵션을 기록하고 결정적인 벡터를 돌려준다."""

    def __init__(self, parameters=7, max_seq_length=512, normalize=True, dimension=3):
        self.calls = []
        self.max_seq_length = max_seq_length
        self._parameters = parameters
        self._normalize = normalize
        self._dimension = dimension
        self.tokenizer = self._tokenize

    def _tokenize(self, texts, **kwargs):
        return {"input_ids": [list(range(len(text.split()))) for text in texts]}

    def eval(self):
        return self

    def parameters(self):
        return [SimpleNamespace(numel=lambda: self._parameters)]

    def encode(self, sentences, **kwargs):
        import numpy as np

        self.calls.append((list(sentences), kwargs))
        rows = []
        for i, sentence in enumerate(sentences):
            vector = np.array([len(sentence), i + 1.0, 2.0][: self._dimension], dtype=np.float64)
            rows.append(vector / np.linalg.norm(vector) if self._normalize else vector)
        return np.array(rows)


def build_with(model, candidate=None, texts=None):
    pytest.importorskip("numpy")
    pytest.importorskip("torch")
    pytest.importorskip("sentence_transformers")
    candidate = candidate or fake_candidate("fake/m", 7, "query: ", "passage: ")
    index = emb.build_candidate_index(
        candidate, texts or {"d1": "alpha beta", "d2": "gamma"}, load_model=lambda c: model
    )
    return candidate, index


def test_build_applies_prefixes_normalizes_and_scores_by_inner_product():
    model = FakeSentenceModel()
    candidate, index = build_with(model)
    doc_call, doc_kwargs = model.calls[0]
    assert doc_call == ["passage: alpha beta", "passage: gamma"]
    assert doc_kwargs["normalize_embeddings"] is True
    assert str(index.matrix.dtype) == "float32"
    score = index.score("라우터")
    assert model.calls[1][0] == ["query: 라우터"]  # 질의 접두사
    assert model.calls[1][1]["normalize_embeddings"] is True
    assert set(score) == {"d1", "d2"}  # 코퍼스 전체에 점수를 매긴다
    assert index.meta["model"]["max_norm_deviation"] < emb.NORM_TOLERANCE
    assert index.meta["model"]["query_prefix"] == "query: "
    assert index.meta["model"]["document_prefix"] == "passage: "
    assert candidate.name == index.meta["model"]["name"]


def test_build_rejects_rows_that_are_not_unit_norm():
    with pytest.raises(ContractError, match="unit norm"):
        build_with(FakeSentenceModel(normalize=False))


def test_build_counts_truncated_documents_with_the_prefix_included():
    texts = {"short": "a b", "long": " ".join(["w"] * 600)}
    _, index = build_with(FakeSentenceModel(), texts=texts)
    model = index.meta["model"]
    assert model["n_truncated_docs"] == 1  # 접두사 포함 토큰 수가 512를 넘는 문서
    assert model["max_doc_tokens"] == 601
    assert model["max_seq_length"] == 512


@pytest.mark.parametrize(
    ("model_kwargs", "message"),
    [({"parameters": 8}, "parameters"), ({"max_seq_length": 128}, "max_seq_length")],
)
def test_build_checks_the_loaded_model_against_the_registered_candidate(model_kwargs, message):
    with pytest.raises(ContractError, match=message):
        build_with(FakeSentenceModel(**model_kwargs))


def test_build_caps_a_long_context_model_at_8192():
    candidate = emb.Candidate("fake/long", "0" * 40, 7, "mean", 32768, "", "")
    model = FakeSentenceModel(max_seq_length=32768)
    build_with(model, candidate=candidate)
    assert model.max_seq_length == 8192


# ------------------------------------------------------------ 모듈 import와 기본 계약


def test_embedding_module_has_no_top_level_model_imports():
    source = (ROOT / "src/krsec_rag_lab/experiments/embedding.py").read_text("utf-8")
    for package in ("numpy", "torch", "sentence_transformers"):
        for line in source.splitlines():
            if f"import {package}" in line or f"from {package}" in line:
                assert line.startswith(" "), line  # 함수 안(들여쓰기)에서만 import한다
    assert dense.DEVICE == emb.DEVICE == "cpu"


# ------------------------------------------------------------ 커밋된 결과 (모델·KISA 캐시 없이)

COMMITTED = (EMBEDDING_DIR / "comparison.json").exists()
RUNS = (KEY, KISA_KEY)


@pytest.fixture
def committed_cli(monkeypatch):
    monkeypatch.setattr(run_experiment, "ROOT", ROOT)
    return run_experiment.main


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/embedding not committed yet")
def test_committed_results_pass_the_compare(committed_cli, capsys):
    assert committed_cli(["--exp", "embedding", "--compare"]) == 0
    assert "compare OK" in capsys.readouterr().out


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/embedding not committed yet")
@pytest.mark.parametrize(
    ("filename", "path"),
    [
        ("metrics.json", ("runs", KEY, "test", "macro", "ndcg@10")),
        ("metrics.json", ("runs", KISA_KEY, "test", "macro", "ndcg@10")),
        ("comparison.json", ("comparisons", KEY, "delta")),
        ("comparison.json", ("comparisons", KISA_KEY, "ci95", "high")),
    ],
)
def test_a_copy_with_one_number_changed_fails_the_compare(
    committed_cli, capsys, tmp_path, filename, path
):
    copy_dir = tmp_path / "embedding"
    shutil.copytree(EMBEDDING_DIR, copy_dir)
    assert committed_cli(["--exp", "embedding", "--compare", "--out-dir", str(tmp_path)]) == 0
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
    assert committed_cli(["--exp", "embedding", "--compare", "--out-dir", str(tmp_path)]) == 1
    assert "compare FAILED" in capsys.readouterr().err


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/embedding not committed yet")
def test_committed_comparison_fields_lock_and_candidate_evidence():
    comparison = read_json(EMBEDDING_DIR / "comparison.json")
    assert comparison["primary"]["track"] == "public"
    assert comparison["primary"]["variant"] == "swap"
    assert comparison["primary"]["baseline"] == "dense"
    assert [s["track"] for s in comparison["secondary"]] == ["kisa"]
    assert comparison["secondary"][0]["baseline"] == "dense"
    for key in RUNS:
        block = comparison["comparisons"][key]
        assert block["verdict"] in ("hypothesis-confirmed", "hypothesis-rejected")
        assert block["ci95"]["low"] <= block["ci95"]["high"]
        assert len(block["improved_top10"]) <= 10
    manifest = read_json(EMBEDDING_DIR / "manifest.json")
    for entry in manifest["runs"].values():
        assert entry["test"]["config_hash"] == harness.entry_hash("embedding", entry)
        assert entry["selected"]["selected_on"] == "dev"
        assert entry["stored_results"]["path"].startswith("results/experiments/embedding/")
    public = manifest["runs"][KEY]
    names = {row["config"]["model"] for row in public["grid"]["rows"]}
    assert names == {c.name for c in emb.CANDIDATES}  # 후보별 dev 수치가 manifest에 있다
    assert (
        public["selected"]["config"]
        == public["grid"]["rows"][emb.select(public["grid"]["rows"])]["config"]
    )
    assert manifest["runs"][KISA_KEY]["selected"]["config"] == public["selected"]["config"]
    assert [row["config"] for row in manifest["runs"][KISA_KEY]["grid"]["rows"]] == [
        public["selected"]["config"]
    ]
    for entry in manifest["runs"].values():
        for model in entry["description"]["models_loaded"]:
            assert "n_truncated_docs" in model and model["parameters"] > 0
    # 접두사는 manifest에 적힌 실제 인코딩 설정이다
    for model in public["description"]["models_loaded"]:
        candidate = emb.candidate_named(model["name"])
        assert model["query_prefix"] == candidate.query_prefix
        assert model["document_prefix"] == candidate.document_prefix
        assert model["dtype"] == "float32" and model["normalized"] is True


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/embedding not committed yet")
def test_committed_files_have_only_allowed_fields_and_no_absolute_paths():
    for path in (EMBEDDING_DIR / "public/swap.jsonl", EMBEDDING_DIR / "kisa/swap.jsonl"):
        for row in data.read_jsonl(path):
            scoring.validate_record(row)
    text = ""
    for path in sorted(EMBEDDING_DIR.rglob("*")):
        if path.is_file():
            text += path.read_text("utf-8")
    assert "/Users" not in text
    for filename in ("manifest.json", "metrics.json", "comparison.json"):
        assert harness.find_absolute_paths(read_json(EMBEDDING_DIR / filename)) == []
    for question in data.load_questions("public", ROOT):
        assert question.query not in text


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/embedding not committed yet")
def test_committed_report_matches_comparison():
    comparison = read_json(EMBEDDING_DIR / "comparison.json")
    report = (ROOT / "docs/experiments/embedding.md").read_text("utf-8")
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
    manifest = read_json(EMBEDDING_DIR / "manifest.json")
    for row in manifest["runs"][KEY]["grid"]["rows"]:
        assert f"{row['dev_macro_ndcg@10']:.4f}" in report
        assert row["config"]["model"] in report
        assert row["config"]["revision"] in report

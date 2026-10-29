"""실행기·결과 파일·CLI 테스트 - 합성 코퍼스와 가짜 dense 인덱스만 쓰고 모델·KISA 캐시를 쓰지 않는다.

확인하는 것: 결과 레코드 허용 필드와 본문 비유출, dev에서만 고르는 설정(BM25 k1·b, τ), 분할 인자 의미,
metrics.json이 저장된 결과만으로 재계산되는지, 두 트랙 x 세 검색기, KISA 캐시 누락 시 실행 실패,
커밋된 results/baselines 파일의 정합성.
"""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from krsec_rag_lab.baselines import data, report, runner, scoring

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_baselines.py"
SPEC = importlib.util.spec_from_file_location("run_baselines", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
run_baselines = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_baselines
SPEC.loader.exec_module(run_baselines)

OUT = Path("results/baselines")

# ------------------------------------------------------------ 합성 공개 트랙

PUBLIC_RECORDS = {
    "CVE-2026-0001": "Acme Router firmware allows remote buffer overflow",
    "CVE-2026-0002": "Acme Router web console allows command injection",
    "CVE-2026-0003": "Globex Gateway improper authentication in the admin panel",
    "CVE-2026-0004": "Globex Gateway cross site scripting in the login page",
    "CVE-2026-0005": "Initech Database server SQL injection through the search box",
    "CVE-2026-0006": "Initech Database backup tool path traversal",
    "CVE-2026-0007": "Umbrella Camera firmware hard coded credentials",
    "CVE-2026-0008": "Umbrella Camera streaming service denial of service",
}


def public_query(qid, query, query_type, split, gold=(), unjudged=()):
    return {
        "id": qid,
        "query": query,
        "query_type": query_type,
        "split": split,
        "gold": list(gold),
        "unjudged": list(unjudged),
        "vendor_product": None,
    }


PUBLIC_QUERIES = [
    public_query("q-cve-1", "CVE-2026-0001 취약점의 영향 범위가 궁금합니다.", "cve_explicit", "dev", ["CVE-2026-0001"]),
    public_query("q-prod-1", "globex:gateway에서 발견된 취약점 레코드를 찾아주세요.", "product_symptom", "dev", ["CVE-2026-0003"], ["CVE-2026-0004"]),
    public_query("q-na-1", "CVE-2026-9001를 설명하는 레코드를 찾아주세요.", "no_answer", "dev"),
    public_query("q-cve-2", "CVE-2026-0005는 어떤 취약점인가요?", "cve_explicit", "test", ["CVE-2026-0005"]),
    public_query("q-cve-3", "CVE-2026-0007 취약점의 영향 범위가 궁금합니다.", "cve_explicit", "test", ["CVE-2026-0007"]),
    public_query("q-prod-2", "umbrella:camera에서 발견된 취약점 레코드를 찾아주세요.", "product_symptom", "test", ["CVE-2026-0007", "CVE-2026-0008"]),
    public_query("q-na-2", "CVE-2026-9002를 설명하는 레코드를 찾아주세요.", "no_answer", "test"),
]  # fmt: skip


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8"
    )


def write_public_fixture(root, queries=None):
    rows = [{"id": cve, "description_en": text} for cve, text in PUBLIC_RECORDS.items()]
    write_jsonl(root / data.PUBLIC_CORPUS, rows)
    write_jsonl(root / data.PUBLIC_QUERIES, PUBLIC_QUERIES if queries is None else queries)


class FakeDense:
    """가짜 dense 인덱스: 질의/문서 토큰 겹침 수를 점수로 쓴다. 모델을 부르지 않는다."""

    def __init__(self, texts):
        self.texts = texts
        self.meta = {
            "model": {"name": "fake", "revision": "fake", "n_truncated_docs": 0},
            "runtime": {"python": "fake"},
            "doc_encode_seconds": 0.0,
        }

    def score(self, query):
        words = set(query.casefold().replace(":", " ").split())
        return {
            doc_id: len(words & set(text.casefold().split())) / 10
            for doc_id, text in self.texts.items()
        }


@pytest.fixture
def public_root(tmp_path):
    write_public_fixture(tmp_path)
    return tmp_path


def run_public(root, retriever, split="all"):
    return runner.run_baseline("public", retriever, root, split=split, dense_factory=FakeDense)


def read_manifest(root):
    return json.loads((root / OUT / "manifest.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------ 결과 파일


@pytest.mark.parametrize("retriever", runner.RETRIEVERS)
def test_results_file_has_only_allowed_fields_and_no_body_text(public_root, retriever):
    run_public(public_root, retriever)
    path = public_root / OUT / "public" / f"{retriever}.jsonl"
    raw = path.read_text(encoding="utf-8")
    rows = [json.loads(line) for line in raw.splitlines()]
    assert {row["question_id"] for row in rows} == {q["id"] for q in PUBLIC_QUERIES}
    for row in rows:
        assert set(row) == scoring.RECORD_FIELDS
        scoring.validate_record(row)
        for item in row["results"]:
            assert set(item) == scoring.RESULT_FIELDS
    # 문서 본문·질의 본문 조각이 결과 파일에 없다
    for text in (*PUBLIC_RECORDS.values(), *(q["query"] for q in PUBLIC_QUERIES)):
        assert text not in raw
    assert "buffer overflow" not in raw
    assert "취약점" not in raw


def test_unjudged_are_removed_and_counted(public_root):
    run_public(public_root, "bm25")
    rows = {
        json.loads(line)["question_id"]: json.loads(line)
        for line in (public_root / OUT / "public" / "bm25.jsonl").read_text("utf-8").splitlines()
    }
    row = rows["q-prod-1"]
    assert row["n_unjudged_removed"] == 1
    assert "CVE-2026-0004" not in [item["doc_id"] for item in row["results"]]
    assert row["results"][0]["doc_id"] == "CVE-2026-0003"
    assert rows["q-cve-1"]["n_unjudged_removed"] == 0


@pytest.mark.parametrize("retriever", runner.RETRIEVERS)
def test_metrics_are_recomputed_from_stored_results(public_root, retriever):
    returned = run_public(public_root, retriever)
    on_disk = json.loads((public_root / OUT / "metrics.json").read_text("utf-8"))["runs"][
        f"public/{retriever}"
    ]
    recomputed = runner.compute_run_metrics("public", retriever, public_root, OUT)
    assert on_disk == json.loads(json.dumps(returned))
    assert json.loads(json.dumps(recomputed)) == on_disk
    assert set(on_disk) == {"dev", "test"}


def test_rerun_is_deterministic(public_root):
    run_public(public_root, "bm25")
    first = (public_root / OUT / "public" / "bm25.jsonl").read_text("utf-8")
    run_public(public_root, "bm25")
    assert (public_root / OUT / "public" / "bm25.jsonl").read_text("utf-8") == first


# ------------------------------------------------------------ 설정은 dev에서만


def test_exact_returns_empty_for_non_cve_queries_and_unknown_ids(public_root):
    returned = run_public(public_root, "exact")
    by_type = returned["dev"]["by_type"]
    assert by_type["cve_explicit"]["metrics"]["ndcg@10"] == 1.0
    assert by_type["product_symptom"]["metrics"]["ndcg@10"] == 0.0  # 빈 결과는 0점
    na = returned["dev"]["no_answer"]
    assert na["abstain_rate"] == 1.0  # 코퍼스에 없는 ID는 빈 결과 -> 기권
    assert na["n_no_answer"] == 1


@pytest.mark.parametrize("retriever", ["exact", "bm25", "dense"])
def test_tau_and_bm25_params_come_from_dev_only(tmp_path, retriever):
    """test 질문을 바꿔도 dev에서 고른 τ·k1·b는 그대로이고, dev 질문을 바꾸면 달라질 수 있다."""
    base = tmp_path / "base"
    changed = tmp_path / "changed"
    write_public_fixture(base)
    # test 쪽에 1위 점수가 아주 높은 no_answer와 점수가 낮은 정답 질문을 더한다
    extra = [
        public_query("q-na-3", "acme router acme router acme router firmware", "no_answer", "test"),
        public_query("q-prod-3", "zzz", "product_symptom", "test", ["CVE-2026-0002"]),
    ]
    write_public_fixture(changed, PUBLIC_QUERIES + extra)
    run_public(base, retriever)
    run_public(changed, retriever)
    selected_base = read_manifest(base)["runs"][f"public/{retriever}"]["selected"]
    selected_changed = read_manifest(changed)["runs"][f"public/{retriever}"]["selected"]
    assert selected_base == selected_changed
    assert selected_base["selected_on"] == "dev"


def test_tau_is_chosen_from_dev_no_answer_top1_scores(tmp_path):
    root = tmp_path
    queries = [
        public_query("d-cve", "CVE-2026-0001 취약점", "cve_explicit", "dev", ["CVE-2026-0001"]),
        public_query("d-prod", "acme router", "product_symptom", "dev", ["CVE-2026-0001"]),
        public_query("d-na", "acme router firmware gateway", "no_answer", "dev"),
        public_query("t-cve", "CVE-2026-0005 취약점", "cve_explicit", "test", ["CVE-2026-0005"]),
        public_query("t-na", "CVE-2026-9001 알려주세요", "no_answer", "test"),
    ]
    write_public_fixture(root, queries)
    run_public(root, "bm25")
    entry = read_manifest(root)["runs"]["public/bm25"]
    records = {
        json.loads(line)["question_id"]: json.loads(line)
        for line in (root / OUT / "public" / "bm25.jsonl").read_text("utf-8").splitlines()
    }
    info = scoring.select_tau(
        [records["d-na"]["top1_score_raw"]],
        [records["d-cve"]["top1_score_raw"], records["d-prod"]["top1_score_raw"]],
    )
    assert entry["selected"]["tau"] == info["tau"]
    assert entry["selected"]["tau_selection"]["rule"].startswith("dev에서")


def test_bm25_selection_fails_clearly_without_scored_answerable_dev_questions(tmp_path):
    queries = [
        public_query("q-na-1", "CVE-2026-9001를 설명하는 레코드", "no_answer", "dev"),
        public_query("q-cve-2", "CVE-2026-0005는?", "cve_explicit", "test", ["CVE-2026-0005"]),
    ]
    write_public_fixture(tmp_path, queries)
    with pytest.raises(ValueError, match="scored answerable dev"):
        run_public(tmp_path, "bm25")


def test_bm25_grid_prefers_defaults_on_ties_and_records_grid(public_root):
    run_public(public_root, "bm25")
    config = read_manifest(public_root)["runs"]["public/bm25"]["config"]
    rows = config["grid"]["rows"]
    assert len(rows) == len(runner.BM25_GRID_K1) * len(runner.BM25_GRID_B)
    best = max(row["dev_macro_ndcg@10"] for row in rows)
    selected = config["selected"]
    assert selected["dev_macro_ndcg@10"] == best
    tied = {(r["k1"], r["b"]) for r in rows if r["dev_macro_ndcg@10"] == best}
    if (runner.DEFAULT_K1, runner.DEFAULT_B) in tied:
        assert (selected["k1"], selected["b"]) == (runner.DEFAULT_K1, runner.DEFAULT_B)
    assert config["tokenizer"]["id"] == "bm25-tok-v1"


# ------------------------------------------------------------ 분할 인자


def test_split_dev_writes_only_dev_and_test_uses_frozen_config(public_root):
    run_public(public_root, "bm25", split="dev")
    path = public_root / OUT / "public" / "bm25.jsonl"
    dev_ids = {json.loads(line)["question_id"] for line in path.read_text("utf-8").splitlines()}
    assert dev_ids == {"q-cve-1", "q-prod-1", "q-na-1"}
    entry = read_manifest(public_root)["runs"]["public/bm25"]
    assert entry["splits_stored"] == ["dev"]
    metrics = json.loads((public_root / OUT / "metrics.json").read_text("utf-8"))["runs"]
    assert set(metrics["public/bm25"]) == {"dev"}

    run_public(public_root, "bm25", split="test")
    entry_after = read_manifest(public_root)["runs"]["public/bm25"]
    assert entry_after["selected"] == entry["selected"]  # test는 설정을 다시 고르지 않는다
    assert entry_after["splits_stored"] == ["dev", "test"]
    all_ids = {json.loads(line)["question_id"] for line in path.read_text("utf-8").splitlines()}
    assert all_ids == {q["id"] for q in PUBLIC_QUERIES}

    # all로 처음부터 돌려도 같은 결과 파일이다
    saved = path.read_text("utf-8")
    run_public(public_root, "bm25", split="all")
    assert path.read_text("utf-8") == saved


def test_split_test_without_dev_selection_fails(public_root):
    with pytest.raises(ValueError, match="dev-selected"):
        run_public(public_root, "bm25", split="test")


def test_split_test_fails_when_inputs_changed_since_the_dev_run(public_root):
    run_public(public_root, "bm25", split="dev")
    queries = public_root / data.PUBLIC_QUERIES
    rows = data.read_jsonl(queries)
    rows[1]["unjudged"] = []  # 같은 ID, 바뀐 라벨
    write_jsonl(queries, rows)
    with pytest.raises(ValueError, match="inputs changed"):
        run_public(public_root, "bm25", split="test")
    run_public(public_root, "bm25", split="all")  # 처음부터 다시 돌리면 통과한다


def test_compute_metrics_fails_on_partially_stored_split(public_root):
    run_public(public_root, "exact")
    path = public_root / OUT / "public" / "exact.jsonl"
    lines = path.read_text("utf-8").splitlines()
    dropped = [line for line in lines if json.loads(line)["question_id"] != "q-cve-1"]
    path.write_text("\n".join(dropped) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="stored rows"):
        runner.compute_run_metrics("public", "exact", public_root, OUT)


def test_rerunning_dev_drops_stale_test_rows(public_root):
    run_public(public_root, "exact")
    run_public(public_root, "exact", split="dev")
    path = public_root / OUT / "public" / "exact.jsonl"
    ids = {json.loads(line)["question_id"] for line in path.read_text("utf-8").splitlines()}
    assert ids == {"q-cve-1", "q-prod-1", "q-na-1"}


@pytest.mark.parametrize(
    ("track", "retriever", "split"),
    [("web", "bm25", "all"), ("public", "tfidf", "all"), ("public", "bm25", "val")],
)
def test_bad_arguments_are_rejected(public_root, track, retriever, split):
    with pytest.raises(ValueError, match="bad arguments"):
        runner.run_baseline(track, retriever, public_root, split=split)


# ------------------------------------------------------------ manifest 필수 항목


def test_manifest_records_required_settings(public_root):
    run_public(public_root, "bm25")
    run_public(public_root, "dense")
    manifest = read_manifest(public_root)
    assert manifest["protocol_version"] == "eval-protocol-v2"
    bm25 = manifest["runs"]["public/bm25"]
    for field in ("inputs", "n_documents", "index_text", "stored_results", "config", "selected"):
        assert field in bm25
    assert bm25["config"]["tokenizer"]["rules"]
    assert bm25["stored_results"]["top_n"] == 100
    assert (
        bm25["inputs"]["corpus"]["sha256"]
        == hashlib.sha256((public_root / data.PUBLIC_CORPUS).read_bytes()).hexdigest()
    )
    assert {"index_seconds", "query_latency_median_seconds", "n_queries_timed"} <= set(
        bm25["timing"]
    )
    assert {"platform", "python"} <= set(bm25["environment"])
    assert str(public_root) not in json.dumps(manifest)


# ------------------------------------------------------------ 합성 KISA 트랙

NTT_IDS = ["90001", "90002", "90003", "90004", "90005", "90006"]
KISA_BODIES = {
    "90001": "Acme 라우터 보안 업데이트 CVE-2026-1001 CVE-2026-1002 를 인용한다",
    "90002": "Globex 게이트웨이 인증 우회 CVE-2026-1003 을 인용한다",
    "90003": "Initech 데이터베이스 패치 안내 CVE-2026-1004 취약점",
    "90004": "스미싱 문자 주의 안내 본문 CVE 없음",
    "90005": "Umbrella 카메라 펌웨어 업데이트 CVE-2026-1002 도 인용한다",
    "90006": "일반 보안 점검 방법 설명 문서 서버 패치 절차",
}


def kisa_question(qid, query, query_type, split, answers=(), unjudged=(), excluded=False):
    return {
        "question_id": qid,
        "query": query,
        "query_type": query_type,
        "split": split,
        "answers": [
            {"doc_id": doc, "doc_sha256": hashlib.sha256(doc.encode()).hexdigest()}
            for doc in answers
        ],
        "unjudged": list(unjudged),
        "excluded": excluded,
    }


KISA_QUESTIONS = [
    kisa_question("k-cve-1", "CVE-2026-1001 관련 공지가 있나요?", "cve_explicit", "dev", ["90001"]),
    kisa_question("k-cve-2", "CVE-2026-1002를 인용한 공지", "cve_explicit", "dev", ["90001", "90005"], []),
    kisa_question("k-prod-1", "Globex 게이트웨이 인증 우회 공지", "product_symptom", "dev", ["90002"]),
    kisa_question("k-exp-ex", "설명 질문이지만 정답이 판정 불가", "explanation_comparison", "dev", [], ["90006"], True),
    kisa_question("k-na-1", "CVE-2026-9999 관련 공지가 있나요?", "no_answer", "dev"),
    kisa_question("k-cve-3", "CVE-2026-1004 알려주세요", "cve_explicit", "test", ["90003"]),
    kisa_question("k-exp-1", "서버 패치 절차 설명", "explanation_comparison", "test", ["90006"], ["90003"]),
    kisa_question("k-na-2", "CVE-2026-9998 관련 공지가 있나요?", "no_answer", "test"),
]  # fmt: skip


def write_kisa_fixture(root):
    documents = [
        {"nttId": ntt, "sha256": hashlib.sha256(ntt.encode()).hexdigest()} for ntt in NTT_IDS
    ]
    (root / "fixtures/kisa").mkdir(parents=True)
    (root / data.KISA_MANIFEST).write_text(json.dumps({"documents": documents}), encoding="utf-8")
    write_jsonl(
        root / data.KISA_METADATA,
        [{"nttId": ntt, "title": f"공지 {ntt} 제목", "cve_ids": []} for ntt in NTT_IDS],
    )
    write_jsonl(root / data.KISA_GOLDEN, KISA_QUESTIONS)


def fake_body_loader(ntt_id, document):
    assert document["nttId"] == ntt_id
    return KISA_BODIES[ntt_id]


@pytest.fixture
def kisa_root(tmp_path):
    write_kisa_fixture(tmp_path)
    return tmp_path


@pytest.mark.parametrize("retriever", runner.RETRIEVERS)
def test_kisa_track_all_retrievers(kisa_root, retriever):
    returned = runner.run_baseline(
        "kisa", retriever, kisa_root, load_body=fake_body_loader, dense_factory=FakeDense
    )
    assert returned["dev"]["n_excluded"] == 1  # excluded 질문은 집계에서 빠진다
    assert returned["dev"]["n_questions"] == 4
    assert returned["test"]["n_excluded"] == 0
    raw = (kisa_root / OUT / "kisa" / f"{retriever}.jsonl").read_text("utf-8")
    ids = {json.loads(line)["question_id"] for line in raw.splitlines()}
    assert "k-exp-ex" not in ids  # excluded는 결과에도 없다
    assert len(ids) == len(KISA_QUESTIONS) - 1
    for body in KISA_BODIES.values():
        assert body not in raw
    manifest_text = (kisa_root / OUT / "manifest.json").read_text("utf-8")
    assert str(kisa_root) not in manifest_text


def test_kisa_exact_indexes_title_and_body_cve_ids_and_condenses(kisa_root):
    returned = runner.run_baseline("kisa", "exact", kisa_root, load_body=fake_body_loader)
    dev = returned["dev"]["by_type"]["cve_explicit"]
    assert dev["metrics"]["ndcg@10"] == 1.0
    assert dev["metrics"]["recall@1"] == pytest.approx((1.0 + 0.5) / 2)  # k-cve-2는 두 공지가 동점
    assert dev["tie_at_cutoff"]["@1"] == 1
    # k-exp-1: 정답 90006, unjudged 90003. exact는 빈 결과 -> 0점
    test = returned["test"]["by_type"]["explanation_comparison"]
    assert test["metrics"]["ndcg@10"] == 0.0
    assert returned["test"]["no_answer"]["abstain_rate"] == 1.0


def test_kisa_track_requires_a_body_loader(kisa_root):
    with pytest.raises(ValueError, match="load_body"):
        runner.run_baseline("kisa", "bm25", kisa_root)


def test_kisa_loader_failure_aborts_the_run(kisa_root):
    def failing(ntt_id, document):
        raise RuntimeError("cache_missing")

    with pytest.raises(RuntimeError, match="cache_missing"):
        runner.run_baseline("kisa", "bm25", kisa_root, load_body=failing)
    assert not (kisa_root / OUT / "kisa" / "bm25.jsonl").exists()


def test_kisa_answer_hash_mismatch_fails(kisa_root):
    rows = [dict(q) for q in KISA_QUESTIONS]
    rows[0] = kisa_question("k-cve-1", "CVE-2026-1001", "cve_explicit", "dev", ["90001"])
    rows[0]["answers"][0]["doc_sha256"] = "0" * 64
    write_jsonl(kisa_root / data.KISA_GOLDEN, rows)
    with pytest.raises(ValueError, match="doc_sha256"):
        runner.run_baseline("kisa", "exact", kisa_root, load_body=fake_body_loader)


def test_script_kisa_cache_missing_is_exit_1_without_leaking_the_path(tmp_path, capsys):
    code = run_baselines.main(
        ["--track", "kisa", "--retriever", "exact", "--kisa-root", str(tmp_path / "no-cache")]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert "cache_missing" in captured.err
    assert "no-cache" not in captured.err + captured.out


def test_script_exit_1_also_for_kisa_error_subclasses(monkeypatch, capsys, tmp_path):
    class FakeKisaError(Exception):
        pass

    class FakeParseError(FakeKisaError):
        pass

    class FakeKisa:
        KisaError = FakeKisaError

        @staticmethod
        def load_cached_body(root, ntt_id, document):
            raise FakeParseError("invalid_id")

    monkeypatch.setattr(run_baselines, "load_kisa_module", lambda: FakeKisa)
    code = run_baselines.main(
        ["--track", "kisa", "--retriever", "exact", "--kisa-root", str(tmp_path)]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert "error: invalid_id" in captured.err


def test_script_requires_kisa_root_for_kisa_track(capsys):
    with pytest.raises(SystemExit):
        run_baselines.main(["--track", "kisa", "--retriever", "exact"])
    assert "--kisa-root" in capsys.readouterr().err


# ------------------------------------------------------------ 커밋된 결과의 정합성

COMMITTED = ROOT / OUT


def committed_runs():
    if not (COMMITTED / "manifest.json").exists():
        return []
    return sorted(json.loads((COMMITTED / "manifest.json").read_text("utf-8"))["runs"])


@pytest.mark.skipif(not committed_runs(), reason="results/baselines not committed yet")
@pytest.mark.parametrize("key", committed_runs())
def test_committed_results_match_schema_and_recomputed_metrics(key):
    track, retriever = key.split("/")
    path = COMMITTED / track / f"{retriever}.jsonl"
    rows = data.read_jsonl(path)
    for row in rows:
        scoring.validate_record(row)
    questions = {q.question_id: q for q in data.load_questions(track, ROOT)}
    assert {row["question_id"] for row in rows} == {
        qid for qid, q in questions.items() if not q.excluded
    }
    stored = json.loads((COMMITTED / "metrics.json").read_text("utf-8"))["runs"][key]
    recomputed = runner.compute_run_metrics(track, retriever, ROOT, OUT)
    assert json.loads(json.dumps(recomputed)) == stored
    entry = json.loads((COMMITTED / "manifest.json").read_text("utf-8"))["runs"][key]
    assert entry["protocol_version"] == "eval-protocol-v2"
    assert entry["selected"]["selected_on"] == "dev"
    assert entry["config"]


@pytest.mark.skipif(not committed_runs(), reason="results/baselines not committed yet")
def test_committed_outputs_have_no_personal_paths():
    for path in [*COMMITTED.rglob("*.json*"), ROOT / "docs" / "baselines.md"]:
        if path.exists():
            assert "/" + "Users" + "/" not in path.read_text("utf-8"), path


# ------------------------------------------------------------ docs 표


def test_render_docs_replaces_only_the_marked_block(public_root):
    run_public(public_root, "bm25")
    doc = public_root / report.DOC_PATH
    doc.parent.mkdir(parents=True)
    doc.write_text(f"앞 문단\n{report.BEGIN}\n옛 표\n{report.END}\n뒤 문단\n", encoding="utf-8")
    report.render_docs(public_root)
    text = doc.read_text("utf-8")
    assert text.startswith("앞 문단\n") and text.endswith("뒤 문단\n")
    assert "옛 표" not in text
    assert "| bm25 | dev |" in text and "| bm25 | test |" in text
    report.render_docs(public_root)  # 두 번 돌려도 같다
    assert doc.read_text("utf-8") == text


def test_render_docs_fails_without_markers(public_root):
    run_public(public_root, "exact")
    doc = public_root / report.DOC_PATH
    doc.parent.mkdir(parents=True)
    doc.write_text("표시 구간 없음\n", encoding="utf-8")
    with pytest.raises(ValueError, match="substring"):
        report.render_docs(public_root)


@pytest.mark.skipif(not committed_runs(), reason="results/baselines not committed yet")
def test_committed_docs_tables_match_committed_metrics():
    metrics = json.loads((COMMITTED / "metrics.json").read_text("utf-8"))
    manifest = json.loads((COMMITTED / "manifest.json").read_text("utf-8"))
    text = (ROOT / report.DOC_PATH).read_text("utf-8")
    block = text[text.index(report.BEGIN) + len(report.BEGIN) : text.index(report.END)]
    assert block.strip() == report.render_tables(metrics, manifest).strip()

"""청킹 실험 테스트 - 합성 텍스트·합성 토큰 오프셋·가짜 dense 인덱스만 쓰고 모델·KISA 캐시를 쓰지 않는다.

확인하는 것: 청크 경계(겹침, 마지막 청크, 텍스트보다 큰 청크), 청크 ID에 텍스트가 없음, 문서 점수 = 청크 최댓값,
근거 구간 겹침 판정(제목 길이 + 1 이동 포함), 청크 hit@10 계산, 하네스를 거친 end-to-end(합성 KISA 트랙),
모델 패키지 비접촉, 커밋된 results/experiments/chunking의 정합성과 `--compare`와 보고서 표 일치.
"""

import gc
import hashlib
import itertools
import json
import re
import shutil
import weakref
from pathlib import Path

import pytest
from test_experiments_harness import run_experiment, write_jsonl

from krsec_rag_lab.baselines import data, runner, scoring
from krsec_rag_lab.baselines import dense as dense_module
from krsec_rag_lab.experiments import ContractError, harness
from krsec_rag_lab.experiments import chunking as ch

ROOT = Path(__file__).resolve().parents[1]
OUT = Path("results/experiments")
CHUNKING_DIR = ROOT / OUT / "chunking"
CHUNK_ID_RE = re.compile(r"\d+#\d+-\d+")

# ------------------------------------------------------------ 청크 경계


@pytest.mark.parametrize(
    ("n_tokens", "size", "overlap", "expected"),
    [
        (10, 4, 0, [(0, 4), (4, 8), (8, 10)]),  # 마지막 청크는 짧다
        (8, 4, 0, [(0, 4), (4, 8)]),  # 딱 나누어 떨어지면 빈 꼬리 청크가 없다
        (10, 4, 1, [(0, 4), (3, 7), (6, 10)]),  # 겹침 1: 간격 3, 마지막 창이 끝에 닿으면 멈춘다
        (8, 4, 2, [(0, 4), (2, 6), (4, 8)]),  # 겹침 2: 마지막 창이 끝에 닿으면 멈춘다
        (9, 4, 2, [(0, 4), (2, 6), (4, 8), (6, 9)]),  # 마지막 창은 앞 창과 겹치되 새 토큰을 담는다
        (5, 4, 3, [(0, 4), (1, 5)]),
        (3, 4, 0, [(0, 3)]),  # 텍스트가 청크보다 짧다 -> 청크 1개
        (4, 4, 0, [(0, 4)]),  # 청크와 길이가 같다 -> 청크 1개
        (1, 4, 3, [(0, 1)]),
        (0, 4, 0, []),
    ],
)
def test_token_windows(n_tokens, size, overlap, expected):
    assert ch.token_windows(n_tokens, size, overlap) == expected


@pytest.mark.parametrize(("size", "overlap"), [(0, 0), (-1, 0), (4, 4), (4, 5), (4, -1)], ids=str)
def test_token_windows_rejects_bad_settings(size, overlap):
    with pytest.raises(ValueError, match="size"):
        ch.token_windows(10, size, overlap)


def synthetic_offsets(n_tokens, width=2, gap=1, start=0):
    """폭 `width`인 토큰이 `gap`칸 띄어 이어지는 합성 오프셋. 마지막 토큰 끝 = 텍스트 길이."""
    offsets = []
    position = start
    for _ in range(n_tokens):
        offsets.append((position, position + width))
        position += width + gap
    return offsets


def test_chunk_spans_follow_token_offsets_and_cover_the_text():
    offsets = synthetic_offsets(10)  # 토큰 i = [3i, 3i+2), 텍스트 길이 29
    length = offsets[-1][1]
    assert length == 29
    spans = ch.chunk_text_spans(offsets, length, 4, 0)
    assert spans == [(0, 11), (12, 23), (24, 29)]
    # 겹침 1: 둘째 청크는 첫 청크의 마지막 토큰에서 시작한다
    assert ch.chunk_text_spans(offsets, length, 4, 1) == [(0, 11), (9, 20), (18, 29)]


def test_first_chunk_starts_at_zero_and_last_chunk_ends_at_the_text_end():
    offsets = synthetic_offsets(6, start=2)  # 앞에 공백 2자, 뒤에 공백 4자
    spans = ch.chunk_text_spans(offsets, 6 * 3 + 2 + 4, 3, 0)
    assert spans[0][0] == 0
    assert spans[-1][1] == 6 * 3 + 2 + 4
    assert ch.chunk_text_spans(offsets, 30, 100, 0) == [(0, 30)]  # 텍스트보다 큰 청크: 전체 한 청크


def test_text_without_tokens_is_one_chunk():
    assert ch.chunk_text_spans([], 7, 4, 0) == [(0, 7)]


def test_chunk_ids_are_offsets_only_and_unique():
    secret = "비밀본문조각"
    text = f"제목\n{secret} " + "단어 " * 30
    words = [(m.start(), m.end()) for m in re.finditer(r"\S+", text)]
    chunks = ch.build_chunks("72143", text, words, 8, 1)
    assert len(chunks) > 2
    ids = [chunk.chunk_id for chunk in chunks]
    assert len(set(ids)) == len(ids)
    for chunk in chunks:
        assert CHUNK_ID_RE.fullmatch(chunk.chunk_id)
        assert chunk.chunk_id == f"72143#{chunk.start}-{chunk.end}"
        assert secret not in chunk.chunk_id and "단어" not in chunk.chunk_id
    assert ch.make_chunk_id("9", 3, 12) == "9#3-12"


def test_adjacent_chunks_with_zero_overlap_do_not_overlap_in_characters():
    text = "a " * 20
    words = [(m.start(), m.end()) for m in re.finditer(r"\S+", text)]
    chunks = ch.build_chunks("1", text, words, 5, 0)
    for before, after in itertools.pairwise(chunks):
        assert before.end <= after.start


# ------------------------------------------------------------ 문서 점수 = 청크 최댓값


def test_doc_score_is_the_max_of_its_chunk_scores():
    doc_of = {"1#0-5": "1", "1#5-9": "1", "2#0-4": "2", "3#0-4": "3"}
    scores = {"1#0-5": 0.2, "1#5-9": 0.9, "2#0-4": 0.5, "3#0-4": -0.3}
    assert ch.doc_scores_from_chunks(scores, doc_of) == {"1": 0.9, "2": 0.5, "3": -0.3}


def test_doc_score_max_does_not_depend_on_chunk_order():
    doc_of = {"a#0-1": "a", "a#1-2": "a", "a#2-3": "a"}
    for order in (["a#0-1", "a#1-2", "a#2-3"], ["a#2-3", "a#0-1", "a#1-2"]):
        scores = dict(zip(order, [0.1, 0.7, 0.4], strict=True))
        assert ch.doc_scores_from_chunks(scores, doc_of) == {"a": 0.7}


# ------------------------------------------------------------ 근거 구간 겹침


@pytest.mark.parametrize(
    ("chunk", "span", "expected"),
    [
        ((0, 5), (5, 8), False),  # 반개구간: 맞닿기만 하면 겹치지 않는다
        ((5, 8), (0, 5), False),
        ((0, 5), (4, 8), True),  # 1자 겹침
        ((4, 8), (0, 5), True),
        ((0, 10), (3, 4), True),  # 청크가 근거를 품는다
        ((3, 4), (0, 10), True),  # 근거가 청크를 품는다
        ((0, 5), (0, 5), True),
        ((0, 5), (9, 12), False),
    ],
)
def test_overlap_is_at_least_one_character(chunk, span, expected):
    assert ch.overlaps(*chunk, *span) is expected


def test_gold_chunks_shift_evidence_by_title_length_plus_one():
    title = "제목셋"  # 길이 3 -> 색인 텍스트에서 본문은 4자 밀린다
    chunks = [
        ch.Chunk(ch.make_chunk_id("d", 0, 4), "d", 0, 4),  # 제목 + 줄바꿈
        ch.Chunk(ch.make_chunk_id("d", 4, 8), "d", 4, 8),  # 본문 [0, 4)
        ch.Chunk(ch.make_chunk_id("d", 8, 12), "d", 8, 12),  # 본문 [4, 8)
        ch.Chunk(ch.make_chunk_id("e", 0, 20), "e", 0, 20),  # 다른 문서
    ]
    evidence = {"d": [(0, 2)]}  # 본문 [0, 2)
    shifted = ch.gold_chunk_ids(chunks, evidence, {"d": len(title) + 1})
    assert shifted == {"d#4-8"}
    unshifted = ch.gold_chunk_ids(chunks, evidence, {})
    assert unshifted == {
        "d#0-4"
    }  # 이동을 안 하면 제목 청크가 정답이 되는 오류를 이 테스트가 잡는다


def test_gold_chunks_collect_every_judge_span_and_edge_overlaps():
    chunks = [ch.Chunk(f"d#{s}-{s + 4}", "d", s, s + 4) for s in range(0, 20, 4)]
    evidence = {
        "d": [(3, 5), (15, 17)]
    }  # 첫 구간은 두 청크에 걸치고, 둘째는 [12,16)과 [16,20)에 걸친다
    assert ch.gold_chunk_ids(chunks, evidence, {"d": 0}) == {
        "d#0-4",
        "d#4-8",
        "d#12-16",
        "d#16-20",
    }
    assert ch.gold_chunk_ids(chunks, {"d": [(4, 5)]}, {"d": 0}) == {"d#4-8"}
    assert (
        ch.gold_chunk_ids(chunks, {"d": [(4, 4)]}, {"d": 0}) == frozenset()
    )  # 빈 구간은 겹치지 않는다


# ------------------------------------------------------------ 격자와 사전 등록 값


def test_grid_and_registration_are_the_preregistered_ones():
    assert ch.grid("kisa", ch.VARIANT) == [
        {"size": 256, "overlap": 0},
        {"size": 256, "overlap": 32},
        {"size": 512, "overlap": 0},
        {"size": 512, "overlap": 64},
        {"size": 1024, "overlap": 0},
        {"size": 1024, "overlap": 128},
    ]
    assert ch.PRIMARY == ("kisa", "chunk_max")
    assert ch.VARIANTS == {"kisa": ("chunk_max",)}
    assert ch.BASELINES == {"kisa": "dense"}
    assert ch.CHUNK_HIT_K == 10
    assert [ch.config_label(c) for c in ch.grid("kisa", ch.VARIANT)][:2] == ["256/0", "256/32"]


def baseline_manifest(name=dense_module.MODEL_NAME, revision=dense_module.MODEL_REVISION):
    return {"runs": {"kisa/dense": {"config": {"model": {"name": name, "revision": revision}}}}}


def test_fixed_config_pins_the_baseline_model_and_rejects_a_different_one():
    fixed = ch.fixed_config("kisa", ch.VARIANT, baseline_manifest())
    assert fixed["dense"] == {"name": "BAAI/bge-m3", "revision": dense_module.MODEL_REVISION}
    assert fixed["tokenizer"] == fixed["dense"]
    with pytest.raises(ContractError, match="baseline dense model"):
        ch.fixed_config("kisa", ch.VARIANT, baseline_manifest(revision="other"))
    with pytest.raises(ContractError, match="baseline dense model"):
        ch.fixed_config("kisa", ch.VARIANT, baseline_manifest(name="other/model"))


# ------------------------------------------------------------ 합성 KISA 트랙

NTT_IDS = ["91001", "91002", "91003", "91004"]
FILLER = "filler"


def make_body(marker, position, length=40):
    """공백으로 나뉜 `length`개 낱말 본문, `position`번째 낱말이 `marker`."""
    return " ".join(marker if i == position else f"{FILLER}{i}" for i in range(length))


BODIES = {
    "91001": make_body("alphaword", 3),
    "91002": make_body("betaword", 30),  # 앞 청크에는 없고 뒤쪽 청크에만 있다
    "91003": make_body("gammaword", 17),
    "91004": make_body("deltaword", 36),
}
TITLES = {ntt: f"공지 {ntt} 제목" for ntt in NTT_IDS}


def evidence_for(ntt, marker):
    body = BODIES[ntt]
    start = body.index(marker)
    return [
        {
            "judge": "A",
            "parser_version": "kisa-html-v1",
            "start": start,
            "end": start + len(marker),
        },
        {
            "judge": "B",
            "parser_version": "kisa-html-v1",
            "start": start,
            "end": start + len(marker),
        },
    ]


def golden_row(qid, query, query_type, split, ntt=None, marker=None, unjudged=()):
    answers = []
    if ntt:
        answers.append(
            {
                "doc_id": ntt,
                "doc_sha256": hashlib.sha256(ntt.encode()).hexdigest(),
                "evidence": evidence_for(ntt, marker),
            }
        )
    return {
        "question_id": qid,
        "query": query,
        "query_type": query_type,
        "split": split,
        "answers": answers,
        "unjudged": list(unjudged),
        "excluded": False,
    }


GOLDEN = [
    golden_row("k-d-cve", "alphaword 공지", "cve_explicit", "dev", "91001", "alphaword"),
    golden_row("k-d-prod", "betaword 공지", "product_symptom", "dev", "91002", "betaword"),
    golden_row("k-d-na", "nothing here", "no_answer", "dev"),
    golden_row("k-t-cve", "gammaword 공지", "cve_explicit", "test", "91003", "gammaword"),
    golden_row("k-t-prod", "deltaword 공지", "product_symptom", "test", "91004", "deltaword"),
    golden_row(
        "k-t-exp", "alphaword betaword", "explanation_comparison", "test", "91001", "alphaword",
        unjudged=["91002"],
    ),
    golden_row("k-t-na", "nothing there", "no_answer", "test"),
]  # fmt: skip


def write_kisa_fixture(root, golden=GOLDEN):
    documents = [{"nttId": n, "sha256": hashlib.sha256(n.encode()).hexdigest()} for n in NTT_IDS]
    (root / "fixtures/kisa").mkdir(parents=True)
    (root / data.KISA_MANIFEST).write_text(
        json.dumps({"parser_version": "kisa-html-v1", "documents": documents}), encoding="utf-8"
    )
    write_jsonl(root / data.KISA_METADATA, [{"nttId": n, "title": TITLES[n]} for n in NTT_IDS])
    write_jsonl(root / data.KISA_GOLDEN, golden)


def body_loader(ntt_id, document):
    assert document["nttId"] == ntt_id
    return BODIES[ntt_id]


def overlap_score(query, text):
    return len(set(query.split()) & set(text.split())) / 10


class FakeDense:
    """가짜 dense 인덱스: 질의 낱말과 텍스트 낱말의 겹침 수를 점수로 쓴다. 모델을 부르지 않는다."""

    def __init__(self, texts):
        self.texts = texts
        self.meta = {
            "model": {"name": dense_module.MODEL_NAME, "revision": dense_module.MODEL_REVISION},
            "runtime": {"python": "fake"},
            "doc_encode_seconds": 0.0,
        }

    def score(self, query):
        return {key: overlap_score(query, text) for key, text in self.texts.items()}


def fake_tokenizer():
    def offsets_of(texts):
        return [[(m.start(), m.end()) for m in re.finditer(r"\S+", text)] for text in texts]

    return offsets_of


PUBLIC_RECORDS = [
    {"id": "CVE-2026-1000", "description_en": "short text"},
    {"id": "CVE-2026-1001", "description_en": " ".join(f"w{i}" for i in range(12))},
    {"id": "CVE-2026-1002", "description_en": " ".join(f"w{i}" for i in range(40))},
]


@pytest.fixture
def small_grid(monkeypatch):
    """토큰 8, 16개 청크(겹침 0, 크기의 1/8)와 공백 토큰화로 합성 본문(약 45 토큰)을 여러 청크로 나눈다."""
    monkeypatch.setattr(ch, "SIZES", (8, 16))
    monkeypatch.setattr(ch, "load_offsets_tokenizer", fake_tokenizer)


@pytest.fixture
def root(tmp_path, small_grid):
    write_kisa_fixture(tmp_path)
    runner.run_baseline("kisa", "dense", tmp_path, load_body=body_loader, dense_factory=FakeDense)
    return tmp_path


class RecordingFactory:
    """dense_factory 대역: 호출마다 받은 청크 텍스트 키를 기록하고 지금 살아 있는 인덱스 수를 센다."""

    def __init__(self):
        self.calls = []

    def __call__(self, texts):
        self.calls.append(dict(texts))
        return FakeDense(texts)


def run_chunking(root, factory=None, **kwargs):
    return harness.run_experiment(
        "chunking",
        "kisa",
        root,
        load_body=body_loader,
        dense_factory=factory or FakeDense,
        **kwargs,
    )


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_end_to_end_on_the_synthetic_kisa_track(root):
    factory = RecordingFactory()
    comparison = run_chunking(root, factory)
    assert comparison["primary"]["track"] == "kisa"
    assert comparison["primary"]["variant"] == "chunk_max"
    assert comparison["primary"]["baseline"] == "dense"
    assert comparison["primary"]["verdict"] in ("hypothesis-confirmed", "hypothesis-rejected")
    assert comparison["secondary"] == []
    out_dir = root / OUT / "chunking"
    assert sorted(p.relative_to(out_dir).as_posix() for p in out_dir.rglob("*") if p.is_file()) == [
        "comparison.json",
        "kisa/chunk_max.jsonl",  # 청크 순위 파일은 따로 저장하지 않는다
        "manifest.json",
        "metrics.json",
    ]
    assert harness.verify_outputs(harness.load_experiment("chunking"), root, OUT) == []
    # dense 인덱스에는 청크 ID를 키로 청크 텍스트가 들어간다(문서 전체가 아니다)
    for call in factory.calls:
        assert call
        assert all(CHUNK_ID_RE.fullmatch(key) for key in call)
        assert max(len(text.split()) for text in call.values()) <= 16  # 청크는 최대 크기 토큰


def test_stored_doc_scores_are_the_max_over_the_chunks_of_the_selected_config(root):
    run_chunking(root)
    out_dir = root / OUT / "chunking"
    entry = read_json(out_dir / "manifest.json")["runs"]["kisa/chunk_max"]
    config = entry["selected"]["config"]
    texts = {n: f"{TITLES[n]}\n{BODIES[n]}" for n in NTT_IDS}
    chunk_texts = {}
    for ntt, text in texts.items():
        words = [(m.start(), m.end()) for m in re.finditer(r"\S+", text)]
        for chunk in ch.build_chunks(ntt, text, words, config["size"], config["overlap"]):
            chunk_texts[chunk.chunk_id] = (chunk.doc_id, text[chunk.start : chunk.end])
    stored = {r["question_id"]: r for r in data.read_jsonl(out_dir / "kisa/chunk_max.jsonl")}
    questions = {q["question_id"]: q for q in GOLDEN}
    for question_id, record in stored.items():
        query = questions[question_id]["query"]
        expected: dict[str, float] = {}
        for doc_id, text in chunk_texts.values():
            expected[doc_id] = max(expected.get(doc_id, 0.0), overlap_score(query, text))
        expected_record = scoring.make_record(
            question_id, expected, frozenset(questions[question_id]["unjudged"])
        )
        assert record == json.loads(json.dumps(expected_record))
    assert set(stored) == {q["question_id"] for q in GOLDEN}


def test_manifest_records_grid_selection_fixed_config_and_chunk_observations(root):
    run_chunking(root)
    entry = read_json(root / OUT / "chunking/manifest.json")["runs"]["kisa/chunk_max"]
    labels = ["8/0", "8/1", "16/0", "16/2"]
    assert [ch.config_label(row["config"]) for row in entry["grid"]["rows"]] == labels
    assert entry["selected"]["selected_on"] == "dev"
    assert entry["test"]["config"] == entry["selected"]["config"]
    assert entry["fixed"]["dense"]["name"] == "BAAI/bge-m3"
    assert entry["baseline"]["retriever"] == "dense"
    description = entry["description"]
    assert set(description["chunk_stats"]) == set(labels)  # manifest는 키를 정렬해 쓴다
    for label in labels:
        stats = description["chunk_stats"][label]
        assert stats["n_chunks"] >= stats["n_docs"] == len(NTT_IDS)
        assert stats["n_docs_with_2plus_chunks"] == len(NTT_IDS)  # 본문 40 낱말 + 제목 > 16
    # 청크 hit@10: dev는 격자 전체, test는 확정 설정만
    by_config = description["chunk_hit"]["by_config"]
    assert set(by_config) == set(labels)
    selected = ch.config_label(entry["selected"]["config"])
    for label in labels:
        assert "dev" in by_config[label]
        assert ("test" in by_config[label]) is (label == selected)
    dev = by_config[selected]["dev"]
    assert dev["n_questions"] == 2 and dev["n_with_gold_chunks"] == 2
    assert dev["macro_hit@10"] == 1.0  # 마커 낱말이 든 청크가 근거 구간과 겹치고 1위다
    assert description["public_records_with_2plus_chunks"] is None  # 합성 루트에 공개 코퍼스가 없다


def test_outputs_leave_out_bodies_titles_and_absolute_paths(root):
    run_chunking(root)
    out_dir = root / OUT / "chunking"
    text = "".join(p.read_text("utf-8") for p in out_dir.rglob("*") if p.is_file())
    assert FILLER not in text
    assert "betaword" not in text
    assert "공지 91001" not in text  # 제목
    assert str(root) not in text
    assert harness.find_absolute_paths(read_json(out_dir / "manifest.json")) == []


def test_only_one_dense_index_is_alive_at_a_time(root):
    refs = []
    alive_before_each_build = []

    def factory(texts):
        gc.collect()
        alive_before_each_build.append(sum(ref() is not None for ref in refs))
        index = FakeDense(texts)
        refs.append(weakref.ref(index))
        return index

    run_chunking(root, factory)
    assert len(alive_before_each_build) >= 4  # 격자 4개 설정마다 한 번 이상 만든다
    assert set(alive_before_each_build) == {0}  # 새 인덱스를 만들 때 앞 인덱스는 이미 내려가 있다


def test_changing_the_grid_after_test_is_a_lock_error(root, monkeypatch):
    run_chunking(root)
    monkeypatch.setattr(ch, "SIZES", (24,))  # 확정 설정이 격자에서 빠진다
    with pytest.raises(harness.LockError):
        run_chunking(root)


# ------------------------------------------------------------ 공개 트랙: 판정 없이 청크 2개 이상 레코드 수만


def test_public_track_is_not_judged_and_only_counts_multi_chunk_records(tmp_path, small_grid):
    write_kisa_fixture(tmp_path)
    write_jsonl(tmp_path / data.PUBLIC_CORPUS, PUBLIC_RECORDS)
    assert "public" not in ch.VARIANTS
    with pytest.raises(ContractError, match="no track"):
        harness.run_experiment("chunking", "public", tmp_path, dense_factory=FakeDense)
    questions = data.load_kisa_questions(tmp_path)
    corpus = data.load_kisa_corpus(tmp_path, body_loader)
    ctx = harness.Context(
        root=tmp_path,
        track="kisa",
        variant=ch.VARIANT,
        corpus=corpus,
        questions=questions,
        baselines_manifest={},
        fixed={},
        dense_factory=FakeDense,
    )
    state = ch.setup(ctx)
    # 공개 색인 텍스트 = id + 공백 + 설명: 3, 13, 41 토큰 -> 크기 8에서는 둘, 크기 16에서는 하나가 청크 2개 이상
    assert state.public_multi_chunk == {"8/0": 2, "8/1": 2, "16/0": 1, "16/2": 1}


# ------------------------------------------------------------ 청크 hit@10 계산


CROWD = [ch.Chunk(f"u#{i}-{i + 1}", "u", i, i + 1) for i in range(9)]  # unjudged 문서의 청크 9개


def hit_state(rankings, unjudged=(), evidence=None):
    chunks = [
        ch.Chunk("d#0-10", "d", 0, 10),  # 제목 "abc" + 줄바꿈 + 본문 [0, 6)
        ch.Chunk("d#10-20", "d", 10, 20),  # 본문 [6, 16)
        ch.Chunk("e#0-10", "e", 0, 10),
        ch.Chunk("e#10-20", "e", 10, 20),
        *CROWD,
    ]
    questions = [
        data.Question("q-dev", "x", "cve_explicit", "dev", frozenset({"d"}), frozenset(unjudged), False),
        data.Question("q-test", "x", "cve_explicit", "test", frozenset({"d"}), frozenset(), False),
        data.Question("q-na", "x", "no_answer", "dev", frozenset(), frozenset(), False),
    ]  # fmt: skip
    return ch.State(
        texts={},
        dense_factory=FakeDense,
        chunks={"cfg": chunks},
        token_counts={},
        questions=questions,
        evidence=evidence if evidence is not None else {"q-dev": {"d": [(7, 9)]}, "q-test": {"d": [(7, 9)]}},
        shifts={"d": 4, "e": 4, "u": 4},
        public_multi_chunk=None,
        rankings=rankings,
    )  # fmt: skip


def test_chunk_hit_uses_shifted_evidence():
    # 근거 본문 [7, 9) -> 색인 텍스트 [11, 13) -> 청크 d#10-20만 정답
    state = hit_state({("cfg", "q-dev"): ["e#0-10", "d#10-20", "d#0-10", "e#10-20"]})
    report = ch.chunk_hit_report(state, "cfg")
    assert report["dev"]["macro_hit@10"] == 1.0
    assert "test" not in report  # test 순위가 없으면(확정 설정이 아니면) 보고하지 않는다
    assert report["dev"]["n_questions"] == 1  # no_answer 질문은 정답이 없어 세지 않는다
    wrong = hit_state({("cfg", "q-dev"): ["e#0-10", "d#0-10", "e#10-20", "d#10-20"][:3]})
    assert (
        ch.chunk_hit_report(wrong, "cfg")["dev"]["macro_hit@10"] == 0.0
    )  # 정답 청크가 순위에 없다


@pytest.mark.parametrize(
    ("unjudged", "expected"),
    [
        ((), 0.0),  # 정답 청크가 11위라 놓친다
        (("u",), 1.0),  # unjudged 문서의 청크 9개를 지우면 2위가 된다
    ],
)
def test_chunk_hit_removes_unjudged_document_chunks_before_cutting_at_ten(unjudged, expected):
    ranking = [*(c.chunk_id for c in CROWD), "e#0-10", "d#10-20"]
    state = hit_state({("cfg", "q-dev"): ranking}, unjudged=unjudged)
    assert ch.chunk_hit_report(state, "cfg")["dev"]["macro_hit@10"] == expected


def test_chunk_hit_reports_test_only_when_test_rankings_exist_and_skips_questions_without_evidence():
    rankings = {("cfg", "q-dev"): ["d#10-20"], ("cfg", "q-test"): ["d#0-10"]}
    state = hit_state(rankings)
    report = ch.chunk_hit_report(state, "cfg")
    assert report["dev"]["macro_hit@10"] == 1.0
    assert report["test"]["macro_hit@10"] == 0.0  # 1위가 근거와 안 겹치는 제목 쪽 청크
    no_evidence = hit_state(rankings, evidence={})
    report = ch.chunk_hit_report(no_evidence, "cfg")
    assert report["dev"]["macro_hit@10"] is None  # 근거가 없으면 정답 청크가 없어 정의되지 않는다
    assert report["dev"]["n_with_gold_chunks"] == 0
    assert report["dev"]["n_questions"] == 1


# ------------------------------------------------------------ 모델 패키지 비접촉


def test_chunking_module_has_no_top_level_model_imports():
    source = (ROOT / "src/krsec_rag_lab/experiments/chunking.py").read_text("utf-8")
    top_level = [line for line in source.splitlines() if line.startswith(("import ", "from "))]
    for package in ("numpy", "torch", "sentence_transformers", "transformers"):
        assert not any(re.search(rf"\b{package}\b", line) for line in top_level)


# ------------------------------------------------------------ 커밋된 결과 (model·KISA 캐시 없이)

COMMITTED = (CHUNKING_DIR / "comparison.json").exists()


@pytest.fixture
def committed_cli(monkeypatch):
    monkeypatch.setattr(run_experiment, "ROOT", ROOT)
    return run_experiment.main


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/chunking not committed yet")
def test_committed_results_pass_the_compare(committed_cli, capsys):
    assert committed_cli(["--exp", "chunking", "--compare"]) == 0
    assert "compare OK" in capsys.readouterr().out


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/chunking not committed yet")
@pytest.mark.parametrize(
    ("filename", "path"),
    [
        ("metrics.json", ("runs", "kisa/chunk_max", "test", "macro", "ndcg@10")),
        ("comparison.json", ("comparisons", "kisa/chunk_max", "delta")),
        ("comparison.json", ("comparisons", "kisa/chunk_max", "ci95", "high")),
    ],
)
def test_a_copy_with_one_number_changed_fails_the_compare(
    committed_cli, capsys, tmp_path, filename, path
):
    copy_dir = tmp_path / "chunking"
    shutil.copytree(CHUNKING_DIR, copy_dir)
    assert committed_cli(["--exp", "chunking", "--compare", "--out-dir", str(tmp_path)]) == 0
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
    assert committed_cli(["--exp", "chunking", "--compare", "--out-dir", str(tmp_path)]) == 1
    assert "compare FAILED" in capsys.readouterr().err


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/chunking not committed yet")
def test_committed_comparison_fields_lock_and_chunk_observations():
    comparison = read_json(CHUNKING_DIR / "comparison.json")
    assert comparison["primary"]["track"] == "kisa"
    assert comparison["primary"]["variant"] == "chunk_max"
    assert comparison["primary"]["baseline"] == "dense"
    assert comparison["secondary"] == []
    block = comparison["comparisons"]["kisa/chunk_max"]
    assert block["verdict"] == comparison["primary"]["verdict"]
    assert block["verdict"] in ("hypothesis-confirmed", "hypothesis-rejected")
    assert block["ci95"]["low"] <= block["ci95"]["high"]
    manifest = read_json(CHUNKING_DIR / "manifest.json")
    assert list(manifest["runs"]) == ["kisa/chunk_max"]
    entry = manifest["runs"]["kisa/chunk_max"]
    assert entry["test"]["config_hash"] == harness.entry_hash("chunking", entry)
    assert entry["selected"]["selected_on"] == "dev"
    assert entry["selected"]["config"] in ch.grid("kisa", ch.VARIANT)
    assert [row["config"] for row in entry["grid"]["rows"]] == ch.grid("kisa", ch.VARIANT)
    by_config = entry["description"]["chunk_hit"]["by_config"]
    assert set(by_config) == {ch.config_label(c) for c in ch.grid("kisa", ch.VARIANT)}
    selected = ch.config_label(entry["selected"]["config"])
    assert all("dev" in report for report in by_config.values())
    assert [label for label, report in by_config.items() if "test" in report] == [selected]
    assert set(entry["description"]["public_records_with_2plus_chunks"]) == set(by_config)


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/chunking not committed yet")
def test_committed_files_have_only_allowed_fields_and_no_absolute_paths():
    rows = data.read_jsonl(CHUNKING_DIR / "kisa/chunk_max.jsonl")
    for row in rows:
        scoring.validate_record(row)
        assert all(not CHUNK_ID_RE.fullmatch(item["doc_id"]) for item in row["results"])
    assert sorted(p.relative_to(CHUNKING_DIR).as_posix() for p in CHUNKING_DIR.rglob("*")) == [
        "comparison.json",
        "kisa",
        "kisa/chunk_max.jsonl",
        "manifest.json",
        "metrics.json",
    ]
    text = "".join(p.read_text("utf-8") for p in CHUNKING_DIR.rglob("*") if p.is_file())
    assert "/Users" not in text
    for filename in ("manifest.json", "metrics.json", "comparison.json"):
        assert harness.find_absolute_paths(read_json(CHUNKING_DIR / filename)) == []
    for question in data.load_kisa_questions(ROOT):
        assert question.query not in text


@pytest.mark.skipif(not COMMITTED, reason="results/experiments/chunking not committed yet")
def test_committed_results_use_the_stored_baseline_and_the_report_matches_comparison():
    comparison = read_json(CHUNKING_DIR / "comparison.json")
    report = (ROOT / "docs/experiments/chunking.md").read_text("utf-8")
    block = comparison["comparisons"]["kisa/chunk_max"]
    assert block["verdict"] in report
    for value in (block["experiment_macro"], block["baseline_macro"]):
        assert f"{value:.4f}" in report, value
    assert f"{block['delta']:+.4f}" in report
    assert f"{block['ci95']['low']:+.4f}" in report
    assert f"{block['ci95']['high']:+.4f}" in report
    for item in block["degraded"]:
        assert item["question_id"] in report, item["question_id"]
    for item in block["improved_top10"]:
        assert item["question_id"] in report, item["question_id"]
    entry = read_json(CHUNKING_DIR / "manifest.json")["runs"]["kisa/chunk_max"]
    for label, observed in entry["description"]["chunk_hit"]["by_config"].items():
        assert label in report
        assert f"{observed['dev']['macro_hit@10']:.4f}" in report, label

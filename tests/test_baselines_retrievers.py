"""베이스라인 검색기 단위 테스트 - 토큰화, BM25, exact lookup, dense(모델을 내려받지 않는다).

합성 코퍼스만 쓴다. dense는 가짜 행렬로 점수 계약만 확인하고 `embed` 그룹 패키지를 import하지 않는다.
"""

import json
import math
import subprocess
import sys
from pathlib import Path

import pytest

from krsec_rag_lab.baselines import dense
from krsec_rag_lab.baselines.bm25 import BM25Index
from krsec_rag_lab.baselines.exact import ExactCveIndex
from krsec_rag_lab.baselines.tokens import tokenize

ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------ 토큰화 규칙 bm25-tok-v1


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # CVE ID: 하이픈 유지 단일 토큰, 대소문자 무시
        ("CVE-2026-70283", ["cve-2026-70283"]),
        ("cve-2026-70283", ["cve-2026-70283"]),
        ("CVE-2026-12345678", ["cve-2026-12345678"]),
        # 한글 조사가 붙어도 끝 경계를 찾는다(\b였다면 실패한다). 뒤따르는 한글은 따로 토큰화한다
        ("CVE-2026-12345를 설명", ["cve-2026-12345", "를", "설명"]),
        # 위첨자는 ASCII 숫자가 아니라 ID에 붙지 않는다(NFKC를 하지 않는다)
        ("CVE-2026-1234²", ["cve-2026-1234"]),
        # 앞에 영숫자가 붙거나 숫자가 4자리 미만이면 CVE ID가 아니다
        ("xcve-2026-1234", ["xcve", "2026", "1234"]),
        ("CVE-2026-123", ["cve", "2026", "123"]),
        # 전각 문자는 정규화하지 않으므로 ASCII 토큰이 아니다
        ("ＣＶＥ-2026-1234", ["2026", "1234"]),
        # 영문·숫자: 구분자는 _ : . - 공백 등, 어간·불용어 처리 없음
        ("windows_admin_center", ["windows", "admin", "center"]),
        ("h2database:h2", ["h2database", "h2"]),
        ("Apache Log4j 2.14.1", ["apache", "log4j", "2", "14", "1"]),
        ("man-in-the-middle", ["man", "in", "the", "middle"]),
        # 한글: 겹치는 문자 2-gram, 한 글자 연속열은 1-gram
        ("취약점", ["취약", "약점"]),
        ("서버", ["서버"]),
        ("가", ["가"]),
        ("한 글", ["한", "글"]),
        # 한영 혼합: 문자 종류가 바뀌면 끊는다
        ("서버Server", ["서버", "server"]),
        ("보안패치KB5034441적용", ["보안", "안패", "패치", "kb5034441", "적용"]),
        # 그 밖의 문자(문장부호, 한자, 이모지)는 버린다
        ("(취약점)!?", ["취약", "약점"]),
        ("漢字 emoji 🙂", ["emoji"]),
        ("", []),
    ],
)
def test_tokenize_rules(text, expected):
    assert tokenize(text) == expected


# ------------------------------------------------------------ BM25


def _bm25_reference(tf, dl, avgdl, df, n_docs, k1, b):
    idf = math.log(1.0 + (n_docs - df + 0.5) / (df + 0.5))
    return idf * tf * (k1 + 1.0) / (tf + k1 * (1.0 - b + b * dl / avgdl))


def test_bm25_matches_reference_formula():
    texts = {"d1": "alpha beta", "d2": "alpha", "d3": "gamma gamma gamma"}
    k1, b = 1.2, 0.75
    index = BM25Index(texts, k1=k1, b=b)
    avgdl = (2 + 1 + 3) / 3
    scores = index.score("beta alpha")
    expected_d1 = _bm25_reference(1, 2, avgdl, 1, 3, k1, b) + _bm25_reference(
        1, 2, avgdl, 2, 3, k1, b
    )
    expected_d2 = _bm25_reference(1, 1, avgdl, 2, 3, k1, b)
    assert scores["d1"] == pytest.approx(expected_d1, abs=1e-12)
    assert scores["d2"] == pytest.approx(expected_d2, abs=1e-12)
    assert "d3" not in scores  # 일치 토큰이 없는 문서는 검색되지 않는다


def test_bm25_no_match_is_empty_and_repeated_query_terms_fold():
    index = BM25Index({"d1": "alpha beta", "d2": "beta"})
    assert index.score("zzz") == {}
    assert index.score("") == {}
    assert index.score("alpha alpha alpha") == index.score("alpha")


def test_bm25_b_zero_ignores_length_and_b_one_penalizes_long_docs():
    texts = {"short": "alpha", "long": "alpha x1 x2 x3 x4 x5", "other": "beta"}
    flat = BM25Index(texts, b=0.0).score("alpha")
    assert flat["short"] == pytest.approx(flat["long"], abs=1e-12)
    normalized = BM25Index(texts, b=1.0).score("alpha")
    assert normalized["short"] > normalized["long"]


@pytest.mark.parametrize(("k1", "b"), [(-0.1, 0.5), (1.2, -0.1), (1.2, 1.1)])
def test_bm25_rejects_out_of_range_parameters(k1, b):
    with pytest.raises(ValueError, match="k1"):
        BM25Index({"d1": "alpha"}, k1=k1, b=b)


def test_bm25_cve_hyphen_kept_so_other_ids_do_not_match():
    texts = {
        "CVE-2026-0001": "CVE-2026-0001 buffer overflow in the router",
        "CVE-2026-0002": "CVE-2026-0002 buffer overflow in the camera",
    }
    scores = BM25Index(texts).score("CVE-2026-0001를 설명해 주세요")
    # 하이픈을 풀면 cve·2026이 두 문서에 공통이라 다른 문서가 걸린다
    assert set(scores) == {"CVE-2026-0001"}


def test_bm25_korean_particles_match_through_bigrams():
    texts = {
        "n1": "서버 취약점 패치 공지",
        "n2": "스미싱 문자 주의 안내",
    }
    scores = BM25Index(texts).score("취약점을 알려주세요")
    assert set(scores) == {"n1"}  # '취약', '약점' 2-gram이 일치. 조사 '을'은 어디에도 없다


# ------------------------------------------------------------ exact CVE lookup


@pytest.fixture
def exact_index():
    return ExactCveIndex(
        {
            "100": ["CVE-2026-0001", "CVE-2026-0002"],
            "200": ["CVE-2026-0002"],
            "300": [],
        }
    )


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("CVE-2026-0001 알려줘", {"100": 1.0}),
        ("cve-2026-0001를 인용한 공지", {"100": 1.0}),  # 소문자·한글 조사
        ("CVE-2026-0002는?", {"100": 1.0, "200": 1.0}),  # 두 공지가 인용
        ("CVE-2026-0001과 CVE-2026-0002 비교", {"100": 2.0, "200": 1.0}),  # 많이 맞는 문서가 앞선다
        ("CVE-2026-0001 CVE-2026-0001", {"100": 1.0}),  # 질의의 중복 ID는 한 번
        ("CVE-2026-9999", {}),  # 코퍼스에 없는 ID
        ("취약점 패치 공지", {}),  # CVE ID 없는 질의는 빈 결과
        ("CVE-2026-00019", {}),  # 다른 ID(숫자가 이어짐)
    ],
)
def test_exact_lookup(exact_index, query, expected):
    assert exact_index.score(query) == expected


def test_exact_index_rejects_malformed_key():
    with pytest.raises(ValueError, match="malformed"):
        ExactCveIndex({"d": ["not-a-cve"]})


# ------------------------------------------------------------ dense (모델 없이)


def test_dense_module_does_not_import_embed_packages():
    code = (
        "import sys\n"
        "import krsec_rag_lab.baselines.dense, krsec_rag_lab.baselines.runner\n"
        "import krsec_rag_lab.baselines.report\n"
        "banned = ('numpy', 'torch', 'sentence_transformers', 'transformers')\n"
        "loaded = [m for m in banned if m in sys.modules]\n"
        "assert not loaded, loaded\n"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_dense_representation_matches_embeddings_demo_manifest():
    manifest = json.loads(
        (ROOT / "fixtures/embeddings_demo/manifest.json").read_text(encoding="utf-8")
    )["model"]
    described = dense.model_description()
    for field in ("name", "revision", "pooling", "normalized", "dtype", "max_seq_length"):
        assert described[field] == manifest[field]
    assert described["revision"] == "5617a9f61b028005a4858fdac845db406aefb181"
    assert described["device"] == "cpu"


class _FakeVector:
    def __init__(self, values):
        self.values = values


class _FakeMatrix:
    """`matrix @ vector`와 `.tolist()`만 흉내 낸다(numpy 없이 DenseIndex.score 계약 확인)."""

    def __init__(self, rows):
        self.rows = rows

    def __matmul__(self, vector):
        sims = [sum(a * b for a, b in zip(row, vector.values, strict=True)) for row in self.rows]
        return type("Sims", (), {"tolist": lambda self_: sims})()


def test_dense_index_scores_every_document():
    index = dense.DenseIndex(
        doc_ids=["a", "b", "c"],
        matrix=_FakeMatrix([[1.0, 0.0], [0.0, 1.0], [0.6, 0.8]]),
        encode_query=lambda query: _FakeVector([0.6, 0.8]),
        meta={},
    )
    scores = index.score("아무 질의")
    assert list(scores) == ["a", "b", "c"]  # 코퍼스 전체에 점수를 매긴다
    assert scores == pytest.approx({"a": 0.6, "b": 0.8, "c": 1.0})


@pytest.mark.parametrize(
    ("lengths", "expected"), [([], 0), ([10, 8192], 0), ([8193], 1), ([8192, 8193, 20000], 2)]
)
def test_truncated_count_uses_max_seq_length(lengths, expected):
    assert dense.truncated_count(lengths) == expected

"""두 트랙의 질의·코퍼스 로더 - docs/eval-protocol.md 11절의 입력을 같은 형태로 맞춘다.

- 공개 트랙: 질의 eval/public/queries.jsonl, 코퍼스 fixtures/nvd/cves.jsonl (문서 ID = 레코드 `id`).
  색인 텍스트는 `id` + 공백 + `description_en`이다(CPE·CWE·CVSS는 색인하지 않는다).
- KISA 트랙: 질의 eval/golden/golden_v1.jsonl, 코퍼스 fixtures/kisa/manifest.json의 고정 공지 50건
  (문서 ID = `nttId`). 색인 텍스트는 `제목 + 줄바꿈 + 본문`이고 본문은 호출자가 넘기는 `load_body`로만
  읽는다(scripts/fetch_kisa.py의 `load_cached_body`). 본문은 이 모듈이 어디에도 쓰지 않는다.

질의 레코드는 `Question` 하나로 맞춘다. `excluded`는 채점·집계에서 빼는 질문이다(1절): KISA는 골든셋의
`excluded` 플래그, 공개 트랙은 정답이 있어야 하는 유형인데 `gold`가 빈 질문이다.
"""

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from krsec_rag_lab.splits import extract_cve_ids, normalize_cve_id

SPLITS = ("dev", "test")
QUERY_TYPES = ("cve_explicit", "product_symptom", "explanation_comparison", "no_answer")
TRACKS = ("public", "kisa")

PUBLIC_QUERIES = Path("eval/public/queries.jsonl")
PUBLIC_CORPUS = Path("fixtures/nvd/cves.jsonl")
KISA_GOLDEN = Path("eval/golden/golden_v1.jsonl")
KISA_MANIFEST = Path("fixtures/kisa/manifest.json")
KISA_METADATA = Path("fixtures/kisa/metadata.jsonl")

PUBLIC_INDEX_TEXT = "'{id} {description_en}' (레코드 id + 공백 + 영문 설명, CPE·CWE·CVSS 미색인)"
KISA_INDEX_TEXT = "'{title}\\n{body}' (공지 제목 + 줄바꿈 + 정규화 본문)"

BodyLoader = Callable[[str, Mapping[str, str]], str]


@dataclass(frozen=True)
class Question:
    question_id: str
    query: str
    query_type: str
    split: str
    gold: frozenset[str]
    unjudged: frozenset[str]
    excluded: bool


@dataclass(frozen=True)
class Corpus:
    texts: dict[str, str]  # 문서 ID -> 색인 텍스트 (순서는 입력 순서)
    exact_keys: dict[str, tuple[str, ...]]  # 문서 ID -> exact lookup 키(CVE ID)


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _check_question(question: Question, doc_ids: set[str] | None) -> None:
    if question.split not in SPLITS:
        raise ValueError(f"{question.question_id}: split must be one of {SPLITS}")
    if question.query_type not in QUERY_TYPES:
        raise ValueError(f"{question.question_id}: unknown query_type {question.query_type!r}")
    if question.gold & question.unjudged:
        raise ValueError(f"{question.question_id}: gold and unjudged overlap")
    if question.query_type == "no_answer" and question.gold:
        raise ValueError(f"{question.question_id}: no_answer must have empty gold")
    if doc_ids is not None and not (question.gold | question.unjudged) <= doc_ids:
        raise ValueError(f"{question.question_id}: gold/unjudged id not in corpus")


def check_questions(questions: list[Question], doc_ids: set[str]) -> None:
    """정답·unjudged ID가 모두 코퍼스 안에 있는지 확인한다(없으면 ValueError)."""
    for question in questions:
        _check_question(question, doc_ids)


def _check_unique(questions: list[Question]) -> list[Question]:
    ids = [question.question_id for question in questions]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate question ids")
    return questions


def load_public_questions(root: Path) -> list[Question]:
    questions = []
    for row in read_jsonl(root / PUBLIC_QUERIES):
        gold = frozenset(row["gold"])
        questions.append(
            Question(
                question_id=row["id"],
                query=row["query"],
                query_type=row["query_type"],
                split=row["split"],
                gold=gold,
                unjudged=frozenset(row["unjudged"]),
                excluded=row["query_type"] != "no_answer" and not gold,
            )
        )
    for question in questions:
        _check_question(question, None)
    return _check_unique(questions)


def load_public_corpus(root: Path) -> Corpus:
    texts: dict[str, str] = {}
    keys: dict[str, tuple[str, ...]] = {}
    for record in read_jsonl(root / PUBLIC_CORPUS):
        doc_id = normalize_cve_id(record["id"])
        if doc_id in texts:
            raise ValueError(f"duplicate corpus id {doc_id}")
        texts[doc_id] = f"{doc_id} {record['description_en']}"
        keys[doc_id] = (doc_id,)
    return Corpus(texts, keys)


def load_kisa_questions(root: Path) -> list[Question]:
    """골든셋 질문. 정답 = `answers[].doc_id`. 정답의 본문 해시가 고정 manifest와 같은지 확인한다."""
    manifest = json.loads((root / KISA_MANIFEST).read_text(encoding="utf-8"))
    sha_by_id = {doc["nttId"]: doc["sha256"] for doc in manifest["documents"]}
    questions = []
    for row in read_jsonl(root / KISA_GOLDEN):
        for answer in row["answers"]:
            if answer["doc_sha256"] != sha_by_id.get(answer["doc_id"]):
                raise ValueError(f"{row['question_id']}: answer doc_sha256 differs from manifest")
        questions.append(
            Question(
                question_id=row["question_id"],
                query=row["query"],
                query_type=row["query_type"],
                split=row["split"],
                gold=frozenset(answer["doc_id"] for answer in row["answers"]),
                unjudged=frozenset(row["unjudged"]),
                excluded=bool(row["excluded"]),
            )
        )
    doc_ids = set(sha_by_id)
    for question in questions:
        _check_question(question, doc_ids)
    return _check_unique(questions)


def load_kisa_corpus(root: Path, load_body: BodyLoader) -> Corpus:
    """고정 공지 전체를 `load_body(nttId, manifest 문서 항목)`로 읽는다. 누락·해시 불일치는 예외다."""
    manifest = json.loads((root / KISA_MANIFEST).read_text(encoding="utf-8"))
    titles = {str(row["nttId"]): row["title"] for row in read_jsonl(root / KISA_METADATA)}
    texts: dict[str, str] = {}
    keys: dict[str, tuple[str, ...]] = {}
    for document in manifest["documents"]:
        ntt_id = document["nttId"]
        title = titles[ntt_id]
        body = load_body(ntt_id, document)
        texts[ntt_id] = f"{title}\n{body}"
        keys[ntt_id] = tuple(extract_cve_ids(f"{title}\n{body}"))
    return Corpus(texts, keys)


def load_questions(track: str, root: Path) -> list[Question]:
    if track == "public":
        return load_public_questions(root)
    if track == "kisa":
        return load_kisa_questions(root)
    raise ValueError(f"unknown track {track!r}")


def input_fingerprints(track: str, root: Path) -> dict[str, dict[str, str]]:
    """결과가 기대는 입력 파일의 리포 상대 경로와 sha256 (manifest용)."""
    if track == "public":
        paths = {"queries": PUBLIC_QUERIES, "corpus": PUBLIC_CORPUS}
    else:
        paths = {
            "queries": KISA_GOLDEN,
            "corpus_manifest": KISA_MANIFEST,
            "corpus_metadata": KISA_METADATA,
        }
    return {
        name: {"path": path.as_posix(), "sha256": file_sha256(root / path)}
        for name, path in paths.items()
    }

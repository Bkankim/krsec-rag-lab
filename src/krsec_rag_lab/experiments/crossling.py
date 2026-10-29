"""한영 교차 실험 `crossling` - 공개 트랙의 한국어 질문을 로컬 모델로 영어로 번역(KO->EN)해 검색한다.

가설(사전 등록, test 실행 전에 고정): 공개 트랙의 한국어 질문을 로컬 번역 모델로 영어로 바꿔 BM25로
검색하면, 원래 한국어 질문의 BM25보다 test macro nDCG@10이 높다. 주 판정은 BM25(기준 =
results/baselines/public/bm25.jsonl)이고, 같은 번역을 bge-m3 dense에 넣은 변형은 기준 dense.jsonl과
비교하는 보조 판정이다. KISA 트랙은 질문과 문서가 모두 한국어라 대상이 아니다.

바꾸는 요소는 질의 쪽 언어 하나다. 문서(NVD 영문 설명)와 색인 텍스트, BM25 k1·b·`bm25-tok-v1` 토큰화,
dense 모델은 기준선과 같다. 번역 모델은 `Helsinki-NLP/opus-mt-ko-en`(Marian, revision 고정)이고 디코딩은
결정적이다(beam 4, 샘플링 없음, 질문 하나씩 처리).

번역문은 커밋된 `results/experiments/crossling/translations.jsonl`에서 읽는다(`--out-dir`과 무관). 이
파일의 sha256이 `reproduction_inputs`로 manifest와 test 설정 해시에 들어가므로 번역문만 바꾼 뒤 test를
다시 돌리면 `LockError`다. 검색(`setup`·`make_scorer`)과 `--compare`는 번역 모델 없이 돈다. 번역 파일을
만드는 `translate_questions`와 `python -m krsec_rag_lab.experiments.crossling`은 transformers·torch를 함수
안에서만 읽는다(`embed` 그룹).
"""

import argparse
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from krsec_rag_lab.baselines import data, dense
from krsec_rag_lab.baselines.bm25 import BM25Index
from krsec_rag_lab.baselines.tokens import TOKENIZER_ID
from krsec_rag_lab.experiments import ContractError
from krsec_rag_lab.experiments.harness import Context
from krsec_rag_lab.splits import extract_cve_ids

NAME = "crossling"
HYPOTHESIS = (
    "공개 트랙의 한국어 질문을 로컬 번역 모델로 영어로 바꿔(KO->EN) BM25로 검색하면, "
    "원래 한국어 질문의 BM25보다 test macro nDCG@10이 높다."
)
BM25_VARIANT = "bm25_ko2en"
DENSE_VARIANT = "dense_ko2en"
PRIMARY = ("public", BM25_VARIANT)
VARIANTS = {"public": (BM25_VARIANT, DENSE_VARIANT)}
BASELINES = {"public": {BM25_VARIANT: "bm25", DENSE_VARIANT: "dense"}}

TRANSLATIONS_PATH = "results/experiments/crossling/translations.jsonl"
TRANSLATION_FIELDS = frozenset({"question_id", "translation", "source_sha256", "model", "revision"})

MODEL_NAME = "Helsinki-NLP/opus-mt-ko-en"
MODEL_REVISION = "e42d1f41b66194e6d10512f8a27bebc1f4f5097e"
DECODING = {
    "num_beams": 4,
    "do_sample": False,
    "max_new_tokens": 256,
    "length_penalty": 1.0,
    "batch_size": 1,
    "device": "cpu",
    "dtype": "float32",
    "seed": 0,
}
TRANSLATION_DESCRIPTION = {
    "direction": "KO->EN, 질의 쪽만(문서·색인 텍스트는 바꾸지 않는다)",
    "model": MODEL_NAME,
    "revision": MODEL_REVISION,
    "decoding": DECODING,
    "input": "질문의 query 문자열 그대로(전처리·CVE ID 보정 없음)",
    "file": TRANSLATIONS_PATH,
}


def grid(track: str, variant: str) -> list[dict]:
    """고를 설정이 없다. dev는 기권 τ만 고른다(기준선과 같은 규칙, 하네스가 처리)."""
    return [{}]


def reproduction_inputs(track: str, variant: str) -> dict[str, str]:
    return {"translations": TRANSLATIONS_PATH}


def _baseline_bm25(baselines_manifest: Mapping) -> Mapping:
    entry = baselines_manifest["runs"][f"public/{BASELINES['public'][BM25_VARIANT]}"]
    tokenizer = entry["config"]["tokenizer"]["id"]
    if tokenizer != TOKENIZER_ID:
        raise ContractError(f"baseline tokenizer {tokenizer!r} != {TOKENIZER_ID!r}")
    return entry["selected"]


def fixed_config(track: str, variant: str, baselines_manifest: Mapping) -> dict:
    """test 잠금 해시에 들어가는 고정 설정: 번역 모델·디코딩과 검색기(기준선에서 가져온 BM25 k1·b, dense 모델)."""
    fixed: dict = {"translation": TRANSLATION_DESCRIPTION}
    if variant == BM25_VARIANT:
        selected = _baseline_bm25(baselines_manifest)
        fixed["bm25"] = {"k1": selected["k1"], "b": selected["b"], "tokenizer": TOKENIZER_ID}
    else:
        fixed["dense"] = {"name": dense.MODEL_NAME, "revision": dense.MODEL_REVISION}
    return fixed


# ------------------------------------------------------------ 번역 파일


def source_sha256(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()


def load_translations(path: Path, questions: Sequence[data.Question]) -> dict[str, str]:
    """번역 파일을 읽어 질문 ID -> 번역문으로 돌려준다. 어긋나는 것이 하나라도 있으면 ContractError.

    파일은 `questions` 전부(제외 질문 포함)의 번역을 정확히 한 번씩 가져야 하고(빠짐·중복·초과 불가), 행마다
    허용 필드만 있고, 번역 모델·revision이 이 모듈의 상수와 같고, `source_sha256`이 지금 질문 문장의
    sha256과 같아야 한다(질의셋이 바뀐 뒤의 낡은 번역을 막는다).
    """
    if not path.exists():
        raise ContractError(f"translations file missing: {TRANSLATIONS_PATH}")
    rows = data.read_jsonl(path)
    translations: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != TRANSLATION_FIELDS:
            found = sorted(row) if isinstance(row, dict) else type(row).__name__
            raise ContractError(
                f"translations row has fields {found}, expected {sorted(TRANSLATION_FIELDS)}"
            )
        qid = row["question_id"]
        if not isinstance(qid, str):
            raise ContractError(f"translations: question_id must be a string, got {qid!r}")
        if qid in translations:
            raise ContractError(f"translations: duplicate question id {qid}")
        if (row["model"], row["revision"]) != (MODEL_NAME, MODEL_REVISION):
            raise ContractError(f"translations: {qid} was made by another model or revision")
        text = row["translation"]
        if not isinstance(text, str) or not text.strip():
            raise ContractError(f"translations: {qid} has an empty translation")
        translations[qid] = text
    by_id = {question.question_id: question for question in questions}
    missing = sorted(set(by_id) - set(translations))
    if missing:
        raise ContractError(f"translations missing for {len(missing)} question(s): {missing[:5]}")
    extra = sorted(set(translations) - set(by_id))
    if extra:
        raise ContractError(f"translations for unknown question(s): {extra[:5]}")
    stale = sorted(
        row["question_id"]
        for row in rows
        if row["source_sha256"] != source_sha256(by_id[row["question_id"]].query)
    )
    if stale:
        raise ContractError(f"translations are stale for {len(stale)} question(s): {stale[:5]}")
    return translations


def cve_preservation(
    questions: Sequence[data.Question], translations: Mapping[str, str]
) -> dict[str, dict]:
    """번역이 질문의 CVE ID 집합을 바꿨는지 센다(`splits.extract_cve_ids` 집합이 번역 뒤에도 같은가).

    채점 대상(제외되지 않은) 질문만 센다. `all`과 분할(dev, test)별로 돌려준다. `changed`는 집합이 달라진
    질문, `lost`는 원문의 ID가 번역문에서 빠진 질문, `added`는 번역문에 원문에 없는 ID가 생긴 질문이다.
    """
    result: dict[str, dict] = {}
    scored = [question for question in questions if not question.excluded]
    for label, subset in (
        ("all", scored),
        *((split, [q for q in scored if q.split == split]) for split in data.SPLITS),
    ):
        with_cve = changed = lost = added = 0
        changed_ids: list[str] = []
        for question in subset:
            before = set(extract_cve_ids(question.query))
            after = set(extract_cve_ids(translations[question.question_id]))
            with_cve += bool(before)
            if before != after:
                changed += 1
                changed_ids.append(question.question_id)
            lost += bool(before - after)
            added += bool(after - before)
        result[label] = {
            "n_questions": len(subset),
            "n_with_cve_id": with_cve,
            "n_changed": changed,
            "n_lost": lost,
            "n_added": added,
            "changed_question_ids": sorted(changed_ids),
        }
    return result


# ------------------------------------------------------------ 검색


@dataclass
class State:
    variant: str
    translations: dict[str, str]
    bm25: BM25Index | None
    dense: object | None
    cve: dict[str, dict]


def setup(ctx: Context) -> State:
    """번역 파일을 읽고 변형의 검색기를 만든다(BM25는 모델 없이, dense는 `dense_factory`로 모델 필요)."""
    translations = load_translations(ctx.root / TRANSLATIONS_PATH, ctx.questions)
    cve = cve_preservation(ctx.questions, translations)
    if ctx.variant == BM25_VARIANT:
        params = _baseline_bm25(ctx.baselines_manifest)
        return State(
            ctx.variant,
            translations,
            BM25Index(ctx.corpus.texts, k1=params["k1"], b=params["b"]),
            None,
            cve,
        )
    return State(ctx.variant, translations, None, ctx.dense_factory(ctx.corpus.texts), cve)


def make_scorer(state: State, config: Mapping) -> Callable[[data.Question], dict[str, float]]:
    index = state.bm25 if state.bm25 is not None else state.dense

    def score(question: data.Question) -> dict[str, float]:
        return index.score(state.translations[question.question_id])

    return score


def describe(state: State, config: Mapping) -> dict:
    description: dict = {
        "translation": TRANSLATION_DESCRIPTION,
        "cve_id_preservation": state.cve,
    }
    if state.bm25 is not None:
        description["bm25"] = {
            "k1": state.bm25.k1,
            "b": state.bm25.b,
            "tokenizer": TOKENIZER_ID,
            "candidates": "번역문 토큰이 하나라도 든 문서만 순위에 든다(일치가 없으면 빈 순위)",
        }
    else:
        meta = state.dense.meta
        description["dense"] = {
            "model": meta["model"],
            "runtime": meta["runtime"],
            "doc_encode_seconds": meta["doc_encode_seconds"],
            "candidates": "코퍼스 전체",
        }
    return description


# ------------------------------------------------------------ 번역 파일 만들기(embed 그룹, 모델 필요)


def translate_questions(questions: Sequence[data.Question]) -> list[dict]:
    """질문마다 KO->EN 번역을 만든다. 결정적 디코딩(beam 4, 샘플링 없음)이고 질문을 하나씩 처리한다.

    transformers·torch는 `embed` 그룹이라 이 함수 안에서만 읽는다. 가중치는 revision을 고정해 받는다.
    """
    import torch
    from transformers import MarianMTModel, MarianTokenizer

    torch.manual_seed(DECODING["seed"])
    tokenizer = MarianTokenizer.from_pretrained(MODEL_NAME, revision=MODEL_REVISION)
    model = MarianMTModel.from_pretrained(MODEL_NAME, revision=MODEL_REVISION)
    model.eval()
    rows = []
    for question in sorted(questions, key=lambda q: q.question_id):
        batch = tokenizer([question.query], return_tensors="pt")
        with torch.inference_mode():
            generated = model.generate(
                **batch,
                num_beams=DECODING["num_beams"],
                do_sample=DECODING["do_sample"],
                max_new_tokens=DECODING["max_new_tokens"],
                length_penalty=DECODING["length_penalty"],
            )
        text = tokenizer.batch_decode(generated, skip_special_tokens=True)[0].strip()
        rows.append(
            {
                "question_id": question.question_id,
                "translation": text,
                "source_sha256": source_sha256(question.query),
                "model": MODEL_NAME,
                "revision": MODEL_REVISION,
            }
        )
    return rows


def write_translations(path: Path, rows: Sequence[Mapping]) -> None:
    lines = [json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(
        description="공개 트랙 질문 전체를 KO->EN으로 번역해 저장한다."
    )
    parser.add_argument("--root", type=Path, default=root, help="리포 루트(기본: 이 체크아웃)")
    args = parser.parse_args(argv)
    questions = data.load_public_questions(args.root)
    rows = translate_questions(questions)
    write_translations(args.root / TRANSLATIONS_PATH, rows)
    print(f"wrote {len(rows)} translations to {TRANSLATIONS_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

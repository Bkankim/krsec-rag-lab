"""베이스라인 실행 - 설정은 dev에서만 고르고(BM25 k1·b, 기권 τ) test는 확정한 설정으로 한 번 돈다.

`run_baseline`은 한 (트랙, 검색기) 조합을 실행해 세 파일을 갱신한다.

- `<out>/<track>/<retriever>.jsonl`: 질문별 원시 결과(scoring.RECORD_FIELDS만, dev+test 한 파일)
- `<out>/manifest.json`: 실행 메타데이터(시각, 모델, 설정, 선택한 τ·k1·b, 입력 해시, 소요 시간, 환경)
- `<out>/metrics.json`: 위 jsonl과 질의셋 라벨만으로 다시 계산한 트랙 x 검색기 x 분할 x 유형 지표

분할 인자: `dev`는 설정을 고르고 dev 결과를 쓴다(이전 test 결과는 설정이 바뀔 수 있어 지운다), `test`는
manifest에 확정된 설정으로 test만 돈다(설정 선택 없음), `all`은 dev 선택 뒤 test까지 돈다.
KISA 트랙의 본문은 호출자가 넘기는 `load_body`로만 읽고 어떤 출력에도 쓰지 않는다.
"""

import json
import os
import platform
import statistics
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from krsec_rag_lab.baselines import data, scoring
from krsec_rag_lab.baselines.bm25 import DEFAULT_B, DEFAULT_K1, BM25Index
from krsec_rag_lab.baselines.dense import build_dense_index
from krsec_rag_lab.baselines.exact import ExactCveIndex
from krsec_rag_lab.baselines.tokens import TOKENIZER_ID, TOKENIZER_RULES

RETRIEVERS = ("exact", "bm25", "dense")
RESULTS_DIR = Path("results/baselines")
BM25_GRID_K1 = (0.9, 1.2, 1.5, 2.0, 3.0)
BM25_GRID_B = (0.3, 0.5, 0.75, 0.9, 1.0)

ScoreFn = Callable[[str], dict[str, float]]


@dataclass
class Scorer:
    score: ScoreFn
    index_seconds: float
    config: dict
    params: dict


def _timed(build: Callable[[], object]) -> tuple[object, float]:
    started = time.perf_counter()
    built = build()
    return built, time.perf_counter() - started


def score_questions(
    scorer: ScoreFn, questions: Sequence[data.Question]
) -> tuple[dict[str, dict], list[float]]:
    """채점 대상 질문마다 결과 레코드를 만들고 질문당 소요 시간(점수 계산 + 정렬)을 잰다."""
    records: dict[str, dict] = {}
    latencies: list[float] = []
    for question in questions:
        started = time.perf_counter()
        scores = scorer(question.query)
        record = scoring.make_record(question.question_id, scores, question.unjudged)
        latencies.append(time.perf_counter() - started)
        scoring.validate_record(record)
        records[question.question_id] = record
    return records, latencies


def _top1(records: Mapping[str, Mapping], questions: Sequence[data.Question]):
    no_answer = [records[q.question_id]["top1_score_raw"] for q in questions if not q.gold]
    answerable = [records[q.question_id]["top1_score_raw"] for q in questions if q.gold]
    return no_answer, answerable


def _build_fixed(retriever: str, corpus: data.Corpus, dense_factory) -> Scorer:
    """매개변수가 없는 검색기(exact, dense)의 점수 함수."""
    if retriever == "exact":
        index, seconds = _timed(lambda: ExactCveIndex(corpus.exact_keys))
        assert isinstance(index, ExactCveIndex)
        config = {
            "index": "CVE ID -> 문서 ID 역색인",
            "keys": "공개 트랙은 레코드 id, KISA 트랙은 제목+본문에서 splits.extract_cve_ids로 뽑은 ID",
            "score": "질의의 서로 다른 CVE ID 중 문서가 키로 가진 개수",
            "n_keys": index.n_keys,
            "candidates": "CVE ID가 일치한 문서만 반환(없으면 빈 결과)",
        }
        return Scorer(index.score, seconds, config, {})
    dense = dense_factory(corpus.texts)
    meta = dense.meta
    config = {
        "model": meta["model"],
        "runtime": meta["runtime"],
        "score": "정규화 벡터 내적(= 코사인), 코퍼스 전체에 점수를 매김(전수 검색)",
        "candidates": "코퍼스 전체",
    }
    return Scorer(dense.score, meta["doc_encode_seconds"], config, {})


def _bm25_config(grid_rows: list[dict], chosen: dict) -> dict:
    return {
        "tokenizer": {"id": TOKENIZER_ID, "rules": TOKENIZER_RULES},
        "formula": "Okapi BM25, idf = ln(1 + (N - df + 0.5) / (df + 0.5)), 질의 토큰 중복은 접음",
        "candidates": "질의 토큰이 하나라도 든 문서만 반환(일치가 없으면 빈 결과)",
        "defaults": {"k1": DEFAULT_K1, "b": DEFAULT_B},
        "grid": {"k1": list(BM25_GRID_K1), "b": list(BM25_GRID_B), "rows": grid_rows},
        "selection": (
            "dev의 macro nDCG@10(condensed, 정답이 있는 유형의 단순 평균) 최대, 같으면 기본값"
            "(k1=1.2, b=0.75)을 먼저, 그다음 격자 순서(k1 오름차순, b 오름차순)에서 앞선 쪽"
        ),
        "selected": chosen,
    }


def select_on_dev(
    retriever: str, corpus: data.Corpus, dev: Sequence[data.Question], dense_factory
) -> tuple[Scorer, dict[str, dict], list[float], dict]:
    """dev에서 설정(BM25 k1·b)과 τ를 고른다. (점수 함수, dev 레코드, dev 질의 시간, τ 선택 정보)."""
    if retriever == "bm25":
        best = None
        grid_rows = []
        default = (DEFAULT_K1, DEFAULT_B)
        points = sorted(
            ((k1, b) for k1 in BM25_GRID_K1 for b in BM25_GRID_B), key=lambda p: (p != default,)
        )
        for k1, b in points:
            index, seconds = _timed(lambda k1=k1, b=b: BM25Index(corpus.texts, k1=k1, b=b))
            assert isinstance(index, BM25Index)
            records, latencies = score_questions(index.score, dev)
            macro = scoring.evaluate_split(records, dev, "dev", None)["macro"]["ndcg@10"]
            grid_rows.append({"k1": k1, "b": b, "dev_macro_ndcg@10": macro})
            if best is None or macro > best[0]:
                best = (macro, k1, b, index, seconds, records, latencies)
        assert best is not None
        macro, k1, b, index, seconds, records, latencies = best
        chosen = {"k1": k1, "b": b, "dev_macro_ndcg@10": macro}
        scorer = Scorer(index.score, seconds, _bm25_config(grid_rows, chosen), {"k1": k1, "b": b})
    else:
        scorer = _build_fixed(retriever, corpus, dense_factory)
        records, latencies = score_questions(scorer.score, dev)
    no_answer, answerable = _top1(records, dev)
    return scorer, records, latencies, scoring.select_tau(no_answer, answerable)


def scorer_from_manifest(
    retriever: str, corpus: data.Corpus, entry: Mapping, dense_factory
) -> Scorer:
    """`--split test` 전용: manifest에 확정된 설정으로 점수 함수를 다시 만든다."""
    if retriever == "bm25":
        params = {"k1": entry["selected"]["k1"], "b": entry["selected"]["b"]}
        index, seconds = _timed(lambda: BM25Index(corpus.texts, **params))
        assert isinstance(index, BM25Index)
        return Scorer(index.score, seconds, entry["config"], params)
    scorer = _build_fixed(retriever, corpus, dense_factory)
    return scorer


def _read_json(path: Path, default: dict) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else default


def _write_json(path: Path, payload: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    path.write_text(text + "\n", encoding="utf-8")


def read_results(path: Path) -> dict[str, dict]:
    records = {}
    for record in data.read_jsonl(path):
        scoring.validate_record(record)
        records[record["question_id"]] = record
    return records


def write_results(path: Path, records: Mapping[str, Mapping], order: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(records[qid], ensure_ascii=False, sort_keys=True) for qid in order]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def compute_run_metrics(track: str, retriever: str, root: Path, out_dir: Path) -> dict:
    """저장된 jsonl + 질의셋 라벨 + manifest의 τ만으로 분할별 지표를 계산한다."""
    key = f"{track}/{retriever}"
    entry = _read_json(root / out_dir / "manifest.json", {"runs": {}})["runs"][key]
    questions = data.load_questions(track, root)
    records = read_results(root / out_dir / track / f"{retriever}.jsonl")
    tau = entry["selected"]["tau"]
    metrics = {}
    for split in data.SPLITS:
        split_questions = [q for q in questions if q.split == split and not q.excluded]
        if split_questions and all(q.question_id in records for q in split_questions):
            metrics[split] = scoring.evaluate_split(records, questions, split, tau)
    return metrics


def _cpu_name() -> str:
    if platform.system() == "Darwin":
        try:
            out = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
                check=True,
            )
            return out.stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            pass
    return platform.processor() or platform.machine()


def environment() -> dict:
    """측정 환경(호스트 이름·사용자·경로는 적지 않는다)."""
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu": _cpu_name(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
    }


def run_baseline(
    track: str,
    retriever: str,
    root: Path,
    split: str = "all",
    out_dir: Path = RESULTS_DIR,
    load_body: data.BodyLoader | None = None,
    dense_factory: Callable[..., object] = build_dense_index,
) -> dict:
    """한 (트랙, 검색기)를 실행하고 결과·manifest·metrics를 쓴다. 이 조합의 지표 딕셔너리를 돌려준다."""
    if (
        track not in data.TRACKS
        or retriever not in RETRIEVERS
        or split not in (*data.SPLITS, "all")
    ):
        raise ValueError(f"bad arguments: track={track!r} retriever={retriever!r} split={split!r}")
    run_dev = split in ("dev", "all")
    run_test = split in ("test", "all")
    key = f"{track}/{retriever}"
    manifest_path = root / out_dir / "manifest.json"
    manifest = _read_json(manifest_path, {"runs": {}})
    previous = manifest["runs"].get(key)
    if not run_dev and previous is None:
        raise ValueError(f"{key}: --split test needs a dev-selected config; run --split dev first")

    questions = data.load_questions(track, root)
    if track == "public":
        corpus = data.load_public_corpus(root)
    else:
        if load_body is None:
            raise ValueError("kisa track needs load_body (--kisa-root)")
        corpus = data.load_kisa_corpus(root, load_body)
    data.check_questions(questions, set(corpus.texts))
    scored = [q for q in questions if not q.excluded]
    dev = [q for q in scored if q.split == "dev"]
    test = [q for q in scored if q.split == "test"]

    results_path = root / out_dir / track / f"{retriever}.jsonl"
    records: dict[str, dict] = {}
    timed: list[float] = []
    if run_dev:
        scorer, dev_records, dev_latencies, tau_info = select_on_dev(
            retriever, corpus, dev, dense_factory
        )
        records.update(dev_records)
        timed += dev_latencies
        selected = {"selected_on": "dev", "tau": tau_info["tau"], "tau_selection": tau_info}
        selected.update(scorer.params)
        if retriever == "bm25":
            selected["dev_macro_ndcg@10"] = scorer.config["selected"]["dev_macro_ndcg@10"]
        config = scorer.config
    else:
        assert previous is not None
        scorer = scorer_from_manifest(retriever, corpus, previous, dense_factory)
        records.update({q: r for q, r in read_results(results_path).items() if q in _ids(dev)})
        selected, config = previous["selected"], previous["config"]
    if run_test:
        test_records, test_latencies = score_questions(scorer.score, test)
        records.update(test_records)
        timed += test_latencies

    order = [q.question_id for q in scored if q.question_id in records]
    write_results(results_path, records, order)

    entry = {
        "track": track,
        "retriever": retriever,
        "protocol_version": scoring.PROTOCOL_VERSION,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "splits_stored": [
            s for s in data.SPLITS if any(q.split == s and q.question_id in records for q in scored)
        ],
        "inputs": data.input_fingerprints(track, root),
        "n_documents": len(corpus.texts),
        "index_text": data.PUBLIC_INDEX_TEXT if track == "public" else data.KISA_INDEX_TEXT,
        "stored_results": {
            "path": (out_dir / track / f"{retriever}.jsonl").as_posix(),
            "top_n": scoring.RESULT_TOP_N,
            "fields": sorted(scoring.RECORD_FIELDS),
            "result_fields": sorted(scoring.RESULT_FIELDS),
            "ranking": "(점수 내림차순, 문서 ID 오름차순) 정렬 뒤 질문의 unjudged를 지운 condensed list",
        },
        "config": config,
        "selected": selected,
        "timing": {
            "index_seconds": scorer.index_seconds,
            "query_latency_median_seconds": statistics.median(timed) if timed else None,
            "n_queries_timed": len(timed),
        },
        "environment": environment(),
    }
    manifest["protocol_version"] = scoring.PROTOCOL_VERSION
    manifest["runs"][key] = entry
    _write_json(manifest_path, manifest)

    metrics_path = root / out_dir / "metrics.json"
    all_metrics = _read_json(metrics_path, {"runs": {}})
    run_metrics = compute_run_metrics(track, retriever, root, out_dir)
    all_metrics["protocol_version"] = scoring.PROTOCOL_VERSION
    all_metrics["runs"][key] = run_metrics
    _write_json(metrics_path, all_metrics)
    return run_metrics


def _ids(questions: Sequence[data.Question]) -> set[str]:
    return {q.question_id for q in questions}

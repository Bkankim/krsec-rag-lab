"""실험 대 기준선 비교와 판정 - 스펙 #43 "실험 공통 규칙"의 구현. 표준 라이브러리만 쓴다.

순서: (1) 비교 전 필수 검사(`check_comparable`) -> (2) 질문별 paired delta -> (3) 유형별 층화 paired
bootstrap -> (4) 판정(`decide`) -> (5) 유형별·보조 지표 delta, 악화·개선 질문 목록.

계산식(고정):
- 질문별 delta = 실험 nDCG@10 - 기준 nDCG@10. 대상 = test의 비제외, 정답이 있는 질문.
- 유형은 `QUERY_TYPES` 순서로, 유형 안의 질문은 `question_id` 오름차순으로 놓는다.
- `random.Random(SEED)` 하나를 반복 전에 한 번만 만들어 모든 반복·유형이 공유한다. 매 회 유형 순서대로
  n_t개를 `randrange(n_t)`로 복원추출해 유형 평균을 내고, 유형 평균의 단순 평균(macro)이 그 회의 값이다.
- RESAMPLES회 값을 정렬해 하한 = `vals[int(0.025*B)]`, 상한 = `vals[int(0.975*B) - 1]`.
- 판정: delta > 0 이고 하한 > 0 이면 `hypothesis-confirmed`, 그 밖은 `hypothesis-rejected`.

결과 파일에는 질문 ID·유형·순위·점수만 있다. 질문 문장과 문서 본문은 이 모듈이 읽지도 쓰지도 않는다.
"""

import json
import random
from collections.abc import Collection, Mapping, Sequence
from pathlib import Path

from krsec_rag_lab.baselines import data, scoring
from krsec_rag_lab.experiments import ComparisonError

SEED = 20261029
RESAMPLES = 10000
LOWER_Q = 0.025
UPPER_Q = 0.975
METRIC = "ndcg@10"
CONFIRMED = "hypothesis-confirmed"
REJECTED = "hypothesis-rejected"
IMPROVED_LIMIT = 10
TOLERANCE = 1e-9  # --compare가 저장된 값과 다시 계산한 값을 비교하는 절대 허용오차


# ------------------------------------------------------------ 저장본 읽기와 비교 전 검사


def read_stored(path: Path) -> dict[str, dict]:
    """저장된 결과 jsonl을 질문 ID로 읽는다. 허용 필드 밖의 키·순서 위반·중복 질문 ID는 실패다."""
    if not path.exists():
        raise ComparisonError(f"stored results missing: {path.name}")
    records: dict[str, dict] = {}
    for record in data.read_jsonl(path):
        try:
            scoring.validate_record(record)
        except ValueError as error:
            raise ComparisonError(f"{path.name}: {error}") from error
        question_id = record["question_id"]
        if question_id in records:
            raise ComparisonError(f"{path.name}: duplicate question id {question_id}")
        records[question_id] = record
    return records


def scored_ids(questions: Sequence[data.Question], split: str | None = None) -> set[str]:
    return {
        q.question_id for q in questions if not q.excluded and (split is None or q.split == split)
    }


def check_known(
    label: str, records: Mapping[str, Mapping], questions: Sequence[data.Question]
) -> None:
    """저장본의 질문 ID는 모두 질의셋의 비제외 질문이어야 한다(excluded·모르는 ID 거부)."""
    unknown = sorted(set(records) - scored_ids(questions))
    if unknown:
        raise ComparisonError(f"{label}: unknown question id(s) {unknown[:5]}")


def check_records(
    label: str, records: Mapping[str, Mapping], questions: Sequence[data.Question]
) -> None:
    """저장본에 비제외 test 질문이 빠짐없이 있고, 질의셋에 없는 질문 ID가 없어야 한다."""
    expected_test = scored_ids(questions, "test")
    missing = sorted(expected_test - set(records))
    if missing:
        raise ComparisonError(f"{label}: missing {len(missing)} test question(s): {missing[:5]}")
    check_known(label, records, questions)


def check_comparable(
    *,
    exp_entry: Mapping,
    base_entry: Mapping,
    current_inputs: Mapping,
    questions: Sequence[data.Question],
    exp_records: Mapping[str, Mapping] | None,
    base_records: Mapping[str, Mapping],
) -> None:
    """비교 전 필수 검사. 하나라도 어긋나면 비교는 실패한다(교집합으로 줄이지 않는다).

    실험의 protocol_version, 질의셋·코퍼스 입력 해시(실험, 기준, 지금 리포의 입력 파일 셋 모두 일치),
    양쪽 저장본의 비제외 test 질문 ID(빠짐·중복·초과 없음). `exp_records`가 None이면 기준선 쪽만 본다
    (실행 직전 점검).
    """
    if exp_entry["protocol_version"] != base_entry["protocol_version"]:
        raise ComparisonError(
            f"protocol_version differs: experiment {exp_entry['protocol_version']!r} vs "
            f"baseline {base_entry['protocol_version']!r}"
        )
    if exp_entry["protocol_version"] != scoring.PROTOCOL_VERSION:
        raise ComparisonError(
            f"protocol_version {exp_entry['protocol_version']!r} != {scoring.PROTOCOL_VERSION!r}"
        )
    for label, inputs in (("experiment", exp_entry["inputs"]), ("baseline", base_entry["inputs"])):
        if inputs != current_inputs:
            raise ComparisonError(f"{label} input hashes differ from the current input files")
    check_records("baseline", base_records, questions)
    if exp_records is not None:
        check_records("experiment", exp_records, questions)


def check_baseline_entry(base_manifest: Mapping, track: str, baseline: str) -> Mapping:
    """기준선 manifest의 한 항목. 없거나 protocol_version이 다르면 ComparisonError."""
    entry = base_manifest.get("runs", {}).get(f"{track}/{baseline}")
    if entry is None:
        raise ComparisonError(
            f"baseline {track}/{baseline} missing from results/baselines manifest"
        )
    if base_manifest.get("protocol_version") != entry.get("protocol_version"):
        raise ComparisonError("baseline manifest protocol_version differs from its run entry")
    return entry


# ------------------------------------------------------------ bootstrap과 판정


def bootstrap_macro_delta(
    delta_by_type: Mapping[str, Mapping[str, float]],
    resamples: int = RESAMPLES,
    seed: int = SEED,
) -> dict:
    """유형별 층화 paired bootstrap의 macro delta 95% 구간. 모듈 docstring의 계산식 그대로다.

    `delta_by_type[유형][질문 ID]` = 질문별 delta. 질문이 없는 유형은 건너뛴다(macro 분모에서 빠짐).
    """
    unknown = set(delta_by_type) - set(data.QUERY_TYPES)
    if unknown:
        raise ValueError(f"unknown query types {sorted(unknown)}")
    groups = [
        [deltas[question_id] for question_id in sorted(deltas)]
        for query_type in data.QUERY_TYPES
        if (deltas := delta_by_type.get(query_type))
    ]
    if not groups:
        raise ValueError("bootstrap needs at least one scored question")
    rng = random.Random(seed)
    values = []
    for _ in range(resamples):
        means = []
        for group in groups:
            n = len(group)
            means.append(sum(group[rng.randrange(n)] for _ in range(n)) / n)
        values.append(sum(means) / len(means))
    values.sort()
    return {
        "low": values[int(LOWER_Q * resamples)],
        "high": values[int(UPPER_Q * resamples) - 1],
        "resamples": resamples,
        "seed": seed,
    }


def decide(delta: float, low: float) -> str:
    """delta > 0 이고 구간 하한 > 0 이면 confirmed, 그 밖(하한이 0 이하 포함)은 rejected."""
    return CONFIRMED if delta > 0 and low > 0 else REJECTED


# ------------------------------------------------------------ 한 실행의 비교


def first_gold_rank(record: Mapping, gold: Collection[str]) -> int | None:
    """저장된 condensed 상위 100건 안의 첫 정답 순위. 없으면 None(= 저장 범위 밖)."""
    for item in record["results"]:
        if item["doc_id"] in gold:
            return item["rank"]
    return None


def _delta(experiment: float | None, baseline: float | None) -> float | None:
    if experiment is None or baseline is None:
        return None
    return experiment - baseline


def _triple(exp_value: float | None, base_value: float | None) -> dict:
    return {"experiment": exp_value, "baseline": base_value, "delta": _delta(exp_value, base_value)}


def question_rows(
    questions: Sequence[data.Question],
    exp_records: Mapping[str, Mapping],
    base_records: Mapping[str, Mapping],
) -> list[dict]:
    """test의 비제외, 정답이 있는 질문마다 전후 nDCG@10과 첫 정답 순위(질문 ID 오름차순)."""
    rows = []
    for question in sorted(questions, key=lambda q: q.question_id):
        if question.split != "test" or question.excluded or not question.gold:
            continue
        exp_record = exp_records[question.question_id]
        base_record = base_records[question.question_id]
        before = scoring.question_values(base_record, question.gold)[METRIC]
        after = scoring.question_values(exp_record, question.gold)[METRIC]
        assert before is not None and after is not None
        rows.append(
            {
                "question_id": question.question_id,
                "query_type": question.query_type,
                "rank_before": first_gold_rank(base_record, question.gold),
                "rank_after": first_gold_rank(exp_record, question.gold),
                "ndcg_before": before,
                "ndcg_after": after,
                "delta": after - before,
            }
        )
    return rows


def compare_run(
    *,
    track: str,
    variant: str,
    baseline: str,
    questions: Sequence[data.Question],
    exp_records: Mapping[str, Mapping],
    exp_entry: Mapping,
    base_records: Mapping[str, Mapping],
    base_entry: Mapping,
    current_inputs: Mapping,
    resamples: int = RESAMPLES,
) -> dict:
    """한 (트랙, 변형)의 test 비교 결과. `comparison.json`의 `comparisons[<track>/<variant>]` 블록이다."""
    check_comparable(
        exp_entry=exp_entry,
        base_entry=base_entry,
        current_inputs=current_inputs,
        questions=questions,
        exp_records=exp_records,
        base_records=base_records,
    )
    exp_eval = scoring.evaluate_split(exp_records, questions, "test", exp_entry["selected"]["tau"])
    base_eval = scoring.evaluate_split(
        base_records, questions, "test", base_entry["selected"]["tau"]
    )
    exp_macro = exp_eval["macro"][METRIC]
    base_macro = base_eval["macro"][METRIC]
    if exp_macro is None or base_macro is None:
        raise ComparisonError(f"{track}/{variant}: no scored answerable test questions")
    delta = exp_macro - base_macro

    rows = question_rows(questions, exp_records, base_records)
    by_type_deltas: dict[str, dict[str, float]] = {}
    for row in rows:
        by_type_deltas.setdefault(row["query_type"], {})[row["question_id"]] = row["delta"]
    interval = bootstrap_macro_delta(by_type_deltas, resamples=resamples)
    verdict = decide(delta, interval["low"])

    by_type = {}
    for query_type, exp_type in exp_eval["by_type"].items():
        base_type = base_eval["by_type"].get(query_type)
        if base_type is None or not exp_type["n_scored"]:
            continue
        metrics = {
            name: _triple(exp_type["metrics"][name], base_type["metrics"][name])
            for name in (METRIC, "hit@10", "mrr@10")
        }
        by_type[query_type] = {
            "n_scored": exp_type["n_scored"],
            "observation_only": exp_type["observation_only"],
            "metrics": metrics,
        }
    cve = by_type.get("cve_explicit")
    cve_delta = cve["metrics"][METRIC]["delta"] if cve else None

    degraded = sorted(
        (r for r in rows if r["delta"] < 0), key=lambda r: (r["delta"], r["question_id"])
    )
    improved = sorted(
        (r for r in rows if r["delta"] > 0), key=lambda r: (-r["delta"], r["question_id"])
    )
    return {
        "track": track,
        "variant": variant,
        "baseline": baseline,
        "verdict": verdict,
        "metric": "test macro nDCG@10 (condensed, 정답이 있는 유형의 단순 평균)",
        "experiment_macro": exp_macro,
        "baseline_macro": base_macro,
        "delta": delta,
        "ci95": {"low": interval["low"], "high": interval["high"]},
        "bootstrap": {
            "resamples": interval["resamples"],
            "seed": interval["seed"],
            "stratified_by": "query_type",
            "n_per_type": {t: len(v) for t, v in by_type_deltas.items()},
        },
        "n_test_questions": len(rows),
        "secondary_metrics": {
            name: _triple(exp_eval["macro"][name], base_eval["macro"][name])
            for name in ("hit@10", "mrr@10")
        },
        "by_type": by_type,
        "cve_explicit": {
            "delta_ndcg@10": cve_delta,
            "regression": None if cve_delta is None else cve_delta < 0,
        },
        "no_answer": {
            "experiment": _no_answer(exp_eval),
            "baseline": _no_answer(base_eval),
        },
        "timing": {
            "note": "참고값: 2단계 실험은 같은 맥에서 병렬로 돌아 시간이 서로 간섭할 수 있다",
            "experiment": _timing(exp_entry),
            "baseline": _timing(base_entry),
        },
        "n_degraded": len(degraded),
        "n_improved": len(improved),
        "n_unchanged": len(rows) - len(degraded) - len(improved),
        "rank_note": "rank_*는 저장된 condensed 상위 100건 안의 첫 정답 순위이고 null은 저장 범위 밖이다",
        "degraded": degraded,
        "improved_top10": improved[:IMPROVED_LIMIT],
    }


def _no_answer(evaluation: Mapping) -> dict:
    block = evaluation["no_answer"]
    return {
        key: block[key]
        for key in ("n_no_answer", "n_answerable", "tau", "abstain_rate", "false_abstain_rate")
    }


def _timing(entry: Mapping) -> dict:
    timing = entry["timing"]
    return {
        "index_seconds": timing["index_seconds"],
        "query_latency_median_seconds": timing["query_latency_median_seconds"],
    }


def verdict_ref(block: Mapping) -> dict:
    return {key: block[key] for key in ("track", "variant", "baseline", "verdict")}


def assemble_comparison(
    *,
    experiment: str,
    hypothesis: str,
    primary: tuple[str, str],
    blocks: Mapping[str, Mapping],
) -> dict:
    """`comparison.json` 전체. `primary`는 주 (트랙, 변형)의 판정이고, 아직 test를 돌리지 않았으면 None이다."""
    primary_key = "/".join(primary)
    return {
        "protocol_version": scoring.PROTOCOL_VERSION,
        "experiment": experiment,
        "hypothesis": hypothesis,
        "rule": {
            "verdict": f"delta > 0 이고 ci95.low > 0 이면 {CONFIRMED}, 그 밖은 {REJECTED}",
            "bootstrap": (
                f"test 질문을 유형별 층화 복원추출 {RESAMPLES}회, random.Random({SEED}) 하나를 "
                "공유, 매 회 macro nDCG@10 차이 재계산, 2.5/97.5 백분위"
            ),
        },
        "primary": verdict_ref(blocks[primary_key]) if primary_key in blocks else None,
        "secondary": [verdict_ref(b) for key, b in blocks.items() if key != primary_key],
        "comparisons": dict(blocks),
    }


# ------------------------------------------------------------ --compare: 값 대조


def diff_values(expected, actual, tolerance: float = TOLERANCE, path: str = "$") -> list[str]:
    """저장된 값과 다시 계산한 값의 차이 목록. 숫자는 절대 허용오차, 나머지는 정확히 같아야 한다."""
    if isinstance(expected, bool) or isinstance(actual, bool):
        return [] if expected is actual else [f"{path}: {expected!r} != {actual!r}"]
    if isinstance(expected, int | float) and isinstance(actual, int | float):
        if abs(expected - actual) <= tolerance:
            return []
        return [f"{path}: {expected!r} != {actual!r} (|diff| > {tolerance})"]
    if isinstance(expected, dict) and isinstance(actual, dict):
        out = []
        for key in sorted(set(expected) | set(actual)):
            if key not in expected:
                out.append(f"{path}.{key}: missing in stored file")
            elif key not in actual:
                out.append(f"{path}.{key}: missing in recomputed")
            else:
                out += diff_values(expected[key], actual[key], tolerance, f"{path}.{key}")
        return out
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            return [f"{path}: length {len(expected)} != {len(actual)}"]
        out = []
        for index, (left, right) in enumerate(zip(expected, actual, strict=True)):
            out += diff_values(left, right, tolerance, f"{path}[{index}]")
        return out
    return [] if expected == actual else [f"{path}: {expected!r} != {actual!r}"]


def canonical_json(payload) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

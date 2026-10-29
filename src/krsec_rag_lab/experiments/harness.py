"""실험 하네스 - 모듈 import, 실행, 저장, test 잠금, 저장본만으로 하는 재계산.

실험 모듈은 `importlib.import_module(f"krsec_rag_lab.experiments.{name}")`로 이름만으로 찾는다. 실험 이름
목록도, 특정 실험 전용 분기도 없다. 모듈이 내놓아야 하는 것은 docs/experiments/README.md가 정한다.

`run_experiment`는 한 트랙의 변형들을 실행한다. 설정(모듈의 격자, 기권 τ)은 dev에서만 고르고 test는 확정한
설정으로 한 번 돈다. 실행 뒤 `<out>/<exp>/`의 `metrics.json`·`comparison.json`을 저장본에서 다시 만든다.
`verify_outputs`(`--compare`)는 같은 재계산을 파일에 쓰지 않고 돌려 커밋된 두 파일과 대조한다.

test 잠금: manifest의 `runs["<track>/<variant>"]["test"]`에 test를 돈 설정의 해시를 남긴다. 해시가 다른
설정으로 test를 실행하는 모든 경로(`split` = test, all)는 `LockError`다. dev 재실행은 잠금을 지우지 않으며
같은 설정을 다시 고를 때만 허용한다.

KISA 본문은 호출자가 넘기는 `load_body`로만 읽고 어떤 출력에도 쓰지 않는다. 출력(manifest·metrics·
comparison)에는 리포 기준 상대 경로만 쓴다.
"""

import hashlib
import importlib
import json
import os
import re
import statistics
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import ModuleType

from krsec_rag_lab.baselines import data, scoring
from krsec_rag_lab.baselines.dense import build_dense_index
from krsec_rag_lab.baselines.runner import environment
from krsec_rag_lab.experiments import ComparisonError, ContractError, ExperimentError, LockError
from krsec_rag_lab.experiments import compare as cmp

RESULTS_DIR = Path("results/experiments")
BASELINES_DIR = Path("results/baselines")
SPLIT_CHOICES = (*data.SPLITS, "all")
SCORED_SPLIT_FIELD = "dev_macro_ndcg@10"
DEFAULT_SELECTION_RULE = "dev macro nDCG@10 최대, 같으면 격자 순서에서 앞선 설정"
_NAME_RE = re.compile(r"[a-z][a-z0-9_]*")
_WINDOWS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
_PATH_HINTS = ("/Users/", "/home/", "/private/", "/var/folders/", "/tmp/")

ScoreFn = Callable[[data.Question], Mapping[str, float]]


@dataclass
class Context:
    """`setup`에 넘기는 실행 문맥. 코퍼스·질의는 이 (트랙, 변형) 실행에서 한 번 읽은 것이다."""

    root: Path
    track: str
    variant: str
    corpus: data.Corpus
    questions: list[data.Question]
    baselines_manifest: dict
    fixed: dict
    dense_factory: Callable[..., object]


# ------------------------------------------------------------ 모듈 import와 계약 검사

_REQUIRED = ("NAME", "HYPOTHESIS", "PRIMARY", "VARIANTS", "BASELINES")
_REQUIRED_CALLABLES = ("grid", "setup", "make_scorer")


def load_experiment(name: str) -> ModuleType:
    """이름으로 실험 모듈을 import하고 인터페이스 계약을 검사한다."""
    if not _NAME_RE.fullmatch(name):
        raise ContractError(f"bad experiment name {name!r}")
    qualified = f"krsec_rag_lab.experiments.{name}"
    try:
        module = importlib.import_module(qualified)
    except ModuleNotFoundError as error:
        if error.name == qualified:
            raise ContractError(f"unknown experiment {name!r}") from error
        raise
    validate_module(module, name)
    return module


def validate_module(module: ModuleType, name: str) -> None:
    for attribute in _REQUIRED:
        if not hasattr(module, attribute):
            raise ContractError(f"experiment {name!r}: missing {attribute}")
    for attribute in _REQUIRED_CALLABLES:
        if not callable(getattr(module, attribute, None)):
            raise ContractError(f"experiment {name!r}: {attribute} must be a function")
    if module.NAME != name:
        raise ContractError(f"experiment {name!r}: NAME is {module.NAME!r}")
    if not module.VARIANTS or not set(module.VARIANTS) <= set(data.TRACKS):
        raise ContractError(f"experiment {name!r}: VARIANTS must map tracks to variant names")
    for track, variants in module.VARIANTS.items():
        if not variants or len(set(variants)) != len(variants):
            raise ContractError(f"experiment {name!r}: bad variants for track {track}")
        if any(not _NAME_RE.fullmatch(variant) for variant in variants):
            raise ContractError(f"experiment {name!r}: variant names must match {_NAME_RE.pattern}")
        if track not in module.BASELINES:
            raise ContractError(f"experiment {name!r}: no baseline for track {track}")
    track, variant = module.PRIMARY
    if variant not in module.VARIANTS.get(track, ()):
        raise ContractError(f"experiment {name!r}: PRIMARY {module.PRIMARY} is not a variant")


def baseline_of(module: ModuleType, track: str) -> str:
    return module.BASELINES[track]


# ------------------------------------------------------------ 파일 입출력


def exp_dir(root: Path, out_dir: Path, name: str) -> Path:
    return root / out_dir / name


def _stored_path(root: Path, out_dir: Path, name: str, track: str, variant: str) -> Path:
    return exp_dir(root, out_dir, name) / track / f"{variant}.jsonl"


def _manifest_relative_path(out_dir: Path, name: str, track: str, variant: str) -> str:
    # 리포 밖 --out-dir의 절대 경로는 적지 않는다(기본 경로로 대신 적는다)
    base = RESULTS_DIR if out_dir.is_absolute() else out_dir
    return (base / name / track / f"{variant}.jsonl").as_posix()


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    path.write_text(text + "\n", encoding="utf-8")


def _write_results(path: Path, records: Mapping[str, Mapping], order: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(records[qid], ensure_ascii=False, sort_keys=True) for qid in order]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def read_manifest(root: Path, out_dir: Path, name: str) -> dict:
    path = exp_dir(root, out_dir, name) / "manifest.json"
    if not path.exists():
        return {"protocol_version": scoring.PROTOCOL_VERSION, "experiment": name, "runs": {}}
    return _read_json(path)


def read_baselines_manifest(root: Path) -> dict:
    path = root / BASELINES_DIR / "manifest.json"
    if not path.exists():
        raise ComparisonError("results/baselines/manifest.json missing")
    return _read_json(path)


def read_baseline_records(root: Path, track: str, baseline: str) -> dict[str, dict]:
    return cmp.read_stored(root / BASELINES_DIR / track / f"{baseline}.jsonl")


def find_absolute_paths(value, location: str = "$") -> list[str]:
    """출력에 들어가는 값 안의 절대 경로로 보이는 문자열의 위치(값은 적지 않는다)."""
    found = []
    if isinstance(value, str):
        pathlike = value.startswith("/") and not any(c.isspace() for c in value)
        if pathlike or _WINDOWS_PATH_RE.match(value) or any(h in value for h in _PATH_HINTS):
            found.append(location)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            found += find_absolute_paths(item, f"{location}.{key}")
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            found += find_absolute_paths(item, f"{location}[{index}]")
    return found


# ------------------------------------------------------------ 설정 해시(test 잠금)


def _file_fingerprint(root: Path, relative: str) -> dict[str, str]:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ContractError(f"reproduction input path must be repo-relative: {relative!r}")
    full = root / relative
    if not full.exists():
        raise ContractError(f"reproduction input missing: {relative}")
    return {"path": relative, "sha256": data.file_sha256(full)}


def reproduction_of(module: ModuleType, root: Path, track: str, variant: str) -> dict:
    hook = getattr(module, "reproduction_inputs", None)
    paths = hook(track, variant) if hook else {}
    return {name: _file_fingerprint(root, relative) for name, relative in sorted(paths.items())}


def fixed_of(module: ModuleType, track: str, variant: str, baselines_manifest: Mapping) -> dict:
    hook = getattr(module, "fixed_config", None)
    return dict(hook(track, variant, baselines_manifest)) if hook else {}


def config_hash(
    *,
    name: str,
    track: str,
    variant: str,
    config: Mapping,
    tau: float,
    inputs: Mapping,
    reproduction: Mapping,
    fixed: Mapping,
) -> str:
    """test를 돌리는 설정의 해시: 확정 설정(격자에서 고른 값, τ), 고정 설정, 입력·재현 입력의 sha256."""
    payload = {
        "experiment": name,
        "track": track,
        "variant": variant,
        "protocol_version": scoring.PROTOCOL_VERSION,
        "config": config,
        "tau": tau,
        "inputs": inputs,
        "reproduction_inputs": reproduction,
        "fixed": fixed,
    }
    return hashlib.sha256(cmp.canonical_json(payload).encode("utf-8")).hexdigest()


def entry_hash(name: str, entry: Mapping) -> str:
    """manifest 항목에 적힌 확정 설정으로 다시 계산한 test 설정 해시."""
    return config_hash(
        name=name,
        track=entry["track"],
        variant=entry["variant"],
        config=entry["selected"]["config"],
        tau=entry["selected"]["tau"],
        inputs=entry["inputs"],
        reproduction=entry["reproduction_inputs"],
        fixed=entry["fixed"],
    )


# ------------------------------------------------------------ 채점과 dev 선택


def score_questions(
    scorer: ScoreFn, questions: Sequence[data.Question]
) -> tuple[dict[str, dict], list[float]]:
    """채점 대상 질문마다 결과 레코드를 만들고 질문당 소요 시간(점수 계산 + 정렬)을 잰다."""
    records: dict[str, dict] = {}
    latencies: list[float] = []
    for question in questions:
        started = time.perf_counter()
        scores = scorer(question)
        record = scoring.make_record(question.question_id, scores, question.unjudged)
        latencies.append(time.perf_counter() - started)
        try:
            scoring.validate_record(record)
        except ValueError as error:
            raise ContractError(
                f"{question.question_id}: scorer output invalid: {error}"
            ) from error
        records[question.question_id] = record
    return records, latencies


def default_select(rows: Sequence[Mapping]) -> int:
    """dev macro nDCG@10이 최대인 행, 같으면 격자 순서에서 앞선 행의 인덱스."""
    best = 0
    for index, row in enumerate(rows):
        if row[SCORED_SPLIT_FIELD] > rows[best][SCORED_SPLIT_FIELD]:
            best = index
    return best


def select_on_dev(
    module: ModuleType,
    state: object,
    track: str,
    variant: str,
    dev: Sequence[data.Question],
) -> dict:
    """격자 전체를 dev에서 채점해 설정과 τ를 고른다. dev의 점수 외에는 아무것도 보지 않는다."""
    configs = list(module.grid(track, variant))
    if not configs:
        raise ContractError(f"{module.NAME}: empty grid for {track}/{variant}")
    rows: list[dict] = []
    runs: list[tuple[dict[str, dict], list[float]]] = []
    for config in configs:
        scorer = module.make_scorer(state, config)
        records, latencies = score_questions(scorer, dev)
        macro = scoring.evaluate_split(records, dev, "dev", None)["macro"]["ndcg@10"]
        if macro is None:
            raise ExperimentError("dev selection needs scored answerable dev questions; none")
        rows.append({"config": config, SCORED_SPLIT_FIELD: macro})
        runs.append((records, latencies))
    select = getattr(module, "select", default_select)
    index = select(rows)
    if not 0 <= index < len(rows):
        raise ContractError(f"{module.NAME}: select returned {index}")
    records, latencies = runs[index]
    no_answer = [records[q.question_id]["top1_score_raw"] for q in dev if not q.gold]
    answerable = [records[q.question_id]["top1_score_raw"] for q in dev if q.gold]
    tau_info = scoring.select_tau(no_answer, answerable)
    return {
        "rows": rows,
        "index": index,
        "config": configs[index],
        "records": records,
        "latencies": latencies,
        "tau_info": tau_info,
        "rule": getattr(module, "SELECTION_RULE", DEFAULT_SELECTION_RULE),
    }


# ------------------------------------------------------------ 실행


def _check_arguments(module: ModuleType, track: str, variants, split: str) -> list[str]:
    if track not in module.VARIANTS:
        raise ContractError(f"experiment {module.NAME!r} has no track {track!r}")
    if split not in SPLIT_CHOICES:
        raise ContractError(f"bad split {split!r}")
    available = list(module.VARIANTS[track])
    if variants is None:
        return available
    unknown = [v for v in variants if v not in available]
    if unknown:
        raise ContractError(f"unknown variant(s) {unknown} for {track}; available: {available}")
    return [v for v in available if v in variants]


def _load_inputs(
    track: str, root: Path, load_body: data.BodyLoader | None
) -> tuple[list[data.Question], data.Corpus]:
    questions = data.load_questions(track, root)
    if track == "public":
        corpus = data.load_public_corpus(root)
    else:
        if load_body is None:
            raise ExperimentError("kisa track needs load_body (--kisa-root)")
        corpus = data.load_kisa_corpus(root, load_body)
    data.check_questions(questions, set(corpus.texts))
    return questions, corpus


def run_experiment(
    module: ModuleType | str,
    track: str,
    root: Path,
    *,
    variants: Sequence[str] | None = None,
    split: str = "all",
    out_dir: Path = RESULTS_DIR,
    load_body: data.BodyLoader | None = None,
    dense_factory: Callable[..., object] = build_dense_index,
) -> dict:
    """한 트랙의 변형들을 실행하고 결과·manifest·metrics·comparison을 쓴다. comparison을 돌려준다."""
    if isinstance(module, str):
        module = load_experiment(module)
    selected_variants = _check_arguments(module, track, variants, split)
    name = module.NAME
    questions, corpus = _load_inputs(track, root, load_body)
    baselines_manifest = read_baselines_manifest(root)
    baseline = baseline_of(module, track)
    base_entry = cmp.check_baseline_entry(baselines_manifest, track, baseline)
    # 기준선 쪽 비교 전 검사는 실행 전에 한다: test를 돌리고 나서 비교가 안 되는 일을 막는다
    cmp.check_comparable(
        exp_entry=base_entry,
        base_entry=base_entry,
        current_inputs=data.input_fingerprints(track, root),
        questions=questions,
        exp_records=None,
        base_records=read_baseline_records(root, track, baseline),
    )
    # 모든 변형을 메모리에서 먼저 끝낸다: 뒤쪽 변형이 잠금 위반으로 실패해도 앞쪽 변형의 test가 저장되지 않는다
    pending = [
        _run_variant(
            module,
            track,
            variant,
            root,
            split=split,
            out_dir=out_dir,
            questions=questions,
            corpus=corpus,
            baselines_manifest=baselines_manifest,
            dense_factory=dense_factory,
        )
        for variant in selected_variants
    ]
    _commit(module, root, out_dir, pending)
    return _read_json(exp_dir(root, out_dir, name) / "comparison.json")


@dataclass
class Pending:
    """한 변형의 쓸 내용. `_commit`이 파일에 쓰기 전까지 디스크는 바뀌지 않는다."""

    key: str
    results_path: Path
    records: dict[str, dict]
    order: list[str]
    entry: dict


def _snapshot(directory: Path) -> dict[Path, bytes]:
    return (
        {p: p.read_bytes() for p in directory.rglob("*") if p.is_file()}
        if directory.exists()
        else {}
    )


def _restore(directory: Path, before: Mapping[Path, bytes]) -> None:
    if directory.exists():
        for path in directory.rglob("*"):
            if path.is_file() and path not in before:
                path.unlink()
    for path, content in before.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)


def _commit(module: ModuleType, root: Path, out_dir: Path, pending: Sequence[Pending]) -> None:
    """결과 jsonl·manifest·metrics·comparison을 쓴다. 쓰다가(재계산의 비교 전 검사 포함) 실패하면 쓰기 전 상태로 되돌린다."""
    directory = exp_dir(root, out_dir, module.NAME)
    before = _snapshot(directory)
    try:
        manifest = read_manifest(
            root, out_dir, module.NAME
        )  # 긴 setup 동안 바뀐 항목을 덮지 않도록 쓰기 직전에 다시 읽는다
        for item in pending:
            _write_results(item.results_path, item.records, item.order)
            manifest["runs"][item.key] = item.entry
        manifest["protocol_version"] = scoring.PROTOCOL_VERSION
        manifest["experiment"] = module.NAME
        _write_json(directory / "manifest.json", manifest)
        write_outputs(module, root, out_dir)
    except BaseException:
        _restore(directory, before)
        raise


def _run_variant(
    module: ModuleType,
    track: str,
    variant: str,
    root: Path,
    *,
    split: str,
    out_dir: Path,
    questions: list[data.Question],
    corpus: data.Corpus,
    baselines_manifest: dict,
    dense_factory: Callable[..., object],
) -> Pending:
    name = module.NAME
    key = f"{track}/{variant}"
    run_dev = split in ("dev", "all")
    run_test = split in ("test", "all")
    manifest = read_manifest(root, out_dir, name)
    entry = manifest["runs"].get(key)
    lock = entry.get("test") if entry else None
    inputs = data.input_fingerprints(track, root)
    reproduction = reproduction_of(module, root, track, variant)
    fixed = fixed_of(module, track, variant, baselines_manifest)

    def hash_of(config: Mapping, tau: float) -> str:
        return config_hash(
            name=name,
            track=track,
            variant=variant,
            config=config,
            tau=tau,
            inputs=inputs,
            reproduction=reproduction,
            fixed=fixed,
        )

    # 이미 test를 돈 설정과 입력·고정 설정이 달라졌으면 모델을 만들기 전에 실패한다
    if lock and hash_of(lock["config"], lock["tau"]) != lock["config_hash"]:
        raise LockError(
            f"{key}: test already ran with another config or inputs (config_hash "
            f"{lock['config_hash'][:12]}); a changed setup needs a new hypothesis"
        )
    if not run_dev:
        if entry is None:
            raise ExperimentError(
                f"{key}: --split test needs a dev-selected config; run --split dev first"
            )
        if (entry["inputs"], entry["reproduction_inputs"], entry["fixed"]) != (
            inputs,
            reproduction,
            fixed,
        ):
            raise ExperimentError(
                f"{key}: inputs changed since the dev run; rerun --split dev or all"
            )

    scored = [q for q in questions if not q.excluded]
    dev = [q for q in scored if q.split == "dev"]
    test = [q for q in scored if q.split == "test"]
    ctx = Context(
        root=root,
        track=track,
        variant=variant,
        corpus=corpus,
        questions=questions,
        baselines_manifest=baselines_manifest,
        fixed=fixed,
        dense_factory=dense_factory,
    )
    started = time.perf_counter()
    state = module.setup(ctx)
    setup_seconds = time.perf_counter() - started

    results_path = _stored_path(root, out_dir, name, track, variant)
    previous = cmp.read_stored(results_path) if results_path.exists() else {}
    timed: list[float] = []
    if run_dev:
        selection = select_on_dev(module, state, track, variant, dev)
        config, tau = selection["config"], selection["tau_info"]["tau"]
        selected = {
            "selected_on": "dev",
            "config": config,
            SCORED_SPLIT_FIELD: selection["rows"][selection["index"]][SCORED_SPLIT_FIELD],
            "tau": tau,
            "tau_selection": selection["tau_info"],
        }
        grid = {"rows": selection["rows"], "selection_rule": selection["rule"]}
        new_hash = hash_of(config, tau)
        if lock and new_hash != lock["config_hash"]:
            raise LockError(
                f"{key}: dev reselected a config different from the one test ran with "
                f"(config_hash {lock['config_hash'][:12]}); refusing to overwrite"
            )
        records = dict(selection["records"])
        timed += selection["latencies"]
    else:
        assert entry is not None
        selected, grid = entry["selected"], entry["grid"]
        config, tau = selected["config"], selected["tau"]
        new_hash = hash_of(config, tau)
        if lock and new_hash != lock["config_hash"]:
            raise LockError(
                f"{key}: test already ran with another config (config_hash {lock['config_hash'][:12]})"
            )
        dev_ids = {q.question_id for q in dev}
        records = {qid: record for qid, record in previous.items() if qid in dev_ids}
        if len(records) != len(dev_ids):
            raise ExperimentError(f"{key}: stored dev rows are incomplete; rerun --split dev")
    scorer = module.make_scorer(state, config)
    if run_test:
        test_records, test_latencies = score_questions(scorer, test)
        records.update(test_records)
        timed += test_latencies
    elif lock:
        # dev 재실행은 잠금과 test 결과를 지우지 않는다
        test_ids = {q.question_id for q in test}
        records.update({qid: record for qid, record in previous.items() if qid in test_ids})

    describe = getattr(module, "describe", None)
    description = dict(describe(state, config)) if describe else {}
    now = datetime.now(UTC).isoformat(timespec="seconds")
    new_lock = lock
    if run_test:
        new_lock = {
            "executed_at": lock["executed_at"] if lock else now,
            "config_hash": new_hash,
            "config": config,
            "tau": tau,
        }
    order = [q.question_id for q in scored if q.question_id in records]
    new_entry = {
        "experiment": name,
        "track": track,
        "variant": variant,
        "protocol_version": scoring.PROTOCOL_VERSION,
        "created_at": now,
        "splits_stored": [
            s
            for s in data.SPLITS
            if any(q.split == s for q in scored)
            and all(q.question_id in records for q in scored if q.split == s)
        ],
        "inputs": inputs,
        "reproduction_inputs": reproduction,
        "n_documents": len(corpus.texts),
        "index_text": data.PUBLIC_INDEX_TEXT if track == "public" else data.KISA_INDEX_TEXT,
        "baseline": {
            "retriever": baseline_of(module, track),
            "stored_results": f"{BASELINES_DIR.as_posix()}/{track}/{baseline_of(module, track)}.jsonl",
        },
        "stored_results": {
            "path": _manifest_relative_path(out_dir, name, track, variant),
            "top_n": scoring.RESULT_TOP_N,
            "fields": sorted(scoring.RECORD_FIELDS),
            "result_fields": sorted(scoring.RESULT_FIELDS),
            "ranking": "(점수 내림차순, 문서 ID 오름차순) 정렬 뒤 질문의 unjudged를 지운 condensed list",
        },
        "fixed": fixed,
        "description": description,
        "grid": grid,
        "selected": selected,
        "timing": {
            "index_seconds": setup_seconds,
            "query_latency_median_seconds": statistics.median(timed) if timed else None,
            "n_queries_timed": len(timed),
        },
        "environment": {**environment(), "omp_num_threads": os.environ.get("OMP_NUM_THREADS")},
    }
    if new_lock is not None:
        new_entry["test"] = new_lock
    leaked = find_absolute_paths(new_entry)
    if leaked:
        raise ContractError(f"{key}: manifest would contain absolute paths at {leaked}")

    return Pending(key, results_path, records, order, new_entry)


# ------------------------------------------------------------ 저장본에서 metrics·comparison 재계산


def compute_outputs(module: ModuleType, root: Path, out_dir: Path) -> tuple[dict, dict]:
    """manifest + 저장된 원시 결과 + 질의셋 라벨 + 기준선 저장본만으로 (metrics, comparison)을 만든다.

    모델·KISA 캐시를 읽지 않는다. 파일은 쓰지 않는다.
    """
    name = module.NAME
    manifest = read_manifest(root, out_dir, name)
    if not manifest["runs"]:
        raise ExperimentError(f"{name}: no stored runs under the output directory")
    baselines_manifest = read_baselines_manifest(root)
    metrics: dict = {"protocol_version": scoring.PROTOCOL_VERSION, "experiment": name, "runs": {}}
    blocks: dict[str, dict] = {}
    for track in data.TRACKS:
        if track not in module.VARIANTS:
            continue
        if not any(f"{track}/{variant}" in manifest["runs"] for variant in module.VARIANTS[track]):
            continue
        questions = data.load_questions(track, root)
        current_inputs = data.input_fingerprints(track, root)
        baseline = baseline_of(module, track)
        for variant in module.VARIANTS[track]:
            key = f"{track}/{variant}"
            entry = manifest["runs"].get(key)
            if entry is None:
                continue
            records = cmp.read_stored(_stored_path(root, out_dir, name, track, variant))
            cmp.check_known(key, records, questions)
            tau = entry["selected"]["tau"]
            run_metrics = {}
            for split in data.SPLITS:
                split_questions = [q for q in questions if q.split == split and not q.excluded]
                stored = [q for q in split_questions if q.question_id in records]
                if not stored:
                    continue
                if len(stored) != len(split_questions):
                    raise ComparisonError(
                        f"{key}: {split} has {len(stored)}/{len(split_questions)} stored rows"
                    )
                run_metrics[split] = scoring.evaluate_split(records, questions, split, tau)
            metrics["runs"][key] = run_metrics
            lock = entry.get("test")
            if lock is not None and entry_hash(name, entry) != lock["config_hash"]:
                raise LockError(f"{key}: manifest config_hash does not match its recorded config")
            # 잠금이 없는 dev 전용 항목도 지금 입력 파일에서 만든 것이어야 한다(라벨이 바뀐 채 옛 순위를 채점하지 않는다)
            if entry["inputs"] != current_inputs:
                raise ComparisonError(
                    f"{key}: stored input hashes differ from the current input files"
                )
            for label, fingerprint in entry["reproduction_inputs"].items():
                current = data.file_sha256(root / fingerprint["path"])
                if current != fingerprint["sha256"]:
                    raise ComparisonError(f"{key}: reproduction input {label!r} changed")
            if lock is None:
                continue
            if "test" not in run_metrics:
                raise ExperimentError(f"{key}: test lock recorded but test rows are not stored")
            base_entry = cmp.check_baseline_entry(baselines_manifest, track, baseline)
            blocks[key] = cmp.compare_run(
                track=track,
                variant=variant,
                baseline=baseline,
                questions=questions,
                exp_records=records,
                exp_entry=entry,
                base_records=read_baseline_records(root, track, baseline),
                base_entry=base_entry,
                current_inputs=current_inputs,
            )
    comparison = cmp.assemble_comparison(
        experiment=name, hypothesis=module.HYPOTHESIS, primary=tuple(module.PRIMARY), blocks=blocks
    )
    return metrics, comparison


def write_outputs(module: ModuleType, root: Path, out_dir: Path) -> tuple[dict, dict]:
    metrics, comparison = compute_outputs(module, root, out_dir)
    leaked = find_absolute_paths(metrics) + find_absolute_paths(comparison)
    if leaked:
        raise ContractError(f"outputs would contain absolute paths at {leaked}")
    directory = exp_dir(root, out_dir, module.NAME)
    _write_json(directory / "metrics.json", metrics)
    _write_json(directory / "comparison.json", comparison)
    return metrics, comparison


def verify_outputs(module: ModuleType, root: Path, out_dir: Path) -> list[str]:
    """`--compare`: 저장본에서 다시 계산한 값을 커밋된 metrics.json·comparison.json과 대조한다.

    파일을 쓰지 않는다. 차이 목록을 돌려주고 비어 있으면 일치다(숫자는 abs 1e-9, 판정·문자열은 정확히).
    """
    metrics, comparison = compute_outputs(module, root, out_dir)
    directory = exp_dir(root, out_dir, module.NAME)
    problems: list[str] = []
    for filename, recomputed in (("metrics.json", metrics), ("comparison.json", comparison)):
        path = directory / filename
        if not path.exists():
            problems.append(f"{filename}: missing")
            continue
        stored = _read_json(path)
        # 저장본은 JSON 왕복을 거치므로 다시 계산한 값도 같은 형태로 맞춘 뒤 대조한다
        normalized = json.loads(json.dumps(recomputed, ensure_ascii=False))
        problems += [f"{filename} {line}" for line in cmp.diff_values(stored, normalized)]
    return problems

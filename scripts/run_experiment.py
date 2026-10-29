"""M3 실험 실행 CLI - 실험 하나 = `krsec_rag_lab.experiments.<name>` 모듈 하나.

    uv run --group embed python scripts/run_experiment.py --exp hybrid --track public
    uv run --group embed python scripts/run_experiment.py --exp hybrid --track kisa --kisa-root <KISA 캐시가 있는 체크아웃>
    uv run --group embed python scripts/run_experiment.py --exp hybrid --track public --variant rrf --split dev
    uv run python scripts/run_experiment.py --exp hybrid --compare                      # 모델·KISA 캐시 없이 저장본만으로 재계산 대조
    uv run --group embed python scripts/run_experiment.py --exp hybrid --track public --out-dir <빈 디렉터리>   # 재현 확인: 커밋된 결과를 덮어쓰지 않는다

`--variant`를 생략하면 그 트랙의 모든 변형을, 주면 그 변형만 실행한다. `--split`은 dev(격자·τ 선택 + dev 결과),
test(manifest에 확정된 설정으로 test만), all(기본: dev 선택 뒤 test 1회)이다. 이미 test를 돈 설정과 다른 설정으로
test를 실행하면(--split test, all 모두) exit 1이다.

`--compare`는 파일을 쓰지 않고 저장된 원시 결과·manifest·질의셋 라벨·기준선 저장본에서 metrics와 comparison을
다시 계산해 커밋된 metrics.json·comparison.json과 대조한다(숫자는 abs 1e-9). 어긋나면 exit 1이다.
KISA 본문은 --kisa-root 아래 data/kisa에서 fetch_kisa.load_cached_body로만 읽고 출력·로그에 남기지 않는다.
"""

import argparse
import importlib.util
import json
import sys
from collections.abc import Mapping
from pathlib import Path

from krsec_rag_lab.baselines import data
from krsec_rag_lab.experiments import ExperimentError, harness

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
MAX_PROBLEMS_SHOWN = 20


def load_kisa_module():
    """scripts/fetch_kisa.py를 모듈로 읽는다(실행하지 않는다: load_cached_body만 쓴다)."""
    if "fetch_kisa" in sys.modules:
        return sys.modules["fetch_kisa"]
    spec = importlib.util.spec_from_file_location("fetch_kisa", SCRIPTS / "fetch_kisa.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def kisa_body_loader(kisa_root: Path, kisa) -> data.BodyLoader:
    def load(ntt_id: str, document: Mapping[str, str]) -> str:
        return kisa.load_cached_body(kisa_root, ntt_id, document)

    return load


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--exp", required=True, help="실험 이름(krsec_rag_lab.experiments.<name>)")
    parser.add_argument("--track", choices=data.TRACKS)
    parser.add_argument(
        "--variant", action="append", help="변형 이름(생략하면 그 트랙의 모든 변형)"
    )
    parser.add_argument("--split", choices=harness.SPLIT_CHOICES, default="all")
    parser.add_argument(
        "--kisa-root", type=Path, help="KISA 캐시(data/kisa)가 있는 체크아웃 루트(kisa 트랙 필수)"
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=harness.RESULTS_DIR,
        help="결과를 쓸 디렉터리(기본값: results/experiments, 리포 기준). 다른 경로를 주면 커밋된 "
        "결과를 건드리지 않는다(재현 확인용)",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="저장본만으로 metrics·comparison을 다시 계산해 커밋된 파일과 대조(쓰기 없음, 불일치 exit 1)",
    )
    return parser


def run_compare(module, out_dir: Path) -> int:
    problems = harness.verify_outputs(module, ROOT, out_dir)
    if problems:
        for line in problems[:MAX_PROBLEMS_SHOWN]:
            print(f"mismatch: {line}", file=sys.stderr)
        extra = len(problems) - MAX_PROBLEMS_SHOWN
        if extra > 0:
            print(f"... and {extra} more", file=sys.stderr)
        print(f"compare FAILED: {len(problems)} mismatch(es)", file=sys.stderr)
        return 1
    comparison = json.loads(
        (harness.exp_dir(ROOT, out_dir, module.NAME) / "comparison.json").read_text("utf-8")
    )
    print(
        f"compare OK: {module.NAME} metrics.json and comparison.json match the values "
        "recomputed from stored results (abs tol 1e-09)"
    )
    print(json.dumps(summary(comparison), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def summary(comparison: Mapping) -> dict:
    """CLI 출력용 요약: 주·보조 판정과 (트랙, 변형)별 기준·실험 macro, delta, 95% 구간."""
    rows = {
        key: {
            "baseline": block["baseline"],
            "baseline_macro_ndcg@10": block["baseline_macro"],
            "experiment_macro_ndcg@10": block["experiment_macro"],
            "delta": block["delta"],
            "ci95": [block["ci95"]["low"], block["ci95"]["high"]],
            "verdict": block["verdict"],
            "n_degraded": block["n_degraded"],
            "n_improved": block["n_improved"],
            "cve_explicit_regression": block["cve_explicit"]["regression"],
        }
        for key, block in comparison["comparisons"].items()
    }
    return {
        "primary": comparison["primary"],
        "secondary": comparison["secondary"],
        "test": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out_dir = args.out_dir if args.out_dir == harness.RESULTS_DIR else args.out_dir.resolve()
    kisa = None
    try:
        module = harness.load_experiment(args.exp)
        if args.compare:
            if args.track or args.variant or args.kisa_root or args.split != "all":
                parser.error("--compare takes no --track, --variant, --split or --kisa-root")
            return run_compare(module, out_dir)
        if args.track is None:
            parser.error("--track is required")
        load_body = None
        if args.track == "kisa":
            if args.kisa_root is None:
                parser.error("--kisa-root is required for the kisa track")
            kisa = load_kisa_module()
            load_body = kisa_body_loader(args.kisa_root, kisa)
        comparison = harness.run_experiment(
            module,
            args.track,
            ROOT,
            variants=args.variant,
            split=args.split,
            out_dir=out_dir,
            load_body=load_body,
        )
    except ExperimentError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except Exception as error:
        # KisaError 메시지는 본문·경로를 담지 않는다(cache_missing, cache_hash_mismatch 등)
        if kisa is not None and isinstance(error, kisa.KisaError):
            print(f"error: {error}", file=sys.stderr)
            return 1
        raise
    print(json.dumps(summary(comparison), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

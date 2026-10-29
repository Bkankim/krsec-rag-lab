"""베이스라인 3종 실행 CLI - exact CVE lookup / BM25 / dense(bge-m3), 공개 트랙과 KISA 트랙.

    uv run python scripts/run_baselines.py --track public --retriever exact
    uv run python scripts/run_baselines.py --track public --retriever bm25
    uv run python scripts/run_baselines.py --track kisa --retriever bm25 --kisa-root <KISA 캐시가 있는 체크아웃>
    uv run --group embed python scripts/run_baselines.py --track public --retriever dense   # CI에서는 돌리지 않는다
    uv run python scripts/run_baselines.py --render-docs      # results/baselines/metrics.json -> docs/baselines.md 표

`--split`은 dev(설정 선택 + dev 결과), test(manifest에 확정된 설정으로 test만), all(기본: dev 선택 뒤 test 1회).
KISA 본문은 --kisa-root 아래 data/kisa에서 fetch_kisa.load_cached_body로만 읽는다. 본문과 --kisa-root 경로는
출력 파일·로그에 남기지 않는다. 누락·해시 불일치는 실행 실패(exit 1)다.
"""

import argparse
import importlib.util
import json
import sys
from collections.abc import Mapping
from pathlib import Path

from krsec_rag_lab.baselines import data, report, runner

ROOT = Path(__file__).resolve().parents[1]


def load_kisa_module():
    """scripts/fetch_kisa.py를 모듈로 읽는다(실행하지 않는다: load_cached_body만 쓴다)."""
    if "fetch_kisa" in sys.modules:
        return sys.modules["fetch_kisa"]
    spec = importlib.util.spec_from_file_location("fetch_kisa", ROOT / "scripts" / "fetch_kisa.py")
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
    parser.add_argument("--track", choices=data.TRACKS)
    parser.add_argument("--retriever", choices=runner.RETRIEVERS)
    parser.add_argument("--split", choices=(*data.SPLITS, "all"), default="all")
    parser.add_argument(
        "--kisa-root", type=Path, help="KISA 캐시(data/kisa)가 있는 체크아웃 루트(kisa 트랙 필수)"
    )
    parser.add_argument(
        "--render-docs",
        action="store_true",
        help="metrics.json의 표를 docs/baselines.md의 표시 구간에 옮긴다(실행 없음)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.render_docs:
        report.render_docs(ROOT)
        print("docs/baselines.md tables updated")
        return 0
    if args.track is None or args.retriever is None:
        parser.error("--track and --retriever are required")
    load_body = None
    if args.track == "kisa":
        if args.kisa_root is None:
            parser.error("--kisa-root is required for the kisa track")
        kisa = load_kisa_module()
        load_body = kisa_body_loader(args.kisa_root, kisa)
    try:
        metrics = runner.run_baseline(
            args.track, args.retriever, ROOT, split=args.split, load_body=load_body
        )
    except Exception as error:
        # KisaError 메시지는 본문·경로를 담지 않는다(cache_missing, cache_hash_mismatch 등)
        if args.track == "kisa" and type(error).__name__ == "KisaError":
            print(f"error: {error}", file=sys.stderr)
            return 1
        raise
    print(json.dumps(report.summary(metrics), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

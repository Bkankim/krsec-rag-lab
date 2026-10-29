"""공개 평가 트랙 질의셋을 생성한다(#35, eval-protocol 11절).

입력은 `fixtures/nvd/cves.jsonl` 하나다. 네트워크·KISA 캐시를 쓰지 않는다. 같은 입력과 seed로 다시 실행하면
`eval/public/` 출력의 sha256이 같다.

    uv run python scripts/build_public_eval.py
"""

import sys
from pathlib import Path

from krsec_rag_lab.public_eval import main

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    raise SystemExit(main(["--root", str(ROOT), *sys.argv[1:]]))

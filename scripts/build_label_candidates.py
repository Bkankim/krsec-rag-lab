"""약한 라벨 후보·seed 고정 표본·검수 양식을 생성한다(#27, eval-protocol 8절 1단계).

입력은 공개 메타데이터(fixtures/kisa)와 NVD fixture의 CVE ID뿐이다. KISA 본문과 로컬 캐시(data/kisa)는
읽지 않고 네트워크도 쓰지 않는다. 같은 입력과 seed로 다시 실행하면 출력 파일의 sha256이 같다.

    uv run python scripts/build_label_candidates.py
"""

import sys
from pathlib import Path

from krsec_rag_lab.golden import main

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    raise SystemExit(main(["build", "--root", str(ROOT), *sys.argv[1:]]))

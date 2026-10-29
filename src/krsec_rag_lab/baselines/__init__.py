"""베이스라인 3종(exact CVE lookup / BM25 / dense) - 프레임워크 없는 함수 모음.

세 검색기는 모두 `질의 문자열 -> {문서 ID: 점수}` 함수로 쓰이고, 순위·채점·결과 저장은 공통 코드가 한다.
exact와 BM25는 표준 라이브러리만 쓴다. dense는 `embed` 그룹 패키지(numpy, sentence-transformers)를
함수 안에서만 import한다(CI의 dev 그룹에는 없다). 정의의 정본은 docs/eval-protocol.md, 결과 해석은
docs/baselines.md다.
"""

"""로컬 LLM 생성 파이프라인(M5) - 프레임워크 없는 함수 모음.

검색(#11 BM25) -> 문맥 -> 프롬프트 -> Ollama -> 출력 계약 파싱은 `pipeline`, Ollama HTTP 호출은 `llm`이다.
정의의 정본은 docs/m5-generation.md다. 모델 호출은 함수 안에서만 일어나므로 import는 항상 안전하다.
"""

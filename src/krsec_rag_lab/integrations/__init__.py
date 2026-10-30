"""LangChain/LangGraph 어댑터(M5) - 코어 함수를 감싸기만 한다.

이 패키지만 langchain-core·langgraph를 import한다(`uv sync --locked --group langchain`에 있고 CI의 dev 그룹에는 없다).
그래서 이 파일은 아무것도 import하지 않는다: `langchain_adapter`·`langgraph_pipeline`을 직접 import할 때만 필요하다.
정의의 정본은 docs/m5-integration.md다.
"""

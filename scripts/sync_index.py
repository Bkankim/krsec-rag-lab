"""KISA 전체 코퍼스 스냅샷과 Qdrant 컬렉션의 증분 동기화 CLI. 구현은 krsec_rag_lab.corpus.index_sync, 규칙은 docs/m4-idempotency.md."""

from krsec_rag_lab.corpus.index_sync import main

if __name__ == "__main__":
    raise SystemExit(main())

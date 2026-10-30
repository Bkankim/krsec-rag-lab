"""LangChain `BaseRetriever` 어댑터 - 코어 BM25 검색(`generation.pipeline.retrieve`)을 그대로 감싼다.

순위 규칙(`(-점수, 문서 ID)` 정렬, 0건 가능)은 코어 함수가 정하고 이 어댑터는 바꾸지 않는다. 문서 ID·점수·순위는
`Document.metadata`에, 본문(색인 텍스트)은 `page_content`에 둔다.
"""

from typing import Any

from langchain_core.callbacks import CallbackManagerForRetrieverRun
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever
from pydantic import ConfigDict

from krsec_rag_lab.generation.pipeline import retrieve


class BM25CoreRetriever(BaseRetriever):
    """`index`(`GenerationIndex`: `score`와 `text`를 가진 BM25 색인)의 상위 `k`개 문서를 돌려준다.

    metadata: `doc_id`(문서 ID), `score`(BM25 점수), `rank`(1부터). `Document.id`도 문서 ID다.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    index: Any
    k: int = 3

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun
    ) -> list[Document]:
        return [
            Document(
                id=doc_id,
                page_content=self.index.text(doc_id),
                metadata={"doc_id": doc_id, "score": score, "rank": rank},
            )
            for rank, (doc_id, score) in enumerate(retrieve(self.index, query, self.k), start=1)
        ]

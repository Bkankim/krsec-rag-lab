"""Okapi BM25 - 표준 라이브러리만 쓰는 메모리 역색인.

점수: sum over 질의의 고유 토큰 t of idf(t) * tf * (k1 + 1) / (tf + k1 * (1 - b + b * dl / avgdl))
idf(t) = ln(1 + (N - df + 0.5) / (df + 0.5)) (Lucene 형식, 항상 양수).

질의 토큰은 중복을 접어 한 번만 센다. 질의 토큰이 하나도 없는 문서는 점수 딕셔너리에 넣지 않는다(검색되지
않음). 그래서 일치 토큰이 없는 질의는 빈 결과이고, 정렬·동점 처리는 공통 채점 코드가 한다.
"""

import math
from collections import Counter
from collections.abc import Callable, Mapping

from krsec_rag_lab.baselines.tokens import tokenize

DEFAULT_K1 = 1.2
DEFAULT_B = 0.75


class BM25Index:
    def __init__(
        self,
        texts: Mapping[str, str],
        k1: float = DEFAULT_K1,
        b: float = DEFAULT_B,
        tokenizer: Callable[[str], list[str]] = tokenize,
    ):
        if k1 < 0 or not 0 <= b <= 1:
            raise ValueError(f"need k1 >= 0 and 0 <= b <= 1, got k1={k1}, b={b}")
        self.k1 = k1
        self.b = b
        self._tokenizer = tokenizer
        self._doc_ids = list(texts)
        self._doc_len: list[int] = []
        self._postings: dict[str, list[tuple[int, int]]] = {}
        for index, doc_id in enumerate(self._doc_ids):
            tokens = tokenizer(texts[doc_id])
            self._doc_len.append(len(tokens))
            for term, tf in Counter(tokens).items():
                self._postings.setdefault(term, []).append((index, tf))
        n_docs = len(self._doc_ids)
        self._avgdl = sum(self._doc_len) / n_docs if n_docs else 0.0
        self._idf = {
            term: math.log(1.0 + (n_docs - len(postings) + 0.5) / (len(postings) + 0.5))
            for term, postings in self._postings.items()
        }

    @property
    def n_documents(self) -> int:
        return len(self._doc_ids)

    def score(self, query: str) -> dict[str, float]:
        """질의 토큰이 하나라도 든 문서의 BM25 점수. 일치가 없으면 빈 딕셔너리."""
        scores: dict[int, float] = {}
        for term in dict.fromkeys(self._tokenizer(query)):
            postings = self._postings.get(term)
            if postings is None:
                continue
            idf = self._idf[term]
            for index, tf in postings:
                norm = 1.0 - self.b + self.b * self._doc_len[index] / self._avgdl
                scores[index] = scores.get(index, 0.0) + idf * tf * (self.k1 + 1.0) / (
                    tf + self.k1 * norm
                )
        return {self._doc_ids[index]: score for index, score in scores.items()}

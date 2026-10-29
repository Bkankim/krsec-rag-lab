"""exact CVE-ID lookup - CVE 명시 질의의 하한선.

질의에서 `splits.extract_cve_ids`로 CVE ID를 뽑고, 그 ID를 키로 가진 문서를 돌려준다. 점수는 문서가
질의의 서로 다른 CVE ID를 몇 개 키로 가졌는가다(질의가 CVE 여러 개를 적으면 많이 맞는 문서가 앞선다).
CVE ID가 없는 질의와 코퍼스에 없는 ID는 빈 결과다. 문서의 키는 트랙이 정한다: 공개 트랙은 레코드 `id`
하나, KISA 트랙은 제목과 본문에서 뽑은 CVE ID다(data.py).
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping

from krsec_rag_lab.splits import extract_cve_ids, normalize_cve_id


class ExactCveIndex:
    def __init__(self, keys: Mapping[str, Iterable[str]]):
        self._by_cve: dict[str, list[str]] = defaultdict(list)
        for doc_id, cve_ids in keys.items():
            for cve_id in dict.fromkeys(normalize_cve_id(value) for value in cve_ids):
                self._by_cve[cve_id].append(doc_id)
        self.n_documents = len(keys)
        self.n_keys = len(self._by_cve)

    def score(self, query: str) -> dict[str, float]:
        scores: dict[str, float] = {}
        for cve_id in extract_cve_ids(query):
            for doc_id in self._by_cve.get(cve_id, ()):
                scores[doc_id] = scores.get(doc_id, 0.0) + 1.0
        return scores

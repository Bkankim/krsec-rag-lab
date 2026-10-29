# M3 실험 요약

M3 실험 5개(하이브리드+RRF, 리랭커, 청킹, 한영 교차, 임베딩 교체)의 판정을 한 표로 모은 문서다. 실험은 한 번에 한 요소만 바꿔
M2 베이스라인([baselines.md](../baselines.md), `results/baselines/`)과 비교했고, 가설·주 트랙·판정 규칙은 test를 돌리기 전에
고정했다(런 스펙 이슈 #43, 하네스 계약은 [README.md](README.md)). 실험마다 보고서가 있고 표의 실험 이름이 그 링크다.

## 판정 표

표는 `scripts/make_readme_tables.py`가 각 실험의 질문별 원시 결과(`results/experiments/<exp>/`)와 질의셋 라벨에서 하네스의 비교
함수로 다시 계산해 쓰고, 저장된 `comparison.json`·`metrics.json`과 abs 1e-9로 대조한 값이다. 손으로 옮기지 않는다.

<!-- BEGIN SUMMARY TABLES (scripts/make_readme_tables.py) -->

이 구간은 `scripts/make_readme_tables.py`가 `results/experiments/`의 질문별 원시 결과와 질의셋 라벨에서 하네스의 비교 함수(`krsec_rag_lab.experiments.compare`)로 다시 계산해 쓴다. 손으로 고치지 않는다. 검증: `uv run python scripts/make_readme_tables.py --check`. 지표는 test macro nDCG@10(condensed list, 정답이 있는 유형의 단순 평균)이고 delta = 실험 - 기준이다. 95% 구간은 test 질문을 유형별로 층화 복원추출한 paired bootstrap(10000회, 시드 20261029)의 2.5/97.5 백분위이며, delta > 0 이고 구간 하한 > 0 일 때만 `hypothesis-confirmed`다.

주 판정 5건: hypothesis-confirmed 0, hypothesis-rejected 5.

| 실험 | 가설 (사전 등록) | 주 트랙 (변형) | 기준 | test n | 기준 macro nDCG@10 | 실험 macro nDCG@10 | delta | 95% 구간 | 판정 | 보조 판정 | cve_explicit 회귀 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [hybrid](hybrid.md) | BM25와 dense(bge-m3)를 RRF로 합친 순위는 BM25 단독보다 test macro nDCG@10이 높다. | public (rrf) | bm25 | 74 | 0.8551 | 0.8775 | +0.0223 | [-0.0117, +0.0616] | `hypothesis-rejected` | kisa/rrf: `hypothesis-rejected` | 아니오 (+0.0000) |
| [rerank](rerank.md) | cross-encoder 리랭커(BAAI/bge-reranker-v2-m3)로 BM25 상위 N건을 다시 정렬하면 같은 후보군의 BM25 순서보다 test macro nDCG@10이 높다. | public (rerank) | bm25 | 74 | 0.8551 | 0.8581 | +0.0030 | [-0.0206, +0.0244] | `hypothesis-rejected` | kisa/rerank: `hypothesis-rejected` | 아니오 (+0.0000) |
| [chunking](chunking.md) | KISA 공지를 청크로 나눠 bge-m3로 인코딩하고 문서 점수를 청크 점수의 최댓값으로 두면, 문서 하나를 한 벡터로 만드는 dense 베이스라인보다 test macro nDCG@10이 높다. | kisa (chunk_max) | dense | 23 | 0.8131 | 0.8785 | +0.0654 | [-0.0082, +0.1510] | `hypothesis-rejected` | - | 아니오 (+0.1962) |
| [crossling](crossling.md) | 공개 트랙의 한국어 질문을 로컬 번역 모델로 영어로 바꿔(KO->EN) BM25로 검색하면, 원래 한국어 질문의 BM25보다 test macro nDCG@10이 높다. | public (bm25_ko2en) | bm25 | 74 | 0.8551 | 0.2771 | -0.5780 | [-0.6723, -0.4832] | `hypothesis-rejected` | public/dense_ko2en: `hypothesis-rejected` | 예 (-0.6335) |
| [embedding](embedding.md) | bge-m3 대신 다른 다국어 임베딩 모델 하나로 바꾸면(다른 조건은 같게: 색인 텍스트, 질의 문자열, 전수 내적 검색, 청킹 없음) dense 베이스라인보다 test macro nDCG@10이 높다. | public (swap) | dense | 74 | 0.4353 | 0.4393 | +0.0040 | [-0.0637, +0.0726] | `hypothesis-rejected` | kisa/swap: `hypothesis-rejected` | 예 (-0.0917) |

보조 비교 (같은 규칙의 판정이고 이슈 라벨은 주 판정을 따른다):

| 실험 | 비교 (트랙/변형) | 기준 | test n | 기준 macro nDCG@10 | 실험 macro nDCG@10 | delta | 95% 구간 | 판정 | cve_explicit 회귀 |
|---|---|---|---|---|---|---|---|---|---|
| hybrid | kisa/rrf | bm25 | 23 | 0.9451 | 0.9394 | -0.0057 | [-0.0606, +0.0530] | `hypothesis-rejected` | 예 (-0.0909) |
| rerank | kisa/rerank | bm25 | 23 | 0.9451 | 0.9451 | +0.0000 | [-0.0738, +0.0738] | `hypothesis-rejected` | 아니오 (+0.0000) |
| crossling | public/dense_ko2en | dense | 74 | 0.4353 | 0.2713 | -0.1641 | [-0.2417, -0.0891] | `hypothesis-rejected` | 예 (-0.0297) |
| embedding | kisa/swap | dense | 23 | 0.8131 | 0.7196 | -0.0935 | [-0.1657, -0.0235] | `hypothesis-rejected` | 예 (-0.2805) |

<!-- END SUMMARY TABLES (scripts/make_readme_tables.py) -->

표 읽는 법:

- 주 판정은 이슈 라벨과 `comparison.json`의 최상위 `primary`가 같은 대상이다. 보조 판정은 같은 규칙을 다른 트랙·변형에 적용한 것이다.
- `cve_explicit 회귀`는 판정과 별개로 `cve_explicit` 유형의 nDCG@10 delta가 0보다 작은지를 적는다(괄호는 그 delta). 런 스펙이
  판정 결과와 상관없이 명시하도록 정한 보조 항목이다.
- 유형별 delta와 n_scored < 10 유형(관찰로만 읽는다), hit@10·MRR@10, no_answer 기권, 색인 시간과 질의 지연은 각 실험 보고서의 4절,
  질문별 실패 사례는 6절에 있다. 시간 수치는 같은 맥에서 병렬로 돌린 참고값이다.

## 다음 실험 후보 (판정 없음)

아래는 이번 런의 판정이 아니라 후보 목록이다. 다섯 실험은 한 요소씩만 판정했고, 후보를 돌리려면 새 가설과 판정 규칙을 test 실행 전에
사전 등록해야 한다. 이번 결과를 본 뒤 설정을 바꿔 같은 가설을 다시 판정하지 않는다.

- 누적 조합: 하이브리드 위에 리랭커를 얹거나, 청킹을 하이브리드와 함께 쓰는 식으로 요소를 합친 구성. 이번 런은 합친 구성을 판정하지 않았다.
- 청킹(KISA 트랙)과 질문 수: 청킹은 주 판정이 기각이지만 delta의 부호와 구간이 표에 있다. 구간이 넓은 것은 test 질문이 적기 때문이므로,
  질문을 늘린 골든셋(M4)에서 같은 가설을 새로 등록해 다시 보는 후보다.
- 한영 교차: KO->EN 질의 번역은 두 변형 모두 기준보다 낮았다(표). 번역이 CVE ID를 바꾼 질문이 있다는 점이 보고서의 확인 사항이므로
  (crossling 보고서 4.7, 6.3절), ID를 보정한 번역이나 문서 쪽 번역은 새 가설이다.
- 임베딩 교체: 이번에는 공개 트랙 dev로 로드되는 후보 2개만 비교해 고른 모델 하나를 test에서 판정했다. 다른 모델 군이나 질의·문서 접두사 변형은 후보 범위를 넓힌 새 실험이다.
- 생성단 연결과 생성 평가(M5)는 검색 실험이 아니므로 이 목록 밖이다.

## 한계

- test 질문 수가 작다. 판정 구간은 test 질문을 유형별로 층화 복원추출한 질문 단위 bootstrap이라, 같은 공지·CVE를 쓰는 질문의 의존을
  독립으로 다뤄 구간을 좁게 낼 수 있다(dev와 test 사이는 [eval-protocol.md](../eval-protocol.md) 6절의 그룹 분할로 분리돼 있다).
- `hypothesis-rejected`는 "이 설정이 이 표본에서 기준을 이긴다는 증거가 없다"는 뜻이다. 효과가 없다는 증명이 아니고, 구간이 0을 걸친
  실험과 구간 전체가 0 아래인 실험을 같은 라벨 안에서 구분해 읽어야 한다(표의 delta와 95% 구간).
- n_scored < 10인 유형은 관찰로만 읽고 유형별 우열 주장에 쓰지 않는다. macro에는 들어간다.
- 정답은 공개 트랙이 NVD 메타데이터, KISA 트랙이 두 LLM의 교차 판정이다(사람 검수 아님, 한계: [release-v0.1.md](../release-v0.1.md) 한계 절).
- 설정은 dev에서만 골랐고 test는 확정 설정으로 한 번 돌았다. 결과를 본 뒤 설정·가설·판정 규칙을 바꾸지 않았다. 설정을 바꾸는 재시도는
  새 가설이며 이번 런에서 하지 않았다.
- 시간 수치는 같은 맥(Apple M5 Pro, 18코어, `OMP_NUM_THREADS=4`)에서 실험을 병렬로 돌린 참고값이다. 청크 단위 지표처럼 저장된 순위에서
  다시 계산할 수 없는 값은 manifest의 `description` 값이고 `--compare` 범위 밖이다(청킹 보고서).
- KISA 트랙 실험은 로컬 KISA 캐시가 있어야 다시 돌릴 수 있다. 캐시 없이는 저장본에서의 재계산(`--compare`)과 이 표의 검증까지만 된다.

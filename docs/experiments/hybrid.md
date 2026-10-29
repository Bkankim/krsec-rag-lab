# 하이브리드 + RRF 실험 (`hybrid`)

결과: 주 트랙(공개)은 `hypothesis-rejected`, 보조 트랙(KISA)도 `hypothesis-rejected`다. 사전 등록한 설정으로 test를 한 번 돌렸고 결과를 본 뒤 설정·가설·판정 규칙을 바꾸지 않았다. 하네스 계약은 [README.md](README.md), 판정 규칙의 정본은 런 스펙 이슈 #43의 "실험 공통 규칙"이다.

## 1. 가설 (사전 등록)

- 가설: BM25와 dense(bge-m3)를 RRF로 합친 순위는 BM25 단독보다 test macro nDCG@10이 높다.
- 주 트랙: 공개 트랙, 기준 = `results/baselines/public/bm25.jsonl`. KISA 트랙(기준 = `results/baselines/kisa/bm25.jsonl`)은 같은 규칙의 보조 판정이다. 이슈 라벨은 주 트랙 판정을 따른다.
- 판정: test macro nDCG@10의 `delta = 실험 - 기준`이 0보다 크고, 유형별 층화 paired bootstrap(10000회, 시드 `20261029`) 95% 구간의 하한이 0보다 크면 `hypothesis-confirmed`, 그 밖은 `hypothesis-rejected`.

## 2. 구성

- BM25: 기준선 manifest에 확정된 트랙별 설정과 `bm25-tok-v1` 토큰화를 그대로 쓴다 (공개 k1=1.2, b=0.75; KISA k1=3.0, b=0.9). 일치 문서가 없으면 BM25 순위는 비어 있다.
- dense: 기준선과 같은 bge-m3 dense 표현(`baselines.dense.build_dense_index`): `BAAI/bge-m3` revision `5617a9f61b028005a4858fdac845db406aefb181`, CLS pooling, L2 정규화, float32, max_seq_length 8192, CPU. 코퍼스 전체에 점수를 매긴다.
- 융합: RRF 점수 = sum over {BM25, dense} 1 / (k + rank). rank는 각 검색기의 **전체 순위**(unjudged 제거 전, BM25는 일치 문서만)이고, 한 검색기에 없는 문서는 그 검색기 항이 없다. 점수가 같으면 문서 ID 오름차순이고, unjudged 제거와 상위 100건 저장은 기준선과 같은 공통 채점 코드가 한다.
- k: 격자 {10, 30, 60, 100}에서 트랙마다 dev macro nDCG@10이 가장 큰 값. 최댓값이 여럿(abs 1e-12 이내)이면 60, 60이 그중에 없으면 그중 가장 작은 값.
- τ(no_answer 기권 임계값): 기준선과 같은 규칙(dev에서 abstain_rate - false_abstain_rate 최대, 같으면 가장 낮은 τ)으로 RRF 점수의 원래 1위 점수에 대해 dev에서 고른다.
- 가중 RRF, 학습형 융합, 리랭킹은 이 실험 범위 밖이다.

## 3. 재현 명령

`<KISA-ROOT>`는 KISA 캐시(`data/kisa`)가 있는 체크아웃이다. 모델이 필요한 실행은 `embed` 그룹을 쓴다. 측정은 `OMP_NUM_THREADS=4`로 했다.

```
uv sync --locked --group embed
OMP_NUM_THREADS=4 uv run --no-sync python scripts/run_experiment.py --exp hybrid --track public --split dev   # k, tau 선택(몇 번 돌려도 됨)
OMP_NUM_THREADS=4 uv run --no-sync python scripts/run_experiment.py --exp hybrid --track public              # dev 선택 뒤 test 1회
OMP_NUM_THREADS=4 uv run --no-sync python scripts/run_experiment.py --exp hybrid --track kisa --kisa-root <KISA-ROOT>
uv sync --locked --dev
uv run python scripts/run_experiment.py --exp hybrid --compare   # 모델·KISA 캐시 없이 저장본에서 metrics·comparison을 다시 계산해 대조(불일치 exit 1)
OMP_NUM_THREADS=4 uv run --group embed python scripts/run_experiment.py --exp hybrid --track public --out-dir <빈 디렉터리>   # 재현 확인: 커밋된 결과를 건드리지 않고 같은 저장본이 나와야 한다
```

산출물: `results/experiments/hybrid/{public,kisa}/rrf.jsonl`, `manifest.json`, `metrics.json`, `comparison.json`. test 설정 해시는 manifest의 `runs[<track>/rrf].test.config_hash`다.

## 4. 결과

### 4.1 dev에서 고른 설정

| 트랙 | k=10 | k=30 | k=60 | k=100 | 선택 k | τ | 비고 |
|---|---|---|---|---|---|---|---|
| public | 0.8284 | 0.8272 | 0.8277 | 0.8277 | 10 | 0.091712 | k=60과 k=100은 같은 값이고 k=10이 단독 최댓값이라 동점 규칙을 쓰지 않았다 |
| kisa | 0.9384 | 0.9384 | 0.9247 | 0.9247 | 10 | 0.135965 | k=10과 k=30이 같은 최댓값이고 60이 그중에 없어 가장 작은 k=10 (동점 규칙 적용) |

값은 dev macro nDCG@10이다. 기준선 BM25의 dev macro는 공개 0.8533, KISA 0.7970다.

### 4.2 test 판정 (macro nDCG@10)

| 트랙 | 역할 | 기준(BM25) | 실험(RRF) | delta | 95% 구간 | 판정 |
|---|---|---|---|---|---|---|
| public | 주 | 0.8551 | 0.8775 | +0.0223 | [-0.0117, +0.0616] | `hypothesis-rejected` |
| kisa | 보조 | 0.9451 | 0.9394 | -0.0057 | [-0.0606, +0.0530] | `hypothesis-rejected` |

`comparison.json`의 `primary`는 공개 트랙 판정(`hypothesis-rejected`)이고 `secondary`는 KISA 판정이다. 구간은 test 질문을 유형별로 층화 복원추출한 10000회의 2.5/97.5 백분위다. test 질문 수(정답이 있는 비제외 질문)는 공개 74건, KISA 23건이다.

### 4.3 유형별 delta (test)

n_scored < 10인 유형은 관찰로만 읽고 우열 주장에 쓰지 않는다(`observation_only`). macro에는 들어간다.

| 트랙 | 유형 | n_scored | 관찰만 | nDCG@10 기준 | nDCG@10 실험 | delta | hit@10 delta | MRR@10 delta |
|---|---|---|---|---|---|---|---|---|
| public | cve_explicit | 35 | 아니오 | 1.0000 | 1.0000 | +0.0000 | +0.0000 | +0.0000 |
| public | product_symptom | 39 | 아니오 | 0.7103 | 0.7549 | +0.0447 | +0.0513 | +0.0624 |
| kisa | cve_explicit | 11 | 아니오 | 0.9091 | 0.8182 | -0.0909 | +0.0000 | -0.1212 |
| kisa | explanation_comparison | 5 | 예 | 0.9262 | 1.0000 | +0.0738 | +0.0000 | +0.1000 |
| kisa | product_symptom | 7 | 예 | 1.0000 | 1.0000 | +0.0000 | +0.0000 | +0.0000 |

### 4.4 macro hit@10, MRR@10 (test)

| 트랙 | hit@10 기준 | hit@10 실험 | delta | MRR@10 기준 | MRR@10 실험 | delta |
|---|---|---|---|---|---|---|
| public | 0.8974 | 0.9231 | +0.0256 | 0.8539 | 0.8850 | +0.0312 |
| kisa | 0.9697 | 0.9697 | +0.0000 | 0.9364 | 0.9293 | -0.0071 |

### 4.5 `cve_explicit` 회귀 여부 (판정과 별개)

- public: `cve_explicit` nDCG@10 delta +0.0000 -> **회귀 없음**.
- kisa: `cve_explicit` nDCG@10 delta -0.0909 -> **회귀 있음**.

### 4.6 no_answer 기권 (test, τ는 각자 dev에서 고름)

| 트랙 | 검색기 | τ | no_answer 기권율(높을수록 좋음) | 정답 질문 오기권율(낮을수록 좋음) | n_no_answer | n_answerable |
|---|---|---|---|---|---|---|
| public | BM25 | 5.191784 | 1.0000 | 0.1351 | 12 | 74 |
| public | RRF | 0.091712 | 1.0000 | 0.0811 | 12 | 74 |
| kisa | BM25 | 11.436208 | 1.0000 | 0.3043 | 6 | 23 |
| kisa | RRF | 0.135965 | 0.8333 | 0.2174 | 6 | 23 |

BM25와 RRF의 점수 척도가 달라(RRF 점수는 최대 약 2/(k+1)) τ는 검색기마다 따로 고른 값이다. 척도가 다른 τ끼리 크기를 비교하지 않는다.

### 4.7 색인 시간과 질의 지연 (참고값)

측정 환경: Apple M5 Pro, 18코어, `OMP_NUM_THREADS=4`, CPU 추론. 같은 맥에서 다른 작업이 함께 돌았을 수 있어 참고값으로만 읽는다.

| 트랙 | 검색기 | 색인(setup) 초 | 질의 지연 중앙값 초 |
|---|---|---|---|
| public | BM25 | 0.010 | 0.000005 |
| public | RRF(BM25 + dense 질의 인코딩 포함) | 57.673 | 0.035903 |
| kisa | BM25 | 0.010 | 0.000029 |
| kisa | RRF(BM25 + dense 질의 인코딩 포함) | 55.772 | 0.035466 |

RRF의 색인 시간은 BM25 색인과 bge-m3 코퍼스 인코딩을 합친 값이고, 질의 지연은 질의마다 bge-m3로 질의를 인코딩하는 비용이 대부분이다. 기준선 BM25 값은 기준선 manifest에서 가져왔다.

## 5. 판정

- **주 판정(공개 트랙): `hypothesis-rejected`.** delta +0.0223는 양수지만 95% 구간 [-0.0117, +0.0616]의 하한이 0 이하라 BM25 단독보다 높다고 주장할 수 없다.
- **보조 판정(KISA 트랙): `hypothesis-rejected`.** delta -0.0057, 95% 구간 [-0.0606, +0.0530]. 점추정치부터 음수이고 `cve_explicit` 회귀가 있다.
- 결과가 가설을 기각해도 정상 종료다. 이슈 라벨은 `comparison.json`의 `primary.verdict`대로 `hypothesis-rejected`다.

## 6. 실패 사례 분석

질문 문장과 문서 본문은 쓰지 않고 질문 ID만 쓴다. 순위는 저장된 condensed 상위 100건 안의 첫 정답 순위이고 "범위 밖"은 그 안에 정답이 없다는 뜻이다(전체 순위에서 미검색인지와 구분하지 못한다). 아래 "확인"은 저장된 결과 파일(기준선 BM25·dense 저장본과 이 실험의 저장본)에서 직접 계산한 사실이고, "추정"은 그 사실로부터의 해석이다.

### 6.1 공개 트랙(NVD, 문서 = CVE 레코드)

악화 질문 7건(전부), 개선 7건(표에는 상위 7건), 변화 없음 60건.

| 구분 | 질문 ID | 유형 | 첫 정답 순위 전(BM25) | 후(RRF) | nDCG@10 전 | nDCG@10 후 | delta |
|---|---|---|---|---|---|---|---|
| 악화 | pub-prod-0035 | product_symptom | 7 | 13 | 0.3333 | 0.0000 | -0.3333 |
| 악화 | pub-prod-0042 | product_symptom | 8 | 15 | 0.3155 | 0.0000 | -0.3155 |
| 악화 | pub-prod-0033 | product_symptom | 1 | 2 | 0.9052 | 0.6699 | -0.2353 |
| 악화 | pub-prod-0015 | product_symptom | 1 | 1 | 0.9306 | 0.7264 | -0.2042 |
| 악화 | pub-prod-0030 | product_symptom | 2 | 2 | 0.7799 | 0.6285 | -0.1514 |
| 악화 | pub-prod-0047 | product_symptom | 3 | 2 | 0.1834 | 0.1389 | -0.0445 |
| 악화 | pub-prod-0048 | product_symptom | 1 | 1 | 1.0000 | 0.9670 | -0.0330 |
| 개선 | pub-prod-0041 | product_symptom | 범위 밖 | 1 | 0.0000 | 1.0000 | +1.0000 |
| 개선 | pub-prod-0004 | product_symptom | 범위 밖 | 1 | 0.0000 | 0.6131 | +0.6131 |
| 개선 | pub-prod-0007 | product_symptom | 범위 밖 | 3 | 0.0000 | 0.5000 | +0.5000 |
| 개선 | pub-prod-0019 | product_symptom | 범위 밖 | 5 | 0.0000 | 0.4416 | +0.4416 |
| 개선 | pub-prod-0017 | product_symptom | 2 | 1 | 0.6309 | 1.0000 | +0.3691 |
| 개선 | pub-prod-0060 | product_symptom | 1 | 1 | 0.7386 | 0.8116 | +0.0730 |
| 개선 | pub-prod-0031 | product_symptom | 1 | 1 | 0.8826 | 0.9456 | +0.0630 |

### 6.2 KISA 트랙(문서 = nttId)

악화 질문 2건(전부), 개선 1건(표에는 상위 1건), 변화 없음 20건.

| 구분 | 질문 ID | 유형 | 첫 정답 순위 전(BM25) | 후(RRF) | nDCG@10 전 | nDCG@10 후 | delta |
|---|---|---|---|---|---|---|---|
| 악화 | g1-cve-2026-10816 | cve_explicit | 1 | 3 | 1.0000 | 0.5000 | -0.5000 |
| 악화 | g1-cve-2026-63030 | cve_explicit | 1 | 3 | 1.0000 | 0.5000 | -0.5000 |
| 개선 | g1-ec-10 | explanation_comparison | 2 | 1 | 0.6309 | 1.0000 | +0.3691 |

### 6.3 원인

**공개 트랙**

- 확인: 개선 상위 4건(`pub-prod-0041`, `pub-prod-0004`, `pub-prod-0007`, `pub-prod-0019`)은 기준선에서 첫 정답이 저장 범위 밖이다. BM25 결과가 비어 있거나(0041, 0004, 0019) 4건뿐인데 정답이 없었고(0007), bge-m3 dense는 정답을 1~5위에 두었다. RRF에서는 BM25 항이 없는 문서도 dense 항만으로 순위를 얻으므로 이 질문들이 구제됐다. 이 4건의 delta 합이 개선분의 대부분이다.
- 확인: 악화 7건 중 `pub-prod-0035`, `pub-prod-0042`는 정답이 BM25 7위, 8위인데 dense 저장본(상위 100건)에는 정답이 없다. RRF에서는 정답이 BM25 항 하나만 받고, 상위 10건에서 정답이 빠져 13위, 15위가 됐다(상위 10건 안 정답 수 BM25 1건 -> RRF 0건).
- 확인: `pub-prod-0015`, `pub-prod-0030`, `pub-prod-0033`은 정답이 45~56건인 질문이다. 첫 정답 순위는 같거나 한 칸 차이인데 상위 10건 안 정답 수가 BM25 9건에서 RRF 7~8건으로 줄어 nDCG@10이 내려갔다(dense 단독의 상위 10건 정답은 3~8건이었다).
- 추정: 정답이 많은 질문에서는 BM25가 잘 맞추는 상위 구간에 dense가 놓은 비정답 문서가 섞여 들어와 정답을 밀어낸다. 문서 본문을 보지 않았으므로 섞인 문서가 어떤 문서인지는 확인하지 못했다.
- 확인: `cve_explicit` 35건은 BM25와 RRF 모두 nDCG@10 1.0으로 변화가 없다(dense 단독은 0.2271). 공개 트랙에서는 dense가 약한 `cve_explicit`에서 RRF가 BM25의 완전한 순위를 깨지 않았다.
- 확인: dev에서는 RRF(0.8284)가 BM25(0.8533)보다 낮았고 test에서는 높았다. dev와 test에서 방향이 다르다. 추정: 표본 변동이며, 한쪽 분할의 결과로 우열을 주장하기 어렵다.

**KISA 트랙**

- 확인: 악화 2건(`g1-cve-2026-10816`, `g1-cve-2026-63030`)은 모두 `cve_explicit`이다. 정답이 BM25 1위였고 dense 저장본에서는 22위, 33위였는데 RRF에서 3위가 됐다. dense 단독의 KISA `cve_explicit` nDCG@10은 0.4394(BM25 0.9091)이다. 추정: dense는 CVE 번호 문자열 일치를 잘 잡지 못해 `cve_explicit`에서 정답에 낮은 순위를 준다.
- 산술 예(추정의 근거): 선택된 k=10에서 BM25 1위와 dense 22위를 받은 문서의 RRF 점수는 1/11 + 1/32 = 0.1222이고, BM25 2위와 dense 1위를 받은 문서는 1/12 + 1/11 = 0.1742다. 두 검색기에서 모두 상위인 비정답이 한쪽에서만 1위인 정답을 앞설 수 있다. 앞선 문서가 실제로 그런 순위였는지는 저장본(상위 100건)으로 이 질문들에 대해 확인하지 않았다.
- 확인: 개선 1건(`g1-ec-10`, `explanation_comparison`)은 정답이 BM25 2위, dense 1위였고 RRF 1위가 됐다. 유형별 delta의 `explanation_comparison`, `product_symptom`은 n_scored 5, 7이라 관찰로만 읽는다.
- 확인: dev에서는 RRF가 BM25보다 크게 높았지만(0.9384 대 0.7970) test에서는 기준선 BM25 0.9451, RRF 0.9394로 차이가 거의 없다. 같은 설정으로 test를 한 번만 돌았으므로 이 차이를 보고 설정을 바꾸지 않았다.

## 7. 한계

- 질문 단위 재표집은 test 안 질문끼리의 의존(같은 공지·CVE를 쓰는 질문)을 독립으로 다뤄 구간을 실제보다 좁게 낼 수 있다. dev와 test 사이는 eval-protocol 6절의 그룹 분할로 이미 분리돼 있다.
- KISA 트랙 test는 정답이 있는 질문 23건이고 `product_symptom`(7건), `explanation_comparison`(5건)은 n_scored < 10이라 유형별 우열을 주장할 수 없다. 구간이 넓다([-0.0606, +0.0530]). 어느 방향의 효과도 이 표본으로는 확인하지 못한다.
- 첫 정답 순위는 저장된 상위 100건 안의 순위다. "범위 밖"은 전체 순위에서 미검색인지 단지 100위 밖인지 구분하지 못한다.
- k 격자는 4개 값이고 dev macro의 차이가 작다(공개 최댓값과 최솟값의 차이 약 0.0012). 선택은 규칙대로 했지만 이 격자 안의 k 사이에서 test 결과가 안정적이라고 확인한 것은 아니다. test는 선택한 k 하나만 돌았다.
- τ는 RRF 점수 척도에 대해 dev에서 고른 값이고, no_answer 질문은 공개 12건, KISA 6건이라 기권율은 거친 값이다. 기준선과 척도가 다른 τ를 직접 비교하지 않는다.
- 기준선과 같은 입력 텍스트·같은 질의 전처리를 썼으므로 이 결과는 "BM25 + bge-m3 dense를 RRF로 합친 단순 융합" 하나에만 해당한다. 가중 RRF, 다른 융합 방식, 질의 재작성은 측정하지 않았다.
- 질의 지연과 색인 시간은 참고값이다. 다른 작업과 같은 맥에서 돌았을 수 있고 CPU 추론이다.
- test는 확정 설정으로 한 번 돌았다. 같은 설정으로 빈 `--out-dir`에 다시 돌린 재현 실행은 두 트랙의 `rrf.jsonl`과 `metrics.json`이 커밋된 파일과 바이트까지 같았고(`comparison.json`은 참고값인 색인 시간·지연만 달랐다), 이 보고서의 숫자는 커밋된 첫 실행을 기준으로 한다.

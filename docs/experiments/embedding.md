# 임베딩 교체 실험 (`embedding`)

결과: 주 트랙(공개)은 `hypothesis-rejected`, 보조 트랙(KISA)도 `hypothesis-rejected`다. 공개 트랙은 delta가 +0.0040으로 사실상 같고 구간이 0을 넘나든다. KISA 트랙은 delta -0.0935이고 구간 전체가 0 아래라 bge-m3보다 낮다. 사전 등록한 설정으로 test를 트랙마다 한 번 돌렸고 결과를 본 뒤 설정·가설·판정 규칙을 바꾸지 않았다. 하네스 계약은 [README.md](README.md), 판정 규칙의 정본은 런 스펙 이슈 #43의 "실험 공통 규칙"이다.

## 1. 가설 (사전 등록)

- 가설: bge-m3 대신 다른 다국어 임베딩 모델 하나로 바꾸면(다른 조건은 같게: 색인 텍스트, 질의 문자열, 전수 내적 검색, 청킹 없음) dense 베이스라인보다 test macro nDCG@10이 높다.
- 주 트랙: 공개 트랙, 기준 = `results/baselines/public/dense.jsonl`. KISA 트랙(기준 = `results/baselines/kisa/dense.jsonl`)은 같은 규칙의 보조 판정이다. 이슈 라벨은 주 트랙 판정을 따른다.
- 판정: test macro nDCG@10의 `delta = 실험 - 기준`이 0보다 크고, 유형별 층화 paired bootstrap(10000회, 시드 `20261029`) 95% 구간의 하한이 0보다 크면 `hypothesis-confirmed`, 그 밖은 `hypothesis-rejected`.

## 2. 구성

- 바꾼 것은 임베딩 모델(과 그 모델의 정해진 접두사)뿐이다. 색인 텍스트(공개: `id + 공백 + description_en`, KISA: `제목 + 줄바꿈 + 본문`), 질의 문자열, 청킹 없음, L2 정규화, float32, CPU, 정규화 벡터의 전수 내적, 상위 100건 저장은 기준선(bge-m3, revision `5617a9f61b028005a4858fdac845db406aefb181`)과 같다.
- 모델 고유로 따르는 것: pooling, 질의·문서 접두사(모델 카드의 사용법), 최대 길이(모델 최대와 8192 중 작은 값). 접두사는 질의·문서 문자열 앞에 그대로 붙인다.
- 후보 선택(공개 트랙 dev만 사용): 로드되는 후보 2개를 공개 트랙 dev macro nDCG@10으로 비교해 높은 쪽을 고른다. 같으면(abs 1e-12 이내) 파라미터가 적은 쪽, 그것도 같으면 모델 ID 사전순. 고른 모델 하나를 두 트랙에 고정한다. KISA 트랙의 격자는 그 모델 하나이고 KISA dev로는 τ만 고른다. 탈락 후보는 test 질의를 인코딩하지 않는다.
- τ(no_answer 기권 임계값): 기준선과 같은 규칙(dev에서 abstain_rate - false_abstain_rate 최대, 같으면 가장 낮은 τ)으로 트랙마다 dev에서 고른다.

### 2.1 후보와 제외

| 후보 | revision | 파라미터 | pooling | 최대 길이 | 질의 접두사 | 문서 접두사 | 상태 |
|---|---|---|---|---|---|---|---|
| `intfloat/multilingual-e5-large` | `3d7cfbdacd47fdda877c5cd8a79fbcc4f2a574f3` | 559,890,432 | mean | 512 | `query: ` | `passage: ` | 로드 성공 |
| `Qwen/Qwen3-Embedding-0.6B` | `97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3` | 595,776,512 | last token | 8192 (모델 최대 32768) | `Instruct: Given a web search query, retrieve relevant passages that answer the query` + 줄바꿈 + `Query:` | 없음 | 로드 성공 |
| `google/embeddinggemma-2` | `914f7f89142e33e77833254d9c9b90c3cef7303b` | - | - | - | - | - | 제외 |

- 제외 사유: 지금 lock의 transformers 5.17.0이 모델 유형 `embedding_gemma2`를 인식하지 못해 `SentenceTransformer(...)` 로드가 `ValueError`로 실패했다(체크포인트는 transformers 5.18.0.dev0 기준). `pyproject.toml`·`uv.lock`은 이 티켓이 바꾸지 않으므로 후보에서 뺐다.
- 두 후보 모두 `sentence_transformers` 6.1.0, `torch` 2.14.1, `transformers` 5.17.0(모두 lock 그대로)에서 float32 CPU로 로드된다. 접두사와 질의·문서 형식은 각 모델 카드와 `config_sentence_transformers.json`의 `prompts`를 따랐다.
- 후보 둘은 이 머신 캐시와 Hugging Face 공개 가중치(revision 고정)에서 가져왔다. 후보 3개 이상 비교, 파인튜닝, 양자화는 범위 밖이다.

## 3. 재현 명령

`<KISA-ROOT>`는 KISA 캐시(`data/kisa`)가 있는 체크아웃이다. 모델이 필요한 실행은 `embed` 그룹을 쓴다. 측정은 `OMP_NUM_THREADS=4`로 했다. 공개 트랙을 먼저 끝내야 KISA 트랙이 고른 모델을 읽는다(같은 실험의 두 트랙은 순서대로 돌린다).

```
uv sync --locked --group embed
OMP_NUM_THREADS=4 uv run --no-sync python scripts/run_experiment.py --exp embedding --track public --split dev   # 후보 선택, tau (몇 번 돌려도 됨)
OMP_NUM_THREADS=4 uv run --no-sync python scripts/run_experiment.py --exp embedding --track public --split test  # 확정 설정으로 test 1회 (--split all은 dev 선택 뒤 test 1회)
OMP_NUM_THREADS=4 uv run --no-sync python scripts/run_experiment.py --exp embedding --track kisa --kisa-root <KISA-ROOT>
uv sync --locked --dev
uv run python scripts/run_experiment.py --exp embedding --compare   # 모델·KISA 캐시 없이 저장본에서 metrics·comparison을 다시 계산해 대조(불일치 exit 1)
```

산출물: `results/experiments/embedding/{public,kisa}/swap.jsonl`, `manifest.json`, `metrics.json`, `comparison.json`. test 설정 해시는 manifest의 `runs[<track>/swap].test.config_hash`다. 이번 실행에서는 재현 실행(빈 `--out-dir`에 같은 설정으로 다시 돌리기)을 하지 않았다.

## 4. 결과

### 4.1 후보별 dev와 선택 (공개 트랙)

| 후보 | revision | 파라미터 | dev macro nDCG@10 | 선택 |
|---|---|---|---|---|
| `intfloat/multilingual-e5-large` | `3d7cfbdacd47fdda877c5cd8a79fbcc4f2a574f3` | 559,890,432 | 0.4890 | 선택 |
| `Qwen/Qwen3-Embedding-0.6B` | `97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3` | 595,776,512 | 0.3918 | 탈락 |

참고: 기준선 bge-m3의 공개 dev macro는 0.3977이다. e5가 단독 최댓값이라 동점 규칙은 쓰지 않았다. 탈락한 Qwen3는 dev 질의만 인코딩했고 test 질의는 인코딩하지 않았다. 선택은 `manifest.json`의 `runs["public/swap"].grid`에 규칙과 함께 있다.

KISA 트랙은 위에서 고른 e5 하나에 고정했다(KISA dev macro 0.8369, 기준선 bge-m3의 KISA dev macro 0.8802).

| 트랙 | 선택 모델 | τ | dev 기권율 | dev 오기권율 |
|---|---|---|---|---|
| public | `intfloat/multilingual-e5-large` | 0.843979 | 0.7500 | 0.5000 |
| kisa | `intfloat/multilingual-e5-large` | 0.867720 | 0.7500 | 0.2632 |

### 4.2 test 판정 (macro nDCG@10)

| 트랙 | 역할 | 기준(bge-m3) | 실험(e5-large) | delta | 95% 구간 | 판정 |
|---|---|---|---|---|---|---|
| public | 주 | 0.4353 | 0.4393 | +0.0040 | [-0.0637, +0.0726] | `hypothesis-rejected` |
| kisa | 보조 | 0.8131 | 0.7196 | -0.0935 | [-0.1657, -0.0235] | `hypothesis-rejected` |

`comparison.json`의 `primary`는 공개 트랙 판정(`hypothesis-rejected`)이고 `secondary`는 KISA 판정이다. 구간은 test 질문을 유형별로 층화 복원추출한 10000회의 2.5/97.5 백분위다. test 질문 수(정답이 있는 비제외 질문)는 공개 74건, KISA 23건이다.

### 4.3 유형별 delta (test)

n_scored < 10인 유형은 관찰로만 읽고 우열 주장에 쓰지 않는다(`observation_only`). macro에는 들어간다.

| 트랙 | 유형 | n_scored | 관찰만 | nDCG@10 기준 | nDCG@10 실험 | delta | hit@10 delta | MRR@10 delta |
|---|---|---|---|---|---|---|---|---|
| public | cve_explicit | 35 | 아니오 | 0.2271 | 0.1354 | -0.0917 | -0.0857 | -0.0924 |
| public | product_symptom | 39 | 아니오 | 0.6436 | 0.7433 | +0.0998 | +0.0256 | +0.0575 |
| kisa | cve_explicit | 11 | 아니오 | 0.4394 | 0.1589 | -0.2805 | -0.1818 | -0.3097 |
| kisa | explanation_comparison | 5 | 예 | 1.0000 | 1.0000 | +0.0000 | +0.0000 | +0.0000 |
| kisa | product_symptom | 7 | 예 | 1.0000 | 1.0000 | +0.0000 | +0.0000 | +0.0000 |

### 4.4 macro hit@10, MRR@10 (test)

| 트랙 | hit@10 기준 | hit@10 실험 | delta | MRR@10 기준 | MRR@10 실험 | delta |
|---|---|---|---|---|---|---|
| public | 0.5531 | 0.5231 | -0.0300 | 0.4517 | 0.4343 | -0.0174 |
| kisa | 0.8485 | 0.7879 | -0.0606 | 0.8023 | 0.6991 | -0.1032 |

### 4.5 `cve_explicit` 회귀 여부 (판정과 별개)

- public: `cve_explicit` nDCG@10 delta -0.0917 -> **회귀 있음**.
- kisa: `cve_explicit` nDCG@10 delta -0.2805 -> **회귀 있음**.

### 4.6 no_answer 기권 (test, τ는 각자 dev에서 고름)

| 트랙 | 검색기 | τ | no_answer 기권율(높을수록 좋음) | 정답 질문 오기권율(낮을수록 좋음) | n_no_answer | n_answerable |
|---|---|---|---|---|---|---|
| public | bge-m3 | 0.607314 | 0.6667 | 0.5270 | 12 | 74 |
| public | e5-large | 0.843979 | 0.6667 | 0.5000 | 12 | 74 |
| kisa | bge-m3 | 0.614911 | 0.5000 | 0.2174 | 6 | 23 |
| kisa | e5-large | 0.867720 | 0.5000 | 0.2609 | 6 | 23 |

e5의 코사인 점수는 좁은 구간(0.7~0.9대)에 몰려 τ가 높다. τ는 모델마다 따로 고른 값이라 크기를 직접 비교하지 않는다.

### 4.7 색인 시간과 질의 지연, 잘린 문서 (참고값)

측정 환경: Apple M5 Pro, 18코어, `OMP_NUM_THREADS=4`, CPU 추론, torch 2.14.1, sentence-transformers 6.1.0, 배치 8. 같은 맥에서 다른 실험이 병렬로 돌았을 수 있어 참고값으로만 읽는다.

| 트랙 | 검색기 | 색인(setup) 초 | 문서 인코딩 초 | 질의 지연 중앙값 초 | 잘린 문서 수 | 최대 문서 토큰 |
|---|---|---|---|---|---|---|
| public | bge-m3 (기준선 manifest) | 62.837 | - | 0.044774 | 0 / 1560 (한도 8192) | 517 |
| public | e5-large | 231.299 (두 후보 인코딩 합) | 92.033 | 0.073224 | 1 / 1560 (한도 512) | 519 |
| public | Qwen3-0.6B (탈락) | (위 setup에 포함) | 134.060 | - | 0 / 1560 (한도 8192) | 445 |
| kisa | bge-m3 (기준선 manifest) | 56.581 | - | 0.045202 | 2 / 50 (한도 8192) | 22749 |
| kisa | e5-large | 29.181 | 25.500 | 0.075178 | 27 / 50 (한도 512) | 22751 |

공개 트랙 e5 색인 시간 231초는 e5와 Qwen3 두 후보의 문서 인코딩과 모델 로드를 합친 값이다. 잘린 문서 수와 최대 토큰 수는 접두사를 붙인 입력 기준이고 manifest의 `description.models_loaded`에 있다(저장 결과에서 다시 계산할 수 없는 `description` 값이다).

## 5. 판정

- **주 판정(공개 트랙): `hypothesis-rejected`.** delta +0.0040는 양수지만 95% 구간 [-0.0637, +0.0726]의 하한이 0 이하라 e5가 bge-m3보다 높다고 주장할 수 없다.
- **보조 판정(KISA 트랙): `hypothesis-rejected`.** delta -0.0935이고 95% 구간 [-0.1657, -0.0235]이 전부 0 아래다. 이 표본에서는 e5가 bge-m3보다 낮다.
- 결과가 가설을 기각해도 정상 종료다. 이슈 라벨은 `comparison.json`의 `primary.verdict`대로 `hypothesis-rejected`다.

## 6. 실패 사례 분석

질문 문장과 문서 본문은 쓰지 않고 질문 ID만 쓴다. 순위는 저장된 condensed 상위 100건 안의 첫 정답 순위이고 "범위 밖"은 그 안에 정답이 없다는 뜻이다(전체 순위에서 미검색인지와 구분하지 못한다). 아래 "확인"은 저장된 결과 파일(기준선 bge-m3 저장본과 이 실험의 저장본)과 manifest에서 직접 확인한 사실이고, "추정"은 그 사실로부터의 해석이다.

### 6.1 공개 트랙(NVD, 문서 = CVE 레코드)

악화 질문 15건(전부), 개선 16건(표에는 상위 10건), 변화 없음 43건.

| 구분 | 질문 ID | 유형 | 첫 정답 순위 전(bge-m3) | 후(e5) | nDCG@10 전 | nDCG@10 후 | delta |
|---|---|---|---|---|---|---|---|
| 악화 | pub-cve-0018 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0048 | cve_explicit | 1 | 17 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0010 | cve_explicit | 1 | 5 | 1.0000 | 0.3869 | -0.6131 |
| 악화 | pub-prod-0051 | product_symptom | 1 | 4 | 1.0000 | 0.4307 | -0.5693 |
| 악화 | pub-cve-0015 | cve_explicit | 4 | 20 | 0.4307 | 0.0000 | -0.4307 |
| 악화 | pub-cve-0058 | cve_explicit | 5 | 64 | 0.3869 | 0.0000 | -0.3869 |
| 악화 | pub-cve-0036 | cve_explicit | 1 | 2 | 1.0000 | 0.6309 | -0.3691 |
| 악화 | pub-prod-0036 | product_symptom | 1 | 2 | 1.0000 | 0.6309 | -0.3691 |
| 악화 | pub-cve-0012 | cve_explicit | 3 | 10 | 0.5000 | 0.2891 | -0.2109 |
| 악화 | pub-cve-0001 | cve_explicit | 2 | 4 | 0.6309 | 0.4307 | -0.2003 |
| 악화 | pub-prod-0015 | product_symptom | 1 | 6 | 0.5442 | 0.3511 | -0.1932 |
| 악화 | pub-prod-0058 | product_symptom | 1 | 1 | 1.0000 | 0.8415 | -0.1585 |
| 악화 | pub-prod-0047 | product_symptom | 2 | 13 | 0.1389 | 0.0000 | -0.1389 |
| 악화 | pub-prod-0009 | product_symptom | 2 | 3 | 0.6309 | 0.5000 | -0.1309 |
| 악화 | pub-prod-0052 | product_symptom | 1 | 1 | 1.0000 | 0.9197 | -0.0803 |
| 개선 | pub-cve-0014 | cve_explicit | 범위 밖 | 1 | 0.0000 | 1.0000 | +1.0000 |
| 개선 | pub-prod-0034 | product_symptom | 39 | 1 | 0.0000 | 1.0000 | +1.0000 |
| 개선 | pub-prod-0017 | product_symptom | 4 | 1 | 0.4307 | 1.0000 | +0.5693 |
| 개선 | pub-prod-0019 | product_symptom | 5 | 1 | 0.4416 | 1.0000 | +0.5584 |
| 개선 | pub-prod-0030 | product_symptom | 2 | 1 | 0.2809 | 0.8358 | +0.5549 |
| 개선 | pub-prod-0055 | product_symptom | 3 | 1 | 0.5000 | 1.0000 | +0.5000 |
| 개선 | pub-prod-0045 | product_symptom | 2 | 1 | 0.4819 | 0.9337 | +0.4519 |
| 개선 | pub-prod-0005 | product_symptom | 1 | 1 | 0.4959 | 0.8580 | +0.3620 |
| 개선 | pub-prod-0048 | product_symptom | 1 | 1 | 0.6512 | 0.9670 | +0.3158 |
| 개선 | pub-prod-0004 | product_symptom | 1 | 1 | 0.6131 | 0.9197 | +0.3066 |

### 6.2 KISA 트랙(문서 = nttId)

악화 질문 6건(전부), 개선 1건(표에는 상위 1건), 변화 없음 16건.

| 구분 | 질문 ID | 유형 | 첫 정답 순위 전(bge-m3) | 후(e5) | nDCG@10 전 | nDCG@10 후 | delta |
|---|---|---|---|---|---|---|---|
| 악화 | g1-cve-2026-15410 | cve_explicit | 1 | 32 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | g1-cve-2026-76461 | cve_explicit | 1 | 9 | 1.0000 | 0.3010 | -0.6990 |
| 악화 | g1-cve-2026-14669 | cve_explicit | 3 | 11 | 0.5000 | 0.0000 | -0.5000 |
| 악화 | g1-cve-2026-75650 | cve_explicit | 1 | 3 | 1.0000 | 0.5000 | -0.5000 |
| 악화 | g1-cve-2026-9198 | cve_explicit | 1 | 2 | 1.0000 | 0.6309 | -0.3691 |
| 악화 | g1-cve-2026-53873 | cve_explicit | 7 | 15 | 0.3333 | 0.0000 | -0.3333 |
| 개선 | g1-cve-2026-63030 | cve_explicit | 33 | 8 | 0.0000 | 0.3155 | +0.3155 |

### 6.3 원인

- 확인: 두 트랙 모두 악화의 대부분이 `cve_explicit`이다(공개 악화 15건 중 8건, KISA 악화 6건 중 6건). 유형 평균도 같은 방향이다(공개 nDCG@10 0.2271 -> 0.1354, KISA 0.4394 -> 0.1589). 질의에 CVE 번호 문자열이 있고 정답 문서가 그 번호를 가진 경우에 e5가 bge-m3보다 정답에 낮은 순위를 준다. 추정: 접두사 `query: `/`passage: `를 쓰는 e5는 번호 문자열의 일치를 의미 유사도로 잘 반영하지 못한다. 이 원인은 두 모델의 질의별 유사도 분해로 확인하지 않았다.
- 확인: 공개 트랙 `product_symptom`은 개선이다(nDCG@10 0.6436 -> 0.7433, delta +0.0998, 개선 상위 10건 중 9건). 이 유형의 개선과 `cve_explicit` 회귀가 상쇄되어 macro delta가 +0.0040에 머물렀다. 추정: 제품명과 증상을 풀어 쓴 질의는 e5가 영어 설명 문서와 의미적으로 잘 맞춘다.
- 확인: KISA 악화 6건 중 4건(`g1-cve-2026-15410`, `-76461`, `-14669`, `-75650`)의 정답 공지는 e5의 512 토큰 한도를 넘어 잘리고, 2건(`-9198`, `-53873`)은 한도 안이다. 6건 모두 질의의 CVE 번호가 e5가 실제로 보는 앞부분 안에 들어 있었다(e5 토크나이저의 토큰 오프셋으로 대략 확인한 값이고 본문은 출력하지 않았다). 따라서 이 악화는 "번호가 잘려 나가서"만으로 설명되지 않는다. 한도가 512라는 사실 자체는 아래 한계에 적는다.
- 확인: dev에서는 e5가 기준선보다 공개 트랙에서 높았고(0.4890 대 0.3977) KISA에서는 낮았다(0.8369 대 0.8802). 공개 test에서는 거의 같았다(0.4393 대 0.4353). dev와 test에서 방향이 다르다. 추정: 공개 트랙 표본의 변동이 크고(구간 폭 약 0.136) dev 우위가 test에 이어지지 않았다.
- 확인: 후보 선택은 공개 dev에서 e5(0.4890)가 Qwen3-0.6B(0.3918)와 기준선(0.3977)보다 높았다. Qwen3는 기준선보다도 낮아 탈락했다. Qwen3의 test 성능은 측정하지 않았다(규칙).

## 7. 한계

- 질문 단위 재표집은 test 안 질문끼리의 의존(같은 공지·CVE를 쓰는 질문)을 독립으로 다뤄 구간을 실제보다 좁게 낼 수 있다. dev와 test 사이는 eval-protocol 6절의 그룹 분할로 이미 분리돼 있다.
- 후보는 로드되는 2개뿐이다. `google/embeddinggemma-2`는 lock의 transformers가 모델 유형을 몰라 제외했고, 그 밖의 다국어 모델(큰 모델, 다른 접두사 변형)은 측정하지 않았다. 이 결과는 "e5-large 한 모델이 bge-m3보다 높지 않다"에만 해당한다. 후보 선택은 공개 dev 한 번의 비교이고 dev 표본이 작아 두 후보의 차이(0.0972)가 안정적인지는 확인하지 않았다.
- e5-large의 최대 길이는 512 토큰이다. KISA 공지 50건 중 27건이 잘리고(bge-m3는 8192 한도에서 2건) 이는 모델이 지원하는 최대 길이를 따른 것이다. 청킹이 없는 이 실험에서 KISA 비교는 "긴 공지를 앞 512 토큰만 보는 모델 대 8192 토큰까지 보는 모델"의 비교를 겸한다. 정답 공지가 잘려도 질의의 CVE 번호는 보존되는 사례만 확인했고, 잘림이 `explanation_comparison` 등 다른 유형에 미친 영향은 분리하지 못했다. 이 점은 청킹 실험(#46)이 다룬다.
- KISA 트랙 test는 정답이 있는 질문 23건이고 `product_symptom`(7건), `explanation_comparison`(5건)은 n_scored < 10이라 유형별 우열을 주장할 수 없다(둘 다 기준선에서도 1.0이라 천장이다). KISA 구간 전체가 0 아래라 판정은 기각이지만, 이 차이는 `cve_explicit` 11건에서 나온다(다른 두 유형은 기준선과 실험 모두 1.0이라 차이가 없다).
- 첫 정답 순위는 저장된 상위 100건 안의 순위다. "범위 밖"은 전체 순위에서 미검색인지 단지 100위 밖인지 구분하지 못한다.
- τ는 모델마다 dev에서 고른 값이고 no_answer 질문은 공개 12건, KISA 6건이라 기권율은 거친 값이다. 점수 척도가 다른 τ끼리는 직접 비교하지 않는다.
- 질의 지연과 색인 시간은 참고값이다. 다른 작업과 같은 맥에서 돌았을 수 있고 CPU 추론이며 배치 크기(8)는 기준선(2)과 다르다.
- test는 트랙마다 확정 설정으로 한 번 돌았다. 이 보고서의 숫자는 커밋된 첫 실행 기준이다.

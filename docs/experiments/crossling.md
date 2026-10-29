# 한영 교차 실험 (`crossling`)

결과: 주 판정(공개 트랙, BM25 KO->EN)은 `hypothesis-rejected`, 보조 판정(같은 번역을 bge-m3 dense에 넣은 변형)도 `hypothesis-rejected`다. 두 변형 모두 기준보다 낮고(delta -0.5780, -0.1641) 95% 구간 전체가 0보다 아래다. 사전 등록한 설정으로 test를 한 번 돌렸고 결과를 본 뒤 설정·가설·판정 규칙을 바꾸지 않았다. 하네스 계약은 [README.md](README.md), 판정 규칙의 정본은 런 스펙 이슈 #43의 "실험 공통 규칙"이다.

## 1. 가설 (사전 등록)

- 가설: 공개 트랙의 한국어 질문을 로컬 번역 모델로 영어로 바꿔(KO->EN) BM25로 검색하면, 원래 한국어 질문의 BM25보다 test macro nDCG@10이 높다.
- 주 트랙·변형: 공개 트랙 `bm25_ko2en`, 기준 = `results/baselines/public/bm25.jsonl`. 보조 판정: 같은 번역을 bge-m3 dense에 넣은 `dense_ko2en`, 기준 = `results/baselines/public/dense.jsonl`. 이슈 라벨은 주 판정을 따른다. KISA 트랙은 질문과 문서가 모두 한국어라 대상이 아니다.
- 바꾸는 요소는 질의 쪽 언어 하나다. 문서(NVD 영문 설명)와 색인 텍스트는 바꾸지 않는다(KO->EN, 질의 쪽만).
- 판정: test macro nDCG@10의 `delta = 실험 - 기준`이 0보다 크고, 유형별 층화 paired bootstrap(10000회, 시드 `20261029`) 95% 구간의 하한이 0보다 크면 `hypothesis-confirmed`, 그 밖은 `hypothesis-rejected`.

## 2. 구성

- 번역 모델: `Helsinki-NLP/opus-mt-ko-en`(Marian) revision `e42d1f41b66194e6d10512f8a27bebc1f4f5097e`. 로컬 CPU에서 돌고 외부 API를 쓰지 않는다. 선택 근거: (1) 모델 카드의 라이선스가 Apache-2.0이라 MIT 리포의 결과물(번역문 파일)을 재배포하는 데 제약이 없다. 후보였던 `facebook/nllb-200-distilled-600M`은 모델 카드에 `cc-by-nc-4.0`(비상업)이 적혀 있어 피했다. (2) NLLB 600M보다 작아 질문 144건을 CPU에서 몇 분 안에 번역한다. (3) 토크나이저가 SentencePiece 하나(`embed` 그룹에 `sentencepiece` 추가)라 의존성이 작다. 번역 품질로 고른 것이 아니다: 두 모델의 번역을 비교하지 않았고(번역 모델 여러 개 비교는 범위 밖), test 결과를 보기 전에 정했다.
- 디코딩(결정적): beam 4, 샘플링 없음, `max_new_tokens` 256, length_penalty 1.0, 질문 하나씩(batch 1, 패딩 없음), float32, CPU, `torch.manual_seed(0)`. 같은 환경에서 번역을 두 번 만들어 `translations.jsonl`이 바이트까지 같음을 확인했다. 입력은 질문의 `query` 문자열 그대로이고 전처리나 CVE ID 보정은 하지 않았다.
- 번역 파일: `results/experiments/crossling/translations.jsonl`(질문 ID, 번역문, 원문 sha256, 모델, revision). 공개 트랙 질문 144건 전부(제외 질문 포함)다. 공개 트랙 질문은 이 리포가 만든 합성 질문이라 번역문을 커밋했다. 검색은 이 파일로 하므로 BM25 변형의 재실행과 `--compare`는 번역 모델 없이 된다. 이 파일의 sha256이 두 변형의 `reproduction_inputs`로 manifest와 test 설정 해시에 들어간다: 번역문만 바꾸고 test나 all을 돌리면 `LockError`다(테스트가 검증).
- BM25(`bm25_ko2en`): 기준선 manifest에 확정된 k1=1.2, b=0.75와 `bm25-tok-v1` 토큰화를 그대로 쓴다. 번역문 토큰이 하나라도 든 문서만 순위에 든다.
- dense(`dense_ko2en`): 기준선과 같은 bge-m3 dense(`BAAI/bge-m3` revision `5617a9f61b028005a4858fdac845db406aefb181`, CLS pooling, L2 정규화, float32, max_seq_length 8192, CPU). 질의 문자열만 번역문이다.
- 설정 격자는 없다(`grid`가 `[{}]`). dev는 기권 τ만 기준선과 같은 규칙(abstain_rate - false_abstain_rate 최대, 같으면 가장 낮은 τ)으로 고른다.
- 변형마다 기준선이 다르므로 하네스의 `BASELINES`를 `{변형: 기준선}` 형태로 쓴다(하네스 계약 확장, 이 티켓의 별도 커밋. 문자열 형태는 그대로라 기존 hybrid 결과는 불변).

## 3. 재현 명령

모델이 필요한 실행은 `embed` 그룹을 쓴다. 측정은 `OMP_NUM_THREADS=4`로 했다.

```
uv sync --locked --group embed
OMP_NUM_THREADS=4 uv run --no-sync python -m krsec_rag_lab.experiments.crossling                      # 번역 파일 만들기(번역 모델 필요, 결정적)
OMP_NUM_THREADS=4 uv run --no-sync python scripts/run_experiment.py --exp crossling --track public --split dev   # τ 선택(몇 번 돌려도 됨)
OMP_NUM_THREADS=4 uv run --no-sync python scripts/run_experiment.py --exp crossling --track public               # dev 선택 뒤 test 1회
uv sync --locked --dev
uv run python scripts/run_experiment.py --exp crossling --compare   # 모델·KISA 캐시 없이 저장본에서 metrics·comparison을 다시 계산해 대조(불일치 exit 1)
uv run python scripts/run_experiment.py --exp crossling --track public --variant bm25_ko2en --out-dir <빈 디렉터리>   # 재현 확인: 번역 모델·embed 그룹 없이 BM25 결과가 커밋된 저장본과 같아야 한다
```

산출물: `results/experiments/crossling/public/{bm25_ko2en,dense_ko2en}.jsonl`, `manifest.json`, `metrics.json`, `comparison.json`, `translations.jsonl`. test 설정 해시는 manifest의 `runs[<track>/<variant>].test.config_hash`다.

## 4. 결과

### 4.1 dev에서 고른 설정

| 변형 | 선택 | τ | dev macro nDCG@10 (실험) | dev macro nDCG@10 (기준) |
|---|---|---|---|---|
| bm25_ko2en | 격자 없음 | 8.492416 | 0.3923 | 0.8533 |
| dense_ko2en | 격자 없음 | 0.558438 | 0.2858 | 0.3977 |

### 4.2 test 판정 (macro nDCG@10)

| 변형 | 역할 | 기준 | 기준(macro) | 실험 | delta | 95% 구간 | 판정 |
|---|---|---|---|---|---|---|---|
| bm25_ko2en | 주 | bm25 | 0.8551 | 0.2771 | -0.5780 | [-0.6723, -0.4832] | `hypothesis-rejected` |
| dense_ko2en | 보조 | dense | 0.4353 | 0.2713 | -0.1641 | [-0.2417, -0.0891] | `hypothesis-rejected` |

`comparison.json`의 `primary`는 `bm25_ko2en`(기준 bm25) 판정이고 `secondary`는 `dense_ko2en`(기준 dense) 판정이다. 구간은 test 질문을 유형별로 층화 복원추출한 10000회의 2.5/97.5 백분위다. test 질문 수(정답이 있는 비제외 질문)는 74건이다.

### 4.3 유형별 delta (test)

n_scored < 10인 유형은 관찰로만 읽고 우열 주장에 쓰지 않는다(`observation_only`). 공개 트랙의 두 유형은 모두 n_scored가 35, 39다. no_answer는 순위 지표에서 빠진다.

| 변형 | 유형 | n_scored | 관찰만 | nDCG@10 기준 | nDCG@10 실험 | delta | hit@10 delta | MRR@10 delta |
|---|---|---|---|---|---|---|---|---|
| bm25_ko2en | cve_explicit | 35 | 아니오 | 1.0000 | 0.3665 | -0.6335 | -0.4571 | -0.6919 |
| bm25_ko2en | product_symptom | 39 | 아니오 | 0.7103 | 0.1877 | -0.5226 | -0.5128 | -0.5306 |
| dense_ko2en | cve_explicit | 35 | 아니오 | 0.2271 | 0.1974 | -0.0297 | -0.0286 | -0.0290 |
| dense_ko2en | product_symptom | 39 | 아니오 | 0.6436 | 0.3451 | -0.2985 | -0.3077 | -0.3741 |

### 4.4 macro hit@10, MRR@10 (test)

| 변형 | hit@10 기준 | hit@10 실험 | delta | MRR@10 기준 | MRR@10 실험 | delta |
|---|---|---|---|---|---|---|
| bm25_ko2en | 0.8974 | 0.4125 | -0.4850 | 0.8539 | 0.2426 | -0.6112 |
| dense_ko2en | 0.5531 | 0.3850 | -0.1681 | 0.4517 | 0.2501 | -0.2016 |

### 4.5 `cve_explicit` 회귀 여부 (판정과 별개)

- bm25_ko2en: `cve_explicit` nDCG@10 delta -0.6335 -> **회귀 있음**.
- dense_ko2en: `cve_explicit` nDCG@10 delta -0.0297 -> **회귀 있음**.

### 4.6 no_answer 기권 (test, τ는 각자 dev에서 고름)

| 변형 | 검색기 | τ | no_answer 기권율(높을수록 좋음) | 정답 질문 오기권율(낮을수록 좋음) | n_no_answer | n_answerable |
|---|---|---|---|---|---|---|
| bm25_ko2en | BM25(한국어 질의, 기준) | 5.191784 | 1.0000 | 0.1351 | 12 | 74 |
| bm25_ko2en | BM25(번역 질의) | 8.492416 | 0.8333 | 0.1892 | 12 | 74 |
| dense_ko2en | dense(한국어 질의, 기준) | 0.607314 | 0.6667 | 0.5270 | 12 | 74 |
| dense_ko2en | dense(번역 질의) | 0.558438 | 0.2500 | 0.2973 | 12 | 74 |

점수 척도가 검색기마다 다르고 번역 질의는 점수 분포도 달라 τ는 각자 고른 값이다. 척도가 다른 τ끼리 크기를 비교하지 않는다.

### 4.7 번역의 CVE ID 보존 (질문의 `extract_cve_ids` 집합이 번역 뒤에도 같은가)

번역은 CVE ID를 보정하지 않는다(보정은 다른 변수다). 채점 대상(제외되지 않은) 질문 144건 중 질문에 CVE ID가 든 것은 84건이고, 번역 뒤 ID 집합이 달라진 질문은 **31건**이다. 달라진 질문은 모두 원문의 ID가 번역문에서 사라지거나 바뀐 경우(31건)이고, 이 중 3건은 번역문에 원문에 없는 ID(`CVE-YYYY-NNNN` 형태)가 새로 생기기도 했다.

| 분할 | 질문 수 | CVE ID가 든 질문 | ID 집합이 달라진 질문 | 원문 ID가 빠지거나 바뀐 질문 | 원문에 없는 ID가 생긴 질문 |
|---|---|---|---|---|---|
| dev | 58 | 37 | 12 | 12 | 0 |
| test | 86 | 47 | 19 | 19 | 3 |
| 합계 | 144 | 84 | 31 | 31 | 3 |

달라진 질문 ID 목록은 manifest의 `description.cve_id_preservation.changed_question_ids`에 있다. 이 값은 저장된 번역 파일에서 `setup`이 계산해 manifest에 적은 `description` 값이며 `--compare`가 다시 계산하는 대상은 아니다(테스트가 번역 파일에서 같은 값을 다시 계산해 대조한다).

### 4.8 색인 시간과 질의 지연 (참고값)

측정 환경: Apple M5 Pro, 18코어, `OMP_NUM_THREADS=4`, CPU 추론. 2단계 실험 네 개가 같은 맥에서 병렬로 돌았을 수 있으므로 간섭이 있을 수 있어 참고값으로만 읽는다.

| 변형 | 검색기 | 색인(setup) 초 | 질의 지연 중앙값 초 |
|---|---|---|---|
| bm25_ko2en | BM25(한국어 질의, 기준) | 0.010 | 0.000005 |
| bm25_ko2en | BM25(번역 질의) | 0.012 | 0.000177 |
| dense_ko2en | dense(한국어 질의, 기준) | 62.837 | 0.044774 |
| dense_ko2en | dense(번역 질의) | 125.149 | 0.072139 |

번역 질의의 시간에는 번역 비용이 들어 있지 않다(번역은 미리 만들어 커밋한 파일을 읽는다). 번역 자체의 소요 시간은 이 표에 없다.

## 5. 판정

- **주 판정(공개 트랙, BM25): `hypothesis-rejected`.** delta -0.5780는 음수이고 95% 구간 [-0.6723, -0.4832]의 상한도 0보다 작아, 번역이 BM25 검색을 높이기는커녕 낮춘다는 쪽으로 구간이 한쪽에 치우쳐 있다. 개선된 질문은 0건, 악화된 질문은 54건(변화 없음 20건)이다.
- **보조 판정(공개 트랙, dense): `hypothesis-rejected`.** delta -0.1641, 95% 구간 [-0.2417, -0.0891]. 개선 8건, 악화 27건, 변화 없음 39건.
- 결과가 가설을 기각해도 정상 종료다. 이슈 라벨은 `comparison.json`의 `primary.verdict`대로 `hypothesis-rejected`다.

## 6. 실패 사례 분석

질문 문장과 문서 본문은 쓰지 않고 질문 ID만 쓴다(공개 트랙 질문은 합성이지만 이 표는 ID로만 적는다). 순위는 저장된 condensed 상위 100건 안의 첫 정답 순위이고 "범위 밖"은 그 안에 정답이 없다는 뜻이다(전체 순위에서 미검색인지와 구분하지 못한다). 아래 원인 설명의 "확인"은 저장된 결과 파일(기준선과 이 실험의 저장본, 번역 파일, 질의셋 라벨)에서 직접 계산한 사실이고, "추정"은 그 사실로부터의 해석이다. 이 분석은 test 결과를 본 뒤에 썼고 설정을 바꾸는 데 쓰지 않았다.

### 6.1 BM25(`bm25_ko2en`): 악화 54건 전부, 개선 0건

| 구분 | 질문 ID | 유형 | 첫 정답 순위 전(BM25 한국어) | 후(BM25 번역) | nDCG@10 전 | nDCG@10 후 | delta |
|---|---|---|---|---|---|---|---|
| 악화 | pub-cve-0001 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0002 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0006 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0010 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0012 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0015 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0016 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0023 | cve_explicit | 1 | 42 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0026 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0033 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0037 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0044 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0046 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0048 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0050 | cve_explicit | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-cve-0060 | cve_explicit | 1 | 59 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0003 | product_symptom | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0005 | product_symptom | 1 | 46 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0022 | product_symptom | 1 | 28 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0023 | product_symptom | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0025 | product_symptom | 1 | 11 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0029 | product_symptom | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0034 | product_symptom | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0040 | product_symptom | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0043 | product_symptom | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0044 | product_symptom | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0045 | product_symptom | 1 | 76 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0048 | product_symptom | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0052 | product_symptom | 1 | 56 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0058 | product_symptom | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0033 | product_symptom | 1 | 범위 밖 | 0.9052 | 0.0000 | -0.9052 |
| 악화 | pub-prod-0031 | product_symptom | 1 | 범위 밖 | 0.8826 | 0.0000 | -0.8826 |
| 악화 | pub-prod-0060 | product_symptom | 1 | 12 | 0.7386 | 0.0000 | -0.7386 |
| 악화 | pub-prod-0015 | product_symptom | 1 | 5 | 0.9306 | 0.2369 | -0.6937 |
| 악화 | pub-prod-0057 | product_symptom | 1 | 3 | 1.0000 | 0.3094 | -0.6906 |
| 악화 | pub-prod-0030 | product_symptom | 2 | 4 | 0.7799 | 0.0948 | -0.6851 |
| 악화 | pub-prod-0036 | product_symptom | 1 | 8 | 1.0000 | 0.3155 | -0.6845 |
| 악화 | pub-cve-0004 | cve_explicit | 1 | 6 | 1.0000 | 0.3562 | -0.6438 |
| 악화 | pub-cve-0054 | cve_explicit | 1 | 5 | 1.0000 | 0.3869 | -0.6131 |
| 악화 | pub-cve-0041 | cve_explicit | 1 | 4 | 1.0000 | 0.4307 | -0.5693 |
| 악화 | pub-cve-0018 | cve_explicit | 1 | 3 | 1.0000 | 0.5000 | -0.5000 |
| 악화 | pub-cve-0022 | cve_explicit | 1 | 3 | 1.0000 | 0.5000 | -0.5000 |
| 악화 | pub-cve-0032 | cve_explicit | 1 | 3 | 1.0000 | 0.5000 | -0.5000 |
| 악화 | pub-cve-0039 | cve_explicit | 1 | 3 | 1.0000 | 0.5000 | -0.5000 |
| 악화 | pub-cve-0052 | cve_explicit | 1 | 3 | 1.0000 | 0.5000 | -0.5000 |
| 악화 | pub-cve-0007 | cve_explicit | 1 | 2 | 1.0000 | 0.6309 | -0.3691 |
| 악화 | pub-cve-0009 | cve_explicit | 1 | 2 | 1.0000 | 0.6309 | -0.3691 |
| 악화 | pub-cve-0028 | cve_explicit | 1 | 2 | 1.0000 | 0.6309 | -0.3691 |
| 악화 | pub-cve-0034 | cve_explicit | 1 | 2 | 1.0000 | 0.6309 | -0.3691 |
| 악화 | pub-cve-0058 | cve_explicit | 1 | 2 | 1.0000 | 0.6309 | -0.3691 |
| 악화 | pub-prod-0035 | product_symptom | 7 | 74 | 0.3333 | 0.0000 | -0.3333 |
| 악화 | pub-prod-0042 | product_symptom | 8 | 46 | 0.3155 | 0.0000 | -0.3155 |
| 악화 | pub-prod-0011 | product_symptom | 1 | 2 | 1.0000 | 0.7328 | -0.2672 |
| 악화 | pub-prod-0047 | product_symptom | 3 | 33 | 0.1834 | 0.0000 | -0.1834 |

### 6.2 dense(`dense_ko2en`): 악화 27건 전부, 개선 8건

| 구분 | 질문 ID | 유형 | 첫 정답 순위 전(dense 한국어) | 후(dense 번역) | nDCG@10 전 | nDCG@10 후 | delta |
|---|---|---|---|---|---|---|---|
| 악화 | pub-prod-0003 | product_symptom | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0023 | product_symptom | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0029 | product_symptom | 1 | 29 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0041 | product_symptom | 1 | 21 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0044 | product_symptom | 1 | 범위 밖 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0052 | product_symptom | 1 | 14 | 1.0000 | 0.0000 | -1.0000 |
| 악화 | pub-prod-0031 | product_symptom | 1 | 24 | 0.8200 | 0.0000 | -0.8200 |
| 악화 | pub-prod-0043 | product_symptom | 1 | 범위 밖 | 0.8066 | 0.0000 | -0.8066 |
| 악화 | pub-prod-0011 | product_symptom | 1 | 5 | 1.0000 | 0.3172 | -0.6828 |
| 악화 | pub-prod-0036 | product_symptom | 1 | 7 | 1.0000 | 0.3333 | -0.6667 |
| 악화 | pub-prod-0048 | product_symptom | 1 | 16 | 0.6512 | 0.0000 | -0.6512 |
| 악화 | pub-prod-0033 | product_symptom | 3 | 범위 밖 | 0.6410 | 0.0000 | -0.6410 |
| 악화 | pub-cve-0001 | cve_explicit | 2 | 73 | 0.6309 | 0.0000 | -0.6309 |
| 악화 | pub-cve-0012 | cve_explicit | 3 | 26 | 0.5000 | 0.0000 | -0.5000 |
| 악화 | pub-prod-0016 | product_symptom | 1 | 3 | 1.0000 | 0.5000 | -0.5000 |
| 악화 | pub-prod-0005 | product_symptom | 1 | 18 | 0.4959 | 0.0000 | -0.4959 |
| 악화 | pub-prod-0045 | product_symptom | 2 | 34 | 0.4819 | 0.0000 | -0.4819 |
| 악화 | pub-cve-0015 | cve_explicit | 4 | 17 | 0.4307 | 0.0000 | -0.4307 |
| 악화 | pub-prod-0058 | product_symptom | 1 | 1 | 1.0000 | 0.6047 | -0.3953 |
| 악화 | pub-cve-0060 | cve_explicit | 1 | 2 | 1.0000 | 0.6309 | -0.3691 |
| 악화 | pub-prod-0025 | product_symptom | 1 | 2 | 1.0000 | 0.6309 | -0.3691 |
| 악화 | pub-prod-0040 | product_symptom | 1 | 2 | 1.0000 | 0.6309 | -0.3691 |
| 악화 | pub-prod-0060 | product_symptom | 1 | 2 | 0.7850 | 0.6036 | -0.1814 |
| 악화 | pub-prod-0015 | product_symptom | 1 | 5 | 0.5442 | 0.3668 | -0.1774 |
| 악화 | pub-prod-0047 | product_symptom | 2 | 범위 밖 | 0.1389 | 0.0000 | -0.1389 |
| 악화 | pub-prod-0017 | product_symptom | 4 | 5 | 0.4307 | 0.3869 | -0.0438 |
| 악화 | pub-prod-0030 | product_symptom | 2 | 4 | 0.2809 | 0.2494 | -0.0315 |
| 개선 | pub-prod-0019 | product_symptom | 5 | 1 | 0.4416 | 1.0000 | +0.5584 |
| 개선 | pub-prod-0055 | product_symptom | 3 | 1 | 0.5000 | 1.0000 | +0.5000 |
| 개선 | pub-prod-0034 | product_symptom | 39 | 5 | 0.0000 | 0.3869 | +0.3869 |
| 개선 | pub-cve-0020 | cve_explicit | 16 | 7 | 0.0000 | 0.3333 | +0.3333 |
| 개선 | pub-cve-0056 | cve_explicit | 24 | 8 | 0.0000 | 0.3155 | +0.3155 |
| 개선 | pub-prod-0004 | product_symptom | 1 | 1 | 0.6131 | 0.9197 | +0.3066 |
| 개선 | pub-cve-0058 | cve_explicit | 5 | 2 | 0.3869 | 0.6309 | +0.2441 |
| 개선 | pub-prod-0028 | product_symptom | 1 | 1 | 0.8368 | 0.8979 | +0.0611 |

### 6.3 원인 (BM25)

원인 분석은 test의 정답이 있는 질문 74건을 `cve_explicit`(35건)과 `product_symptom`(39건)으로 나눠 본 것이다.

- 확인: test `cve_explicit` 35건 중 번역이 CVE ID 집합을 보존한 질문은 19건, 바꾼 질문은 16건이다(4.7의 test 47건에는 no_answer 12건의 ID도 들어 있다). 기준선 BM25는 `cve_explicit` 35건 모두에서 nDCG@10이 1.0이다(질문의 ID 토큰이 정답 문서의 ID 토큰과 정확히 일치).
- 확인: ID를 바꾼 16건은 번역 BM25의 nDCG@10이 0.0이다(첫 정답 순위는 14건이 범위 밖, 나머지 2건은 42위와 59위). 바뀐 모양은 접두사만 `CVE-`에서 `CVS-`나 `CFE-`로 바뀌고 숫자는 그대로인 경우가 11건, 숫자가 바뀌거나 잘리거나 공백이 끼어든 경우가 5건(이 중 2건은 접두사도 바뀜)이다. 어느 경우든 ID가 정답 문서의 ID 토큰과 일치하지 않는다.
- 확인: ID가 보존된 19건도 평균 nDCG@10이 1.0에서 0.6752로 떨어졌다. 정답이 1위인 질문은 6건뿐이고 나머지 13건은 모두 1위 문서에 질문의 ID 토큰이 없다(정답 문서는 2~6위). 한국어 질의의 한글 토큰은 색인에 하나도 없다(코퍼스에 한글이 든 문서는 0건이고, test 채점 대상 질문의 한글 토큰이 질문별 중복을 빼고 합쳐 997개인데 모두 색인 어휘 밖이다). 그래서 한국어 질의는 ID 토큰만 점수를 냈다. 번역문에는 `the`, `of`, `vulnerability`, `scope`, `severity`, `impact`처럼 문서 설명에 실제로 나오는 영어 낱말이 들어와 ID 토큰 말고도 점수를 낸다.
- 확인: `product_symptom` 39건에서 기준선 BM25의 nDCG@10은 0.7103, 번역 BM25는 0.1877이다. 질문의 `vendor:product`에서 뽑은 토큰이 번역문에 모두 남아 있는 질문은 39건 중 7건뿐이고 나머지 32건은 번역이 제품명을 바꾸거나 쪼갰다(철자 변형, 단어 누락). 제품명이 남은 7건도 0.8022에서 0.1682로 떨어졌다.
- 추정: 한국어 질의가 영문 코퍼스에서 잘 되는 이유는 한국어 조사와 안내 문구(2-gram 토큰)가 영어 문서와 겹치지 않아 검색에 영향을 주지 않고, 영문 식별자(제품명, CVE ID)만 일치 신호로 남기 때문이다. 번역은 이 안내 문구까지 영어 낱말로 바꿔 코퍼스의 흔한 낱말과 겹치게 만들고, 동시에 일치 신호인 식별자를 훼손한다. 제품명이 남은 7건에서도 큰 하락이 있다는 사실이 두 번째 효과(영어 안내 문구가 만드는 잡음)와 일치하지만, 이 7건만으로 두 효과의 크기를 나눌 수는 없다. BM25에 불용어 제거가 없다는 사실(`bm25-tok-v1`: 어간·불용어 처리 없음)이 이 잡음을 막지 못한다. 불용어를 지우거나 식별자를 복원하면 결과가 달라질 수 있지만 그것은 다른 변수이고 이 실험에서 측정하지 않았다.

### 6.4 원인 (dense)

- 확인: 기준선 dense는 `cve_explicit`에서 nDCG@10이 0.2271로 낮고(ID 문자열 일치를 잘 잡지 못함), 번역 dense는 0.1974다. `product_symptom`은 0.6436에서 0.3451로 떨어졌다.
- 확인: ID를 바꾼 16건의 번역 dense nDCG@10은 0.1644(기준 0.2851), ID가 보존된 19건은 0.2252(기준 0.1783)다. ID가 보존된 `cve_explicit`에서는 번역 dense가 기준 dense보다 높았다(개선 8건 중 3건(`pub-cve-0020`, `pub-cve-0056`, `pub-cve-0058`)이 ID가 보존된 `cve_explicit`이고 나머지 5건은 `product_symptom`이다).
- 확인: 제품명이 번역문에 남은 `product_symptom` 7건은 0.6800에서 0.5697로, 제품명이 바뀐 32건은 0.6356에서 0.2960으로 떨어졌다.
- 추정: bge-m3는 다국어 임베딩이라 한국어 질문과 영어 문서 사이의 의미 연결을 이미 하므로 번역의 이득이 작고, 번역이 제품명을 바꾸면 임베딩이 가리키는 제품이 달라져 손해가 크다. 이 추정은 문서 본문을 보지 않고 점수 차이에서 읽은 것이다.

## 7. 한계

- 번역 모델은 하나(`opus-mt-ko-en`)이고 품질이 특히 영문 식별자(제품명 `vendor:product`, CVE ID)와 짧은 질문에서 약하다. 이 결과는 "이 모델의 번역을 그대로 검색에 넣은 경우"에만 해당한다. 더 큰 번역 모델, 식별자 보호, LLM 질의 재작성, 문서 쪽 번역(EN->KO)은 측정하지 않았다(범위 밖).
- CVE ID 보정(원문 ID를 번역문에 되살리기)은 하지 않았다. 실험의 목적은 번역만 바꿨을 때의 효과를 보는 것이어서 보정은 다른 변수다. ID가 보존된 질문만 놓고 보면 BM25 하락이 훨씬 작다(6.3). 이 비교는 사후 분할이라 새 가설의 근거가 아니다.
- 질문 단위 재표집은 test 안 질문끼리의 의존(같은 제품·CVE를 쓰는 질문)을 독립으로 다뤄 구간을 실제보다 좁게 낼 수 있다. dev와 test 사이는 eval-protocol 6절의 그룹 분할로 이미 분리돼 있다. 다만 이번 delta는 구간 상한도 0보다 한참 낮아 결론이 이 한계에 민감하지 않다.
- 공개 트랙 질문은 이 리포가 템플릿으로 만든 합성 질문이라 문장 형태가 몇 가지로 반복된다. 같은 템플릿이 번역에서 같은 방식으로 틀어지므로 질문 간 오류가 독립이 아니다. 실제 사용자 질문의 한국어 다양성은 반영하지 못한다.
- 첫 정답 순위는 저장된 상위 100건 안의 순위다. "범위 밖"은 전체 순위에서 미검색인지 단지 100위 밖인지 구분하지 못한다.
- 6.3·6.4의 원인 설명 중 "추정"은 저장본의 점수 차이에서 읽은 해석이고 문서 본문을 직접 비교해 검증하지 않았다.
- 번역 파일은 같은 환경(Python 3.13, torch 2.14.1, transformers 5.17.0, sentencepiece 0.2.2, CPU)에서 두 번 만들어 바이트까지 같았다. 다른 런타임 버전이나 다른 CPU에서 같은 번역이 나온다고 확인한 것은 아니다. 그래서 검색은 번역 모델이 아니라 커밋된 파일로 한다.
- 질의 지연과 색인 시간은 참고값이다. 다른 실험과 같은 맥에서 병렬로 돌았고 CPU 추론이다.
- test는 확정 설정으로 한 번 돌았다(dev의 τ 선택 뒤). 같은 설정으로 다시 돌린 재현 실행은 허용되며, 번역 파일이나 설정이 바뀌면 test 잠금이 실패한다.

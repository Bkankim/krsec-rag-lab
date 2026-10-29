# v0.1 릴리스 노트 (M2: 베이스라인 3종 + 첫 릴리스)

Bkankim의 단독 프로젝트 [krsec-rag-lab](../README.md)의 첫 릴리스다. 두 트랙(공개 트랙, KISA 트랙)에서 베이스라인 3종
(exact CVE lookup / BM25 / dense bge-m3)을 측정한 질문별 원시 결과, 재현 명령, 데이터 manifest, 모델 revision을 묶었다.
README의 결과 표는 이 원시 결과에서 스크립트로 다시 계산한 값이다. 수치의 해석은 [baselines.md](baselines.md)에 있다.

## 무엇이 들어 있나

| 구분 | 내용 | 정본 |
|---|---|---|
| 평가 규약 | eval-protocol v2 (`gold` / `unjudged` / 비관련, condensed list, `excluded`, dev/test 분리, `no_answer` 별도 표) | [eval-protocol.md](eval-protocol.md) |
| 공개 트랙 | NVD fixture 1560건 + 질문 144문항(dev 58 / test 86), 정답은 메타데이터로 기계적 결정 | `eval/public/` |
| KISA 트랙 | 고정 KISA 공지 50건 + 질문 54문항(채점 52, `excluded` 2), 정답은 두 모델의 교차 판정 | `eval/golden/` |
| 베이스라인 | exact CVE lookup, BM25(`bm25-tok-v1`), dense(bge-m3 dense only) x 두 트랙 | [baselines.md](baselines.md), `results/baselines/` |
| 원시 결과 | 질문 하나 = 한 줄: 질문 ID, `unjudged`를 지운 상위 100건의 문서 ID·순위·점수, 지우기 전 1위 점수, 지운 문서 수 | `results/baselines/<track>/<retriever>.jsonl` |

## 재현

### 공개 트랙 (새 클론, 네트워크·KISA 캐시 불필요)

`uv sync --locked --dev` 뒤 exact와 BM25를 다시 돌려 커밋된 결과와 비교한다. `--out-dir`을 주면 커밋된
`results/baselines`를 건드리지 않고 그 디렉터리에만 쓴다.

```bash
git clone https://github.com/Bkankim/krsec-rag-lab.git && cd krsec-rag-lab
uv sync --locked --dev
OUT=$(mktemp -d)
uv run python scripts/run_baselines.py --track public --retriever exact --out-dir "$OUT"
uv run python scripts/run_baselines.py --track public --retriever bm25 --out-dir "$OUT"
uv run python scripts/check_release.py --compare-results "$OUT"
```

`check_release.py --compare-results`는 `results/baselines/public/{exact,bm25}.jsonl`과 질문 ID 집합이 같은지,
문서 ID·순위가 일치하는지, 점수가 abs 1e-9 안인지 비교하고 같을 때만 종료 코드 0이다. 실행 시각·소요 시간 같은
메타데이터(`manifest.json`)는 비교하지 않는다.

### dense (별도 단계)

dense는 `embed` 그룹(torch, sentence-transformers)과 HF에서 받는 bge-m3 가중치(약 2.1GB)가 필요해 CI에서는 돌리지 않는다.
모델은 `BAAI/bge-m3` revision `5617a9f61b028005a4858fdac845db406aefb181`, CLS pooling, L2 정규화, float32, CPU다.

```bash
uv sync --locked --group embed
uv run --no-sync python scripts/run_baselines.py --track public --retriever dense --out-dir "$OUT"
uv run python scripts/check_release.py --compare-results "$OUT" --retrievers dense --atol 1e-4
```

`--atol 1e-4`는 환경에 따라 소수 자리가 달라질 수 있어 둔 느슨한 허용치이고, 이 허용치가 다른 환경에서 충분한지는
확인하지 않았다(아래 한계의 미검증 항목). 순위 불일치는 허용치와 무관하게 실패다.

### KISA 트랙 (로컬 캐시 필요)

KISA 공지 본문은 재배포하지 않으므로 이 트랙은 본문 캐시(`data/kisa`)를 직접 만든 환경에서만 다시 돌릴 수 있다
(수집·캐시 검사 절차는 [README](../README.md)의 "KISA 소표본"). 캐시가 있는 체크아웃 루트를 `--kisa-root`로 넘긴다.

```bash
uv run --no-sync python scripts/run_baselines.py --track kisa --retriever bm25 --kisa-root <KISA 캐시가 있는 체크아웃> --out-dir "$OUT"
uv run python scripts/check_release.py --compare-results "$OUT" --track kisa
```

### README 표와 원시 결과의 일치 검증

```bash
uv run python scripts/make_readme_tables.py --check   # 일치하면 0, 불일치·누락·빈 입력·질문 ID 오류는 1
uv run python scripts/check_release.py                # 아래 asset 목록 검사
```

`make_readme_tables.py --check`는 `results/baselines/manifest.json`이 가리키는 원시 결과와 `eval/**` 정답에서
`src/krsec_rag_lab/metrics.py`와 규약 v2 채점(condensed list)으로 지표를 다시 계산하고, 그 값이
`results/baselines/metrics.json` 및 README의 생성 구간 표와 모두 같을 때만 통과한다.

## 데이터와 모델

| 항목 | 값 |
|---|---|
| 평가 규약 | `eval-protocol-v2` ([eval-protocol.md](eval-protocol.md)) |
| dense 모델 | `BAAI/bge-m3` revision `5617a9f61b028005a4858fdac845db406aefb181` |
| KISA 고정 공지 | 50건, 수집 2026-09-19T05:18:29+00:00, 파서 `kisa-html-v1`, 본문 sha256은 `fixtures/kisa/manifest.json` (본문은 미배포) |
| NVD fixture | 1560건, 수집 2026-10-29T11:01:43+00:00, 파일·레코드 sha256은 `fixtures/nvd/manifest.json` |
| 입력 해시 | `results/baselines/manifest.json`의 `runs.<트랙>/<검색기>.inputs`에 질의셋·코퍼스 sha256 |
| 베이스라인 실행 | 2026-10-29T12:46~12:49 UTC, Apple M5 Pro, Python 3.13.14 (`manifest.json`의 `environment`) |
| 교차 판정 | 판정자 A `claude-opus-5-5`, B `gpt-6.1-sol`, 2026-10-29T10:55:30Z~11:42:21Z, 호출 172건 ([judge_manifest.json](../eval/golden/judge_manifest.json)) |

## asset

GitHub 릴리스 `v0.1`에 첨부하는 파일이다. asset 이름은 리포 경로의 `/`를 `__`로 바꾼 이름이고, 각 asset은 대응하는 리포
파일의 사본이다(sha256 동일). 모든 파일은 허용 필드만 갖는다: 결과 파일은 질문 ID·문서 ID·순위·점수(와 지우기 전 1위
점수, 지운 문서 수)뿐이고, 그 밖은 manifest(JSON)와 정답 파일(질의·정답 ID·판정 요약)이다. KISA 공지 본문은 없다.

<!-- BEGIN ASSETS (scripts/check_release.py --print-assets) -->

| asset 이름 | 리포 경로 | 크기(바이트) | sha256 |
|---|---|---|---|
| `eval__golden__agreement.json` | `eval/golden/agreement.json` | 2694 | `9998fa9d41fc0659e78c5c7f880de52cf673f77667b3a703dc67bc937eef7510` |
| `eval__golden__error_rates.json` | `eval/golden/error_rates.json` | 2241 | `6b66e83947b2c6fd0d5ce31d8afa175f6726bd665f59f9a4f8ab2e3f1be3b221` |
| `eval__golden__golden_v1.jsonl` | `eval/golden/golden_v1.jsonl` | 29231 | `2f94253c6c0551c536973c95b830dcf123e7acb858304fa8678812a19360d3dc` |
| `eval__golden__judge_manifest.json` | `eval/golden/judge_manifest.json` | 13584 | `7eb6d0d8160cc35490a9c26c0d8482c6952388efe3c242caa2222540b189393b` |
| `eval__public__manifest.json` | `eval/public/manifest.json` | 4510 | `8d07aa30d93579317ec3d2dfe903b622f24828cd34e3db84fa2ca01ed74b0aa1` |
| `eval__public__queries.jsonl` | `eval/public/queries.jsonl` | 79561 | `1d8ab42360e3cee23e8d67bc933e5af7ec6a8365eb32d315105233016d294a99` |
| `fixtures__kisa__manifest.json` | `fixtures/kisa/manifest.json` | 11352 | `bf670ecd666e77139ae0c53a7be0badb5bdd82e8ff54d4876d59290b68c8b0c4` |
| `fixtures__kisa__metadata.jsonl` | `fixtures/kisa/metadata.jsonl` | 38254 | `c1512e8d234e0dbe4d32430877e61775612dd2248046122f74e227d446737eaf` |
| `fixtures__nvd__manifest.json` | `fixtures/nvd/manifest.json` | 266490 | `893bdee1c8454f4b78cc5257493e48038717a22c71dd3249a138fa3616d9cae6` |
| `results__baselines__kisa__bm25.jsonl` | `results/baselines/kisa/bm25.jsonl` | 161032 | `aa56a3aae836af708bb4f04df2d77adf181fab7a2636d5758aeb53ff405041f2` |
| `results__baselines__kisa__dense.jsonl` | `results/baselines/kisa/dense.jsonl` | 166222 | `9aacf60f0f9c4ba66d54f5855f9259c67d717caf1a0b0bca9e9cc5f14621c0a8` |
| `results__baselines__kisa__exact.jsonl` | `results/baselines/kisa/exact.jsonl` | 5988 | `992c1661fa6f9773deb5f312755018a1883b6b6462b5bfd62fafc828ded2c6b0` |
| `results__baselines__manifest.json` | `results/baselines/manifest.json` | 24764 | `5d539b6a98c2d379c9584e37ccbe474a699bdd08c19e4c06eca84074ab0e63e7` |
| `results__baselines__metrics.json` | `results/baselines/metrics.json` | 33318 | `c129a906ff1055f3dd3dafaeede2d7de12391ba95dad719a7a6460806e5385f0` |
| `results__baselines__public__bm25.jsonl` | `results/baselines/public/bm25.jsonl` | 298585 | `41556ebaeaa628bc78a27527447dc4f8dd86a82a4dd350f4c0092f74dfdf69e9` |
| `results__baselines__public__dense.jsonl` | `results/baselines/public/dense.jsonl` | 1035323 | `b159891e290360bdafc7efa556da8d6867d5880b0a1cbba267d0e37363259173` |
| `results__baselines__public__exact.jsonl` | `results/baselines/public/exact.jsonl` | 17051 | `699f0d51d7036e284107a33495a41c3857028308f653ebadaa921ac5f3ad2477` |

<!-- END ASSETS -->

내려받은 asset은 `shasum -a 256 <파일>`로 위 표와 대조한다. 리포 쪽 검사는 `uv run python scripts/check_release.py`다:

1. 목록의 항목이 허용 asset이고 파일이 있다.
2. `results/baselines/manifest.json`이 요구하는 원시 결과 6개와 질의셋이 모두 목록에 있다.
3. asset 사본의 sha256이 목록, 대응하는 리포 원본 파일, manifest의 입력 해시와 같다.
4. 허용 필드만 있다(결과 파일은 `scoring.validate_record`, 질의·정답 파일은 키 목록, JSON은 긴 문자열 없음).
5. asset 사본만으로 리포 레이아웃을 복원해 README 표를 다시 계산하면 README와 같다.

## 본문 유출 점검 (LICENSES/README.md 체크리스트 적용)

[LICENSES/README.md](../LICENSES/README.md)의 "본문 유출 방지 점검 대상"을 이 릴리스에 적용한 결과다.

| 점검 대상 | 이 릴리스에서의 적용 | 결과 |
|---|---|---|
| 노트북 입력/출력 셀 | 노트북은 asset에 없고 이 릴리스에서 바뀌지 않았다. 노트북에 KISA 식별자(`nttId`, `data/kisa`, `boho`)가 없음을 `grep -c`로 확인했다 | 해당 없음 (0건) |
| 검색 결과 원시 JSON | 결과 6개 파일 모두 `scoring.validate_record`로 허용 필드(질문 ID·문서 ID·순위·점수, `top1_score_raw`, `n_unjudged_removed`)만 허용 | `check_release.py` 통과 |
| 생성 답변 로그·평가 로그 | 이 릴리스에는 생성 답변과 로그 asset이 없다 | 해당 없음 |
| 판정자 요청·응답 로그 | `eval/golden/judgments/*.jsonl`은 asset이 아니다. asset인 `golden_v1.jsonl`은 질문 ID·문서 ID·문서 sha256·오프셋·고정 코드·집계만 허용(키 목록과 reason 고정 형식 검사) | `check_release.py` 통과 |
| 릴리스 첨부 파일 | asset 17개 전부 허용 필드 검사, JSON의 500자 초과 문자열 없음 | `check_release.py` 통과 |
| README·블로그의 예시 인용 | README에 공지 본문 인용 없음(표는 지표 값, 질문 ID는 합성 데이터와 공개 메타데이터뿐) | 해당 없음 |
| `scripts/check_kisa_leaks.py` (total_matches=0) | 본문 표본 검색은 KISA 캐시가 있는 체크아웃에서 돌려야 한다. 이 노트를 쓴 작업에서는 실행하지 않았고 머지 전·후 점검 결과는 PR에 기록한다 | 이 문서에는 결과를 적지 않음 |

## 한계

이 릴리스의 수치는 아래 한계 안에서만 읽는다.

**정답은 사람 검수가 아니다.**

- KISA 트랙 정답은 두 LLM(A: Anthropic `claude-opus-5-5`, B: OpenAI `gpt-6.1-sol`)의 독립 교차 판정이다. 둘 다 relevant로
  일치하고 근거 구간이 있는 공지만 `gold`다. 두 모델이 같은 방향으로 틀린 판정은 걸러지지 않는다. `status`는
  `cross_judged_not_human_verified`다.
- `product_symptom`·`explanation_comparison` 질문은 판정자 A와 같은 모델이 별도 호출로 썼다. 같은 모델이 질문을 쓰고 판정하므로
  A의 판정이 질문 의도와 맞아떨어지기 쉽다.
- 판정 묶음 밖 공지는 비관련으로 간주한다(풀링 평가). 묶음에 없던 관련 공지는 골든셋에서 빠지고, 이 때문에 점수가 낮게 나올 수 있다.
- 판정은 비결정적이다. 같은 명령을 다시 돌려도 같은 판정이 나온다고 주장하지 않는다. 판정 입력(공지 본문)은 재배포하지 않아
  제3자가 같은 판정을 재현할 수 없다.

**kappa** ([agreement.json](../eval/golden/agreement.json), 판정자 A·B 모두 유효한 이진 라벨을 낸 쌍 전체, `unjudged` 필터 전):

| 과제 | 쌍 | 일치율 | kappa |
|---|---|---|---|
| error_rate_sample (오라벨·누락 점검 표본) | 36 | 1.000 | 1.000 |
| cve_explicit | 21 | 1.000 | 정의 불가 (두 판정자가 모두 한 가지 라벨만 써서) |
| product_symptom | 23 | 1.000 | 1.000 |
| explanation_comparison | 14 | 0.857 | 0.417 |
| no_answer | 50 | 1.000 | 정의 불가 (두 판정자가 모두 한 가지 라벨만 써서) |

쌍 수가 14~50으로 작아 kappa의 신뢰 구간은 넓다. 일치율이 높은 것은 판정이 쉬운 질문이 많다는 뜻일 수 있고, 정답이 맞다는 증거가
아니다. 오라벨률 0/24, 누락률 0/12는 36쌍 표본이며 누락률은 후보 밖 점검 표본(같은 제품명 제목 공지)에서 잰 값이라 코퍼스 전체의 누락률이 아니다.

**`unjudged`와 `excluded` 건수.**

| 트랙 | 질문 | 채점 | `excluded` | `unjudged` |
|---|---|---|---|---|
| KISA | 54 | 52 | 2 (모두 `explanation_comparison`, dev 1 / test 1) | 4쌍, 질문 4개에 1건씩 (판정 갈림 2건 + 잘린 본문의 not_relevant 2건) |
| 공개 | 144 | 144 | 0 | `product_symptom` 60문항 전부에 질문당 39건 (총 2340쌍), 나머지 유형은 0 |

- KISA `excluded` 2건: `g1-ec-04`(dev)는 판정이 갈려 `gold`가 비었고, `g1-ec-02`(test)는 판정 묶음의 공지를 두 판정자가 모두 not_relevant로
  판정해 `gold`가 비었다. 둘 다 `no_answer`로 바꾸지 않고 채점에서 뺐다.
- 공개 트랙 `unjudged`의 원인은 NVD 레코드 39건에 CPE 구성(`configurations`)이 없어 제품 소속을 정할 수 없는 것이다
  (`vendor_products_status = no_configurations`). 절단된 CPE 목록 때문에 `unjudged`가 된 레코드는 0건이다
  (정답은 절단 없는 `vendor_products`로 정했다, [eval/public/manifest.json](../eval/public/manifest.json)).
  `unjudged`는 순위에서 지운 뒤 채점하므로(condensed list) 점수에 영향을 준다.

**트랙별 한계.**

- KISA 트랙은 로컬 캐시(`data/kisa`)가 있어야 재현된다. 본문은 재배포하지 않고(`LICENSES/README.md`), 판정 과정에서 본문이
  외부 모델 API 2종으로 전송됐다. 캐시가 없는 환경에서는 asset의 원시 결과로 표 일치 검증(`--check`)까지만 할 수 있다.
- 공개 트랙은 질문이 한국어, 문서가 영어(NVD 설명문)인 교차 언어 설정이다. 질문은 템플릿으로 만들어 문장 다양성이 낮고,
  `product_symptom` 정답은 CPE 메타데이터로 정했다. CPE는 색인하지 않으므로 설명문에 제품명이 없는 정답은 BM25가 찾을 수 없다.
  `explanation_comparison`은 공개 트랙에서 만들지 않았다(메타데이터로 기계적 정답을 정할 수 없고 LLM 판정은 쓰지 않는다).
- `no_answer`는 이 fixture 코퍼스에 없음을 기계적으로 확인한 CVE ID 질의로 한정한다. NVD 전체에 없다는 뜻이 아니다.

**표본 크기.** 공개 144문항(cve_explicit 60 / product_symptom 60 / no_answer 24), KISA 54문항(채점 52). split·유형별 n이
5~39이고 n_scored < 10인 칸(†)은 관찰로만 읽는다. dev에서 고른 k1·b·τ는 이 표본에서 잡음에 민감해 KISA 트랙에서는
BM25와 dense의 순서가 dev와 test에서 뒤바뀐다. 자세한 주의점은 [baselines.md 6절](baselines.md#6-해석할-때의-한계)에 있다.

**미검증 항목.**

- dense 재현: 커밋된 dense 결과는 #11 실행의 산출물이고, 이 릴리스 준비 작업에서 dense를 다시 실행하지 않았다. 위 dense 재현 명령과
  `--atol 1e-4`는 검증하지 않았다. 점수는 환경(torch 등)에 따라 달라질 수 있다.
- KISA 트랙 재현: 캐시가 없는 환경에서는 실행하지 않았다. 캐시가 있는 환경에서의 재실행 결과는 #11에서 만든 것이 전부다.
- 본문 유출 점검: 위 표의 `check_kisa_leaks.py`는 이 노트에서 실행 결과를 적지 않았다. 필드 허용 검사는 본문 유출의 일부 경로만 막는다.
- BM25 토큰화 대안(형태소 분석기 등)과의 점수 비교(ablation)는 하지 않았다([baselines.md](baselines.md) 3절).
- 질의 지연·색인 시간은 한 대의 머신(Apple M5 Pro, CPU 추론)에서 잰 값이다.
- test를 본 이력: 개발 중 실행에서 test 수치가 함께 출력됐다. 설정은 dev 기준으로 정했지만 이 사실은 남긴다([baselines.md](baselines.md) 6절).

## 라이선스

코드·문서·자작 평가 데이터는 MIT다. NVD·CISA KEV 서브셋은 `fixtures/nvd/NOTICE.md`의 고지를 따르며(NVD 공식 데이터로
표기하지 않는다), KISA 보안공지 본문은 재배포 조건이 확인되지 않아 포함하지 않는다. 소스별 범위는 [LICENSES/README.md](../LICENSES/README.md).

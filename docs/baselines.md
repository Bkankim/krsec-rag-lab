# 베이스라인 3종 (exact CVE lookup / BM25 / dense)

M2의 기준선이다. M3 실험(하이브리드, 리랭커, 청킹, 한영 교차, 임베딩 교체)은 이 문서의 수치와 설정을 비교 대상으로
쓴다. 채점 규칙의 정본은 [eval-protocol v2](eval-protocol.md)이고, 이 문서는 그 규칙을 어떻게 적용했는지와
측정 결과를 적는다. 모든 수치는 `results/baselines/`의 질문별 원시 결과와 `metrics.json`에서 나온다.

## 1. 무엇을 쟀나

두 트랙을 따로 보고한다(eval-protocol 11절: 문서 단위와 정답 출처가 달라 합산하거나 한 열로 비교하지 않는다).

| 항목 | 공개 트랙 | KISA 트랙 |
|---|---|---|
| 코퍼스 | `fixtures/nvd/cves.jsonl` 1560건 (문서 ID = CVE 레코드 `id`) | `fixtures/kisa/manifest.json`의 고정 공지 50건 (문서 ID = `nttId`) |
| 색인 텍스트 | `id` + 공백 + `description_en` (CPE·CWE·CVSS는 색인하지 않는다) | 공지 제목 + 줄바꿈 + 정규화 본문 |
| 질의·정답 | `eval/public/queries.jsonl`: 144문항 (dev 58 / test 86), 정답은 fixture 메타데이터로 기계적 결정 | `eval/golden/golden_v1.jsonl`: 54문항 중 `excluded` 2건 제외, 정답은 두 모델의 교차 판정(`gold`) |
| 새 클론 재현 | exact, BM25 (표준 라이브러리만) | 로컬 KISA 캐시 필요 (`--kisa-root`) |

검색기 3종의 점수는 `(점수 내림차순, 문서 ID 오름차순)`으로 정렬한다(7.4). dense는 코퍼스 전체에 점수를 매기고,
exact와 BM25는 질의와 일치한 문서에만 점수를 매겨 나머지 문서는 검색되지 않은 것으로 본다(정답이 있는 질문의 빈 결과는
0점, 7.2 B8).
채점 전에 질문의 `unjudged` 문서를 순위에서 지운다(condensed list, 1절). 지표는 `src/krsec_rag_lab/metrics.py`를
그대로 쓰고, 기권(abstain)은 `unjudged`를 지우기 전 원래 1위 점수를 쓴다.

KISA 트랙은 풀링 평가라 판정 묶음 밖 공지를 비관련으로 간주하고, 정답은 사람 검수가 아니라 두 모델의 일치다
(eval-protocol 1절 한계). 공개 트랙의 정답 규칙은 `eval/public/manifest.json`에 있다. 이 문서의 KISA 트랙 수치에는 공지
본문·요약·발췌가 들어 있지 않고, 질문 ID와 지표만 있다.

### 검색기

- **exact**: 질의에서 `splits.extract_cve_ids`로 CVE ID를 뽑아 그 ID를 키로 가진 문서를 돌려준다. 점수는 문서가 키로
  가진 질의 CVE ID의 개수다. CVE ID가 없는 질의와 코퍼스에 없는 ID는 빈 결과다(정답이 있는 질의에서 빈 결과는 0점으로
  평균에 들어간다, 7.2 B8). 공개 트랙의 문서 키는 레코드 `id`이고, KISA 트랙은 제목+본문에서 뽑은 CVE ID다
  (`fixtures/kisa/metadata.jsonl`의 `cve_ids`와 50건 전부 일치함을 확인했다).
- **BM25**: Okapi BM25 (idf = ln(1 + (N - df + 0.5) / (df + 0.5)), 질의 토큰 중복은 접음). 질의 토큰이 하나도 안 든
  문서는 검색되지 않는다(일치가 없는 질의는 빈 결과). 토큰화 규칙은 3절.
- **dense**: bge-m3 dense 출력만(sparse·colbert 헤드 미사용). 모델 `BAAI/bge-m3` revision
  `5617a9f61b028005a4858fdac845db406aefb181`, CLS pooling, L2 정규화, float32, `max_seq_length` 8192, CPU. 이 표현은
  `fixtures/embeddings_demo/manifest.json`(#5)과 같고 테스트가 대조한다. 질의 접두사 지시문은 쓰지 않는다. 점수는
  정규화 벡터의 내적(= 코사인)이고 코퍼스 전체를 전수로 훑는다(ANN 없음, eval-protocol 4절). 입력이 8192 토큰을 넘으면
  잘라 쓰고 잘린 문서 수를 manifest에 적는다(청킹은 M3).

## 2. 재현

```bash
uv sync --locked --dev
# 재현 확인: --out-dir을 주면 커밋된 results/baselines를 건드리지 않고 그 디렉터리에만 쓴다
OUT=$(mktemp -d)
uv run python scripts/run_baselines.py --track public --retriever exact --out-dir "$OUT"
uv run python scripts/run_baselines.py --track public --retriever bm25 --out-dir "$OUT"
# $OUT/public/*.jsonl이 results/baselines/public/*.jsonl과 문서 ID·순위가 같고 점수가 abs 1e-9 안인지 비교한다
# --out-dir 없이 돌리면 results/baselines를 새로 쓴다(manifest의 시각·소요 시간이 바뀐다)
# dense (CI에서는 돌리지 않는다): bge-m3를 HF에서 받는다
uv sync --locked --group embed
uv run --no-sync python scripts/run_baselines.py --track public --retriever dense
# KISA 트랙: KISA 캐시(data/kisa)가 있는 체크아웃 루트를 넘긴다
uv run --no-sync python scripts/run_baselines.py --track kisa --retriever bm25 --kisa-root <KISA-ROOT>
uv run python scripts/run_baselines.py --render-docs      # 아래 표를 metrics.json에서 다시 만든다
```

`--split`은 `dev`(설정 선택 + dev 결과), `test`(manifest에 확정된 설정으로 test만), `all`(기본값: dev에서 고른 뒤
test를 한 번 실행)이다. 결과 파일은 `results/baselines/<track>/<retriever>.jsonl`(질문 하나 = 한 줄: 질문 ID,
unjudged를 지운 상위 100건의 문서 ID·순위·점수, `top1_score_raw`, `n_unjudged_removed`만), 실행 메타데이터는
`results/baselines/manifest.json`, 지표는 `results/baselines/metrics.json`(결과 파일과 질의셋 라벨만으로 재계산)이다.
같은 입력이면 exact·BM25 결과는 실행마다 문서 ID·순위가 같고 점수가 같다(테스트 `test_rerun_is_deterministic`). manifest의 시각과 소요 시간만 실행마다 다르다.

## 3. 설정 판정

### 토큰화 규칙 (`bm25-tok-v1`)

**판정**: casefold(NFKC 없음) 뒤 세 종류의 토큰을 뽑는다. 나머지 문자는 버린다.

1. CVE ID(`cve-YYYY-NNNN+`)는 하이픈을 유지한 토큰 하나다. 경계는 `splits.py`와 같은 ASCII look-around다.
2. 영문·숫자 연속열(`[a-z0-9]+`)은 토큰 하나다. `_ : . -`와 공백은 구분자라 `windows_admin_center`는 세 토큰이다.
   어간 추출과 불용어 제거는 하지 않는다.
3. 한글 음절 연속열(`[가-힣]+`)은 겹치는 문자 2-gram이다(`취약점` -> `취약`, `약점`). 한 글자 연속열은 그 글자 하나다.

**이유**:

- 이 질의셋의 한국어 질문은 `CVE-2026-12345를`처럼 조사가 CVE ID에 바로 붙는다. 공백 분리는 이 토큰을 ID와 다른 토큰으로
  만들어 exact와 같은 정보를 쓰지 못한다. `\b` 경계도 한글을 `\w`로 보기 때문에 끝 경계를 못 찾는다(eval-protocol 5절).
  그래서 look-around 경계로 ID를 먼저 잘라낸다.
- CVE ID를 `cve`, `2026`, `12345`로 쪼개면 `cve`와 연도 토큰이 코퍼스 대부분에 공통이라 다른 ID가 걸린다. 하이픈을
  유지한 토큰은 ID가 같을 때만 일치한다(테스트 `test_bm25_cve_hyphen_kept_so_other_ids_do_not_match`).
- 한국어는 조사·어미가 어간에 붙는다. 형태소 분석기 없이 어간을 가르는 가장 단순한 방법이 문자 2-gram이고, 조사는 2-gram
  일부만 바꾼다(`취약점을` -> `취약`, `약점`, `점을`: 앞의 둘이 `취약점`과 일치). 사전이 없어 새 제품명·용어에도 같은 규칙이
  적용된다. 2-gram의 노이즈(`점을` 같은 조각)는 idf가 낮추거나 어디에도 없어 점수에 안 든다.
- 영문은 NVD 설명문과 제품명(`vendor:product`)이 주로 쓰는 단어 단위 토큰이면 충분하다. 어간 추출을 넣으면 제품명이
  뭉개지고 변수가 늘어난다. 변수는 M3에서 한 번에 하나씩 바꾼다(PLAN 원칙 2).

Rejected: 형태소 분석기(kiwi, mecab 등) | 공개 트랙 BM25가 표준 라이브러리만으로 돌아야 한다는 재현 조건(#13)과 충돌.
공백 분리만 | 조사가 붙은 CVE ID 질의가 일치하지 않음. 하이픈 분리 | 연도·`cve` 토큰이 다른 ID를 걸리게 함.
NFKC 정규화 | `CVE-2026-1234²`의 위첨자가 ID에 붙음(eval-protocol 5절). 한글 3-gram 이상 | 짧은 제품명·용어(`서버`)를 못 잡음.

Not-tested: 위 판정은 규칙의 설계 근거이고 대안 토큰화와의 점수 비교(ablation)는 하지 않았다. 질의 템플릿의 한국어
조각(`취약점`, `알려주세요`)이 KISA 코퍼스에서는 실제로 일치해 노이즈가 될 수 있다(KISA 트랙 BM25가 큰 k1(3.0)과 큰 b(0.9)를
고른 것과 관련이 있을 수 있으나 원인을 분리하지 않았다).

### BM25 k1·b (dev에서만 선택)

격자: k1 in {0.9, 1.2, 1.5, 2.0, 3.0} x b in {0.3, 0.5, 0.75, 0.9, 1.0}(25점). 기준은 dev의 macro nDCG@10(condensed,
정답이 있는 유형의 단순 평균)이고, 같으면 기본값(k1=1.2, b=0.75)을 먼저, 그다음 격자 순서에서 앞선 쪽을 고른다. 25점의
dev 값은 `manifest.json`의 `config.grid.rows`에 있다. 선택한 값은 아래 4절 표 아래에 적었다.

- 공개 트랙: dev 격자 25점의 macro nDCG@10이 0.8504~0.8533(세 가지 값)으로 거의 평평하다. 기본값(k1=1.2, b=0.75)이
  최댓값 0.8533과 같아 기본값이 선택된다. 이 질의셋에서 k1·b는 거의 구별되지 않는다.
- KISA 트랙: dev macro nDCG@10이 k1이 클수록, b가 클수록 오른다(0.5772~0.7970). 고른 점은 격자의 모서리 근처(k1=3.0,
  b=0.9)다. 첫 격자(k1 최대 2.0, b 최대 0.9)에서 최적이 모서리여서 k1 3.0과 b 1.0을 더했고, 확장 뒤에도 k1은 상한이다.
  dev 질문이 19개(정답 있는 질문)뿐이라 이 선택은 잡음에 민감하다. 격자를 더 넓히지 않고 이 한계를 적는다.

### 기권 τ (dev에서만 선택)

규칙: dev의 원래 1위 점수(`top1_score_raw`) 값들을 후보로 삼아 `abstain_rate - false_abstain_rate`(Youden J)를 최대로
하는 τ를 고르고, 같으면 가장 낮은 τ를 고른다. 결과가 빈 질문은 τ와 상관없이 기권이다(7.3). τ는 검색기마다 따로 정하고
test에는 그대로 적용한다(규칙 전체는 `manifest.json`의 `selected.tau_selection`). dev의 `no_answer`가 12건(공개) 또는
4건(KISA)이라 τ도 잡음에 민감하다.

## 4. 결과

아래 표는 `uv run python scripts/run_baselines.py --render-docs`가 `metrics.json`과 `manifest.json`에서 만든다
(직접 고치지 않는다). macro는 정답이 있는 유형의 단순 평균이고 `n_scored`는 평균에 들어간 질문 수다. `no_answer` 질문은
순위 지표가 정의되지 않아(7.3) 유형별 표에서는 빼고 별도 표에 적는다.

<!-- BEGIN GENERATED TABLES (scripts/run_baselines.py --render-docs) -->

### 공개 트랙 (NVD, 문서 = CVE 레코드)

#### 요약 (macro = 정답이 있는 유형의 단순 평균)

| 검색기 | split | n_scored | macro nDCG@10 | macro hit@10 | macro MRR@10 |
|---|---|---|---|---|---|
| exact | dev | 46 | 0.5000 | 0.5000 | 0.5000 |
| exact | test | 74 | 0.5000 | 0.5000 | 0.5000 |
| bm25 | dev | 46 | 0.8533 | 0.8571 | 0.8571 |
| bm25 | test | 74 | 0.8551 | 0.8974 | 0.8539 |
| dense | dev | 46 | 0.3977 | 0.5095 | 0.3905 |
| dense | test | 74 | 0.4353 | 0.5531 | 0.4517 |

#### 유형별

| 검색기 | split | 유형 | n_scored | n_skipped | n_excluded | nDCG@10 | hit@1 | hit@5 | hit@10 | recall@10 | MRR@10 | tie_at_cutoff@1/5/10 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| exact | dev | cve_explicit | 25 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0/0/0 |
| exact | dev | product_symptom | 21 | 0 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0/0/0 |
| exact | test | cve_explicit | 35 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0/0/0 |
| exact | test | product_symptom | 39 | 0 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0/0/0 |
| bm25 | dev | cve_explicit | 25 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0/0/0 |
| bm25 | dev | product_symptom | 21 | 0 | 0 | 0.7066 | 0.7143 | 0.7143 | 0.7143 | 0.7143 | 0.7143 | 1/10/9 |
| bm25 | test | cve_explicit | 35 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0/0/0 |
| bm25 | test | product_symptom | 39 | 0 | 0 | 0.7103 | 0.6667 | 0.7436 | 0.7949 | 0.6285 | 0.7077 | 8/14/16 |
| dense | dev | cve_explicit | 25 | 0 | 0 | 0.3121 | 0.2400 | 0.3200 | 0.4000 | 0.4000 | 0.2850 | 0/0/0 |
| dense | dev | product_symptom | 21 | 0 | 0 | 0.4833 | 0.4286 | 0.5714 | 0.6190 | 0.5667 | 0.4960 | 0/0/0 |
| dense | test | cve_explicit | 35 | 0 | 0 | 0.2271 | 0.1714 | 0.2857 | 0.2857 | 0.2857 | 0.2081 | 0/0/0 |
| dense | test | product_symptom | 39 | 0 | 0 | 0.6436 | 0.6154 | 0.8205 | 0.8205 | 0.5969 | 0.6953 | 0/0/0 |

† n_scored < 10: 우열 판정 없이 관찰로만 읽는다(eval-protocol 5절).

#### no_answer (기권)

| 검색기 | split | n_no_answer | τ | abstain_rate | n_answerable | false_abstain_rate |
|---|---|---|---|---|---|---|
| exact | dev | 12 | 1.0000 | 1.0000 | 46 | 0.4565 |
| exact | test | 12 | 1.0000 | 1.0000 | 74 | 0.5270 |
| bm25 | dev | 12 | 5.1918 | 1.0000 | 46 | 0.0217 |
| bm25 | test | 12 | 5.1918 | 1.0000 | 74 | 0.1351 |
| dense | dev | 12 | 0.6073 | 0.8333 | 46 | 0.4130 |
| dense | test | 12 | 0.6073 | 0.6667 | 74 | 0.5270 |

#### 색인 시간과 질의 지연

| 검색기 | 문서 수 | 색인 시간(초) | 질의 지연 중앙값(ms) | 측정한 질의 수 |
|---|---|---|---|---|
| exact | 1560 | 0.0005 | 0.0010 | 144 |
| bm25 | 1560 | 0.0100 | 0.0050 | 144 |
| dense | 1560 | 62.8373 | 44.7736 | 144 |

### KISA 트랙 (문서 = nttId)

#### 요약 (macro = 정답이 있는 유형의 단순 평균)

| 검색기 | split | n_scored | macro nDCG@10 | macro hit@10 | macro MRR@10 |
|---|---|---|---|---|---|
| exact | dev | 19 | 0.3333 | 0.3333 | 0.3333 |
| exact | test | 23 | 0.3333 | 0.3333 | 0.3333 |
| bm25 | dev | 19 | 0.7970 | 1.0000 | 0.7191 |
| bm25 | test | 23 | 0.9451 | 0.9697 | 0.9364 |
| dense | dev | 19 | 0.8802 | 0.9259 | 0.8648 |
| dense | test | 23 | 0.8131 | 0.8485 | 0.8023 |

#### 유형별

| 검색기 | split | 유형 | n_scored | n_skipped | n_excluded | nDCG@10 | hit@1 | hit@5 | hit@10 | recall@10 | MRR@10 | tie_at_cutoff@1/5/10 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| exact | dev | cve_explicit | 9† | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1/0/0 |
| exact | dev | product_symptom | 5† | 0 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0/0/0 |
| exact | dev | explanation_comparison | 5† | 0 | 1 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0/0/0 |
| exact | test | cve_explicit | 11 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0/0/0 |
| exact | test | product_symptom | 7† | 0 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0/0/0 |
| exact | test | explanation_comparison | 5† | 0 | 1 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0/0/0 |
| bm25 | dev | cve_explicit | 9† | 0 | 0 | 0.9285 | 0.8889 | 0.8889 | 1.0000 | 1.0000 | 0.9074 | 0/0/0 |
| bm25 | dev | product_symptom | 5† | 0 | 0 | 0.6623 | 0.2000 | 0.8000 | 1.0000 | 1.0000 | 0.5333 | 0/0/0 |
| bm25 | dev | explanation_comparison | 5† | 0 | 1 | 0.8003 | 0.6000 | 1.0000 | 1.0000 | 1.0000 | 0.7167 | 0/0/0 |
| bm25 | test | cve_explicit | 11 | 0 | 0 | 0.9091 | 0.9091 | 0.9091 | 0.9091 | 0.9091 | 0.9091 | 0/0/0 |
| bm25 | test | product_symptom | 7† | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0/0/0 |
| bm25 | test | explanation_comparison | 5† | 0 | 1 | 0.9262 | 0.8000 | 1.0000 | 1.0000 | 1.0000 | 0.9000 | 0/0/0 |
| dense | dev | cve_explicit | 9† | 0 | 0 | 0.7145 | 0.6667 | 0.7778 | 0.7778 | 0.7778 | 0.6944 | 0/0/0 |
| dense | dev | product_symptom | 5† | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0/0/0 |
| dense | dev | explanation_comparison | 5† | 0 | 1 | 0.9262 | 0.8000 | 1.0000 | 1.0000 | 1.0000 | 0.9000 | 0/0/0 |
| dense | test | cve_explicit | 11 | 0 | 0 | 0.4394 | 0.3636 | 0.4545 | 0.5455 | 0.5455 | 0.4069 | 0/0/0 |
| dense | test | product_symptom | 7† | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0/0/0 |
| dense | test | explanation_comparison | 5† | 0 | 1 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0/0/0 |

† n_scored < 10: 우열 판정 없이 관찰로만 읽는다(eval-protocol 5절).

#### no_answer (기권)

| 검색기 | split | n_no_answer | τ | abstain_rate | n_answerable | false_abstain_rate |
|---|---|---|---|---|---|---|
| exact | dev | 4 | 1.0000 | 1.0000 | 19 | 0.5263 |
| exact | test | 6 | 1.0000 | 1.0000 | 23 | 0.5217 |
| bm25 | dev | 4 | 11.4362 | 1.0000 | 19 | 0.1579 |
| bm25 | test | 6 | 11.4362 | 1.0000 | 23 | 0.3043 |
| dense | dev | 4 | 0.6149 | 0.7500 | 19 | 0.1579 |
| dense | test | 6 | 0.6149 | 0.5000 | 23 | 0.2174 |

#### 색인 시간과 질의 지연

| 검색기 | 문서 수 | 색인 시간(초) | 질의 지연 중앙값(ms) | 측정한 질의 수 |
|---|---|---|---|---|
| exact | 50 | 0.0003 | 0.0012 | 52 |
| bm25 | 50 | 0.0099 | 0.0286 | 52 |
| dense | 50 | 56.5810 | 45.2021 | 52 |

<!-- END GENERATED TABLES -->

## 5. CVE 명시 질의: exact를 못 이기는 검색기의 비용

**판정**: `cve_explicit` 유형에서 exact를 이긴 검색기는 없다. 두 트랙 모두 exact의 nDCG@10은 1.0이다(공개 60문항,
KISA 20문항, 전부 첫 정답이 1위). BM25는 공개 트랙에서 exact와 같고 KISA 트랙에서 못 미치며, dense는 두 트랙에서 크게
못 미친다. CVE ID가 질의에 있으면 exact를 먼저 두고 BM25·dense는 그 뒤에 두는 것이 이 기준선에서 비용 대비 낫다.
반대로 CVE ID가 없는 질문(`product_symptom`, `explanation_comparison`)은 exact가 빈 결과라 0점이다. exact는 CVE 질의의
하한선일 뿐 일반 검색기가 아니다. 공개 트랙 exact의 `false_abstain_rate`가 0.46~0.53인 것도 CVE ID가 없는 질문을 전부
기권으로 돌려서다.

**근거 (질문별 실패 사례)**: 첫 정답이 1위가 아닌 `cve_explicit` 질문이다. 순위는 condensed list 기준이다.

| 트랙 | 검색기 | 1위가 아닌 문항 / 전체 | 질문 ID (분할, 첫 정답 순위) |
|---|---|---|---|
| 공개 | exact | 0 / 60 | 없음 |
| 공개 | BM25 | 0 / 60 | 없음 (CVE ID 토큰이 정답 레코드와만 일치) |
| 공개 | dense | 48 / 60 (1위 12건, 2~10위 8건, 11~100위 20건, 100위 밖 20건) | 100위 밖 20건 중 5건: `pub-cve-0002`(test) `pub-cve-0004`(test) `pub-cve-0006`(test) `pub-cve-0008`(dev) `pub-cve-0014`(test). 2위: `pub-cve-0001`(test). 3위: `pub-cve-0012`(test). 전체는 `results/baselines/public/dense.jsonl`에서 `cve_explicit` 질문의 정답 순위로 뽑는다 |
| KISA | exact | 0 / 20 | 없음 |
| KISA | BM25 | 2 / 20 | `g1-cve-2026-62817`(test, 41위), `g1-cve-2026-69834`(dev, 6위) |
| KISA | dense | 10 / 20 | `g1-cve-2025-68686`(dev, 4위) `g1-cve-2026-10816`(test, 22위) `g1-cve-2026-14669`(test, 3위) `g1-cve-2026-48448`(test, 14위) `g1-cve-2026-53873`(test, 7위) `g1-cve-2026-60696`(dev, 12위) `g1-cve-2026-62817`(test, 40위) `g1-cve-2026-63030`(test, 33위) `g1-cve-2026-6637`(test, 25위) `g1-cve-2026-69834`(dev, 39위) |

- 공개 dense가 CVE ID 질의에서 약한 이유(추정, 확인하지 않음): 임베딩은 CVE ID의 숫자열을 서브워드 조각으로 보므로
  ID 일치가 순위를 정하는 힘이 약하고, 질문 템플릿과 설명문의 주제 유사도가 순위에 섞인다. 관측된 사실은 60건 중 20건에서
  정답 레코드가 상위 100건에도 없다는 것이다.
- KISA BM25의 두 실패는 둘 다 정기 보안 업데이트 권고(CVE 인용 996건, 423건 - `fixtures/kisa/metadata.jsonl`의 `cve_ids`
  개수)가 정답인 질문이다: `g1-cve-2026-69834`의 정답 공지는 996건, `g1-cve-2026-62817`의 정답 공지는 423건을 인용한다.
  이 공지들은 토큰이 많아 길이 정규화(b가 큼)가 점수를 깎고, 짧은 공지가 질의의 한국어 조각과 일치해 앞선다. exact는 ID 일치만
  보므로 영향이 없다. 이 설명은 인용 개수(공개 메타데이터)와 순위에서 나온 추정이고 BM25 점수 구성 요소를 분해해 확인하지는 않았다.
- 비용 (이 머신에서 잰 값, 4절의 색인 시간 표와 같다): exact와 BM25의 색인은 마이크로~밀리초이고 질의 지연은
  마이크로초 단위다. dense는 공개 트랙 1560건에 약 1분, KISA 50건(긴 공지 포함)에도 약 1분이 걸리고(배치 크기 2,
  CPU) 질의 하나에 수십 ms가 든다. 질의 지연은 exact보다 4~5자릿수 크다. 모델 가중치 약 2.1GB를 HF에서 받아야 하고
  `embed` 그룹(torch, sentence-transformers)이 필요해 CI에서는 돌리지 않는다. KISA 트랙 dense는 2건이 8192 토큰을 넘어
  잘렸다(최대 22749 토큰, 청킹은 M3).

측정 환경: Apple M5 Pro(18 코어), macOS 27.2, Python 3.13.14, torch 2.14.1, sentence-transformers 6.1.0, numpy 2.5.3,
CPU 추론(`device=cpu`). 색인 시간은 코퍼스 인코딩(dense) 또는 역색인 구축(exact, BM25)만 잰 값이고 모델 로딩 시간은
뺀다. 질의 지연은 질의 하나의 점수 계산 + 정렬을 질의마다 잰 중앙값이다(dev와 test 질문 전체, 첫 호출의 워밍업 포함).
다른 하드웨어에서는 절대값이 달라진다.

## 6. 해석할 때의 한계

- **표본이 작다.** KISA 트랙은 유형별 n이 5~11이고, 표시한 n_scored < 10(†)은 우열 판정 없이 관찰로만 쓴다
  (eval-protocol 5절). dev에서 고른 k1·b·τ는 이 표본에서 잡음에 민감하다. 예를 들어 KISA 트랙에서
  BM25와 dense의 macro nDCG@10 순서가 dev(dense 0.8802 > BM25 0.7970)와 test(BM25 0.9451 > dense 0.8131)에서 뒤바뀐다.
  유형별 n이 5~11이라 어느 쪽이 낫다고 판정하지 않는다.
- **KISA 정답은 모델 교차 판정이고 풀링 평가다.** 판정 묶음 밖 공지에 숨은 정답이 있으면 점수가 낮게 나온다.
  `explanation_comparison`은 정답이 1~2건이라 BM25와 dense의 차이가 한두 질문에서 갈린다.
- **공개 트랙 `product_symptom`의 exact는 정의상 0점**이다(CVE ID가 없어 빈 결과). exact가 BM25·dense보다 낮은 이유는
  검색 품질이 아니라 이 유형이 CVE 조회로 풀리지 않기 때문이다.
- **공개 트랙 `product_symptom`의 BM25**: 60문항 중 nDCG@10이 1.0인 질문 35건, 0.0인 질문 14건, 중간 11건이다. 정답은
  CPE 메타데이터로 정했고 CPE는 질의가 정답을 보고 풀지 않도록 색인하지 않았으므로, 설명문에 제품명이 없는 정답은 BM25가
  찾을 수 없다. 0점 14건의 원인이 이것인지는 질문별로 분해하지 않았다.
- **test를 본 이력.** `--split all`이 기본이라 개발 중 실행에서 test 수치가 출력에 함께 보였다. 개발 중에 바꾼 두 가지는
  (1) 동점이면 기본값(k1=1.2, b=0.75)을 고르는 규칙(공개 트랙 dev 격자가 평평해 임의 선택을 피하려고), (2) KISA dev 최적이
  격자 모서리라 격자를 4x4에서 5x5로 넓힌 것이다. 둘 다 dev 기준으로 정했지만 같은 실행 출력에 test 수치가 있었다는
  사실은 남긴다. 아래 결과는 설정을 확정한 코드로 모든 조합을 처음부터 다시 실행한 것이다(test는 확정 설정으로 한 번).
- **동점의 영향.** 동점은 문서 ID 사전순으로 깬다(7.4). 공개 트랙 BM25 `product_symptom`은 같은 길이·같은 토큰 구성의
  설명문이 많아 test에서 질문 39건 중 5위 경계 동점이 14건, 10위 경계 동점이 16건이다(표의 `tie_at_cutoff`). 이 유형의 hit/nDCG는
  동점 안에서 ID 순서에 일부 의존한다. 정답 라벨과 무관한 규칙이라 편향은 없다고 가정하지만 검증된 가정은 아니다.
- **dense 점수는 환경에 따라 소수 자리가 달라질 수 있다.** 재현 대조는 exact·BM25만 요구한다(dense는 CI에서 돌리지 않는다).

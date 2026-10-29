# krsec-rag-lab

한국어 보안 문서 RAG 평가 하네스 - 온프렘 스택 ablation 리포트. Bkankim의 단독 프로젝트다.

KISA 보안공지(한국어)와 NVD CVE(영어)를 코퍼스로, 두 LLM이 교차 판정한 골든 평가셋 위에서
RAG 파이프라인의 각 구성요소(청킹·하이브리드 검색·리랭킹·임베딩)를 하나씩 바꿔가며
검색·생성 품질과 비용(지연시간·VRAM)을 측정한 기록을 남긴다.

핵심 원칙:

- **측정이 먼저다.** 모든 실험은 가설 → 측정 → 판정(기각 포함)으로 종료한다. 데모는 부록이다.
- **재현 가능해야 한다.** README의 모든 수치는 릴리스에 첨부된 질문별 원시 결과에서 재생성된다
  (`uv run python scripts/make_readme_tables.py --check`가 일치를 검증한다).
- **온프렘으로 돌아간다.** 로컬 임베딩(bge-m3) + Qdrant + 로컬 LLM. 검색·생성 실행에는 외부 API 의존이 없다.
  예외: 골든셋 정답 판정에는 외부 모델 API 2종을 쓴다(KISA 본문 전송 고지는 [LICENSES/](LICENSES/)).
- **정답의 한계를 밝힌다.** 평가 정답은 두 LLM(Anthropic Opus 계열, OpenAI GPT 계열)의 교차 판정이며 사람 검수가
  아니다. 두 판정자가 모두 relevant로 일치하고 근거 구간이 있는 문서만 정답으로 확정하고 불일치·kappa를 기록한다. 공개 트랙(NVD fixture)의
  정답만 LLM 판정 없이 메타데이터로 정한다(정의: [docs/eval-protocol.md](docs/eval-protocol.md)).

## 상태

**M4 완료, v0.3** - KISA 보안공지 게시판 전체를 한 번 수집해 누락·중복·파싱 실패를 센 결과와, 그 코퍼스를 Qdrant에
증분 동기화해 갱신·삭제·재인덱싱 멱등성 1~5단계를 검증한 결과를 v0.3 릴리스로 묶었다(아래 "M4 결과"). 평가 트랙의
고정 50건과 M2·M3 결과는 바뀌지 않았다. 릴리스 노트(asset 목록·sha256·한계): [docs/release-v0.3.md](docs/release-v0.3.md),
수집 보고: [docs/m4-collection.md](docs/m4-collection.md), 색인 보고: [docs/m4-idempotency.md](docs/m4-idempotency.md).

이전 릴리스: M3 완료, v0.2(M3 실험 5개, 다섯 주 판정이 모두 `hypothesis-rejected`, 아래 "M3 실험 결과").
노트: [docs/release-v0.2.md](docs/release-v0.2.md), 실험 요약: [docs/experiments/summary.md](docs/experiments/summary.md).
M2 완료, v0.1(베이스라인 3종 exact CVE lookup / BM25 / dense bge-m3, 두 트랙). 노트: [docs/release-v0.1.md](docs/release-v0.1.md).
M5 이후의 로드맵은 [PLAN.md](PLAN.md)와 [Milestones](../../milestones)에 있다.

## 평가 트랙과 재현

평가는 두 트랙으로 나눈다. 문서 단위와 정답 출처가 달라 두 트랙의 수치를 합치거나 한 열로 비교하지 않는다
(정의: [docs/eval-protocol.md](docs/eval-protocol.md) 11절).

| | 공개 트랙 | KISA 트랙 |
|---|---|---|
| 코퍼스 | `fixtures/nvd/cves.jsonl`의 NVD CVE 레코드 1560건 | `fixtures/kisa/manifest.json`의 고정 KISA 공지 50건 |
| 질문·정답 | `eval/public/queries.jsonl` 144문항, 정답은 NVD 메타데이터로 기계적 결정(LLM 판정 없음) | `eval/golden/golden_v1.jsonl` 54문항, 정답은 두 모델의 교차 판정 |
| 재현 조건 | 새 클론에서 `uv sync --locked --dev`만으로 exact·BM25 재현 (dense는 `embed` 그룹) | 로컬 KISA 캐시(`data/kisa`)가 있어야 한다(본문은 재배포하지 않는다) |

**공개 트랙** (새 클론, 네트워크·KISA 캐시 불필요). `--out-dir`을 주면 커밋된 `results/baselines`를 건드리지 않는다:

```bash
git clone https://github.com/Bkankim/krsec-rag-lab.git && cd krsec-rag-lab
uv sync --locked --dev
OUT=$(mktemp -d)
uv run python scripts/run_baselines.py --track public --retriever exact --out-dir "$OUT"
uv run python scripts/run_baselines.py --track public --retriever bm25 --out-dir "$OUT"
uv run python scripts/check_release.py --compare-results "$OUT"   # 커밋된 결과와 문서 ID·순위·점수(abs 1e-9) 비교
```

dense(bge-m3, 모델 약 2.1GB를 내려받는다)는 별도 단계다. 점수의 소수 자리는 환경에 따라 달라질 수 있다:

```bash
OUT=$(mktemp -d)
uv sync --locked --group embed
uv run --no-sync python scripts/run_baselines.py --track public --retriever dense --out-dir "$OUT"
```

**KISA 트랙** (KISA 캐시가 있는 체크아웃 루트를 `--kisa-root`로 넘긴다. 캐시 수집은 아래 "KISA 소표본"):

```bash
OUT=$(mktemp -d)
uv run --no-sync python scripts/run_baselines.py --track kisa --retriever bm25 --kisa-root <KISA 캐시가 있는 체크아웃> --out-dir "$OUT"
```

README 표와 원시 결과의 일치 검증(네트워크·캐시 불필요, 베이스라인 표, M3 판정 표, M4 표 모두):

```bash
uv run python scripts/make_readme_tables.py --check
uv run python scripts/check_release.py                                  # v0.1 asset 검사
uv run python scripts/check_release.py --note docs/release-v0.2.md      # v0.2 asset 검사
uv run python scripts/check_release.py --note docs/release-v0.3.md      # v0.3 asset 검사
```

**M3 실험** (모델·KISA 캐시 없이 저장본에서 `metrics.json`·`comparison.json`을 다시 계산해 커밋된 파일과 대조한다.
불일치는 종료 코드 1). 모델이 필요한 실험 재실행 명령과 한계는 실험별 보고서와
[docs/release-v0.2.md](docs/release-v0.2.md)의 재현 절에 있다:

```bash
for exp in hybrid rerank chunking crossling embedding; do
  uv run python scripts/run_experiment.py --exp "$exp" --compare
done
```

## 결과

기준선 3종의 질문별 원시 결과(`results/baselines/`)에서 다시 계산한 표다. 설정(BM25 k1·b, 기권 τ)은 dev에서만 골랐고
test는 확정한 설정으로 한 번 쟀다. 해석과 질문별 실패 사례는 [docs/baselines.md](docs/baselines.md)에 있다.

<!-- BEGIN GENERATED TABLES (scripts/make_readme_tables.py) -->

이 구간은 `scripts/make_readme_tables.py`가 질문별 원시 결과(`results/baselines/`)에서 다시 계산해 쓴다. 손으로 고치지 않는다. 검증: `uv run python scripts/make_readme_tables.py --check`. macro는 정답이 있는 유형의 단순 평균이다. † 표시는 n_scored < 10이라 우열 판정 없이 관찰로만 읽는다.

### 공개 트랙 (NVD fixture, 문서 = CVE 레코드)

| 검색기 | split | 채점 질문 | 제외 | macro nDCG@10 | macro hit@10 | macro MRR@10 |
|---|---|---|---|---|---|---|
| exact | dev | 58 | 0 | 0.5000 | 0.5000 | 0.5000 |
| exact | test | 86 | 0 | 0.5000 | 0.5000 | 0.5000 |
| bm25 | dev | 58 | 0 | 0.8533 | 0.8571 | 0.8571 |
| bm25 | test | 86 | 0 | 0.8551 | 0.8974 | 0.8539 |
| dense | dev | 58 | 0 | 0.3977 | 0.5095 | 0.3905 |
| dense | test | 86 | 0 | 0.4353 | 0.5531 | 0.4517 |

유형별 (no_answer는 아래 기권 표):

| 검색기 | split | 유형 | n_scored | nDCG@10 | hit@1 | hit@10 | recall@10 | MRR@10 |
|---|---|---|---|---|---|---|---|---|
| exact | dev | cve_explicit | 25 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| exact | dev | product_symptom | 21 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| exact | test | cve_explicit | 35 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| exact | test | product_symptom | 39 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| bm25 | dev | cve_explicit | 25 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| bm25 | dev | product_symptom | 21 | 0.7066 | 0.7143 | 0.7143 | 0.7143 | 0.7143 |
| bm25 | test | cve_explicit | 35 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| bm25 | test | product_symptom | 39 | 0.7103 | 0.6667 | 0.7949 | 0.6285 | 0.7077 |
| dense | dev | cve_explicit | 25 | 0.3121 | 0.2400 | 0.4000 | 0.4000 | 0.2850 |
| dense | dev | product_symptom | 21 | 0.4833 | 0.4286 | 0.6190 | 0.5667 | 0.4960 |
| dense | test | cve_explicit | 35 | 0.2271 | 0.1714 | 0.2857 | 0.2857 | 0.2081 |
| dense | test | product_symptom | 39 | 0.6436 | 0.6154 | 0.8205 | 0.5969 | 0.6953 |

no_answer (기권):

| 검색기 | split | n_no_answer | τ | abstain_rate | n_answerable | false_abstain_rate |
|---|---|---|---|---|---|---|
| exact | dev | 12 | 1.0000 | 1.0000 | 46 | 0.4565 |
| exact | test | 12 | 1.0000 | 1.0000 | 74 | 0.5270 |
| bm25 | dev | 12 | 5.1918 | 1.0000 | 46 | 0.0217 |
| bm25 | test | 12 | 5.1918 | 1.0000 | 74 | 0.1351 |
| dense | dev | 12 | 0.6073 | 0.8333 | 46 | 0.4130 |
| dense | test | 12 | 0.6073 | 0.6667 | 74 | 0.5270 |

### KISA 트랙 (문서 = nttId, 로컬 캐시로 만든 결과)

| 검색기 | split | 채점 질문 | 제외 | macro nDCG@10 | macro hit@10 | macro MRR@10 |
|---|---|---|---|---|---|---|
| exact | dev | 23 | 1 | 0.3333 | 0.3333 | 0.3333 |
| exact | test | 29 | 1 | 0.3333 | 0.3333 | 0.3333 |
| bm25 | dev | 23 | 1 | 0.7970 | 1.0000 | 0.7191 |
| bm25 | test | 29 | 1 | 0.9451 | 0.9697 | 0.9364 |
| dense | dev | 23 | 1 | 0.8802 | 0.9259 | 0.8648 |
| dense | test | 29 | 1 | 0.8131 | 0.8485 | 0.8023 |

유형별 (no_answer는 아래 기권 표):

| 검색기 | split | 유형 | n_scored | nDCG@10 | hit@1 | hit@10 | recall@10 | MRR@10 |
|---|---|---|---|---|---|---|---|---|
| exact | dev | cve_explicit | 9† | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| exact | dev | product_symptom | 5† | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| exact | dev | explanation_comparison | 5† | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| exact | test | cve_explicit | 11 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| exact | test | product_symptom | 7† | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| exact | test | explanation_comparison | 5† | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| bm25 | dev | cve_explicit | 9† | 0.9285 | 0.8889 | 1.0000 | 1.0000 | 0.9074 |
| bm25 | dev | product_symptom | 5† | 0.6623 | 0.2000 | 1.0000 | 1.0000 | 0.5333 |
| bm25 | dev | explanation_comparison | 5† | 0.8003 | 0.6000 | 1.0000 | 1.0000 | 0.7167 |
| bm25 | test | cve_explicit | 11 | 0.9091 | 0.9091 | 0.9091 | 0.9091 | 0.9091 |
| bm25 | test | product_symptom | 7† | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| bm25 | test | explanation_comparison | 5† | 0.9262 | 0.8000 | 1.0000 | 1.0000 | 0.9000 |
| dense | dev | cve_explicit | 9† | 0.7145 | 0.6667 | 0.7778 | 0.7778 | 0.6944 |
| dense | dev | product_symptom | 5† | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| dense | dev | explanation_comparison | 5† | 0.9262 | 0.8000 | 1.0000 | 1.0000 | 0.9000 |
| dense | test | cve_explicit | 11 | 0.4394 | 0.3636 | 0.5455 | 0.5455 | 0.4069 |
| dense | test | product_symptom | 7† | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| dense | test | explanation_comparison | 5† | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

no_answer (기권):

| 검색기 | split | n_no_answer | τ | abstain_rate | n_answerable | false_abstain_rate |
|---|---|---|---|---|---|---|
| exact | dev | 4 | 1.0000 | 1.0000 | 19 | 0.5263 |
| exact | test | 6 | 1.0000 | 1.0000 | 23 | 0.5217 |
| bm25 | dev | 4 | 11.4362 | 1.0000 | 19 | 0.1579 |
| bm25 | test | 6 | 11.4362 | 1.0000 | 23 | 0.3043 |
| dense | dev | 4 | 0.6149 | 0.7500 | 19 | 0.1579 |
| dense | test | 6 | 0.6149 | 0.5000 | 23 | 0.2174 |

<!-- END GENERATED TABLES (scripts/make_readme_tables.py) -->

## M3 실험 결과

실험 5개는 한 번에 한 요소만 바꿔 M2 베이스라인과 같은 입력·같은 채점으로 비교했다. 가설, 주 트랙, 판정 규칙은 test를
돌리기 전에 고정했고(런 스펙 이슈 #43), test는 dev에서 확정한 설정으로 한 번만 돌았다. 실험 이름은 각 보고서(가설, 구성, 재현
명령, 질문별 실패 사례, 한계)로 링크된다. 보조 트랙과 `cve_explicit` 회귀 여부까지 한 표에 모은 요약과 다음 실험 후보는
[docs/experiments/summary.md](docs/experiments/summary.md), 하네스 계약은 [docs/experiments/README.md](docs/experiments/README.md)에 있다.

<!-- BEGIN M3 TABLES (scripts/make_readme_tables.py) -->

이 구간은 `scripts/make_readme_tables.py`가 `results/experiments/`의 질문별 원시 결과와 질의셋 라벨에서 하네스의 비교 함수(`krsec_rag_lab.experiments.compare`)로 다시 계산해 쓴다. 손으로 고치지 않는다. 검증: `uv run python scripts/make_readme_tables.py --check`. 지표는 test macro nDCG@10(condensed list, 정답이 있는 유형의 단순 평균)이고 delta = 실험 - 기준이다. 95% 구간은 test 질문을 유형별로 층화 복원추출한 paired bootstrap(10000회, 시드 20261029)의 2.5/97.5 백분위이며, delta > 0 이고 구간 하한 > 0 일 때만 `hypothesis-confirmed`다.

주 판정 5건: hypothesis-confirmed 0, hypothesis-rejected 5.

| 실험 | 주 트랙 (변형) | 기준 | test n | 기준 macro nDCG@10 | 실험 macro nDCG@10 | delta | 95% 구간 | 판정 |
|---|---|---|---|---|---|---|---|---|
| [hybrid](docs/experiments/hybrid.md) | public (rrf) | bm25 | 74 | 0.8551 | 0.8775 | +0.0223 | [-0.0117, +0.0616] | `hypothesis-rejected` |
| [rerank](docs/experiments/rerank.md) | public (rerank) | bm25 | 74 | 0.8551 | 0.8581 | +0.0030 | [-0.0206, +0.0244] | `hypothesis-rejected` |
| [chunking](docs/experiments/chunking.md) | kisa (chunk_max) | dense | 23 | 0.8131 | 0.8785 | +0.0654 | [-0.0082, +0.1510] | `hypothesis-rejected` |
| [crossling](docs/experiments/crossling.md) | public (bm25_ko2en) | bm25 | 74 | 0.8551 | 0.2771 | -0.5780 | [-0.6723, -0.4832] | `hypothesis-rejected` |
| [embedding](docs/experiments/embedding.md) | public (swap) | dense | 74 | 0.4353 | 0.4393 | +0.0040 | [-0.0637, +0.0726] | `hypothesis-rejected` |

<!-- END M3 TABLES (scripts/make_readme_tables.py) -->

## M4 결과

KISA 보안공지 게시판(`bbsId=B0000133`) 전체를 한 번 수집한 계측과, 그 스냅샷을 Qdrant 컬렉션에 맞추는 증분 동기화의
멱등성 검증 결과다. 평가 트랙의 고정 50건(`fixtures/kisa`)은 바꾸지 않았고, 전체 코퍼스는 `fixtures/kisa_full/`(메타데이터와
manifest)와 로컬 캐시에 따로 둔다. 본문은 커밋하지 않는다. 수집 규칙·재현 명령·해석은
[docs/m4-collection.md](docs/m4-collection.md), 동기화 규칙·검증 시나리오·`max_seq_length` 근거는
[docs/m4-idempotency.md](docs/m4-idempotency.md)에 있다. 수집은 KISA 사이트에, 멱등성 검증은 Docker(Qdrant)와 임베딩
모델에 접근해야 재실행된다. 아래 표와 저장본의 대조는 둘 다 필요 없다.

<!-- BEGIN M4 TABLES (scripts/make_readme_tables.py) -->

이 구간은 `scripts/make_readme_tables.py`가 `results/m4/collection/report.json`, `results/m4/idempotency/report.json`, `fixtures/kisa_full/manifest.json`, `fixtures/kisa_full/metadata.jsonl`에서 다시 만들어 쓴다. 손으로 고치지 않는다. 검증: `uv run python scripts/make_readme_tables.py --check`. 보고서와 manifest의 건수가 서로 맞는지 대조한 뒤에 표를 만든다.

### 전체 수집: 규모, 누락, 중복, 파싱 실패 ([m4-collection.md](docs/m4-collection.md))

| 항목 | 값 |
|---|---|
| 발견 ID (고정 대상) | 2592 |
| 게시판 표시 총수 / 차이 | 2592 / 0 |
| 상세 성공 | 2590 |
| 상세 실패 (fetch_failed) | 0 |
| 파싱 실패 | 2 (`parse_failed:empty_article`: 71467, 71509) |
| 미처리 | 0 |
| 누락 (발견했지만 `ok` 아님) | 2 (71467, 71509) |
| 목록 페이지 / 원시 행 | 262 / 3902 |
| 목록 중복: 페이지 안 / 페이지 사이 | 5 / 1305 |
| 목록 중복 ID / 제목·날짜 충돌 ID | 5 (72027, 72132, 72133, 72207, 72230) / 0 |
| 내용 중복 (본문 sha256이 같은 묶음 / 문서) | 0 / 0 |
| RSS 항목 / 목록에 없는 RSS 전용 ID | 10 / 0 |
| 고정 50건 포함 / 본문 sha256 일치 | 50 / 50 (기대 50) |
| 메타데이터 행 / CVE ID가 있는 행 / 서로 다른 CVE ID | 2590 / 1832 / 21168 |
| 수집 완료 / 중단 | 예 / 없음 |
| 요청 수 | 2856 (robots 1, RSS 1, 목록 262, 상세 2592) |
| 소요 시간 (초) | 4935.4 |

### 멱등성 검증 1~5단계 ([m4-idempotency.md](docs/m4-idempotency.md))

검증 통과 (갱신·삭제·추가 각 5건, 시드 59, 실패 단계 없음, 소요 2598.7초).

| 항목 | 값 |
|---|---|
| 스냅샷 | 대상 ID 2592, `ok` 2590, 파싱 실패 2, 기준 스냅샷 2585 |
| 모델 | `BAAI/bge-m3` revision `5617a9f61b028005a4858fdac845db406aefb181` |
| pooling / dtype / 차원 | cls / float32 / 1024 |
| `max_seq_length` / batch_size / 장치 | 8192 / 1 / cpu |
| Qdrant | 서버 1.19.2, 이미지 `qdrant/qdrant:v1.19.2` |
| 런타임 | Python 3.13.14, sentence-transformers 6.1.0, torch 2.14.1, numpy 2.5.3, qdrant-client 1.19.1 |
| 환경 | Darwin arm64, 코어 18, `OMP_NUM_THREADS=8` |
| 허용오차 | 영향 없는 point 0.0, 벡터 abs 1e-05 |

| 단계 | 동작 | 계획 (추가/갱신/삭제) | point 수 | 인코딩 | 쓰기 (upsert/payload/delete) | 비교 | 통과 | 소요 (초) |
|---|---|---|---|---|---|---|---|---|
| 1 | `full_sync_baseline` | 2585/0/0 | 2585 | 2585 | 2585/0/0 | point 수 = 스냅샷 문서 수 | 예 | 1298.6 |
| 2 | `resync_same_snapshot` | 0/0/0 | 2585 | 0 | 0/0/0 | ID 집합·payload 동일, 벡터 최대 차 0.0 | 예 | 0.8 |
| 3 | `incremental_variant` | 5/5/5 | 2585 | 10 | 10/0/5 | point 수 = 스냅샷 문서 수, 영향 없는 2575건 중 2575건 동일, 갱신 벡터 변경 5건, 삭제 확인, 추가 확인 | 예 | 9.1 |
| 4 | `from_scratch_variant` | 2585/0/0 | 2585 | 2585 | 2585/0/0 | ID 집합·payload 동일, 벡터 최대 차 0.0 | 예 | 1283.6 |
| 5 | `revert_to_baseline` | 5/5/5 | 2585 | 10 | 10/0/5 | ID 집합·payload 동일, 벡터 최대 차 0.0 | 예 | 4.4 |

<!-- END M4 TABLES (scripts/make_readme_tables.py) -->

## 한계

- 정답은 두 LLM의 교차 판정이고 사람 검수가 아니다. kappa·`unjudged`·`excluded` 건수와 미검증 항목:
  [docs/release-v0.1.md 한계 절](docs/release-v0.1.md#한계), 판정 설정과 한계: [eval/golden/judge_manifest.json](eval/golden/judge_manifest.json).
- 표본이 작다(KISA 트랙은 채점 대상 52문항이고 split·유형별 n은 더 작다). 지표 해석의 주의점은 [docs/baselines.md 6절](docs/baselines.md#6-해석할-때의-한계)에 있다.
- KISA 트랙은 로컬 캐시가 있어야 재현된다. 공개 트랙은 질문이 한국어, 문서가 영어인 교차 언어 설정이다.
- M3 판정은 작은 test 표본에서의 질문 단위 paired bootstrap 구간이다. `hypothesis-rejected`는 "이 설정이 이 표본에서 기준을
  이긴다는 증거가 없다"는 뜻이고 효과가 없다는 증명이 아니다. 실험은 한 요소씩만 바꿨고 누적 조합은 판정하지 않았다
  (한계 전체: [docs/experiments/summary.md](docs/experiments/summary.md), 실험별 보고서의 한계 절).
- M4 수집은 한 시점의 스냅샷이다. 이후 올라온 글은 코퍼스에 들어오지 않고, 이미지뿐인 공지는 텍스트 본문이 없어 파싱 실패로
  남는다. 멱등성 검증의 벡터 허용오차는 같은 장비·같은 스레드 수·batch_size 1에서의 값이다. 이 단계에서는 검색 품질을
  평가하지 않았다(한계 전체: [docs/m4-collection.md](docs/m4-collection.md), [docs/m4-idempotency.md](docs/m4-idempotency.md)).

## 데이터와 라이선스

원본 데이터의 소스별 라이선스와 재배포 범위는 [LICENSES/](LICENSES/) 참조.
KISA 보안공지 본문은 재배포하지 않는다(수집 스크립트와 메타데이터 인덱스만 제공).
릴리스 asset에는 질문 ID·문서 ID·순위·점수와 manifest·정답 파일, 전체 코퍼스의 메타데이터(URL·제목·날짜·nttId·CVE ID)와
M4 보고서만 있고 본문은 없다.

## 실행

```bash
uv sync --locked --dev
uv run pytest
```

## KISA 소표본 (별도 로컬 실행)

공개 기본 테스트는 리포에 포함된 fixture와 자작 합성 데이터만 사용하며 네트워크나 KISA 캐시가 필요 없다.
KISA 트랙 평가(`scripts/run_baselines.py --track kisa`)는 아래 수집과 캐시 검사를 별도로 실행한
환경에서만 진행한다. 원문·요약·발췌는 출력하거나 평가 결과에 포함하지 않는다.

```bash
uv run python scripts/fetch_kisa.py --limit 50 --delay 1.5
uv run python scripts/fetch_kisa.py --check-cache
```

- `fixtures/kisa/metadata.jsonl`: URL·제목·날짜·nttId·CVE ID만 저장한다.
- `fixtures/kisa/manifest.json`: 대상 ID, UTC 수집 시각, 본문 SHA256, 파서 버전을 고정한다.
- `data/kisa/<nttId>/source.html`, `body.txt`: 원 응답과 추출 본문의 로컬 캐시다.
  `/data/*` gitignore 차단을 유지하며 커밋·릴리스·CI artifact로 업로드하지 않는다.

manifest가 없을 때만 공식 [RSS](https://www.boho.or.kr/kr/rss.do?bbsId=B0000133)와
[목록 페이지](https://www.boho.or.kr/kr/bbs/list.do?bbsId=B0000133&menuNo=205020)를
함께 사용해 50~100건을 선택한다. 고정 공지와 RSS의 중복은 `nttId`로 제거하고
날짜·ID 역순으로 표본을 고른다. 표본은 당시 두 경로에서 발견한 공지의 일부이며,
전체 KISA 공지의 대표성을 보장하지 않는다. 이후에는 고정 ID만 사용하므로 `--limit`은
기존 manifest에 영향을 주지 않는다. 정상 캐시는 재요청하지 않고, 새 clone에서는
동일 ID를 수집해 기존 해시와 대조한다. 중단된 최초 수집은 완료된 ID를 건너뛰어 재개한다.

파서 `kisa-html-v1`은 `b_title`의 제목·날짜와 `content_html`의 텍스트를 추출한다.
HTML 엔티티를 해제하고 script/style/noscript를 제외한 뒤 블록 요소의 줄 경계,
줄 내부 공백, 빈 줄을 정규화한다. **SHA256은 이 본문의 UTF-8 바이트**를 대상으로
하며 마지막 개행은 없다. 조회수 등 바깥 UI 변화는 해시에 영향을 주지 않는다.
이미지 OCR·첨부파일 다운로드는 수행하지 않으며 CVE는 추출 본문의 명시적 ID만 수집한다.

```bash
uv run python scripts/fetch_kisa.py --refresh
```

`--refresh`는 고정 ID를 재수집한다. 본문 해시나 허용 메타데이터가 바뀌면 종료 코드 1과
ID·해시만 보고하고, 기존 manifest·메타·정상 캐시는 보존한다. 관찰한 응답은 같은
무시 디렉터리의 `observed.html`·`observed.txt`에만 남긴다. 같은 본문이면 최초 수집 시각도
보존한다. 파서 버전이 다른 manifest나 손상된 캐시는 자동으로 승인하지 않는다.
`--check-cache`는 오프라인으로 원 응답의 재파싱 결과까지 대조하고, 캐시 부재 시
수집 명령을 안내하며 실패한다. 평가 코드(`run_baselines.py`의 KISA 트랙)는 `load_cached_body`를 이 경계로 사용한다.

모든 HTTP 요청은 명시적 UA와 기본 1.5초 간격을 사용한다(`--delay`는 1~2초).
robots.txt를 먼저 확인하고 더 긴 crawl-delay/request-rate가 있으면 이를 따른다.
접근 차단·리다이렉트·robots 금지는 즉시 중단하며 자동 우회하지 않는다.
그 외 요청·파싱 실패도 실행 중 누적 3건이면 중단한다.
실행 종료 시 `report`의 `success`(수집·검증 성공), `failed`(요청·캐시 오류),
`parse_failed`(파싱 오류), `new`(새 ID), `cached`, `restored`, `unchanged`,
`changed`, `metadata_changed`, `pending` 건수를 출력한다. 변경·실패 시 종료 코드는 1이다.

커밋할 변경을 stage한 뒤 본문 유출 표본 검사도 실행한다.

```bash
uv run python scripts/check_kisa_leaks.py
git status --short --ignored -- data/kisa
git ls-files -- data/kisa
```

검사기는 최소 3개 문서의 고유 본문 문자열을 메모리에서 선택해 `git grep -I -F`의
표준 입력으로 전달한다. tracked 작업 파일과 staged index, JSON 이스케이프 형태를
검색하며 원 문자열 대신 SHA256·일치 건수만 출력한다. 이는 표본 검사이므로 모든 변형의
유출 부재를 보장하는 것은 아니다. 커밋 diff의 허용 필드와 노트북 출력도 함께 검토한다.

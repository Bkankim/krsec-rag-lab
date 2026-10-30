# v1.0 릴리스 노트 (M5: 통합 + 생성 평가, 최종 재현 패키지)

Bkankim의 단독 프로젝트 [krsec-rag-lab](../README.md)의 네 번째이자 마지막 릴리스다. 검색 결과로 답을 만드는 생성 단계(로컬 Ollama 모델
하나, top-k 1·3·5)의 질문별 결과와 기계 지표, k=3 답의 faithfulness·정답성 교차 판정, LangChain/LangGraph 통합 어댑터를 v0.3의 asset
전부에 더해 묶었다. 마일스톤 M0~M5가 이 릴리스로 끝난다(M6 온프렘 서빙은 선택 과제이고 범위에서 제외했다). KISA 공지 본문과 KISA 트랙의
생성 답변 원문은 배포하지 않는다. README의 M5 표와 이 노트의 M5 표는 `results/m5/` 저장본에서 스크립트로 다시 만든 값이고, M3·M4
표도 v0.2·v0.3 때와 같은 함수로 다시 만든 값이다. 수치의 해석은 [m5-generation.md](m5-generation.md),
[m5-generation-eval.md](m5-generation-eval.md), [m5-integration.md](m5-integration.md)에 있다.

## 무엇이 들어 있나

| 구분 | 내용 | 정본 |
|---|---|---|
| 평가 규약 | eval-protocol v2 (v0.1~v0.3과 같다, 바꾸지 않았다) | [eval-protocol.md](eval-protocol.md) |
| v0.3의 asset 전부 | 베이스라인(v0.1), M3 실험 5개(v0.2), M4 전체 수집·멱등성 보고서와 전체 코퍼스 메타데이터(v0.3). M3·M4 재계산 검사도 그대로 돈다 | [release-v0.1.md](release-v0.1.md), [release-v0.2.md](release-v0.2.md), [release-v0.3.md](release-v0.3.md) |
| 생성 결과 | 트랙(공개, KISA) x k(1, 3, 5)마다 질문 하나 = 한 줄: 상태, 기권, 검증된 인용 문서 ID, 검색된 문서 ID, 입력·출력 토큰, 지연, 문맥 해시. 공개 트랙 행만 `answer`(NVD 문서에 기반한 모델 답)를 가진다. KISA 행에는 답변이 없다 | [m5-generation.md](m5-generation.md), `results/m5/generation/{public,kisa}_k{1,3,5}.jsonl` |
| 생성 manifest·지표 | 모델 digest·가중치 해시·Ollama 버전, 요청 옵션, 프롬프트 해시, 입력 파일 해시, 실행 ID / 트랙 x k x 분할 x 유형별 기계 지표 | `results/m5/generation/{manifest.json,topk.json}` |
| 판정 결과 | k=3 판정 행(질문 ID, 분할, 유형, 상태, 판정자별 고정 라벨·reason code, 확정 라벨)과 축별 집계(분모, 일치, kappa) | [m5-generation-eval.md](m5-generation-eval.md), `results/m5/judgments/{public,kisa}.jsonl`, `summary.json`, `manifest.json` |
| 통합 | 코어 함수를 부르는 `BaseRetriever` 어댑터와 검색-생성-인용 검사 상태 그래프, 코어 경로와의 동등성 | [m5-integration.md](m5-integration.md), `src/krsec_rag_lab/integrations/` |
| 구현 | 생성 파이프라인(검색, 문맥, 프롬프트, 출력 계약 파싱, 재질의), 판정 도구, CLI | `src/krsec_rag_lab/generation/`, `scripts/run_generation.py`, `scripts/judge_generation.py`, `scripts/run_langgraph.py` |
| 검사 | M5 저장본 검사와 표 재생성 대조, v1.0 asset 목록 검사 | `scripts/make_readme_tables.py`, `scripts/check_release.py` |

## M0~M5 요약

마일스톤마다 무엇을 했고 어디에 결과가 있는지만 적는다. 수치는 아래 M3·M4·M5 구간과 각 보고서에서 읽는다.

| 마일스톤 | 한 일 | 릴리스 | 정본 |
|---|---|---|---|
| M0 | 임베딩부터 검색까지 데이터 레이어를 직접 구현하고 문서 1건·질의 1건을 전 단계 추적, NumPy 전수·Qdrant exact·HNSW 대조 | - | [qdrant-comparison.md](qdrant-comparison.md), `notebooks/00_embeddings_from_scratch.ipynb` |
| M1 | 미니 코퍼스(NVD fixture, 고정 KISA 공지), 평가 규약, CVE 자동 라벨 오류율 측정, 두 모델 교차 판정 골든셋 v1 | - | [eval-protocol.md](eval-protocol.md), [metrics-crosscheck.md](metrics-crosscheck.md), `eval/` |
| M2 | 베이스라인 3종(exact CVE lookup, BM25, dense bge-m3)을 두 트랙에서 측정 | v0.1 | [baselines.md](baselines.md), [release-v0.1.md](release-v0.1.md) |
| M3 | 실험 5개(하이브리드, 리랭커, 청킹, 한영 교차, 임베딩 교체), 가설 판정과 실패 사례 | v0.2 | [experiments/summary.md](experiments/summary.md), [release-v0.2.md](release-v0.2.md) |
| M4 | KISA 게시판 전체 수집(누락·중복·파싱 실패 계측), 증분 동기화와 멱등성 검증 | v0.3 | [m4-collection.md](m4-collection.md), [m4-idempotency.md](m4-idempotency.md), [release-v0.3.md](release-v0.3.md) |
| M5 | 로컬 LLM 생성과 top-k 실험, 생성 답 교차 판정, LangChain/LangGraph 통합 | v1.0 | [m5-generation.md](m5-generation.md), [m5-generation-eval.md](m5-generation-eval.md), [m5-integration.md](m5-integration.md) |

## M3 판정

v0.2의 판정 표다(M3 실험은 이 릴리스에서 다시 돌리지 않았다). 보조 판정과 `cve_explicit` 회귀 여부는
[experiments/summary.md](experiments/summary.md)에 있다.

<!-- BEGIN M3 RESULTS (scripts/make_readme_tables.py) -->

이 구간은 `scripts/make_readme_tables.py`가 `results/experiments/`의 질문별 원시 결과와 질의셋 라벨에서 하네스의 비교 함수(`krsec_rag_lab.experiments.compare`)로 다시 계산해 쓴다. 손으로 고치지 않는다. 검증: `uv run python scripts/make_readme_tables.py --check`. 지표는 test macro nDCG@10(condensed list, 정답이 있는 유형의 단순 평균)이고 delta = 실험 - 기준이다. 95% 구간은 test 질문을 유형별로 층화 복원추출한 paired bootstrap(10000회, 시드 20261029)의 2.5/97.5 백분위이며, delta > 0 이고 구간 하한 > 0 일 때만 `hypothesis-confirmed`다.

주 판정 5건: hypothesis-confirmed 0, hypothesis-rejected 5.

| 실험 | 주 트랙 (변형) | 기준 | test n | 기준 macro nDCG@10 | 실험 macro nDCG@10 | delta | 95% 구간 | 판정 |
|---|---|---|---|---|---|---|---|---|
| [hybrid](experiments/hybrid.md) | public (rrf) | bm25 | 74 | 0.8551 | 0.8775 | +0.0223 | [-0.0117, +0.0616] | `hypothesis-rejected` |
| [rerank](experiments/rerank.md) | public (rerank) | bm25 | 74 | 0.8551 | 0.8581 | +0.0030 | [-0.0206, +0.0244] | `hypothesis-rejected` |
| [chunking](experiments/chunking.md) | kisa (chunk_max) | dense | 23 | 0.8131 | 0.8785 | +0.0654 | [-0.0082, +0.1510] | `hypothesis-rejected` |
| [crossling](experiments/crossling.md) | public (bm25_ko2en) | bm25 | 74 | 0.8551 | 0.2771 | -0.5780 | [-0.6723, -0.4832] | `hypothesis-rejected` |
| [embedding](experiments/embedding.md) | public (swap) | dense | 74 | 0.4353 | 0.4393 | +0.0040 | [-0.0637, +0.0726] | `hypothesis-rejected` |

<!-- END M3 RESULTS (scripts/make_readme_tables.py) -->

## M4 결과

v0.3의 수집·멱등성 표다(수집과 검증은 이 릴리스에서 다시 돌리지 않았다).

<!-- BEGIN M4 RESULTS (scripts/make_readme_tables.py) -->

이 구간은 `scripts/make_readme_tables.py`가 `results/m4/collection/report.json`, `results/m4/idempotency/report.json`, `fixtures/kisa_full/manifest.json`, `fixtures/kisa_full/metadata.jsonl`에서 다시 만들어 쓴다. 손으로 고치지 않는다. 검증: `uv run python scripts/make_readme_tables.py --check`. 보고서와 manifest의 건수가 서로 맞는지 대조한 뒤에 표를 만든다.

### 전체 수집: 규모, 누락, 중복, 파싱 실패 ([m4-collection.md](m4-collection.md))

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

### 멱등성 검증 1~5단계 ([m4-idempotency.md](m4-idempotency.md))

검증 통과 (갱신·삭제·추가 각 5건, 시드 59, 실패 단계 없음, 소요 2598.7초).

| 항목 | 값 |
|---|---|
| 스냅샷 | 대상 ID 2592, `ok` 2590, `ok` 아님 2, 기준 스냅샷 2585 |
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

<!-- END M4 RESULTS (scripts/make_readme_tables.py) -->

## M5 결과

생성은 `qwen3:8b` 하나, 프롬프트 하나, 시드 하나이고 검색은 M2의 BM25다. 기계 지표는 트랙 x k마다, LLM 판정은 k=3만이다.

<!-- BEGIN M5 RESULTS (scripts/make_readme_tables.py) -->

이 구간은 `scripts/make_readme_tables.py`가 `results/m5/generation/`과 `results/m5/judgments/`의 저장본(질문별 행, `topk.json`, `summary.json`)을 다시 검사하고 질의셋 라벨과 판정 행에서 지표를 다시 계산해 만든다. 손으로 고치지 않는다. 검증: `uv run python scripts/make_readme_tables.py --check`. 세 축(faithfulness, 정답성, 답 없음 처리)은 따로 보고하고 하나의 점수로 합치지 않는다. 분할 `all`은 dev와 test의 합이다. 판정은 두 모델의 교차 판정이고 사람 검수가 아니며, KISA 생성 답변 원문은 어디에도 없다.

### 실행 구성 ([m5-generation.md](m5-generation.md), [m5-generation-eval.md](m5-generation-eval.md))

| 항목 | 값 |
|---|---|
| 생성 모델 | `qwen3:8b` (8.2B, Q4_K_M, Apache-2.0), Ollama 0.32.15 |
| 모델 digest | `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41` |
| 요청 옵션 | temperature 0, seed 42, num_ctx 16384, num_predict 512, think false, format json |
| 프롬프트 sha256 / 실행 ID | `48c60b10def29cd43a76f3c74f3fef51cada5af483d61b0df28029c4fae4bbc7` / `8a7c1c6b2f8bf06b` |
| 검색 | BM25 (M2 선택 값, public k1 1.2, b 0.75; kisa k1 3.0, b 0.9), 문서당 3000자 상한 |
| 생성 질문 수 | public 144, kisa 52 (k 1, 3, 5) |
| 판정자 | A `claude-opus-5-5` (Anthropic, 2.1.312 (Claude Code)), B `gpt-6.1-sol` (OpenAI, codex-cli 0.163.0) |
| 판정 범위 | k=3, public test, kisa dev+test |
| 판정 대상 / 두 판정자 모두 유효 | public 63 / 63, kisa 39 / 39 |
| 판정자 호출 | 204회 (재질의 0회), 한도 대기 0회, 상태 `complete` |

### top-k 기계 지표: 공개 트랙 (NVD), 144문항 dev+test ([m5-generation.md](m5-generation.md))

| k | 계약 파싱 성공률 | 재질의 수 | 문맥 초과 | 올바른 기권률 | 잘못된 기권률 | 인용 적중률 | 무효 인용률 | 입력 토큰 중앙값 | 입력 토큰 최대 | 지연 중앙값(초) |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1.000 | 0 | 0 | 1.000 | 0.142 | 0.942 | 0.000 | 288 | 465 | 0.95 |
| 3 | 1.000 | 0 | 0 | 1.000 | 0.125 | 0.952 | 0.000 | 295 | 834 | 1.70 |
| 5 | 1.000 | 0 | 0 | 1.000 | 0.125 | 0.962 | 0.000 | 295 | 1012 | 1.78 |

### top-k 기계 지표: KISA 트랙, 52문항 dev+test ([m5-generation.md](m5-generation.md))

| k | 계약 파싱 성공률 | 재질의 수 | 문맥 초과 | 올바른 기권률 | 잘못된 기권률 | 인용 적중률 | 무효 인용률 | 입력 토큰 중앙값 | 입력 토큰 최대 | 지연 중앙값(초) |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1.000 | 0 | 0 | 1.000 | 0.476 | 0.909 | 0.000 | 835 | 2287 | 1.36 |
| 3 | 1.000 | 0 | 0 | 1.000 | 0.071 | 0.974 | 0.000 | 3282 | 4909 | 4.45 |
| 5 | 1.000 | 0 | 0 | 1.000 | 0.048 | 0.950 | 0.000 | 4824 | 7271 | 7.46 |

### faithfulness: 두 판정자 교차 판정, k=3 ([m5-generation-eval.md](m5-generation-eval.md))

| 트랙 (분할) | 유형 | 분모 | 확정 supported 비율 | 일치율 | 불일치율 | invalid | kappa |
|---|---|---|---|---|---|---|---|
| public (test) | cve_explicit | 35 | 0.600 | 0.943 | 0.057 | 0 | 0.878 |
| public (test) | product_symptom | 28 | 0.964 | 0.964 | 0.036 | 0 | 0.000 |
| public (test) | all | 63 | 0.762 | 0.952 | 0.048 | 0 | 0.859 |
| kisa (all) | cve_explicit | 18 | 0.944 | 1.000 | 0.000 | 0 | 1.000 |
| kisa (all) | product_symptom | 12 | 0.917 | 0.917 | 0.083 | 0 | 0.000 |
| kisa (all) | explanation_comparison | 9 | 0.667 | 1.000 | 0.000 | 0 | 1.000 |
| kisa (all) | all | 39 | 0.872 | 0.974 | 0.026 | 0 | 0.875 |

### 정답성: 두 판정자 교차 판정, k=3 ([m5-generation-eval.md](m5-generation-eval.md))

| 트랙 (분할) | 유형 | 분모 | 확정 correct 비율 | 일치율 | 불일치율 | invalid | kappa |
|---|---|---|---|---|---|---|---|
| public (test) | cve_explicit | 35 | 0.629 | 0.857 | 0.143 | 0 | 0.668 |
| public (test) | product_symptom | 28 | 0.500 | 0.929 | 0.071 | 0 | 0.857 |
| public (test) | all | 63 | 0.571 | 0.889 | 0.111 | 0 | 0.766 |
| kisa (all) | cve_explicit | 18 | 0.833 | 0.889 | 0.111 | 0 | 0.455 |
| kisa (all) | product_symptom | 12 | 0.833 | 0.917 | 0.083 | 0 | 0.625 |
| kisa (all) | explanation_comparison | 9 | 0.778 | 0.889 | 0.111 | 0 | 0.609 |
| kisa (all) | all | 39 | 0.821 | 0.897 | 0.103 | 0 | 0.552 |

### 답 없음 처리와 판정 제외: k=3, 기계 판정 ([m5-generation-eval.md](m5-generation-eval.md))

| 트랙 (분할) | 유형 | 행 수 | 판정 | 기권 제외 | 파싱 실패 제외 | 문맥 초과 제외 | 올바른 기권률 | 잘못된 기권률 | 인용 적중률 |
|---|---|---|---|---|---|---|---|---|---|
| public (test) | cve_explicit | 35 | 35 | 0 | 0 | 0 | - | 0.000 | 1.000 |
| public (test) | product_symptom | 39 | 28 | 11 | 0 | 0 | - | 0.282 | 0.929 |
| public (test) | no_answer | 12 | 0 | 12 | 0 | 0 | 1.000 | - | - |
| public (test) | all | 86 | 63 | 23 | 0 | 0 | 1.000 | 0.149 | 0.968 |
| kisa (all) | cve_explicit | 20 | 18 | 2 | 0 | 0 | - | 0.100 | 1.000 |
| kisa (all) | product_symptom | 12 | 12 | 0 | 0 | 0 | - | 0.000 | 0.917 |
| kisa (all) | explanation_comparison | 10 | 9 | 1 | 0 | 0 | - | 0.100 | 1.000 |
| kisa (all) | no_answer | 10 | 0 | 10 | 0 | 0 | 1.000 | - | - |
| kisa (all) | all | 52 | 39 | 13 | 0 | 0 | 1.000 | 0.071 | 0.974 |

### 판정자 불일치 (확정되지 않은 질문-축 수)

| 트랙 | 축 | 불일치 (`disagree`) | 무효 (`invalid`) |
|---|---|---|---|
| public | faithfulness | 3 | 0 |
| public | correctness | 7 | 0 |
| kisa | faithfulness | 1 | 0 |
| kisa | correctness | 4 | 0 |

<!-- END M5 RESULTS (scripts/make_readme_tables.py) -->

## 재현

`<KISA-ROOT>`는 KISA 로컬 캐시(`data/kisa/`, `data/kisa_full/`, `data/m5/`)를 둘 체크아웃 경로다. 본문은 재배포하지 않으므로 캐시는 각자
수집해 만든다. 여섯 갈래로 나뉜다. 모델·네트워크 없이 되는 것, KISA 사이트에 접근해야 하는 것(M4), Docker와 임베딩 모델이 필요한 것(M4),
로컬 Ollama가 필요한 것(생성), 외부 모델 API 2종이 필요한 것(판정), `langchain` 그룹이 필요한 것(통합).

### 새 클론에서 모델·네트워크·KISA 캐시 없이 되는 것

`uv sync --locked --dev`만 하면 된다. 커밋된 결과와 manifest, 생성·판정 저장본, 문서의 생성 구간을 서로 대조한다.

```bash
git clone https://github.com/Bkankim/krsec-rag-lab.git && cd krsec-rag-lab
uv sync --locked --dev
# 베이스라인 표 + M3 판정 표 + M4 표 + M5 표(저장본 검사, README와 이 노트의 구간)를 다시 만들어 대조(불일치 exit 1)
uv run python scripts/make_readme_tables.py --check
uv run python scripts/check_release.py --note docs/release-v1.0.md     # 아래 asset 목록 검사 (v0.3의 검사를 모두 포함)
uv run python scripts/check_release.py --note docs/release-v0.3.md     # v0.3 asset 검사도 그대로 통과한다
uv run python scripts/check_release.py --note docs/release-v0.2.md     # v0.2 asset 검사
uv run python scripts/check_release.py                                 # v0.1 asset 검사
for exp in hybrid rerank chunking crossling embedding; do
  uv run python scripts/run_experiment.py --exp "$exp" --compare       # M3 저장본 재계산 대조
done
uv run python scripts/run_generation.py --metrics-only                 # M5 생성 저장본 검사 + topk.json 재계산 대조
uv run python scripts/judge_generation.py --summary-only               # M5 판정 저장본 검사 + summary.json 재계산 대조
```

M5의 대조는 `results/m5/`의 12개 파일과 질의셋 라벨을 읽고, 생성 manifest가 적은 입력 파일(공개: 질의셋과 NVD 코퍼스, KISA: 질의셋과 고정 공지의 manifest·메타데이터)의 sha256이 같은지도 본다. 질의셋은 반드시 있어야 하고 나머지는 파일이 있을 때만 비교한다(asset 사본에는 NVD 코퍼스가 없다). 트랙 2개 x k(1, 3, 5)의 고정 구성, 행 키 집합(공개 생성 행만 `answer`를 가진다), 질문 집합(예상 집합과 정확히
같고 중복 없음), 파일 해시, 계약 파싱 성공률 80% 하한, 판정 행과 생성 행의 대응을 본 뒤 `topk.json`과 `summary.json`을 저장된 행에서 다시
계산해 커밋된 파일과 대조하고(abs 1e-9), 그 값으로 README와 이 노트의 M5 구간을 만든다. 이 대조는 생성이나 판정을 다시 돌려 같은 값이 나오는지를
보는 것이 아니다.

### KISA 사이트 접근이 필요한 것: 전체 수집 (M4)

v0.3과 같다. 게시판 `bbsId=B0000133`에 요청을 보내고, 요청은 전부 `scripts/fetch_kisa.py`의 `Client`로만 보낸다(robots.txt 먼저, 간격 1.5초,
리다이렉트 거부, 403·429·401·robots 거부는 즉시 중단). 첫 수집은 한 시간 반 안팎이 걸린다. 옵션과 재실행 확인은
[m4-collection.md](m4-collection.md)에 있다.

```bash
uv run python scripts/collect_kisa_full.py --cache-root <KISA-ROOT>
```

### Docker와 모델이 필요한 것: 동기화와 멱등성 검증 (M4)

Qdrant 컨테이너(비기본 호스트 포트)와 `embed`·`qdrant` 그룹, bge-m3 가중치(revision 고정), 위 수집으로 만든 캐시가 필요하다.
[m4-idempotency.md](m4-idempotency.md)의 재현 명령과 같다.

```bash
docker run -d --name krsec-qdrant-m4 --label krsec-run=1 -p 127.0.0.1:16340:6333 qdrant/qdrant:v1.19.2
uv sync --locked --group qdrant --group embed
export KRSEC_QDRANT_URL=http://127.0.0.1:16340 OMP_NUM_THREADS=8
uv run --no-sync python scripts/sync_index.py --verify-idempotency --cache-root <KISA-ROOT>   # 1~5단계 검증
docker rm -f krsec-qdrant-m4
uv sync --locked --dev
```

### 로컬 Ollama가 필요한 것: 생성 (M5)

로컬 Ollama와 모델 `qwen3:8b`(digest는 아래 "데이터와 모델" 표와 `results/m5/generation/manifest.json`의 `model`)가 필요하다. 생성은 외부 모델
API를 쓰지 않는다. KISA 트랙은 `<KISA-ROOT>`의 고정 50건 캐시(`data/kisa/`)를 `load_cached_body`로 읽고, 답변 원문은
`<KISA-ROOT>/data/m5/generation/`(gitignore)에만 쓴다. 실행 시간은 `results/m5/generation/manifest.json`의 `wall_seconds_this_invocation`에 있다.

```bash
ollama serve                                   # 별도 프로세스. 이미 떠 있으면 그것을 쓰고, 띄웠다면 그 프로세스만 끈다
ollama pull qwen3:8b
uv run python scripts/run_generation.py --track public --k 1 3 5
uv run python scripts/run_generation.py --track kisa --kisa-root <KISA-ROOT> --k 1 3 5
uv run python scripts/run_generation.py --track public --k 3 --limit 5 --out-dir <빈 디렉터리>   # 소표본(커밋본을 건드리지 않는다)
```

온도 0, 시드 42여도 다른 하드웨어·Ollama 버전에서 같은 답이 나온다고 보장하지 않는다(한계). 계약 파싱 성공률이 (트랙, k)마다 80% 미만이면
그 결과를 쓰지 않고 exit 1이다.

### 외부 모델 API 2종이 필요한 것: 판정 (M5)

판정자 A(`claude -p`, Anthropic)와 B(`codex exec`, OpenAI)의 CLI 로그인이 필요하다. 판정 요청에는 KISA 문맥·생성 답변·근거 구간 본문이 실려
외부 API로 전송된다([LICENSES/README.md](../LICENSES/README.md)). 요청에 쓴 본문·답변은 리포·릴리스·CI artifact·로그·호출 캐시에 남기지 않고,
남는 것은 질문 ID, 판정자별 고정 라벨·reason code, 집계뿐이다. 사용량 한도가 나오면 상태를 저장하고 기다렸다가 같은 캐시로 재개한다.

```bash
uv run python scripts/judge_generation.py --track public --limit 3 --out-dir <빈 디렉터리>   # 소표본: 형식 확인(커밋본을 건드리지 않는다)
uv run python scripts/judge_generation.py --kisa-root <KISA-ROOT>                          # 전체 판정 + 산출물, 한도 대기 뒤 재개 포함
```

### langchain 그룹이 필요한 것: 통합 (M5)

`langchain` 그룹(`langchain-core`, `langgraph`)은 CI와 `uv sync --locked --dev`에 들어가지 않는다. 그룹이 없으면 통합 테스트 파일은 통째로 skip되고
코어 테스트는 그대로 돈다. 공개 트랙만 그래프로 돌린다(KISA 트랙은 돌리지도 남기지도 않는다).

```bash
uv sync --locked --group langchain
uv run --no-sync pytest -q tests/test_integrations.py                              # skip 없이 통과해야 한다
ollama serve                                                                       # 이미 떠 있으면 그것을 쓴다
uv run --no-sync python scripts/run_langgraph.py --compare --n 10                  # 커밋된 public_k3.jsonl과 대조
uv sync --locked --dev                                                             # 끝나면 dev 그룹으로 되돌린다
```

## 데이터와 모델

| 항목 | 값 |
|---|---|
| 평가 규약 | `eval-protocol-v2` ([eval-protocol.md](eval-protocol.md)) |
| 코퍼스 | 공개 트랙은 NVD fixture, KISA 트랙은 고정 KISA 공지. M4의 전체 코퍼스 스냅샷은 평가 트랙과 따로 두고 바꾸지 않았다. 생성·판정은 두 트랙의 기존 질의셋을 그대로 쓴다 |
| 생성 모델 | `qwen3:8b` (Qwen3-8B, Q4_K_M, Apache-2.0), Ollama digest `500a1f067a9f782620b40bee6f7b0c89e17ae61f686b92c24933e4ca4b2b8b41`, 서버 0.32.15 |
| 요청 옵션 | `temperature 0`, `seed 42`, `num_ctx 16384`, `num_predict 512`, `think false`, `format json` |
| 프롬프트 | 하나로 고정하고 튜닝하지 않는다. sha256 `48c60b10def29cd43a76f3c74f3fef51cada5af483d61b0df28029c4fae4bbc7`, 원문은 [m5-generation.md](m5-generation.md) |
| 검색 | M2의 BM25(`bm25-tok-v1`, 트랙별 k1·b는 `results/baselines/manifest.json`의 선택 값), 문서당 3000자 상한 |
| 출력 계약 | JSON 객체 하나 `{"answer", "abstain", "citations"}`. 파싱 실패면 재질의 1회. 계약 파싱 성공률 하한 80% |
| 판정자 | A `claude-opus-5-5`(Anthropic, `claude -p`, effort medium), B `gpt-6.1-sol`(OpenAI, `codex exec`, effort medium). 같은 지시문과 같은 입력, 서로의 결과를 보지 않는다. CLI 버전과 플래그 전체는 `results/m5/judgments/manifest.json`의 `judges` |
| 판정 규칙 | 두 판정자가 모두 유효하고 같으면 그 라벨, 둘 다 유효한데 다르면 `disagree`, 하나라도 무효면 `invalid`. 두 판정자 유효율 90% 하한, 판정 대상 트랙당 20건 하한 |
| 통합 의존성 | `pyproject.toml`의 `langchain` 그룹(`langchain-core>=1.7,<2`, `langgraph>=1.2,<2`), `uv.lock`에 고정 |
| 실행 환경 | M5 표의 "실행 구성" 줄과 `results/m5/generation/manifest.json`의 `environment` |
| 그 밖 | 임베딩 모델, Qdrant, M3 실험 모델, 교차 판정(골든셋)은 [release-v0.1.md](release-v0.1.md), [release-v0.2.md](release-v0.2.md), [release-v0.3.md](release-v0.3.md)의 같은 절과 같다 |

## asset

GitHub 릴리스 `v1.0`에 첨부하는 파일이다. v0.3의 asset 전부와 고정 목록 M5 파일 12개
(`results/m5/generation/{manifest.json,topk.json,public_k1.jsonl,public_k3.jsonl,public_k5.jsonl,kisa_k1.jsonl,kisa_k3.jsonl,kisa_k5.jsonl}`,
`results/m5/judgments/{manifest.json,summary.json,public.jsonl,kisa.jsonl}`)다. 이 열두 개가 목록에 하나라도 없으면 검사가 실패한다(파일과 노트
행을 함께 지워도 같다). asset 이름은 리포 경로의 `/`를 `__`로 바꾼 이름이고, 각 asset은 대응하는 리포 파일의 사본이다(sha256 동일).
모든 파일은 허용 필드만 갖는다. M5 JSON(manifest, topk, summary)은 500자를 넘는 문자열과 `/`로 시작하는 문자열(키 포함)이 없다.
생성 행의 키 집합은 KISA는 정해진 17개 키뿐이고(`answer` 없음), 공개 트랙은 거기에 `answer` 하나를 더한다(길이 예외는 이 필드만). 판정 행의
키 집합은 정해진 14개이고 값은 고정 라벨·reason code·null뿐이다. 알 수 없는 키는 거부한다. KISA 공지 본문과 KISA 생성 답변은 없다.

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
| `fixtures__kisa_full__manifest.json` | `fixtures/kisa_full/manifest.json` | 533466 | `17362c4a515b56ba070b33595c82f7dcdc8d46e38ac8686f0eaf6f076da9c3c5` |
| `fixtures__kisa_full__metadata.jsonl` | `fixtures/kisa_full/metadata.jsonl` | 937882 | `f08b63276d39b5ca56885b28270d86813d9ffe059d2eb56b5bf1c34d243db722` |
| `fixtures__nvd__manifest.json` | `fixtures/nvd/manifest.json` | 266490 | `893bdee1c8454f4b78cc5257493e48038717a22c71dd3249a138fa3616d9cae6` |
| `results__baselines__kisa__bm25.jsonl` | `results/baselines/kisa/bm25.jsonl` | 161032 | `aa56a3aae836af708bb4f04df2d77adf181fab7a2636d5758aeb53ff405041f2` |
| `results__baselines__kisa__dense.jsonl` | `results/baselines/kisa/dense.jsonl` | 166222 | `9aacf60f0f9c4ba66d54f5855f9259c67d717caf1a0b0bca9e9cc5f14621c0a8` |
| `results__baselines__kisa__exact.jsonl` | `results/baselines/kisa/exact.jsonl` | 5988 | `992c1661fa6f9773deb5f312755018a1883b6b6462b5bfd62fafc828ded2c6b0` |
| `results__baselines__manifest.json` | `results/baselines/manifest.json` | 24764 | `5d539b6a98c2d379c9584e37ccbe474a699bdd08c19e4c06eca84074ab0e63e7` |
| `results__baselines__metrics.json` | `results/baselines/metrics.json` | 33318 | `c129a906ff1055f3dd3dafaeede2d7de12391ba95dad719a7a6460806e5385f0` |
| `results__baselines__public__bm25.jsonl` | `results/baselines/public/bm25.jsonl` | 298585 | `41556ebaeaa628bc78a27527447dc4f8dd86a82a4dd350f4c0092f74dfdf69e9` |
| `results__baselines__public__dense.jsonl` | `results/baselines/public/dense.jsonl` | 1035323 | `b159891e290360bdafc7efa556da8d6867d5880b0a1cbba267d0e37363259173` |
| `results__baselines__public__exact.jsonl` | `results/baselines/public/exact.jsonl` | 17051 | `699f0d51d7036e284107a33495a41c3857028308f653ebadaa921ac5f3ad2477` |
| `results__experiments__chunking__comparison.json` | `results/experiments/chunking/comparison.json` | 6488 | `f68f64c5b90e729eecce6f7c43d49c165e2a8ae739d4205914d2df09092bd0f1` |
| `results__experiments__chunking__kisa__chunk_max.jsonl` | `results/experiments/chunking/kisa/chunk_max.jsonl` | 166222 | `458b58ac05b0577d85bc00a826c4fe9af4204b5834d002c6a87157c14b417ee7` |
| `results__experiments__chunking__manifest.json` | `results/experiments/chunking/manifest.json` | 14914 | `64bd2632fc38fc3f97e000acc42804d440e6a482202ea02da88932723d3e8d20` |
| `results__experiments__chunking__metrics.json` | `results/experiments/chunking/metrics.json` | 6329 | `3979c50d4f7ddb506ba5cf179bff8aa23ae136dc4df1fe8b1a3d91e38fd65513` |
| `results__experiments__crossling__comparison.json` | `results/experiments/crossling/comparison.json` | 31450 | `284773f3d956456a4313476e068e4598a7f2d748e16a283b518e56e84b3eda47` |
| `results__experiments__crossling__manifest.json` | `results/experiments/crossling/manifest.json` | 15702 | `79f1da1353770d4bc0f0811b8c26e7f3f268e062817b2b9ba2173a90c048660e` |
| `results__experiments__crossling__metrics.json` | `results/experiments/crossling/metrics.json` | 10551 | `df51f9b6c1748b21481daee252304a62b09e8a9cef69c9ba7eb48358eb08a09e` |
| `results__experiments__crossling__public__bm25_ko2en.jsonl` | `results/experiments/crossling/public/bm25_ko2en.jsonl` | 1024380 | `b0e09d1b73cefd029e8f78f5f3b5d5a6f4ed51e47e068a85257fe18ba797a173` |
| `results__experiments__crossling__public__dense_ko2en.jsonl` | `results/experiments/crossling/public/dense_ko2en.jsonl` | 1037150 | `a8e4dfb2f9ce437210fdac37eb962002ffa9375a8d9c52ecc9049de8c24260d5` |
| `results__experiments__crossling__translations.jsonl` | `results/experiments/crossling/translations.jsonl` | 42960 | `46a0156b2875813d026c34e59a0e1faf7938f5622f86230e2b6a0bc1a94a0907` |
| `results__experiments__embedding__comparison.json` | `results/experiments/embedding/comparison.json` | 17324 | `2602a1eb8186bf55a77480245e46e6d2b34941be58d4e4b82e23eb0a3a65ebbe` |
| `results__experiments__embedding__kisa__swap.jsonl` | `results/experiments/embedding/kisa/swap.jsonl` | 165949 | `929bb7433643f076788ce24b04252151a8153beecedbc6d30ac4547afe4239bc` |
| `results__experiments__embedding__manifest.json` | `results/experiments/embedding/manifest.json` | 14574 | `4809f4b46de9fd2cdbfe4d5557ce1251354e9134dc25a630e087df2517ec063e` |
| `results__experiments__embedding__metrics.json` | `results/experiments/embedding/metrics.json` | 11391 | `e754e187e7e84fa20add576cf42636804786ce0cf485777dcc1efd0ce912622f` |
| `results__experiments__embedding__public__swap.jsonl` | `results/experiments/embedding/public/swap.jsonl` | 1034962 | `3d83140928054a792c2990f7dbd9b56b4aece7e2c61e95fdb4e008d3022b2f52` |
| `results__experiments__hybrid__comparison.json` | `results/experiments/hybrid/comparison.json` | 13080 | `c2b17027640dc161fffe00ea0606e6db794c0ba3ea8612964bb367fc26aec3d0` |
| `results__experiments__hybrid__kisa__rrf.jsonl` | `results/experiments/hybrid/kisa/rrf.jsonl` | 168271 | `1dfd4b344ddf1a4d95a7d3d93657fcfd541dd1470c7d836b76ef14fb09ee4641` |
| `results__experiments__hybrid__manifest.json` | `results/experiments/hybrid/manifest.json` | 10653 | `882ebcd05ac9d86f8fe0a085e43b6c66af58182867ca46204ab2268a1131eb3e` |
| `results__experiments__hybrid__metrics.json` | `results/experiments/hybrid/metrics.json` | 11374 | `e809b657c52ccd0c9c666f29193e00ff64f0c80f79e5f48702d42f1609e7631c` |
| `results__experiments__hybrid__public__rrf.jsonl` | `results/experiments/hybrid/public/rrf.jsonl` | 1045704 | `659911050cd6c05911ef4962e8586de152aaf255dcb4d8686d4e229b49249f4e` |
| `results__experiments__rerank__comparison.json` | `results/experiments/rerank/comparison.json` | 11741 | `46fdb29557725983b478f5cca4633154f839b74d85a0c9abcba1bc15a8c5fdbd` |
| `results__experiments__rerank__kisa__rerank.jsonl` | `results/experiments/rerank/kisa/rerank.jsonl` | 161888 | `58232c4ef91f9f8fc64d2fac88d65b9e4309665da40868523962a7fe02d2a368` |
| `results__experiments__rerank__manifest.json` | `results/experiments/rerank/manifest.json` | 11040 | `a3d23b47bd06d2d571ef5b9363e187441b7dd34996168439920a5386b4258a72` |
| `results__experiments__rerank__metrics.json` | `results/experiments/rerank/metrics.json` | 11309 | `57032ab408a5e80d93f6ba5b9ba9450f2779d9be82123cdc924c8679e1406f1c` |
| `results__experiments__rerank__public__rerank.jsonl` | `results/experiments/rerank/public/rerank.jsonl` | 300662 | `4cc1f66632dc12a4ab5c552992b24d9e1ea34a9c3f3864f196e8fe338cfa4739` |
| `results__m4__collection__report.json` | `results/m4/collection/report.json` | 1344 | `08fe27adcb994555b55931510af0448d7909c400a1e359bdcc892ff23dfd030d` |
| `results__m4__idempotency__report.json` | `results/m4/idempotency/report.json` | 6433 | `f8b33bbd4d62ce70cd09256beb74ff52d0d87d247a2e5e4659b60ea249f4bd61` |
| `results__m5__generation__kisa_k1.jsonl` | `results/m5/generation/kisa_k1.jsonl` | 22192 | `de1946338426a844d347606709e2cd579cc7ca5e7bf568498e4c75258098dae2` |
| `results__m5__generation__kisa_k3.jsonl` | `results/m5/generation/kisa_k3.jsonl` | 23616 | `0ea59aca3f46841e6098e99ec0bb98aeda2fa7961c2086437758e878b876e941` |
| `results__m5__generation__kisa_k5.jsonl` | `results/m5/generation/kisa_k5.jsonl` | 24777 | `474466f59a55c1c58ca2bb8d1762c2f442224a01a0bacd153504a5274530ee33` |
| `results__m5__generation__manifest.json` | `results/m5/generation/manifest.json` | 6956 | `a899bad42ddc27260e2385131b341336494153ab7629a699567d035fb665485e` |
| `results__m5__generation__public_k1.jsonl` | `results/m5/generation/public_k1.jsonl` | 82151 | `5658c324122d58a42041d9dcf7047d66e1eefa528e6d8f2dca889fe48e1a1c30` |
| `results__m5__generation__public_k3.jsonl` | `results/m5/generation/public_k3.jsonl` | 85857 | `5c1bf0ec3bb66b996c6ac51ef0b298a424c36361efca00e35e2f30155b8b440e` |
| `results__m5__generation__public_k5.jsonl` | `results/m5/generation/public_k5.jsonl` | 89836 | `f8772343745934fb80c3bf183fc9c4facc4809ceb49d0ee350e763a938d4f086` |
| `results__m5__generation__topk.json` | `results/m5/generation/topk.json` | 85701 | `36f69b15eeb63a6aa1ffb5b08a7038691248643840c7c25e94df53650dd335eb` |
| `results__m5__judgments__kisa.jsonl` | `results/m5/judgments/kisa.jsonl` | 23184 | `138cd5c2939cb956a72710c91862d9ed97428f11e89aee6a77ea9fde7abde52e` |
| `results__m5__judgments__manifest.json` | `results/m5/judgments/manifest.json` | 4673 | `3c31aaa4f66e0a65e8d03f018a4b40295552f093bc122e3960c63c6c05390d41` |
| `results__m5__judgments__public.jsonl` | `results/m5/judgments/public.jsonl` | 39093 | `5617d15ed7c43bec24b0cf4ee5ed8666ef263772ebf07cd794ea2422be5d2ae2` |
| `results__m5__judgments__summary.json` | `results/m5/judgments/summary.json` | 34440 | `4dcb1d64d4ff817d38977a36a20595232b7930dbc2916d0da8a0c2bcc4eee62a` |

<!-- END ASSETS -->

내려받은 asset은 `shasum -a 256 <파일>`로 위 표와 대조한다. 리포 쪽 검사는 `uv run python scripts/check_release.py --note docs/release-v1.0.md`다:

1. 목록의 항목이 허용 asset이고 파일이 있다. v1.0 허용 asset은 v0.3 목록에 M5 파일 12개를 더한 것이다.
2. v0.3의 필수 파일(베이스라인·실험 manifest가 요구하는 결과·질의셋·재현 입력, 실험 JSON 3종, M4 파일 넷)과 M5 파일 12개가 모두 목록에 있다.
   M3·M4·M5 asset 하나만 빠져도 실패한다.
3. asset 사본의 sha256이 목록, 대응하는 리포 원본 파일, manifest의 입력 해시와 같다.
4. 허용 필드만 있다(v0.3의 규칙에 더해 M5 JSON의 긴 문자열·`/` 시작 문자열 거부, 생성·판정 행의 키 집합 일치와 값 형식).
5. asset 사본만으로 리포 레이아웃을 복원해 README의 베이스라인 표를 다시 계산하면 README와 같다.
6. 같은 사본으로 실험 5개의 `metrics.json`·`comparison.json`을 다시 계산하면(abs 1e-9) 저장된 파일과 같고, README의 M3 판정 구간,
   `docs/experiments/summary.md`의 표 구간, 이 노트의 M3 구간이 그 값으로 만든 표와 같다.
7. 같은 사본의 M4 보고서, manifest, 메타데이터가 서로 맞고, README와 이 노트의 M4 구간이 그 값으로 만든 표와 같다.
8. 같은 사본의 M5 생성·판정 저장본이 저장본 검사를 통과하고(행 키·집합, 해시, `topk.json`·`summary.json` 재계산 대조), README와 이 노트의 M5
   구간이 그 값으로 만든 표와 같다.

NVD 코퍼스 파일(`fixtures/nvd/cves.jsonl`)은 asset이 아니다(v0.2 노트의 같은 절과 같다).

### 발행 뒤 검증 (내려받은 asset)

릴리스를 발행한 뒤 asset을 빈 디렉터리에 내려받아(`gh release download v1.0 --dir "$DL"`) 같은 검사를 그 파일들에 대해 돌린다.
리포 파일 사본이 아니라 실제로 올라간 파일이 대상이고, 목록에 없는 파일이 섞여 있으면 실패한다:

```bash
DL=$(mktemp -d)
gh release download v1.0 --repo Bkankim/krsec-rag-lab --dir "$DL"
uv run python scripts/check_release.py --note docs/release-v1.0.md --assets-dir "$DL"
```

## 본문 유출 점검 (LICENSES/README.md 체크리스트 적용)

[LICENSES/README.md](../LICENSES/README.md)의 "본문 유출 방지 점검 대상"을 이 릴리스에 적용한 결과다.

| 점검 대상 | 이 릴리스에서의 적용 | 결과 |
|---|---|---|
| 노트북 입력/출력 셀 | 노트북은 asset에 없고 이 릴리스에서 바뀌지 않았다 | 해당 없음 |
| 검색 결과 원시 JSON | v0.2·v0.3과 같다. 결과 파일 전부 `scoring.validate_record`로 허용 필드만 허용한다 | `check_release.py` 통과 |
| 전체 코퍼스 메타데이터 | v0.3과 같다. URL·제목·날짜·nttId·CVE ID 다섯 키만 허용하고 각 문자열은 500자 이하다 | `check_release.py` 통과 |
| manifest·보고서 JSON | M3·M4·M5 모두 건수, ID, sha256, reason code, 시각, 실행 환경 값만 있다. 500자를 넘는 문자열과 `/`로 시작하는 문자열(키 포함)이 없다 | `check_release.py` 통과 |
| 생성 답변 로그·생성 행 | KISA 생성 행에는 `answer`가 없고 키 집합이 정해진 17개와 정확히 같다. 공개 트랙 `answer`는 NVD 공개 문서에 기반한 답이다. KISA 답변 원문은 `<KISA-ROOT>/data/m5/`(gitignore)에만 있다 | `check_release.py` 통과 |
| 판정자 요청·응답 로그 | 판정 행은 고정 키 14개, 고정 라벨·reason code·null뿐이다. 판정 호출 캐시(`data/m5/judgments/`)는 gitignore이고 라벨·코드·요청 해시만 담는다. 골든셋 판정 로그(`eval/golden/judgments/*.jsonl`)는 asset이 아니다 | `check_release.py` 통과 |
| 통합 어댑터 | KISA 트랙을 그래프로 돌리지 않고, 외부 추적(LangSmith 등)을 끈 채 돈다 | [m5-integration.md](m5-integration.md) |
| 색인 payload | Qdrant point의 payload에 본문·제목 텍스트를 넣지 않는다. 컬렉션 자체는 asset이 아니다 | 해당 없음 |
| 릴리스 첨부 파일 | asset 전부 허용 필드 검사 | `check_release.py` 통과 |
| README·블로그의 예시 인용 | README·노트의 표는 건수·ID·모델 정보·비율뿐이고 공지 본문 인용이 없다 | 해당 없음 |
| `scripts/check_kisa_leaks.py` (total_matches=0) | 본문 표본 검색은 KISA 캐시가 있는 체크아웃에서 돌려야 한다. 이 노트를 쓴 작업에서는 실행하지 않았고 머지 전 점검 결과는 PR에 기록한다 | 이 문서에는 결과를 적지 않음 |

길이와 경로 검사는 본문 유출 검증의 일부 경로만 막는다. 본문 유출의 확인은 위 `check_kisa_leaks.py` 결과로 한다.

## 한계

이 릴리스의 수치는 아래 한계 안에서만 읽는다. v0.1~v0.3의 한계(정답은 사람 검수가 아니라 교차 판정, 표본 크기, M3 판정은 작은 표본의 한 번
측정, M4 수집은 한 시점의 스냅샷)는 그대로 적용되고 [release-v0.1.md](release-v0.1.md), [release-v0.2.md](release-v0.2.md),
[release-v0.3.md](release-v0.3.md)의 한계 절에 있다.

**생성.**

- 모델 하나(`qwen3:8b`), 프롬프트 하나, 시드 하나의 결과라 분산을 모른다. 프롬프트는 소표본을 포함해 고치지 않았고 다른 모델과 비교하지 않았다.
- 공개 트랙 `no_answer`의 올바른 기권은 BM25가 한 건도 찾지 못해 빈 문맥 문구를 받은 쉬운 경우가 섞여 있다. 문서가 있어도 답이 없음을 알아보는
  능력의 증거가 아니다([m5-generation.md](m5-generation.md) 해석 절).
- 인용 적중은 정답 문서를 인용했다는 뜻이지 답이 맞다는 뜻이 아니다. 문서당 3000자 상한 때문에 긴 KISA 공지의 뒷부분은 모델이 보지 못한다.
- 입력 토큰은 Ollama 응답의 `prompt_eval_count`이고 지연은 이 장비·이 Ollama 버전의 값이다. 문맥 초과는 보내기 전에 셀 수 없어 응답으로 판정한다.
- 온도 0, 시드 42에서 재실행 결과가 같았지만(문항 일부로 확인) 다른 하드웨어·Ollama 버전에서의 재현은 보장하지 않는다.

**판정.**

- 두 모델이 같은 방향으로 틀릴 수 있다. 일치한 라벨은 "두 모델이 같게 판정했다"는 뜻이지 맞다는 보증이 아니고 사람 검수가 아니다.
- 판정자는 둘, 지시문 하나, effort medium 하나다. 판정은 k=3만이고 공개 트랙은 test 분할만 판정했다. k=1·5는 기계 지표로만 비교한다.
- 표본이 작다. KISA 판정 대상은 유형별로 한 자릿수에서 십여 건이라 kappa가 불안정하다(한 라벨만 쓰이면 null이다). 일치율을 kappa와 함께 읽는다.
- 정답성은 정답 자료(공개 `description_en`, KISA 근거 구간 발췌) 안에서의 일치다. 판정 호출은 요청마다 비결정적일 수 있어 다시 돌리면 일부 라벨이
  달라질 수 있다. 저장본은 호출 캐시와 판정 행으로 고정되어 있다.

**통합.**

- 그래프는 코어 파이프라인의 얇은 포장이라 더 좋은 답을 만들지 않는다. 실제 모델 동등성 비교는 질문 일부(전부 `cve_explicit`)로만 했고, 나머지 경로는
  가짜 LLM 테스트로만 본다. `BM25CoreRetriever`는 BM25 하나만 감싼다.
- CLI와 그래프는 공개 트랙만 돌린다. 외부 추적은 끈다.

**재현 범위.**

- 저장본의 대조(`make_readme_tables.py --check`, `check_release.py`, `run_generation.py --metrics-only`, `judge_generation.py --summary-only`)는
  모델·Ollama·Docker·외부 API·네트워크·KISA 캐시 없이 통과한다. 생성과 판정은 각 작업에서 한 번 측정한 값이고 이 릴리스 준비 작업에서는 다시
  돌리지 않았다.
- KISA 트랙의 생성·판정 재실행과 본문 유출 점검(`check_kisa_leaks.py`)은 KISA 캐시가 있는 환경에서 돌려야 한다.
- 모델 가중치는 Hugging Face와 Ollama 라이브러리의 공개 가중치이고 digest·revision을 고정했지만, 가중치 자체의 재배포는 하지 않는다.

## 라이선스

코드·문서·자작 평가 데이터는 MIT다. NVD·CISA KEV 서브셋은 `fixtures/nvd/NOTICE.md`의 고지를 따르며(NVD 공식 데이터로
표기하지 않는다), KISA 보안공지 본문은 재배포 조건이 확인되지 않아 포함하지 않는다. 생성 모델 `qwen3:8b`는 Apache-2.0이다. 소스별 범위는
[LICENSES/README.md](../LICENSES/README.md).

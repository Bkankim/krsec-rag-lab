# M5 생성 평가 교차 판정

k=3 생성 결과(`docs/m5-generation.md`)의 답을 faithfulness(문맥이 뒷받침하는가)와 정답성(정답 자료와 맞는가)으로 두 모델이 따로
판정한 결과다. 답 없음 처리는 #65의 기계 지표를 그대로 옮긴다. 세 축을 따로 보고하고 하나의 점수로 합치지 않는다. 이
프로젝트는 Bkankim의 단독 프로젝트다.

- 코드: `src/krsec_rag_lab/generation/judge_gen.py`, CLI `scripts/judge_generation.py`, 테스트 `tests/test_judge_generation.py`
- 결과: `results/m5/judgments/{manifest.json, public.jsonl, kisa.jsonl, summary.json}`
- 판정자 호출 캐시(`data/m5/judgments/cache`, gitignore)에는 라벨·reason code·요청 해시만 있다. KISA 문맥·근거 구간·생성 답변 원문은
  디스크(결과, 캐시, 로그)에 남기지 않는다(`LICENSES/README.md`).

## 판정 규칙

| 항목 | 규칙 |
|---|---|
| 판정 범위 | k=3 생성 행만. 공개 트랙은 `test` 분할 전부, KISA 트랙은 채점 질문 전부(dev+test, `excluded` 제외 52건) |
| 판정자 | A `claude-opus-5-5`(`claude -p`, 도구·MCP·사용자 설정·세션 저장 없음, `--effort medium`), B `gpt-6.1-sol`(`codex exec -s read-only`, 도구 비활성, effort medium). 플래그 전체와 CLI 버전은 `manifest.json`의 `judges` |
| 입력 | 두 판정자에게 같은 지시문(`manifest.json`의 `instruction_sha256`)과 같은 JSON 입력: 질문, k=3 문맥(생성 때 모델이 본 그대로), 답, 정답 자료. 서로의 결과는 보지 않는다 |
| 정답 자료 | 공개: gold 레코드의 `description_en`. KISA: gold 문서마다 판정자 A·B 근거 구간(`answers[].evidence` 오프셋)의 합집합을 캐시 본문에서 잘라 메모리에서만 쓴다. gold 문서가 여럿이면 문서 ID 순서로 잇는다. `no_answer` 질문은 정답 자료가 없다(`reference: null`) |
| 판정하지 않는 행 | `abstain=true` -> `skipped_abstain`, 파싱 실패 -> `skipped_parse_failed`, 문맥 초과 -> `skipped_context_overflow`. 분모에서 빼고 수를 따로 적는다(답 없음 처리 축은 기계 판정) |
| `no_answer` 비기권 답 | faithfulness만 판정한다. 정답성은 `not_applicable`(분모에서 뺀다). 지어낸 답을 잡기 위한 규칙이다 |
| 호출 한도 | 질문당 판정자별 1회 + 라벨·코드가 고정 목록 밖이면(형식 오류) 재질의 1회. 재질의 뒤에도 틀린 축은 그 판정자의 라벨이 null(`status`는 `judged` 유지) |
| 사용량 한도 | 한도 오류를 감지하면 상태(`limit_events.json`)를 저장하고 메시지의 재시도 시각(없으면 40분)까지 기다렸다 같은 캐시로 재개한다. 판정자마다 따로 기다린다 |
| 확정 | 두 판정자가 모두 유효하고 같으면 그 라벨, 둘 다 유효한데 다르면 `disagree`, 하나라도 null이면 `invalid` |
| 분모 | faithfulness = `judged` 행 전부, 정답성 = `judged` 중 정답 자료가 있는 질문. 일치율·불일치율·kappa 분모 = 그 축에서 두 판정자가 모두 유효한 행 |
| kappa | Cohen's kappa. 이진화: supported/correct vs 나머지. 한 라벨만 쓰였거나 유효 쌍이 없으면 null과 사유 |
| 완료 조건 | 트랙별 두 판정자 모두 유효한 질문이 판정 대상의 90% 이상이고 판정 대상이 20건 이상(아니면 exit 1) |

### 라벨과 reason code

판정자는 축마다 라벨 하나와 고정 reason code 하나만 낸다(자유 서술·인용은 요청하지 않고, 응답에 있어도 파싱하지 않고 버린다).

| 축 | 라벨 | reason code |
|---|---|---|
| faithfulness | `supported` | `all_claims_in_context` |
| | `partially_supported` | `some_claims_not_in_context`, `extra_detail_beyond_context` |
| | `unsupported` | `claims_not_in_context`, `contradicts_context`, `no_substantive_answer` |
| 정답성 | `correct` | `matches_reference` |
| | `partially_correct` | `covers_part_of_reference`, `includes_wrong_detail` |
| | `incorrect` | `contradicts_reference`, `misses_reference`, `answers_other_question` |
| | `not_applicable` | `no_reference`(정답 자료가 없는 질문, 판정자 호출 결과가 아니라 고정값) |

### 판정 행 (고정 키 집합)

`results/m5/judgments/<track>.jsonl`의 한 줄 = 질문 하나. 키는 이것뿐이고 값은 고정 라벨·코드·null이다
(`validate_row`, `--summary-only`, #68 릴리스 검사).

`question_id`, `split`, `query_type`, `status`(`judged` | `skipped_abstain` | `skipped_parse_failed` |
`skipped_context_overflow`), `faithfulness_A`, `faithfulness_B`, `faithfulness`, `correctness_A`, `correctness_B`,
`correctness`, `faithfulness_reason_A`, `faithfulness_reason_B`, `correctness_reason_A`, `correctness_reason_B`.

## 입력 정합

- 문맥: #65 행의 `retrieved`와 `pipeline.build_context`로 k=3 문맥을 다시 만들고 행의 `context_sha256`·`truncated`·`context_chars`와
  하나라도 다르면 실패한다(검색을 다시 하지 않는다).
- KISA 답변 원문: `<KISA-ROOT>/data/m5/generation/kisa_k3.jsonl`의 `run_id`가 커밋된 `results/m5/generation/manifest.json`과 같고,
  답변을 뺀 나머지 값이 커밋된 `kisa_k3.jsonl` 행과 같고, 질문 집합이 같아야 한다(다르면 exit 1).
- 근거 구간: 오프셋이 기대는 파서 버전(`kisa-html-v1`)이 `fixtures/kisa/manifest.json`과 같고 본문 길이 안에 들어와야 한다.
- 저장본 검사(`--summary-only`)는 판정 행이 커밋된 k=3 생성 행과 질문 집합·분할·유형·상태가 대응하는지, `manifest.json`의 해시가
  파일과 같은지도 본다.

## 재현

```sh
# 판정자 A는 claude CLI가 로그인된 상태여야 한다
uv run python scripts/judge_generation.py --track public --limit 3 --out-dir <빈 디렉터리>   # 소표본: 형식 확인(커밋본을 건드리지 않는다)
uv run python scripts/judge_generation.py --kisa-root <KISA-ROOT>                          # 전체 판정 + 산출물. 한도 대기 뒤 재개 포함
uv run python scripts/judge_generation.py --summary-only                                    # 모델·API·KISA 캐시 없이 저장본 검사 + summary.json 재계산 대조(다르면 exit 1)
uv run python scripts/judge_generation.py --render-docs                                     # summary.json·판정 행 -> 이 문서의 표
```

종료 코드: 0 완료 / 1 미완료(유효율 90% 미만, 판정 대상 20건 미만, 입력 불일치, `--summary-only` 대조 실패) / 2 판정자 호출 실패
(다시 실행하면 캐시에서 재개) / 3 한도 대기 횟수 초과(다시 실행하면 재개). 같은 요청은 캐시에서 읽으므로 다시 실행해도 호출하지 않는다.

## 실행 기록

| 항목 | 값 |
|---|---|
| 생성 실행 | `results/m5/generation/manifest.json`의 `run_id` `8a7c1c6b2f8bf06b`(모델 `qwen3:8b`), k=3 |
| 판정 대상 | 공개 63건(test 86행 중), KISA 39건(52행 중) |
| 총 호출 수 | 204회(A 102 + B 102, 재질의 0회). 소표본 공개 3문항 x 2(6회)는 캐시에서 전체 실행에 그대로 쓰였다 |
| 유효율 | 공개·KISA 모두 두 판정자 유효 100%(A·B 각각도 100%) |
| 한도 대기 | 0회, 0초. 이번 실행에서는 codex 사용량 한도가 발생하지 않았다. 한도 감지·저장·재개 경로는 가짜 판정자 테스트로 검증했다 |
| 소요 | 호출은 모두 약 4분(UTC 00:08 ~ 00:12) 안에 끝났다. 정확한 첫·마지막 호출 시각은 `manifest.json`의 `calls` |

## 결과

숫자는 `results/m5/judgments/summary.json`과 판정 행에서만 온다(`--render-docs`). 정답성 분모는 `no_answer`를 뺀 판정 대상이다.

<!-- BEGIN GENERATED TABLES (scripts/judge_generation.py --render-docs) -->

### 판정 대상과 판정자 유효율

| 트랙 | 판정 대상 | 두 판정자 모두 유효 | 유효율 | A 유효율 | B 유효율 |
|---|---|---|---|---|---|
| 공개 트랙 (NVD, test) | 63 | 63 | 1.000 | 1.000 | 1.000 |
| KISA 트랙 | 39 | 39 | 1.000 | 1.000 | 1.000 |

### faithfulness (확정 supported 비율 / 일치 / kappa)

| 트랙 | 분할 | 유형 | 분모 | 확정 supported 비율 | 두 판정자 유효 | 일치율 | 불일치율 | invalid | kappa |
|---|---|---|---|---|---|---|---|---|---|
| public | test | cve_explicit | 35 | 0.600 | 35 | 0.943 | 0.057 | 0 | 0.878 |
| public | test | product_symptom | 28 | 0.964 | 28 | 0.964 | 0.036 | 0 | 0.000 |
| public | test | all | 63 | 0.762 | 63 | 0.952 | 0.048 | 0 | 0.859 |
| kisa | dev | cve_explicit | 8 | 1.000 | 8 | 1.000 | 0.000 | 0 | null (both judges used a single label, kappa is undefined) |
| kisa | dev | product_symptom | 5 | 0.800 | 5 | 0.800 | 0.200 | 0 | 0.000 |
| kisa | dev | explanation_comparison | 4 | 0.500 | 4 | 1.000 | 0.000 | 0 | 1.000 |
| kisa | dev | all | 17 | 0.824 | 17 | 0.941 | 0.059 | 0 | 0.767 |
| kisa | test | cve_explicit | 10 | 0.900 | 10 | 1.000 | 0.000 | 0 | 1.000 |
| kisa | test | product_symptom | 7 | 1.000 | 7 | 1.000 | 0.000 | 0 | null (both judges used a single label, kappa is undefined) |
| kisa | test | explanation_comparison | 5 | 0.800 | 5 | 1.000 | 0.000 | 0 | 1.000 |
| kisa | test | all | 22 | 0.909 | 22 | 1.000 | 0.000 | 0 | 1.000 |
| kisa | all | cve_explicit | 18 | 0.944 | 18 | 1.000 | 0.000 | 0 | 1.000 |
| kisa | all | product_symptom | 12 | 0.917 | 12 | 0.917 | 0.083 | 0 | 0.000 |
| kisa | all | explanation_comparison | 9 | 0.667 | 9 | 1.000 | 0.000 | 0 | 1.000 |
| kisa | all | all | 39 | 0.872 | 39 | 0.974 | 0.026 | 0 | 0.875 |

### 정답성 (확정 correct 비율 / 일치 / kappa)

| 트랙 | 분할 | 유형 | 분모 | 확정 correct 비율 | 두 판정자 유효 | 일치율 | 불일치율 | invalid | kappa |
|---|---|---|---|---|---|---|---|---|---|
| public | test | cve_explicit | 35 | 0.629 | 35 | 0.857 | 0.143 | 0 | 0.668 |
| public | test | product_symptom | 28 | 0.500 | 28 | 0.929 | 0.071 | 0 | 0.857 |
| public | test | all | 63 | 0.571 | 63 | 0.889 | 0.111 | 0 | 0.766 |
| kisa | dev | cve_explicit | 8 | 0.875 | 8 | 0.875 | 0.125 | 0 | 0.000 |
| kisa | dev | product_symptom | 5 | 0.800 | 5 | 1.000 | 0.000 | 0 | 1.000 |
| kisa | dev | explanation_comparison | 4 | 0.500 | 4 | 0.750 | 0.250 | 0 | 0.500 |
| kisa | dev | all | 17 | 0.765 | 17 | 0.882 | 0.118 | 0 | 0.605 |
| kisa | test | cve_explicit | 10 | 0.800 | 10 | 0.900 | 0.100 | 0 | 0.615 |
| kisa | test | product_symptom | 7 | 0.857 | 7 | 0.857 | 0.143 | 0 | 0.000 |
| kisa | test | explanation_comparison | 5 | 1.000 | 5 | 1.000 | 0.000 | 0 | null (both judges used a single label, kappa is undefined) |
| kisa | test | all | 22 | 0.864 | 22 | 0.909 | 0.091 | 0 | 0.463 |
| kisa | all | cve_explicit | 18 | 0.833 | 18 | 0.889 | 0.111 | 0 | 0.455 |
| kisa | all | product_symptom | 12 | 0.833 | 12 | 0.917 | 0.083 | 0 | 0.625 |
| kisa | all | explanation_comparison | 9 | 0.778 | 9 | 0.889 | 0.111 | 0 | 0.609 |
| kisa | all | all | 39 | 0.821 | 39 | 0.897 | 0.103 | 0 | 0.552 |

### 답 없음 처리와 판정 제외 (기계 판정, #65 topk.json k=3)

| 트랙 | 분할 | 유형 | 행 수 | 판정 | 기권 제외 | 파싱 실패 제외 | 문맥 초과 제외 | 올바른 기권률 | 잘못된 기권률 | 인용 적중률 |
|---|---|---|---|---|---|---|---|---|---|---|
| public | test | cve_explicit | 35 | 35 | 0 | 0 | 0 | - | 0.000 | 1.000 |
| public | test | product_symptom | 39 | 28 | 11 | 0 | 0 | - | 0.282 | 0.929 |
| public | test | no_answer | 12 | 0 | 12 | 0 | 0 | 1.000 | - | - |
| public | test | all | 86 | 63 | 23 | 0 | 0 | 1.000 | 0.149 | 0.968 |
| kisa | dev | cve_explicit | 9 | 8 | 1 | 0 | 0 | - | 0.111 | 1.000 |
| kisa | dev | product_symptom | 5 | 5 | 0 | 0 | 0 | - | 0.000 | 0.800 |
| kisa | dev | explanation_comparison | 5 | 4 | 1 | 0 | 0 | - | 0.200 | 1.000 |
| kisa | dev | no_answer | 4 | 0 | 4 | 0 | 0 | 1.000 | - | - |
| kisa | dev | all | 23 | 17 | 6 | 0 | 0 | 1.000 | 0.105 | 0.941 |
| kisa | test | cve_explicit | 11 | 10 | 1 | 0 | 0 | - | 0.091 | 1.000 |
| kisa | test | product_symptom | 7 | 7 | 0 | 0 | 0 | - | 0.000 | 1.000 |
| kisa | test | explanation_comparison | 5 | 5 | 0 | 0 | 0 | - | 0.000 | 1.000 |
| kisa | test | no_answer | 6 | 0 | 6 | 0 | 0 | 1.000 | - | - |
| kisa | test | all | 29 | 22 | 7 | 0 | 0 | 1.000 | 0.043 | 1.000 |
| kisa | all | cve_explicit | 20 | 18 | 2 | 0 | 0 | - | 0.100 | 1.000 |
| kisa | all | product_symptom | 12 | 12 | 0 | 0 | 0 | - | 0.000 | 0.917 |
| kisa | all | explanation_comparison | 10 | 9 | 1 | 0 | 0 | - | 0.100 | 1.000 |
| kisa | all | no_answer | 10 | 0 | 10 | 0 | 0 | 1.000 | - | - |
| kisa | all | all | 52 | 39 | 13 | 0 | 0 | 1.000 | 0.071 | 0.974 |

### 불일치·무효 (질문 ID와 reason code만)

| 트랙 | 질문 ID | 유형 | 축 | 확정 | A 라벨 / 코드 | B 라벨 / 코드 |
|---|---|---|---|---|---|---|
| public | pub-cve-0001 | cve_explicit | correctness | disagree | correct / matches_reference | partially_correct / includes_wrong_detail |
| public | pub-cve-0004 | cve_explicit | correctness | disagree | correct / matches_reference | partially_correct / includes_wrong_detail |
| public | pub-cve-0010 | cve_explicit | faithfulness | disagree | supported / all_claims_in_context | partially_supported / extra_detail_beyond_context |
| public | pub-cve-0010 | cve_explicit | correctness | disagree | correct / matches_reference | partially_correct / includes_wrong_detail |
| public | pub-cve-0022 | cve_explicit | correctness | disagree | correct / matches_reference | partially_correct / includes_wrong_detail |
| public | pub-cve-0028 | cve_explicit | correctness | disagree | correct / matches_reference | partially_correct / includes_wrong_detail |
| public | pub-cve-0041 | cve_explicit | faithfulness | disagree | partially_supported / extra_detail_beyond_context | supported / all_claims_in_context |
| public | pub-prod-0017 | product_symptom | correctness | disagree | correct / matches_reference | partially_correct / includes_wrong_detail |
| public | pub-prod-0022 | product_symptom | faithfulness | disagree | supported / all_claims_in_context | partially_supported / some_claims_not_in_context |
| public | pub-prod-0022 | product_symptom | correctness | disagree | correct / matches_reference | partially_correct / includes_wrong_detail |
| kisa | g1-cve-2026-20349 | cve_explicit | correctness | disagree | partially_correct / covers_part_of_reference | correct / matches_reference |
| kisa | g1-cve-2026-76461 | cve_explicit | correctness | disagree | partially_correct / covers_part_of_reference | correct / matches_reference |
| kisa | g1-ps-03 | product_symptom | faithfulness | disagree | unsupported / claims_not_in_context | supported / all_claims_in_context |
| kisa | g1-ps-11 | product_symptom | correctness | disagree | partially_correct / covers_part_of_reference | correct / matches_reference |
| kisa | g1-ec-07 | explanation_comparison | correctness | disagree | partially_correct / covers_part_of_reference | correct / matches_reference |

<!-- END GENERATED TABLES -->

## 해석

- **faithfulness**: 확정 supported는 공개 test 0.762(48/63), KISA 0.872(34/39)다. 확정된 비-supported는 거의 `partially_supported`다
  (공개 12건 중 10건이 두 판정자 모두 `extra_detail_beyond_context`, 문맥에 없는 세부를 덧붙임). `unsupported`는 KISA test
  `cve_explicit` 1건(두 판정자 모두 `contradicts_context`)뿐이다. 공개 `cve_explicit`의 supported 비율(0.600)이 `product_symptom`(0.964)보다
  낮은 것은 `cve_explicit` 답에 문맥에 없는 세부를 덧붙인 경우가 많았다는 뜻이다(reason code 기준). 어떤 세부인지는 본문 인용을 남기지 않아
  이 문서에서 분해하지 않는다.
- **정답성**: 확정 correct는 공개 test 0.571(36/63), KISA 0.821(32/39)다. 공개는 두 판정자가 일치한 `partially_correct` 18건(판정자별 코드는 `covers_part_of_reference` 둘 다 8, `includes_wrong_detail` 둘 다 6, 코드만 갈린 4)과 `incorrect` 2건(`misses_reference`)이 있다. KISA는 확정 `incorrect` 3건
  (`contradicts_reference` 1, `misses_reference` 2)이고 `partially_correct`로 확정된 것이 없다(아래 불일치 4건이 전부 부분 정답 여부의 이견이다).
- **답 없음 처리**: 올바른 기권률은 두 트랙 모두 1.000이고 잘못된 기권률은 공개 test 0.149, KISA 0.071이다. 판정에서 제외된 행은
  공개 23건(기권 23), KISA 13건(기권 13)이고 파싱 실패·문맥 초과는 0건이다. `no_answer` 질문은 전부 기권해서 이번 데이터에는
  "비기권 답의 faithfulness만 판정" 경로에 걸리는 행이 없다(그 규칙은 합성 데이터 테스트로만 검증했다). 공개 `no_answer`는 BM25가
  0건을 돌려주는 쉬운 경우가 섞여 있다(`docs/m5-generation.md`).
- **세 축은 서로 다른 것을 잰다**: 기계 지표의 인용 적중(공개 0.968, KISA 0.974)은 정답 문서를 인용했는지만 보고, faithfulness는
  문맥 근거, 정답성은 정답 자료와의 일치를 본다. 인용이 맞아도 답이 `partially_supported`·`partially_correct`일 수 있다.

## 불일치 분석

불일치는 공개 10건(faithfulness 3 + 정답성 7 질문-축), KISA 5건(faithfulness 1 + 정답성 4)이고 무효(`invalid`)는 없다. 질문 ID와 라벨·코드는
위 표(불일치·무효)에 있다.

- 방향이 트랙마다 다르다. 공개 정답성 7건은 전부 A가 `correct`, B가 `partially_correct`(`includes_wrong_detail`)다. 반대로 KISA
  정답성 4건은 전부 A가 `partially_correct`(`covers_part_of_reference`), B가 `correct`다. 공개 faithfulness 3건은 2건이 B가 더 엄격하고 1건이 A가 더 엄격하며, KISA faithfulness 1건은 A가 더 엄격하다. 정답 자료의 형태
  (공개: 영문 설명 한 단락, KISA: 근거 구간 발췌)와 판정자의 해석이 만나 갈렸을 가능성이 있으나, 이 실행만으로 원인을 가릴 수는 없다.
- 불일치 15건 중 14건은 경계(`correct` 대 `partially_correct`, `supported` 대 `partially_supported`)에서 났다. `incorrect`나 `unsupported`가
  걸린 불일치는 KISA `g1-ps-03`의 faithfulness 1건(A `unsupported`, B `supported`)뿐이다.
- kappa는 표본이 작고 라벨이 한쪽에 몰려 불안정하다. 한쪽 판정자가 모두 positive이고 다른 쪽이 1건만 달라도 0.000이 나오고(예:
  KISA `product_symptom` faithfulness), 한 라벨만 쓰이면 null이다. 일치율을 kappa와 함께 읽는다.

## 한계

- 두 모델이 같은 방향으로 틀릴 수 있다. 일치한 라벨은 "두 모델이 같게 판정했다"는 뜻이지 맞다는 보증이 아니다. 사람 검수가 아니다.
- 판정자는 둘뿐이고 지시문은 하나, 프롬프트 튜닝을 하지 않았다. 판정자 effort는 medium 하나다.
- 표본이 작다. KISA는 판정 대상 39건(유형별 9~18건), `no_answer`는 판정 대상이 0건이라 유형 칸에서 비어 있다. 공개는 test 분할만 판정했다.
- 정답성은 정답 자료 안에서의 일치다. 공개는 `description_en`, KISA는 근거 구간 발췌라서 답이 자료 밖의 맞는 내용을 더 담으면
  `partially_correct`·`includes_wrong_detail`로 갈릴 수 있다. KISA 문맥은 문서당 3000자에서 잘려 있어(`truncated`) 근거 구간이 문맥 밖에
  있는 질문은 faithfulness와 정답성이 서로 다른 자료를 보고 판정한다.
- 생성은 모델 하나·시드 하나의 결과(`docs/m5-generation.md`)이고 판정 호출은 요청마다 비결정적일 수 있어 다시 돌리면 일부 라벨이 달라질 수
  있다. 저장본은 호출 캐시와 판정 행으로 고정되어 있다.
- k=1·5는 LLM 판정 범위 밖이다. 그 비교는 기계 지표·입력 토큰·지연으로 한다(`docs/m5-generation.md`).

## 범위 밖

k=1·5의 LLM 판정, 사람 검수, 판정자 추가, 생성 재실행, 프롬프트 튜닝.

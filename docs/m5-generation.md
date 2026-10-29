# M5 생성 파이프라인과 top-k 실험

검색 결과로 답을 만드는 단계를 프레임워크 없는 함수와 CLI로 만들고, 트랙 x k(1, 3, 5)마다 기계 지표와 입력 토큰 수를
기록한 결과다. 생성은 로컬 Ollama 모델 하나로만 하고(외부 모델 API 없음), 검색은 M2의 BM25(#11)를 그대로 쓴다.
LLM 판정(faithfulness·정답성)은 이 문서의 범위 밖이다(`docs/m5-generation-eval.md`). 이 프로젝트는 Bkankim의 단독
프로젝트다.

- 코드: `src/krsec_rag_lab/generation/{pipeline,llm}.py`, CLI `scripts/run_generation.py`, 테스트 `tests/test_generation.py`
- 결과: `results/m5/generation/{manifest.json, public_k{1,3,5}.jsonl, kisa_k{1,3,5}.jsonl, topk.json}`
- KISA 트랙의 답변 원문은 커밋하지 않는다. 로컬 캐시 `<KISA-ROOT>/data/m5/generation/kisa_k<k>.jsonl`(gitignore)에만 있다
  (`LICENSES/README.md` KISA 행: 생성 답변은 공지 본문을 옮길 수 있다).

## 모델 선택 근거

| 항목 | 값 |
|---|---|
| 모델 | `qwen3:8b` (Qwen3-8B, Q4_K_M 양자화, Ollama) |
| 라이선스 | Apache-2.0 (`ollama show`의 라이선스 문구 첫머리로 확인, 문구 sha256은 manifest에 고정) - 재배포 제약이 약하다 |
| 크기·메모리 | 가중치 약 5.2 GB. 이 맥(24 GB 통합 메모리)에서 `num_ctx` 16384로 올렸을 때 `ollama ps` 크기가 약 7.7 GB다 |
| 컨텍스트 한도 | 모델 한도 40960 토큰(`/api/show`의 `qwen3.context_length`). 실행은 16384로 고정한다 |
| 한국어 | 공개 모델 카드가 한국어를 포함한 다국어 지원을 밝힌다(이 리포가 따로 검증한 것은 아니다). 질문은 한국어, 문서는 영어(NVD)·한국어(KISA)다 |
| 선택 이유 | 라이선스·메모리 조건을 만족하는 후보 중 한국어 지원이 공개 모델 카드에 명시된 가장 큰 크기. 모델 여러 개를 비교하지 않는다(범위 밖) |
| 대체 후보 | 트랙 x k 중 하나라도 계약 파싱 성공률이 80% 미만이면 후보 모델 한 개로만 다시 시도하고 그래도 미달이면 중단·보고한다(이번 실행은 해당 없음) |

Qwen3는 기본이 사고(thinking) 모드라서 요청에 `think: false`를 준다. 사고 토큰은 JSON 출력 계약과 지연을 해친다.
정확한 digest·가중치 sha256·Ollama 서버 버전은 `results/m5/generation/manifest.json`의 `model`에 있다.

## 파이프라인과 공개 함수

`retrieve` -> `build_context` -> `build_prompt` -> LLM -> `parse_answer`를 `generate`가 묶고(재질의 1회 포함),
`run_question`이 질문 한 건의 결과 행까지 만든다. run 함수 하나에 몰아넣지 않으므로 #66·#67이 각 함수를 그대로 부른다.

| 함수 | 하는 일 |
|---|---|
| `build_index(track, root, load_body)` | #11과 같은 BM25 색인. 트랙별 k1·b는 `results/baselines/manifest.json`의 선택 값, 토큰화는 `bm25-tok-v1`. KISA는 `load_body(nttId, 문서 항목)`(= `fetch_kisa.load_cached_body`를 감싼 것)가 필요하다 |
| `retrieve(index, question, k)` | 질문 문자열의 BM25 점수를 `(-점수, 문서 ID)`로 정렬한 상위 k개 `(문서 ID, 점수)`. 질문의 `unjudged`를 지우기 전 순위다. `results/baselines/**` 저장본(condensed)은 쓰지 않는다. 0건이 나올 수 있다 |
| `build_context(track, doc_ids, load_body, char_cap)` | 문서마다 `[문서 ID]` 머리 줄 + 색인 텍스트(문서당 `char_cap`자까지, 기본 3000)를 빈 줄로 이어 붙인 `context_text`와 잘린 문서 ID 목록. 여기서 `load_body(doc_id)`는 색인 텍스트를 돌려주는 함수다(`index.text`) |
| `build_prompt(question, context_text)` | 채팅 메시지 `[system, user]`. 문맥이 비면 고정 문구로 대신한다. `prompt_fingerprint()`가 고정 문구 전체의 sha256이다 |
| `generate(question, context_text, allowed_ids, llm)` | `llm(messages)`를 부르고 `parse_answer`로 파싱한다. 파싱 실패면 재질의를 1회 한다(최대 2회 호출). `GenerationResult`(answer, abstain, citations, n_invalid_citations, status, n_attempts, prompt_tokens, completion_tokens, latency_ms)를 돌려준다 |
| `parse_answer(raw, allowed_ids)` | `(answer, abstain, citations, invalid_citations, parse_status)`. 입력 문자열을 담지 않는 고정 reason code만 낸다 |
| `run_question(question, index, k, llm, track)` | 위 함수를 묶어 결과 행(`answer` 포함)을 만든다. 커밋 행은 `commit_row(row, track)`로 거른다 |

`llm`은 `llm(messages) -> LLMResponse`를 만족하는 호출 가능 객체다. 실행은 `OllamaLLM`(표준 라이브러리 `urllib`로
`/api/chat` 호출), 테스트는 가짜 LLM을 쓴다. `llm.max_prompt_tokens`가 있으면 문맥 초과 판정에 쓴다.

## 프롬프트 (고정 문구 원문)

프롬프트는 하나로 고정하고 튜닝하지 않는다. 문서 내용은 이 문구에 들어 있지 않다(문맥은 실행 시 `{context}`로 들어간다).

system:

```text
당신은 보안 문서 질의응답 도우미입니다. 사용자가 준 [문서] 목록의 내용만 근거로 질문에 한국어로 답하세요. 문서에 질문의 답이 없으면 추측하지 말고 기권하세요.
출력은 JSON 객체 하나만 쓰고 다른 글자는 쓰지 마세요: {"answer": 문자열, "abstain": true 또는 false, "citations": [문서 ID 문자열, ...]}
- answer: 질문에 대한 답. 기권하면 빈 문자열.
- abstain: 문서에 답이 없어 기권하면 true, 답하면 false.
- citations: 답의 근거로 쓴 문서의 ID 목록. [문서 ID] 머리에 적힌 ID를 그대로 쓰고, 기권하면 빈 목록.
```

user (`{context}` = `[문서 ID]` 머리 + 색인 텍스트들, 비면 `(검색된 문서 없음)`):

```text
[문서]
{context}

[질문]
{question}
```

재질의(파싱 실패 1회째 뒤에만): 첫 질의 메시지 + `assistant`(직전 응답 원문) + `user`(아래 문구, `{reason}` = 고정 reason code).
온도 0에 고정 시드라 같은 요청을 다시 보내면 같은 답이 나오므로, 실패 사유를 알리는 교정 요청을 덧붙인다.

```text
직전 응답이 출력 형식 규칙을 어겼습니다(사유: {reason}). 위 규칙대로 JSON 객체 하나만 다시 출력하세요.
```

프롬프트 sha256(`prompt_fingerprint()`, manifest의 `prompt.sha256`): `48c60b10def29cd43a76f3c74f3fef51cada5af483d61b0df28029c4fae4bbc7`

## 출력 계약

모델은 JSON 객체 하나 `{"answer": str, "abstain": bool, "citations": [문서 ID]}`로 답한다.

- `citations`는 문맥에 있던 문서 ID만 유효하다. 그 밖의 문자열은 무효 인용으로 개수만 센다(`n_invalid_citations`).
  답 하나의 citations는 중복을 지운 집합으로 본다. 인용 원소는 문자열이거나 정수(JSON 숫자로 쓴 nttId)여야 하고 정수는
  문자열로 바꾼다. 추가 키는 무시한다.
- 상태(`status`): `ok`(계약 파싱 성공) | `parse_failed:<reason>` | `context_overflow`.
- reason code(고정): `empty`, `not_json`, `not_object`, `missing_answer`, `missing_abstain`, `missing_citations`,
  `bad_answer`, `bad_abstain`, `bad_citations`.
- 재질의: 첫 응답이 `parse_failed`면 1회 다시 묻는다. 시도 횟수는 `n_attempts`(1 또는 2)다. 두 번째도 실패하면 그 reason이 최종
  상태다. 파싱 성공률 = 최종 `status == ok`인 행 수 / 예상 질문 수(`context_overflow`와 최종 파싱 실패는 실패이고 재질의 전후를
  따로 세지 않는다).
- 실패 행은 `abstain=false`, `citations=[]`, `n_invalid_citations=0`이다(파싱 실패는 기권으로 세지 않는다).

## 입력 토큰 수·지연·문맥 초과

- 입력 토큰 수 = Ollama 응답의 `prompt_eval_count`(없으면 null), 출력 토큰 수 = `eval_count`. 재질의가 있으면 입력 토큰은
  첫 시도 값, 출력 토큰·지연은 모든 시도의 합이다.
- 검증: 실행 시작 때 같은 프롬프트를 두 번 보내 `prompt_eval_count`가 같은지 확인한다(질문 3개, k=5 문맥). 서버가 접두사
  KV 캐시를 써도 응답 값은 전체 입력 토큰 수여서 같았다(`token_counting.repro_check`: 질문 3개 x 2회 중 3쌍 모두 같음). 다르면 실행을 중단하고
  `--keep-alive 0`(요청마다 모델을 내려 캐시를 쓰지 않음)으로 다시 돌리게 한다.
- 지연 `latency_ms` = (`total_duration` - `load_duration`)를 밀리초로 바꾼 값(모델 적재 시간 제외).
- 문맥 초과: 보내기 전에 셀 수 없다(Ollama에 tokenize 엔드포인트가 없고 토크나이저 파일을 따로 받지 않는다). 응답의
  `prompt_eval_count >= num_ctx - num_predict`(= 16384 - 512)이면 `context_overflow`로 바꿔 기록하고 파싱·재질의를 하지 않는다.
  경계(직전 값은 ok, 같은 값은 초과)를 테스트한다.

## 요청 옵션

`/api/chat`, `stream: false`, `format: "json"`, `think: false`, `options` = `temperature 0`, `seed 42`, `num_ctx 16384`,
`num_predict 512`. `num_ctx`는 k=5 x 문서당 3000자 + 고정 문구 + 출력 예약(512)을 담도록 정했다(한국어는 문자당 0.6토큰 안팎).

## 결과 행 (고정 키 집합)

`results/m5/generation/<track>_k<k>.jsonl`의 한 줄 = 질문 하나. 키는 이것뿐이다(`validate_row`, `--metrics-only`, #68 릴리스 검사).

| 키 | 뜻 |
|---|---|
| `question_id`, `split`, `query_type`, `k` | 질문 ID, 분할, 유형, 문맥 문서 수 상한 |
| `status` | `ok` / `parse_failed:<reason>` / `context_overflow` |
| `abstain` | 기권 여부(`ok`일 때만 참이 될 수 있다) |
| `citations` | 문맥에 있던 검증된 문서 ID(무효 문자열은 저장하지 않는다) |
| `n_invalid_citations` | 무효 인용 수 |
| `retrieved` | 검색된 문서 ID 순서 목록(문맥 문서 순서와 같다) |
| `truncated` | 문서당 상한으로 잘린 문서 ID |
| `n_retrieved` | 검색된 수(k보다 적거나 0일 수 있다. 0건이어도 LLM을 부른다) |
| `prompt_tokens`, `completion_tokens` | 입력(첫 시도)·출력(모든 시도 합) 토큰 수, 없으면 null |
| `latency_ms` | 적재 시간 제외 지연(모든 시도 합) |
| `context_sha256` | `context_text`의 sha256(#66·#67이 같은 문맥을 다시 만들었는지 확인) |
| `n_attempts`, `context_chars` | LLM 호출 횟수(1~2), 문맥 문자 수 |
| `answer` | 공개 트랙만. KISA 행에는 없다 |

KISA 로컬 캐시 행 = 위 키 + `answer` + `run_id`(manifest의 실행 ID). 실행 ID는 모델 digest·옵션·프롬프트·문서 상한·검색
설정이 같으면 같은 값이라, #66이 로컬 캐시와 커밋 행이 같은 실행인지 확인한다(`context_sha256`도 같아야 한다).
같은 `run_id`의 로컬 행이 있으면 다시 호출하지 않고 이어서 돌린다.

문맥을 다시 만들려면: `retrieved`의 ID 순서대로 `build_context(track, retrieved, index.text)`를 부르면 `context_sha256`과
같은 문자열이 나온다.

## 기계 지표 (`topk.json`)

`topk.json`의 칸 = 트랙 x k x 분할(dev, test, all) x 유형(질문 유형 4개, `macro`, `all`). 저장된 jsonl과 질의셋 라벨만으로
다시 계산한다(`--metrics-only`).

| 지표 | 정의 |
|---|---|
| `parse_success_rate` | 최종 `ok` 행 / 행 수. 파싱 실패율 `parse_fail_rate`, 문맥 초과율 `context_overflow_rate`는 따로 |
| `correct_abstain_rate` | `no_answer` 질문 중 `ok`이면서 `abstain=true` 비율(분모 = `no_answer` 질문 전부, 파싱 실패는 기권 아님) |
| `false_abstain_rate` | 정답 있는 질문 중 `ok`이면서 `abstain=true` 비율(분모 = 정답 있는 질문 전부) |
| `citation_hit_rate` | 정답 있는 질문 중 `ok`·`abstain=false`·`citations ∩ gold ≠ ∅` 비율(분모 = 정답 있는 질문 중 `ok`·비기권, 0이면 null) |
| `invalid_citation_rate` | 무효 인용 수 합 / (검증 인용 수 합 + 무효 인용 수 합)(마이크로, 분모 0이면 null, 무인용 답은 0을 더한다) |
| `n_unjudged_citations` | unjudged 문서를 인용한 수. 적중도 무효도 아니고(검증 인용에는 들어간다) 따로 센다 |
| `prompt_tokens_median`, `prompt_tokens_max`, `latency_ms_median` | 입력 토큰 수 중앙값·최대, 지연 중앙값(null 제외) |
| `context_chars_median`, `n_truncated_questions`, `n_retried` | 문맥 문자 수 중앙값, 문서가 잘린 질문 수, 재질의한 질문 수 |

`macro`는 정답 있는 유형(`cve_explicit`, `product_symptom`, `explanation_comparison` 중 행이 있는 것)의 비율 지표 단순 평균이다
(정의된 값만). 정답성·faithfulness는 LLM 판정이라 여기에 없다(#66).

## 재현

```sh
ollama serve                      # 별도 프로세스. 끝나면 띄운 프로세스만 끈다
ollama pull qwen3:8b
uv run python scripts/run_generation.py --track public --k 1 3 5
uv run python scripts/run_generation.py --track kisa --kisa-root <KISA-ROOT> --k 1 3 5
uv run python scripts/run_generation.py --metrics-only    # 모델·Ollama·KISA 캐시 없이 저장본 검사 + topk.json 대조
uv run python scripts/run_generation.py --render-docs     # topk.json -> 이 문서의 표
uv run python scripts/run_generation.py --track public --k 3 --limit 5 --out-dir <빈 디렉터리>   # 소표본(커밋본을 건드리지 않는다)
```

`--metrics-only`는 manifest의 해시, 행 키 집합, 질문 집합(예상 집합과 정확히 같고 중복 없음), 성공률 80% 하한을 검사한 뒤
`topk.json`을 다시 계산해 커밋본과 절대 오차 1e-9 안에서 비교한다. 다르면 exit 1이다. 실행 중 계약 파싱 성공률이
(트랙, k)마다 80% 미만이면 그 결과를 쓰지 않고 exit 1이다.

## 소표본 측정과 예상 시간

전체 실행 전에 공개 8문항(유형을 돌려 가며 고름) x k 1·3·5와 KISA 6문항 x k 1·3·5를 `--limit`으로 먼저 돌려 측정했다
(커밋 결과와 섞이지 않게 `--out-dir`을 따로 줬다).

| 측정 | 값 |
|---|---|
| 계약 파싱 성공률 (소표본) | 공개 8/8, KISA 6/6 (k 1·3·5 모두), 재질의 0건 |
| `prompt_eval_count` 재현성 | 같은 프롬프트 2회 전송, 3쌍 모두 같음 (접두사 KV 캐시를 써도 응답 값은 전체 입력 토큰 수) |
| 문항당 시간 (공개) | 8문항 x 3 k = 24건에 약 33초, 건당 약 1.4초 |
| 문항당 시간 (KISA) | 6문항 x 3 k = 18건에 약 71초, 건당 약 3.9초(k=5가 가장 길어 문항당 약 5초) |
| 전체 예상 시간 | 공개 144 x 3 = 432건 x 1.4초 = 약 10분 + KISA 52 x 3 = 156건 x 3.9초 = 약 10분, 합계 약 20분 (4시간 상한 대비 충분) |

전체 실행의 실제 소요(`manifest.json`의 `wall_seconds_this_invocation`): 공개 k=1·3·5 = 193·229·252초(합 약 11분),
KISA k=1·3·5 = 100·232·376초(합 약 12분). 예상과 같은 범위였다.

## top-k 표

숫자는 `results/m5/generation/topk.json`에서만 온다(`--render-docs`).

<!-- BEGIN GENERATED TABLES (scripts/run_generation.py --render-docs) -->

### 공개 트랙 (NVD): k별 요약 (dev+test 전체)

| k | 질문 수 | 계약 파싱 성공률 | 재질의 수 | 문맥 초과 | 올바른 기권률 | 잘못된 기권률 | 인용 적중률 | 무효 인용률 | 입력 토큰 중앙값 | 입력 토큰 최대 | 지연 중앙값(초) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 144 | 1.000 | 0 | 0 | 1.000 | 0.142 | 0.942 | 0.000 | 288 | 465 | 0.95 |
| 3 | 144 | 1.000 | 0 | 0 | 1.000 | 0.125 | 0.952 | 0.000 | 295 | 834 | 1.70 |
| 5 | 144 | 1.000 | 0 | 0 | 1.000 | 0.125 | 0.962 | 0.000 | 295 | 1012 | 1.78 |

### 공개 트랙 (NVD): 유형별 (dev+test 전체)

| k | 유형 | 질문 수 | 파싱 성공률 | 올바른 기권률 | 잘못된 기권률 | 인용 적중률 | 무효 인용률 | unjudged 인용 수 | 입력 토큰 중앙값 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | cve_explicit | 60 | 1.000 | - | 0.000 | 1.000 | 0.000 | 0 | 293 |
| 1 | product_symptom | 60 | 1.000 | - | 0.283 | 0.860 | 0.000 | 2 | 290 |
| 1 | no_answer | 24 | 1.000 | 1.000 | - | - | - | 0 | 251 |
| 1 | macro | 120 | 1.000 | - | 0.142 | 0.930 | 0.000 | - | - |
| 3 | cve_explicit | 60 | 1.000 | - | 0.000 | 1.000 | 0.000 | 0 | 293 |
| 3 | product_symptom | 60 | 1.000 | - | 0.250 | 0.889 | 0.000 | 5 | 389 |
| 3 | no_answer | 24 | 1.000 | 1.000 | - | - | - | 0 | 251 |
| 3 | macro | 120 | 1.000 | - | 0.125 | 0.944 | 0.000 | - | - |
| 5 | cve_explicit | 60 | 1.000 | - | 0.000 | 1.000 | 0.000 | 0 | 293 |
| 5 | product_symptom | 60 | 1.000 | - | 0.250 | 0.911 | 0.000 | 7 | 490 |
| 5 | no_answer | 24 | 1.000 | 1.000 | - | - | - | 0 | 251 |
| 5 | macro | 120 | 1.000 | - | 0.125 | 0.956 | 0.000 | - | - |

### 공개 트랙 (NVD): 분할별 macro (정답 있는 유형의 단순 평균)

| k | 분할 | 파싱 성공률 | 잘못된 기권률 | 인용 적중률 | 무효 인용률 |
|---|---|---|---|---|---|
| 1 | dev | 1.000 | 0.095 | 0.941 | 0.000 |
| 1 | test | 1.000 | 0.167 | 0.923 | 0.000 |
| 1 | all | 1.000 | 0.142 | 0.930 | 0.000 |
| 3 | dev | 1.000 | 0.095 | 0.912 | 0.000 |
| 3 | test | 1.000 | 0.141 | 0.964 | 0.000 |
| 3 | all | 1.000 | 0.125 | 0.944 | 0.000 |
| 5 | dev | 1.000 | 0.119 | 0.938 | 0.000 |
| 5 | test | 1.000 | 0.128 | 0.966 | 0.000 |
| 5 | all | 1.000 | 0.125 | 0.956 | 0.000 |

### KISA 트랙: k별 요약 (dev+test 전체)

| k | 질문 수 | 계약 파싱 성공률 | 재질의 수 | 문맥 초과 | 올바른 기권률 | 잘못된 기권률 | 인용 적중률 | 무효 인용률 | 입력 토큰 중앙값 | 입력 토큰 최대 | 지연 중앙값(초) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 52 | 1.000 | 0 | 0 | 1.000 | 0.476 | 0.909 | 0.000 | 835 | 2287 | 1.36 |
| 3 | 52 | 1.000 | 0 | 0 | 1.000 | 0.071 | 0.974 | 0.000 | 3282 | 4909 | 4.45 |
| 5 | 52 | 1.000 | 0 | 0 | 1.000 | 0.048 | 0.950 | 0.000 | 4824 | 7271 | 7.46 |

### KISA 트랙: 유형별 (dev+test 전체)

| k | 유형 | 질문 수 | 파싱 성공률 | 올바른 기권률 | 잘못된 기권률 | 인용 적중률 | 무효 인용률 | unjudged 인용 수 | 입력 토큰 중앙값 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | cve_explicit | 20 | 1.000 | - | 0.700 | 1.000 | 0.000 | 0 | 1054 |
| 1 | product_symptom | 12 | 1.000 | - | 0.333 | 1.000 | 0.000 | 0 | 844 |
| 1 | explanation_comparison | 10 | 1.000 | - | 0.200 | 0.750 | 0.000 | 1 | 1464 |
| 1 | no_answer | 10 | 1.000 | 1.000 | - | - | - | 0 | 830 |
| 1 | macro | 42 | 1.000 | - | 0.411 | 0.917 | 0.000 | - | - |
| 3 | cve_explicit | 20 | 1.000 | - | 0.100 | 1.000 | 0.000 | 0 | 3116 |
| 3 | product_symptom | 12 | 1.000 | - | 0.000 | 0.917 | 0.000 | 0 | 3248 |
| 3 | explanation_comparison | 10 | 1.000 | - | 0.100 | 1.000 | 0.000 | 1 | 3977 |
| 3 | no_answer | 10 | 1.000 | 1.000 | - | - | - | 0 | 3215 |
| 3 | macro | 42 | 1.000 | - | 0.067 | 0.972 | 0.000 | - | - |
| 5 | cve_explicit | 20 | 1.000 | - | 0.100 | 0.944 | 0.000 | 0 | 4486 |
| 5 | product_symptom | 12 | 1.000 | - | 0.000 | 0.917 | 0.000 | 0 | 5058 |
| 5 | explanation_comparison | 10 | 1.000 | - | 0.000 | 1.000 | 0.000 | 1 | 5966 |
| 5 | no_answer | 10 | 1.000 | 1.000 | - | - | - | 0 | 4570 |
| 5 | macro | 42 | 1.000 | - | 0.033 | 0.954 | 0.000 | - | - |

### KISA 트랙: 분할별 macro (정답 있는 유형의 단순 평균)

| k | 분할 | 파싱 성공률 | 잘못된 기권률 | 인용 적중률 | 무효 인용률 |
|---|---|---|---|---|---|
| 1 | dev | 1.000 | 0.630 | 0.833 | 0.000 |
| 1 | test | 1.000 | 0.248 | 1.000 | 0.000 |
| 1 | all | 1.000 | 0.411 | 0.917 | 0.000 |
| 3 | dev | 1.000 | 0.104 | 0.933 | 0.000 |
| 3 | test | 1.000 | 0.030 | 1.000 | 0.000 |
| 3 | all | 1.000 | 0.067 | 0.972 | 0.000 |
| 5 | dev | 1.000 | 0.037 | 0.933 | 0.000 |
| 5 | test | 1.000 | 0.030 | 0.967 | 0.000 |
| 5 | all | 1.000 | 0.033 | 0.954 | 0.000 |

<!-- END GENERATED TABLES -->

## 해석과 한계

- **계약 파싱**: 6개 (트랙, k) 모두 성공률 1.000(공개 144/144, KISA 52/52), 재질의·문맥 초과 0건이라 80% 하한을 넉넉히 넘었다.
  프롬프트는 소표본을 포함해 한 번도 고치지 않았다. 대체 후보 모델은 쓰지 않았다.
- **올바른 기권률 1.000은 쉬운 경우가 섞여 있다**: 공개 트랙 `no_answer` 24건은 질의 토큰이 코퍼스에 하나도 없어 BM25가
  0건을 돌려주고(`n_retrieved = 0`, 모든 k), 모델은 빈 문맥 문구를 보고 기권했다. 기권은 검색 결과가 비었다는 신호에 기댄 것이라
  "문서가 있어도 답이 없음을 알아보는 능력"의 증거가 아니다. KISA `no_answer` 10건은 문맥이 비지 않았는데도 전부 기권했다
  (k 1·3·5).
- **잘못된 기권률은 k가 커질수록 줄어든다**: KISA 0.476 -> 0.071 -> 0.048(k=1 -> 3 -> 5). k=1에서 기권은 `cve_explicit` 14,
  `product_symptom` 4, `explanation_comparison` 2건이다. 문맥이 한 건뿐이라 정답이 빠졌을 가능성이 높지만 원인(검색 순위 대 모델 판단)은
  이 실행에서 따로 분해하지 않았다. 공개 트랙은 0.142 -> 0.125 -> 0.125로 거의 평평하고 기권은 전부 `product_symptom`이다.
- **인용 적중률**은 기권하지 않은 답 중 비율이라 잘못된 기권이 많은 k=1에서는 분모가 작다. 트랙 간·k 간 비교는 분모
  (`n_cited_answers`)와 함께 본다. 무효 인용(문맥 밖 ID)은 모든 칸에서 0이었다. unjudged 문서 인용은 공개 2·5·7건(k 1·3·5의 인용 수),
  KISA 1건(모든 k에서 같은 질문)으로 적중도 무효도 아니다.
- **입력 토큰**: 문맥 길이에 비례한다. 중앙값은 공개 288·295·295(문서가 짧고 BM25 일치 문서가 적어 k=3과 5가 같다), KISA
  835·3282·4824, 최대는 KISA k=5의 7271로 `num_ctx - num_predict` = 15872에 한참 못 미친다.
- **지연**(적재 제외, 중앙값): 공개 약 1.0·1.7·1.8초, KISA 약 1.4·4.5·7.5초. 지연은 문맥 길이를 따른다.
- **문서 상한 3000자**: KISA 코퍼스 50건 중 10건이 상한을 넘는다. 질문 단위로 문서가 잘린 질문 수는 k=1·3·5에서 10·32·47건
  (52건 중)이다. 길이가 긴 공지의 뒷부분(표·CVE 목록 등)은 모델이 못 본다. 상한을 올리면 입력 토큰이 늘고 `num_ctx`도 올려야 한다.
- **결정성**: 온도 0, 시드 42에서 공개 12문항 x k 3개를 다시 돌려 답·인용·토큰 수가 모두 같았다(36/36). 다른 하드웨어·Ollama
  버전에서의 재현은 보장하지 않는다(manifest에 서버 버전과 환경을 적었다).
- **한계**: 모델 하나, 프롬프트 하나, 시드 하나의 결과라 분산을 모른다. KISA 채점 질문은 52건이라 유형별 칸(특히
  `no_answer` 10건)은 표본이 작다. 답의 정확성·근거 충실도는 이 표에 없다(#66의 LLM 판정). 기계 지표의 "인용 적중"은
  정답 문서를 인용했다는 뜻이지 답이 맞다는 뜻이 아니다. 질문은 한국어이고 NVD 문서는 영어라 답의 언어·번역 품질은 보지 않는다.
- **알려진 제약**: 문맥 초과는 보내기 전에 셀 수 없어 응답으로 판정한다(이번 실행은 0건). 인용 ID는 공백만 다듬고 정확히
  일치해야 유효하다(대소문자·대괄호 변형은 무효로 센다). 이번 실행에서 그런 변형은 없었다.

## 범위 밖

LLM 판정(faithfulness·정답성), LangChain/LangGraph, 프롬프트 튜닝, 다른 검색기, 모델 여러 개 비교.

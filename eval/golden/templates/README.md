# 골든셋 검수 양식

이 폴더는 사람이 채울 양식만 둔다. 채운 검수 결과와 사람 검수 골든셋은 여기에도, `eval/golden/candidates/`에도
두지 않는다(후보는 사람 검수 정답이 아니다). 정답 단위는 문서(`nttId`)다 - `docs/eval-protocol.md` 1, 8절.

| 파일 | 내용 |
|---|---|
| `review_template.csv` | 헤더만 있는 빈 양식 |
| `review_sheet_candidate_sample.csv` | 표본 쌍(`eval/golden/candidates/weak_label_sample_pairs.jsonl`)에서 미리 채운 양식. 사람이 채울 칸은 비어 있다 |

## 칸

미리 채워진 칸(고치지 않는다): `question_id`, `query_type`, `doc_id`, `doc_sha256`(문서 버전, `fixtures/kisa/manifest.json`의 sha256),
`stratum`, `in_candidate_set`(`true`면 CVE 조인 후보, `false`면 후보 밖 점검 표본), `weak_label`, `evidence_parser_version`.

사람이 채우는 칸:

| 칸 | 값 |
|---|---|
| `evidence_start`, `evidence_end` | 근거 위치. 정규화 본문 문자 오프셋의 반개구간 `[start, end)`(eval-protocol 8절). 관련 판정일 때 필수, 본문 텍스트는 적지 않는다 |
| `relevance` | `relevant`(질문에 답하는 근거가 있음) / `not_relevant` |
| `reason` | 판정 이유. 본문 인용 없이 추상적으로 적는다 |
| `error_class` | `mislabel`(오라벨) / `omission`(누락) / `ok`(정상) |

`error_class`는 판정과 후보 여부에서 정해진다. 모순되면 오류율 계산기가 거부한다.

| `in_candidate_set` | `relevance` | `error_class` |
|---|---|---|
| true | relevant | ok |
| true | not_relevant | mislabel |
| false | relevant | omission |
| false | not_relevant | ok |

## 오류율

```sh
uv run python -m krsec_rag_lab.golden error-rates <채운 검수 CSV>
```

오라벨률은 후보 집합 안 쌍 중 `mislabel` 비율, 누락률은 후보 밖 점검 표본 중 `omission` 비율이다. 누락률은 후보 밖 표본에서
잰 값이라 코퍼스 전체의 누락률이 아니다. `relevance`가 빈 행은 미검수로 세고 분모에서 뺀다. Excel로 저장한 CSV(UTF-8 BOM, `TRUE`/`FALSE`)도 읽는다. (question_id, doc_id)가 겹치거나 `in_candidate_set`이 `stratum`·`weak_label`과 모순되는 행, 칸 수가 헤더와 다른 행은 한 줄 사유와 exit 1로 거부한다.

## 골든셋 레코드 스키마

`uv run python -m krsec_rag_lab.golden validate <golden.jsonl>`이 검사한다. 한 줄 = 질문 하나:

```
{"question_id": str, "query": str, "query_type": "cve_explicit"|"product_symptom"|"explanation_comparison"|"no_answer",
 "split": "dev"|"test" (선택, 쓰면 모든 레코드에 필요), "cve_ids": [CVE...] (선택),
 "surface_cve": bool (선택, 질의 문장에 CVE ID가 있었는지. 쓰면 문장과 일치해야 한다),
 "answers": [{"doc_id": nttId, "doc_sha256": 64자 hex,
              "evidence": [{"parser_version": str, "start": int, "end": int, "nttId": doc_id와 같은 값(선택)}], "reason": str}],
 "no_answer_reason": str (no_answer만, 이때 answers는 빈 목록)}
```

본문·요약·발췌·설명 원문을 담는 필드(`body`, `text`, `excerpt`, `summary` 등)와 위 목록에 없는 필드는 거부한다.
`split`이 있으면 `splits.assert_disjoint`로 dev/test 누수를 검사한다.

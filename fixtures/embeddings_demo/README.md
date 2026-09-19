# embeddings_demo fixture

`notebooks/00_embeddings_from_scratch.ipynb`(이슈 #5)이 생성한다.
이슈 #6(Qdrant exact/HNSW 대조)이 **같은 문서·같은 질의·같은 벡터**를 재사용하기 위한 인계물이다.
#6에서 임베딩을 다시 만들면 검색 방식의 차이와 임베딩의 차이가 섞여 대조가 성립하지 않는다.

| 파일 | 내용 |
|---|---|
| `documents.json` | 합성 문서 10건 + 질의 1건 + 기대 정답 `doc_id` |
| `doc_embeddings.npy` | 문서 임베딩 `(10, 1024)` float32, L2 정규화됨. 행 순서 = `documents.json`의 `documents` 순서 |
| `query_embedding.npy` | 질의 임베딩 `(1024,)` float32, L2 정규화됨 |
| `baseline_scores.json` | NumPy 전수 코사인 점수와 top-3 (근사 검색의 대조 기준) |
| `manifest.json` | 모델명·revision·pooling·정규화 여부·차원·런타임·`documents.json` sha256·생성 시각 |

## 데이터 출처

`documents.json`의 `text`는 **전부 이 리포를 위해 직접 작성한 합성 한국어 보안 공지 요약**이다.
실제 KISA/NVD 권고문 본문이 아니며 사실 확인 용도로 쓸 수 없다.
`cve`·`product` 필드만 실제 공개 식별자를 참조한다.
PLAN.md 원칙 6(재배포 조건 미확인 원문은 리포 어디에도 넣지 않는다)에 따른 조치다.

## 재생성

```bash
uv sync --group embed
uv run --no-sync jupyter nbconvert --to notebook --execute --inplace \
  notebooks/00_embeddings_from_scratch.ipynb
```

모델 revision·시드·device(CPU)가 노트북에 고정돼 있으므로 같은 값이 다시 나와야 한다.
값이 달라지면 `manifest.json`의 `runtime`을 먼저 비교한다.

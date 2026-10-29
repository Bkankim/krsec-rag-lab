# 라이선스 맵

## 이 리포가 직접 만드는 것

- **코드·문서**: [MIT](../LICENSE)
- **자작 평가 데이터**(질문·정답 라벨·판정 이유): MIT. 단 라벨이 가리키는 원본 문서는
  아래 소스별 조건을 따르며, 라벨에는 원문 본문을 포함하지 않는다(ID·URL·위치 참조만).

## 원본 데이터 소스

| 소스 | 정책 | 확인 상태 (2026-09-19) | 리포 포함 범위 |
|---|---|---|---|
| KISA 보안공지 (boho.or.kr) | 정책 원문 **미확인** - 사이트에 공공누리 마크·저작권 정책 페이지가 없고 "All rights reserved" 푸터만 확인됨 | 허용 여부 미확인. **확인 전까지 프로젝트 방침으로 본문 미배포** | 수집 스크립트 + 메타데이터 인덱스(URL·제목·날짜·게시물 ID·추출 CVE ID)만. 전체 코퍼스의 메타데이터 인덱스(`fixtures/kisa_full/metadata.jsonl`)와 manifest(`fixtures/kisa_full/manifest.json`)도 URL·제목·날짜·nttId·추출 CVE ID·본문 sha256만 담고, 본문은 로컬 캐시 `data/kisa_full/`(gitignore) |
| NVD (nvd.nist.gov) | 미국 연방정부 저작물 + CVE 레코드는 MITRE 고지 재현 조건 - [Terms of Use](https://nvd.nist.gov/developers/terms-of-use) | 약관 확인 (2026-10-29 재확인: MITRE CVE Terms of Use, NVD API Terms of Use) | `fixtures/nvd/cves.jsonl`에 선정 필드만 담은 서브셋 포함. MITRE 저작권·라이선스 고지와 NVD 고지를 `fixtures/nvd/NOTICE.md`에 동봉(선정 필드로 수정한 콘텐츠이므로 NVD 공식 데이터로 표기하지 않는다). 원 응답 캐시는 `data/nvd/`(gitignore). API 키 커밋 금지 |
| CISA KEV | CC0 1.0 - [license.txt](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt) | 원문 확인 | `fixtures/nvd/kev.json`에 KISA 인용 CVE와 겹치는 항목만 포함. 전체 카탈로그 원본은 `data/nvd/`(gitignore) |
| SigmaHQ rules | [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License) - author·원본 링크·라이선스 표시 보존 | 원문 확인 | 초기 범위 제외. 도입 시 룰 파일의 author 필드 보존 + DRL 전문 + 원본 링크 동봉 |
| MITRE ATT&CK | [Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) - 복제물에 저작권 표시와 라이선스 전문 재현 | 약관 확인 | 초기 범위 제외. 도입 시 고지 문구 + 라이선스 전문 동봉 |

## 정답 판정용 외부 모델 API로의 본문 전송

골든셋 정답 판정을 위해 KISA 보안공지 본문은 로컬 캐시에서 읽혀 판정용 외부 모델 API 2종(Anthropic 계열,
OpenAI 계열)으로 전송된다. 전송은 로컬에서 실행하는 판정 단계에 한정되고, 본문은 리포·릴리스·CI artifact에
넣지 않는다. 리포에 남기는 판정 결과는 질문 ID·판정자 구분·문서 ID·오프셋·고정 코드·집계뿐이며 본문 인용을 포함하지 않는다. 이
전송은 위 KISA 행의 재배포 허용 여부를 바꾸지 않는다(확인 전까지 본문 미배포). 전송된 본문의 처리는 각 API 제공자의
약관을 따른다. NVD·CISA KEV 서브셋은 이미 리포에 포함된 공개 범위라 해당 없다.

## 본문 유출 방지 점검 대상

KISA 본문이 새어 들어갈 수 있는 경로 - 커밋·릴리스 전 매번 점검한다:

- 노트북 입력/출력 셀
- 검색 결과 원시 JSON(허용 필드: 질문 ID·문서 ID·순위·점수·근거 위치. 본문 텍스트 금지)
- 생성 답변 로그·평가 로그
- 판정자 요청·응답 로그(본문 인용 금지, 허용 필드는 질문 ID·판정자 구분·문서 ID·오프셋·고정 코드)
- 릴리스 첨부 파일
- README·블로그의 예시 인용

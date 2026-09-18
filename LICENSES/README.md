# 라이선스 맵

## 이 리포가 직접 만드는 것

- **코드·문서**: [MIT](../LICENSE)
- **자작 평가 데이터**(질문·정답 라벨·판정 이유): MIT. 단 라벨이 가리키는 원본 문서는
  아래 소스별 조건을 따르며, 라벨에는 원문 본문을 포함하지 않는다(ID·URL·위치 참조만).

## 원본 데이터 소스

| 소스 | 정책 | 확인 상태 (2026-09-19) | 리포 포함 범위 |
|---|---|---|---|
| KISA 보안공지 (boho.or.kr) | 정책 원문 **미확인** - 사이트에 공공누리 마크·저작권 정책 페이지가 없고 "All rights reserved" 푸터만 확인됨 | 허용 여부 미확인. **확인 전까지 프로젝트 방침으로 본문 미배포** | 수집 스크립트 + 메타데이터 인덱스(URL·제목·날짜·게시물 ID·추출 CVE ID)만. 본문은 로컬 캐시(gitignore) |
| NVD (nvd.nist.gov) | 미국 연방정부 저작물 + CVE 레코드는 MITRE 고지 재현 조건 - [Terms of Use](https://nvd.nist.gov/developers/terms-of-use) | 약관 확인 | 평가용 서브셋 JSON 포함(MITRE 고지 동봉). API 키 커밋 금지 |
| CISA KEV | CC0 1.0 - [license.txt](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt) | 원문 확인 | 스냅샷 포함 가능 |
| SigmaHQ rules | [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License) - author·원본 링크·라이선스 표시 보존 | 원문 확인 | 초기 범위 제외. 도입 시 룰 파일의 author 필드 보존 + DRL 전문 + 원본 링크 동봉 |
| MITRE ATT&CK | [Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) - 복제물에 저작권 표시와 라이선스 전문 재현 | 약관 확인 | 초기 범위 제외. 도입 시 고지 문구 + 라이선스 전문 동봉 |

## 본문 유출 방지 점검 대상

KISA 본문이 새어 들어갈 수 있는 경로 - 커밋·릴리스 전 매번 점검한다:

- 노트북 입력/출력 셀
- 검색 결과 원시 JSON(허용 필드: 질문 ID·문서 ID·순위·점수·근거 위치. 본문 텍스트 금지)
- 생성 답변 로그·평가 로그
- 릴리스 첨부 파일
- README·블로그의 예시 인용

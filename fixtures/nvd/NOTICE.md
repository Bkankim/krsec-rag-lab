# NOTICE - NVD, CVE(MITRE), CISA KEV

이 디렉터리의 `cves.jsonl`은 NVD API 2.0 / NVD 연도별 JSON 피드 응답에서 **선정한 필드만** 옮긴 파생 서브셋이다.
`kev.json`은 CISA KEV 카탈로그의 일부 항목이다. 원문 전체가 아니며, 이 리포가 NVD·CISA가 만든 공식 사본이
아니다. 구성과 필드는 `README.md`, 수집 시각·소스·해시는 `manifest.json`에 있다.

## CVE (MITRE)

출처: https://www.cve.org/Legal/TermsOfUse (확인일 2026-10-29, 해당 페이지에서 그대로 옮김)

> CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute Common Vulnerabilities and Exposures (CVE™). Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.
>
> ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN PROVIDED BY MITRE ARE PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF TRUSTEES, OFFICERS, AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.

Copyright © 1999-2026, The MITRE Corporation

CVE is a trademark and the CVE logo is a registered trademark of The MITRE Corporation.

## NVD (NIST)

출처: https://nvd.nist.gov/developers/terms-of-use (확인일 2026-10-29, 해당 페이지에서 그대로 옮김)

> Services which utilize or access the NVD API are asked to display the following notice prominently within the application: "This product uses the NVD API but is not endorsed or certified by the NVD."
>
> You may use the NVD name in order to identify the source of API content subject to these rules. You may not use the NVD name, to imply endorsement of any product, service, or entity, not-for-profit, commercial or otherwise.
>
> If you modify the content accessed through the API, you may not attribute the source as the NVD.

**This product uses the NVD API but is not endorsed or certified by the NVD.**

`cves.jsonl`은 위 조건의 "수정된 콘텐츠"에 해당한다(필드 선별, 이름 변경, 목록 절단). 따라서 이 파일의 내용을
NVD의 공식 데이터로 표시하지 않는다. 원본 레코드는 `manifest.json`의 소스 URL과 CVE ID로 NVD에서 조회한다.

## CISA KEV

출처: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
라이선스: CC0 1.0 - https://www.cisa.gov/sites/default/files/licenses/kev/license.txt

`kev.json`은 KISA 인용 CVE와 겹치는 항목만 담는다. 카탈로그 버전·공개 시각은 파일과 `manifest.json`에 있다.

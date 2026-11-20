# 라이선스

[English](LICENSING.md)

이 문서는 참고용 번역입니다. 영어본과 차이가 있으면 영어본이 우선합니다.

Copyright (C) 2026 JC-Lab

bomcensus는 이중 라이선스로 제공됩니다. 아래 둘 중 하나를 선택해 사용할 수 있습니다.

## 1. GNU AGPL v3

bomcensus는 GNU Affero General Public License 버전 3(`AGPL-3.0-only`)으로 제공됩니다. 전문은 [LICENSE](LICENSE)에 있습니다. AGPL의 이후 버전은 적용되지 않습니다.

요약하면, bomcensus 또는 이를 기반으로 한 저작물을 배포할 때는 그 저작물의 소스를 같은 라이선스로 제공해야 합니다. bomcensus를 수정해 네트워크로 사용자에게 제공할 때는 그 사용자에게 수정본의 소스를 제공해야 합니다. 효력이 있는 것은 라이선스 전문이며 이 요약이 아닙니다.

### 제7조에 따른 추가 조건

AGPL 제7조가 허용하는 범위에서 bomcensus에는 다음 조건이 추가로 적용됩니다.

- **상표 (제7조 (e)).** 이 라이선스는 bomcensus 이름과 로고, 그 밖에 JC-Lab의 상호·상표·서비스표를 사용할 권리를 부여하지 않습니다. [상표](#상표)를 참고하십시오.
- **수정본 (제7조 (c)).** 수정본은 출처를 사실과 다르게 표시해서는 안 됩니다. 원본과 다르다는 점을 표시해야 하며, bomcensus라는 이름이나 브랜드로 제공해서는 안 됩니다.

## 2. 상용 라이선스

AGPL 조건을 따를 수 없는 경우를 위해 JC-Lab이 상용 라이선스를 제공합니다. 대표적인 경우는 다음과 같습니다.

- bomcensus의 전부 또는 일부를 비공개 제품에 엔진으로 포함하는 경우
- bomcensus 구성 요소(server, agent, probe, scanner)를 제품에 포함해 배포하면서 제품 소스를 공개하지 않는 경우
- 수정한 bomcensus를 서비스로 운영하면서 수정 내용을 공개하지 않는 경우

상용 라이선스는 JC-Lab과 별도로 체결하는 서면 계약입니다. 계약을 체결한 이용자에게는 AGPL 대신 그 계약 조건이 적용됩니다.

문의: joseph@jc-lab.net

## 적용되는 라이선스

JC-Lab과 체결한 상용 라이선스 계약이 없다면 bomcensus의 사용에는 `AGPL-3.0-only`와 위 추가 조건이 적용됩니다.

소스 파일에는 `SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial`을 표기합니다. 두 번째 식별자는 위에서 설명한 상용 라이선스를 가리키며 [LICENSES/LicenseRef-bomcensus-Commercial.txt](LICENSES/LicenseRef-bomcensus-Commercial.txt)에 정의되어 있습니다. 계약을 체결한 경우에만 적용됩니다.

## 상표

"bomcensus"와 bomcensus 로고(이하 "상표")는 JC-Lab의 상표입니다. AGPL과 상용 라이선스 어느 쪽도 상표를 사용할 권리를 부여하지 않습니다. 상용 라이선스 계약서에 명시한 경우만 예외입니다.

서면 허락 없이 할 수 없는 것:

- 상표 또는 혼동을 일으킬 만큼 유사한 표지를 제품, 서비스, 회사, 프로젝트, 패키지, 도메인, 계정의 이름에 사용하는 것
- 수정본을 상표를 붙여 배포하거나 운영하는 것. 수정본은 다른 이름을 써야 하고, UI·문서·홍보물에서 bomcensus 로고와 브랜드를 제거해야 합니다.
- JC-Lab이 귀하의 제품이나 서비스를 보증·후원하거나 그와 제휴한 것처럼 보이게 상표를 사용하는 것
- 용도를 불문하고 bomcensus 로고를 사용하는 것

허용되는 것:

- "bomcensus와 호환", "bomcensus 기반"처럼 사실을 설명하기 위해 일반 텍스트로 이름을 언급하는 것. 이때 이름을 자사 제품명보다 두드러지게 표시해서는 안 됩니다.
- 수정하지 않은 공식 릴리스를 bomcensus라고 밝히고 재배포하는 것
- 기존 연동이 의존하는 기술적 식별자(import 경로, 바이너리·파일 이름, 프로토콜·설정 키)를 그대로 두는 것

상용 라이선스로 bomcensus를 포함한 제품은 계약에서 허용하지 않는 한 상표를 사용할 수 없습니다("powered by" 표기 포함).

## 서드파티 구성 요소

bomcensus에 포함된 서드파티 구성 요소에는 각자의 라이선스가 적용됩니다.

## 기여

기여는 [기여자 라이선스 계약](https://gist.github.com/jclab-joseph/9ff42dd5f6afb4074fccd15ced478b3d)에 따라 받습니다. [CONTRIBUTING.ko.md](CONTRIBUTING.ko.md)를 참고하십시오.

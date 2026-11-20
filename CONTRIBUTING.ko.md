# 기여 안내

[English](CONTRIBUTING.md)

## 기여자 라이선스 계약

bomcensus는 AGPL-3.0-only와 상용 라이선스의 이중 라이선스로 제공됩니다([LICENSING.ko.md](LICENSING.ko.md) 참고). 두 라이선스로 모두 제공하려면 JC-Lab이 모든 기여물에 대한 이용허락을 받아야 합니다. 풀 리퀘스트는 작성자가 [기여자 라이선스 계약](https://gist.github.com/jclab-joseph/9ff42dd5f6afb4074fccd15ced478b3d)에 서명한 뒤에만 병합됩니다.

- 풀 리퀘스트를 열면 CLA assistant가 링크가 담긴 댓글을 남깁니다. 그 링크에서 GitHub 계정으로 서명합니다.
- 한 번 서명하면 이후 풀 리퀘스트에도 적용됩니다. CLA 내용이 바뀌면 새 버전에 다시 서명해야 합니다.
- 업무의 일부로 기여한다면 서명 전에 회사가 허용하는지 확인하십시오. CLA 제6조를 참고하십시오.
- 풀 리퀘스트에 포함된 커밋의 작성자 모두가 서명해야 합니다.

## 라이선스 헤더

모든 소스 파일은 아래 헤더로 시작합니다. 주석 문법은 해당 언어에 맞추고, 연도는 파일을 만든 해로 적습니다.

```go
// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.
```

생성 코드는 예외입니다.

## 서드파티 코드와 의존성

bomcensus에 들어가는 모든 것은 AGPL-3.0-only와 상용 라이선스 양쪽으로 배포할 수 있어야 합니다.

- 허용: MIT, BSD-2-Clause, BSD-3-Clause, ISC, Apache-2.0, MPL-2.0(수정하지 않은 경우)
- 불가: GPL, AGPL, LGPL, SSPL, BUSL, 상업적 이용을 제한하는 라이선스
- 그 밖의 라이선스는 의존성을 추가하기 전에 이슈로 먼저 문의하십시오.

다른 프로젝트의 코드는 라이선스가 허용 목록에 있을 때만 가져올 수 있습니다. 가져온 경우 풀 리퀘스트에 출처와 라이선스를 밝히고 원래의 저작권 표시를 유지하십시오.

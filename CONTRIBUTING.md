# Contributing

[한국어](CONTRIBUTING.ko.md)

## Contributor License Agreement

bomcensus is dual-licensed under the AGPL-3.0-only and a commercial license (see [LICENSING.md](LICENSING.md)). To offer both, JC-Lab needs a license to every contribution. A pull request can be merged only after its authors have signed the [Contributor License Agreement](https://gist.github.com/jclab-joseph/9ff42dd5f6afb4074fccd15ced478b3d).

- When you open a pull request, CLA assistant comments on it with a link. Sign with your GitHub account from there.
- A signature covers your later pull requests as well. If the CLA text changes, you will be asked to sign the new version.
- If you contribute as part of your job, make sure your employer allows it before signing. See section 6 of the CLA.
- Every author of the commits in a pull request must sign.

## License headers

Every source file starts with this header, using the comment syntax of its language. Use the year the file was created.

```go
// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.
```

Generated code is exempt.

## Third-party code and dependencies

Everything in bomcensus must be distributable under both the AGPL-3.0-only and a commercial license.

- Accepted: MIT, BSD-2-Clause, BSD-3-Clause, ISC, Apache-2.0, and MPL-2.0 (unmodified).
- Not accepted: GPL, AGPL, LGPL, SSPL, BUSL, and any license that restricts commercial use.
- For any other license, open an issue before adding the dependency.

Do not copy code from other projects into a contribution unless its license is on the accepted list. When you do, state the source and license in the pull request and keep the original copyright notice.

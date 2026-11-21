// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package testhook connects package sign with its test helper package.
// Being internal to internal/sign, it can only be imported by sign itself
// and by internal/sign/signtest.
package testhook

// SetTrust replaces the compiled-in trust values and returns a function that
// restores the previous ones. Package sign assigns it during initialization.
var SetTrust func(releaseKeys, codeSigningRoots string) (restore func())

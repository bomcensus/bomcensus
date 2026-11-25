// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package session is the built-in console login: the password provider of
// the configured user, cookie sessions, the CSRF check of cookie
// authenticated requests and the login throttle.
//
// It puts an auth.Principal into the request context; handlers and
// services read the caller only from there (auth.FromContext).
package session

import "context"

type sessionKey struct{}

func withSessionID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, sessionKey{}, id)
}

func sessionIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(sessionKey{}).(string)
	return id
}

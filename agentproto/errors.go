// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package agentproto

import (
	"errors"
	"fmt"
	"time"
)

// Error codes the agent acts on (docs/PROTOCOL.md §6).
const (
	CodeInvalidRequest     = "invalid_request"
	CodeUnauthorized       = "unauthorized"
	CodeAgentRevoked       = "agent_revoked"
	CodeAgentPending       = "agent_pending"
	CodeClientCertMismatch = "client_certificate_mismatch"
	CodeCounterReplayed    = "counter_replayed"
	CodeBodyTooLarge       = "body_too_large"
	CodeForbidden          = "forbidden"
	CodeEnrollmentRefused  = "enrollment_refused"
	CodeRateLimited        = "rate_limited"
	CodeNotFound           = "not_found"
	CodeUnavailable        = "unavailable"
	CodeInternal           = "internal_error"
)

// Error is an answer of the server other than success.
//
// Status classifies it with the HTTP status numbers the protocol is
// defined with (400 invalid request, 401 unknown agent or bad signature,
// 403 refused, 404 not found, 409 counter replayed, 413 too large, 429 rate
// limited, 500 internal, 503 unavailable). A channel that is not HTTP
// carries Status, Code and Message unchanged; the agent's retry and
// recovery decisions depend on them.
//
// A channel returns an Error only for an answer it authenticated (except
// for the downloads, whose content authenticates itself); an answer it
// cannot authenticate is a transport error.
type Error struct {
	Status  int
	Code    string
	Message string
	// RetryAfter is set on rate-limited answers.
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("server returned status %d", e.Status)
	}
	return fmt.Sprintf("server returned status %d (%s): %s", e.Status, e.Code, e.Message)
}

// Errorf returns an Error.
func Errorf(status int, code, format string, args ...any) *Error {
	return &Error{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

// AsError returns the Error in err's chain.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// IsStatus reports whether err is an Error with status.
func IsStatus(err error, status int) bool {
	e, ok := AsError(err)
	return ok && e.Status == status
}

// IsCode reports whether err is an Error with code.
func IsCode(err error, code string) bool {
	e, ok := AsError(err)
	return ok && e.Code == code
}

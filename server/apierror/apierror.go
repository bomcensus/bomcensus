// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package apierror writes errors in the format of the admin API
// ({"code": ..., "message": ...}), for middleware and mounted handlers that
// answer API clients themselves.
package apierror

import (
	"net/http"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/apierr"
)

// Error codes of the admin API.
const (
	CodeInvalidArgument = apierr.CodeInvalidArgument
	CodeUnauthenticated = apierr.CodeUnauthenticated
	CodeForbidden       = apierr.CodeForbidden
	CodeNotFound        = apierr.CodeNotFound
	CodeTooManyRequests = apierr.CodeTooManyRequests
	CodeUnavailable     = apierr.CodeUnavailable
	CodeInternal        = apierr.CodeInternal
)

// Write writes an error response.
func Write(w http.ResponseWriter, status int, code, message string) {
	apierr.Write(w, status, gen.Error{Code: code, Message: message})
}

// Unauthenticated writes 401 with CodeUnauthenticated.
func Unauthenticated(w http.ResponseWriter, message string) {
	Write(w, http.StatusUnauthorized, CodeUnauthenticated, message)
}

// Forbidden writes 403 with CodeForbidden.
func Forbidden(w http.ResponseWriter, message string) {
	Write(w, http.StatusForbidden, CodeForbidden, message)
}

// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package apierr maps errors of the console API handlers to HTTP statuses and
// the common error body {code, message}. Handlers return either an *Error or
// a store error; the router renders it with From and Write.
package apierr

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/server/scope"
)

// Stable error codes.
const (
	CodeInvalidArgument = "invalid_argument"
	CodeUnauthenticated = "unauthenticated"
	CodeForbidden       = "forbidden"
	CodeNotFound        = "not_found"
	CodeMethod          = "method_not_allowed"
	CodeConflict        = "conflict"
	CodeInUse           = "in_use"
	CodeInvalidState    = "invalid_state"
	CodeTooLarge        = "payload_too_large"
	CodeTooManyRequests = "too_many_requests"
	CodeUnavailable     = "unavailable"
	CodeInternal        = "internal"
)

// Error is an error with the status and body the client sees. Err is the
// cause; it is logged but never sent.
type Error struct {
	Status  int
	Code    string
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// New returns an Error with a fixed message.
func New(status int, code, message string) *Error {
	return &Error{Status: status, Code: code, Message: message}
}

// Invalid is a 400 with a formatted message.
func Invalid(format string, args ...any) *Error {
	return New(http.StatusBadRequest, CodeInvalidArgument, fmt.Sprintf(format, args...))
}

// NotFound is a 404 for the named kind of record ("asset", "cluster").
func NotFound(what string) *Error {
	return New(http.StatusNotFound, CodeNotFound, what+" not found")
}

// Conflict is a 409 with a message.
func Conflict(message string) *Error {
	return New(http.StatusConflict, CodeConflict, message)
}

// Unauthenticated is a 401.
func Unauthenticated(message string) *Error {
	return New(http.StatusUnauthorized, CodeUnauthenticated, message)
}

// Forbidden is a 403.
func Forbidden(message string) *Error {
	return New(http.StatusForbidden, CodeForbidden, message)
}

// Unavailable is a 503 for a function that is not configured or not running.
func Unavailable(message string) *Error {
	return New(http.StatusServiceUnavailable, CodeUnavailable, message)
}

// Wrap attaches a cause to e and returns it.
func (e *Error) Wrap(err error) *Error {
	c := *e
	c.Err = err
	return &c
}

// From returns the status and body for err. Store errors map as follows:
// ErrNotFound 404, ErrInvalid 400, ErrConflict, ErrInUse and ErrInvalidState
// 409. Data scope errors: scope.ErrOutside 403, scope.ErrInvalidID 400;
// scope.ErrNone (a missing scope, a bug) is 500. A request body over its
// limit is 413. Anything else is 500 with a generic message.
func From(err error) (int, gen.Error) {
	var e *Error
	if errors.As(err, &e) {
		return e.Status, gen.Error{Code: e.Code, Message: e.Message}
	}
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		return http.StatusRequestEntityTooLarge, gen.Error{Code: CodeTooLarge, Message: "request body too large"}
	case errors.Is(err, scope.ErrOutside):
		return http.StatusForbidden, gen.Error{Code: CodeForbidden, Message: "outside the data scope of the request"}
	case errors.Is(err, scope.ErrInvalidID):
		return http.StatusBadRequest, gen.Error{Code: CodeInvalidArgument, Message: "invalid scope id"}
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, gen.Error{Code: CodeNotFound, Message: "not found"}
	case errors.Is(err, store.ErrInvalid):
		return http.StatusBadRequest, gen.Error{Code: CodeInvalidArgument, Message: "invalid value"}
	case errors.Is(err, store.ErrConflict):
		return http.StatusConflict, gen.Error{Code: CodeConflict, Message: "conflicts with an existing record"}
	case errors.Is(err, store.ErrInUse):
		return http.StatusConflict, gen.Error{Code: CodeInUse, Message: "still in use"}
	case errors.Is(err, store.ErrInvalidState):
		return http.StatusConflict, gen.Error{Code: CodeInvalidState, Message: "not possible in the current state"}
	}
	return http.StatusInternalServerError, gen.Error{Code: CodeInternal, Message: "internal error"}
}

// Write sends body as JSON with status.
func Write(w http.ResponseWriter, status int, body gen.Error) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Render writes err as From maps it and returns the status.
func Render(w http.ResponseWriter, err error) int {
	status, body := From(err)
	Write(w, status, body)
	return status
}

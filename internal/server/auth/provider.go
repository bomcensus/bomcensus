// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

// ErrInvalidCredentials is returned when a username and password do not
// match a user.
var ErrInvalidCredentials = errors.New("auth: invalid credentials")

// Provider is where users come from. The only implementation now is the
// single user from the environment; database accounts or OIDC would be
// further implementations.
type Provider interface {
	// Authenticate returns the principal for the credentials or
	// ErrInvalidCredentials.
	Authenticate(ctx context.Context, username, password string) (Principal, error)
}

// Environment variables of the single console user.
const (
	EnvAdminUser         = "BOMCENSUS_ADMIN_USER"
	EnvAdminPasswordHash = "BOMCENSUS_ADMIN_PASSWORD_HASH"
)

// maxConcurrentHashes bounds the memory used by argon2 when many logins
// arrive at once.
const maxConcurrentHashes = 2

// EnvProvider authenticates the one user configured through the
// environment.
type EnvProvider struct {
	user string
	hash *passwordHash // nil: login disabled
	sem  chan struct{}
}

// NewEnvProvider returns the provider for user with passwordHash, an argon2id
// PHC string. When either is empty every login fails and a warning is
// logged. A hash in any other form is an error.
func NewEnvProvider(logger *slog.Logger, user, passwordHash string) (*EnvProvider, error) {
	p := &EnvProvider{sem: make(chan struct{}, maxConcurrentHashes)}
	if user == "" || passwordHash == "" {
		if logger != nil {
			logger.Warn("console login is disabled: " + EnvAdminUser + " and " + EnvAdminPasswordHash + " must both be set")
		}
		return p, nil
	}
	h, err := parsePasswordHash(passwordHash)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (create one with bomcensus-server hash-password)", EnvAdminPasswordHash, err)
	}
	p.user, p.hash = user, h
	return p, nil
}

// EnvProviderFromEnviron reads the user from the process environment.
func EnvProviderFromEnviron(logger *slog.Logger) (*EnvProvider, error) {
	return NewEnvProvider(logger, os.Getenv(EnvAdminUser), os.Getenv(EnvAdminPasswordHash))
}

// Enabled reports whether a user is configured.
func (p *EnvProvider) Enabled() bool { return p.hash != nil }

// Authenticate implements Provider. The password hash is computed whether or
// not the username matches, and both comparisons take constant time, so the
// response time does not reveal the username.
func (p *EnvProvider) Authenticate(ctx context.Context, username, password string) (Principal, error) {
	if p.hash == nil {
		return Principal{}, ErrInvalidCredentials
	}
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return Principal{}, ctx.Err()
	}
	passOK := p.hash.verify(password)
	<-p.sem
	got, want := sha256.Sum256([]byte(username)), sha256.Sum256([]byte(p.user))
	userOK := subtle.ConstantTimeCompare(got[:], want[:]) == 1
	if !passOK || !userOK {
		return Principal{}, ErrInvalidCredentials
	}
	return Principal{ID: "env:" + p.user, Name: p.user}, nil
}

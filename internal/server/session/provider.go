// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package session

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"os"

	"github.com/bomcensus/bomcensus/server/auth"
)

// ErrInvalidCredentials is auth.ErrInvalidCredentials.
var ErrInvalidCredentials = auth.ErrInvalidCredentials

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

// Authenticate implements auth.PasswordProvider. The password hash is computed whether or
// not the username matches, and both comparisons take constant time, so the
// response time does not reveal the username.
func (p *EnvProvider) Authenticate(ctx context.Context, username, password string) (auth.Principal, error) {
	if p.hash == nil {
		return nil, ErrInvalidCredentials
	}
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	passOK := p.hash.verify(password)
	<-p.sem
	got, want := sha256.Sum256([]byte(username)), sha256.Sum256([]byte(p.user))
	userOK := subtle.ConstantTimeCompare(got[:], want[:]) == 1
	if !passOK || !userOK {
		return nil, ErrInvalidCredentials
	}
	return auth.User{UserID: "env:" + p.user, UserName: p.user}, nil
}

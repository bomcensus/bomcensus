// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package store

import (
	"context"
	"io"
	"time"
)

// ReleaseSource tells how the server obtained a release.
type ReleaseSource string

const (
	ReleaseOnline ReleaseSource = "online"
	ReleaseUpload ReleaseSource = "upload"
)

// MaxReleaseFileSize bounds a single release file.
const MaxReleaseFileSize = 256 << 20

// DefaultUpdateCheckIntervalMinutes applies until update settings are saved.
const DefaultUpdateCheckIntervalMinutes = 60

// Release is a signed release manifest.
type Release struct {
	Version     string
	Manifest    []byte
	Signature   []byte
	PublishedAt time.Time
	Source      ReleaseSource
	Verified    bool
	Notes       string
	CreatedAt   time.Time
}

// ReleaseFile is one file of a release, identified by version, OS,
// architecture and name.
type ReleaseFile struct {
	Version string
	OS      string
	Arch    string
	Name    string
	SHA256  []byte
	Size    int64
}

// UpdateSettings is the deployed version and how often agents ask for it.
type UpdateSettings struct {
	TargetVersion        string // empty means none
	CheckIntervalMinutes int
}

// Releases stores release manifests, their files and the update settings.
type Releases interface {
	// CreateRelease stores r. CreatedAt defaults to now. ErrConflict when
	// the version exists.
	CreateRelease(ctx context.Context, r Release) (Release, error)
	GetRelease(ctx context.Context, version string) (Release, error)
	// ListReleases returns releases, most recently published first.
	ListReleases(ctx context.Context) ([]Release, error)
	// DeleteRelease removes a release and its files. ErrInUse while it is
	// the target version.
	DeleteRelease(ctx context.Context, version string) error

	// PutReleaseFile streams content into the store in bounded memory. The
	// store computes size and SHA-256; when f.SHA256 or f.Size are set they
	// must match or the write fails with ErrInvalid. Files are immutable:
	// ErrConflict when the file exists, ErrNotFound when the release does
	// not. The write is atomic; within WithTx it joins that transaction.
	PutReleaseFile(ctx context.Context, f ReleaseFile, content io.Reader) (ReleaseFile, error)
	// ListReleaseFiles returns the files of a release ordered by OS, arch
	// and name.
	ListReleaseFiles(ctx context.Context, version string) ([]ReleaseFile, error)
	// OpenReleaseFile returns the file metadata and a reader of its content
	// that loads it piece by piece. The reader verifies size and SHA-256 and
	// returns an error instead of io.EOF on mismatch. When opened inside
	// WithTx it must be drained before the transaction ends.
	OpenReleaseFile(ctx context.Context, version, os, arch, name string) (ReleaseFile, io.ReadCloser, error)

	// GetUpdateSettings returns the stored settings, or no target version
	// and DefaultUpdateCheckIntervalMinutes when never saved.
	GetUpdateSettings(ctx context.Context) (UpdateSettings, error)
	// PutUpdateSettings stores s. ErrNotFound when the target version is not
	// a stored release, ErrInvalid when the interval is not positive.
	PutUpdateSettings(ctx context.Context, s UpdateSettings) error
}

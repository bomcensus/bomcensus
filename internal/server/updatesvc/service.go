// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package updatesvc stores verified release bundles and serves them to
// agents and scanners: per-platform bundles for self-update, probe binaries
// for agentless collection, and the deployed version.
//
// A release is stored only after release.Open has verified it completely
// (manifest signature and validity, file hashes, code signatures). What is
// served later is the stored manifest, signature and files, which the store
// checks against their recorded SHA-256 on every read; the updater and the
// scanner verify everything again before use.
package updatesvc

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/release"
	"github.com/bomcensus/bomcensus/internal/server/store"
	"github.com/bomcensus/bomcensus/internal/sign"
)

// ProbeName is the file name of the probe inside a release.
const ProbeName = "bomcensus-probe"

// MaxCheckIntervalMinutes bounds the update check interval (one week).
const MaxCheckIntervalMinutes = 7 * 24 * 60

// Errors returned by the service.
var (
	// ErrVerification wraps the reason a bundle was rejected.
	ErrVerification = errors.New("updatesvc: release verification failed")
	// ErrExists means the release, with every platform in the bundle, is
	// already stored.
	ErrExists = errors.New("updatesvc: release already imported")
	// ErrInvalid wraps rejected settings.
	ErrInvalid = errors.New("updatesvc: invalid settings")
)

// Store is what the service needs from the database.
type Store interface {
	store.Releases
	WithTx(ctx context.Context, fn func(store.Store) error) error
}

// Config configures a Service.
type Config struct {
	Store  Store
	Logger *slog.Logger
	// Now is the clock used for manifest validity. Default time.Now.
	Now func() time.Time
}

// Service imports and serves releases.
type Service struct {
	st  Store
	log *slog.Logger
	now func() time.Time
}

// New returns a Service.
func New(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("updatesvc: store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Service{st: cfg.Store, log: cfg.Logger, now: cfg.Now}, nil
}

// Release is a stored release with the platforms it has files for.
type Release struct {
	store.Release
	Platforms []release.Platform
}

// Import verifies a bundle read from r and stores it. A bundle of a version
// that is already stored with the same manifest adds the platforms that are
// missing; when nothing is missing the result is ErrExists. A bundle of a
// stored version with another manifest is store.ErrConflict.
func (s *Service) Import(ctx context.Context, r io.Reader, source store.ReleaseSource) (Release, error) {
	b, err := release.Open(ctx, r, s.now())
	if err != nil {
		if ctx.Err() != nil {
			return Release{}, ctx.Err()
		}
		return Release{}, fmt.Errorf("%w: %w", ErrVerification, err)
	}
	m := b.Manifest()
	version := b.Version()
	added := 0
	err = s.st.WithTx(ctx, func(tx store.Store) error {
		existing, err := tx.GetRelease(ctx, version)
		switch {
		case errors.Is(err, store.ErrNotFound):
			if _, err := tx.CreateRelease(ctx, store.Release{
				Version:     version,
				Manifest:    b.ManifestBytes(),
				Signature:   b.Signature(),
				PublishedAt: m.IssuedAt,
				Source:      source,
				Verified:    true,
			}); err != nil {
				return err
			}
		case err != nil:
			return err
		case !bytes.Equal(existing.Manifest, b.ManifestBytes()):
			return fmt.Errorf("updatesvc: version %s is stored with a different manifest: %w", version, store.ErrConflict)
		}
		have, err := tx.ListReleaseFiles(ctx, version)
		if err != nil {
			return err
		}
		for _, p := range b.Platforms() {
			if slices.ContainsFunc(have, func(f store.ReleaseFile) bool { return f.OS == p.OS && f.Arch == p.Arch }) {
				continue
			}
			for _, f := range b.Files(p.OS, p.Arch) {
				e, _ := m.Lookup(f.OS, f.Arch, f.Name)
				sum, err := e.Digest()
				if err != nil {
					return err
				}
				if _, err := tx.PutReleaseFile(ctx, store.ReleaseFile{
					Version: version, OS: f.OS, Arch: f.Arch, Name: f.Name, SHA256: sum[:], Size: e.Size,
				}, bytes.NewReader(f.Data)); err != nil {
					return err
				}
			}
			added++
		}
		if added == 0 {
			return ErrExists
		}
		return nil
	})
	if err != nil {
		return Release{}, err
	}
	s.log.Info("release imported", "version", version, "source", source, "platforms", added)
	return s.Get(ctx, version)
}

// ImportDir imports every *.tar file in dir. Bundles that are already
// stored are skipped; bundles that fail verification are logged and
// skipped. Only a failure to read the directory is returned.
func (s *Service) ImportDir(ctx context.Context, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("updatesvc: read release directory: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			s.log.Warn("cannot open release bundle", "path", path, "err", err)
			continue
		}
		_, err = s.Import(ctx, f, store.ReleaseUpload)
		f.Close()
		switch {
		case err == nil, errors.Is(err, ErrExists):
		case ctx.Err() != nil:
			return ctx.Err()
		default:
			s.log.Warn("release bundle rejected", "path", path, "err", err)
		}
	}
	return nil
}

func (s *Service) platforms(ctx context.Context, version string) ([]release.Platform, []store.ReleaseFile, error) {
	files, err := s.st.ListReleaseFiles(ctx, version)
	if err != nil {
		return nil, nil, err
	}
	var out []release.Platform
	for _, f := range files {
		p := release.Platform{OS: f.OS, Arch: f.Arch}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, files, nil
}

// Get returns one release.
func (s *Service) Get(ctx context.Context, version string) (Release, error) {
	r, err := s.st.GetRelease(ctx, version)
	if err != nil {
		return Release{}, err
	}
	p, _, err := s.platforms(ctx, version)
	if err != nil {
		return Release{}, err
	}
	return Release{Release: r, Platforms: p}, nil
}

// List returns all releases, most recently published first.
func (s *Service) List(ctx context.Context) ([]Release, error) {
	rs, err := s.st.ListReleases(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Release, 0, len(rs))
	for _, r := range rs {
		p, _, err := s.platforms(ctx, r.Version)
		if err != nil {
			return nil, err
		}
		out = append(out, Release{Release: r, Platforms: p})
	}
	return out, nil
}

func platformFiles(files []store.ReleaseFile, os, arch string) []store.ReleaseFile {
	var out []store.ReleaseFile
	for _, f := range files {
		if f.OS == os && f.Arch == arch {
			out = append(out, f)
		}
	}
	return out
}

// tarSize is the size of a tar archive written by archive/tar in USTAR
// format with entries of the given sizes.
func tarSize(sizes ...int64) int64 {
	n := int64(1024) // end-of-archive marker
	for _, sz := range sizes {
		n += 512 + (sz+511)/512*512
	}
	return n
}

// Bundle streams a release bundle holding only the files of one platform,
// in the format of release.Write. The size is known in advance. The caller
// must close the reader; closing early stops the stream.
func (s *Service) Bundle(ctx context.Context, version, os, arch string) (io.ReadCloser, int64, error) {
	r, err := s.st.GetRelease(ctx, version)
	if err != nil {
		return nil, 0, err
	}
	all, err := s.st.ListReleaseFiles(ctx, version)
	if err != nil {
		return nil, 0, err
	}
	files := platformFiles(all, os, arch)
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("updatesvc: release %s has no files for %s-%s: %w", version, os, arch, store.ErrNotFound)
	}
	sizes := []int64{int64(len(r.Manifest)), int64(len(r.Signature))}
	for _, f := range files {
		sizes = append(sizes, f.Size)
	}
	size := tarSize(sizes...)

	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(s.writeBundle(ctx, pw, r, files))
	}()
	return pr, size, nil
}

func (s *Service) writeBundle(ctx context.Context, w io.Writer, r store.Release, files []store.ReleaseFile) error {
	tw := tar.NewWriter(w)
	epoch := time.Unix(0, 0)
	header := func(name string, mode, size int64) error {
		return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: mode, Size: size, ModTime: epoch, Format: tar.FormatUSTAR})
	}
	for _, e := range []struct {
		name string
		data []byte
	}{{release.ManifestName, r.Manifest}, {release.SignatureName, r.Signature}} {
		if err := header(e.name, 0o644, int64(len(e.data))); err != nil {
			return err
		}
		if _, err := tw.Write(e.data); err != nil {
			return err
		}
	}
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, rc, err := s.st.OpenReleaseFile(ctx, f.Version, f.OS, f.Arch, f.Name)
		if err != nil {
			return err
		}
		err = header(release.File{OS: f.OS, Arch: f.Arch, Name: f.Name}.Path(), 0o755, f.Size)
		if err == nil {
			_, err = io.Copy(tw, rc)
		}
		rc.Close()
		if err != nil {
			return fmt.Errorf("updatesvc: bundle %s: %w", f.Name, err)
		}
	}
	return tw.Close()
}

// Probe returns the probe binary for a platform and its version: the one of
// the deployed version when that release has the platform, otherwise the one
// of the newest release that has it.
func (s *Service) Probe(ctx context.Context, os, arch string) ([]byte, string, error) {
	version, err := s.probeVersion(ctx, os, arch)
	if err != nil {
		return nil, "", err
	}
	_, rc, err := s.st.OpenReleaseFile(ctx, version, os, arch, ProbeName)
	if err != nil {
		return nil, "", err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, store.MaxReleaseFileSize+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > store.MaxReleaseFileSize {
		return nil, "", errors.New("updatesvc: probe exceeds the file size limit")
	}
	return data, version, nil
}

func hasFile(files []store.ReleaseFile, os, arch, name string) bool {
	return slices.ContainsFunc(files, func(f store.ReleaseFile) bool { return f.OS == os && f.Arch == arch && f.Name == name })
}

func (s *Service) probeVersion(ctx context.Context, os, arch string) (string, error) {
	set, err := s.st.GetUpdateSettings(ctx)
	if err != nil {
		return "", err
	}
	if set.TargetVersion != "" {
		files, err := s.st.ListReleaseFiles(ctx, set.TargetVersion)
		if err != nil {
			return "", err
		}
		if hasFile(files, os, arch, ProbeName) {
			return set.TargetVersion, nil
		}
	}
	rs, err := s.st.ListReleases(ctx)
	if err != nil {
		return "", err
	}
	slices.SortFunc(rs, func(a, b store.Release) int { return compareVersions(b.Version, a.Version) })
	for _, r := range rs {
		if !r.Verified {
			continue
		}
		files, err := s.st.ListReleaseFiles(ctx, r.Version)
		if err != nil {
			return "", err
		}
		if hasFile(files, os, arch, ProbeName) {
			return r.Version, nil
		}
	}
	return "", fmt.Errorf("updatesvc: no release has a probe for %s-%s: %w", os, arch, store.ErrNotFound)
}

// compareVersions orders by semver precedence; versions that do not parse
// sort before those that do, then by string.
func compareVersions(a, b string) int {
	if c, err := sign.CompareVersions(a, b); err == nil {
		return c
	}
	va, vb := sign.ValidVersion(a), sign.ValidVersion(b)
	switch {
	case va && !vb:
		return 1
	case !va && vb:
		return -1
	}
	return strings.Compare(a, b)
}

// CompareVersions is the release ordering used by the service, exported for
// sorting release lists the same way.
func CompareVersions(a, b string) int { return compareVersions(a, b) }

// Settings returns the update settings.
func (s *Service) Settings(ctx context.Context) (store.UpdateSettings, error) {
	return s.st.GetUpdateSettings(ctx)
}

// SetSettings stores the update settings. The target version, when set,
// must be a stored, verified release; the interval must be between 1 and
// MaxCheckIntervalMinutes.
func (s *Service) SetSettings(ctx context.Context, set store.UpdateSettings) error {
	if set.CheckIntervalMinutes < 1 || set.CheckIntervalMinutes > MaxCheckIntervalMinutes {
		return fmt.Errorf("%w: check interval must be between 1 and %d minutes", ErrInvalid, MaxCheckIntervalMinutes)
	}
	if set.TargetVersion != "" {
		r, err := s.st.GetRelease(ctx, set.TargetVersion)
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: release %s is not imported", ErrInvalid, set.TargetVersion)
		}
		if err != nil {
			return err
		}
		if !r.Verified {
			return fmt.Errorf("%w: release %s is not verified", ErrInvalid, set.TargetVersion)
		}
	}
	old, err := s.st.GetUpdateSettings(ctx)
	if err != nil {
		return err
	}
	if err := s.st.PutUpdateSettings(ctx, set); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: release %s is not imported", ErrInvalid, set.TargetVersion)
		}
		return err
	}
	if old.TargetVersion != set.TargetVersion {
		s.log.Info("deployed version changed", "from", old.TargetVersion, "to", set.TargetVersion)
	}
	return nil
}

// Check is what an agent's update check returns.
type Check struct {
	// TargetVersion is the deployed version; empty when none is deployed.
	TargetVersion        string
	CheckIntervalMinutes int
	// The fields below are set when the deployed release has files for the
	// caller's platform.
	Manifest   []byte
	Signature  []byte
	Files      []store.ReleaseFile
	BundleSize int64
	// Newer is true when TargetVersion is newer than the caller's version.
	// Agents never downgrade (SECURITY.md §5.1).
	Newer bool
}

// Check answers an agent's update check.
func (s *Service) Check(ctx context.Context, currentVersion, os, arch string) (Check, error) {
	set, err := s.st.GetUpdateSettings(ctx)
	if err != nil {
		return Check{}, err
	}
	out := Check{TargetVersion: set.TargetVersion, CheckIntervalMinutes: set.CheckIntervalMinutes}
	if set.TargetVersion == "" {
		return out, nil
	}
	r, err := s.st.GetRelease(ctx, set.TargetVersion)
	if err != nil {
		return Check{}, err
	}
	all, err := s.st.ListReleaseFiles(ctx, set.TargetVersion)
	if err != nil {
		return Check{}, err
	}
	files := platformFiles(all, os, arch)
	if len(files) == 0 {
		return out, nil
	}
	sizes := []int64{int64(len(r.Manifest)), int64(len(r.Signature))}
	for _, f := range files {
		sizes = append(sizes, f.Size)
	}
	out.Manifest, out.Signature, out.Files = r.Manifest, r.Signature, files
	out.BundleSize = tarSize(sizes...)
	out.Newer = sign.Newer(set.TargetVersion, currentVersion)
	return out, nil
}

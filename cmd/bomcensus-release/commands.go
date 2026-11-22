// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bomcensus/bomcensus/internal/release"
	"github.com/bomcensus/bomcensus/internal/sign"
)

// Linker paths of the trust variables in package sign.
const (
	ldflagReleaseKeys      = "github.com/bomcensus/bomcensus/internal/sign.releaseKeys"
	ldflagCodeSigningRoots = "github.com/bomcensus/bomcensus/internal/sign.codeSigningRoots"
)

// Files written by keygen.
const (
	fileManifestKey = "manifest.key"
	fileManifestPub = "manifest.pub"
	fileCACert      = "codesign-ca.crt"
	fileCAKey       = "codesign-ca.key"
	fileCodeCert    = "codesign.crt"
	fileCodeKey     = "codesign.key"
)

func runKeygen(_ context.Context, args []string, stdout io.Writer) error {
	fs := newFlagSet("keygen", "--out DIR [flags]")
	out := fs.String("out", "", "directory to write the keys to (created if missing)")
	name := fs.String("name", "bomcensus", "common name prefix of the certificates")
	caValidity := fs.Duration("ca-validity", 10*365*24*time.Hour, "validity of the code-signing CA")
	certValidity := fs.Duration("cert-validity", 3*365*24*time.Hour, "validity of the code-signing certificate")
	force := fs.Bool("force", false, "overwrite existing files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		fs.Usage()
		return errors.New("keygen: --out is required")
	}
	if *certValidity > *caValidity {
		return errors.New("keygen: certificate validity exceeds CA validity")
	}
	names := []string{fileManifestKey, fileManifestPub, fileCACert, fileCAKey, fileCodeCert, fileCodeKey}
	if !*force {
		for _, n := range names {
			if _, err := os.Lstat(filepath.Join(*out, n)); err == nil {
				return fmt.Errorf("keygen: %s already exists (use --force to overwrite)", filepath.Join(*out, n))
			}
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	now := time.Now().Add(-time.Minute)
	ca, caKey, err := sign.NewCodeSigningCA(*name+" code signing CA", now, now.Add(*caValidity))
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	leaf, leafKey, err := sign.NewCodeSigningCert(ca, caKey, *name+" code signing", now, now.Add(*certValidity))
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}

	privPEM, err := encodePrivateKey(priv)
	if err != nil {
		return err
	}
	pubPEM, err := encodePublicKey(pub)
	if err != nil {
		return err
	}
	caKeyPEM, err := encodePrivateKey(caKey)
	if err != nil {
		return err
	}
	leafKeyPEM, err := encodePrivateKey(leafKey)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	writes := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{fileManifestKey, privPEM, 0o600},
		{fileManifestPub, pubPEM, 0o644},
		{fileCAKey, caKeyPEM, 0o600},
		{fileCACert, encodeCertificates(ca), 0o644},
		{fileCodeKey, leafKeyPEM, 0o600},
		{fileCodeCert, encodeCertificates(leaf), 0o644},
	}
	for _, w := range writes {
		if err := writeFileAtomic(filepath.Join(*out, w.name), w.data, w.mode); err != nil {
			return fmt.Errorf("keygen: %w", err)
		}
	}
	fmt.Fprintf(stdout, "wrote %s to %s\n", strings.Join(names, ", "), *out)
	return nil
}

func runSignELF(ctx context.Context, args []string, stdout io.Writer) error {
	return runSign(ctx, "sign-elf", sign.SignELF, args, stdout)
}

func runSignPE(ctx context.Context, args []string, stdout io.Writer) error {
	return runSign(ctx, "sign-pe", sign.SignPE, args, stdout)
}

// runSign signs files in place with signFile (AuthentiELF or Authenticode).
func runSign(ctx context.Context, name string, signFile func(context.Context, []byte, *sign.CodeSigner) ([]byte, error), args []string, stdout io.Writer) error {
	fs := newFlagSet(name, "--key KEY --cert CERT [--timestamp-url URL] FILE...")
	keyFile := fs.String("key", "", "code-signing private key (PEM)")
	certFile := fs.String("cert", "", "code-signing certificate, optionally followed by intermediates (PEM)")
	tsURL := fs.String("timestamp-url", "", "RFC 3161 timestamp authority URL (optional)")
	program := fs.String("program-name", "bomcensus", "program name recorded in the signature")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || *certFile == "" || fs.NArg() == 0 {
		fs.Usage()
		return fmt.Errorf("%s: --key, --cert and at least one file are required", name)
	}
	key, err := readSigner(*keyFile)
	if err != nil {
		return err
	}
	certs, err := readCertificates(*certFile)
	if err != nil {
		return err
	}
	signer := &sign.CodeSigner{
		Key:           key,
		Certificate:   certs[0],
		Intermediates: certs[1:],
		TimestampURL:  *tsURL,
		ProgramName:   *program,
	}
	for _, path := range fs.Args() {
		if err := ctx.Err(); err != nil {
			return err
		}
		st, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if !st.Mode().IsRegular() {
			return fmt.Errorf("%s: %s is not a regular file", name, path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		signed, err := signFile(ctx, data, signer)
		if err != nil {
			return fmt.Errorf("%s: %s: %w", name, path, err)
		}
		if err := writeFileAtomic(path, signed, st.Mode().Perm()); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Fprintf(stdout, "signed %s\n", path)
	}
	return nil
}

func runBundle(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlagSet("bundle", "--version V --manifest-key KEY --dir BINDIR --out FILE")
	version := fs.String("version", "", "release version (semver)")
	keyFile := fs.String("manifest-key", "", "Ed25519 manifest private key: PEM file, or gcp-kms://<CryptoKeyVersion> (token in $GOOGLE_OAUTH_ACCESS_TOKEN)")
	dir := fs.String("dir", "", "directory with <os>-<arch>/<binary> files")
	out := fs.String("out", "", "bundle file to write")
	validity := fs.Duration("validity", 365*24*time.Hour, "manifest validity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *version == "" || *keyFile == "" || *dir == "" || *out == "" || fs.NArg() != 0 {
		fs.Usage()
		return errors.New("bundle: --version, --manifest-key, --dir and --out are required")
	}
	if !sign.ValidVersion(*version) {
		return fmt.Errorf("bundle: %q is not a semver version", *version)
	}
	key, err := openManifestSigner(ctx, *keyFile)
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	files, err := collectFiles(*dir)
	if err != nil {
		return err
	}

	now := time.Now().UTC().Truncate(time.Second)
	m := &sign.Manifest{Version: *version, IssuedAt: now, ExpiresAt: now.Add(*validity)}
	for _, f := range files {
		sum := sha256.Sum256(f.Data)
		m.Files = append(m.Files, sign.File{
			OS: f.OS, Arch: f.Arch, Name: f.Name,
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(f.Data)),
		})
	}
	manifest, err := sign.EncodeManifest(m)
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	sig, err := key.Sign(nil, manifest, crypto.Hash(0))
	if err != nil {
		return fmt.Errorf("bundle: sign manifest: %w", err)
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), manifest, sig) {
		return errors.New("bundle: manifest signature does not verify")
	}
	var buf bytes.Buffer
	if err := release.Write(ctx, &buf, manifest, sig, files); err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	if err := writeFileAtomic(*out, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	fmt.Fprintf(stdout, "wrote %s (version %s, %d files)\n", *out, *version, len(files))
	return nil
}

// collectFiles reads dir/<os>-<arch>/<name> in a stable order.
func collectFiles(dir string) ([]release.File, error) {
	platforms, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	var files []release.File
	for _, p := range platforms {
		osName, arch, ok := strings.Cut(p.Name(), "-")
		if !p.IsDir() || !ok || !sign.ValidPlatformName(osName) || !sign.ValidPlatformName(arch) {
			return nil, fmt.Errorf("bundle: unexpected entry %s (want <os>-<arch> directories)", filepath.Join(dir, p.Name()))
		}
		entries, err := os.ReadDir(filepath.Join(dir, p.Name()))
		if err != nil {
			return nil, fmt.Errorf("bundle: %w", err)
		}
		for _, e := range entries {
			path := filepath.Join(dir, p.Name(), e.Name())
			if !e.Type().IsRegular() || !sign.ValidFileName(e.Name()) {
				return nil, fmt.Errorf("bundle: unexpected entry %s", path)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("bundle: %w", err)
			}
			files = append(files, release.File{OS: osName, Arch: arch, Name: e.Name(), Data: data})
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("bundle: no files in %s", dir)
	}
	return files, nil
}

func runManifestPub(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlagSet("manifest-pub", "--manifest-key KEY")
	keyFile := fs.String("manifest-key", "", "Ed25519 manifest private key: PEM file, or gcp-kms://<CryptoKeyVersion>")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" || fs.NArg() != 0 {
		fs.Usage()
		return errors.New("manifest-pub: --manifest-key is required")
	}
	key, err := openManifestSigner(ctx, *keyFile)
	if err != nil {
		return fmt.Errorf("manifest-pub: %w", err)
	}
	out, err := encodePublicKey(key.Public())
	if err != nil {
		return err
	}
	_, err = stdout.Write(out)
	return err
}

func runPrintLDFlags(_ context.Context, args []string, stdout io.Writer) error {
	fs := newFlagSet("print-ldflags", "--keys DIR")
	dir := fs.String("keys", "", "key directory written by keygen")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || fs.NArg() != 0 {
		fs.Usage()
		return errors.New("print-ldflags: --keys is required")
	}
	// manifest.pub first, then further keys such as manifest-next.pub.
	pubFiles, err := filepath.Glob(filepath.Join(*dir, "manifest*.pub"))
	if err != nil {
		return err
	}
	sort.Slice(pubFiles, func(i, j int) bool {
		a, b := filepath.Base(pubFiles[i]) == fileManifestPub, filepath.Base(pubFiles[j]) == fileManifestPub
		if a != b {
			return a
		}
		return pubFiles[i] < pubFiles[j]
	})
	if len(pubFiles) == 0 {
		return fmt.Errorf("print-ldflags: no manifest*.pub in %s", *dir)
	}
	var keys []ed25519.PublicKey
	for _, f := range pubFiles {
		k, err := readManifestPublicKey(f)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	caFiles, err := filepath.Glob(filepath.Join(*dir, "codesign-ca*.crt"))
	if err != nil {
		return err
	}
	sort.Strings(caFiles)
	if len(caFiles) == 0 {
		return fmt.Errorf("print-ldflags: no codesign-ca*.crt in %s", *dir)
	}
	var roots []*x509.Certificate
	for _, f := range caFiles {
		c, err := readCertificates(f)
		if err != nil {
			return err
		}
		roots = append(roots, c...)
	}
	fmt.Fprintf(stdout, "-X %s=%s -X %s=%s\n",
		ldflagReleaseKeys, sign.EncodeReleaseKeys(keys...),
		ldflagCodeSigningRoots, sign.EncodeCodeSigningRoots(roots...))
	return nil
}

func runVerify(ctx context.Context, args []string, stdout io.Writer) error {
	fs := newFlagSet("verify", "BUNDLE...")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return errors.New("verify: at least one bundle is required")
	}
	for _, path := range fs.Args() {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("verify: %w", err)
		}
		b, err := release.Open(ctx, f, time.Now())
		f.Close()
		if err != nil {
			return fmt.Errorf("verify: %s: %w", path, err)
		}
		var ps []string
		for _, p := range b.Platforms() {
			ps = append(ps, p.String())
		}
		fmt.Fprintf(stdout, "%s: version %s, platforms %s: OK\n", path, b.Version(), strings.Join(ps, " "))
	}
	return nil
}

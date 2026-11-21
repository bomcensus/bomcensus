// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package config reads the server configuration from BOMCENSUS_* environment
// variables.
//
// Every variable that is set is checked, and all problems are reported
// together. Values that are secret (the database URL, which may carry a
// password, and the master key) are held as Secret, which never prints its
// value.
package config

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Environment variable names.
const (
	EnvDatabaseURL       = "BOMCENSUS_DATABASE_URL"
	EnvAdminUser         = "BOMCENSUS_ADMIN_USER"
	EnvAdminPasswordHash = "BOMCENSUS_ADMIN_PASSWORD_HASH"
	EnvWebListen         = "BOMCENSUS_WEB_LISTEN"
	EnvWebTLS            = "BOMCENSUS_WEB_TLS"
	EnvWebServerNames    = "BOMCENSUS_WEB_SERVER_NAMES"
	EnvTrustProxy        = "BOMCENSUS_TRUST_PROXY"
	EnvAgentListen       = "BOMCENSUS_AGENT_LISTEN"
	EnvAgentServerNames  = "BOMCENSUS_AGENT_SERVER_NAMES"
	EnvMasterKey         = "BOMCENSUS_MASTER_KEY"
	EnvMasterKeyFile     = "BOMCENSUS_MASTER_KEY_FILE"
	EnvReleaseDir        = "BOMCENSUS_RELEASE_DIR"
	EnvEmbeddedScanner   = "BOMCENSUS_EMBEDDED_SCANNER"
	EnvLogLevel          = "BOMCENSUS_LOG_LEVEL"
	EnvLogFormat         = "BOMCENSUS_LOG_FORMAT"
)

// Defaults.
const (
	DefaultWebListen   = ":8080"
	DefaultAgentListen = ":8443"
	DefaultServerName  = "localhost"
)

// WebTLS is how the console listener handles TLS.
type WebTLS string

// WebTLS values.
const (
	// WebTLSAuto serves HTTPS. The certificate follows the stored Web/API
	// TLS setting, which starts as an automatic certificate from the
	// internal web CA.
	WebTLSAuto WebTLS = "auto"
	// WebTLSManual serves HTTPS with the certificate uploaded through the
	// console. Until one is uploaded the automatic certificate is served.
	WebTLSManual WebTLS = "manual"
	// WebTLSOff serves plain HTTP, for a listener behind an ingress or
	// reverse proxy that terminates TLS.
	WebTLSOff WebTLS = "off"
)

// LogFormat is the log output format.
type LogFormat string

// LogFormat values.
const (
	LogText LogFormat = "text"
	LogJSON LogFormat = "json"
)

// Purpose says what the configuration is loaded for; it decides which
// variables are required.
type Purpose int

// Purposes.
const (
	// Serve needs everything: the database and the master key.
	Serve Purpose = iota
	// Migrate needs the database only.
	Migrate
)

// Secret is a configuration value that must not appear in logs. Its String,
// GoString and LogValue never show the value; Reveal does.
type Secret string

// Reveal returns the value.
func (s Secret) Reveal() string { return string(s) }

// String implements fmt.Stringer.
func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return "[redacted]"
}

// GoString implements fmt.GoStringer.
func (s Secret) GoString() string { return strconv.Quote(s.String()) }

// LogValue implements slog.LogValuer.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.String()) }

// Config is the server configuration.
type Config struct {
	// DatabaseURL is the PostgreSQL connection string.
	DatabaseURL Secret
	// AdminUser and AdminPasswordHash (argon2id PHC string) are the single
	// console user. Both empty disables login.
	AdminUser         string
	AdminPasswordHash string

	// WebListen is the console listener address.
	WebListen string
	WebTLS    WebTLS
	// WebServerNames are the SANs of the automatic Web/API certificate.
	WebServerNames []string
	// TrustProxy makes the console believe X-Forwarded-* headers.
	TrustProxy bool

	// AgentListen is the agent listener address. TLS is always on.
	AgentListen string
	// AgentServerNames are the SANs of the automatic Agent TLS
	// certificates.
	AgentServerNames []string

	// MasterKey (base64) or MasterKeyFile (a file holding it): exactly one
	// is set for Serve.
	MasterKey     Secret
	MasterKeyFile string

	// ReleaseDir holds release bundles imported at start; empty for none.
	ReleaseDir string
	// EmbeddedScanner runs the scanner inside the server process.
	EmbeddedScanner bool

	LogLevel  slog.Level
	LogFormat LogFormat
}

// Load reads the process environment. The default agent server name is the
// host name.
func Load(p Purpose) (Config, error) {
	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	return Parse(os.LookupEnv, host, p)
}

// Parse reads the configuration through lookup. hostname is the default of
// AgentServerNames; when it is empty, DefaultServerName is used.
func Parse(lookup func(string) (string, bool), hostname string, p Purpose) (Config, error) {
	get := func(name string) string {
		v, _ := lookup(name)
		return strings.TrimSpace(v)
	}
	var errs []error
	fail := func(name, format string, args ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", name, fmt.Sprintf(format, args...)))
	}

	c := Config{
		DatabaseURL:       Secret(get(EnvDatabaseURL)),
		AdminUser:         get(EnvAdminUser),
		AdminPasswordHash: get(EnvAdminPasswordHash),
		WebListen:         orDefault(get(EnvWebListen), DefaultWebListen),
		AgentListen:       orDefault(get(EnvAgentListen), DefaultAgentListen),
		MasterKeyFile:     get(EnvMasterKeyFile),
		ReleaseDir:        get(EnvReleaseDir),
	}
	// The key is taken untrimmed from the environment; the secret package
	// ignores surrounding white space when it decodes it.
	if v, ok := lookup(EnvMasterKey); ok {
		c.MasterKey = Secret(v)
	}

	if c.DatabaseURL == "" {
		fail(EnvDatabaseURL, "required (for example postgres://user:password@host:5432/bomcensus)")
	}

	switch {
	case c.AdminUser != "" && c.AdminPasswordHash == "":
		fail(EnvAdminPasswordHash, "required when %s is set (create one with: bomcensus-server hash-password)", EnvAdminUser)
	case c.AdminUser == "" && c.AdminPasswordHash != "":
		fail(EnvAdminUser, "required when %s is set", EnvAdminPasswordHash)
	case c.AdminPasswordHash != "" && !strings.HasPrefix(c.AdminPasswordHash, "$argon2id$"):
		fail(EnvAdminPasswordHash, "must be an argon2id PHC string, not a password (create one with: bomcensus-server hash-password)")
	}

	if err := checkListen(c.WebListen); err != nil {
		fail(EnvWebListen, "%v", err)
	}
	if err := checkListen(c.AgentListen); err != nil {
		fail(EnvAgentListen, "%v", err)
	}
	if c.WebListen == c.AgentListen && !strings.HasSuffix(c.WebListen, ":0") {
		fail(EnvAgentListen, "must differ from %s (%s)", EnvWebListen, c.WebListen)
	}

	switch v := WebTLS(strings.ToLower(get(EnvWebTLS))); v {
	case "":
		c.WebTLS = WebTLSAuto
	case WebTLSAuto, WebTLSManual, WebTLSOff:
		c.WebTLS = v
	default:
		fail(EnvWebTLS, "must be auto, manual or off, got %q", v)
	}

	var err error
	if c.WebServerNames, err = serverNames(get(EnvWebServerNames), DefaultServerName); err != nil {
		fail(EnvWebServerNames, "%v", err)
	}
	if hostname == "" {
		hostname = DefaultServerName
	}
	if c.AgentServerNames, err = serverNames(get(EnvAgentServerNames), hostname); err != nil {
		fail(EnvAgentServerNames, "%v", err)
	}

	if c.TrustProxy, err = boolean(get(EnvTrustProxy), false); err != nil {
		fail(EnvTrustProxy, "%v", err)
	}
	if c.EmbeddedScanner, err = boolean(get(EnvEmbeddedScanner), true); err != nil {
		fail(EnvEmbeddedScanner, "%v", err)
	}

	switch {
	case strings.TrimSpace(c.MasterKey.Reveal()) != "" && c.MasterKeyFile != "":
		fail(EnvMasterKey, "set either %s or %s, not both", EnvMasterKey, EnvMasterKeyFile)
	case strings.TrimSpace(c.MasterKey.Reveal()) == "" && c.MasterKeyFile == "" && p == Serve:
		fail(EnvMasterKey, "required: set %s (32 random bytes, base64) or %s (a file holding it)", EnvMasterKey, EnvMasterKeyFile)
	}

	if c.LogLevel, err = logLevel(get(EnvLogLevel)); err != nil {
		fail(EnvLogLevel, "%v", err)
	}
	switch v := LogFormat(strings.ToLower(get(EnvLogFormat))); v {
	case "":
		c.LogFormat = LogText
	case LogText, LogJSON:
		c.LogFormat = v
	default:
		fail(EnvLogFormat, "must be text or json, got %q", v)
	}

	if len(errs) > 0 {
		return Config{}, fmt.Errorf("configuration: %w", errors.Join(errs...))
	}
	return c, nil
}

// NewLogger returns a logger writing to w in the configured format and
// level.
func (c Config) NewLogger(w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: c.LogLevel}
	if c.LogFormat == LogJSON {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// checkListen accepts host:port with a numeric port; the host may be empty
// (all interfaces).
func checkListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("must be host:port or :port, got %q", addr)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("invalid port %q", port)
	}
	if strings.ContainsAny(host, " \t/") {
		return fmt.Errorf("invalid host %q", host)
	}
	return nil
}

// serverNames splits a comma-separated list of DNS names and IP addresses.
// An empty list gives def.
func serverNames(v, def string) ([]string, error) {
	if v == "" {
		v = def
	}
	var out []string
	seen := map[string]bool{}
	for _, n := range strings.Split(v, ",") {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if !validServerName(n) {
			return nil, fmt.Errorf("%q is neither a DNS name nor an IP address", n)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no server name given")
	}
	return out, nil
}

// validServerName accepts an IP address or a DNS name of letters, digits,
// hyphens and dots, optionally starting with a "*." wildcard label.
func validServerName(n string) bool {
	if _, err := netip.ParseAddr(n); err == nil {
		return true
	}
	if len(n) > 253 {
		return false
	}
	labels := strings.Split(strings.TrimPrefix(n, "*."), ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func boolean(v string, def bool) (bool, error) {
	switch strings.ToLower(v) {
	case "":
		return def, nil
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("must be true or false, got %q", v)
}

func logLevel(v string) (slog.Level, error) {
	switch strings.ToLower(v) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("must be debug, info, warn or error, got %q", v)
}

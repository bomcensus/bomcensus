// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package config

import (
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

const testHash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"

func lookup(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
}

// minimal is the smallest environment that serves.
func minimal() map[string]string {
	return map[string]string{
		EnvDatabaseURL: "postgres://u:p@db/bomcensus",
		EnvMasterKey:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
}

func with(kv ...string) map[string]string {
	env := minimal()
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "<unset>" {
			delete(env, kv[i])
			continue
		}
		env[kv[i]] = kv[i+1]
	}
	return env
}

func TestParseDefaults(t *testing.T) {
	c, err := Parse(lookup(minimal()), "node1.example", Serve)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		DatabaseURL:      "postgres://u:p@db/bomcensus",
		WebListen:        ":8080",
		WebTLS:           WebTLSAuto,
		WebServerNames:   []string{"localhost"},
		AgentListen:      ":8443",
		AgentServerNames: []string{"node1.example"},
		MasterKey:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		EmbeddedScanner:  true,
		LogLevel:         slog.LevelInfo,
		LogFormat:        LogText,
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("got  %#v\nwant %#v", c, want)
	}
	c, err = Parse(lookup(minimal()), "", Serve)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.AgentServerNames, []string{"localhost"}) {
		t.Fatalf("agent names without host name: %v", c.AgentServerNames)
	}
}

func TestParseValues(t *testing.T) {
	env := with(
		EnvAdminUser, "admin",
		EnvAdminPasswordHash, testHash,
		EnvWebListen, "127.0.0.1:9080",
		EnvWebTLS, "OFF",
		EnvWebServerNames, " console.example.com , 10.0.0.1,console.example.com,",
		EnvTrustProxy, "yes",
		EnvAgentListen, "[::1]:9443",
		EnvAgentServerNames, "agents.example.com,*.agents.example.com",
		EnvMasterKey, "<unset>",
		EnvMasterKeyFile, "/run/secrets/master-key",
		EnvReleaseDir, "/releases",
		EnvEmbeddedScanner, "false",
		EnvLogLevel, "debug",
		EnvLogFormat, "json",
	)
	c, err := Parse(lookup(env), "ignored", Serve)
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		DatabaseURL:       "postgres://u:p@db/bomcensus",
		AdminUser:         "admin",
		AdminPasswordHash: testHash,
		WebListen:         "127.0.0.1:9080",
		WebTLS:            WebTLSOff,
		WebServerNames:    []string{"console.example.com", "10.0.0.1"},
		TrustProxy:        true,
		AgentListen:       "[::1]:9443",
		AgentServerNames:  []string{"agents.example.com", "*.agents.example.com"},
		MasterKeyFile:     "/run/secrets/master-key",
		ReleaseDir:        "/releases",
		EmbeddedScanner:   false,
		LogLevel:          slog.LevelDebug,
		LogFormat:         LogJSON,
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("got  %#v\nwant %#v", c, want)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		purpose Purpose
		want    []string // substrings of the error
	}{
		{"no database", with(EnvDatabaseURL, "<unset>"), Serve, []string{EnvDatabaseURL + ": required"}},
		{"no master key", with(EnvMasterKey, "<unset>"), Serve, []string{EnvMasterKey + ": required"}},
		{"blank master key", with(EnvMasterKey, "  "), Serve, []string{EnvMasterKey + ": required"}},
		{"both master keys", with(EnvMasterKeyFile, "/k"), Serve, []string{"not both"}},
		{"both master keys for migrate", with(EnvMasterKeyFile, "/k"), Migrate, []string{"not both"}},
		{"user without hash", with(EnvAdminUser, "admin"), Serve, []string{EnvAdminPasswordHash + ": required"}},
		{"hash without user", with(EnvAdminPasswordHash, testHash), Serve, []string{EnvAdminUser + ": required"}},
		{"plaintext password", with(EnvAdminUser, "admin", EnvAdminPasswordHash, "secret123"), Serve, []string{"not a password"}},
		{"bad web tls", with(EnvWebTLS, "on"), Serve, []string{EnvWebTLS + ": must be auto, manual or off"}},
		{"bad web listen", with(EnvWebListen, "8080"), Serve, []string{EnvWebListen + ": must be host:port"}},
		{"bad agent port", with(EnvAgentListen, ":99999"), Serve, []string{EnvAgentListen + ": invalid port"}},
		{"same listen", with(EnvWebListen, ":9000", EnvAgentListen, ":9000"), Serve, []string{"must differ"}},
		{"bad server name", with(EnvWebServerNames, "bad name"), Serve, []string{EnvWebServerNames}},
		{"bad label", with(EnvAgentServerNames, "-x.example"), Serve, []string{EnvAgentServerNames}},
		{"empty names", with(EnvAgentServerNames, ",,"), Serve, []string{"no server name"}},
		{"bad bool", with(EnvTrustProxy, "maybe"), Serve, []string{EnvTrustProxy + ": must be true or false"}},
		{"bad scanner bool", with(EnvEmbeddedScanner, "2"), Serve, []string{EnvEmbeddedScanner}},
		{"bad level", with(EnvLogLevel, "trace"), Serve, []string{EnvLogLevel}},
		{"bad format", with(EnvLogFormat, "xml"), Serve, []string{EnvLogFormat}},
		{"all at once", with(EnvDatabaseURL, "<unset>", EnvWebTLS, "x", EnvLogFormat, "y"), Serve,
			[]string{EnvDatabaseURL, EnvWebTLS, EnvLogFormat}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(lookup(tt.env), "host", tt.purpose)
			if err == nil {
				t.Fatal("no error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
		})
	}
}

func TestParseMigrateNeedsNoMasterKey(t *testing.T) {
	if _, err := Parse(lookup(with(EnvMasterKey, "<unset>")), "host", Migrate); err != nil {
		t.Fatal(err)
	}
}

func TestSecretIsNotPrinted(t *testing.T) {
	c, err := Parse(lookup(minimal()), "host", Serve)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	slog.New(slog.NewTextHandler(&b, nil)).Info("cfg", "db", c.DatabaseURL, "key", c.MasterKey, "all", c)
	out := b.String() + fmt.Sprintf("%v %+v %#v %s", c, c, c, c.MasterKey)
	for _, leak := range []string{"u:p@db", "AAAAAAAA"} {
		if strings.Contains(out, leak) {
			t.Fatalf("secret %q printed: %s", leak, out)
		}
	}
	if c.DatabaseURL.Reveal() != "postgres://u:p@db/bomcensus" {
		t.Fatal("Reveal")
	}
}

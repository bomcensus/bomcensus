// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package proc

import (
	"path/filepath"
	"regexp"
	"strings"
)

const masked = "****"

// secretWords mark an option or variable name as holding a secret when they
// appear anywhere in it (case-insensitive).
var secretWords = []string{
	"password", "passwd", "passphrase", "secret", "token",
	"apikey", "api-key", "api_key",
	"accesskey", "access-key", "access_key",
	"privatekey", "private-key", "private_key",
	"credential",
}

// secretNames hold a secret when they are the whole name or its last part
// ("MYSQL_PWD", "--db-pass", keytool "-storepass").
var secretNames = []string{
	"pass", "pwd", "pw",
	"storepass", "keypass", "srcstorepass", "deststorepass", "srckeypass", "destkeypass",
}

// notSecretSuffixes mark names that refer to where a secret is, not the
// secret itself ("--password-file", "--token-auth-file", "--password-stdin").
var notSecretSuffixes = []string{"file", "path", "dir", "stdin", "env", "length", "len", "ttl"}

// Tools whose short options take a password.
var (
	// -p<password>, attached only: "-p" alone prompts.
	attachedPasswordFlag = map[string]string{
		"mysql": "-p", "mysqldump": "-p", "mysqladmin": "-p", "mysqlimport": "-p",
		"mysqlcheck": "-p", "mysqlshow": "-p", "mysqlbinlog": "-p", "mysqlslap": "-p",
		"mariadb": "-p", "mariadb-dump": "-p", "mariadb-admin": "-p", "mariadb-import": "-p",
		"mariadb-check": "-p", "mariadb-show": "-p", "mariadb-binlog": "-p", "mariadb-slap": "-p",
		"sshpass": "-p",
	}
	// Option followed by the password as the next argument.
	separatePasswordFlag = map[string]string{
		"sshpass":   "-p",
		"redis-cli": "-a",
	}
)

var (
	// scheme://user:password@ — the password runs to the last '@' before
	// the path.
	urlUserinfo = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://[^/?#@\s:]*):[^/?#\s]*@`)
	// HTTP header arguments ("-H 'Authorization: Bearer ...'").
	secretHeader = regexp.MustCompile(`(?i)^\s*(authorization|proxy-authorization|cookie|x-api-key|x-auth-token|private-token)\s*:`)
)

// maskCmdline joins the arguments with spaces, with the values of arguments
// that look like secrets replaced by "****".
func maskCmdline(args []string) string {
	if len(args) == 0 {
		return ""
	}
	out := maskArgs(args)
	s := strings.ToValidUTF8(strings.Join(out, " "), "�")
	if len(s) > maxCmdlineOut {
		s = strings.ToValidUTF8(s[:maxCmdlineOut], "")
	}
	return s
}

// maskArgs masks the words of a command. The tool-specific rules apply from
// the word naming the tool on, so "sudo mysql -p..." and the words of a
// shell script are covered as well.
func maskArgs(args []string) []string {
	var attached, separate string
	curl := false

	out := make([]string, len(args))
	maskNext := false
	userNext := false
	for i, a := range args {
		if maskNext {
			maskNext = false
			if !strings.HasPrefix(a, "-") {
				out[i] = masked
				continue
			}
		}
		if userNext {
			userNext = false
			if !strings.HasPrefix(a, "-") {
				out[i] = maskUserPassword(a)
				continue
			}
		}
		if tool := strings.TrimSuffix(filepath.Base(strings.Trim(a, "\"'`")), ":"); isTool(tool) {
			attached = attachedPasswordFlag[tool]
			separate = separatePasswordFlag[tool]
			curl = tool == "curl"
			out[i] = a
			continue
		}
		if i == 0 {
			out[i] = maskURL(a)
			continue
		}

		switch {
		case separate != "" && a == separate:
			out[i] = a
			maskNext = true
		case attached != "" && len(a) > len(attached) && strings.HasPrefix(a, attached) && !strings.HasPrefix(a, "--"):
			out[i] = attached + masked
		case curl && (a == "-u" || a == "--user" || a == "-U" || a == "--proxy-user"):
			out[i] = a
			userNext = true
		case curl && len(a) > 2 && (strings.HasPrefix(a, "-u") || strings.HasPrefix(a, "-U")) && !strings.HasPrefix(a, "--"):
			out[i] = a[:2] + maskUserPassword(a[2:])
		case secretHeader.MatchString(a):
			j := strings.IndexByte(a, ':')
			out[i] = a[:j+1] + " " + masked
		case strings.ContainsAny(a, " \t\n"):
			// A script ("sh -c '...'") or a value with spaces: mask its
			// words as if they were arguments.
			out[i] = strings.Join(maskArgs(append([]string{""}, strings.Fields(a)...))[1:], " ")
		default:
			out[i], maskNext = maskOption(a)
		}
	}
	return out
}

func isTool(name string) bool {
	_, a := attachedPasswordFlag[name]
	_, s := separatePasswordFlag[name]
	return a || s || name == "curl"
}

// maskOption handles "--name=value", "-Dname=value", "NAME=value" and
// "--name" followed by the value. It returns the masked argument and whether
// the next argument is the value of a secret option.
//
// Leading quotes are ignored so that words of a shell script ("'--token=x'")
// are recognized too.
func maskOption(a string) (string, bool) {
	if key, _, ok := strings.Cut(a, "="); ok {
		name := strings.TrimLeft(key, "\"'`-")
		if isName(name) && isSecretName(name) {
			return key + "=" + masked, false
		}
		return maskURL(a), false
	}
	if bare := strings.Trim(a, "\"'`"); strings.HasPrefix(bare, "-") {
		name := strings.TrimLeft(bare, "-")
		if isName(name) && isSecretName(name) {
			return a, true
		}
	}
	return maskURL(a), false
}

func isSecretName(name string) bool {
	n := strings.ToLower(name)
	if strings.HasPrefix(n, "no-") || strings.HasPrefix(n, "no_") {
		return false
	}
	for _, s := range notSecretSuffixes {
		if strings.HasSuffix(n, s) && len(n) > len(s) {
			return false
		}
	}
	for _, w := range secretWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	last := n
	if i := strings.LastIndexAny(n, "-_."); i >= 0 {
		last = n[i+1:]
	}
	for _, w := range secretNames {
		if last == w {
			return true
		}
	}
	return false
}

// isName reports whether s looks like an option or variable name, so that
// arbitrary words containing '=' are not taken for options.
func isName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func maskURL(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	return urlUserinfo.ReplaceAllString(s, "${1}:"+masked+"@")
}

// maskUserPassword masks the password of a "user:password" value.
func maskUserPassword(s string) string {
	if user, _, ok := strings.Cut(s, ":"); ok {
		return user + ":" + masked
	}
	return s
}

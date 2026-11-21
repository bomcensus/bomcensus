// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package kube

import (
	"strings"
	"testing"
	"time"
)

func kubeconfig(user string) []byte {
	return []byte(`apiVersion: v1
kind: Config
current-context: test
clusters:
- name: c
  cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
contexts:
- name: test
  context: {cluster: c, user: u}
- name: other
  context: {cluster: c, user: plugin}
users:
- name: u
  user:
` + user + `
- name: plugin
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: /bin/true
      interactiveMode: Never
`)
}

func TestNewClientKubeconfig(t *testing.T) {
	c, err := NewClient(Config{Kubeconfig: kubeconfig("    token: abc")})
	if err != nil {
		t.Fatal(err)
	}
	if c.Kube == nil || c.Exec == nil {
		t.Fatal("incomplete client")
	}
	rc, err := restConfig(Config{Kubeconfig: kubeconfig("    token: abc")})
	if err != nil {
		t.Fatal(err)
	}
	if rc.QPS != DefaultQPS || rc.Burst != DefaultBurst || rc.Timeout != DefaultRequestTimeout || rc.UserAgent != defaultUserAgent {
		t.Errorf("defaults not applied: qps %v burst %d timeout %v ua %q", rc.QPS, rc.Burst, rc.Timeout, rc.UserAgent)
	}
	rc, err = restConfig(Config{Kubeconfig: kubeconfig("    token: abc"), QPS: 5, Burst: 7, RequestTimeout: time.Second})
	if err != nil || rc.QPS != 5 || rc.Burst != 7 || rc.Timeout != time.Second {
		t.Errorf("overrides: %v %+v", err, rc)
	}
	if ec := c.Exec.(*restExecutor).config; ec.Timeout != 0 {
		t.Errorf("exec config has timeout %v", ec.Timeout)
	}
}

func TestNewClientRejectsExternalCredentials(t *testing.T) {
	for name, cfg := range map[string]Config{
		"exec plugin":     {Kubeconfig: kubeconfig("    token: abc"), Context: "other"},
		"token file":      {Kubeconfig: kubeconfig("    tokenFile: /var/run/token")},
		"client key file": {Kubeconfig: kubeconfig("    client-certificate: /c.pem\n    client-key: /k.pem")},
		"auth provider":   {Kubeconfig: kubeconfig("    auth-provider: {name: oidc}")},
		"missing context": {Kubeconfig: kubeconfig("    token: abc"), Context: "nope"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewClient(cfg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// The operator can allow them explicitly.
	if _, err := NewClient(Config{Kubeconfig: kubeconfig("    token: abc"), Context: "other", AllowExternalCredentials: true}); err != nil {
		t.Errorf("allowed exec plugin rejected: %v", err)
	}
}

func TestNewClientCAFile(t *testing.T) {
	cfg := strings.Replace(string(kubeconfig("    token: abc")), "insecure-skip-tls-verify: true", "certificate-authority: /ca.pem", 1)
	if _, err := NewClient(Config{Kubeconfig: []byte(cfg)}); err == nil || !strings.Contains(err.Error(), "certificate authority file") {
		t.Errorf("err %v", err)
	}
}

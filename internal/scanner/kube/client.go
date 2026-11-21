// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

// Package kube collects Kubernetes clusters through the API server: the
// workload inventory from pod specs and statuses, and container contents by
// piping the probe into running containers over the pods/exec subresource.
// Nothing is deployed into the cluster and no image is pulled.
package kube

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/remotecommand"
)

// Defaults for API access.
const (
	DefaultQPS            = 20
	DefaultBurst          = 40
	DefaultRequestTimeout = 30 * time.Second
	defaultUserAgent      = "bomcensus-scanner"
)

// Config selects how to reach the API server.
type Config struct {
	// Kubeconfig is a kubeconfig file content. When empty the in-cluster
	// configuration (service account) is used.
	Kubeconfig []byte
	// Context selects a kubeconfig context. Empty means the current one.
	Context string
	// QPS and Burst limit API requests. Zero means DefaultQPS/DefaultBurst.
	QPS   float32
	Burst int
	// RequestTimeout bounds each API request except exec streams, whose
	// duration is bounded by the caller's context. Zero means
	// DefaultRequestTimeout.
	RequestTimeout time.Duration
	// AllowExternalCredentials accepts kubeconfigs that run credential
	// plugins (exec, auth-provider) or read files on the scanner host. A
	// kubeconfig usually comes from the server; running commands or reading
	// local files on its behalf would give the server code execution on the
	// scanner, so this is off unless the operator configures it locally.
	AllowExternalCredentials bool
	UserAgent                string
}

// ExecRequest is one exec session in a container.
type ExecRequest struct {
	Namespace string
	Pod       string
	Container string
	Command   []string
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
}

// Executor runs a command in a container with stdin, stdout and stderr
// attached and no TTY. A non-zero exit status is reported as an error that
// implements ExitStatus() int (k8s.io/client-go/util/exec.ExitError).
type Executor interface {
	Exec(ctx context.Context, r ExecRequest) error
}

// Client bundles the typed API client and the exec transport.
type Client struct {
	Kube kubernetes.Interface
	Exec Executor
}

// NewClientWith builds a client from existing parts (tests, or callers that
// already hold a clientset).
func NewClientWith(kube kubernetes.Interface, exec Executor) *Client {
	return &Client{Kube: kube, Exec: exec}
}

// NewClient builds a client from kubeconfig bytes or the in-cluster
// configuration.
func NewClient(cfg Config) (*Client, error) {
	rc, err := restConfig(cfg)
	if err != nil {
		return nil, err
	}
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("kube: new clientset: %w", err)
	}
	// Exec streams last as long as the collection; the per-request timeout
	// must not cut them.
	ec := rest.CopyConfig(rc)
	ec.Timeout = 0
	execKube, err := kubernetes.NewForConfig(ec)
	if err != nil {
		return nil, fmt.Errorf("kube: new exec clientset: %w", err)
	}
	return &Client{Kube: kube, Exec: &restExecutor{config: ec, kube: execKube}}, nil
}

func restConfig(cfg Config) (*rest.Config, error) {
	var rc *rest.Config
	if len(cfg.Kubeconfig) == 0 {
		c, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("kube: in-cluster configuration: %w", err)
		}
		rc = c
	} else {
		apiCfg, err := clientcmd.Load(cfg.Kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("kube: parse kubeconfig: %w", err)
		}
		if !cfg.AllowExternalCredentials {
			if err := checkSelfContained(apiCfg, cfg.Context); err != nil {
				return nil, err
			}
		}
		c, err := clientcmd.NewNonInteractiveClientConfig(*apiCfg, cfg.Context, &clientcmd.ConfigOverrides{}, nil).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("kube: kubeconfig: %w", err)
		}
		rc = c
	}
	rc.QPS = cfg.QPS
	if rc.QPS <= 0 {
		rc.QPS = DefaultQPS
	}
	rc.Burst = cfg.Burst
	if rc.Burst <= 0 {
		rc.Burst = DefaultBurst
	}
	rc.Timeout = cfg.RequestTimeout
	if rc.Timeout <= 0 {
		rc.Timeout = DefaultRequestTimeout
	}
	rc.UserAgent = cfg.UserAgent
	if rc.UserAgent == "" {
		rc.UserAgent = defaultUserAgent
	}
	return rc, nil
}

// checkSelfContained rejects credentials that run programs or read files on
// the scanner host, for the context that will be used.
func checkSelfContained(c *clientcmdapi.Config, contextName string) error {
	name := contextName
	if name == "" {
		name = c.CurrentContext
	}
	kctx, ok := c.Contexts[name]
	if !ok || kctx == nil {
		return fmt.Errorf("kube: kubeconfig has no context %q", name)
	}
	if cl := c.Clusters[kctx.Cluster]; cl != nil && cl.CertificateAuthority != "" {
		return errors.New("kube: kubeconfig refers to a certificate authority file; embed certificate-authority-data instead")
	}
	ai := c.AuthInfos[kctx.AuthInfo]
	if ai == nil {
		return nil
	}
	switch {
	case ai.Exec != nil:
		return errors.New("kube: kubeconfig uses an exec credential plugin, which is not allowed")
	case ai.AuthProvider != nil:
		return errors.New("kube: kubeconfig uses an auth-provider plugin, which is not allowed")
	case ai.ClientCertificate != "" || ai.ClientKey != "" || ai.TokenFile != "":
		return errors.New("kube: kubeconfig refers to credential files; embed the data instead")
	}
	return nil
}

// restExecutor runs exec sessions over WebSocket, falling back to SPDY for
// API servers that do not support the WebSocket protocol.
type restExecutor struct {
	config *rest.Config
	kube   kubernetes.Interface
}

func (e *restExecutor) Exec(ctx context.Context, r ExecRequest) error {
	req := e.kube.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(r.Namespace).Name(r.Pod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: r.Container,
			Command:   r.Command,
			Stdin:     r.Stdin != nil,
			Stdout:    r.Stdout != nil,
			Stderr:    r.Stderr != nil,
			TTY:       false,
		}, scheme.ParameterCodec)
	spdy, err := remotecommand.NewSPDYExecutor(e.config, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("kube: spdy executor: %w", err)
	}
	ws, err := remotecommand.NewWebSocketExecutor(e.config, "GET", req.URL().String())
	if err != nil {
		return fmt.Errorf("kube: websocket executor: %w", err)
	}
	ex, err := remotecommand.NewFallbackExecutor(ws, spdy, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
	if err != nil {
		return fmt.Errorf("kube: executor: %w", err)
	}
	return ex.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: r.Stdin, Stdout: r.Stdout, Stderr: r.Stderr})
}

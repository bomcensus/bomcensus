// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/bomcensus/bomcensus/internal/server/bootstrap"
	"github.com/bomcensus/bomcensus/internal/server/config"
	"github.com/bomcensus/bomcensus/internal/server/secret"
)

// serviceAccountNamespace holds the namespace of the pod's ServiceAccount.
const serviceAccountNamespace = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// bootstrapScanner implements "bootstrap-scanner": it stores an enrollment
// string for a scanner in a Kubernetes Secret (see internal/server/bootstrap).
// The database and the master key come from the normal server configuration.
func bootstrapScanner(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("bootstrap-scanner", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ns := fs.String("secret-namespace", "", "namespace of the Secret (default: the namespace of the pod)")
	name := fs.String("secret-name", "", "name of the Secret (required)")
	key := fs.String("secret-key", bootstrap.DefaultSecretKey, "data key holding the enrollment string")
	keyName := fs.String("key-name", bootstrap.DefaultKeyName, "name of a new Register Key")
	maxUses := fs.Int("max-uses", 1, "maximum uses of a new Register Key (0 = unlimited)")
	timeout := fs.Duration("timeout", 10*time.Minute, "how long to wait for the database and the PKI")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig file (default: in-cluster configuration)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *name == "" {
		return errors.New("--secret-name is required")
	}
	if *ns == "" {
		b, err := os.ReadFile(serviceAccountNamespace)
		if err != nil {
			return errors.New("--secret-namespace is required outside a pod")
		}
		*ns = strings.TrimSpace(string(b))
	}

	cfg, err := config.Load(config.Serve)
	if err != nil {
		return err
	}
	log := cfg.NewLogger(stderr).With("command", "bootstrap-scanner")
	mk, err := secret.LoadKey(cfg.MasterKey.Reveal(), cfg.MasterKeyFile)
	if err != nil {
		return err
	}
	box, err := secret.New(mk)
	clear(mk)
	if err != nil {
		return err
	}

	var rc *rest.Config
	if *kubeconfig != "" {
		rc, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
	} else {
		rc, err = rest.InClusterConfig()
	}
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	db, err := bootstrap.Connect(ctx, cfg.DatabaseURL.Reveal(), 0, log)
	if err != nil {
		return err
	}
	defer db.Close()
	res, err := bootstrap.Scanner(ctx, bootstrap.Options{
		Store: db, Box: box, Kube: kube,
		Namespace: *ns, SecretName: *name, SecretKey: *key,
		KeyName: *keyName, MaxUses: *maxUses,
		Logger: log,
	})
	if err != nil {
		return err
	}
	log.Info("scanner bootstrap done", "outcome", res.Outcome, "key_id", res.KeyID, "secret", *ns+"/"+*name)
	return nil
}

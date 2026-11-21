// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package pkisvc

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/bomcensus/bomcensus/internal/pki"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

// object is a decoded store.PKIObject.
type object struct {
	name      string
	version   int64
	chain     []*x509.Certificate
	key       crypto.Signer // nil when the object has no key
	createdAt time.Time
}

func keyAAD(name string) []byte { return []byte("pki:" + name) }

func (s *Service) decode(r store.PKIObject) (*object, error) {
	chain, err := pki.ParseCertificatesPEM(r.CertChainPEM)
	if err != nil {
		return nil, fmt.Errorf("pkisvc: %s: %w", r.Name, err)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("pkisvc: %s: no certificate", r.Name)
	}
	o := &object{name: r.Name, version: r.Version, chain: chain, createdAt: r.CreatedAt}
	if len(r.EncryptedKey) > 0 {
		pemKey, err := s.box.Open(r.EncryptedKey, keyAAD(r.Name))
		if err != nil {
			return nil, fmt.Errorf("pkisvc: %s: open key: %w", r.Name, err)
		}
		defer clear(pemKey)
		if o.key, err = pki.ParsePrivateKeyPEM(pemKey); err != nil {
			return nil, fmt.Errorf("pkisvc: %s: %w", r.Name, err)
		}
	}
	return o, nil
}

// get returns the object, or nil without error when it does not exist.
func (s *Service) get(ctx context.Context, p store.PKI, name string) (*object, error) {
	r, err := p.GetPKIObject(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.decode(r)
}

// put writes chain and key under name if the stored version is expect (0:
// must not exist).
func (s *Service) put(ctx context.Context, p store.PKI, name string, chain []*x509.Certificate, key crypto.Signer, state string, expect int64) (*object, error) {
	r := store.PKIObject{Name: name, CertChainPEM: pki.EncodeCertificatesPEM(chain...), State: state}
	if key != nil {
		pemKey, err := pki.EncodePrivateKeyPEM(key)
		if err != nil {
			return nil, fmt.Errorf("pkisvc: %s: %w", name, err)
		}
		r.EncryptedKey, err = s.box.Seal(pemKey, keyAAD(name))
		clear(pemKey)
		if err != nil {
			return nil, fmt.Errorf("pkisvc: %s: %w", name, err)
		}
	}
	out, err := p.PutPKIObject(ctx, r, expect)
	if err != nil {
		return nil, err
	}
	return &object{name: name, version: out.Version, chain: chain, key: key, createdAt: out.CreatedAt}, nil
}

// replace writes the object whatever its current version is.
func (s *Service) replace(ctx context.Context, p store.PKI, name string, chain []*x509.Certificate, key crypto.Signer, state string) error {
	cur, err := s.get(ctx, p, name)
	if err != nil {
		return err
	}
	var expect int64
	if cur != nil {
		expect = cur.version
	}
	_, err = s.put(ctx, p, name, chain, key, state, expect)
	return err
}

// remove deletes the object if it exists.
func (s *Service) remove(ctx context.Context, p store.PKI, name string) error {
	r, err := p.GetPKIObject(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return p.DeletePKIObject(ctx, name, r.Version)
}

var caNames = map[string]string{
	store.PKIAgentCA:    "bomcensus Agent CA",
	store.PKIWebCA:      "bomcensus Web CA",
	store.PKIAgentTLSCA: "bomcensus Agent TLS CA",
}

func (s *Service) newCA(commonName string) (*pki.CA, error) {
	now := s.now()
	return pki.NewCA(pki.CAOptions{
		Subject:   pkix.Name{CommonName: commonName, Organization: []string{"bomcensus"}},
		NotBefore: now.Add(-backdate),
		Lifetime:  s.cfg.CALifetime,
	})
}

// ensureCA returns the CA stored under name, creating it when missing. When
// several replicas create it at once, all of them end up with the winner's.
func (s *Service) ensureCA(ctx context.Context, p store.PKI, name string) (*pki.CA, error) {
	o, err := s.get(ctx, p, name)
	if err != nil {
		return nil, err
	}
	if o == nil {
		ca, err := s.newCA(caNames[name])
		if err != nil {
			return nil, err
		}
		_, err = s.put(ctx, p, name, []*x509.Certificate{ca.Cert}, ca.Key, store.PKIStateActive, 0)
		switch {
		case err == nil:
			s.log.Info("created internal CA", "name", name, "spki", spkiString(ca.Cert))
			return ca, nil
		case !errors.Is(err, store.ErrConflict):
			return nil, err
		}
		if o, err = s.get(ctx, p, name); err != nil {
			return nil, err
		}
		if o == nil {
			return nil, fmt.Errorf("pkisvc: %s vanished after a concurrent create", name)
		}
	}
	if o.key == nil {
		return nil, fmt.Errorf("pkisvc: %s has no key", name)
	}
	return pki.LoadCA(o.chain[0], o.key)
}

// loadCA returns the stored CA or nil when it does not exist.
func (s *Service) loadCA(ctx context.Context, p store.PKI, name string) (*pki.CA, error) {
	o, err := s.get(ctx, p, name)
	if err != nil || o == nil {
		return nil, err
	}
	if o.key == nil {
		return nil, fmt.Errorf("pkisvc: %s has no key", name)
	}
	return pki.LoadCA(o.chain[0], o.key)
}

// issueLeaf issues a server or client certificate from ca and returns the
// chain [leaf, ca] and the key.
func (s *Service) issueLeaf(ca *pki.CA, usage x509.ExtKeyUsage, names []string) ([]*x509.Certificate, crypto.Signer, error) {
	key, err := pki.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	dns, ips := splitNames(names)
	opts := pki.LeafOptions{
		CommonName:  names[0],
		DNSNames:    dns,
		IPAddresses: ips,
		NotBefore:   s.now().Add(-backdate),
		Lifetime:    s.cfg.LeafLifetime,
	}
	var cert *x509.Certificate
	if usage == x509.ExtKeyUsageClientAuth {
		cert, err = ca.IssueClient(&key.PublicKey, opts)
	} else {
		cert, err = ca.IssueServer(&key.PublicKey, opts)
	}
	if err != nil {
		return nil, nil, err
	}
	return []*x509.Certificate{cert, ca.Cert}, key, nil
}

// needsRenewal reports whether an automatic leaf must be reissued: past two
// thirds of its lifetime, not issued by ca, or with other names than
// configured.
func (s *Service) needsRenewal(o *object, ca *pki.CA, names []string) bool {
	leaf := o.chain[0]
	if len(o.chain) != 2 || !o.chain[1].Equal(ca.Cert) || leaf.CheckSignatureFrom(ca.Cert) != nil {
		return true
	}
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	if !s.now().Before(leaf.NotBefore.Add(life * 2 / 3)) {
		return true
	}
	want := slices.Clone(names)
	have := certNames(leaf)
	slices.Sort(want)
	slices.Sort(have)
	return !slices.Equal(want, have)
}

// ensureAutoLeaf issues or renews an automatic leaf when the endpoint is in
// automatic mode. The leaf is read before the mode so that a concurrent
// switch to manual mode makes the versioned write fail instead of
// overwriting the manual certificate.
func (s *Service) ensureAutoLeaf(ctx context.Context, endpoint store.TLSEndpoint, leafName, caName string, usage x509.ExtKeyUsage, names []string) error {
	o, err := s.get(ctx, s.st, leafName)
	if err != nil {
		return err
	}
	set, err := s.st.GetTLSSetting(ctx, endpoint)
	if err != nil {
		return err
	}
	if set.Mode != store.TLSModeAuto {
		return nil
	}
	ca, err := s.loadCA(ctx, s.st, caName)
	if err != nil {
		return err
	}
	if ca == nil {
		return fmt.Errorf("pkisvc: %s is missing in automatic mode", caName)
	}
	if o != nil && !s.needsRenewal(o, ca, names) {
		return nil
	}
	chain, key, err := s.issueLeaf(ca, usage, names)
	if err != nil {
		return err
	}
	var expect int64
	if o != nil {
		expect = o.version
	}
	_, err = s.put(ctx, s.st, leafName, chain, key, store.PKIStateActive, expect)
	if errors.Is(err, store.ErrConflict) {
		return nil // another replica wrote it first
	}
	if err != nil {
		return err
	}
	s.log.Info("issued TLS certificate", "name", leafName, "expires_at", chain[0].NotAfter)
	return nil
}

// Bootstrap creates whatever is missing and loads the snapshot: the Agent
// CA always, the web CA and certificate when Web/API TLS is on and
// automatic, and the Agent TLS CA, anchor and certificates when Agent TLS is
// automatic. It is safe to run on several replicas at once.
func (s *Service) Bootstrap(ctx context.Context) error {
	if _, err := s.ensureCA(ctx, s.st, store.PKIAgentCA); err != nil {
		return err
	}
	if s.cfg.WebTLS {
		set, err := s.st.GetTLSSetting(ctx, store.TLSEndpointWeb)
		if err != nil {
			return err
		}
		if set.Mode == store.TLSModeAuto {
			if _, err := s.ensureCA(ctx, s.st, store.PKIWebCA); err != nil {
				return err
			}
		}
	}
	set, err := s.st.GetTLSSetting(ctx, store.TLSEndpointAgent)
	if err != nil {
		return err
	}
	if set.Mode == store.TLSModeAuto {
		ca, err := s.ensureCA(ctx, s.st, store.PKIAgentTLSCA)
		if err != nil {
			return err
		}
		anchor, err := s.get(ctx, s.st, ObjAgentTLSAnchor)
		if err != nil {
			return err
		}
		if anchor == nil {
			_, err := s.put(ctx, s.st, ObjAgentTLSAnchor, []*x509.Certificate{ca.Cert}, nil, store.PKIStateActive, 0)
			if err != nil && !errors.Is(err, store.ErrConflict) {
				return err
			}
		}
	}
	return s.Maintain(ctx)
}

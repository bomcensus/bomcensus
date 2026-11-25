// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package session

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ErrCSRF is returned by CheckCSRF for a request that may come from another
// site.
var ErrCSRF = errors.New("auth: cross-site request rejected")

// CSRFHeader and CSRFHeaderValue must be sent by the console client on every
// request that is not GET, HEAD or OPTIONS.
const (
	CSRFHeader      = "X-Requested-With"
	CSRFHeaderValue = "bomcensus"
)

// CheckCSRF rejects state-changing requests that may have been made by a
// page of another origin.
//
// The session cookie is SameSite=Strict, so a cross-site request does not
// carry it. These checks are a second layer for what SameSite does not
// cover (another origin on the same site, browsers that ignore the
// attribute) and they also protect the login request itself:
//
//   - GET, HEAD and OPTIONS are not checked; they never change state.
//   - When an Origin header is present, its host must equal the request host.
//     Otherwise, when a Referer header is present, its host must equal the
//     request host. A request with neither (a non-browser client) passes this
//     step.
//   - The request must carry "X-Requested-With: bomcensus". A page of another
//     origin cannot add a custom header without a CORS preflight, and the
//     server never answers preflights, so a forged form or fetch fails here.
//
// The request host is the Host header, or X-Forwarded-Host when the service
// trusts a proxy.
func (s *Service) CheckCSRF(r *http.Request) error {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return nil
	}
	host := s.requestHost(r)
	if origin := r.Header.Get("Origin"); origin != "" {
		if !sameHost(origin, host) {
			return fmt.Errorf("%w: origin does not match host", ErrCSRF)
		}
	} else if ref := r.Header.Get("Referer"); ref != "" {
		if !sameHost(ref, host) {
			return fmt.Errorf("%w: referer does not match host", ErrCSRF)
		}
	}
	if r.Header.Get(CSRFHeader) != CSRFHeaderValue {
		return fmt.Errorf("%w: missing %s header", ErrCSRF, CSRFHeader)
	}
	return nil
}

// sameHost reports whether the URL raw refers to host. Default ports are
// ignored on both sides.
func sameHost(raw, host string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return normalizeHost(u.Host, u.Scheme) == normalizeHost(host, u.Scheme)
}

func normalizeHost(h, scheme string) string {
	h = strings.ToLower(h)
	switch {
	case scheme == "https" && strings.HasSuffix(h, ":443"):
		h = strings.TrimSuffix(h, ":443")
	case scheme == "http" && strings.HasSuffix(h, ":80"):
		h = strings.TrimSuffix(h, ":80")
	}
	return h
}

// Copyright (C) 2026 JC-Lab
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-bomcensus-Commercial
// Additional terms apply. See LICENSING.md.

package adminapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	gen "github.com/bomcensus/bomcensus/internal/gen/adminapi"
	"github.com/bomcensus/bomcensus/internal/server/adminapi/inventoryapi"
	"github.com/bomcensus/bomcensus/internal/server/auth"
	"github.com/bomcensus/bomcensus/internal/server/store"
)

type memSessions struct {
	mu sync.Mutex
	m  map[string]store.Session
}

func (s *memSessions) CreateSession(_ context.Context, pid, pname string, exp time.Time) (store.Session, error) {
	var b [32]byte
	_, _ = rand.Read(b[:])
	ss := store.Session{ID: base64.RawURLEncoding.EncodeToString(b[:]), PrincipalID: pid, PrincipalName: pname, ExpiresAt: exp}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[ss.ID] = ss
	return ss, nil
}

func (s *memSessions) GetSession(_ context.Context, id string, now time.Time) (store.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss, ok := s.m[id]
	if !ok || !ss.ExpiresAt.After(now) {
		return store.Session{}, store.ErrNotFound
	}
	return ss, nil
}

func (s *memSessions) DeleteSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
	return nil
}

func (s *memSessions) DeleteExpiredSessions(context.Context, time.Time) (int64, error) { return 0, nil }

type adminOnly struct{}

func (adminOnly) Authenticate(_ context.Context, u, p string) (auth.Principal, error) {
	if u == "admin" && p == "secret" {
		return auth.Principal{ID: "env:admin", Name: "admin"}, nil
	}
	return auth.Principal{}, auth.ErrInvalidCredentials
}

type stub struct{ gen.StrictServerInterface }

// testAPI serves auth and meta through inventoryapi and fakes a few other
// operations.
type testAPI struct {
	*inventoryapi.Handlers
	stub
}

// GetAsset returns the error named by the id.
func (testAPI) GetAsset(_ context.Context, req gen.GetAssetRequestObject) (gen.GetAssetResponseObject, error) {
	switch req.Id {
	case "missing":
		return nil, fmt.Errorf("postgres: get asset: %w", store.ErrNotFound)
	case "invalid":
		return nil, fmt.Errorf("postgres: get asset: %w", store.ErrInvalid)
	case "in-use":
		return nil, store.ErrInUse
	case "state":
		return nil, store.ErrInvalidState
	case "conflict":
		return nil, store.ErrConflict
	case "boom":
		return nil, fmt.Errorf("connection reset by peer at 10.1.2.3")
	case "panic":
		panic("handler bug")
	}
	return gen.GetAsset200JSONResponse{Id: req.Id, Tags: []string{}, Sections: []gen.SectionCoverage{}, Containers: []gen.AssetContainer{}}, nil
}

// UploadRelease reads the whole body.
func (testAPI) UploadRelease(_ context.Context, req gen.UploadReleaseRequestObject) (gen.UploadReleaseResponseObject, error) {
	for {
		p, err := req.Body.NextPart()
		if err == io.EOF {
			return gen.UploadRelease201JSONResponse{}, nil
		}
		if err != nil {
			return nil, err
		}
		if _, err := io.Copy(io.Discard, p); err != nil {
			return nil, err
		}
	}
}

var testConsole = fstest.MapFS{
	"index.html":        {Data: []byte("index")},
	"200.html":          {Data: []byte("spa")},
	"_nuxt/app.123.js":  {Data: []byte("js")},
	"assets/index.html": {Data: []byte("assets page")},
	"favicon.ico":       {Data: []byte("ico")},
}

func newTestRouter(t *testing.T, mod func(*Options)) http.Handler {
	t.Helper()
	svc := auth.NewService(auth.Config{Provider: adminOnly{}, Sessions: &memSessions{m: map[string]store.Session{}}})
	h := inventoryapi.New(inventoryapi.Config{Auth: svc})
	o := Options{Handlers: testAPI{Handlers: h}, Auth: svc, Console: testConsole}
	if mod != nil {
		mod(&o)
	}
	return NewRouter(o)
}

type call struct {
	method, path, body string
	cookie             *http.Cookie
	headers            map[string]string
}

func do(h http.Handler, c call) *httptest.ResponseRecorder {
	var body io.Reader
	if c.body != "" {
		body = strings.NewReader(c.body)
	}
	r := httptest.NewRequest(c.method, c.path, body)
	if c.body != "" && r.Header.Get("Content-Type") == "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.method != http.MethodGet && c.method != http.MethodHead {
		r.Header.Set(auth.CSRFHeader, auth.CSRFHeaderValue)
	}
	for k, v := range c.headers {
		r.Header.Set(k, v)
	}
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var e gen.Error
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("error body %q: %v", w.Body.String(), err)
	}
	if e.Message == "" {
		t.Fatalf("error without message: %q", w.Body.String())
	}
	return e.Code
}

func login(t *testing.T, h http.Handler) *http.Cookie {
	t.Helper()
	w := do(h, call{method: http.MethodPost, path: "/api/v1/auth/login", body: `{"username":"admin","password":"secret"}`})
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	cs := w.Result().Cookies()
	if len(cs) != 1 || cs[0].Name != auth.CookieName || !cs[0].HttpOnly || cs[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("login cookie: %+v", cs)
	}
	return cs[0]
}

func TestAuthRequired(t *testing.T) {
	h := newTestRouter(t, nil)
	for _, c := range []call{
		{method: http.MethodGet, path: "/api/v1/meta"},
		{method: http.MethodGet, path: "/api/v1/auth/me"},
		{method: http.MethodGet, path: "/api/v1/assets/x"},
		{method: http.MethodPost, path: "/api/v1/auth/logout"},
		{method: http.MethodGet, path: "/api/v1/meta", cookie: &http.Cookie{Name: auth.CookieName, Value: strings.Repeat("A", 43)}},
	} {
		w := do(h, c)
		if w.Code != http.StatusUnauthorized || errCode(t, w) != "unauthenticated" {
			t.Errorf("%s %s: %d %s", c.method, c.path, w.Code, w.Body)
		}
	}
}

func TestLoginFlow(t *testing.T) {
	h := newTestRouter(t, nil)
	w := do(h, call{method: http.MethodPost, path: "/api/v1/auth/login", body: `{"username":"admin","password":"wrong"}`})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", w.Code)
	}
	w = do(h, call{method: http.MethodPost, path: "/api/v1/auth/login", body: `{"username":"admin"`})
	if w.Code != http.StatusBadRequest || errCode(t, w) != "invalid_argument" {
		t.Fatalf("bad json: %d %s", w.Code, w.Body)
	}

	cookie := login(t, h)
	w = do(h, call{method: http.MethodGet, path: "/api/v1/auth/me", cookie: cookie})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"env:admin"`) {
		t.Fatalf("me: %d %s", w.Code, w.Body)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("api Cache-Control %q", cc)
	}
	w = do(h, call{method: http.MethodGet, path: "/api/v1/meta", cookie: cookie})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"sbomExport":false`) {
		t.Fatalf("meta: %d %s", w.Code, w.Body)
	}

	w = do(h, call{method: http.MethodPost, path: "/api/v1/auth/logout", cookie: cookie})
	if w.Code != http.StatusNoContent || !strings.Contains(w.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("logout: %d %q", w.Code, w.Header().Get("Set-Cookie"))
	}
	if w = do(h, call{method: http.MethodGet, path: "/api/v1/meta", cookie: cookie}); w.Code != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", w.Code)
	}
}

func TestLoginThrottle(t *testing.T) {
	h := newTestRouter(t, nil)
	for i := 0; i < 5; i++ {
		do(h, call{method: http.MethodPost, path: "/api/v1/auth/login", body: `{"username":"admin","password":"x"}`})
	}
	w := do(h, call{method: http.MethodPost, path: "/api/v1/auth/login", body: `{"username":"admin","password":"secret"}`})
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "30" || errCode(t, w) != "too_many_requests" {
		t.Fatalf("throttle: %d %q %s", w.Code, w.Header().Get("Retry-After"), w.Body)
	}
}

func TestCSRFRejected(t *testing.T) {
	h := newTestRouter(t, nil)
	w := do(h, call{method: http.MethodPost, path: "/api/v1/auth/login", body: `{"username":"admin","password":"secret"}`,
		headers: map[string]string{auth.CSRFHeader: ""}})
	if w.Code != http.StatusForbidden || errCode(t, w) != "forbidden" {
		t.Fatalf("missing header: %d %s", w.Code, w.Body)
	}
	w = do(h, call{method: http.MethodPost, path: "/api/v1/auth/login", body: `{"username":"admin","password":"secret"}`,
		headers: map[string]string{"Origin": "https://evil.example"}})
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign origin: %d", w.Code)
	}
}

func TestErrorMapping(t *testing.T) {
	h := newTestRouter(t, nil)
	cookie := login(t, h)
	for id, want := range map[string]struct {
		status int
		code   string
	}{
		"ok":       {200, ""},
		"missing":  {404, "not_found"},
		"invalid":  {400, "invalid_argument"},
		"in-use":   {409, "in_use"},
		"state":    {409, "invalid_state"},
		"conflict": {409, "conflict"},
		"boom":     {500, "internal"},
		"panic":    {500, "internal"},
	} {
		w := do(h, call{method: http.MethodGet, path: "/api/v1/assets/" + id, cookie: cookie})
		if w.Code != want.status {
			t.Errorf("%s: status %d", id, w.Code)
			continue
		}
		if want.code != "" && errCode(t, w) != want.code {
			t.Errorf("%s: body %s", id, w.Body)
		}
		if strings.Contains(w.Body.String(), "postgres") || strings.Contains(w.Body.String(), "10.1.2.3") {
			t.Errorf("%s: internal detail leaked: %s", id, w.Body)
		}
	}
	w := do(h, call{method: http.MethodGet, path: "/api/v1/assets?limit=abc", cookie: cookie})
	if w.Code != http.StatusBadRequest || errCode(t, w) != "invalid_argument" {
		t.Errorf("bad parameter: %d %s", w.Code, w.Body)
	}
}

func TestNotFoundAndConsole(t *testing.T) {
	h := newTestRouter(t, nil)
	cookie := login(t, h)
	for _, p := range []string{"/api/v1/nope", "/api/v2/assets", "/api", "/api/"} {
		w := do(h, call{method: http.MethodGet, path: p, cookie: cookie})
		if w.Code != http.StatusNotFound || errCode(t, w) != "not_found" {
			t.Errorf("%s: %d %s", p, w.Code, w.Body)
		}
	}
	w := do(h, call{method: http.MethodDelete, path: "/api/v1/meta", cookie: cookie})
	if w.Code != http.StatusMethodNotAllowed || errCode(t, w) != "method_not_allowed" {
		t.Errorf("method: %d %s", w.Code, w.Body)
	}

	for _, c := range []struct {
		path, body, cache string
		status            int
	}{
		{"/", "index", "no-cache", 200},
		{"/favicon.ico", "ico", "no-cache", 200},
		{"/_nuxt/app.123.js", "js", "public, max-age=31536000, immutable", 200},
		{"/assets", "assets page", "no-cache", 200},
		{"/assets/0190-abc", "spa", "no-cache", 200},
		{"/k8s/clusters/x/workloads", "spa", "no-cache", 200},
		{"/../../etc/passwd", "spa", "no-cache", 200},
		{"/_nuxt/missing.js", "", "", 404},
	} {
		w := do(h, call{method: http.MethodGet, path: c.path})
		if w.Code != c.status {
			t.Errorf("%s: status %d", c.path, w.Code)
			continue
		}
		if c.status == 200 && (w.Body.String() != c.body || w.Header().Get("Cache-Control") != c.cache) {
			t.Errorf("%s: body %q cache %q", c.path, w.Body, w.Header().Get("Cache-Control"))
		}
	}
	if ct := do(h, call{method: http.MethodGet, path: "/x"}).Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("fallback content type %q", ct)
	}
	if w := do(h, call{method: http.MethodPost, path: "/assets"}); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("console POST: %d", w.Code)
	}

	noConsole := newTestRouter(t, func(o *Options) { o.Console = nil })
	if w := do(noConsole, call{method: http.MethodGet, path: "/"}); w.Code != http.StatusNotFound {
		t.Errorf("no console: %d", w.Code)
	}
}

func multipartBody(size int) (string, string) {
	const boundary = "xxBOUNDARYxx"
	var b strings.Builder
	b.WriteString("--" + boundary + "\r\nContent-Disposition: form-data; name=\"bundle\"; filename=\"b.tar\"\r\n\r\n")
	b.WriteString(strings.Repeat("a", size))
	b.WriteString("\r\n--" + boundary + "--\r\n")
	return b.String(), "multipart/form-data; boundary=" + boundary
}

func TestBodyLimit(t *testing.T) {
	h := newTestRouter(t, func(o *Options) { o.MaxBodyBytes = 1024; o.MaxUploadBytes = 64 << 10 })
	big := `{"username":"admin","password":"` + strings.Repeat("x", 2000) + `"}`
	w := do(h, call{method: http.MethodPost, path: "/api/v1/auth/login", body: big})
	if w.Code != http.StatusRequestEntityTooLarge || errCode(t, w) != "payload_too_large" {
		t.Fatalf("login body: %d %s", w.Code, w.Body)
	}

	cookie := login(t, h)
	body, ct := multipartBody(32 << 10)
	w = do(h, call{method: http.MethodPost, path: "/api/v1/releases", body: body, cookie: cookie,
		headers: map[string]string{"Content-Type": ct}})
	if w.Code != http.StatusCreated {
		t.Fatalf("upload under the upload limit: %d %s", w.Code, w.Body)
	}
	body, ct = multipartBody(128 << 10)
	w = do(h, call{method: http.MethodPost, path: "/api/v1/releases", body: body, cookie: cookie,
		headers: map[string]string{"Content-Type": ct}})
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("upload over the limit: %d %s", w.Code, w.Body)
	}

	// Without Content-Length the limit applies while reading.
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", io.MultiReader(strings.NewReader(big)))
	r.ContentLength = -1
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(auth.CSRFHeader, auth.CSRFHeaderValue)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("streamed body: %d %s", rec.Code, rec.Body)
	}
}

package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/opentooling/rhcl-probe/internal/service"
)

func TestLimitOutcome(t *testing.T) {
	l := Limit{Count: 3, Window: Duration{10 * time.Second}}
	if o := limitOutcome(l, []int{200, 200, 200, 429, 429}); o.Status != Pass {
		t.Fatalf("exact limit: %+v", o)
	}
	if o := limitOutcome(l, []int{200, 200, 200, 200, 429}); o.Status != Fail {
		t.Fatalf("limit too high passed: %+v", o)
	}
	if o := limitOutcome(l, []int{200, 429, 429, 429}); o.Status != Fail {
		t.Fatalf("limit hit early passed: %+v", o)
	}
}

func TestSplitOutcome(t *testing.T) {
	seq := func(v2Every int) (func() Resp, func(Resp) string) {
		i := 0
		return func() Resp {
				i++
				v := "v1"
				if v2Every > 0 && i%v2Every == 0 {
					v = "v2"
				}
				return Resp{Status: 200, Hop: &service.Hop{Service: "catalog", Version: v}}
			}, func(r Resp) string {
				return r.Hop.Version
			}
	}
	send, ver := seq(10)
	if o := splitOutcome(10, 60, send, ver); o.Status != Pass {
		t.Fatalf("10%%: %+v", o)
	}
	send, ver = seq(0)
	if o := splitOutcome(10, 60, send, ver); o.Status != Fail {
		t.Fatalf("no v2 at all passed: %+v", o)
	}
	send, ver = seq(2)
	if o := splitOutcome(10, 60, send, ver); o.Status != Fail {
		t.Fatalf("50%% passed for a 10%% split: %+v", o)
	}
}

// Every tampered signature must decode to different bytes, including when the last base64url
// character carries padding bits (an RS256 signature ending in "A" was the case that slipped).
func TestTamper(t *testing.T) {
	for i := range 2000 {
		sig := make([]byte, 256)
		rand.Read(sig)
		if i == 0 {
			sig[255] = 0 // encodes to a final "A"
		}
		token := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0." + base64.RawURLEncoding.EncodeToString(sig)
		parts := strings.Split(tamper(token), ".")
		got, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil || bytes.Equal(got, sig) || parts[0] != "eyJhbGciOiJSUzI1NiJ9" || parts[1] != "eyJzdWIiOiJ4In0" {
			t.Fatalf("token %d: signature unchanged or header/payload altered", i)
		}
	}
	if tamper("not-a-jwt") == "not-a-jwt" {
		t.Fatal("non-JWT unchanged")
	}
}

func TestJUnit(t *testing.T) {
	b, err := JUnit(Report{Results: []Result{
		{ID: "a", Group: GroupGateway, Name: "one", Status: Pass},
		{ID: "b", Group: GroupGateway, Name: "two", Status: Fail, Detail: "got 200", Hint: "fix it"},
		{ID: "c", Group: GroupMesh, Name: "three", Status: Skip, Detail: "off"},
	}, Failed: 1, Skipped: 1})
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`<testsuite name="API gateway" tests="2" failures="1"`, `<failure message="got 200">fix it</failure>`, `<skipped message="off">`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in\n%s", want, s)
		}
	}
}

// fakeGateway answers like a gateway with the probe's routes and policies in place.
func fakeGateway(cfg *Config) http.Handler {
	gwPrincipal := cfg.Principal(cfg.Gateway.Namespace, cfg.Gateway.ServiceAccount)
	hop := func(w http.ResponseWriter, r *http.Request, h service.Hop) {
		h.Path, h.Caller, h.Status = r.URL.Path, gwPrincipal, 200
		json.NewEncoder(w).Encode(h)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != cfg.Gateway.Host {
			http.Error(w, "wrong host "+r.Host, http.StatusNotFound)
			return
		}
		auth := r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/locked":
			http.Error(w, "no AuthPolicy", http.StatusForbidden)
		case strings.HasPrefix(r.URL.Path, "/public"):
			hop(w, r, service.Hop{Service: "frontend"})
		case r.URL.Path == "/api":
			switch auth {
			case "APIKEY alice-key":
				hop(w, r, service.Hop{Service: "frontend", Next: &service.Hop{Service: "catalog", Version: "v1"}})
			case "APIKEY bob-key":
				if r.Method == http.MethodPost {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				hop(w, r, service.Hop{Service: "frontend"})
			default:
				http.Error(w, "unauthorized", http.StatusUnauthorized)
			}
		default:
			http.NotFound(w, r)
		}
	})
}

func testProbe(t *testing.T) *Probe {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "alice"), []byte("alice-key\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "bob"), []byte("bob-key"), 0o600)
	cfg := &Config{Release: "probe", Namespace: "rhcl-probe"}
	cfg.Gateway.Name, cfg.Gateway.Namespace, cfg.Gateway.Host = "api-gateway", "api-gateway", "probe.api.example.internal"
	cfg.Gateway.Address, cfg.Gateway.InsecureSkipVerify = "127.0.0.1", true
	cfg.Expect.DefaultDeny = true
	cfg.APIKeys.Dir = dir
	cfg.defaults()

	srv := httptest.NewTLSServer(fakeGateway(cfg))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	cfg.Gateway.HTTPSPort, _ = strconv.Atoi(port)
	p, err := New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGatewayChecks(t *testing.T) {
	p := testProbe(t)
	ctx := context.Background()
	for _, c := range []struct {
		name string
		run  func(context.Context, *Probe) Outcome
	}{
		{"tls", checkTLS},
		{"routing", checkRouting},
		{"default deny", checkDefaultDeny},
		{"no credentials", checkNoCredentials},
		{"wrong key", checkWrongKey},
		{"valid key", checkValidKey},
		{"admin writes", checkAdminWrites},
		{"gateway mtls", checkGatewayMTLS},
	} {
		if o := c.run(ctx, p); o.Status != Pass {
			t.Errorf("%s: %+v", c.name, o)
		}
	}
	// Not configured, so skipped rather than failed.
	for _, run := range []func(context.Context, *Probe) Outcome{checkRedirect, checkOIDC, checkStrict, checkEgress, checkNetworkPolicy} {
		if o := run(ctx, p); o.Status != Skip {
			t.Errorf("expected skip: %+v", o)
		}
	}
}

func TestPlatformChecksWithoutCluster(t *testing.T) {
	p := testProbe(t)
	if o := checkKuadrant(context.Background(), p); o.Status != Fail || !strings.Contains(o.Detail, "no Kubernetes API access") {
		t.Fatalf("%+v", o)
	}
}

func TestRunAndReport(t *testing.T) {
	p := testProbe(t)
	p.Checks = []Check{
		{"ok", GroupGateway, "ok", func(context.Context, *Probe) Outcome { return passf("fine") }},
		{"boom", GroupGateway, "boom", func(context.Context, *Probe) Outcome { panic("bad") }},
	}
	if !p.Run(context.Background()) {
		t.Fatal("run did not start")
	}
	r := p.Report()
	if r.Running || r.Passed != 1 || r.Failed != 1 || !strings.Contains(r.Results[1].Detail, "crashed") {
		t.Fatalf("%+v", r)
	}
}

// The config the chart renders must load, with every field the checks depend on set.
// CI renders the chart and points RENDERED_CONFIG at the result.
func TestRenderedChartConfig(t *testing.T) {
	path := os.Getenv("RENDERED_CONFIG")
	if path == "" {
		t.Skip("RENDERED_CONFIG not set")
	}
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{
		"gateway.host": c.Gateway.Host, "gateway.serviceAccount": c.Gateway.ServiceAccount,
		"services.frontend": c.Services.Frontend, "services.catalogV2": c.Services.CatalogV2,
		"services.outsider": c.Services.Outsider, "serviceAccounts.console": c.ServiceAccounts.Console,
		"serviceAccounts.catalog": c.ServiceAccounts.Catalog, "apiKeys.dir": c.APIKeys.Dir,
		"kuadrant.namespace": c.Kuadrant.Namespace,
	} {
		if v == "" {
			t.Errorf("%s is empty", name)
		}
	}
	for name, l := range map[string]Limit{"public": c.Limits.Public, "free": c.Limits.Free, "gold": c.Limits.Gold} {
		if l.Count <= 0 || l.Window.Duration <= 0 {
			t.Errorf("limit %s: %+v", name, l)
		}
	}
	if c.Routes.Timeout.Duration <= 0 || c.Routes.SplitV2Percent <= 0 || c.Mesh.SplitV2Percent <= 0 {
		t.Errorf("routes %+v, mesh %+v", c.Routes, c.Mesh)
	}
}

func TestLoadConfigRejectsUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(path, []byte(`{"gateway":{"hostname":"typo"}}`), 0o600)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(path, []byte(`{"gateway":{"name":"gw","namespace":"gwns","host":"p.example"},"limits":{"free":{"limit":3,"window":"10s"}},"routes":{"timeout":"3s"}}`), 0o600)
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Gateway.Address != "gw-istio.gwns.svc" || c.Gateway.ServiceAccount != "gw-istio" || c.Limits.Free.Window.Duration != 10*time.Second ||
		c.Routes.Timeout.Duration != 3*time.Second || c.Principal("ns", "sa") != "spiffe://cluster.local/ns/ns/sa/sa" {
		t.Fatalf("%+v", c)
	}
}

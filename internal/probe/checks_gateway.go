package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func checkTLS(ctx context.Context, p *Probe) Outcome {
	g := p.Cfg.Gateway
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if pem, err := os.ReadFile(p.Cfg.CAFile); err == nil {
		pool.AppendCertsFromPEM(pem)
	}
	conf := p.tlsConfig(pool)
	conf.ServerName = g.Host
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: conf}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(g.Address, strconv.Itoa(g.HTTPSPort)))
	if err != nil {
		var unknown x509.UnknownAuthorityError
		hint := ""
		if errors.As(err, &unknown) {
			hint = "The console doesn't trust the gateway's CA. Set trustedCA in the chart values, or add the CA to the cluster trust bundle."
		}
		return failf(hint, "%s: %v", g.Host, err)
	}
	defer conn.Close()
	cert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	issuer := cert.Issuer.String()
	if g.IssuerContains != "" && !strings.Contains(issuer, g.IssuerContains) {
		return failf("Is the TLSPolicy using the issuer you expect?", "issuer %q doesn't contain %q", issuer, g.IssuerContains)
	}
	if days < 7 {
		return failf("cert-manager should have renewed it by now.", "expires in %d days (issuer %s)", days, issuer)
	}
	verified := "verified"
	if g.InsecureSkipVerify {
		verified = "not verified (insecureSkipVerify)"
	}
	return passf("issuer %s, %d days left, %s", cert.Issuer.CommonName, days, verified)
}

func checkRedirect(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.Expect.HTTPRedirect {
		return skipf("expect.httpRedirect is off")
	}
	r := do(ctx, p.Gateway, http.MethodGet, "http://"+p.Cfg.Gateway.Host+"/public", nil)
	loc := r.Header.Get("Location")
	if r.Status != http.StatusMovedPermanently || !strings.HasPrefix(loc, "https://") {
		return failf("Is the platform's HTTP→HTTPS redirect route in place?", "got %s %s", r, loc)
	}
	return passf("301 %s", loc)
}

func checkRouting(ctx context.Context, p *Probe) Outcome {
	r := p.gw(ctx, http.MethodGet, "/public/routing", nil)
	if r.Status != http.StatusOK || r.Hop == nil || r.Hop.Service != "frontend" || r.Hop.Path != "/public/routing" {
		return failf("", "/public/routing: got %s %s", r, trim(r.Body))
	}
	miss := p.gw(ctx, http.MethodGet, "/no-such-route-"+newID(), nil)
	if miss.Status != http.StatusNotFound {
		return failf("", "unmatched path: expected 404, got %s", miss)
	}
	return passf("/public → frontend (200), unmatched path → 404")
}

func checkDefaultDeny(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.Expect.DefaultDeny {
		return skipf("expect.defaultDeny is off")
	}
	r := p.gw(ctx, http.MethodGet, "/locked", nil)
	if r.Status != http.StatusForbidden {
		return failf("Is there a deny-all AuthPolicy on the gateway?", "expected 403, got %s", r)
	}
	return passf("403 %s", trim(r.Body))
}

func checkNoCredentials(ctx context.Context, p *Probe) Outcome {
	r := p.gw(ctx, http.MethodGet, "/api", nil)
	if r.Status != http.StatusUnauthorized {
		return failf("", "expected 401, got %s", r)
	}
	return passf("401")
}

func checkWrongKey(ctx context.Context, p *Probe) Outcome {
	r := p.gw(ctx, http.MethodGet, "/api", map[string]string{"Authorization": p.Cfg.APIKeys.Prefix + " not-a-real-key"})
	if r.Status != http.StatusUnauthorized {
		return failf("", "expected 401, got %s", r)
	}
	return passf("401")
}

func (p *Probe) missingKeys() *Outcome {
	for _, u := range []string{"alice", "bob"} {
		if p.Cfg.APIKey(u) == "" {
			o := failf("The console mounts the keys from the <release>-apikeys Secret.", "no API key for %s", u)
			return &o
		}
	}
	return nil
}

func checkValidKey(ctx context.Context, p *Probe) Outcome {
	if o := p.missingKeys(); o != nil {
		return *o
	}
	r := p.gw(ctx, http.MethodGet, "/api", p.apiKey("alice"))
	if r.Status != http.StatusOK || r.Hop == nil {
		return failf("A 401 here means Authorino doesn't see the key Secret: check auth.apiKeys.namespace.", "alice: got %s %s", r, trim(r.Body))
	}
	return passf("alice: 200 via %s", chain(r))
}

func checkOIDC(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.OIDC.Enabled {
		return skipf("auth.oidc.enabled is off")
	}
	token, err := p.oidcToken(ctx)
	if err != nil {
		return failf("The console couldn't get a token from the IdP. Check the client and the trusted CA.", "%v", err)
	}
	ok := p.gw(ctx, http.MethodGet, "/api", map[string]string{"Authorization": "Bearer " + token})
	if ok.Status != http.StatusOK {
		return failf("A 401 means Authorino rejected the token. If the IdP's certificate comes from an internal CA, Authorino must trust it.",
			"valid token: got %s %s", ok, trim(ok.Body))
	}
	bad := p.gw(ctx, http.MethodGet, "/api", map[string]string{"Authorization": "Bearer " + tamper(token)})
	if bad.Status != http.StatusUnauthorized {
		return failf("", "tampered token: expected 401, got %s", bad)
	}
	return passf("valid token 200, tampered 401")
}

// tamper flips the signature's last character, so the token no longer verifies.
func tamper(token string) string {
	if token == "" {
		return "x"
	}
	last := token[len(token)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	return token[:len(token)-1] + string(repl)
}

func checkAdminWrites(ctx context.Context, p *Probe) Outcome {
	if o := p.missingKeys(); o != nil {
		return *o
	}
	bob := p.gw(ctx, http.MethodPost, "/api", p.apiKey("bob"))
	alice := p.gw(ctx, http.MethodPost, "/api", p.apiKey("alice"))
	if bob.Status != http.StatusForbidden || alice.Status != http.StatusOK {
		return failf("", "POST: bob (no group) expected 403, got %s; alice (admin) expected 200, got %s", bob, alice)
	}
	return passf("POST: bob 403, alice 200")
}

func checkGatewayMTLS(ctx context.Context, p *Probe) Outcome {
	if o := p.missingKeys(); o != nil {
		return *o
	}
	r := p.gw(ctx, http.MethodGet, "/api", p.apiKey("alice"))
	want := p.Cfg.Principal(p.Cfg.Gateway.Namespace, p.Cfg.Gateway.ServiceAccount)
	if r.Hop == nil {
		return failf("", "got %s", r)
	}
	if r.Hop.Caller != want {
		return failf("No caller identity means the hop wasn't mTLS: does the frontend pod have a sidecar?",
			"frontend saw caller %q, expected %s", r.Hop.Caller, want)
	}
	return passf("%s", want)
}

func checkHeaderMatch(ctx context.Context, p *Probe) Outcome {
	hdr := p.apiKey("alice")
	hdr["x-version"] = "v2"
	for i := range 5 {
		r := p.gw(ctx, http.MethodGet, "/split", hdr)
		if r.Hop == nil || r.Hop.Version != "v2" {
			return failf("", "request %d: got %s %s", i+1, r, version(r))
		}
	}
	return passf("5 / 5 to catalog v2")
}

func checkGatewaySplit(ctx context.Context, p *Probe) Outcome {
	return splitOutcome(p.Cfg.Routes.SplitV2Percent, 60, func() Resp {
		return p.gw(ctx, http.MethodGet, "/split", p.apiKey("alice"))
	}, func(r Resp) string { return version(r) })
}

// splitOutcome sends n requests and checks the share that reached v2 is plausible for a
// weighted split of pct percent: within four standard deviations, and never zero for pct > 0.
func splitOutcome(pct, n int, send func() Resp, versionOf func(Resp) string) Outcome {
	counts := map[string]int{}
	for range n {
		r := send()
		if r.Status != http.StatusOK {
			return failf("", "got %s %s", r, trim(r.Body))
		}
		counts[versionOf(r)]++
	}
	v2 := counts["v2"]
	exp := float64(n*pct) / 100
	sd := math.Sqrt(float64(n) * float64(pct) / 100 * (1 - float64(pct)/100))
	lo, hi := math.Max(exp-4*sd, 0), exp+4*sd
	if pct > 0 && pct < 100 {
		lo = math.Max(lo, 1)
	}
	detail := fmt.Sprintf("%d to v1, %d to v2 (target %d%% to v2)", counts["v1"], v2, pct)
	if float64(v2) < lo || float64(v2) > hi || counts["v1"]+v2 != n {
		return failf("", "%s", detail)
	}
	return passf("%s", detail)
}

func checkRewrite(ctx context.Context, p *Probe) Outcome {
	hdr := p.apiKey("alice")
	hdr["x-probe-remove"] = "please"
	r := p.gw(ctx, http.MethodGet, "/rewrite/x", hdr)
	if r.Hop == nil {
		return failf("", "got %s %s", r, trim(r.Body))
	}
	var problems []string
	if r.Hop.Path != "/echo/x" {
		problems = append(problems, fmt.Sprintf("path %q, expected /echo/x", r.Hop.Path))
	}
	if r.Hop.Headers["x-probe-added"] != "gateway" {
		problems = append(problems, "request header x-probe-added missing")
	}
	if _, ok := r.Hop.Headers["x-probe-remove"]; ok {
		problems = append(problems, "request header x-probe-remove not removed")
	}
	if r.Header.Get("x-probe-response") != "gateway" {
		problems = append(problems, "response header x-probe-response missing")
	}
	if len(problems) > 0 {
		return failf("", "%s", strings.Join(problems, "; "))
	}
	return passf("/rewrite/x → /echo/x, request header added and removed, response header added")
}

func checkMirror(ctx context.Context, p *Probe) Outcome {
	id := "mirror-" + newID()
	hdr := p.apiKey("alice")
	hdr["x-probe-id"] = id
	r := p.gw(ctx, http.MethodGet, "/mirror", hdr)
	if r.Status != http.StatusOK || r.Hop == nil || r.Hop.Version != "v1" {
		return failf("", "primary: got %s %s", r, version(r))
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		seen := p.mesh(ctx, p.Cfg.Services.CatalogV2, "/seen?id="+id, nil)
		if seen.Status == http.StatusOK && strings.Contains(seen.Body, "true") {
			return passf("answered by v1, copy reached v2")
		}
		if seen.Status == http.StatusForbidden {
			return failf("The catalog AuthorizationPolicy must allow the console on /seen.", "catalog v2 /seen: 403")
		}
		sleep(ctx, 300*time.Millisecond)
	}
	return failf("", "v1 answered, but no mirrored copy reached v2 in 5s")
}

func checkRouteTimeout(ctx context.Context, p *Probe) Outcome {
	t := p.Cfg.Routes.Timeout.Duration
	hdr := p.apiKey("alice")
	hdr["x-probe-delay"] = "frontend=" + (t + 2*time.Second).String()
	r := p.gw(ctx, http.MethodGet, "/timeout", hdr)
	if r.Status != http.StatusGatewayTimeout || r.Dur > t+1500*time.Millisecond {
		return failf("", "expected 504 after about %s, got %s after %s", t, r, r.Dur.Round(time.Millisecond))
	}
	return passf("504 after %s (timeout %s)", r.Dur.Round(10*time.Millisecond), t)
}

func checkPublicLimit(ctx context.Context, p *Probe) Outcome {
	l := p.Cfg.Limits.Public
	if err := waitWindow(ctx, l); err != nil {
		return skipf("cancelled")
	}
	codes := burst(l.Count+3, func() Resp { return p.gw(ctx, http.MethodGet, "/public", nil) })
	return limitOutcome(l, codes)
}

// limitOutcome expects the first l.Count requests through and 429 after them.
func limitOutcome(l Limit, codes []int) Outcome {
	for i, c := range codes {
		want := http.StatusOK
		if i >= l.Count {
			want = http.StatusTooManyRequests
		}
		if c != want {
			return failf("A limit that is exceeded late usually means other traffic shares the counter.",
				"limit %s: %s", l, codesString(codes))
		}
	}
	return passf("limit %s: %s", l, codesString(codes))
}

func checkPlanLimits(ctx context.Context, p *Probe) Outcome {
	if o := p.missingKeys(); o != nil {
		return *o
	}
	l := p.Cfg.Limits.Free
	if err := waitWindow(ctx, l); err != nil {
		return skipf("cancelled")
	}
	codes := burst(l.Count+3, func() Resp { return p.gw(ctx, http.MethodGet, "/api", p.apiKey("bob")) })
	out := limitOutcome(l, codes)
	if out.Status != Pass {
		out.Detail = "bob (free) " + out.Detail
		return out
	}
	alice := p.gw(ctx, http.MethodGet, "/api", p.apiKey("alice"))
	if alice.Status != http.StatusOK {
		return failf("Each caller should have its own counter.", "bob limited as expected, but alice then got %s", alice)
	}
	return passf("bob (free) %s; alice (gold) unaffected", strings.TrimPrefix(out.Detail, "limit "))
}

func chain(r Resp) string {
	var parts []string
	for h := r.Hop; h != nil; h = h.Next {
		s := h.Service
		if h.Version != "" {
			s += " " + h.Version
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, " → ")
}

func version(r Resp) string {
	if r.Hop == nil {
		return ""
	}
	return r.Hop.Version
}

func trim(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

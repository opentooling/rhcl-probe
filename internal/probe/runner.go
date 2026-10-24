// Package probe runs the checks: platform status read from the Kubernetes API, API gateway
// features exercised through the gateway, and service mesh features exercised between the
// probe's own services.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opentooling/rhcl-probe/internal/kube"
	"github.com/opentooling/rhcl-probe/internal/service"
)

type Status string

const (
	Pass Status = "pass"
	Fail Status = "fail"
	Skip Status = "skip"
)

// Groups, in the order they run and are shown.
const (
	GroupPlatform = "Platform"
	GroupGateway  = "API gateway"
	GroupMesh     = "Service mesh"
)

type Result struct {
	ID         string `json:"id"`
	Group      string `json:"group"`
	Name       string `json:"name"`
	Status     Status `json:"status"`
	Detail     string `json:"detail,omitempty"`
	Hint       string `json:"hint,omitempty"`
	DurationMs int64  `json:"durationMs"`
}

// Outcome is what a check function returns.
type Outcome struct {
	Status Status
	Detail string
	Hint   string
}

func passf(format string, a ...any) Outcome {
	return Outcome{Status: Pass, Detail: fmt.Sprintf(format, a...)}
}
func skipf(format string, a ...any) Outcome {
	return Outcome{Status: Skip, Detail: fmt.Sprintf(format, a...)}
}
func failf(hint, format string, a ...any) Outcome {
	return Outcome{Status: Fail, Detail: fmt.Sprintf(format, a...), Hint: hint}
}

type Check struct {
	ID    string
	Group string
	Name  string
	Run   func(ctx context.Context, p *Probe) Outcome
}

type Report struct {
	Running    bool      `json:"running"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt,omitzero"`
	DurationMs int64     `json:"durationMs"`
	Results    []Result  `json:"results"`
	Passed     int       `json:"passed"`
	Failed     int       `json:"failed"`
	Skipped    int       `json:"skipped"`
	Total      int       `json:"total"`
}

// Probe holds the clients the checks use, and the latest report.
type Probe struct {
	Cfg  *Config
	Kube *kube.Client
	// Gateway dials the gateway for the probe's hostname and verifies its certificate.
	Gateway *http.Client
	// Mesh calls the probe's services directly; the console's sidecar makes those calls mTLS.
	Mesh   *http.Client
	Checks []Check

	mu     sync.Mutex
	report Report
	token  cachedToken
}

func New(cfg *Config, kc *kube.Client) (*Probe, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		if pem, err := os.ReadFile(cfg.CAFile); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	p := &Probe{Cfg: cfg, Kube: kc}
	p.Gateway = &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext:         p.dialGateway,
			TLSClientConfig:     p.tlsConfig(pool),
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     20 * time.Second,
		},
	}
	p.Mesh = &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{MaxIdleConnsPerHost: 8, IdleConnTimeout: 20 * time.Second, TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	p.Checks = AllChecks()
	return p, nil
}

func (p *Probe) tlsConfig(pool *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: pool, InsecureSkipVerify: p.Cfg.Gateway.InsecureSkipVerify} //nolint:gosec // opt-in
}

// dialGateway sends the probe's hostname to the gateway's address, like curl --resolve,
// so the checks need no DNS record and always reach the gateway under test.
func (p *Probe) dialGateway(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == p.Cfg.Gateway.Host {
		switch port {
		case "443":
			port = strconv.Itoa(p.Cfg.Gateway.HTTPSPort)
		case "80":
			port = strconv.Itoa(p.Cfg.Gateway.HTTPPort)
		}
		addr = net.JoinHostPort(p.Cfg.Gateway.Address, port)
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
}

// Run executes every check in order. Only one run at a time; a second call returns false.
func (p *Probe) Run(ctx context.Context) bool {
	p.mu.Lock()
	if p.report.Running {
		p.mu.Unlock()
		return false
	}
	p.report = Report{Running: true, StartedAt: time.Now(), Total: len(p.Checks)}
	p.mu.Unlock()

	for _, c := range p.Checks {
		start := time.Now()
		out := p.safeRun(ctx, c)
		res := Result{ID: c.ID, Group: c.Group, Name: c.Name, Status: out.Status, Detail: out.Detail, Hint: out.Hint,
			DurationMs: time.Since(start).Milliseconds()}
		p.mu.Lock()
		p.report.Results = append(p.report.Results, res)
		switch res.Status {
		case Pass:
			p.report.Passed++
		case Fail:
			p.report.Failed++
		default:
			p.report.Skipped++
		}
		p.mu.Unlock()
	}
	p.mu.Lock()
	p.report.Running = false
	p.report.FinishedAt = time.Now()
	p.report.DurationMs = p.report.FinishedAt.Sub(p.report.StartedAt).Milliseconds()
	p.mu.Unlock()
	return true
}

func (p *Probe) safeRun(ctx context.Context, c Check) (out Outcome) {
	defer func() {
		if r := recover(); r != nil {
			out = failf("", "check crashed: %v", r)
		}
	}()
	if ctx.Err() != nil {
		return skipf("run cancelled")
	}
	return c.Run(ctx, p)
}

// Report returns a copy of the current (or last) report.
func (p *Probe) Report() Report {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := p.report
	r.Results = append([]Result(nil), p.report.Results...)
	return r
}

// --- HTTP helpers ------------------------------------------------------------------------------

// Resp is one request's outcome. Hop is set when the answer came from one of the probe's services.
type Resp struct {
	Status int
	Header http.Header
	Body   string
	Hop    *service.Hop
	Dur    time.Duration
	Err    error
}

func (r Resp) String() string {
	if r.Err != nil {
		return "error: " + r.Err.Error()
	}
	return strconv.Itoa(r.Status)
}

func do(ctx context.Context, c *http.Client, method, target string, hdr map[string]string) Resp {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return Resp{Err: err}
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return Resp{Err: err, Dur: time.Since(start)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out := Resp{Status: resp.StatusCode, Header: resp.Header, Body: strings.TrimSpace(string(body)), Dur: time.Since(start)}
	var hop service.Hop
	if json.Unmarshal(body, &hop) == nil && hop.Service != "" {
		out.Hop = &hop
	}
	return out
}

// gw sends a request through the gateway to a path on the probe's hostname.
func (p *Probe) gw(ctx context.Context, method, path string, hdr map[string]string) Resp {
	return do(ctx, p.Gateway, method, p.Cfg.URL(path), hdr)
}

// mesh calls one of the probe's services directly.
func (p *Probe) mesh(ctx context.Context, base, path string, hdr map[string]string) Resp {
	return do(ctx, p.Mesh, http.MethodGet, strings.TrimSuffix(base, "/")+path, hdr)
}

// fromOutsider asks the outsider (a pod with no sidecar) to call a URL.
func (p *Probe) fromOutsider(ctx context.Context, target string) (service.FetchResult, error) {
	r := p.mesh(ctx, p.Cfg.Services.Outsider, "/fetch?url="+url.QueryEscape(target), nil)
	if r.Err != nil {
		return service.FetchResult{}, r.Err
	}
	var fr service.FetchResult
	if err := json.Unmarshal([]byte(r.Body), &fr); err != nil || r.Status != http.StatusOK {
		return fr, fmt.Errorf("outsider answered %d: %s", r.Status, r.Body)
	}
	return fr, nil
}

func (p *Probe) apiKey(user string) map[string]string {
	return map[string]string{"Authorization": p.Cfg.APIKeys.Prefix + " " + p.Cfg.APIKey(user)}
}

// waitWindow lets a rate-limit window expire, so a limit check starts from a fresh counter.
func waitWindow(ctx context.Context, l Limit) error {
	select {
	case <-time.After(l.Window.Duration + time.Second):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

// burst sends n requests and returns their status codes.
func burst(n int, send func() Resp) []int {
	codes := make([]int, n)
	for i := range codes {
		codes[i] = send().Status
	}
	return codes
}

func codesString(codes []int) string {
	parts := make([]string, len(codes))
	for i, c := range codes {
		parts[i] = strconv.Itoa(c)
	}
	return strings.Join(parts, " ")
}

func newID() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

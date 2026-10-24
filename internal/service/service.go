// Package service is the demo app the probe sends traffic through: frontend → catalog → pricing.
// Every hop answers with what it saw (its version, the caller's mesh identity, the attempt count,
// the request ID) and the answer of the hop after it, so a check can see the whole path.
//
// Requests can ask a hop to misbehave, which is how the probe exercises retries, timeouts and
// outlier detection:
//
//	x-probe-fail: pricing=0.3       pricing answers 500 on 30% of requests
//	x-probe-delay: frontend=3s      frontend waits 3s before answering
//	x-probe-scenario: outlier       catalog calls the pricing pool that includes a faulty pod
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hop is one service's view of a request.
type Hop struct {
	Service   string            `json:"service"`
	Version   string            `json:"version,omitempty"`
	Pod       string            `json:"pod,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
	Method    string            `json:"method,omitempty"`
	Path      string            `json:"path,omitempty"`
	Host      string            `json:"host,omitempty"`
	Caller    string            `json:"caller,omitempty"`
	Attempt   int               `json:"attempt,omitempty"`
	RequestID string            `json:"requestId,omitempty"`
	Status    int               `json:"status"`
	Error     string            `json:"error,omitempty"`
	ElapsedMs int64             `json:"elapsedMs"`
	Headers   map[string]string `json:"headers,omitempty"`
	Next      *Hop              `json:"next,omitempty"`
}

// Config is one instance's role and wiring, from its environment.
type Config struct {
	Role      string // frontend, catalog, pricing or outsider
	Version   string
	Pod       string
	Namespace string
	// Next is the base URL of the hop after this one; empty for the last hop.
	Next string
	// NextOutlier replaces Next for the outlier scenario (the pool with the faulty pod).
	NextOutlier string
	// Faulty instances answer 500 to every request, for outlier detection to eject.
	Faulty bool
}

// Headers passed on to the next hop: tracing, the version selector and the probe's own controls.
var propagated = []string{
	"x-request-id", "traceparent", "tracestate", "b3",
	"x-b3-traceid", "x-b3-spanid", "x-b3-parentspanid", "x-b3-sampled", "x-b3-flags",
	"x-version",
}

type Server struct {
	cfg    Config
	client *http.Client
	rand   func() float64
	seen   *ring
}

func New(cfg Config) *Server {
	return &Server{
		cfg: cfg,
		// No client timeout: the mesh's own timeouts are what the probe tests, so they must fire first.
		client: &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 16, IdleConnTimeout: 30 * time.Second}},
		rand:   rand.Float64,
		seen:   newRing(4096),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	if s.cfg.Role == "outsider" {
		mux.HandleFunc("GET /fetch", s.fetch)
		return mux
	}
	mux.HandleFunc("GET /seen", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"seen": s.seen.has(r.URL.Query().Get("id"))})
	})
	mux.HandleFunc("/", s.serve)
	return mux
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if id := r.Header.Get("x-probe-id"); id != "" {
		s.seen.add(id)
	}
	hop := &Hop{
		Service:   s.cfg.Role,
		Version:   s.cfg.Version,
		Pod:       s.cfg.Pod,
		Namespace: s.cfg.Namespace,
		Method:    r.Method,
		Path:      r.URL.Path,
		Host:      r.Host,
		Caller:    CallerFromXFCC(r.Header.Get("x-forwarded-client-cert")),
		RequestID: r.Header.Get("x-request-id"),
		Status:    http.StatusOK,
	}
	hop.Attempt, _ = strconv.Atoi(r.Header.Get("x-envoy-attempt-count"))
	finish := func() {
		hop.ElapsedMs = time.Since(start).Milliseconds()
		w.Header().Set("x-probe-service", s.cfg.Role)
		w.Header().Set("x-probe-version", s.cfg.Version)
		writeJSON(w, hop.Status, hop)
	}

	if v, ok := Directive(r.Header.Get("x-probe-delay"), s.cfg.Role); ok {
		if d, err := time.ParseDuration(v); err == nil {
			select {
			case <-time.After(d):
			case <-r.Context().Done():
				return
			}
		}
	}
	if s.cfg.Faulty {
		hop.Status, hop.Error = http.StatusInternalServerError, "faulty instance"
		finish()
		return
	}
	if v, ok := Directive(r.Header.Get("x-probe-fail"), s.cfg.Role); ok {
		if p, err := strconv.ParseFloat(v, 64); err == nil && s.rand() < p {
			hop.Status, hop.Error = http.StatusInternalServerError, "injected failure"
			finish()
			return
		}
	}
	// /echo shows the request as this hop received it, for rewrite and header checks.
	if strings.HasPrefix(r.URL.Path, "/echo") {
		hop.Headers = flatten(r.Header)
		finish()
		return
	}

	next := s.cfg.Next
	if r.Header.Get("x-probe-scenario") == "outlier" && s.cfg.NextOutlier != "" {
		next = s.cfg.NextOutlier
	}
	if next != "" {
		hop.Next = s.call(r, next)
		// 502, not the upstream's own code: the mesh retries 503 by default, which would hide
		// the failure the probe is trying to observe one hop further down.
		if hop.Next.Status >= 400 || hop.Next.Status == 0 {
			hop.Status = http.StatusBadGateway
		}
	}
	finish()
}

// call forwards the request to the next hop and returns that hop's view, or what went wrong.
func (s *Server) call(in *http.Request, base string) *Hop {
	start := time.Now()
	req, err := http.NewRequestWithContext(in.Context(), in.Method, strings.TrimSuffix(base, "/")+"/", nil)
	if err != nil {
		return &Hop{Service: base, Error: err.Error()}
	}
	for _, h := range propagated {
		if v := in.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	for k, vs := range in.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-probe-") {
			req.Header[k] = vs
		}
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return &Hop{Service: base, Error: err.Error(), ElapsedMs: time.Since(start).Milliseconds()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var hop Hop
	if json.Unmarshal(body, &hop) != nil || hop.Service == "" {
		// Not one of ours: the sidecar answered (fault abort, RBAC denial, timeout).
		hop = Hop{Service: base, Error: strings.TrimSpace(string(body))}
	}
	hop.Status = resp.StatusCode
	if hop.ElapsedMs == 0 {
		hop.ElapsedMs = time.Since(start).Milliseconds()
	}
	return &hop
}

// FetchResult is what the outsider saw when it called a URL.
type FetchResult struct {
	URL       string `json:"url"`
	Status    int    `json:"status,omitempty"`
	ErrorKind string `json:"errorKind,omitempty"` // timeout, reset, refused, dns or other
	Error     string `json:"error,omitempty"`
	ElapsedMs int64  `json:"elapsedMs"`
}

// fetch lets the probe call a service from a pod outside the mesh, to see what NetworkPolicies
// and STRICT mTLS do to traffic that doesn't come from a sidecar. Only in-cluster targets.
func (s *Server) fetch(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "http" || !InCluster(u.Hostname()) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "url must be http:// to a cluster Service"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	start := time.Now()
	res := FetchResult{URL: target}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	resp, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}}).Do(req)
	res.ElapsedMs = time.Since(start).Milliseconds()
	if err != nil {
		res.ErrorKind, res.Error = ClassifyError(err), err.Error()
	} else {
		resp.Body.Close()
		res.Status = resp.StatusCode
	}
	writeJSON(w, http.StatusOK, res)
}

// InCluster accepts a Service name, <svc>.<ns>, or a name under .svc / .svc.cluster.local.
func InCluster(host string) bool {
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	if strings.Count(host, ".") <= 1 {
		return true
	}
	return strings.HasSuffix(host, ".svc") || strings.HasSuffix(host, ".svc.cluster.local")
}

// ClassifyError tells a NetworkPolicy drop (timeout) from an mTLS rejection (reset) and the rest.
func ClassifyError(err error) string {
	var ne net.Error
	msg := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return "timeout"
	case strings.Contains(msg, "connection reset"), strings.Contains(msg, "EOF"), strings.Contains(msg, "broken pipe"):
		return "reset"
	case strings.Contains(msg, "connection refused"):
		return "refused"
	case strings.Contains(msg, "no such host"):
		return "dns"
	}
	return "other"
}

// Directive reads "role=value" pairs ("pricing=0.3, catalog=1") and returns the value for role.
func Directive(header, role string) (string, bool) {
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.TrimSpace(k) == role {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

// CallerFromXFCC returns the SPIFFE ID of the immediate caller from an X-Forwarded-Client-Cert
// header: the URI field of its last element, which the receiving sidecar appended.
func CallerFromXFCC(xfcc string) string {
	if xfcc == "" {
		return ""
	}
	elements := splitOutsideQuotes(xfcc, ',')
	for _, field := range splitOutsideQuotes(elements[len(elements)-1], ';') {
		if k, v, ok := strings.Cut(strings.TrimSpace(field), "="); ok && strings.EqualFold(k, "URI") {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func splitOutsideQuotes(s string, sep rune) []string {
	var out []string
	var b strings.Builder
	quoted, escaped := false, false
	for _, c := range s {
		switch {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			quoted = !quoted
		case c == sep && !quoted:
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteRune(c)
	}
	return append(out, b.String())
}

func flatten(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		fmt.Println("write response:", err)
	}
}

// ring remembers the last n probe request IDs, so a check can ask whether a mirrored copy arrived.
type ring struct {
	mu    sync.Mutex
	ids   map[string]struct{}
	order []string
	next  int
}

func newRing(n int) *ring { return &ring{ids: make(map[string]struct{}, n), order: make([]string, n)} }

func (r *ring) add(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.ids[id]; ok {
		return
	}
	delete(r.ids, r.order[r.next])
	r.order[r.next] = id
	r.ids[id] = struct{}{}
	r.next = (r.next + 1) % len(r.order)
}

func (r *ring) has(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.ids[id]
	return ok && id != ""
}

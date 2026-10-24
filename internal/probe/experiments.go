package probe

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
)

// Sample is one request of an experiment, as the console shows it: a short label and a tone.
type Sample struct {
	Status int    `json:"status"`
	Label  string `json:"label"`
	Tone   string `json:"tone"` // ok, warn, bad or info
	Ms     int64  `json:"ms"`
}

type ExperimentResult struct {
	Name    string   `json:"name"`
	Samples []Sample `json:"samples"`
	Summary string   `json:"summary"`
}

type Experiment struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Config      string `json:"config"`
	run         func(ctx context.Context, p *Probe, n int) ExperimentResult
}

// Experiments are the hands-on side of the checks: send n requests, show each result.
func (p *Probe) Experiments() []Experiment {
	c := p.Cfg
	return []Experiment{
		{"gateway-split", "Gateway split", fmt.Sprintf("The gateway sends %d%% of /split to catalog v2. A request with x-version: v2 always goes there.", c.Routes.SplitV2Percent),
			"HTTPRoute backendRefs: catalog-v1, catalog-v2 by weight", expGatewaySplit},
		{"mesh-split", "Mesh split", fmt.Sprintf("frontend's sidecar sends %d%% of calls to catalog v2.", c.Mesh.SplitV2Percent),
			"VirtualService catalog: subsets v1 and v2 by weight", expMeshSplit},
		{"retry", "Retries", "pricing fails 30% of requests. catalog's sidecar retries, so the caller still sees 200.",
			"x-probe-fail: pricing=0.3 · retries: attempts 8, retryOn 5xx", expRetry},
		{"fault-abort", "Fault abort", "catalog's sidecar aborts half the calls to pricing with 503, before they leave the pod.",
			"fault.abort: 50%, httpStatus 503", expFaultAbort},
		{"fault-delay", "Fault delay", "catalog's sidecar holds every call to pricing for 1s.",
			"fault.delay: 100%, fixedDelay 1s", expFaultDelay},
		{"outlier", "Circuit breaker", "One pricing pod always fails. After 3 errors in a row, catalog's sidecar ejects it for 30s.",
			"outlierDetection: consecutive5xxErrors 3, baseEjectionTime 30s", expOutlier},
		{"authz", "Authorization", "The console calls catalog directly. Only frontend and the gateway may, so the sidecar answers 403.",
			"AuthorizationPolicy catalog: from frontend and the gateway", expAuthz},
		{"rate-limit", "Rate limit", fmt.Sprintf("bob is on the free plan: %s.", c.Limits.Free),
			"RateLimitPolicy: counter auth.identity.userid, by plan", expRateLimit},
	}
}

// RunExperiment runs one experiment by name.
func (p *Probe) RunExperiment(ctx context.Context, name string, n int) (ExperimentResult, bool) {
	n = max(1, min(n, 60))
	for _, e := range p.Experiments() {
		if e.Name == name {
			res := e.run(ctx, p, n)
			res.Name = name
			return res, true
		}
	}
	return ExperimentResult{}, false
}

func sample(r Resp, label, tone string) Sample {
	return Sample{Status: r.Status, Label: label, Tone: tone, Ms: r.Dur.Milliseconds()}
}

func versionSamples(n int, send func(i int) Resp, versionOf func(Resp) string) ExperimentResult {
	var res ExperimentResult
	count := map[string]int{}
	for i := range n {
		r := send(i)
		v := versionOf(r)
		if r.Status != http.StatusOK {
			res.Samples = append(res.Samples, sample(r, r.String(), "bad"))
			count["error"]++
			continue
		}
		tone := "ok"
		if v == "v2" {
			tone = "info"
		}
		count[v]++
		res.Samples = append(res.Samples, sample(r, v, tone))
	}
	res.Summary = fmt.Sprintf("%d to v1, %d to v2", count["v1"], count["v2"])
	if count["error"] > 0 {
		res.Summary += fmt.Sprintf(", %d failed", count["error"])
	}
	return res
}

func expGatewaySplit(ctx context.Context, p *Probe, n int) ExperimentResult {
	return versionSamples(n, func(int) Resp { return p.gw(ctx, http.MethodGet, "/split", p.apiKey("alice")) }, version)
}

func expMeshSplit(ctx context.Context, p *Probe, n int) ExperimentResult {
	return versionSamples(n, func(int) Resp { return p.front(ctx, nil) }, catalogVersion)
}

func expRetry(ctx context.Context, p *Probe, n int) ExperimentResult {
	var res ExperimentResult
	ok, retried := 0, 0
	for range n {
		r := p.front(ctx, map[string]string{"x-probe-scenario": "retry", "x-probe-fail": "pricing=0.3"})
		_, _, pr := hops(r)
		switch {
		case r.Status != http.StatusOK || pr == nil:
			res.Samples = append(res.Samples, sample(r, r.String(), "bad"))
		case pr.Attempt > 1:
			ok++
			retried++
			res.Samples = append(res.Samples, sample(r, "200 ×"+strconv.Itoa(pr.Attempt), "warn"))
		default:
			ok++
			res.Samples = append(res.Samples, sample(r, "200", "ok"))
		}
	}
	res.Summary = fmt.Sprintf("%d / %d succeeded; %d needed a retry, shown as ×attempts", ok, n, retried)
	return res
}

func expFaultAbort(ctx context.Context, p *Probe, n int) ExperimentResult {
	var res ExperimentResult
	aborted := 0
	for range n {
		r := p.front(ctx, map[string]string{"x-probe-scenario": "fault-abort"})
		if r.Status == http.StatusOK {
			res.Samples = append(res.Samples, sample(r, "200", "ok"))
			continue
		}
		aborted++
		res.Samples = append(res.Samples, sample(r, "503", "bad"))
	}
	res.Summary = fmt.Sprintf("%d aborted by the sidecar, %d reached pricing. The app never saw the aborted ones.", aborted, n-aborted)
	return res
}

func expFaultDelay(ctx context.Context, p *Probe, n int) ExperimentResult {
	var res ExperimentResult
	n = min(n, 10)
	var total int64
	for range n {
		r := p.front(ctx, map[string]string{"x-probe-scenario": "fault-delay"})
		total += r.Dur.Milliseconds()
		res.Samples = append(res.Samples, sample(r, fmt.Sprintf("%.1fs", r.Dur.Seconds()), map[bool]string{true: "warn", false: "bad"}[r.Status == http.StatusOK]))
	}
	res.Summary = fmt.Sprintf("Average %.1fs per request, capped at 10 requests.", float64(total)/float64(n)/1000)
	return res
}

func expOutlier(ctx context.Context, p *Probe, n int) ExperimentResult {
	var res ExperimentResult
	failed := 0
	for range n {
		r := p.front(ctx, map[string]string{"x-probe-scenario": "outlier"})
		if r.Status == http.StatusOK {
			res.Samples = append(res.Samples, sample(r, "200", "ok"))
			continue
		}
		failed++
		res.Samples = append(res.Samples, sample(r, strconv.Itoa(r.Status), "bad"))
	}
	res.Summary = fmt.Sprintf("%d failed before the faulty pod was ejected. Run again within 30s and none fail.", failed)
	return res
}

func expAuthz(ctx context.Context, p *Probe, n int) ExperimentResult {
	var res ExperimentResult
	denied := 0
	for range n {
		r := p.mesh(ctx, p.Cfg.Services.CatalogV1, "/", nil)
		if r.Status == http.StatusForbidden {
			denied++
			res.Samples = append(res.Samples, sample(r, "403", "bad"))
		} else {
			res.Samples = append(res.Samples, sample(r, r.String(), "warn"))
		}
	}
	f := p.front(ctx, nil)
	res.Summary = fmt.Sprintf("%d / %d denied (RBAC: access denied). The same call through frontend: %s.", denied, n, f)
	return res
}

func expRateLimit(ctx context.Context, p *Probe, n int) ExperimentResult {
	var res ExperimentResult
	limited := 0
	for range n {
		r := p.gw(ctx, http.MethodGet, "/api", p.apiKey("bob"))
		tone := "ok"
		switch r.Status {
		case http.StatusOK:
		case http.StatusTooManyRequests:
			limited++
			tone = "warn"
		default:
			tone = "bad"
		}
		res.Samples = append(res.Samples, sample(r, r.String(), tone))
	}
	res.Summary = fmt.Sprintf("%d / %d limited with 429 (free plan: %s).", limited, n, p.Cfg.Limits.Free)
	return res
}

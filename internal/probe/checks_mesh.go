package probe

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/opentooling/rhcl-probe/internal/service"
)

// front calls the frontend directly from the console, so the whole chain stays inside the mesh.
func (p *Probe) front(ctx context.Context, hdr map[string]string) Resp {
	return p.mesh(ctx, p.Cfg.Services.Frontend, "/", hdr)
}

// hops returns frontend, catalog and pricing from a chain, nil where the chain stopped.
func hops(r Resp) (front, catalog, pricing *service.Hop) {
	front = r.Hop
	if front != nil {
		catalog = front.Next
	}
	if catalog != nil {
		pricing = catalog.Next
	}
	return
}

func checkMeshMTLS(ctx context.Context, p *Probe) Outcome {
	r := p.front(ctx, nil)
	f, c, pr := hops(r)
	if r.Status != http.StatusOK || pr == nil {
		return failf("", "chain broken: %s %s", r, trim(r.Body))
	}
	ns, sa := p.Cfg.Namespace, p.Cfg.ServiceAccounts
	want := []struct {
		hop       *service.Hop
		principal string
	}{
		{f, p.Cfg.Principal(ns, sa.Console)},
		{c, p.Cfg.Principal(ns, sa.Frontend)},
		{pr, p.Cfg.Principal(ns, sa.Catalog)},
	}
	for _, w := range want {
		if w.hop.Caller != w.principal {
			return failf("An empty caller means that hop was plaintext.", "%s saw caller %q, expected %s", w.hop.Service, w.hop.Caller, w.principal)
		}
	}
	return passf("console → frontend → catalog → pricing, each caller identified by SPIFFE ID")
}

func checkRequestID(ctx context.Context, p *Probe) Outcome {
	r := p.front(ctx, nil)
	f, c, pr := hops(r)
	if pr == nil {
		return failf("", "chain broken: %s", r)
	}
	if f.RequestID == "" || f.RequestID != c.RequestID || c.RequestID != pr.RequestID {
		return failf("", "x-request-id: frontend %q, catalog %q, pricing %q", f.RequestID, c.RequestID, pr.RequestID)
	}
	return passf("x-request-id %s on all three hops", f.RequestID)
}

func checkStrict(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.Expect.StrictMTLS {
		return skipf("mesh.strictMTLS is off")
	}
	fr, err := p.fromOutsider(ctx, p.Cfg.Services.CatalogV1+"/healthz")
	if err != nil {
		return failf("", "%v", err)
	}
	switch {
	case fr.Status != 0:
		return failf("Is a STRICT PeerAuthentication in place for this namespace?", "plaintext call from a pod without a sidecar got %d", fr.Status)
	case fr.ErrorKind == "timeout":
		return failf("The call timed out, so a NetworkPolicy dropped it before mTLS could reject it.", "%s", fr.Error)
	}
	return passf("plaintext from a pod without a sidecar: connection %s", fr.ErrorKind)
}

func checkMeshAuthz(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.Expect.AuthorizationPolicies {
		return skipf("mesh.authorizationPolicies is off")
	}
	r := p.mesh(ctx, p.Cfg.Services.CatalogV1, "/", nil)
	if r.Status != http.StatusForbidden || !strings.Contains(r.Body, "RBAC") {
		return failf("", "console → catalog: expected 403 RBAC: access denied, got %s %s", r, trim(r.Body))
	}
	f := p.front(ctx, nil)
	if f.Status != http.StatusOK {
		return failf("", "console was denied as expected, but frontend → catalog then failed: %s", f)
	}
	return passf("console → catalog 403 (%s); frontend → catalog 200", trim(r.Body))
}

func checkMeshSplit(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.Expect.TrafficManagement {
		return skipf("mesh.trafficManagement is off")
	}
	return splitOutcome(p.Cfg.Mesh.SplitV2Percent, 60, func() Resp { return p.front(ctx, nil) }, catalogVersion)
}

func catalogVersion(r Resp) string {
	if _, c, _ := hops(r); c != nil {
		return c.Version
	}
	return ""
}

func checkMeshHeader(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.Expect.TrafficManagement {
		return skipf("mesh.trafficManagement is off")
	}
	for i := range 5 {
		r := p.front(ctx, map[string]string{"x-version": "v2"})
		if catalogVersion(r) != "v2" {
			return failf("", "request %d reached catalog %q", i+1, catalogVersion(r))
		}
	}
	return passf("5 / 5 to catalog v2")
}

func checkRetries(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.Expect.TrafficManagement {
		return skipf("mesh.trafficManagement is off")
	}
	hdr := map[string]string{"x-probe-scenario": "retry", "x-probe-fail": "pricing=0.3"}
	retried := 0
	for i := range 20 {
		r := p.front(ctx, hdr)
		_, _, pr := hops(r)
		if r.Status != http.StatusOK || pr == nil {
			return failf("Retries should hide pricing's failures from the caller.", "request %d: %s", i+1, r)
		}
		if pr.Attempt > 1 {
			retried++
		}
	}
	if retried == 0 {
		return failf("", "20 / 20 succeeded, but none needed a retry: is pricing failing on request?")
	}
	return passf("20 / 20 succeeded; %d needed a retry (x-envoy-attempt-count > 1)", retried)
}

func checkFaultAbort(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.Expect.TrafficManagement {
		return skipf("mesh.trafficManagement is off")
	}
	aborted, ok := 0, 0
	for i := range 20 {
		r := p.front(ctx, map[string]string{"x-probe-scenario": "fault-abort"})
		_, _, pr := hops(r)
		switch {
		case r.Status == http.StatusOK:
			ok++
		case pr != nil && pr.Status == http.StatusServiceUnavailable && strings.Contains(pr.Error, "fault filter abort"):
			aborted++
		default:
			return failf("", "request %d: %s %s", i+1, r, trim(r.Body))
		}
	}
	if aborted < 3 || ok < 3 {
		return failf("", "%d aborted, %d succeeded (expected about half each)", aborted, ok)
	}
	return passf("%d / 20 aborted with 503 by catalog's sidecar, %d succeeded", aborted, ok)
}

func checkFaultDelay(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.Expect.TrafficManagement {
		return skipf("mesh.trafficManagement is off")
	}
	for i := range 3 {
		r := p.front(ctx, map[string]string{"x-probe-scenario": "fault-delay"})
		_, c, _ := hops(r)
		if r.Status != http.StatusOK || c == nil || c.ElapsedMs < 1000 {
			return failf("", "request %d: %s after %s", i+1, r, r.Dur.Round(time.Millisecond))
		}
	}
	return passf("3 / 3 delayed by at least 1s before reaching pricing")
}

func checkMeshTimeout(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.Expect.TrafficManagement {
		return skipf("mesh.trafficManagement is off")
	}
	r := p.front(ctx, map[string]string{"x-probe-scenario": "timeout", "x-probe-delay": "pricing=3s"})
	_, _, pr := hops(r)
	if pr == nil || pr.Status != http.StatusGatewayTimeout || r.Dur > 2500*time.Millisecond {
		return failf("", "expected catalog → pricing to time out after 1s, got %s after %s", r, r.Dur.Round(time.Millisecond))
	}
	return passf("catalog → pricing: 504 %s after %s", pr.Error, r.Dur.Round(10*time.Millisecond))
}

func checkOutlier(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.Expect.TrafficManagement {
		return skipf("mesh.trafficManagement is off")
	}
	codes := burst(30, func() Resp { return p.front(ctx, map[string]string{"x-probe-scenario": "outlier"}) })
	failed := 0
	for _, c := range codes {
		if c != http.StatusOK {
			failed++
		}
	}
	for _, c := range codes[20:] {
		if c != http.StatusOK {
			return failf("The faulty pod should have been ejected after 3 errors.", "%d / 30 failed, still failing at the end: %s", failed, codesString(codes))
		}
	}
	if failed > 8 {
		return failf("", "%d / 30 failed before ejection: %s", failed, codesString(codes))
	}
	if failed == 0 {
		// Either it is still ejected from a run less than 30s ago, or it isn't in the pool at all:
		// from here the two look the same, so this is no evidence either way.
		return skipf("no failures, so nothing was ejected: the faulty pod is either still ejected from an earlier run or not in the pool. Run again in 30s.")
	}
	return passf("%d failed, then the faulty pod was ejected and the rest succeeded", failed)
}

func checkEgress(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.Egress.RegistryOnly {
		return skipf("mesh.egress.registryOnly is off")
	}
	blocked := p.Cfg.Egress.BlockedURL
	r := do(ctx, p.Mesh, http.MethodGet, blocked, nil)
	var detail string
	switch {
	case r.Status == http.StatusBadGateway:
		detail = fmt.Sprintf("%s blocked (502 from the sidecar)", blocked)
	case r.Err != nil && service.ClassifyError(r.Err) == "reset":
		detail = fmt.Sprintf("%s blocked (connection reset by the sidecar)", blocked)
	case r.Err != nil && service.ClassifyError(r.Err) == "dns":
		// Air-gapped clusters: the lookup fails before the sidecar sees anything.
		return skipf("%s doesn't resolve here, so the sidecar never saw it. Set mesh.egress.blockedUrl to an external host that resolves.", blocked)
	default:
		return failf("REGISTRY_ONLY makes the sidecar refuse hosts outside the registry.", "%s: got %s", blocked, r)
	}
	if u := p.Cfg.Egress.AllowedURL; u != "" {
		a := do(ctx, p.Mesh, http.MethodGet, u, nil)
		if a.Err != nil || a.Status >= 500 {
			return failf("Is there a ServiceEntry for it (mesh.egress.allowedHosts)?", "%s; allowed %s: got %s", detail, u, a)
		}
		detail += fmt.Sprintf("; %s allowed (%d)", u, a.Status)
	}
	return passf("%s", detail)
}

func checkNetworkPolicy(ctx context.Context, p *Probe) Outcome {
	if !p.Cfg.Expect.NetworkPolicies {
		return skipf("networkPolicies.enabled is off")
	}
	fr, err := p.fromOutsider(ctx, p.Cfg.Services.Frontend+"/healthz")
	if err != nil {
		return failf("", "%v", err)
	}
	if fr.ErrorKind != "timeout" {
		return failf("Only the gateway and the console may reach the frontend.", "outsider → frontend: %d %s", fr.Status, fr.ErrorKind)
	}
	return passf("outsider → frontend dropped (timed out after %dms)", fr.ElapsedMs)
}

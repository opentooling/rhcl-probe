package probe

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/opentooling/rhcl-probe/internal/kube"
)

// AllChecks is the suite, in run order. Rate-limit checks wait for their window to expire
// first, so they don't count requests from the checks before them.
func AllChecks() []Check {
	return []Check{
		{"platform-kuadrant", GroupPlatform, "Kuadrant ready", checkKuadrant},
		{"platform-gateway", GroupPlatform, "Gateway programmed", checkGatewayProgrammed},
		{"platform-routes", GroupPlatform, "Probe routes accepted by the gateway", checkRoutes},
		{"platform-policies", GroupPlatform, "Probe AuthPolicies and RateLimitPolicies enforced", checkPolicies},
		{"platform-sidecars", GroupPlatform, "Probe pods have the istio-proxy sidecar", checkSidecars},

		{"gateway-tls", GroupGateway, "TLS certificate for the probe hostname", checkTLS},
		{"gateway-redirect", GroupGateway, "HTTP redirects to HTTPS", checkRedirect},
		{"gateway-routing", GroupGateway, "Host and path routing", checkRouting},
		{"gateway-default-deny", GroupGateway, "Default deny on a route without AuthPolicy", checkDefaultDeny},
		{"gateway-no-credentials", GroupGateway, "Request without credentials is rejected", checkNoCredentials},
		{"gateway-wrong-key", GroupGateway, "Wrong API key is rejected", checkWrongKey},
		{"gateway-api-key", GroupGateway, "Valid API key is accepted", checkValidKey},
		{"gateway-oidc", GroupGateway, "OIDC token accepted, tampered token rejected", checkOIDC},
		{"gateway-authz", GroupGateway, "Only group admin may POST", checkAdminWrites},
		{"gateway-mtls", GroupGateway, "Gateway to app is mutual TLS", checkGatewayMTLS},
		{"gateway-header-match", GroupGateway, "Header match routes x-version: v2 to catalog v2", checkHeaderMatch},
		{"gateway-split", GroupGateway, "Weighted split between catalog v1 and v2", checkGatewaySplit},
		{"gateway-rewrite", GroupGateway, "URL rewrite and header filters", checkRewrite},
		{"gateway-mirror", GroupGateway, "Request mirroring to catalog v2", checkMirror},
		{"gateway-timeout", GroupGateway, "Route timeout returns 504", checkRouteTimeout},
		{"gateway-public-limit", GroupGateway, "Route rate limit on the public route", checkPublicLimit},
		{"gateway-plan-limit", GroupGateway, "Per-caller limits by plan", checkPlanLimits},

		{"mesh-mtls", GroupMesh, "Service-to-service calls carry SPIFFE identities", checkMeshMTLS},
		{"mesh-request-id", GroupMesh, "Request ID propagated across hops", checkRequestID},
		{"mesh-strict", GroupMesh, "STRICT mTLS rejects plaintext", checkStrict},
		{"mesh-authz", GroupMesh, "AuthorizationPolicy: only frontend may call catalog", checkMeshAuthz},
		{"mesh-split", GroupMesh, "East-west split between catalog v1 and v2", checkMeshSplit},
		{"mesh-header", GroupMesh, "East-west header routing to catalog v2", checkMeshHeader},
		{"mesh-retries", GroupMesh, "Retries hide pricing's injected failures", checkRetries},
		{"mesh-fault-abort", GroupMesh, "Fault injection: abort", checkFaultAbort},
		{"mesh-fault-delay", GroupMesh, "Fault injection: delay", checkFaultDelay},
		{"mesh-timeout", GroupMesh, "Per-hop timeout", checkMeshTimeout},
		{"mesh-outlier", GroupMesh, "Outlier detection ejects the faulty pricing pod", checkOutlier},
		{"mesh-egress", GroupMesh, "Egress limited to the service registry", checkEgress},
		{"mesh-network-policy", GroupMesh, "NetworkPolicy blocks calls that bypass the gateway", checkNetworkPolicy},
	}
}

func checkKuadrant(ctx context.Context, p *Probe) Outcome {
	list, err := p.Kube.Get(ctx, fmt.Sprintf("/apis/kuadrant.io/v1beta1/namespaces/%s/kuadrants", p.Cfg.Kuadrant.Namespace))
	if err != nil {
		return failf("Is Connectivity Link installed, and does the console's ClusterRole allow reading Kuadrant?", "%v", err)
	}
	items := kube.Items(list)
	if len(items) == 0 {
		return failf("Create the Kuadrant CR in "+p.Cfg.Kuadrant.Namespace+".", "no Kuadrant in %s", p.Cfg.Kuadrant.Namespace)
	}
	c, _ := kube.Find(kube.StatusConditions(items[0]), "Ready")
	if c.Status != "True" {
		return failf("", "kuadrant/%s Ready=%s: %s", kube.Name(items[0]), c.Status, c.Message)
	}
	return passf("kuadrant/%s in %s", kube.Name(items[0]), p.Cfg.Kuadrant.Namespace)
}

func checkGatewayProgrammed(ctx context.Context, p *Probe) Outcome {
	g := p.Cfg.Gateway
	obj, err := p.Kube.Get(ctx, fmt.Sprintf("/apis/gateway.networking.k8s.io/v1/namespaces/%s/gateways/%s", g.Namespace, g.Name))
	if err != nil {
		return failf("Set gateway.name and gateway.namespace in the chart values.", "%v", err)
	}
	c, _ := kube.Find(kube.StatusConditions(obj), "Programmed")
	if c.Status != "True" {
		return failf("", "%s/%s Programmed=%s: %s", g.Namespace, g.Name, c.Status, c.Message)
	}
	st, _ := obj["status"].(kube.Object)
	listeners, _ := st["listeners"].([]any)
	return passf("%s/%s, %d listeners", g.Namespace, g.Name, len(listeners))
}

func (p *Probe) instanceSelector() string {
	return "labelSelector=" + url.QueryEscape("app.kubernetes.io/instance="+p.Cfg.Release)
}

func checkRoutes(ctx context.Context, p *Probe) Outcome {
	list, err := p.Kube.Get(ctx, fmt.Sprintf("/apis/gateway.networking.k8s.io/v1/namespaces/%s/httproutes?%s", p.Cfg.Namespace, p.instanceSelector()))
	if err != nil {
		return failf("", "%v", err)
	}
	items := kube.Items(list)
	if len(items) == 0 {
		return failf("", "no HTTPRoutes labelled app.kubernetes.io/instance=%s in %s", p.Cfg.Release, p.Cfg.Namespace)
	}
	var bad []string
	hint := ""
	for _, r := range items {
		st, _ := r["status"].(kube.Object)
		parents, _ := st["parents"].([]any)
		ok := false
		for _, par := range parents {
			pm, _ := par.(kube.Object)
			conds := kube.Conditions(pm["conditions"])
			acc, _ := kube.Find(conds, "Accepted")
			refs, _ := kube.Find(conds, "ResolvedRefs")
			if acc.Status == "True" && refs.Status != "False" {
				ok = true
			} else if acc.Reason == "NotAllowedByListeners" {
				hint = "The gateway only accepts routes from labelled namespaces. Label this one: oc label namespace " + p.Cfg.Namespace + " api-gateway-access=true"
			}
		}
		if !ok {
			bad = append(bad, kube.Name(r))
		}
	}
	if len(bad) > 0 {
		return failf(hint, "not accepted: %s", strings.Join(bad, ", "))
	}
	return passf("%d HTTPRoutes accepted", len(items))
}

func checkPolicies(ctx context.Context, p *Probe) Outcome {
	var bad, good []string
	for _, kind := range []string{"authpolicies", "ratelimitpolicies"} {
		list, err := p.Kube.Get(ctx, fmt.Sprintf("/apis/kuadrant.io/v1/namespaces/%s/%s?%s", p.Cfg.Namespace, kind, p.instanceSelector()))
		if err != nil {
			return failf("", "%s: %v", kind, err)
		}
		for _, it := range kube.Items(list) {
			c, _ := kube.Find(kube.StatusConditions(it), "Enforced")
			name := strings.TrimSuffix(kind, "ies") + "y/" + kube.Name(it)
			if c.Status == "True" {
				good = append(good, name)
			} else {
				bad = append(bad, fmt.Sprintf("%s (%s)", name, firstNonEmpty(c.Message, c.Reason, "no Enforced condition")))
			}
		}
	}
	if len(bad) > 0 {
		return failf("", "not enforced: %s", strings.Join(bad, "; "))
	}
	if len(good) == 0 {
		return failf("", "no probe policies found")
	}
	return passf("%d policies enforced", len(good))
}

func checkSidecars(ctx context.Context, p *Probe) Outcome {
	sel := url.QueryEscape("app.kubernetes.io/instance=" + p.Cfg.Release + ",rhcl-probe/mesh=true")
	list, err := p.Kube.Get(ctx, fmt.Sprintf("/api/v1/namespaces/%s/pods?labelSelector=%s", p.Cfg.Namespace, sel))
	if err != nil {
		return failf("", "%v", err)
	}
	pods := kube.Items(list)
	var missing []string
	for _, pod := range pods {
		spec, _ := pod["spec"].(kube.Object)
		if !slices.Contains(containerNames(spec["containers"]), "istio-proxy") &&
			!slices.Contains(containerNames(spec["initContainers"]), "istio-proxy") {
			missing = append(missing, kube.Name(pod))
		}
	}
	if len(pods) == 0 {
		return failf("", "no probe pods found")
	}
	if len(missing) > 0 {
		return failf("Sidecar injection didn't happen. If the mesh revision isn't \"default\", set mesh.revision; existing pods need a restart.",
			"no sidecar: %s", strings.Join(missing, ", "))
	}
	return passf("%d / %d pods", len(pods), len(pods))
}

func containerNames(raw any) []string {
	list, _ := raw.([]any)
	var out []string
	for _, c := range list {
		m, _ := c.(kube.Object)
		if n, ok := m["name"].(string); ok {
			out = append(out, n)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

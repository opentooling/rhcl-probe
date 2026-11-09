package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"

	"github.com/opentooling/rhcl-probe/internal/kube"
)

// The frontend's container port, as the chart declares it.
const (
	frontendPort     = 8080
	frontendPortName = "http"
)

// peer is the pod a connection comes from, as NetworkPolicy peers see it.
type peer struct {
	labels   map[string]string
	nsLabels map[string]string
	ip       net.IP
}

// policiesAllowingOutsider names the NetworkPolicies in the release namespace that let the
// outsider reach the frontend. NetworkPolicies add up, so any one of them is enough.
func (p *Probe) policiesAllowingOutsider(ctx context.Context) ([]string, error) {
	ns := p.Cfg.Namespace
	pods, err := p.Kube.Get(ctx, fmt.Sprintf("/api/v1/namespaces/%s/pods?%s", ns, p.instanceSelector()))
	if err != nil {
		return nil, err
	}
	var frontend, outsider kube.Object
	for _, pod := range kube.Items(pods) {
		switch labelsOf(pod)["app.kubernetes.io/component"] {
		case "frontend":
			frontend = pod
		case "outsider":
			outsider = pod
		}
	}
	if frontend == nil || outsider == nil {
		return nil, errors.New("frontend or outsider pod not found")
	}
	nsObj, err := p.Kube.Get(ctx, "/api/v1/namespaces/"+url.PathEscape(ns))
	if err != nil {
		return nil, err
	}
	policies, err := p.Kube.Get(ctx, fmt.Sprintf("/apis/networking.k8s.io/v1/namespaces/%s/networkpolicies", ns))
	if err != nil {
		return nil, err
	}
	status, _ := outsider["status"].(kube.Object)
	podIP, _ := status["podIP"].(string)
	from := peer{labels: labelsOf(outsider), nsLabels: labelsOf(nsObj), ip: net.ParseIP(podIP)}
	return allowingPolicies(kube.Items(policies), labelsOf(frontend), from, frontendPort, frontendPortName), nil
}

// allowingPolicies returns the names of the policies that select the target pod for ingress and
// have a rule admitting the peer on the port. The peer is in the policies' own namespace.
func allowingPolicies(policies []kube.Object, target map[string]string, from peer, port int, portName string) []string {
	var names []string
	for _, pol := range policies {
		spec, _ := pol["spec"].(kube.Object)
		if !matchSelector(spec["podSelector"], target) || !hasIngress(spec) {
			continue
		}
		rules, _ := spec["ingress"].([]any)
		for _, r := range rules {
			rule, _ := r.(kube.Object)
			if rulePeersMatch(rule["from"], from) && rulePortsMatch(rule["ports"], port, portName) {
				names = append(names, kube.Name(pol))
				break
			}
		}
	}
	return names
}

// hasIngress: without policyTypes, a policy always restricts ingress.
func hasIngress(spec kube.Object) bool {
	types, ok := spec["policyTypes"].([]any)
	return !ok || slices.Contains(types, any("Ingress"))
}

// rulePeersMatch: a rule without from admits every source.
func rulePeersMatch(raw any, from peer) bool {
	peers, _ := raw.([]any)
	if len(peers) == 0 {
		return true
	}
	for _, it := range peers {
		pr, _ := it.(kube.Object)
		if ipb, ok := pr["ipBlock"].(kube.Object); ok {
			if inIPBlock(ipb, from.ip) {
				return true
			}
			continue
		}
		podSel, hasPod := pr["podSelector"]
		nsSel, hasNS := pr["namespaceSelector"]
		switch {
		case hasPod && hasNS:
			if matchSelector(podSel, from.labels) && matchSelector(nsSel, from.nsLabels) {
				return true
			}
		case hasNS:
			if matchSelector(nsSel, from.nsLabels) {
				return true
			}
		case hasPod:
			// Without a namespaceSelector, podSelector means pods in the policy's namespace.
			if matchSelector(podSel, from.labels) {
				return true
			}
		}
	}
	return false
}

// rulePortsMatch: a rule without ports admits every port.
func rulePortsMatch(raw any, port int, portName string) bool {
	ports, _ := raw.([]any)
	if len(ports) == 0 {
		return true
	}
	for _, it := range ports {
		pp, _ := it.(kube.Object)
		if proto, _ := pp["protocol"].(string); proto != "" && proto != "TCP" {
			continue
		}
		switch v := pp["port"].(type) {
		case nil:
			return true
		case float64:
			end, _ := pp["endPort"].(float64)
			if int(v) == port || (end > 0 && port >= int(v) && port <= int(end)) {
				return true
			}
		case string:
			if v == portName {
				return true
			}
		}
	}
	return false
}

func inIPBlock(ipb kube.Object, ip net.IP) bool {
	if ip == nil {
		return false
	}
	cidr, _ := ipb["cidr"].(string)
	if _, n, err := net.ParseCIDR(cidr); err != nil || !n.Contains(ip) {
		return false
	}
	except, _ := ipb["except"].([]any)
	for _, e := range except {
		s, _ := e.(string)
		if _, n, err := net.ParseCIDR(s); err == nil && n.Contains(ip) {
			return false
		}
	}
	return true
}

// matchSelector evaluates a LabelSelector. An empty selector matches everything; a missing one
// (nil) matches nothing, as only a present selector is passed where the API makes it optional.
func matchSelector(raw any, labels map[string]string) bool {
	sel, ok := raw.(kube.Object)
	if !ok {
		return false
	}
	ml, _ := sel["matchLabels"].(kube.Object)
	for k, v := range ml {
		// The label must be present: OpenShift's policy-group labels match on an empty value.
		s, _ := v.(string)
		if got, has := labels[k]; !has || got != s {
			return false
		}
	}
	exprs, _ := sel["matchExpressions"].([]any)
	for _, it := range exprs {
		e, _ := it.(kube.Object)
		key, _ := e["key"].(string)
		op, _ := e["operator"].(string)
		var values []string
		vals, _ := e["values"].([]any)
		for _, v := range vals {
			if s, ok := v.(string); ok {
				values = append(values, s)
			}
		}
		val, has := labels[key]
		switch op {
		case "In":
			if !has || !slices.Contains(values, val) {
				return false
			}
		case "NotIn":
			if has && slices.Contains(values, val) {
				return false
			}
		case "Exists":
			if !has {
				return false
			}
		case "DoesNotExist":
			if has {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func labelsOf(o kube.Object) map[string]string {
	md, _ := o["metadata"].(kube.Object)
	raw, _ := md["labels"].(kube.Object)
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

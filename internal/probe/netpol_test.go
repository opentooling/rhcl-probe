package probe

import (
	"encoding/json"
	"net"
	"slices"
	"testing"

	"github.com/opentooling/rhcl-probe/internal/kube"
)

func TestAllowingPolicies(t *testing.T) {
	var policies []kube.Object
	err := json.Unmarshal([]byte(`[
	  {"metadata": {"name": "probe-default-deny"},
	   "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/instance": "probe"}}, "policyTypes": ["Ingress"]}},
	  {"metadata": {"name": "probe-frontend"},
	   "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/component": "frontend"}}, "policyTypes": ["Ingress"],
	    "ingress": [{"from": [
	      {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "api-gateway"}},
	       "podSelector": {"matchLabels": {"gateway.networking.k8s.io/gateway-name": "api-gateway"}}},
	      {"podSelector": {"matchLabels": {"app.kubernetes.io/component": "console"}}}],
	     "ports": [{"port": 8080, "protocol": "TCP"}]}]}},
	  {"metadata": {"name": "allow-from-same-namespace"},
	   "spec": {"podSelector": {}, "ingress": [{"from": [{"podSelector": {}}]}]}},
	  {"metadata": {"name": "allow-from-openshift-ingress"},
	   "spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": [{"from": [{"namespaceSelector":
	     {"matchLabels": {"policy-group.network.openshift.io/ingress": ""}}}]}]}},
	  {"metadata": {"name": "egress-only"},
	   "spec": {"podSelector": {}, "policyTypes": ["Egress"], "egress": [{}]}},
	  {"metadata": {"name": "other-port"},
	   "spec": {"podSelector": {}, "ingress": [{"ports": [{"port": 9090}]}]}},
	  {"metadata": {"name": "named-port"},
	   "spec": {"podSelector": {}, "ingress": [{"ports": [{"port": "http"}]}]}},
	  {"metadata": {"name": "port-range"},
	   "spec": {"podSelector": {}, "ingress": [{"ports": [{"port": 8000, "endPort": 8100}]}]}},
	  {"metadata": {"name": "udp-only"},
	   "spec": {"podSelector": {}, "ingress": [{"ports": [{"port": 8080, "protocol": "UDP"}]}]}},
	  {"metadata": {"name": "pod-cidr-except-outsider"},
	   "spec": {"podSelector": {}, "ingress": [{"from": [{"ipBlock": {"cidr": "10.128.0.0/14", "except": ["10.128.2.0/24"]}}]}]}},
	  {"metadata": {"name": "pod-cidr"},
	   "spec": {"podSelector": {}, "ingress": [{"from": [{"ipBlock": {"cidr": "10.128.0.0/14"}}]}]}},
	  {"metadata": {"name": "not-outsider"},
	   "spec": {"podSelector": {}, "ingress": [{"from": [{"podSelector": {"matchExpressions":
	     [{"key": "app.kubernetes.io/component", "operator": "NotIn", "values": ["outsider"]}]}}]}]}},
	  {"metadata": {"name": "other-pods"},
	   "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/component": "catalog"}}, "ingress": [{}]}}
	]`), &policies)
	if err != nil {
		t.Fatal(err)
	}
	frontend := map[string]string{"app.kubernetes.io/instance": "probe", "app.kubernetes.io/component": "frontend"}
	outsider := peer{
		labels:   map[string]string{"app.kubernetes.io/instance": "probe", "app.kubernetes.io/component": "outsider"},
		nsLabels: map[string]string{"kubernetes.io/metadata.name": "rhcl-probe"},
		ip:       net.ParseIP("10.128.2.15"),
	}
	got := allowingPolicies(policies, frontend, outsider, frontendPort, frontendPortName)
	want := []string{"allow-from-same-namespace", "named-port", "port-range", "pod-cidr"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestMatchSelector(t *testing.T) {
	labels := map[string]string{"a": "1", "b": "2"}
	for _, c := range []struct {
		sel  string
		want bool
	}{
		{`{}`, true},
		{`{"matchLabels": {"a": "1"}}`, true},
		{`{"matchLabels": {"a": "2"}}`, false},
		{`{"matchExpressions": [{"key": "a", "operator": "In", "values": ["0", "1"]}]}`, true},
		{`{"matchExpressions": [{"key": "c", "operator": "In", "values": ["1"]}]}`, false},
		{`{"matchExpressions": [{"key": "c", "operator": "NotIn", "values": ["1"]}]}`, true},
		{`{"matchExpressions": [{"key": "b", "operator": "Exists"}]}`, true},
		{`{"matchExpressions": [{"key": "b", "operator": "DoesNotExist"}]}`, false},
		{`{"matchExpressions": [{"key": "b", "operator": "Bogus"}]}`, false},
	} {
		var sel kube.Object
		if err := json.Unmarshal([]byte(c.sel), &sel); err != nil {
			t.Fatal(err)
		}
		if got := matchSelector(sel, labels); got != c.want {
			t.Errorf("%s: got %v", c.sel, got)
		}
	}
	if matchSelector(nil, labels) {
		t.Error("a missing selector matched")
	}
}

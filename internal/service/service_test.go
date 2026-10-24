package service

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCallerFromXFCC(t *testing.T) {
	cases := map[string]string{
		"": "",
		`By=spiffe://cluster.local/ns/p/sa/catalog;Hash=abc;Subject="";URI=spiffe://cluster.local/ns/p/sa/frontend`: "spiffe://cluster.local/ns/p/sa/frontend",
		// Two elements: the last one is the immediate caller.
		`By=a;URI=spiffe://td/ns/gw/sa/gw-istio,By=b;Subject="CN=x,O=y;z";URI=spiffe://td/ns/p/sa/frontend`: "spiffe://td/ns/p/sa/frontend",
		"Hash=abc": "",
	}
	for in, want := range cases {
		if got := CallerFromXFCC(in); got != want {
			t.Errorf("CallerFromXFCC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDirective(t *testing.T) {
	if v, ok := Directive("frontend=3s, pricing = 0.3", "pricing"); !ok || v != "0.3" {
		t.Fatalf("got %q %v", v, ok)
	}
	if _, ok := Directive("frontend=3s", "pricing"); ok {
		t.Fatal("matched a role that isn't there")
	}
}

func TestInCluster(t *testing.T) {
	for host, want := range map[string]bool{
		"catalog": true, "catalog.probe": true, "catalog.probe.svc": true,
		"catalog.probe.svc.cluster.local": true, "example.com.evil": false,
		"10.0.0.1": false, "": false, "api.example.com": false,
	} {
		if got := InCluster(host); got != want {
			t.Errorf("InCluster(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestClassifyError(t *testing.T) {
	if got := ClassifyError(errors.New("read tcp: connection reset by peer")); got != "reset" {
		t.Errorf("reset: got %s", got)
	}
	if got := ClassifyError(errors.New("dial tcp: connect: connection refused")); got != "refused" {
		t.Errorf("refused: got %s", got)
	}
}

// A three-hop chain, with failures injected at the last hop.
func TestChain(t *testing.T) {
	pricing := httptest.NewServer(New(Config{Role: "pricing", Version: "v1"}).Handler())
	defer pricing.Close()
	faulty := httptest.NewServer(New(Config{Role: "pricing", Faulty: true}).Handler())
	defer faulty.Close()
	catalog := New(Config{Role: "catalog", Version: "v2", Next: pricing.URL, NextOutlier: faulty.URL})
	catalogSrv := httptest.NewServer(catalog.Handler())
	defer catalogSrv.Close()
	frontend := httptest.NewServer(New(Config{Role: "frontend", Next: catalogSrv.URL}).Handler())
	defer frontend.Close()

	get := func(hdr map[string]string) (int, Hop) {
		req, _ := http.NewRequest(http.MethodGet, frontend.URL+"/api", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var hop Hop
		if err := json.NewDecoder(resp.Body).Decode(&hop); err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, hop
	}

	code, hop := get(map[string]string{"x-request-id": "r1", "x-probe-id": "id-1"})
	if code != 200 || hop.Next == nil || hop.Next.Next == nil {
		t.Fatalf("chain: %d %+v", code, hop)
	}
	if hop.Next.Version != "v2" || hop.Next.Next.Service != "pricing" || hop.Next.Next.RequestID != "r1" {
		t.Fatalf("hops: %+v / %+v", hop.Next, hop.Next.Next)
	}
	if !catalog.seen.has("id-1") || catalog.seen.has("id-2") {
		t.Fatal("seen ring")
	}

	// A failure two hops down surfaces as 502, with the cause in the nested hop.
	code, hop = get(map[string]string{"x-probe-fail": "pricing=1"})
	if code != 502 || hop.Next.Status != 502 || hop.Next.Next.Status != 500 || hop.Next.Next.Error != "injected failure" {
		t.Fatalf("fail: %d %+v", code, hop.Next.Next)
	}
	code, hop = get(map[string]string{"x-probe-scenario": "outlier"})
	if code != 502 || hop.Next.Next.Error != "faulty instance" {
		t.Fatalf("outlier: %d %+v", code, hop.Next.Next)
	}

	start := time.Now()
	if code, _ = get(map[string]string{"x-probe-delay": "catalog=150ms"}); code != 200 || time.Since(start) < 150*time.Millisecond {
		t.Fatalf("delay: %d after %s", code, time.Since(start))
	}
}

func TestEcho(t *testing.T) {
	srv := httptest.NewServer(New(Config{Role: "frontend", Next: "http://unused.invalid"}).Handler())
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/echo/x", nil)
	req.Header.Set("X-Probe-Added", "gateway")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var hop Hop
	json.NewDecoder(resp.Body).Decode(&hop)
	if hop.Path != "/echo/x" || hop.Headers["x-probe-added"] != "gateway" || hop.Next != nil {
		t.Fatalf("%+v", hop)
	}
}

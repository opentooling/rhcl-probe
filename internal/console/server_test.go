package console

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/opentooling/rhcl-probe/internal/probe"
)

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := &probe.Config{Release: "probe", Namespace: "ns"}
	cfg.Gateway.Host = "probe.example"
	p, err := probe.New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Checks = []probe.Check{
		{ID: "a", Group: probe.GroupGateway, Name: "passes", Run: func(context.Context, *probe.Probe) probe.Outcome {
			return probe.Outcome{Status: probe.Pass, Detail: "fine"}
		}},
		{ID: "b", Group: probe.GroupMesh, Name: "fails", Run: func(context.Context, *probe.Probe) probe.Outcome {
			return probe.Outcome{Status: probe.Fail, Detail: "got 200", Hint: "check it"}
		}},
	}
	srv := httptest.NewServer(New(context.Background(), p).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestRunWaitAndJUnit(t *testing.T) {
	srv := testServer(t)
	resp, err := http.Post(srv.URL+"/api/run?wait=true", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var rep probe.Report
	json.NewDecoder(resp.Body).Decode(&rep)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || rep.Running || rep.Passed != 1 || rep.Failed != 1 {
		t.Fatalf("%d %+v", resp.StatusCode, rep)
	}

	resp, err = http.Get(srv.URL + "/api/report.junit")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `<failure message="got 200">check it</failure>`) {
		t.Fatalf("junit:\n%s", body)
	}
}

func TestUIAndConfig(t *testing.T) {
	srv := testServer(t)
	for path, want := range map[string]string{
		"/":           "<title>rhcl-probe</title>",
		"/app.js":     "runExperiment",
		"/api/config": `"host":"probe.example"`,
		"/healthz":    "ok",
		"/style.css":  "prefers-color-scheme",
		"/api/report": `"running":false`,
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), want) {
			t.Errorf("%s: %d, want %q in %.200s", path, resp.StatusCode, want, body)
		}
	}
	resp, _ := http.Post(srv.URL+"/api/experiments/nope", "", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown experiment: %d", resp.StatusCode)
	}
}

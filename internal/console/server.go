// Package console serves the probe's web UI and its JSON API.
package console

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"github.com/opentooling/rhcl-probe/internal/probe"
)

//go:embed web
var web embed.FS

type Server struct {
	probe *probe.Probe
	// runCtx outlives the request that started a run, so closing the browser doesn't stop it.
	runCtx context.Context
}

func New(ctx context.Context, p *probe.Probe) *Server { return &Server{probe: p, runCtx: ctx} }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(web, "web")
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /api/config", s.config)
	mux.HandleFunc("GET /api/report", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.probe.Report()) })
	mux.HandleFunc("GET /api/report.junit", s.junit)
	mux.HandleFunc("POST /api/run", s.run)
	mux.HandleFunc("GET /api/experiments", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.probe.Experiments()) })
	mux.HandleFunc("POST /api/experiments/{name}", s.experiment)
	return mux
}

// config is what the header shows: where the probe points, never credentials.
func (s *Server) config(w http.ResponseWriter, _ *http.Request) {
	c := s.probe.Cfg
	checks := make([]map[string]string, 0, len(s.probe.Checks))
	for _, ch := range s.probe.Checks {
		checks = append(checks, map[string]string{"id": ch.ID, "group": ch.Group, "name": ch.Name})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"release":   c.Release,
		"namespace": c.Namespace,
		"gateway":   map[string]any{"name": c.Gateway.Name, "namespace": c.Gateway.Namespace, "host": c.Gateway.Host, "address": c.Gateway.Address},
		"limits":    c.Limits,
		"split":     map[string]int{"gateway": c.Routes.SplitV2Percent, "mesh": c.Mesh.SplitV2Percent},
		"expect":    c.Expect,
		"oidc":      c.OIDC.Enabled,
		"checks":    checks,
	})
}

// run starts a run in the background. With ?wait=true it answers when the run is done, with
// the report (that is what `rhcl-probe check` and `helm test` use).
func (s *Server) run(w http.ResponseWriter, r *http.Request) {
	done := make(chan bool, 1)
	go func() { done <- s.probe.Run(s.runCtx) }()
	if r.URL.Query().Get("wait") != "true" {
		// Give a run that can't start (one is already going) the chance to say so.
		select {
		case started := <-done:
			if !started {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "a run is already in progress"})
				return
			}
		case <-time.After(200 * time.Millisecond):
		}
		writeJSON(w, http.StatusAccepted, s.probe.Report())
		return
	}
	select {
	case started := <-done:
		if !started {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "a run is already in progress"})
			return
		}
		writeJSON(w, http.StatusOK, s.probe.Report())
	case <-r.Context().Done():
	}
}

func (s *Server) junit(w http.ResponseWriter, _ *http.Request) {
	b, err := probe.JUnit(s.probe.Report())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Disposition", `attachment; filename="rhcl-probe-junit.xml"`)
	w.Write(b)
}

func (s *Server) experiment(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n == 0 {
		n = 20
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	res, ok := s.probe.RunExperiment(ctx, r.PathValue("name"), n)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such experiment"})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

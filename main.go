// rhcl-probe exercises a Connectivity Link API gateway and an OpenShift Service Mesh with a
// small demo app and reports which features work. One binary, one role per Deployment:
//
//	rhcl-probe                    serve the role in $ROLE (frontend, catalog, pricing, outsider, console)
//	rhcl-probe check --url URL    run the suite on a console and exit 1 if anything failed
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/opentooling/rhcl-probe/internal/console"
	"github.com/opentooling/rhcl-probe/internal/kube"
	"github.com/opentooling/rhcl-probe/internal/probe"
	"github.com/opentooling/rhcl-probe/internal/service"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "check":
			os.Exit(check(os.Args[2:]))
		case "version", "--version":
			fmt.Println(version)
			return
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx); err != nil {
		log.Fatal(err)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func serve(ctx context.Context) error {
	role := env("ROLE", "console")
	var h http.Handler
	switch role {
	case "console":
		cfg, err := probe.LoadConfig(env("CONFIG", "/etc/rhcl-probe/config.json"))
		if err != nil {
			return err
		}
		kc, err := kube.InCluster()
		if err != nil {
			log.Printf("platform checks will fail: %v", err)
		}
		p, err := probe.New(cfg, kc)
		if err != nil {
			return err
		}
		h = console.New(ctx, p).Handler()
	case "frontend", "catalog", "pricing", "outsider":
		h = service.New(service.Config{
			Role:        role,
			Version:     os.Getenv("VERSION"),
			Pod:         os.Getenv("POD_NAME"),
			Namespace:   os.Getenv("POD_NAMESPACE"),
			Next:        os.Getenv("NEXT"),
			NextOutlier: os.Getenv("NEXT_OUTLIER"),
			Faulty:      os.Getenv("FAULTY") == "true",
		}).Handler()
	default:
		return fmt.Errorf("unknown ROLE %q", role)
	}

	srv := &http.Server{Addr: ":" + env("PORT", "8080"), Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	log.Printf("rhcl-probe %s: %s listening on %s", version, role, srv.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// check asks a console to run the suite, prints the results, and returns the exit code.
func check(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	url := fs.String("url", env("CONSOLE_URL", "http://localhost:8080"), "console base URL")
	junit := fs.String("junit", "", "also write JUnit XML to this file")
	timeout := fs.Duration("timeout", 10*time.Minute, "give up after this long")
	fs.Parse(args)

	client := &http.Client{Timeout: *timeout}
	resp, err := client.Post(*url+"/api/run?wait=true", "application/json", nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		return 2
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "run: console answered %s\n", resp.Status)
		return 2
	}
	var rep probe.Report
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
		return 2
	}
	group := ""
	for _, r := range rep.Results {
		if r.Group != group {
			group = r.Group
			fmt.Printf("\n%s\n", group)
		}
		fmt.Printf("  %-4s  %s: %s\n", map[probe.Status]string{probe.Pass: "PASS", probe.Fail: "FAIL", probe.Skip: "SKIP"}[r.Status], r.Name, r.Detail)
		if r.Status == probe.Fail && r.Hint != "" {
			fmt.Printf("        %s\n", r.Hint)
		}
	}
	fmt.Printf("\n%d passed, %d failed, %d skipped in %.0fs\n", rep.Passed, rep.Failed, rep.Skipped, float64(rep.DurationMs)/1000)
	if *junit != "" {
		if b, err := probe.JUnit(rep); err == nil {
			os.WriteFile(*junit, b, 0o644)
		}
	}
	if rep.Failed > 0 {
		return 1
	}
	return 0
}

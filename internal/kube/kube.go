// Package kube is a minimal read-only Kubernetes client: GET a path with the pod's own
// ServiceAccount token, decode the JSON. The probe only reads object status, so it needs
// nothing more than that, and no client library.
package kube

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const saDir = "/var/run/secrets/kubernetes.io/serviceaccount"

type Client struct {
	base      string
	tokenFile string
	http      *http.Client
}

// Object is a decoded Kubernetes object.
type Object = map[string]any

// InCluster builds a client from the pod's environment and ServiceAccount.
func InCluster() (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil, errors.New("not running in a cluster (KUBERNETES_SERVICE_HOST is unset)")
	}
	ca, err := os.ReadFile(saDir + "/ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	return &Client{
		base:      "https://" + net.JoinHostPort(host, port),
		tokenFile: saDir + "/token",
		http: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		},
	}, nil
}

// Get fetches an API path such as /apis/gateway.networking.k8s.io/v1/namespaces/x/gateways/y.
func (c *Client) Get(ctx context.Context, path string) (Object, error) {
	if c == nil {
		return nil, errors.New("no Kubernetes API access")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	// Re-read every time: projected tokens rotate.
	token, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var st struct{ Message string }
		json.Unmarshal(body, &st)
		return nil, &StatusError{Code: resp.StatusCode, Message: st.Message}
	}
	var obj Object
	return obj, json.Unmarshal(body, &obj)
}

type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string { return fmt.Sprintf("%d: %s", e.Code, e.Message) }

// IsNotFound is true for a 404, which for a CRD path also means the API isn't installed.
func IsNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusNotFound
}

// Items returns the items of a list.
func Items(list Object) []Object {
	raw, _ := list["items"].([]any)
	out := make([]Object, 0, len(raw))
	for _, it := range raw {
		if o, ok := it.(Object); ok {
			out = append(out, o)
		}
	}
	return out
}

// Name returns metadata.name.
func Name(o Object) string {
	md, _ := o["metadata"].(Object)
	n, _ := md["name"].(string)
	return n
}

// Condition is one entry of a status.conditions list.
type Condition struct {
	Type, Status, Reason, Message string
}

// Conditions reads a conditions list.
func Conditions(raw any) []Condition {
	list, _ := raw.([]any)
	out := make([]Condition, 0, len(list))
	for _, it := range list {
		m, _ := it.(Object)
		c := Condition{}
		c.Type, _ = m["type"].(string)
		c.Status, _ = m["status"].(string)
		c.Reason, _ = m["reason"].(string)
		c.Message, _ = m["message"].(string)
		out = append(out, c)
	}
	return out
}

// StatusConditions reads status.conditions of an object.
func StatusConditions(o Object) []Condition {
	st, _ := o["status"].(Object)
	return Conditions(st["conditions"])
}

// Find returns the condition of the given type.
func Find(conds []Condition, typ string) (Condition, bool) {
	for _, c := range conds {
		if c.Type == typ {
			return c, true
		}
	}
	return Condition{}, false
}

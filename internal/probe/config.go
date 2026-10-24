package probe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config is what the chart tells the console about the platform and the probe's own resources.
// It is rendered into a ConfigMap as JSON, so the chart's values are the only source of truth.
type Config struct {
	Release     string `json:"release"`
	Namespace   string `json:"namespace"`
	TrustDomain string `json:"trustDomain"`

	Gateway struct {
		Name           string `json:"name"`
		Namespace      string `json:"namespace"`
		ServiceAccount string `json:"serviceAccount"`
		// Host is the hostname of the probe's routes; Address is where the console dials it.
		Host               string `json:"host"`
		Address            string `json:"address"`
		HTTPPort           int    `json:"httpPort"`
		HTTPSPort          int    `json:"httpsPort"`
		IssuerContains     string `json:"issuerContains"`
		InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	} `json:"gateway"`

	Kuadrant struct {
		Namespace string `json:"namespace"`
	} `json:"kuadrant"`

	// Base URLs of the probe's Services, and the ServiceAccounts their pods run as.
	Services struct {
		Frontend  string `json:"frontend"`
		Catalog   string `json:"catalog"`
		CatalogV1 string `json:"catalogV1"`
		CatalogV2 string `json:"catalogV2"`
		Outsider  string `json:"outsider"`
	} `json:"services"`
	ServiceAccounts struct {
		Frontend string `json:"frontend"`
		Catalog  string `json:"catalog"`
		Pricing  string `json:"pricing"`
		Console  string `json:"console"`
	} `json:"serviceAccounts"`

	// What the platform is expected to enforce. A check for something that is off is skipped.
	Expect struct {
		DefaultDeny           bool `json:"defaultDeny"`
		HTTPRedirect          bool `json:"httpRedirect"`
		StrictMTLS            bool `json:"strictMTLS"`
		AuthorizationPolicies bool `json:"authorizationPolicies"`
		TrafficManagement     bool `json:"trafficManagement"`
		NetworkPolicies       bool `json:"networkPolicies"`
	} `json:"expect"`

	Limits struct {
		Public Limit `json:"public"`
		Free   Limit `json:"free"`
		Gold   Limit `json:"gold"`
	} `json:"limits"`

	Routes struct {
		SplitV2Percent int      `json:"splitV2Percent"`
		Timeout        Duration `json:"timeout"`
	} `json:"routes"`

	Mesh struct {
		SplitV2Percent int `json:"splitV2Percent"`
	} `json:"mesh"`

	Egress struct {
		RegistryOnly bool   `json:"registryOnly"`
		BlockedURL   string `json:"blockedUrl"`
		AllowedURL   string `json:"allowedUrl"`
	} `json:"egress"`

	APIKeys struct {
		Prefix string `json:"prefix"`
		// Directory holding one file per user (alice, bob), each the user's key.
		Dir string `json:"dir"`
	} `json:"apiKeys"`

	OIDC struct {
		Enabled          bool   `json:"enabled"`
		IssuerURL        string `json:"issuerUrl"`
		ClientID         string `json:"clientId"`
		Scope            string `json:"scope"`
		ClientSecretFile string `json:"clientSecretFile"`
	} `json:"oidc"`

	// CA bundle (PEM) trusted in addition to the system roots, for the gateway and the IdP.
	CAFile string `json:"caFile"`
}

type Limit struct {
	Count  int      `json:"limit"`
	Window Duration `json:"window"`
}

func (l Limit) String() string { return fmt.Sprintf("%d / %s", l.Count, l.Window) }

// Duration reads "10s" style strings.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	v, err := time.ParseDuration(s)
	d.Duration = v
	return err
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	// Unknown keys are an error: the chart renders this file, so one means the two have drifted.
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.defaults()
	return cfg, nil
}

func (c *Config) defaults() {
	if c.TrustDomain == "" {
		c.TrustDomain = "cluster.local"
	}
	if c.Gateway.HTTPPort == 0 {
		c.Gateway.HTTPPort = 80
	}
	if c.Gateway.HTTPSPort == 0 {
		c.Gateway.HTTPSPort = 443
	}
	if c.Gateway.ServiceAccount == "" {
		c.Gateway.ServiceAccount = c.Gateway.Name + "-istio"
	}
	if c.Gateway.Address == "" {
		c.Gateway.Address = fmt.Sprintf("%s-istio.%s.svc", c.Gateway.Name, c.Gateway.Namespace)
	}
	if c.APIKeys.Prefix == "" {
		c.APIKeys.Prefix = "APIKEY"
	}
	if c.Routes.Timeout.Duration == 0 {
		c.Routes.Timeout.Duration = 2 * time.Second
	}
}

// Principal is the SPIFFE ID of a ServiceAccount, as the mesh reports it.
func (c *Config) Principal(namespace, sa string) string {
	return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", c.TrustDomain, namespace, sa)
}

// APIKey reads a user's key from the mounted Secret.
func (c *Config) APIKey(user string) string {
	if c.APIKeys.Dir == "" {
		return ""
	}
	b, _ := os.ReadFile(filepath.Join(c.APIKeys.Dir, user))
	return strings.TrimSpace(string(b))
}

// URL builds a URL on the probe's gateway hostname.
func (c *Config) URL(path string) string { return "https://" + c.Gateway.Host + path }

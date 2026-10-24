package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type cachedToken struct {
	value   string
	expires time.Time
}

// oidcToken gets an access token with the client credentials grant, and reuses it until
// shortly before it expires.
func (p *Probe) oidcToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	t := p.token
	p.mu.Unlock()
	if t.value != "" && time.Now().Before(t.expires) {
		return t.value, nil
	}
	o := p.Cfg.OIDC
	secret, err := os.ReadFile(o.ClientSecretFile)
	if err != nil {
		return "", fmt.Errorf("client secret: %w", err)
	}

	disc := do(ctx, p.Mesh, http.MethodGet, strings.TrimSuffix(o.IssuerURL, "/")+"/.well-known/openid-configuration", nil)
	if disc.Err != nil || disc.Status != http.StatusOK {
		return "", fmt.Errorf("discovery: %s", disc)
	}
	var meta struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.Unmarshal([]byte(disc.Body), &meta); err != nil || meta.TokenEndpoint == "" {
		return "", fmt.Errorf("discovery document has no token_endpoint")
	}

	form := url.Values{"grant_type": {"client_credentials"}}
	if o.Scope != "" {
		form.Set("scope", o.Scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(o.ClientID), url.QueryEscape(strings.TrimSpace(string(secret))))
	resp, err := p.Mesh.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error_description"`
	}
	json.NewDecoder(resp.Body).Decode(&tok)
	if resp.StatusCode != http.StatusOK || tok.AccessToken == "" {
		return "", fmt.Errorf("token endpoint answered %d %s", resp.StatusCode, tok.Error)
	}
	ttl := time.Duration(tok.ExpiresIn) * time.Second
	if ttl == 0 {
		ttl = time.Minute
	}
	p.mu.Lock()
	p.token = cachedToken{value: tok.AccessToken, expires: time.Now().Add(ttl - 15*time.Second)}
	p.mu.Unlock()
	return tok.AccessToken, nil
}

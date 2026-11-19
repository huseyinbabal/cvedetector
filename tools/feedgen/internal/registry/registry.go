// Package registry lists image tags (metadata only: nothing is pulled).
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Client lists tags anonymously.
type Client struct {
	HTTP *http.Client
}

// New returns a Client.
func New() *Client { return &Client{HTTP: &http.Client{Timeout: 30 * time.Second}} }

// Tags returns up to ~100 tags of a normalized repository such as
// "docker.io/library/nginx" or "quay.io/keycloak/keycloak". Docker Hub tags
// come most recently updated first; others in registry order.
func (c *Client) Tags(ctx context.Context, repo string) ([]string, error) {
	host, path, ok := strings.Cut(repo, "/")
	if !ok {
		return nil, fmt.Errorf("bad repository %q", repo)
	}
	if host == "docker.io" {
		return c.hubTags(ctx, path)
	}
	return c.v2Tags(ctx, host, path)
}

func (c *Client) getJSON(ctx context.Context, u, token string, out any) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cvedetector-discover/1")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return resp, json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}

func (c *Client) hubTags(ctx context.Context, path string) ([]string, error) {
	var page struct {
		Results []struct {
			Name string `json:"name"`
		} `json:"results"`
	}
	u := "https://hub.docker.com/v2/repositories/" + path + "/tags?page_size=100&ordering=last_updated"
	if _, err := c.getJSON(ctx, u, "", &page); err != nil {
		return nil, err
	}
	tags := make([]string, 0, len(page.Results))
	for _, r := range page.Results {
		tags = append(tags, r.Name)
	}
	return tags, nil
}

var challengeRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

// v2Tags uses the OCI distribution API with an anonymous bearer token when
// the registry asks for one.
func (c *Client) v2Tags(ctx context.Context, host, path string) ([]string, error) {
	u := "https://" + host + "/v2/" + path + "/tags/list"
	var out struct {
		Tags []string `json:"tags"`
	}
	resp, err := c.getJSON(ctx, u, "", &out)
	if err == nil {
		return out.Tags, nil
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		return nil, err
	}
	params := map[string]string{}
	for _, m := range challengeRe.FindAllStringSubmatch(resp.Header.Get("WWW-Authenticate"), -1) {
		params[m[1]] = m[2]
	}
	if params["realm"] == "" {
		return nil, err
	}
	q := url.Values{}
	if s := params["service"]; s != "" {
		q.Set("service", s)
	}
	scope := params["scope"]
	if scope == "" {
		scope = "repository:" + path + ":pull"
	}
	q.Set("scope", scope)
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if _, err := c.getJSON(ctx, params["realm"]+"?"+q.Encode(), "", &tok); err != nil {
		return nil, err
	}
	t := tok.Token
	if t == "" {
		t = tok.AccessToken
	}
	if _, err := c.getJSON(ctx, u, t, &out); err != nil {
		return nil, err
	}
	return out.Tags, nil
}

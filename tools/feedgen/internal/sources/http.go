// Package sources fetches vulnerability data from public databases.
package sources

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const userAgent = "cvedetector-feedgen/1"

// Client is an HTTP client with retries for flaky or rate-limited APIs.
type Client struct {
	HTTP     *http.Client
	Attempts int
	Backoff  time.Duration
}

// NewClient returns a Client with sane defaults.
func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 60 * time.Second}, Attempts: 6, Backoff: 3 * time.Second}
}

// Do sends the request built by newReq, retrying on network errors, 429, 403
// (NVD's rate-limit answer) and 5xx. It returns the body of a 200 response.
func (c *Client) Do(ctx context.Context, newReq func() (*http.Request, error)) ([]byte, error) {
	var lastErr error
	for attempt := range c.Attempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(c.Backoff * time.Duration(1<<(attempt-1))):
			}
		}
		req, err := newReq()
		if err != nil {
			return nil, err
		}
		req = req.WithContext(ctx)
		req.Header.Set("User-Agent", userAgent)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch {
		case err != nil:
			lastErr = err
		case resp.StatusCode == http.StatusOK:
			return body, nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden || resp.StatusCode >= 500:
			lastErr = fmt.Errorf("%s %s: %s", req.Method, req.URL.Redacted(), resp.Status)
		default:
			return nil, fmt.Errorf("%s %s: %s: %.200s", req.Method, req.URL.Redacted(), resp.Status, body)
		}
	}
	return nil, fmt.Errorf("giving up after %d attempts: %w", c.Attempts, lastErr)
}

package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// defaultAPIBaseURL is the Cloudflare API v4 root. It is overridable on cfClient
// so tests can point at an httptest server.
const defaultAPIBaseURL = "https://api.cloudflare.com/client/v4"

// maxResponseBytes caps how much of a Cloudflare response we read into memory.
const maxResponseBytes = 1 << 20

// cfClient is a minimal Cloudflare API v4 client used only to discover and
// delete orphaned "_acme-challenge" TXT records. lego's own Cloudflare provider
// does not expose listing or deleting records by name, so we talk to the API
// directly. It uses two scoped tokens, mirroring lego's split-token model:
// zoneToken (Zone:Read) for zone lookups and dnsToken (DNS:Edit) for record
// listing and deletion.
type cfClient struct {
	httpClient *http.Client
	baseURL    string
	zoneToken  string
	dnsToken   string
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfRecord struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfResponse struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

// request performs a Cloudflare API call and returns the decoded envelope,
// failing on transport errors, non-success envelopes, or malformed JSON.
func (c *cfClient) request(ctx context.Context, method, endpoint, token string) (*cfResponse, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: %s %s: %w", method, endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("cloudflare: read response (status %d): %w", resp.StatusCode, err)
	}

	var parsed cfResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("cloudflare: decode response (status %d): %w", resp.StatusCode, err)
	}
	if !parsed.Success {
		return nil, fmt.Errorf("cloudflare: api error (status %d): %s", resp.StatusCode, formatAPIErrors(parsed.Errors))
	}
	return &parsed, nil
}

// findZoneID resolves the zone that owns fqdn by querying progressively shorter
// suffixes (e.g. "_acme-challenge.factory.bg", "factory.bg", "bg") and returning
// the first registered zone.
func (c *cfClient) findZoneID(ctx context.Context, fqdn string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	for i := 0; i+1 < len(labels); i++ {
		candidate := strings.Join(labels[i:], ".")
		resp, err := c.request(ctx, http.MethodGet,
			"/zones?status=active&name="+url.QueryEscape(candidate), c.zoneToken)
		if err != nil {
			return "", err
		}
		var zones []cfZone
		if err := json.Unmarshal(resp.Result, &zones); err != nil {
			return "", fmt.Errorf("cloudflare: decode zones: %w", err)
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("cloudflare: no zone found for %q", fqdn)
}

// listTXTRecords returns every TXT record in the zone matching name exactly.
func (c *cfClient) listTXTRecords(ctx context.Context, zoneID, name string) ([]cfRecord, error) {
	endpoint := fmt.Sprintf("/zones/%s/dns_records?type=TXT&name=%s", zoneID, url.QueryEscape(name))
	resp, err := c.request(ctx, http.MethodGet, endpoint, c.dnsToken)
	if err != nil {
		return nil, err
	}
	var records []cfRecord
	if err := json.Unmarshal(resp.Result, &records); err != nil {
		return nil, fmt.Errorf("cloudflare: decode records: %w", err)
	}
	return records, nil
}

// deleteRecord removes a single DNS record by ID.
func (c *cfClient) deleteRecord(ctx context.Context, zoneID, recordID string) error {
	endpoint := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID)
	_, err := c.request(ctx, http.MethodDelete, endpoint, c.dnsToken)
	return err
}

func formatAPIErrors(errs []cfAPIError) string {
	if len(errs) == 0 {
		return "unknown error"
	}
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, fmt.Sprintf("%d: %s", e.Code, e.Message))
	}
	return strings.Join(parts, "; ")
}

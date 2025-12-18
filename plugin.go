// Package main implements the Packagist plugin for Relicta.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/relicta-tech/relicta-plugin-sdk/helpers"
	"github.com/relicta-tech/relicta-plugin-sdk/plugin"
)

// Packagist API endpoint for package updates.
var packagistAPIEndpoint = "https://packagist.org/api/update-package"

// httpClient is the HTTP client used for requests.
// Can be overridden in tests.
var httpClient HTTPClient = nil

// HTTPClient interface for HTTP operations (allows mocking in tests).
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// getHTTPClient returns the HTTP client to use for requests.
func getHTTPClient() HTTPClient {
	if httpClient != nil {
		return httpClient
	}
	return defaultHTTPClient
}

// Shared HTTP client for connection reuse across requests.
// Includes security hardening: TLS 1.3+, redirect protection, SSRF protection.
var defaultHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return fmt.Errorf("redirect to non-HTTPS URL not allowed")
		}
		// SSRF protection: only allow redirects within packagist.org domain
		// Must be exact match or subdomain (not evil-packagist.org)
		host := req.URL.Host
		if host != "packagist.org" && !strings.HasSuffix(host, ".packagist.org") {
			return fmt.Errorf("redirect away from packagist.org not allowed")
		}
		return nil
	},
	Transport: &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	},
}

// Security validation patterns.
var (
	// packageNamePattern validates vendor/package format.
	// Allows: alphanumerics, dashes, underscores for vendor and package names.
	// Format: vendor/package (e.g., symfony/console, laravel/framework).
	packageNamePattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?/[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$`)

	// simplePackagePattern allows single-character vendor/package names.
	simplePackagePattern = regexp.MustCompile(`^[a-zA-Z0-9]/[a-zA-Z0-9]$`)
)

// validatePackageName validates a Packagist package name.
func validatePackageName(name string) error {
	if name == "" {
		return fmt.Errorf("package name cannot be empty")
	}
	if len(name) > 256 {
		return fmt.Errorf("package name too long (max 256 characters)")
	}

	// Check for valid vendor/package format.
	if !packageNamePattern.MatchString(name) && !simplePackagePattern.MatchString(name) {
		return fmt.Errorf("invalid package name format: must be vendor/package (e.g., vendor/package)")
	}

	// Check for path traversal attempts.
	if strings.Contains(name, "..") {
		return fmt.Errorf("package name cannot contain '..'")
	}

	// Verify exactly one slash (vendor/package).
	parts := strings.Split(name, "/")
	if len(parts) != 2 {
		return fmt.Errorf("package name must be in vendor/package format")
	}

	return nil
}

// validateURL validates that a URL is safe (SSRF protection).
func validateURL(urlStr string) error {
	// Only allow HTTPS.
	if !strings.HasPrefix(urlStr, "https://") {
		return fmt.Errorf("URL must use HTTPS")
	}

	// SSRF protection: only allow packagist.org domain.
	if !strings.HasPrefix(urlStr, "https://packagist.org/") {
		return fmt.Errorf("URL must be on packagist.org domain")
	}

	return nil
}

// PackagistPlugin implements the Publish packages to Packagist (PHP) plugin.
type PackagistPlugin struct{}

// Config represents the Packagist plugin configuration.
type Config struct {
	PackageName string
	APIToken    string
	Username    string
	AutoUpdate  bool
}

// UpdateRequest represents the JSON request body for Packagist API.
type UpdateRequest struct {
	Repository RepositoryInfo `json:"repository"`
}

// RepositoryInfo contains the repository URL for the update request.
type RepositoryInfo struct {
	URL string `json:"url"`
}

// GetInfo returns plugin metadata.
func (p *PackagistPlugin) GetInfo() plugin.Info {
	return plugin.Info{
		Name:        "packagist",
		Version:     "2.0.0",
		Description: "Publish packages to Packagist (PHP)",
		Author:      "Relicta Team",
		Hooks: []plugin.Hook{
			plugin.HookPostPublish,
		},
		ConfigSchema: `{
			"type": "object",
			"properties": {
				"package_name": {"type": "string", "description": "Packagist package name (vendor/package format, required)"},
				"api_token": {"type": "string", "description": "Packagist API token (or use PACKAGIST_API_TOKEN env)"},
				"username": {"type": "string", "description": "Packagist username (or use PACKAGIST_USERNAME env)"},
				"auto_update": {"type": "boolean", "description": "Automatically trigger package update", "default": true}
			},
			"required": ["package_name"]
		}`,
	}
}

// Execute runs the plugin for a given hook.
func (p *PackagistPlugin) Execute(ctx context.Context, req plugin.ExecuteRequest) (*plugin.ExecuteResponse, error) {
	cfg := p.parseConfig(req.Config)

	switch req.Hook {
	case plugin.HookPostPublish:
		return p.postPublish(ctx, cfg, req.Context, req.DryRun)
	default:
		return &plugin.ExecuteResponse{
			Success: true,
			Message: fmt.Sprintf("Hook %s not handled", req.Hook),
		}, nil
	}
}

func (p *PackagistPlugin) postPublish(ctx context.Context, cfg *Config, releaseCtx plugin.ReleaseContext, dryRun bool) (*plugin.ExecuteResponse, error) {
	// Validate package name.
	if err := validatePackageName(cfg.PackageName); err != nil {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid package name: %v", err),
		}, nil
	}

	// Check if auto_update is disabled.
	if !cfg.AutoUpdate {
		return &plugin.ExecuteResponse{
			Success: true,
			Message: "Packagist auto-update is disabled",
			Outputs: map[string]any{
				"package_name": cfg.PackageName,
				"auto_update":  false,
				"skipped":      true,
			},
		}, nil
	}

	// Validate credentials.
	if cfg.Username == "" {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   "Packagist username is required (set PACKAGIST_USERNAME env var or configure username)",
		}, nil
	}

	if cfg.APIToken == "" {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   "Packagist API token is required (set PACKAGIST_API_TOKEN env var or configure api_token)",
		}, nil
	}

	if dryRun {
		return &plugin.ExecuteResponse{
			Success: true,
			Message: "Would trigger Packagist package update",
			Outputs: map[string]any{
				"package_name": cfg.PackageName,
				"auto_update":  cfg.AutoUpdate,
			},
		}, nil
	}

	// Trigger Packagist update via HTTP webhook.
	if err := p.triggerPackagistUpdate(ctx, cfg); err != nil {
		return &plugin.ExecuteResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to trigger Packagist update: %v", err),
		}, nil
	}

	return &plugin.ExecuteResponse{
		Success: true,
		Message: fmt.Sprintf("Packagist package %s update triggered successfully", cfg.PackageName),
		Outputs: map[string]any{
			"package_name": cfg.PackageName,
			"version":      releaseCtx.Version,
		},
	}, nil
}

// triggerPackagistUpdate sends an HTTP POST request to the Packagist API.
func (p *PackagistPlugin) triggerPackagistUpdate(ctx context.Context, cfg *Config) error {
	// Build the API URL with query parameters.
	apiURL := fmt.Sprintf("%s?username=%s&apiToken=%s",
		packagistAPIEndpoint,
		cfg.Username,
		cfg.APIToken,
	)

	// Validate the URL (SSRF protection).
	if err := validateURL(packagistAPIEndpoint); err != nil {
		return fmt.Errorf("invalid API endpoint: %w", err)
	}

	// Build the repository URL for the package.
	repoURL := fmt.Sprintf("https://packagist.org/packages/%s", cfg.PackageName)

	// Create the request body.
	reqBody := UpdateRequest{
		Repository: RepositoryInfo{
			URL: repoURL,
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create HTTP request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Send request.
	resp, err := getHTTPClient().Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response body.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check for success status codes.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("packagist API returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// parseConfig parses the raw configuration into a Config struct.
func (p *PackagistPlugin) parseConfig(raw map[string]any) *Config {
	parser := helpers.NewConfigParser(raw)

	return &Config{
		PackageName: parser.GetString("package_name", "", ""),
		APIToken:    parser.GetString("api_token", "PACKAGIST_API_TOKEN", ""),
		Username:    parser.GetString("username", "PACKAGIST_USERNAME", ""),
		AutoUpdate:  parser.GetBool("auto_update", true),
	}
}

// Validate validates the plugin configuration.
func (p *PackagistPlugin) Validate(_ context.Context, config map[string]any) (*plugin.ValidateResponse, error) {
	vb := helpers.NewValidationBuilder()
	parser := helpers.NewConfigParser(config)

	// Validate package name.
	packageName := parser.GetString("package_name", "", "")
	if packageName == "" {
		vb.AddError("package_name", "Packagist package name is required")
	} else if err := validatePackageName(packageName); err != nil {
		vb.AddError("package_name", err.Error())
	}

	// Note: api_token and username are validated at execution time.
	// They can be provided via environment variables, so we don't require them in config validation.

	return vb.Build(), nil
}

// Package main provides tests for the Packagist plugin.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/relicta-tech/relicta-plugin-sdk/plugin"
)

// mockHTTPClient implements HTTPClient for testing.
type mockHTTPClient struct {
	DoFunc func(req *http.Request) (*http.Response, error)
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.DoFunc != nil {
		return m.DoFunc(req)
	}
	return nil, fmt.Errorf("mock not configured")
}

// mockResponse creates an HTTP response with the given status and body.
func mockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestGetInfo(t *testing.T) {
	p := &PackagistPlugin{}
	info := p.GetInfo()

	if info.Name != "packagist" {
		t.Errorf("expected name 'packagist', got '%s'", info.Name)
	}

	if info.Version != "2.0.0" {
		t.Errorf("expected version '2.0.0', got '%s'", info.Version)
	}

	if info.Description != "Publish packages to Packagist (PHP)" {
		t.Errorf("expected description 'Publish packages to Packagist (PHP)', got '%s'", info.Description)
	}

	if info.Author != "Relicta Team" {
		t.Errorf("expected author 'Relicta Team', got '%s'", info.Author)
	}

	// Check hooks.
	if len(info.Hooks) == 0 {
		t.Error("expected at least one hook")
	}

	hasPostPublish := false
	for _, hook := range info.Hooks {
		if hook == plugin.HookPostPublish {
			hasPostPublish = true
			break
		}
	}
	if !hasPostPublish {
		t.Error("expected PostPublish hook")
	}

	// Check config schema is valid JSON.
	if info.ConfigSchema == "" {
		t.Error("expected non-empty config schema")
	}
}

func TestValidatePackageName(t *testing.T) {
	tests := []struct {
		name        string
		packageName string
		wantErr     bool
		errContains string
	}{
		{
			name:        "valid package name",
			packageName: "vendor/package",
			wantErr:     false,
		},
		{
			name:        "valid package name with dashes",
			packageName: "my-vendor/my-package",
			wantErr:     false,
		},
		{
			name:        "valid package name with underscores",
			packageName: "my_vendor/my_package",
			wantErr:     false,
		},
		{
			name:        "valid package name with numbers",
			packageName: "vendor123/package456",
			wantErr:     false,
		},
		{
			name:        "valid package name symfony style",
			packageName: "symfony/console",
			wantErr:     false,
		},
		{
			name:        "valid package name laravel style",
			packageName: "laravel/framework",
			wantErr:     false,
		},
		{
			name:        "valid single char vendor and package",
			packageName: "a/b",
			wantErr:     false,
		},
		{
			name:        "empty package name",
			packageName: "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "missing vendor",
			packageName: "/package",
			wantErr:     true,
			errContains: "invalid package name format",
		},
		{
			name:        "missing package",
			packageName: "vendor/",
			wantErr:     true,
			errContains: "invalid package name format",
		},
		{
			name:        "no slash",
			packageName: "vendorpackage",
			wantErr:     true,
			errContains: "invalid package name format",
		},
		{
			name:        "multiple slashes",
			packageName: "vendor/sub/package",
			wantErr:     true,
			errContains: "invalid package name format",
		},
		{
			name:        "path traversal attempt",
			packageName: "../vendor/package",
			wantErr:     true,
			errContains: "invalid package name format",
		},
		{
			name:        "special characters not allowed",
			packageName: "vendor@evil/package",
			wantErr:     true,
			errContains: "invalid package name format",
		},
		{
			name:        "spaces not allowed",
			packageName: "vendor name/package",
			wantErr:     true,
			errContains: "invalid package name format",
		},
		{
			name:        "package name too long",
			packageName: strings.Repeat("a", 130) + "/" + strings.Repeat("b", 130),
			wantErr:     true,
			errContains: "too long",
		},
		{
			name:        "vendor starting with dash",
			packageName: "-vendor/package",
			wantErr:     true,
			errContains: "invalid package name format",
		},
		{
			name:        "vendor ending with dash",
			packageName: "vendor-/package",
			wantErr:     true,
			errContains: "invalid package name format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePackageName(tt.packageName)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errContains)
				} else if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got '%s'", err.Error())
				}
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid packagist URL",
			url:     "https://packagist.org/api/update-package",
			wantErr: false,
		},
		{
			name:    "valid packagist packages URL",
			url:     "https://packagist.org/packages/vendor/package",
			wantErr: false,
		},
		{
			name:        "HTTP not allowed",
			url:         "http://packagist.org/api/update-package",
			wantErr:     true,
			errContains: "must use HTTPS",
		},
		{
			name:        "different domain not allowed",
			url:         "https://evil.com/api/update-package",
			wantErr:     true,
			errContains: "must be on packagist.org domain",
		},
		{
			name:        "subdomain attack",
			url:         "https://packagist.org.evil.com/api/update-package",
			wantErr:     true,
			errContains: "must be on packagist.org domain",
		},
		{
			name:        "similar domain attack",
			url:         "https://evil-packagist.org/api/update-package",
			wantErr:     true,
			errContains: "must be on packagist.org domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errContains)
				} else if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing '%s', got '%s'", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got '%s'", err.Error())
				}
			}
		})
	}
}

func TestValidate(t *testing.T) {
	p := &PackagistPlugin{}
	ctx := context.Background()

	tests := []struct {
		name      string
		config    map[string]any
		envVars   map[string]string
		wantValid bool
	}{
		{
			name:      "missing package_name",
			config:    map[string]any{},
			wantValid: false,
		},
		{
			name: "empty package_name",
			config: map[string]any{
				"package_name": "",
			},
			wantValid: false,
		},
		{
			name: "invalid package_name format",
			config: map[string]any{
				"package_name": "invalid-no-slash",
			},
			wantValid: false,
		},
		{
			name: "valid config with package_name only",
			config: map[string]any{
				"package_name": "vendor/package",
			},
			wantValid: true,
		},
		{
			name: "valid config with all options",
			config: map[string]any{
				"package_name": "vendor/package",
				"api_token":    "secret-token",
				"username":     "myuser",
				"auto_update":  true,
			},
			wantValid: true,
		},
		{
			name: "valid config with auto_update disabled",
			config: map[string]any{
				"package_name": "vendor/package",
				"auto_update":  false,
			},
			wantValid: true,
		},
		{
			name: "valid config with env vars",
			config: map[string]any{
				"package_name": "vendor/package",
			},
			envVars: map[string]string{
				"PACKAGIST_API_TOKEN": "env-token",
				"PACKAGIST_USERNAME":  "env-user",
			},
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear any existing env vars.
			_ = os.Unsetenv("PACKAGIST_API_TOKEN")
			_ = os.Unsetenv("PACKAGIST_USERNAME")

			// Set env vars for this test.
			for k, v := range tt.envVars {
				_ = os.Setenv(k, v)
				defer func(key string) { _ = os.Unsetenv(key) }(k)
			}

			resp, err := p.Validate(ctx, tt.config)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Valid != tt.wantValid {
				t.Errorf("expected valid=%v, got valid=%v, errors=%v", tt.wantValid, resp.Valid, resp.Errors)
			}
		})
	}
}

func TestParseConfig(t *testing.T) {
	p := &PackagistPlugin{}

	tests := []struct {
		name     string
		config   map[string]any
		envVars  map[string]string
		expected Config
	}{
		{
			name:   "defaults",
			config: map[string]any{},
			expected: Config{
				PackageName: "",
				APIToken:    "",
				Username:    "",
				AutoUpdate:  true,
			},
		},
		{
			name: "custom values",
			config: map[string]any{
				"package_name": "vendor/package",
				"api_token":    "my-token",
				"username":     "myuser",
				"auto_update":  false,
			},
			expected: Config{
				PackageName: "vendor/package",
				APIToken:    "my-token",
				Username:    "myuser",
				AutoUpdate:  false,
			},
		},
		{
			name:   "env var fallback for api_token",
			config: map[string]any{},
			envVars: map[string]string{
				"PACKAGIST_API_TOKEN": "env-token",
			},
			expected: Config{
				PackageName: "",
				APIToken:    "env-token",
				Username:    "",
				AutoUpdate:  true,
			},
		},
		{
			name:   "env var fallback for username",
			config: map[string]any{},
			envVars: map[string]string{
				"PACKAGIST_USERNAME": "env-user",
			},
			expected: Config{
				PackageName: "",
				APIToken:    "",
				Username:    "env-user",
				AutoUpdate:  true,
			},
		},
		{
			name: "env vars for both api_token and username",
			config: map[string]any{
				"package_name": "vendor/package",
			},
			envVars: map[string]string{
				"PACKAGIST_API_TOKEN": "env-token",
				"PACKAGIST_USERNAME":  "env-user",
			},
			expected: Config{
				PackageName: "vendor/package",
				APIToken:    "env-token",
				Username:    "env-user",
				AutoUpdate:  true,
			},
		},
		{
			name: "config values override env vars",
			config: map[string]any{
				"package_name": "vendor/package",
				"api_token":    "config-token",
				"username":     "config-user",
			},
			envVars: map[string]string{
				"PACKAGIST_API_TOKEN": "env-token",
				"PACKAGIST_USERNAME":  "env-user",
			},
			expected: Config{
				PackageName: "vendor/package",
				APIToken:    "config-token",
				Username:    "config-user",
				AutoUpdate:  true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear any existing env vars.
			_ = os.Unsetenv("PACKAGIST_API_TOKEN")
			_ = os.Unsetenv("PACKAGIST_USERNAME")

			// Set env vars for this test.
			for k, v := range tt.envVars {
				_ = os.Setenv(k, v)
				defer func(key string) { _ = os.Unsetenv(key) }(k)
			}

			cfg := p.parseConfig(tt.config)

			if cfg.PackageName != tt.expected.PackageName {
				t.Errorf("package_name: expected '%s', got '%s'", tt.expected.PackageName, cfg.PackageName)
			}
			if cfg.APIToken != tt.expected.APIToken {
				t.Errorf("api_token: expected '%s', got '%s'", tt.expected.APIToken, cfg.APIToken)
			}
			if cfg.Username != tt.expected.Username {
				t.Errorf("username: expected '%s', got '%s'", tt.expected.Username, cfg.Username)
			}
			if cfg.AutoUpdate != tt.expected.AutoUpdate {
				t.Errorf("auto_update: expected %v, got %v", tt.expected.AutoUpdate, cfg.AutoUpdate)
			}
		})
	}
}

func TestExecuteDryRun(t *testing.T) {
	p := &PackagistPlugin{}
	ctx := context.Background()

	tests := []struct {
		name               string
		config             map[string]any
		releaseCtx         plugin.ReleaseContext
		expectedPackage    string
		expectedAutoUpdate bool
	}{
		{
			name: "basic execution",
			config: map[string]any{
				"package_name": "vendor/package",
				"api_token":    "test-token",
				"username":     "test-user",
			},
			releaseCtx: plugin.ReleaseContext{
				Version: "v1.2.3",
			},
			expectedPackage:    "vendor/package",
			expectedAutoUpdate: true,
		},
		{
			name: "execution with all options",
			config: map[string]any{
				"package_name": "myvendor/mypackage",
				"api_token":    "secret-token",
				"username":     "myuser",
				"auto_update":  true,
			},
			releaseCtx: plugin.ReleaseContext{
				Version: "v3.1.4",
			},
			expectedPackage:    "myvendor/mypackage",
			expectedAutoUpdate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := plugin.ExecuteRequest{
				Hook:    plugin.HookPostPublish,
				Config:  tt.config,
				Context: tt.releaseCtx,
				DryRun:  true,
			}

			resp, err := p.Execute(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !resp.Success {
				t.Errorf("expected success, got error: %s", resp.Error)
			}

			if resp.Message != "Would trigger Packagist package update" {
				t.Errorf("expected dry run message, got: %s", resp.Message)
			}

			// Check outputs.
			if resp.Outputs == nil {
				t.Fatal("expected outputs to be set")
			}

			packageName, ok := resp.Outputs["package_name"].(string)
			if !ok {
				t.Fatal("expected package_name in outputs")
			}
			if packageName != tt.expectedPackage {
				t.Errorf("package_name: expected '%s', got '%s'", tt.expectedPackage, packageName)
			}

			autoUpdate, ok := resp.Outputs["auto_update"].(bool)
			if !ok {
				t.Fatal("expected auto_update in outputs")
			}
			if autoUpdate != tt.expectedAutoUpdate {
				t.Errorf("auto_update: expected %v, got %v", tt.expectedAutoUpdate, autoUpdate)
			}
		})
	}
}

func TestExecuteAutoUpdateDisabled(t *testing.T) {
	p := &PackagistPlugin{}
	ctx := context.Background()

	req := plugin.ExecuteRequest{
		Hook: plugin.HookPostPublish,
		Config: map[string]any{
			"package_name": "vendor/package",
			"auto_update":  false,
		},
		Context: plugin.ReleaseContext{
			Version: "v2.0.0",
		},
		DryRun: false,
	}

	resp, err := p.Execute(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Success {
		t.Errorf("expected success, got error: %s", resp.Error)
	}

	if resp.Message != "Packagist auto-update is disabled" {
		t.Errorf("expected auto-update disabled message, got: %s", resp.Message)
	}

	// Check outputs.
	if resp.Outputs == nil {
		t.Fatal("expected outputs to be set")
	}

	skipped, ok := resp.Outputs["skipped"].(bool)
	if !ok || !skipped {
		t.Error("expected skipped=true in outputs")
	}
}

func TestExecuteMissingCredentials(t *testing.T) {
	p := &PackagistPlugin{}
	ctx := context.Background()

	tests := []struct {
		name        string
		config      map[string]any
		errContains string
	}{
		{
			name: "missing username",
			config: map[string]any{
				"package_name": "vendor/package",
				"api_token":    "test-token",
			},
			errContains: "username is required",
		},
		{
			name: "missing api_token",
			config: map[string]any{
				"package_name": "vendor/package",
				"username":     "test-user",
			},
			errContains: "API token is required",
		},
		{
			name: "missing both",
			config: map[string]any{
				"package_name": "vendor/package",
			},
			errContains: "username is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env vars.
			_ = os.Unsetenv("PACKAGIST_API_TOKEN")
			_ = os.Unsetenv("PACKAGIST_USERNAME")

			req := plugin.ExecuteRequest{
				Hook:    plugin.HookPostPublish,
				Config:  tt.config,
				Context: plugin.ReleaseContext{Version: "v1.0.0"},
				DryRun:  false,
			}

			resp, err := p.Execute(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Success {
				t.Error("expected failure due to missing credentials")
			}

			if !strings.Contains(resp.Error, tt.errContains) {
				t.Errorf("expected error containing '%s', got: %s", tt.errContains, resp.Error)
			}
		})
	}
}

func TestExecuteInvalidPackageName(t *testing.T) {
	p := &PackagistPlugin{}
	ctx := context.Background()

	tests := []struct {
		name        string
		packageName string
		errContains string
	}{
		{
			name:        "empty package name",
			packageName: "",
			errContains: "cannot be empty",
		},
		{
			name:        "missing slash",
			packageName: "vendorpackage",
			errContains: "invalid package name format",
		},
		{
			name:        "path traversal",
			packageName: "../vendor/package",
			errContains: "invalid package name format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := plugin.ExecuteRequest{
				Hook: plugin.HookPostPublish,
				Config: map[string]any{
					"package_name": tt.packageName,
					"api_token":    "test-token",
					"username":     "test-user",
				},
				Context: plugin.ReleaseContext{Version: "v1.0.0"},
				DryRun:  false,
			}

			resp, err := p.Execute(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Success {
				t.Error("expected failure due to invalid package name")
			}

			if !strings.Contains(resp.Error, tt.errContains) {
				t.Errorf("expected error containing '%s', got: %s", tt.errContains, resp.Error)
			}
		})
	}
}

func TestExecuteHTTPSuccess(t *testing.T) {
	// Store original client and restore after test.
	originalClient := httpClient
	defer func() { httpClient = originalClient }()

	// Set up mock HTTP client.
	var capturedRequest *http.Request
	var capturedBody []byte
	httpClient = &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			capturedRequest = req
			body, _ := io.ReadAll(req.Body)
			capturedBody = body
			return mockResponse(http.StatusOK, `{"status":"success"}`), nil
		},
	}

	p := &PackagistPlugin{}
	ctx := context.Background()

	req := plugin.ExecuteRequest{
		Hook: plugin.HookPostPublish,
		Config: map[string]any{
			"package_name": "vendor/package",
			"api_token":    "test-token",
			"username":     "test-user",
		},
		Context: plugin.ReleaseContext{
			Version: "v1.2.3",
		},
		DryRun: false,
	}

	resp, err := p.Execute(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !resp.Success {
		t.Errorf("expected success, got error: %s", resp.Error)
	}

	if !strings.Contains(resp.Message, "update triggered successfully") {
		t.Errorf("expected success message, got: %s", resp.Message)
	}

	// Verify HTTP request details.
	if capturedRequest == nil {
		t.Fatal("expected HTTP request to be captured")
	}

	if capturedRequest.Method != http.MethodPost {
		t.Errorf("expected POST method, got: %s", capturedRequest.Method)
	}

	if capturedRequest.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got: %s", capturedRequest.Header.Get("Content-Type"))
	}

	// Verify URL contains username and apiToken.
	requestURL := capturedRequest.URL.String()
	if !strings.Contains(requestURL, "username=test-user") {
		t.Errorf("expected URL to contain username, got: %s", requestURL)
	}
	if !strings.Contains(requestURL, "apiToken=test-token") {
		t.Errorf("expected URL to contain apiToken, got: %s", requestURL)
	}

	// Verify request body.
	var updateReq UpdateRequest
	if err := json.Unmarshal(capturedBody, &updateReq); err != nil {
		t.Fatalf("failed to unmarshal request body: %v", err)
	}

	expectedRepoURL := "https://packagist.org/packages/vendor/package"
	if updateReq.Repository.URL != expectedRepoURL {
		t.Errorf("expected repository URL '%s', got '%s'", expectedRepoURL, updateReq.Repository.URL)
	}

	// Verify outputs.
	if resp.Outputs == nil {
		t.Fatal("expected outputs to be set")
	}

	if resp.Outputs["version"] != "v1.2.3" {
		t.Errorf("expected version 'v1.2.3', got '%v'", resp.Outputs["version"])
	}
}

func TestExecuteHTTPError(t *testing.T) {
	// Store original client and restore after test.
	originalClient := httpClient
	defer func() { httpClient = originalClient }()

	tests := []struct {
		name        string
		mockFunc    func(req *http.Request) (*http.Response, error)
		errContains string
	}{
		{
			name: "network error",
			mockFunc: func(req *http.Request) (*http.Response, error) {
				return nil, fmt.Errorf("network connection refused")
			},
			errContains: "failed to send request",
		},
		{
			name: "401 unauthorized",
			mockFunc: func(req *http.Request) (*http.Response, error) {
				return mockResponse(http.StatusUnauthorized, `{"error":"invalid credentials"}`), nil
			},
			errContains: "status 401",
		},
		{
			name: "403 forbidden",
			mockFunc: func(req *http.Request) (*http.Response, error) {
				return mockResponse(http.StatusForbidden, `{"error":"access denied"}`), nil
			},
			errContains: "status 403",
		},
		{
			name: "404 not found",
			mockFunc: func(req *http.Request) (*http.Response, error) {
				return mockResponse(http.StatusNotFound, `{"error":"package not found"}`), nil
			},
			errContains: "status 404",
		},
		{
			name: "500 server error",
			mockFunc: func(req *http.Request) (*http.Response, error) {
				return mockResponse(http.StatusInternalServerError, `{"error":"internal server error"}`), nil
			},
			errContains: "status 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpClient = &mockHTTPClient{DoFunc: tt.mockFunc}

			p := &PackagistPlugin{}
			ctx := context.Background()

			req := plugin.ExecuteRequest{
				Hook: plugin.HookPostPublish,
				Config: map[string]any{
					"package_name": "vendor/package",
					"api_token":    "test-token",
					"username":     "test-user",
				},
				Context: plugin.ReleaseContext{Version: "v1.0.0"},
				DryRun:  false,
			}

			resp, err := p.Execute(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if resp.Success {
				t.Error("expected failure due to HTTP error")
			}

			if !strings.Contains(resp.Error, tt.errContains) {
				t.Errorf("expected error containing '%s', got: %s", tt.errContains, resp.Error)
			}
		})
	}
}

func TestExecuteHTTPVariousSuccessStatusCodes(t *testing.T) {
	// Store original client and restore after test.
	originalClient := httpClient
	defer func() { httpClient = originalClient }()

	successCodes := []int{200, 201, 202, 204}

	for _, statusCode := range successCodes {
		t.Run(fmt.Sprintf("status_%d", statusCode), func(t *testing.T) {
			httpClient = &mockHTTPClient{
				DoFunc: func(req *http.Request) (*http.Response, error) {
					return mockResponse(statusCode, `{"status":"ok"}`), nil
				},
			}

			p := &PackagistPlugin{}
			ctx := context.Background()

			req := plugin.ExecuteRequest{
				Hook: plugin.HookPostPublish,
				Config: map[string]any{
					"package_name": "vendor/package",
					"api_token":    "test-token",
					"username":     "test-user",
				},
				Context: plugin.ReleaseContext{Version: "v1.0.0"},
				DryRun:  false,
			}

			resp, err := p.Execute(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !resp.Success {
				t.Errorf("expected success for status %d, got error: %s", statusCode, resp.Error)
			}
		})
	}
}

func TestExecuteUnhandledHook(t *testing.T) {
	p := &PackagistPlugin{}
	ctx := context.Background()

	tests := []struct {
		name string
		hook plugin.Hook
	}{
		{
			name: "PreInit hook",
			hook: plugin.HookPreInit,
		},
		{
			name: "PostInit hook",
			hook: plugin.HookPostInit,
		},
		{
			name: "PreVersion hook",
			hook: plugin.HookPreVersion,
		},
		{
			name: "PostVersion hook",
			hook: plugin.HookPostVersion,
		},
		{
			name: "PreNotes hook",
			hook: plugin.HookPreNotes,
		},
		{
			name: "PostNotes hook",
			hook: plugin.HookPostNotes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := plugin.ExecuteRequest{
				Hook:   tt.hook,
				Config: map[string]any{"package_name": "vendor/package"},
				DryRun: true,
			}

			resp, err := p.Execute(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !resp.Success {
				t.Error("expected success for unhandled hook")
			}

			expectedMsg := "Hook " + string(tt.hook) + " not handled"
			if resp.Message != expectedMsg {
				t.Errorf("expected message '%s', got '%s'", expectedMsg, resp.Message)
			}
		})
	}
}

func TestTriggerPackagistUpdateRequestFormat(t *testing.T) {
	// Store original client and restore after test.
	originalClient := httpClient
	defer func() { httpClient = originalClient }()

	var capturedRequest *http.Request
	var capturedBody []byte
	httpClient = &mockHTTPClient{
		DoFunc: func(req *http.Request) (*http.Response, error) {
			capturedRequest = req
			body, _ := io.ReadAll(req.Body)
			capturedBody = body
			// Replace the body so it can be read again if needed.
			req.Body = io.NopCloser(bytes.NewReader(body))
			return mockResponse(http.StatusOK, `{}`), nil
		},
	}

	p := &PackagistPlugin{}
	ctx := context.Background()

	cfg := &Config{
		PackageName: "symfony/console",
		APIToken:    "my-api-token",
		Username:    "my-username",
	}

	err := p.triggerPackagistUpdate(ctx, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify request URL format.
	expectedURLPrefix := "https://packagist.org/api/update-package?"
	if !strings.HasPrefix(capturedRequest.URL.String(), expectedURLPrefix) {
		t.Errorf("expected URL to start with '%s', got: %s", expectedURLPrefix, capturedRequest.URL.String())
	}

	// Verify query parameters.
	query := capturedRequest.URL.Query()
	if query.Get("username") != "my-username" {
		t.Errorf("expected username 'my-username', got: %s", query.Get("username"))
	}
	if query.Get("apiToken") != "my-api-token" {
		t.Errorf("expected apiToken 'my-api-token', got: %s", query.Get("apiToken"))
	}

	// Verify request body JSON structure.
	var updateReq UpdateRequest
	if err := json.Unmarshal(capturedBody, &updateReq); err != nil {
		t.Fatalf("failed to unmarshal request body: %v", err)
	}

	expectedRepoURL := "https://packagist.org/packages/symfony/console"
	if updateReq.Repository.URL != expectedRepoURL {
		t.Errorf("expected repository URL '%s', got '%s'", expectedRepoURL, updateReq.Repository.URL)
	}
}

func TestGetHTTPClientDefault(t *testing.T) {
	// Store original client and restore after test.
	originalClient := httpClient
	defer func() { httpClient = originalClient }()

	// Reset to nil to test default behavior.
	httpClient = nil

	client := getHTTPClient()
	if client == nil {
		t.Error("expected non-nil HTTP client")
	}

	if client != defaultHTTPClient {
		t.Error("expected default HTTP client to be returned")
	}
}

func TestGetHTTPClientCustom(t *testing.T) {
	// Store original client and restore after test.
	originalClient := httpClient
	defer func() { httpClient = originalClient }()

	// Set a custom client.
	customClient := &mockHTTPClient{}
	httpClient = customClient

	client := getHTTPClient()
	if client != customClient {
		t.Error("expected custom HTTP client to be returned")
	}
}

func TestDefaultHTTPClientConfig(t *testing.T) {
	// Verify timeout is set.
	if defaultHTTPClient.Timeout == 0 {
		t.Error("expected timeout to be set on default HTTP client")
	}

	// Verify transport is set.
	transport, ok := defaultHTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected transport to be *http.Transport")
	}

	// Verify TLS config.
	if transport.TLSClientConfig == nil {
		t.Error("expected TLS config to be set")
	}

	// Verify minimum TLS version.
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS13 {
		t.Error("expected minimum TLS version to be TLS 1.3")
	}

	// Verify connection pool settings.
	if transport.MaxIdleConns == 0 {
		t.Error("expected MaxIdleConns to be set")
	}
	if transport.MaxIdleConnsPerHost == 0 {
		t.Error("expected MaxIdleConnsPerHost to be set")
	}
}

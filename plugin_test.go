// Package main provides tests for the Packagist plugin.
package main

import (
	"context"
	"os"
	"testing"

	"github.com/relicta-tech/relicta-plugin-sdk/plugin"
)

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

	// Check hooks
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

	// Check config schema is valid JSON
	if info.ConfigSchema == "" {
		t.Error("expected non-empty config schema")
	}
}

func TestValidate(t *testing.T) {
	p := &PackagistPlugin{}
	ctx := context.Background()

	tests := []struct {
		name      string
		config    map[string]any
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			// Clear any existing env vars
			os.Unsetenv("PACKAGIST_API_TOKEN")
			os.Unsetenv("PACKAGIST_USERNAME")

			// Set env vars for this test
			for k, v := range tt.envVars {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
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
			},
			releaseCtx: plugin.ReleaseContext{
				Version: "v1.2.3",
			},
			expectedPackage:    "vendor/package",
			expectedAutoUpdate: true,
		},
		{
			name: "execution with auto_update disabled",
			config: map[string]any{
				"package_name": "vendor/package",
				"auto_update":  false,
			},
			releaseCtx: plugin.ReleaseContext{
				Version: "v2.0.0",
			},
			expectedPackage:    "vendor/package",
			expectedAutoUpdate: false,
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

			// Check outputs
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

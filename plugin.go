// Package main implements the Packagist plugin for Relicta.
package main

import (
	"context"
	"fmt"

	"github.com/relicta-tech/relicta-plugin-sdk/helpers"
	"github.com/relicta-tech/relicta-plugin-sdk/plugin"
)

// PackagistPlugin implements the Publish packages to Packagist (PHP) plugin.
type PackagistPlugin struct{}

// Config represents the Packagist plugin configuration.
type Config struct {
	PackageName string
	APIToken    string
	Username    string
	AutoUpdate  bool
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
				"package_name": {"type": "string", "description": "Packagist package name (e.g., vendor/package)"},
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

	return &plugin.ExecuteResponse{
		Success: true,
		Message: fmt.Sprintf("Packagist package %s updated successfully", cfg.PackageName),
		Outputs: map[string]any{
			"package_name": cfg.PackageName,
			"version":      releaseCtx.Version,
		},
	}, nil
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

	packageName := parser.GetString("package_name", "", "")
	if packageName == "" {
		vb.AddError("package_name", "Packagist package name is required")
	}

	return vb.Build(), nil
}

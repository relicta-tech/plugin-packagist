# Packagist Plugin for Relicta

Official Packagist plugin for [Relicta](https://github.com/relicta-tech/relicta) - Publish packages to Packagist (PHP).

## Installation

```bash
relicta plugin install packagist
relicta plugin enable packagist
```

## Configuration

Add to your `release.config.yaml`:

```yaml
plugins:
  - name: packagist
    enabled: true
    config:
      # Add configuration options here
```

## License

MIT License - see [LICENSE](LICENSE) for details.

# Changelog

## 1.1.0

- `--format json` and `--format sarif` (works with GitHub code scanning)
- `# gha-audit: ignore[rule]` and `# gha-audit: ignore-file[rule]` comments
- New LOW rule `checkout-persist-credentials`. Workflows that were clean before may now report it; use
  `--min-severity MEDIUM` to keep the old threshold
- Installable with pip (`gha-audit` command), CI on Linux and macOS

## 1.0.0

Initial release.

# gha-audit

Audit your GitHub Actions workflow files for common security mistakes. It works
**offline** and is read-only: point it at `.github/workflows` and it explains each
problem with a suggested fix. One file, standard library only.

## Usage

```bash
python3 gha_audit.py                       # defaults to .github/workflows
python3 gha_audit.py path/to/ci.yml other-folder/ --min-severity MEDIUM
python3 gha_audit.py --format json                 # machine-readable
python3 gha_audit.py --format sarif > gha.sarif    # GitHub code scanning
# or: pip install git+https://github.com/TPOALOS/gha-audit && gha-audit
```

Example output:

```
HIGH   script-injection  ci.yml:14: untrusted value is expanded directly inside a shell command
         fix: pass it through `env:` and use "$VAR" in the script
HIGH   unpinned-action   ci.yml:9: acme/deploy@main follows a mutable branch
         fix: pin to a full commit SHA
MEDIUM missing-permissions  ci.yml: no `permissions:` block; the token may default to broad write access
         fix: add top-level `permissions: contents: read` and widen per job if needed
```

## Checks

| Rule | Severity | What it flags |
|------|----------|---------------|
| `unpinned-action` | HIGH / MEDIUM / LOW | `uses:` not pinned to a 40-character commit SHA (branch refs are worst; `actions/*` tags are the mildest) |
| `script-injection` | HIGH | attacker-controlled values (issue/PR titles and bodies, branch names, comments, commit messages) expanded inside `run:` commands |
| `pull-request-target-checkout` | HIGH | `pull_request_target` workflows that check out the pull request head |
| `write-all-permissions` | HIGH | `permissions: write-all` |
| `missing-permissions` | MEDIUM | no `permissions:` block anywhere |
| `curl-pipe-shell` | MEDIUM | `curl ... \| bash` style installs |
| `self-hosted-on-pr` | MEDIUM | self-hosted runners in workflows triggered by pull requests |
| `unsecure-commands` | HIGH | `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` |
| `secret-in-command` | LOW | `${{ secrets.X }}` expanded inline in a shell command |
| `checkout-persist-credentials` | LOW | `actions/checkout` without `persist-credentials: false`, which leaves the token in `.git/config` for later steps |

Exit codes: `0` clean, `1` findings, `2` unreadable file or nothing to scan.

### Silencing a finding you accept

```yaml
      - uses: acme/internal-tool@main   # gha-audit: ignore[unpinned-action]
```

`# gha-audit: ignore` silences every rule on that line, `# gha-audit: ignore-file[rule1,rule2]` silences rules
for the whole file (use `ignore-file` without a list to silence everything).

### Upload to GitHub code scanning

```yaml
      - run: python3 gha_audit.py --format sarif > gha.sarif || true
      - uses: github/codeql-action/upload-sarif@<full-commit-sha>
        with:
          sarif_file: gha.sarif
```

## Limits

Python's standard library has no YAML parser, so the checks are line-based heuristics:
- Reusable workflows, composite actions and YAML anchors are not resolved.
- `permissions:` is detected anywhere in the file, not per job.
- `pull-request-target-checkout` looks for a `ref:` line that uses PR head values in a
  file that has a `pull_request_target` trigger.
- It may miss issues and may flag harmless lines. Treat results as review hints; for
  deeper analysis combine it with a full YAML-aware tool.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS

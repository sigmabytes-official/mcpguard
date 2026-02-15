# mcpguard

Offline-first security auditor for MCP (Model Context Protocol) configurations.

Scans your AI tool configs (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf) for hardcoded secrets, overpermissions, supply chain vulnerabilities, and dangerous server combinations — before anything runs.

## Quick Start

```bash
npx mcpguard
```

That's it. Zero config, zero dependencies to install.

## What It Detects

- **Hardcoded secrets** — API keys, tokens, passwords, database URLs (21+ patterns including AWS, GitHub, Anthropic, OpenAI, Stripe, Slack)
- **Overpermissions** — Root filesystem access, shell execution, unrestricted network/database access
- **Command injection vectors** — Shell metacharacters, command substitution in server arguments
- **Transport security** — HTTP without TLS, missing authentication on remote servers
- **Supply chain vulnerabilities** — Known CVEs in MCP packages (e.g., CVE-2025-6514 in mcp-remote), OSV.dev lookup
- **Blast radius analysis** — Dangerous server combinations (filesystem + shell = full system compromise)
- **OWASP ASI mapping** — Every finding tagged to OWASP Agentic Security Top 10

## Supported Clients

| Client | Config Locations |
|--------|-----------------|
| Claude Desktop | System app data directory |
| Claude Code | `.mcp.json` (project), `~/.claude.json` (user) |
| Cursor | `.cursor/mcp.json` (project), `~/.cursor/mcp.json` (global) |
| VS Code | `.vscode/mcp.json` (workspace), user settings |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

## Usage

```bash
# Scan all detected configs
npx mcpguard

# Scan specific config file
npx mcpguard scan --config ./my-mcp-config.json

# JSON output
npx mcpguard scan --format json

# HTML report
npx mcpguard scan --format html --output report.html

# SARIF for GitHub Advanced Security
npx mcpguard scan --format sarif > results.sarif

# CI/CD: fail on high severity or above
npx mcpguard scan --fail-on high --quiet

# Include supply chain CVE checks (requires network)
npx mcpguard scan --supply-chain

# Scan only specific clients
npx mcpguard scan --clients claude-desktop cursor
```

## CI/CD Integration

### GitHub Actions

```yaml
name: MCP Security Audit
on: [push, pull_request]
jobs:
  mcp-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan MCP configurations
        run: npx mcpguard scan --fail-on high --format sarif --output mcp.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcp.sarif
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Terminal | `--format terminal` (default) | Human-readable with colors |
| JSON | `--format json` | Machine-readable, CI/CD pipelines |
| SARIF | `--format sarif` | GitHub Advanced Security |
| HTML | `--format html` | Shareable standalone reports |

## How It Works

1. **Discovery** — Auto-detects MCP config files across all supported AI clients on macOS, Windows, and Linux
2. **Analysis** — Runs 6 analyzers in parallel: secrets, permissions, command injection, transport security, supply chain, blast radius
3. **Scoring** — Calculates per-finding severity scores and a machine-wide risk score (0-100)
4. **Reporting** — Outputs findings with OWASP ASI mapping and actionable remediation advice

## Why mcpguard?

| | mcpguard | mcp-scan (Snyk) | Proximity |
|---|---------|-----------------|-----------|
| Offline-first | Yes | No (needs API) | No (needs LLM) |
| Secrets scanning | 21+ patterns | No | No |
| Multi-client discovery | 5 clients | 4 clients | Single server |
| Cross-client blast radius | Yes | No | No |
| OWASP ASI mapping | Yes | No | No |
| SARIF output | Yes | No | No |
| Supply chain CVE check | Yes (OSV.dev) | No | No |
| Install friction | `npx mcpguard` | `pipx run` | Clone + install |

**Positioning**: mcp-scan analyzes *running* servers at runtime. mcpguard audits *configurations before anything runs*. They're complementary.

## License

MIT

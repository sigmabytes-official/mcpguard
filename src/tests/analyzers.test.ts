import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseConfig } from '../discovery/parser.js';
import { analyzeSecrets } from '../analyzers/secrets.js';
import { analyzePermissions } from '../analyzers/permissions.js';
import { analyzeCommandInjection } from '../analyzers/command-injection.js';
import { analyzeTransportSecurity } from '../analyzers/transport-security.js';
import { analyzeBlastRadius } from '../analyzers/blast-radius.js';
import { analyzeSupplyChain } from '../analyzers/supply-chain.js';
import { calculateMachineRiskScore, exceedsThreshold, sortFindings } from '../rules/severity.js';
import type { McpServerConfig } from '../types/config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(__dirname, 'fixtures');

async function loadFixture(name: string): Promise<unknown> {
  const content = await fs.readFile(path.join(fixturesDir, name), 'utf-8');
  return JSON.parse(content);
}

describe('Config Parser', () => {
  it('should parse mcpServers key (Claude Desktop format)', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    assert.ok(servers.length > 0, 'Should find servers');
    assert.ok(servers.some(s => s.name === 'filesystem'), 'Should find filesystem server');
    assert.ok(servers.some(s => s.name === 'github'), 'Should find github server');
  });

  it('should parse servers key (VS Code format)', async () => {
    const raw = await loadFixture('vscode-servers-key.json');
    const servers = parseConfig(raw, 'vscode', '/test/vscode.json');
    assert.ok(servers.length > 0, 'Should find servers');
    assert.ok(servers.some(s => s.name === 'my-server'), 'Should find my-server');
  });

  it('should extract package names from npx args', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const fs = servers.find(s => s.name === 'filesystem');
    assert.equal(fs?.packageName, '@modelcontextprotocol/server-filesystem');
  });

  it('should detect HTTP and SSE transport types', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const remote = servers.find(s => s.name === 'remote-insecure');
    assert.equal(remote?.transport, 'sse');
    assert.equal(remote?.url, 'http://mcp.example.com/sse');
  });

  it('should return empty for null/undefined input', () => {
    assert.deepEqual(parseConfig(null, 'custom', '/test'), []);
    assert.deepEqual(parseConfig(undefined, 'custom', '/test'), []);
    assert.deepEqual(parseConfig({}, 'custom', '/test'), []);
  });
});

describe('Secrets Analyzer', () => {
  it('should detect GitHub token', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzeSecrets(servers);
    const ghFinding = findings.find(f => f.title.includes('GitHub'));
    assert.ok(ghFinding, 'Should detect GitHub token');
    assert.equal(ghFinding.severity, 'critical');
  });

  it('should detect Anthropic API key', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzeSecrets(servers);
    const antFinding = findings.find(f => f.title.includes('Anthropic'));
    assert.ok(antFinding, 'Should detect Anthropic API key');
    assert.equal(antFinding.severity, 'critical');
  });

  it('should detect database connection string', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzeSecrets(servers);
    const dbFinding = findings.find(f => f.title.includes('Database'));
    assert.ok(dbFinding, 'Should detect database connection string');
    assert.equal(dbFinding.severity, 'critical');
  });

  it('should mask secrets in evidence', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzeSecrets(servers);
    for (const f of findings) {
      assert.ok(!f.evidence.includes('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ'), 'Should not contain full secret');
    }
  });

  it('should not flag safe configs', async () => {
    const raw = await loadFixture('claude-desktop-safe.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzeSecrets(servers);
    assert.equal(findings.length, 0, 'Should have no secret findings');
  });

  it('should detect secrets in headers', async () => {
    const raw = await loadFixture('vscode-servers-key.json');
    const servers = parseConfig(raw, 'vscode', '/test/vscode.json');
    const findings = analyzeSecrets(servers);
    const headerFinding = findings.find(f => f.location.includes('headers'));
    assert.ok(headerFinding, 'Should detect Bearer token in headers');
  });
});

describe('Permissions Analyzer', () => {
  it('should flag root filesystem access', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzePermissions(servers);
    const rootFs = findings.find(f => f.rule === 'overpermission-root-filesystem');
    assert.ok(rootFs, 'Should detect root filesystem access');
    assert.equal(rootFs.severity, 'critical');
  });

  it('should flag shell execution servers', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzePermissions(servers);
    const shellFinding = findings.find(f => f.rule === 'overpermission-shell');
    assert.ok(shellFinding, 'Should detect shell execution');
    assert.equal(shellFinding.severity, 'critical');
  });

  it('should flag database access', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzePermissions(servers);
    const dbFinding = findings.find(f => f.rule === 'overpermission-database');
    assert.ok(dbFinding, 'Should detect database access');
  });

  it('should not flag memory server as dangerous', async () => {
    const raw = await loadFixture('claude-desktop-safe.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzePermissions(servers);
    const criticalFindings = findings.filter(f => f.severity === 'critical');
    assert.equal(criticalFindings.length, 0, 'Memory server should have no critical findings');
  });
});

describe('Transport Security Analyzer', () => {
  it('should flag HTTP remote server', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzeTransportSecurity(servers);
    const httpFinding = findings.find(f => f.rule === 'transport-no-tls');
    assert.ok(httpFinding, 'Should detect HTTP transport');
    assert.equal(httpFinding.severity, 'high');
  });

  it('should flag missing auth on remote server', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzeTransportSecurity(servers);
    const authFinding = findings.find(f => f.rule === 'transport-no-auth');
    assert.ok(authFinding, 'Should detect missing auth');
  });

  it('should not flag stdio servers', async () => {
    const raw = await loadFixture('claude-desktop-safe.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzeTransportSecurity(servers);
    assert.equal(findings.length, 0, 'Stdio servers should have no transport findings');
  });
});

describe('Supply Chain Analyzer', () => {
  it('should detect known vulnerable package (mcp-remote)', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    // Disable network to only test offline detection
    const findings = await analyzeSupplyChain(servers, { enabled: false });
    const vulnFinding = findings.find(f => f.rule === 'supply-chain-known-vulnerable');
    assert.ok(vulnFinding, 'Should detect mcp-remote vulnerability');
    assert.ok(vulnFinding.evidence.includes('CVE-2025-6514'));
  });
});

describe('Blast Radius Analyzer', () => {
  it('should detect filesystem + shell escalation', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzeBlastRadius(servers);
    const fsShell = findings.find(f => f.title.includes('Filesystem + Shell'));
    assert.ok(fsShell, 'Should detect filesystem + shell combination');
    assert.equal(fsShell.severity, 'critical');
  });

  it('should detect database + network escalation', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzeBlastRadius(servers);
    const dbNet = findings.find(f => f.title.includes('Database + Network'));
    assert.ok(dbNet, 'Should detect database + network combination');
  });

  it('should have no escalation paths for safe config', async () => {
    const raw = await loadFixture('claude-desktop-safe.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzeBlastRadius(servers);
    const critical = findings.filter(f => f.severity === 'critical');
    assert.equal(critical.length, 0, 'Safe config should have no critical blast radius');
  });
});

describe('Scoring', () => {
  it('should return 0 for no findings', () => {
    assert.equal(calculateMachineRiskScore([]), 0);
  });

  it('should return high score for critical findings', async () => {
    const raw = await loadFixture('claude-desktop-vulnerable.json');
    const servers = parseConfig(raw, 'claude-desktop', '/test/config.json');
    const findings = analyzeSecrets(servers);
    const score = calculateMachineRiskScore(findings);
    assert.ok(score >= 70, `Score should be high for critical secrets, got ${score}`);
  });

  it('should sort findings by severity', () => {
    const findings: any[] = [
      { severity: 'low', score: 25 },
      { severity: 'critical', score: 95 },
      { severity: 'medium', score: 50 },
    ];
    const sorted = sortFindings(findings);
    assert.equal(sorted[0].severity, 'critical');
    assert.equal(sorted[2].severity, 'low');
  });

  it('should detect threshold exceeded', () => {
    const findings: any[] = [
      { severity: 'high', score: 75 },
      { severity: 'low', score: 25 },
    ];
    assert.ok(exceedsThreshold(findings, 'high'));
    assert.ok(exceedsThreshold(findings, 'medium'));
    assert.ok(!exceedsThreshold(findings, 'critical'));
  });
});

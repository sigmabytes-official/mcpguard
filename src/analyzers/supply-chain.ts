import type { McpServerConfig } from '../types/config.js';
import type { Finding } from '../types/findings.js';
import { RULES } from '../rules/registry.js';
import { getScoreForSeverity } from '../rules/severity.js';

/** Known vulnerable packages with specific CVEs */
const KNOWN_VULNERABLE: Record<string, { cve: string; severity: 'critical' | 'high'; description: string }> = {
  'mcp-remote': {
    cve: 'CVE-2025-6514',
    severity: 'critical',
    description: 'OS command injection vulnerability (437K+ downloads affected)',
  },
};

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
}

interface OsvQueryResponse {
  vulns?: OsvVulnerability[];
}

export async function analyzeSupplyChain(
  servers: McpServerConfig[],
  options: { enabled: boolean } = { enabled: true }
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const packagesToCheck: Map<string, McpServerConfig[]> = new Map();

  for (const server of servers) {
    if (server.packageName) {
      // Check known vulnerable packages first (offline)
      const knownVuln = KNOWN_VULNERABLE[server.packageName];
      if (knownVuln) {
        const rule = RULES['supply-chain-known-vulnerable'];
        findings.push({
          id: rule.id,
          rule: 'supply-chain-known-vulnerable',
          severity: knownVuln.severity,
          score: getScoreForSeverity(knownVuln.severity),
          title: `Known Vulnerable: ${knownVuln.cve}`,
          description: `${rule.description} Package "${server.packageName}" used by server "${server.name}" has ${knownVuln.cve}: ${knownVuln.description}`,
          server: server.name,
          client: server.source,
          configPath: server.configPath,
          location: `package: ${server.packageName}`,
          evidence: `${knownVuln.cve}: ${knownVuln.description}`,
          remediation: `Update "${server.packageName}" to the latest patched version or replace it with a secure alternative.`,
          owaspMapping: rule.owasp.join(', '),
          cwe: 'CWE-1395',
        });
      }

      // Collect packages for batch OSV lookup
      if (!packagesToCheck.has(server.packageName)) {
        packagesToCheck.set(server.packageName, []);
      }
      packagesToCheck.get(server.packageName)!.push(server);
    }
  }

  // Query OSV.dev API for known CVEs (if network is enabled)
  if (options.enabled && packagesToCheck.size > 0) {
    await queryOsvBatch(packagesToCheck, findings);
  }

  return findings;
}

async function queryOsvBatch(
  packages: Map<string, McpServerConfig[]>,
  findings: Finding[]
): Promise<void> {
  const queries = Array.from(packages.entries()).map(([name, servers]) => ({
    package: { name, ecosystem: 'npm' },
    version: servers[0].packageVersion || undefined,
  }));

  try {
    const response = await fetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) return;

    const data = await response.json() as { results: OsvQueryResponse[] };
    const packageNames = Array.from(packages.keys());

    for (let i = 0; i < data.results.length; i++) {
      const result = data.results[i];
      const pkgName = packageNames[i];
      const servers = packages.get(pkgName) || [];

      if (result.vulns && result.vulns.length > 0) {
        for (const vuln of result.vulns) {
          const rule = RULES['supply-chain-cve'];
          for (const server of servers) {
            // Avoid duplicate if already reported as known-vulnerable
            const alreadyReported = findings.some(
              f => f.server === server.name && f.evidence.includes(vuln.id)
            );
            if (alreadyReported) continue;

            findings.push({
              id: rule.id,
              rule: 'supply-chain-cve',
              severity: 'high',
              score: getScoreForSeverity('high'),
              title: `CVE Found: ${vuln.id}`,
              description: `${rule.description} Package "${pkgName}" has vulnerability ${vuln.id}: ${vuln.summary || 'No description available'}.`,
              server: server.name,
              client: server.source,
              configPath: server.configPath,
              location: `package: ${pkgName}`,
              evidence: `${vuln.id}: ${vuln.summary || vuln.details?.slice(0, 100) || 'Unknown'}`,
              remediation: `Update "${pkgName}" to a patched version. Check https://osv.dev/vulnerability/${vuln.id} for details.`,
              owaspMapping: rule.owasp.join(', '),
            });
          }
        }
      }
    }
  } catch {
    // Network failure is non-fatal — supply chain checks are best-effort
  }
}

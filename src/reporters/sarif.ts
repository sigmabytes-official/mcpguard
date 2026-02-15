import type { AuditReport, Finding, Severity } from '../types/findings.js';

/**
 * Generate a SARIF 2.1.0 report for GitHub Advanced Security integration.
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
export function formatSarifReport(report: AuditReport): string {
  const rules = buildRuleIndex(report.findings);
  const ruleArray = Array.from(rules.values());

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'mcpguard',
            version: report.version,
            informationUri: 'https://github.com/sigmasbytes/mcpguard',
            rules: ruleArray.map(r => ({
              id: r.id,
              name: r.rule,
              shortDescription: { text: r.title },
              fullDescription: { text: r.description },
              help: {
                text: r.remediation,
                markdown: `**Remediation:** ${r.remediation}`,
              },
              properties: {
                tags: [r.owaspMapping],
              },
              defaultConfiguration: {
                level: severityToSarifLevel(r.severity),
              },
            })),
          },
        },
        results: report.findings.map(f => ({
          ruleId: f.id,
          ruleIndex: ruleArray.findIndex(r => r.id === f.id),
          level: severityToSarifLevel(f.severity),
          message: {
            text: `${f.title}: ${f.description}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: normalizePathForSarif(f.configPath),
                  uriBaseId: '%SRCROOT%',
                },
                region: {
                  startLine: 1,
                },
              },
              logicalLocations: [
                {
                  name: f.server,
                  kind: 'mcpServer',
                  fullyQualifiedName: `${f.client}/${f.server}`,
                },
              ],
            },
          ],
          properties: {
            server: f.server,
            client: f.client,
            location: f.location,
            evidence: f.evidence,
            owaspMapping: f.owaspMapping,
            score: f.score,
            ...(f.cwe ? { cwe: f.cwe } : {}),
          },
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function severityToSarifLevel(severity: Severity): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
  }
}

function normalizePathForSarif(filePath: string): string {
  // Convert Windows paths to forward slashes for SARIF
  return filePath.replace(/\\/g, '/');
}

function buildRuleIndex(findings: Finding[]): Map<string, Finding> {
  const rules = new Map<string, Finding>();
  for (const f of findings) {
    if (!rules.has(f.id)) {
      rules.set(f.id, f);
    }
  }
  return rules;
}

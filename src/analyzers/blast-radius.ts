import type { McpServerConfig } from '../types/config.js';
import type { Finding, Severity } from '../types/findings.js';
import { KNOWN_PACKAGES, type PermissionProfile } from '../rules/patterns.js';
import { RULES } from '../rules/registry.js';
import { getScoreForSeverity } from '../rules/severity.js';

interface DangerousCombination {
  pair: [string, string];
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
}

const DANGEROUS_COMBINATIONS: DangerousCombination[] = [
  {
    pair: ['filesystem', 'shell'],
    severity: 'critical',
    title: 'Filesystem + Shell = Full System Compromise',
    description: 'Combination of filesystem access and shell execution creates a path to full system compromise. An attacker who poisons one tool can read any file and execute arbitrary commands.',
    remediation: 'Remove either the filesystem or shell MCP server. If both are necessary, ensure they run in isolated environments with strict access controls.',
  },
  {
    pair: ['filesystem', 'network'],
    severity: 'high',
    title: 'Filesystem + Network = Data Exfiltration Risk',
    description: 'Combination of filesystem and network access enables reading sensitive files and sending them to external servers.',
    remediation: 'Restrict filesystem access to non-sensitive directories. Apply network egress filtering to prevent data exfiltration.',
  },
  {
    pair: ['shell', 'code'],
    severity: 'high',
    title: 'Shell + Code Repository = Supply Chain Attack Risk',
    description: 'Combination of shell execution and code repository access enables committing and pushing malicious code.',
    remediation: 'Use read-only repository access tokens. Avoid granting shell access alongside code repository access.',
  },
  {
    pair: ['database', 'network'],
    severity: 'high',
    title: 'Database + Network = Database Dump Exfiltration Risk',
    description: 'Combination of database and network access enables dumping database contents and sending them externally.',
    remediation: 'Use read-only database credentials and restrict network egress to known-good destinations.',
  },
  {
    pair: ['shell', 'network'],
    severity: 'critical',
    title: 'Shell + Network = Remote Code Execution Risk',
    description: 'Combination of shell execution and network access enables downloading and executing remote payloads.',
    remediation: 'Remove shell access or restrict it with a strict command allowlist. Apply network egress controls.',
  },
  {
    pair: ['database', 'shell'],
    severity: 'critical',
    title: 'Database + Shell = Full Data Compromise',
    description: 'Combination of database and shell access enables full data extraction and system manipulation.',
    remediation: 'Separate database access from shell access. Use dedicated, restricted database connections.',
  },
];

export function analyzeBlastRadius(servers: McpServerConfig[]): Finding[] {
  const findings: Finding[] = [];

  // Build category map: which categories are present and from which servers
  const categoryServers = new Map<string, McpServerConfig[]>();

  for (const server of servers) {
    const categories = getServerCategories(server);
    for (const cat of categories) {
      if (!categoryServers.has(cat)) {
        categoryServers.set(cat, []);
      }
      categoryServers.get(cat)!.push(server);
    }
  }

  // Check dangerous combinations
  for (const combo of DANGEROUS_COMBINATIONS) {
    const [catA, catB] = combo.pair;
    const serversA = categoryServers.get(catA);
    const serversB = categoryServers.get(catB);

    if (serversA && serversB) {
      const ruleKey = combo.severity === 'critical' ? 'blast-radius-critical' : 'blast-radius-high';
      const rule = RULES[ruleKey];

      // Report once per unique combination
      const serverNamesA = serversA.map(s => s.name).join(', ');
      const serverNamesB = serversB.map(s => s.name).join(', ');

      findings.push({
        id: rule.id,
        rule: ruleKey,
        severity: combo.severity,
        score: getScoreForSeverity(combo.severity),
        title: combo.title,
        description: `${combo.description} Servers providing ${catA}: [${serverNamesA}]. Servers providing ${catB}: [${serverNamesB}].`,
        server: `${serverNamesA} + ${serverNamesB}`,
        client: serversA[0].source, // Use first server's client
        configPath: serversA[0].configPath,
        location: `Cross-server: ${catA} + ${catB}`,
        evidence: `${catA} servers: [${serverNamesA}], ${catB} servers: [${serverNamesB}]`,
        remediation: combo.remediation,
        owaspMapping: rule.owasp.join(', '),
      });
    }
  }

  // Check for servers shared across multiple clients (wider blast radius)
  const serverByName = new Map<string, Set<string>>();
  for (const server of servers) {
    const key = server.packageName || server.name;
    if (!serverByName.has(key)) {
      serverByName.set(key, new Set());
    }
    serverByName.get(key)!.add(server.source);
  }

  for (const [name, clients] of serverByName) {
    if (clients.size > 1) {
      findings.push({
        id: 'BR-003',
        rule: 'blast-radius-high',
        severity: 'medium',
        score: getScoreForSeverity('medium'),
        title: 'Server Shared Across Multiple AI Clients',
        description: `Server "${name}" is configured in ${clients.size} different AI clients: ${Array.from(clients).join(', ')}. A compromise of this server would affect all these clients.`,
        server: name,
        client: Array.from(clients)[0] as McpServerConfig['source'],
        configPath: '',
        location: `Shared across: ${Array.from(clients).join(', ')}`,
        evidence: `Clients: ${Array.from(clients).join(', ')}`,
        remediation: `Consider whether "${name}" needs to be configured in all clients. Reduce the attack surface by removing it from clients where it's not essential.`,
        owaspMapping: 'ASI06 - Excessive Permissions',
      });
    }
  }

  return findings;
}

function getServerCategories(server: McpServerConfig): string[] {
  const categories: string[] = [];

  // From known package mapping
  if (server.packageName && KNOWN_PACKAGES[server.packageName]) {
    categories.push(KNOWN_PACKAGES[server.packageName].category);
  }

  // Infer from package name keywords
  const name = (server.packageName || server.name || '').toLowerCase();
  const allArgs = (server.args || []).join(' ').toLowerCase();

  if (!categories.includes('filesystem') && (name.includes('filesystem') || name.includes('file-system'))) {
    categories.push('filesystem');
  }
  if (!categories.includes('shell') && (name.includes('shell') || name.includes('exec') || name.includes('terminal'))) {
    categories.push('shell');
  }
  if (!categories.includes('network') && (name.includes('fetch') || name.includes('http') || name.includes('web'))) {
    categories.push('network');
  }
  if (!categories.includes('database') && (name.includes('postgres') || name.includes('mysql') || name.includes('sqlite') || name.includes('mongo') || name.includes('redis'))) {
    categories.push('database');
  }
  if (!categories.includes('code') && (name.includes('github') || name.includes('gitlab') || name.includes('git'))) {
    categories.push('code');
  }
  if (!categories.includes('browser') && (name.includes('puppeteer') || name.includes('playwright') || name.includes('browser') || name.includes('chrome'))) {
    categories.push('browser');
  }

  return categories;
}

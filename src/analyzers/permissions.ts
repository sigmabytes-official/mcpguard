import * as os from 'node:os';
import type { McpServerConfig } from '../types/config.js';
import type { Finding, Severity } from '../types/findings.js';
import { KNOWN_PACKAGES } from '../rules/patterns.js';
import { RULES } from '../rules/registry.js';
import { getScoreForSeverity } from '../rules/severity.js';

export function analyzePermissions(servers: McpServerConfig[]): Finding[] {
  const findings: Finding[] = [];

  for (const server of servers) {
    // Check known package permissions
    if (server.packageName && KNOWN_PACKAGES[server.packageName]) {
      const profile = KNOWN_PACKAGES[server.packageName];
      const ruleKey = getRuleForCategory(profile.category);
      const rule = RULES[ruleKey];

      if (rule) {
        findings.push({
          id: rule.id,
          rule: ruleKey,
          severity: profile.risk,
          score: getScoreForSeverity(profile.risk),
          title: `${profile.description}`,
          description: `${rule.description} Server "${server.name}" uses package "${server.packageName}" which provides ${profile.category} capabilities.`,
          server: server.name,
          client: server.source,
          configPath: server.configPath,
          location: `packageName: ${server.packageName}`,
          evidence: `Package: ${server.packageName}`,
          remediation: getRemediationForCategory(profile.category, server.name),
          owaspMapping: rule.owasp.join(', '),
        });
      }
    }

    // Check for filesystem arguments
    if (server.args) {
      checkFilesystemArgs(server, findings);
    }

    // Check for dangerous command patterns
    if (server.command) {
      checkDangerousCommands(server, findings);
    }
  }

  return findings;
}

function checkFilesystemArgs(server: McpServerConfig, findings: Finding[]): void {
  const args = server.args || [];
  const homeDir = os.homedir();

  for (const arg of args) {
    // Root filesystem access
    if (arg === '/' || arg === 'C:\\' || arg === 'C:/') {
      const rule = RULES['overpermission-root-filesystem'];
      findings.push({
        id: rule.id,
        rule: 'overpermission-root-filesystem',
        severity: 'critical',
        score: getScoreForSeverity('critical'),
        title: 'Root Filesystem Access Granted',
        description: `${rule.description} Server "${server.name}" has access to the entire root filesystem.`,
        server: server.name,
        client: server.source,
        configPath: server.configPath,
        location: `args: ${arg}`,
        evidence: `Path argument: ${arg}`,
        remediation: `Restrict filesystem access to the minimum required directory. Replace "/" with a specific project path like "/path/to/project".`,
        owaspMapping: rule.owasp.join(', '),
      });
    }
    // Home directory access
    else if (arg === '~' || arg === homeDir || arg === '%USERPROFILE%') {
      const rule = RULES['overpermission-home-directory'];
      findings.push({
        id: rule.id,
        rule: 'overpermission-home-directory',
        severity: 'high',
        score: getScoreForSeverity('high'),
        title: 'Home Directory Access Granted',
        description: `${rule.description} Server "${server.name}" has access to the user's entire home directory.`,
        server: server.name,
        client: server.source,
        configPath: server.configPath,
        location: `args: ${arg}`,
        evidence: `Path argument: ${arg}`,
        remediation: `Restrict filesystem access to specific project directories instead of the entire home directory.`,
        owaspMapping: rule.owasp.join(', '),
      });
    }
  }
}

function checkDangerousCommands(server: McpServerConfig, findings: Finding[]): void {
  const cmd = server.command || '';

  // Check for shell-like commands that imply execution capability
  const shellCommands = ['bash', 'sh', 'zsh', 'cmd', 'powershell', 'pwsh', 'cmd.exe'];
  if (shellCommands.some(sc => cmd === sc || cmd.endsWith(`/${sc}`) || cmd.endsWith(`\\${sc}`))) {
    const rule = RULES['overpermission-shell'];
    findings.push({
      id: rule.id,
      rule: 'overpermission-shell',
      severity: 'critical',
      score: getScoreForSeverity('critical'),
      title: 'Direct Shell Command Execution',
      description: `${rule.description} Server "${server.name}" uses a shell (${cmd}) as its command, enabling arbitrary command execution.`,
      server: server.name,
      client: server.source,
      configPath: server.configPath,
      location: `command: ${cmd}`,
      evidence: `Command: ${cmd}`,
      remediation: `Avoid using shell interpreters directly. Use specific, purpose-built MCP servers instead of raw shell access.`,
      owaspMapping: rule.owasp.join(', '),
    });
  }
}

function getRuleForCategory(category: string): string {
  switch (category) {
    case 'filesystem': return 'overpermission-filesystem';
    case 'shell': return 'overpermission-shell';
    case 'network':
    case 'browser': return 'overpermission-network';
    case 'database': return 'overpermission-database';
    default: return 'overpermission-network';
  }
}

function getRemediationForCategory(category: string, serverName: string): string {
  switch (category) {
    case 'filesystem':
      return `Review the filesystem paths granted to "${serverName}". Restrict to minimum required directories and consider read-only access.`;
    case 'shell':
      return `Shell execution via "${serverName}" grants full system access. Consider removing this server or restricting its commands with an allowlist.`;
    case 'network':
    case 'browser':
      return `Review network access granted to "${serverName}". Consider restricting to specific domains and implementing request logging.`;
    case 'database':
      return `Review database access via "${serverName}". Use read-only credentials where possible and restrict to specific tables/schemas.`;
    case 'code':
      return `Review code/repository access via "${serverName}". Ensure the token has minimum required scopes and consider read-only access.`;
    default:
      return `Review the permissions granted to "${serverName}" and ensure they follow the principle of least privilege.`;
  }
}

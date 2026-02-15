import type { McpServerConfig } from '../types/config.js';
import type { Finding } from '../types/findings.js';
import { INJECTION_PATTERNS } from '../rules/patterns.js';
import { RULES } from '../rules/registry.js';
import { getScoreForSeverity } from '../rules/severity.js';

export function analyzeCommandInjection(servers: McpServerConfig[]): Finding[] {
  const findings: Finding[] = [];

  for (const server of servers) {
    if (!server.args) continue;

    for (let i = 0; i < server.args.length; i++) {
      const arg = server.args[i];

      for (const pattern of INJECTION_PATTERNS) {
        if (pattern.regex.test(arg)) {
          const rule = RULES['command-injection'];
          findings.push({
            id: rule.id,
            rule: 'command-injection',
            severity: pattern.severity,
            score: getScoreForSeverity(pattern.severity),
            title: `${pattern.name} Detected in Arguments`,
            description: `${rule.description} The argument at index ${i} for server "${server.name}" contains a ${pattern.name.toLowerCase()} that could enable command injection.`,
            server: server.name,
            client: server.source,
            configPath: server.configPath,
            location: `args[${i}]`,
            evidence: `Argument: "${arg}" (matched: ${pattern.name})`,
            remediation: `Review the argument "${arg}" for server "${server.name}". Ensure it does not contain unintended shell metacharacters. If this is intentional, document it clearly.`,
            owaspMapping: rule.owasp.join(', '),
            cwe: 'CWE-78',
          });
          break; // One finding per arg
        }
      }
    }

    // Check if command itself has injection risk
    if (server.command && server.command.includes(' ')) {
      const rule = RULES['command-injection'];
      findings.push({
        id: rule.id,
        rule: 'command-injection',
        severity: 'medium',
        score: getScoreForSeverity('medium'),
        title: 'Command Contains Spaces',
        description: `The command field for server "${server.name}" contains spaces, which may indicate command injection or misconfiguration.`,
        server: server.name,
        client: server.source,
        configPath: server.configPath,
        location: 'command',
        evidence: `Command: "${server.command}"`,
        remediation: `Use the "args" array for command arguments instead of embedding them in the "command" field.`,
        owaspMapping: rule.owasp.join(', '),
        cwe: 'CWE-78',
      });
    }
  }

  return findings;
}

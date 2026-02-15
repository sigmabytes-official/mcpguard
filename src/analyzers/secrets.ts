import type { McpServerConfig } from '../types/config.js';
import type { Finding } from '../types/findings.js';
import { SECRET_PATTERNS, shannonEntropy } from '../rules/patterns.js';
import { RULES } from '../rules/registry.js';
import { getScoreForSeverity } from '../rules/severity.js';

const HIGH_ENTROPY_THRESHOLD = 4.5;
const MIN_SECRET_LENGTH = 16;

export function analyzeSecrets(servers: McpServerConfig[]): Finding[] {
  const findings: Finding[] = [];

  for (const server of servers) {
    // Check env values
    if (server.env) {
      for (const [key, value] of Object.entries(server.env)) {
        // Check against known secret patterns
        for (const pattern of SECRET_PATTERNS) {
          if (pattern.regex.test(value)) {
            const rule = RULES['hardcoded-secret'];
            findings.push({
              id: rule.id,
              rule: 'hardcoded-secret',
              severity: pattern.severity,
              score: getScoreForSeverity(pattern.severity),
              title: `${pattern.name} Found in Config`,
              description: `${rule.description} A ${pattern.name} was detected in the environment variable "${key}" for server "${server.name}".`,
              server: server.name,
              client: server.source,
              configPath: server.configPath,
              location: `env.${key}`,
              evidence: maskSecret(value),
              remediation: `Remove the hardcoded ${pattern.name} from the config file. Use environment variables or a secrets manager instead. Reference the secret via $\{${key}\} or set it in your shell environment.`,
              owaspMapping: rule.owasp.join(', '),
              cwe: pattern.cwe,
            });
            break; // Only report first matching pattern per value
          }
        }

        // High entropy check for values not caught by patterns
        if (value.length >= MIN_SECRET_LENGTH) {
          const entropy = shannonEntropy(value);
          if (entropy > HIGH_ENTROPY_THRESHOLD) {
            // Check if we already found a pattern match for this
            const alreadyFound = findings.some(
              f => f.server === server.name && f.location === `env.${key}`
            );
            if (!alreadyFound) {
              const rule = RULES['high-entropy-value'];
              findings.push({
                id: rule.id,
                rule: 'high-entropy-value',
                severity: 'medium',
                score: getScoreForSeverity('medium'),
                title: 'High-Entropy Value (Potential Secret)',
                description: `${rule.description} The value of "${key}" has a Shannon entropy of ${entropy.toFixed(2)}, which suggests it may be a secret or token.`,
                server: server.name,
                client: server.source,
                configPath: server.configPath,
                location: `env.${key}`,
                evidence: maskSecret(value),
                remediation: `If this is a secret, remove it from the config and use environment variables or a secrets manager instead.`,
                owaspMapping: rule.owasp.join(', '),
                cwe: 'CWE-798',
              });
            }
          }
        }
      }
    }

    // Check headers for secrets
    if (server.headers) {
      for (const [key, value] of Object.entries(server.headers)) {
        for (const pattern of SECRET_PATTERNS) {
          if (pattern.regex.test(value)) {
            const rule = RULES['hardcoded-secret'];
            findings.push({
              id: rule.id,
              rule: 'hardcoded-secret',
              severity: pattern.severity,
              score: getScoreForSeverity(pattern.severity),
              title: `${pattern.name} Found in Headers`,
              description: `${rule.description} A ${pattern.name} was detected in the header "${key}" for server "${server.name}".`,
              server: server.name,
              client: server.source,
              configPath: server.configPath,
              location: `headers.${key}`,
              evidence: maskSecret(value),
              remediation: `Remove the hardcoded ${pattern.name} from headers. Use environment variable references instead.`,
              owaspMapping: rule.owasp.join(', '),
              cwe: pattern.cwe,
            });
            break;
          }
        }
      }
    }
  }

  return findings;
}

/** Mask a secret value for safe display: show first 4 and last 4 chars */
function maskSecret(value: string): string {
  if (value.length <= 12) return value.slice(0, 3) + '***';
  return value.slice(0, 4) + '...' + value.slice(-4);
}

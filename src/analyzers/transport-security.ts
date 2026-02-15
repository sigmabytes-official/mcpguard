import type { McpServerConfig } from '../types/config.js';
import type { Finding } from '../types/findings.js';
import { RULES } from '../rules/registry.js';
import { getScoreForSeverity } from '../rules/severity.js';

export function analyzeTransportSecurity(servers: McpServerConfig[]): Finding[] {
  const findings: Finding[] = [];

  for (const server of servers) {
    if (server.transport === 'stdio') continue; // Local only, no transport security needed

    if (server.url) {
      // Check for HTTP (no TLS)
      if (server.url.startsWith('http://')) {
        // Allow localhost/127.0.0.1 as low severity
        const isLocal = /^http:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/.test(server.url);

        const rule = RULES['transport-no-tls'];
        findings.push({
          id: rule.id,
          rule: 'transport-no-tls',
          severity: isLocal ? 'low' : 'high',
          score: getScoreForSeverity(isLocal ? 'low' : 'high'),
          title: isLocal
            ? 'Local Server Using HTTP (No TLS)'
            : 'Remote Server Using HTTP (No TLS)',
          description: `${rule.description} Server "${server.name}" connects to ${server.url} over unencrypted HTTP.${isLocal ? ' While this is a local connection, consider using HTTPS for defense in depth.' : ' Data transmitted to this server can be intercepted.'}`,
          server: server.name,
          client: server.source,
          configPath: server.configPath,
          location: `url: ${server.url}`,
          evidence: `URL: ${server.url}`,
          remediation: isLocal
            ? `Consider using HTTPS even for local connections. If this is a development server, ensure it is not exposed to the network.`
            : `Change the URL to use HTTPS (https://) to encrypt data in transit. If the server does not support TLS, use a reverse proxy or tunnel.`,
          owaspMapping: rule.owasp.join(', '),
          cwe: 'CWE-319',
        });
      }

      // Check for missing authentication on remote servers
      const isRemote = server.url.startsWith('http://') || server.url.startsWith('https://');
      const isLocal = /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])/.test(server.url);

      if (isRemote && !isLocal) {
        const hasAuth = server.headers && (
          server.headers['Authorization'] ||
          server.headers['authorization'] ||
          server.headers['X-API-Key'] ||
          server.headers['x-api-key'] ||
          server.headers['X-Api-Key']
        );

        if (!hasAuth) {
          const rule = RULES['transport-no-auth'];
          findings.push({
            id: rule.id,
            rule: 'transport-no-auth',
            severity: 'high',
            score: getScoreForSeverity('high'),
            title: 'No Authentication on Remote Server',
            description: `${rule.description} Server "${server.name}" connects to a remote URL without any authentication headers.`,
            server: server.name,
            client: server.source,
            configPath: server.configPath,
            location: `url: ${server.url}`,
            evidence: `No Authorization or API key headers found`,
            remediation: `Add authentication headers to the server configuration. Use Bearer tokens, API keys, or other authentication mechanisms.`,
            owaspMapping: rule.owasp.join(', '),
            cwe: 'CWE-306',
          });
        }
      }
    }
  }

  return findings;
}

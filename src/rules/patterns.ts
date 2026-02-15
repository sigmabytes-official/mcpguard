import type { Severity } from '../types/findings.js';

export interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  cwe: string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  { name: 'AWS Access Key ID', regex: /AKIA[0-9A-Z]{16}/, severity: 'critical', cwe: 'CWE-798' },
  { name: 'AWS Secret Access Key', regex: /(?:aws)?_?secret_?(?:access)?_?key\s*[:=]\s*['"]?[0-9a-zA-Z/+=]{40}/i, severity: 'critical', cwe: 'CWE-798' },
  { name: 'GitHub Personal Access Token', regex: /ghp_[0-9a-zA-Z]{30,}/, severity: 'critical', cwe: 'CWE-798' },
  { name: 'GitHub OAuth Token', regex: /gho_[0-9a-zA-Z]{30,}/, severity: 'critical', cwe: 'CWE-798' },
  { name: 'GitHub App Token', regex: /(?:ghu|ghs|ghr)_[0-9a-zA-Z]{30,}/, severity: 'critical', cwe: 'CWE-798' },
  { name: 'Anthropic API Key', regex: /sk-ant-[0-9a-zA-Z_-]{40,}/, severity: 'critical', cwe: 'CWE-798' },
  { name: 'OpenAI API Key', regex: /sk-[0-9a-zA-Z]{32,}/, severity: 'critical', cwe: 'CWE-798' },
  { name: 'Stripe Secret Key', regex: /sk_live_[0-9a-zA-Z]{24,}/, severity: 'critical', cwe: 'CWE-798' },
  { name: 'Stripe Publishable Key', regex: /pk_live_[0-9a-zA-Z]{24,}/, severity: 'medium', cwe: 'CWE-798' },
  { name: 'Slack Token', regex: /xox[bpors]-[0-9]{10,}-[0-9a-zA-Z]{10,}/, severity: 'high', cwe: 'CWE-798' },
  { name: 'Slack Webhook', regex: /hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9a-zA-Z]{24}/, severity: 'high', cwe: 'CWE-798' },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/, severity: 'high', cwe: 'CWE-798' },
  { name: 'Google OAuth Client Secret', regex: /GOCSPX-[0-9A-Za-z_-]{28}/, severity: 'critical', cwe: 'CWE-798' },
  { name: 'Private Key', regex: /-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY/, severity: 'critical', cwe: 'CWE-321' },
  { name: 'Database Connection String', regex: /(?:postgres|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s]+:[^@\s]+@/i, severity: 'critical', cwe: 'CWE-798' },
  { name: 'Bearer Token in Header', regex: /Bearer\s+[0-9a-zA-Z._-]{20,}/, severity: 'high', cwe: 'CWE-798' },
  { name: 'Generic API Key Assignment', regex: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]?[0-9a-zA-Z_-]{20,}/i, severity: 'high', cwe: 'CWE-798' },
  { name: 'Generic Password Assignment', regex: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}/i, severity: 'high', cwe: 'CWE-798' },
  { name: 'Twilio Auth Token', regex: /(?:twilio).{0,20}[0-9a-f]{32}/i, severity: 'high', cwe: 'CWE-798' },
  { name: 'SendGrid API Key', regex: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/, severity: 'high', cwe: 'CWE-798' },
  { name: 'Mailgun API Key', regex: /key-[0-9a-zA-Z]{32}/, severity: 'high', cwe: 'CWE-798' },
];

/**
 * Calculate Shannon entropy of a string. High entropy strings (>4.5) may be secrets.
 */
export function shannonEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Known MCP server packages with their permission profiles */
export interface PermissionProfile {
  category: 'filesystem' | 'shell' | 'network' | 'database' | 'code' | 'browser' | 'memory' | 'other';
  risk: Severity;
  description: string;
}

export const KNOWN_PACKAGES: Record<string, PermissionProfile> = {
  // Filesystem
  '@modelcontextprotocol/server-filesystem': { category: 'filesystem', risk: 'high', description: 'Read/write access to specified directories' },
  'mcp-server-filesystem': { category: 'filesystem', risk: 'high', description: 'Read/write access to directories' },

  // Shell / Command execution
  'mcp-shell-server': { category: 'shell', risk: 'critical', description: 'Arbitrary shell command execution' },
  '@anthropic/mcp-server-shell': { category: 'shell', risk: 'critical', description: 'Arbitrary shell command execution' },
  'mcp-server-exec': { category: 'shell', risk: 'critical', description: 'Command execution' },
  'mcp-server-terminal': { category: 'shell', risk: 'critical', description: 'Terminal access' },

  // Database
  '@modelcontextprotocol/server-postgres': { category: 'database', risk: 'high', description: 'PostgreSQL database access' },
  '@modelcontextprotocol/server-sqlite': { category: 'database', risk: 'medium', description: 'SQLite database access' },
  'mcp-server-mysql': { category: 'database', risk: 'high', description: 'MySQL database access' },
  'mcp-server-mongo': { category: 'database', risk: 'high', description: 'MongoDB database access' },

  // Network / Web
  '@modelcontextprotocol/server-fetch': { category: 'network', risk: 'medium', description: 'HTTP fetch capabilities' },
  'mcp-server-fetch': { category: 'network', risk: 'medium', description: 'HTTP fetch capabilities' },
  'mcp-server-puppeteer': { category: 'browser', risk: 'high', description: 'Browser automation with Puppeteer' },
  'mcp-server-playwright': { category: 'browser', risk: 'high', description: 'Browser automation with Playwright' },

  // Code / Git
  '@modelcontextprotocol/server-github': { category: 'code', risk: 'high', description: 'GitHub API access (repos, issues, PRs)' },
  '@modelcontextprotocol/server-gitlab': { category: 'code', risk: 'high', description: 'GitLab API access' },
  '@modelcontextprotocol/server-git': { category: 'code', risk: 'medium', description: 'Local git repository access' },

  // Memory / State
  '@modelcontextprotocol/server-memory': { category: 'memory', risk: 'low', description: 'Key-value memory storage' },

  // Other dangerous
  'mcp-remote': { category: 'network', risk: 'high', description: 'Remote MCP server proxy (CVE-2025-6514)' },
};

/** Command injection patterns to detect in args */
export const INJECTION_PATTERNS: { name: string; regex: RegExp; severity: Severity }[] = [
  { name: 'Shell metacharacter in args', regex: /[;&|`$()]/, severity: 'high' },
  { name: 'Command substitution', regex: /\$\(|\`[^`]+\`/, severity: 'critical' },
  { name: 'Pipe operator', regex: /\|/, severity: 'high' },
  { name: 'Redirect operator', regex: /[<>]/, severity: 'medium' },
  { name: 'Path traversal', regex: /\.\.[\\/]/, severity: 'high' },
  { name: 'Eval-like pattern', regex: /\beval\b|\bexec\b/, severity: 'critical' },
];

/**
 * OWASP Agentic Security Initiative (ASI) Top 10 mapping.
 * Each finding is tagged with one or more ASI categories.
 */
export const OWASP_ASI = {
  ASI01: 'ASI01 - Prompt Injection',
  ASI02: 'ASI02 - Sensitive Data Exposure',
  ASI03: 'ASI03 - Identity & Privilege Abuse',
  ASI04: 'ASI04 - Supply Chain Vulnerabilities',
  ASI05: 'ASI05 - Unsafe Code Execution',
  ASI06: 'ASI06 - Excessive Permissions',
  ASI07: 'ASI07 - Insecure Communication',
  ASI08: 'ASI08 - Insufficient Logging & Monitoring',
  ASI09: 'ASI09 - Denial of Service',
  ASI10: 'ASI10 - Improper Error Handling',
} as const;

export type OwaspAsiCode = keyof typeof OWASP_ASI;

export interface RuleDefinition {
  id: string;
  name: string;
  description: string;
  owasp: OwaspAsiCode[];
}

export const RULES: Record<string, RuleDefinition> = {
  'hardcoded-secret': {
    id: 'SEC-001',
    name: 'Hardcoded Secret in Configuration',
    description: 'API keys, tokens, or passwords are hardcoded in MCP configuration files.',
    owasp: ['ASI02'],
  },
  'high-entropy-value': {
    id: 'SEC-002',
    name: 'High-Entropy Value (Potential Secret)',
    description: 'A value with high Shannon entropy may be a secret.',
    owasp: ['ASI02'],
  },
  'overpermission-filesystem': {
    id: 'PERM-001',
    name: 'Filesystem Access Granted',
    description: 'MCP server has filesystem read/write access.',
    owasp: ['ASI06'],
  },
  'overpermission-shell': {
    id: 'PERM-002',
    name: 'Shell Command Execution Granted',
    description: 'MCP server can execute arbitrary shell commands.',
    owasp: ['ASI05', 'ASI06'],
  },
  'overpermission-network': {
    id: 'PERM-003',
    name: 'Network Access Granted',
    description: 'MCP server can make outbound network requests.',
    owasp: ['ASI06'],
  },
  'overpermission-database': {
    id: 'PERM-004',
    name: 'Database Access Granted',
    description: 'MCP server has direct database access.',
    owasp: ['ASI06'],
  },
  'overpermission-root-filesystem': {
    id: 'PERM-005',
    name: 'Root Filesystem Access',
    description: 'MCP server has access to the root filesystem (/).',
    owasp: ['ASI05', 'ASI06'],
  },
  'overpermission-home-directory': {
    id: 'PERM-006',
    name: 'Home Directory Access',
    description: 'MCP server has access to the user home directory.',
    owasp: ['ASI06'],
  },
  'command-injection': {
    id: 'INJ-001',
    name: 'Command Injection Vector',
    description: 'MCP server arguments contain shell metacharacters that could enable injection.',
    owasp: ['ASI05'],
  },
  'transport-no-tls': {
    id: 'NET-001',
    name: 'Insecure Transport (No TLS)',
    description: 'Remote MCP server is accessed over HTTP without TLS encryption.',
    owasp: ['ASI07'],
  },
  'transport-no-auth': {
    id: 'NET-002',
    name: 'Missing Authentication on Remote Server',
    description: 'Remote MCP server has no authentication headers configured.',
    owasp: ['ASI03', 'ASI07'],
  },
  'supply-chain-cve': {
    id: 'SC-001',
    name: 'Known CVE in MCP Server Package',
    description: 'The MCP server package has known security vulnerabilities.',
    owasp: ['ASI04'],
  },
  'supply-chain-unknown-package': {
    id: 'SC-002',
    name: 'Unverified MCP Server Package',
    description: 'The MCP server package could not be verified against known registries.',
    owasp: ['ASI04'],
  },
  'supply-chain-known-vulnerable': {
    id: 'SC-003',
    name: 'Known Vulnerable Package',
    description: 'This MCP server package has known critical vulnerabilities (e.g., CVE-2025-6514).',
    owasp: ['ASI04'],
  },
  'blast-radius-critical': {
    id: 'BR-001',
    name: 'Critical Privilege Escalation Path',
    description: 'Combination of MCP servers creates a critical privilege escalation path.',
    owasp: ['ASI05', 'ASI06'],
  },
  'blast-radius-high': {
    id: 'BR-002',
    name: 'High-Risk Server Combination',
    description: 'Combination of MCP servers creates a high-risk attack surface.',
    owasp: ['ASI05', 'ASI06'],
  },
};

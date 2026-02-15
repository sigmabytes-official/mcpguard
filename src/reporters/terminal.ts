import type { AuditReport, Finding, Severity } from '../types/findings.js';

// ANSI color codes (works on most terminals without chalk)
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m',
  bgGreen: '\x1b[42m',
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: `${colors.bgRed}${colors.white}${colors.bold}`,
  high: `${colors.red}${colors.bold}`,
  medium: `${colors.yellow}`,
  low: `${colors.blue}`,
  info: `${colors.dim}`,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '!!!',
  high: '!!',
  medium: '!',
  low: '-',
  info: 'i',
};

export function formatTerminalReport(report: AuditReport, quiet: boolean = false): string {
  const lines: string[] = [];

  if (!quiet) {
    lines.push('');
    lines.push(`${colors.bold}${colors.cyan}  mcpguard${colors.reset} ${colors.dim}v${report.version}${colors.reset}`);
    lines.push(`${colors.dim}  MCP Security Auditor${colors.reset}`);
    lines.push('');

    // Summary bar
    lines.push(`${colors.dim}  ${'─'.repeat(60)}${colors.reset}`);
    lines.push(`  ${colors.bold}Scan Summary${colors.reset}`);
    lines.push(`${colors.dim}  ${'─'.repeat(60)}${colors.reset}`);
    lines.push(`  Platform:        ${report.platform}`);
    lines.push(`  Configs found:   ${report.summary.configsFound}`);
    lines.push(`  Servers scanned: ${report.summary.totalServers}`);
    lines.push(`  Findings:        ${report.summary.totalFindings}`);
    lines.push('');

    // Risk score gauge
    const score = report.machineRiskScore;
    const scoreColor = score >= 75 ? colors.red : score >= 50 ? colors.yellow : score >= 25 ? colors.blue : colors.green;
    const gauge = renderGauge(score);
    lines.push(`  ${colors.bold}Machine Risk Score${colors.reset}`);
    lines.push(`  ${scoreColor}${gauge} ${score}/100${colors.reset}`);
    lines.push('');

    // Severity breakdown
    if (report.summary.totalFindings > 0) {
      lines.push(`  ${SEVERITY_COLORS['critical']} CRITICAL ${colors.reset} ${report.summary.critical}  ` +
                 `${SEVERITY_COLORS['high']} HIGH ${colors.reset} ${report.summary.high}  ` +
                 `${SEVERITY_COLORS['medium']} MEDIUM ${colors.reset} ${report.summary.medium}  ` +
                 `${SEVERITY_COLORS['low']} LOW ${colors.reset} ${report.summary.low}  ` +
                 `${SEVERITY_COLORS['info']} INFO ${colors.reset} ${report.summary.info}`);
      lines.push('');
    }
  }

  // Findings
  if (report.findings.length === 0) {
    if (!quiet) {
      lines.push(`  ${colors.green}${colors.bold}No security issues found.${colors.reset}`);
      lines.push('');
    }
  } else {
    if (!quiet) {
      lines.push(`${colors.dim}  ${'─'.repeat(60)}${colors.reset}`);
      lines.push(`  ${colors.bold}Findings${colors.reset}`);
      lines.push(`${colors.dim}  ${'─'.repeat(60)}${colors.reset}`);
      lines.push('');
    }

    for (const finding of report.findings) {
      lines.push(formatFinding(finding, quiet));
    }
  }

  return lines.join('\n');
}

function formatFinding(finding: Finding, quiet: boolean): string {
  const sevColor = SEVERITY_COLORS[finding.severity];
  const icon = SEVERITY_ICONS[finding.severity];

  if (quiet) {
    return `[${finding.severity.toUpperCase()}] ${finding.title} | ${finding.server} | ${finding.configPath}`;
  }

  const lines: string[] = [];
  const sevLabel = finding.severity.toUpperCase().padEnd(8);
  lines.push(`  ${sevColor}[${icon}] ${sevLabel}${colors.reset} ${colors.bold}${finding.title}${colors.reset}`);
  lines.push(`     ${colors.dim}Server:${colors.reset}  ${finding.server}`);
  lines.push(`     ${colors.dim}Client:${colors.reset}  ${finding.client}`);
  lines.push(`     ${colors.dim}Config:${colors.reset}  ${finding.configPath}`);
  lines.push(`     ${colors.dim}Location:${colors.reset} ${finding.location}`);
  lines.push(`     ${colors.dim}Evidence:${colors.reset} ${finding.evidence}`);
  lines.push(`     ${colors.dim}OWASP:${colors.reset}   ${finding.owaspMapping}`);
  if (finding.cwe) {
    lines.push(`     ${colors.dim}CWE:${colors.reset}     ${finding.cwe}`);
  }
  lines.push(`     ${colors.cyan}Fix:${colors.reset}     ${finding.remediation}`);
  lines.push('');

  return lines.join('\n');
}

function renderGauge(score: number): string {
  const width = 30;
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;
  return `[${'█'.repeat(filled)}${'░'.repeat(empty)}]`;
}

import type { Finding, Severity, AuditReport, ReportSummary } from '../types/findings.js';
import { SEVERITY_SCORES, SEVERITY_ORDER } from '../types/findings.js';

/**
 * Calculate the machine-wide risk score (0-100) from all findings.
 * Uses weighted average biased toward higher severity findings.
 */
export function calculateMachineRiskScore(findings: Finding[]): number {
  if (findings.length === 0) return 0;

  // Weight critical findings much more heavily
  const weights: Record<Severity, number> = {
    critical: 10,
    high: 5,
    medium: 2,
    low: 1,
    info: 0.2,
  };

  let totalWeight = 0;
  let weightedSum = 0;

  for (const f of findings) {
    const w = weights[f.severity];
    totalWeight += w;
    weightedSum += f.score * w;
  }

  if (totalWeight === 0) return 0;

  // Cap at 100
  return Math.min(100, Math.round(weightedSum / totalWeight));
}

/**
 * Get the score for a severity level.
 */
export function getScoreForSeverity(severity: Severity): number {
  return SEVERITY_SCORES[severity];
}

/**
 * Sort findings by severity (critical first) then by score.
 */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sevDiff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (sevDiff !== 0) return sevDiff;
    return b.score - a.score;
  });
}

/**
 * Generate the report summary from findings.
 */
export function generateSummary(
  findings: Finding[],
  totalServers: number,
  configsFound: number,
  clientsScanned: number,
): ReportSummary {
  return {
    totalServers,
    totalFindings: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
    clientsScanned,
    configsFound,
  };
}

/**
 * Check if findings exceed the severity threshold.
 */
export function exceedsThreshold(findings: Finding[], threshold: Severity): boolean {
  const thresholdOrder = SEVERITY_ORDER[threshold];
  return findings.some(f => SEVERITY_ORDER[f.severity] >= thresholdOrder);
}

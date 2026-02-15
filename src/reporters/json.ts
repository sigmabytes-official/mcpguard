import type { AuditReport } from '../types/findings.js';

export function formatJsonReport(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}

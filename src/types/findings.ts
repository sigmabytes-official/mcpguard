import type { ClientSource } from './config.js';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: string;
  rule: string;
  severity: Severity;
  score: number;
  title: string;
  description: string;
  server: string;
  client: ClientSource;
  configPath: string;
  location: string;
  evidence: string;
  remediation: string;
  owaspMapping: string;
  cwe?: string;
}

export interface ClientScanResult {
  client: ClientSource;
  configPath: string;
  serversFound: number;
  findings: Finding[];
}

export interface ReportSummary {
  totalServers: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  clientsScanned: number;
  configsFound: number;
}

export interface AuditReport {
  version: string;
  timestamp: string;
  platform: string;
  machineRiskScore: number;
  clientsScanned: ClientScanResult[];
  findings: Finding[];
  summary: ReportSummary;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export const SEVERITY_SCORES: Record<Severity, number> = {
  critical: 95,
  high: 75,
  medium: 50,
  low: 25,
  info: 10,
};

import type { McpServerConfig, ClientSource } from './types/config.js';
import type { AuditReport, Finding, Severity } from './types/findings.js';
import { discoverAll, type DiscoveryOptions } from './discovery/resolver.js';
import { runAllAnalyzers, type AnalyzerOptions } from './analyzers/index.js';
import { calculateMachineRiskScore, sortFindings, generateSummary, exceedsThreshold } from './rules/severity.js';
import { formatTerminalReport } from './reporters/terminal.js';
import { formatJsonReport } from './reporters/json.js';
import { formatSarifReport } from './reporters/sarif.js';
import { formatHtmlReport } from './reporters/html.js';
import { getPlatform } from './utils/platform.js';

export const VERSION = '0.1.0';

export type OutputFormat = 'terminal' | 'json' | 'sarif' | 'html';

export interface ScanOptions {
  cwd?: string;
  clients?: ClientSource[];
  customConfigs?: string[];
  format?: OutputFormat;
  output?: string;
  failOn?: Severity;
  quiet?: boolean;
  supplyChain?: boolean;
}

export interface ScanResult {
  report: AuditReport;
  formatted: string;
  exitCode: number;
}

export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const format = options.format || 'terminal';
  const quiet = options.quiet || false;

  // Phase 1: Discovery
  const discoveryOpts: DiscoveryOptions = {
    cwd: options.cwd,
    clients: options.clients,
    customConfigs: options.customConfigs,
  };
  const { servers, configsFound } = await discoverAll(discoveryOpts);

  // Phase 2: Analysis
  const analyzerOpts: AnalyzerOptions = {
    supplyChain: options.supplyChain || false,
  };
  const rawFindings = await runAllAnalyzers(servers, analyzerOpts);
  const findings = sortFindings(rawFindings);

  // Phase 3: Scoring
  const machineRiskScore = calculateMachineRiskScore(findings);
  const uniqueClients = new Set(servers.map(s => s.source));
  const summary = generateSummary(findings, servers.length, configsFound.size, uniqueClients.size);

  // Build report
  const report: AuditReport = {
    version: VERSION,
    timestamp: new Date().toISOString(),
    platform: getPlatform(),
    machineRiskScore,
    clientsScanned: Array.from(uniqueClients).map(client => ({
      client,
      configPath: Array.from(configsFound.entries())
        .filter(([, c]) => c === client)
        .map(([p]) => p)
        .join(', '),
      serversFound: servers.filter(s => s.source === client).length,
      findings: findings.filter(f => f.client === client),
    })),
    findings,
    summary,
  };

  // Phase 4: Reporting
  let formatted: string;
  switch (format) {
    case 'json':
      formatted = formatJsonReport(report);
      break;
    case 'sarif':
      formatted = formatSarifReport(report);
      break;
    case 'html':
      formatted = formatHtmlReport(report);
      break;
    case 'terminal':
    default:
      formatted = formatTerminalReport(report, quiet);
      break;
  }

  // Determine exit code
  let exitCode = 0;
  if (options.failOn && exceedsThreshold(findings, options.failOn)) {
    exitCode = 1;
  }

  return { report, formatted, exitCode };
}

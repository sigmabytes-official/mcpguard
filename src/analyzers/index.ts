import type { McpServerConfig } from '../types/config.js';
import type { Finding } from '../types/findings.js';
import { analyzeSecrets } from './secrets.js';
import { analyzePermissions } from './permissions.js';
import { analyzeCommandInjection } from './command-injection.js';
import { analyzeTransportSecurity } from './transport-security.js';
import { analyzeSupplyChain } from './supply-chain.js';
import { analyzeBlastRadius } from './blast-radius.js';

export interface AnalyzerOptions {
  supplyChain: boolean;
}

export async function runAllAnalyzers(
  servers: McpServerConfig[],
  options: AnalyzerOptions = { supplyChain: false }
): Promise<Finding[]> {
  // Run offline analyzers in parallel
  const [secrets, permissions, injection, transport, blastRadius] = await Promise.all([
    Promise.resolve(analyzeSecrets(servers)),
    Promise.resolve(analyzePermissions(servers)),
    Promise.resolve(analyzeCommandInjection(servers)),
    Promise.resolve(analyzeTransportSecurity(servers)),
    Promise.resolve(analyzeBlastRadius(servers)),
  ]);

  // Supply chain requires network, run separately
  const supplyChain = await analyzeSupplyChain(servers, { enabled: options.supplyChain });

  return [
    ...secrets,
    ...permissions,
    ...injection,
    ...transport,
    ...supplyChain,
    ...blastRadius,
  ];
}

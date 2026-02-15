import type { McpServerConfig, ClientSource } from '../types/config.js';
import { discoverClaudeDesktop } from './clients/claude-desktop.js';
import { discoverClaudeCode } from './clients/claude-code.js';
import { discoverCursor } from './clients/cursor.js';
import { discoverVsCode } from './clients/vscode.js';
import { discoverWindsurf } from './clients/windsurf.js';
import { discoverCustom } from './clients/custom.js';

export interface DiscoveryOptions {
  cwd?: string;
  clients?: ClientSource[];
  customConfigs?: string[];
}

export interface DiscoveryResult {
  servers: McpServerConfig[];
  configsFound: Map<string, ClientSource>;
}

const ALL_CLIENTS: ClientSource[] = [
  'claude-desktop',
  'claude-code',
  'cursor',
  'vscode',
  'windsurf',
];

export async function discoverAll(options: DiscoveryOptions = {}): Promise<DiscoveryResult> {
  const cwd = options.cwd || process.cwd();
  const enabledClients = options.clients || ALL_CLIENTS;
  const servers: McpServerConfig[] = [];
  const configsFound = new Map<string, ClientSource>();

  const tasks: Promise<McpServerConfig[]>[] = [];

  if (enabledClients.includes('claude-desktop')) {
    tasks.push(discoverClaudeDesktop());
  }
  if (enabledClients.includes('claude-code')) {
    tasks.push(discoverClaudeCode(cwd));
  }
  if (enabledClients.includes('cursor')) {
    tasks.push(discoverCursor(cwd));
  }
  if (enabledClients.includes('vscode')) {
    tasks.push(discoverVsCode(cwd));
  }
  if (enabledClients.includes('windsurf')) {
    tasks.push(discoverWindsurf());
  }

  if (options.customConfigs?.length) {
    tasks.push(discoverCustom(options.customConfigs));
  }

  const results = await Promise.all(tasks);

  for (const batch of results) {
    for (const server of batch) {
      servers.push(server);
      configsFound.set(server.configPath, server.source);
    }
  }

  return { servers, configsFound };
}

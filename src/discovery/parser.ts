import type { McpServerConfig, ClientSource } from '../types/config.js';

interface RawServerEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  type?: string;
  headers?: Record<string, string>;
}

/**
 * Parse a raw MCP config object into normalized McpServerConfig[].
 * Handles both "mcpServers" (Claude, Cursor, Windsurf) and "servers" (VS Code) keys.
 */
export function parseConfig(
  raw: unknown,
  source: ClientSource,
  configPath: string
): McpServerConfig[] {
  if (!raw || typeof raw !== 'object') return [];

  const obj = raw as Record<string, unknown>;
  const serversMap = (obj.mcpServers ?? obj.servers ?? {}) as Record<string, RawServerEntry>;

  if (!serversMap || typeof serversMap !== 'object') return [];

  const results: McpServerConfig[] = [];

  for (const [name, entry] of Object.entries(serversMap)) {
    if (!entry || typeof entry !== 'object') continue;

    const config = parseServerEntry(name, entry, source, configPath);
    if (config) results.push(config);
  }

  return results;
}

function parseServerEntry(
  name: string,
  entry: RawServerEntry,
  source: ClientSource,
  configPath: string
): McpServerConfig | null {
  // Determine transport type
  if (entry.url) {
    const transport = entry.type === 'http' ? 'http' as const : 'sse' as const;
    return {
      name,
      source,
      configPath,
      transport,
      url: entry.url,
      headers: entry.headers,
      env: entry.env,
    };
  }

  if (entry.command) {
    const { packageName, packageVersion } = extractPackageInfo(entry.command, entry.args);
    return {
      name,
      source,
      configPath,
      transport: 'stdio',
      command: entry.command,
      args: entry.args,
      env: entry.env,
      packageName,
      packageVersion,
    };
  }

  return null;
}

/**
 * Extract npm/npx package name and version from command + args.
 * Handles patterns like: npx -y @scope/package@version
 */
export function extractPackageInfo(command: string, args?: string[]): {
  packageName?: string;
  packageVersion?: string;
} {
  const allParts = [command, ...(args || [])];
  const isNpx = command === 'npx' || command.endsWith('/npx') || command.endsWith('\\npx');
  const isNode = command === 'node' || command.endsWith('/node') || command.endsWith('\\node');

  if (isNpx && args) {
    // Find the package name (skip flags like -y, --yes, -p, --package)
    const skipNext = new Set(['-p', '--package']);
    let skipFlag = false;
    for (const arg of args) {
      if (skipFlag) { skipFlag = false; continue; }
      if (skipNext.has(arg)) { skipFlag = true; continue; }
      if (arg.startsWith('-')) continue;

      // This should be the package name
      const atIdx = arg.lastIndexOf('@');
      if (atIdx > 0) {
        return {
          packageName: arg.slice(0, atIdx),
          packageVersion: arg.slice(atIdx + 1),
        };
      }
      return { packageName: arg };
    }
  }

  // Check for direct package execution (e.g., "mcp-server-fetch")
  if (!isNpx && !isNode && !command.includes('/') && !command.includes('\\')) {
    return { packageName: command };
  }

  return {};
}

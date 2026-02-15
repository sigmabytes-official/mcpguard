import * as path from 'node:path';
import { getAppDataDir, getPlatform } from '../../utils/platform.js';
import type { McpServerConfig } from '../../types/config.js';
import { parseConfig } from '../parser.js';
import { readJsonFile } from '../utils.js';

export function getVsCodeConfigPaths(cwd: string): string[] {
  const platform = getPlatform();
  const paths = [
    // Workspace-level
    path.join(cwd, '.vscode', 'mcp.json'),
  ];

  // User-level
  switch (platform) {
    case 'macos':
      paths.push(path.join(getAppDataDir(), 'Code', 'User', 'mcp.json'));
      break;
    case 'windows':
      paths.push(path.join(getAppDataDir(), 'Code', 'User', 'mcp.json'));
      break;
    case 'linux':
      paths.push(path.join(getAppDataDir(), 'Code', 'User', 'mcp.json'));
      break;
  }

  return paths;
}

export async function discoverVsCode(cwd: string): Promise<McpServerConfig[]> {
  const results: McpServerConfig[] = [];

  for (const configPath of getVsCodeConfigPaths(cwd)) {
    const raw = await readJsonFile(configPath);
    if (raw) {
      // VS Code uses "servers" key instead of "mcpServers"
      // parseConfig handles both
      results.push(...parseConfig(raw, 'vscode', configPath));
    }
  }

  return results;
}

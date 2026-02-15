import * as path from 'node:path';
import { getHomeDir, getUserProfileDir, getPlatform } from '../../utils/platform.js';
import type { McpServerConfig } from '../../types/config.js';
import { parseConfig } from '../parser.js';
import { readJsonFile } from '../utils.js';

export function getCursorConfigPaths(cwd: string): string[] {
  const home = getPlatform() === 'windows' ? getUserProfileDir() : getHomeDir();
  return [
    // Project-level
    path.join(cwd, '.cursor', 'mcp.json'),
    // Global
    path.join(home, '.cursor', 'mcp.json'),
  ];
}

export async function discoverCursor(cwd: string): Promise<McpServerConfig[]> {
  const results: McpServerConfig[] = [];

  for (const configPath of getCursorConfigPaths(cwd)) {
    const raw = await readJsonFile(configPath);
    if (raw) {
      results.push(...parseConfig(raw, 'cursor', configPath));
    }
  }

  return results;
}

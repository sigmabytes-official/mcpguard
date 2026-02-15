import * as path from 'node:path';
import { getHomeDir, getUserProfileDir, getPlatform } from '../../utils/platform.js';
import type { McpServerConfig } from '../../types/config.js';
import { parseConfig } from '../parser.js';
import { readJsonFile } from '../utils.js';

export function getWindsurfConfigPaths(): string[] {
  const home = getPlatform() === 'windows' ? getUserProfileDir() : getHomeDir();
  return [
    path.join(home, '.codeium', 'windsurf', 'mcp_config.json'),
  ];
}

export async function discoverWindsurf(): Promise<McpServerConfig[]> {
  const results: McpServerConfig[] = [];

  for (const configPath of getWindsurfConfigPaths()) {
    const raw = await readJsonFile(configPath);
    if (raw) {
      results.push(...parseConfig(raw, 'windsurf', configPath));
    }
  }

  return results;
}

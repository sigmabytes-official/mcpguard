import * as path from 'node:path';
import { getAppDataDir, getPlatform } from '../../utils/platform.js';
import type { McpServerConfig } from '../../types/config.js';
import { parseConfig } from '../parser.js';
import { readJsonFile } from '../utils.js';

export function getClaudeDesktopConfigPaths(): string[] {
  const platform = getPlatform();
  switch (platform) {
    case 'macos':
      return [path.join(getAppDataDir(), 'Claude', 'claude_desktop_config.json')];
    case 'windows':
      return [path.join(getAppDataDir(), 'Claude', 'claude_desktop_config.json')];
    case 'linux':
      return [path.join(getAppDataDir(), 'Claude', 'claude_desktop_config.json')];
  }
}

export async function discoverClaudeDesktop(): Promise<McpServerConfig[]> {
  const results: McpServerConfig[] = [];

  for (const configPath of getClaudeDesktopConfigPaths()) {
    const raw = await readJsonFile(configPath);
    if (raw) {
      results.push(...parseConfig(raw, 'claude-desktop', configPath));
    }
  }

  return results;
}

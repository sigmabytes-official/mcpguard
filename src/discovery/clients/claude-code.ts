import * as path from 'node:path';
import { getHomeDir } from '../../utils/platform.js';
import type { McpServerConfig } from '../../types/config.js';
import { parseConfig } from '../parser.js';
import { readJsonFile } from '../utils.js';

export function getClaudeCodeConfigPaths(cwd: string): string[] {
  return [
    // Project-level
    path.join(cwd, '.mcp.json'),
    // User-level
    path.join(getHomeDir(), '.claude.json'),
  ];
}

export async function discoverClaudeCode(cwd: string): Promise<McpServerConfig[]> {
  const results: McpServerConfig[] = [];

  // Project-level .mcp.json
  const projectConfig = path.join(cwd, '.mcp.json');
  const projectRaw = await readJsonFile(projectConfig);
  if (projectRaw) {
    results.push(...parseConfig(projectRaw, 'claude-code', projectConfig));
  }

  // User-level ~/.claude.json may have mcpServers at top level
  // or nested under projects
  const userConfig = path.join(getHomeDir(), '.claude.json');
  const userRaw = await readJsonFile(userConfig);
  if (userRaw && typeof userRaw === 'object') {
    const obj = userRaw as Record<string, unknown>;
    // Direct mcpServers at top level
    if (obj.mcpServers) {
      results.push(...parseConfig(userRaw, 'claude-code', userConfig));
    }
    // Projects with mcpServers
    if (obj.projects && typeof obj.projects === 'object') {
      for (const [, projectData] of Object.entries(obj.projects as Record<string, unknown>)) {
        if (projectData && typeof projectData === 'object') {
          const pd = projectData as Record<string, unknown>;
          if (pd.mcpServers) {
            results.push(...parseConfig(projectData, 'claude-code', userConfig));
          }
        }
      }
    }
  }

  return results;
}

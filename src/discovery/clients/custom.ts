import * as path from 'node:path';
import type { McpServerConfig } from '../../types/config.js';
import { parseConfig } from '../parser.js';
import { readJsonFile } from '../utils.js';

export async function discoverCustom(configPaths: string[]): Promise<McpServerConfig[]> {
  const results: McpServerConfig[] = [];

  for (const rawPath of configPaths) {
    const configPath = path.resolve(rawPath);
    const raw = await readJsonFile(configPath);
    if (raw) {
      results.push(...parseConfig(raw, 'custom', configPath));
    }
  }

  return results;
}

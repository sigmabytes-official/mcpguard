import { z } from 'zod';

export type ClientSource =
  | 'claude-desktop'
  | 'claude-code'
  | 'cursor'
  | 'vscode'
  | 'windsurf'
  | 'custom';

export interface McpServerConfig {
  name: string;
  source: ClientSource;
  configPath: string;
  transport: 'stdio' | 'http' | 'sse';
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
  packageName?: string;
  packageVersion?: string;
}

// Schema for stdio-based MCP server
export const StdioServerSchema = z.object({
  command: z.string(),
  args: z.array(z.string()).optional(),
  env: z.record(z.string()).optional(),
});

// Schema for HTTP/SSE-based MCP server
export const HttpServerSchema = z.object({
  url: z.string(),
  type: z.enum(['sse', 'http']).optional(),
  headers: z.record(z.string()).optional(),
  env: z.record(z.string()).optional(),
});

// Union server schema
export const ServerEntrySchema = z.union([
  StdioServerSchema,
  HttpServerSchema,
]);

// Top-level config using "mcpServers" key (Claude Desktop, Cursor, Windsurf, Claude Code)
export const McpServersConfigSchema = z.object({
  mcpServers: z.record(ServerEntrySchema).optional(),
});

// Top-level config using "servers" key (VS Code)
export const VsCodeMcpConfigSchema = z.object({
  servers: z.record(ServerEntrySchema).optional(),
});

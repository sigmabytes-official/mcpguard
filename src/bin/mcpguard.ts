#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'node:fs/promises';
import { scan, VERSION, type ScanOptions, type OutputFormat } from '../index.js';
import type { Severity } from '../types/findings.js';
import type { ClientSource } from '../types/config.js';

const program = new Command();

program
  .name('mcpguard')
  .description('Offline-first security auditor for MCP (Model Context Protocol) configurations')
  .version(VERSION);

program
  .command('scan', { isDefault: true })
  .description('Scan MCP configurations for security issues')
  .option('-c, --config <paths...>', 'Additional config file paths to scan')
  .option('-f, --format <format>', 'Output format: terminal, json, sarif, html', 'terminal')
  .option('-o, --output <path>', 'Write report to file instead of stdout')
  .option('--fail-on <severity>', 'Exit with code 1 if findings at this severity or above (critical, high, medium, low)')
  .option('--clients <clients...>', 'Only scan specific clients (claude-desktop, claude-code, cursor, vscode, windsurf)')
  .option('--supply-chain', 'Enable supply chain CVE checks via OSV.dev (requires network)')
  .option('-q, --quiet', 'Minimal output (findings only, no header/summary)')
  .action(async (opts) => {
    try {
      const scanOptions: ScanOptions = {
        cwd: process.cwd(),
        format: validateFormat(opts.format),
        output: opts.output,
        failOn: opts.failOn ? validateSeverity(opts.failOn) : undefined,
        quiet: opts.quiet || false,
        supplyChain: opts.supplyChain || false,
        customConfigs: opts.config,
        clients: opts.clients?.map(validateClient),
      };

      const result = await scan(scanOptions);

      // Output
      if (opts.output) {
        await fs.writeFile(opts.output, result.formatted, 'utf-8');
        if (!opts.quiet) {
          console.log(`Report written to ${opts.output}`);
        }
      } else {
        console.log(result.formatted);
      }

      process.exit(result.exitCode);
    } catch (error) {
      console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
      process.exit(2);
    }
  });

function validateFormat(format: string): OutputFormat {
  const valid: OutputFormat[] = ['terminal', 'json', 'sarif', 'html'];
  if (!valid.includes(format as OutputFormat)) {
    console.error(`Invalid format: ${format}. Valid options: ${valid.join(', ')}`);
    process.exit(2);
  }
  return format as OutputFormat;
}

function validateSeverity(severity: string): Severity {
  const valid: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
  if (!valid.includes(severity as Severity)) {
    console.error(`Invalid severity: ${severity}. Valid options: ${valid.join(', ')}`);
    process.exit(2);
  }
  return severity as Severity;
}

function validateClient(client: string): ClientSource {
  const valid: ClientSource[] = ['claude-desktop', 'claude-code', 'cursor', 'vscode', 'windsurf'];
  if (!valid.includes(client as ClientSource)) {
    console.error(`Invalid client: ${client}. Valid options: ${valid.join(', ')}`);
    process.exit(2);
  }
  return client as ClientSource;
}

program.parse();

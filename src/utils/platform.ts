import * as os from 'node:os';
import * as path from 'node:path';

export type Platform = 'macos' | 'windows' | 'linux';

export function getPlatform(): Platform {
  switch (process.platform) {
    case 'darwin':
      return 'macos';
    case 'win32':
      return 'windows';
    default:
      return 'linux';
  }
}

export function getHomeDir(): string {
  return os.homedir();
}

export function getAppDataDir(): string {
  const platform = getPlatform();
  switch (platform) {
    case 'windows':
      return process.env.APPDATA || path.join(getHomeDir(), 'AppData', 'Roaming');
    case 'macos':
      return path.join(getHomeDir(), 'Library', 'Application Support');
    case 'linux':
      return process.env.XDG_CONFIG_HOME || path.join(getHomeDir(), '.config');
  }
}

export function getUserProfileDir(): string {
  return process.env.USERPROFILE || getHomeDir();
}

/** Resolve a path that may contain ~ or environment variables */
export function resolvePath(p: string): string {
  let resolved = p;
  if (resolved.startsWith('~')) {
    resolved = path.join(getHomeDir(), resolved.slice(1));
  }
  // Expand %VAR% on Windows
  resolved = resolved.replace(/%([^%]+)%/g, (_, key) => process.env[key] || '');
  // Expand $VAR or ${VAR} on Unix
  resolved = resolved.replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (_, key) => process.env[key] || '');
  return path.resolve(resolved);
}

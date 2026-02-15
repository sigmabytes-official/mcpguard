import * as fs from 'node:fs/promises';

export async function readJsonFile(filePath: string): Promise<unknown | null> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    // Strip BOM if present
    const clean = content.replace(/^\uFEFF/, '');
    return JSON.parse(clean);
  } catch {
    // Try stripping JSONC comments (outside of strings) and retry
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const clean = content.replace(/^\uFEFF/, '');
      const stripped = stripJsonComments(clean);
      return JSON.parse(stripped);
    } catch {
      return null;
    }
  }
}

/** Strip single-line comments from JSONC, but only outside of string literals */
function stripJsonComments(text: string): string {
  let result = '';
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (escaped) {
      result += ch;
      escaped = false;
      continue;
    }
    if (ch === '\\' && inString) {
      result += ch;
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inString = !inString;
      result += ch;
      continue;
    }
    if (!inString && ch === '/' && text[i + 1] === '/') {
      // Skip until end of line
      while (i < text.length && text[i] !== '\n') i++;
      result += '\n';
      continue;
    }
    result += ch;
  }
  return result;
}

export async function fileExists(filePath: string): Promise<boolean> {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

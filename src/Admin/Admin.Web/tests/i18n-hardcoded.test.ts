import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import ts from 'typescript';

const sourceRoot = join(process.cwd(), 'src');
const literalAttributeNames = new Set(['aria-label', 'placeholder', 'title']);
const allowedTechnicalText = new Set(['EN', 'IT']);

function tsxFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? tsxFiles(path) : entry.isFile() && entry.name.endsWith('.tsx') && !entry.name.endsWith('.test.tsx') ? [path] : [];
  });
}

describe('UI localization boundary', () => {
  it('does not contain untranslated JSX text or literal accessibility copy', () => {
    const violations: string[] = [];
    for (const path of tsxFiles(sourceRoot)) {
      const source = ts.createSourceFile(path, readFileSync(path, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
      const visit = (node: ts.Node) => {
        if (ts.isJsxText(node)) {
          const text = node.text.trim();
          if (/[A-Za-zÀ-ÿ]/.test(text) && !allowedTechnicalText.has(text)) violations.push(`${path}:${source.getLineAndCharacterOfPosition(node.pos).line + 1}:${text}`);
        }
        if (ts.isJsxAttribute(node) && literalAttributeNames.has(node.name.getText(source)) && node.initializer && ts.isStringLiteral(node.initializer)) {
          violations.push(`${path}:${source.getLineAndCharacterOfPosition(node.pos).line + 1}:${node.name.getText(source)}=${node.initializer.text}`);
        }
        ts.forEachChild(node, visit);
      };
      visit(source);
    }
    expect(violations).toEqual([]);
  });
});

export type DiffKind = 'added' | 'removed' | 'changed';
export interface CanonicalJsonDiff { kind: DiffKind; path: string; oldValue?: string; newValue?: string }

const sensitive = /(^|\/)(password|secret|token|api[-_]?key|private[-_]?key|certificate)(\/|$)/i;
const pointer = (key: string) => key.replaceAll('~', '~0').replaceAll('/', '~1');
const visible = (path: string, value: unknown) => sensitive.test(path) ? '[REDACTED]' : JSON.stringify(value);

export function diffCanonicalJson(base: unknown, target: unknown): CanonicalJsonDiff[] {
  const result: CanonicalJsonDiff[] = [];
  const visit = (left: unknown, right: unknown, path: string) => {
    if (Object.is(left, right)) return;
    const leftObject = left !== null && typeof left === 'object';
    const rightObject = right !== null && typeof right === 'object';
    if (leftObject && rightObject && Array.isArray(left) === Array.isArray(right)) {
      const keys = [...new Set([...Object.keys(left as object), ...Object.keys(right as object)])].sort((a, b) => a.localeCompare(b, 'en'));
      for (const key of keys) {
        const child = `${path}/${pointer(key)}`;
        const inLeft = Object.hasOwn(left as object, key);
        const inRight = Object.hasOwn(right as object, key);
        if (!inLeft) result.push({ kind: 'added', path: child, newValue: visible(child, (right as Record<string, unknown>)[key]) });
        else if (!inRight) result.push({ kind: 'removed', path: child, oldValue: visible(child, (left as Record<string, unknown>)[key]) });
        else visit((left as Record<string, unknown>)[key], (right as Record<string, unknown>)[key], child);
      }
      return;
    }
    result.push({ kind: 'changed', path: path || '/', oldValue: visible(path, left), newValue: visible(path, right) });
  };
  visit(base, target, '');
  return result;
}

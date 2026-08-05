import { describe, expect, it } from 'vitest';
import { diffCanonicalJson } from './canonicalJsonDiff';

describe('canonical JSON diff', () => {
  it('reports deterministic added removed and changed paths', () => {
    expect(diffCanonicalJson({ z: 1, removed: true, nested: { value: 1 } }, { z: 2, added: true, nested: { value: 1 } })).toEqual([
      { kind: 'added', path: '/added', newValue: 'true' },
      { kind: 'removed', path: '/removed', oldValue: 'true' },
      { kind: 'changed', path: '/z', oldValue: '1', newValue: '2' },
    ]);
  });
  it('redacts sensitive values on both sides', () => {
    expect(diffCanonicalJson({ secret: 'old' }, { secret: 'new' })[0]).toEqual({ kind: 'changed', path: '/secret', oldValue: '[REDACTED]', newValue: '[REDACTED]' });
  });
});

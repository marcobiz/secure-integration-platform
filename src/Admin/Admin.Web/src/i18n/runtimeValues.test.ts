import { describe, expect, it } from 'vitest';
import { enTranslation } from './en';
import { itTranslation } from './it';
import { knownRuntimeValues, runtimeLabel } from './runtimeValues';

const translate = (resources: Record<string, string>) => ((key: string, options?: { value?: string }) => resources[key]?.replace('{{value}}', options?.value ?? '') ?? `MISSING:${key}`) as never;

describe('runtime wire value localization', () => {
  it('maps every known status, lifecycle, health, role, scope, audit action, outcome and reason in IT and EN', () => {
    for (const [kind, values] of Object.entries(knownRuntimeValues)) for (const wire of Object.keys(values)) {
      expect(runtimeLabel(translate(enTranslation), kind as keyof typeof knownRuntimeValues, wire)).not.toMatch(/^MISSING:/i);
      expect(runtimeLabel(translate(itTranslation), kind as keyof typeof knownRuntimeValues, wire)).not.toMatch(/^MISSING:/i);
      expect(runtimeLabel(translate(enTranslation), kind as keyof typeof knownRuntimeValues, wire)).not.toMatch(/^Unknown value/i);
      expect(runtimeLabel(translate(itTranslation), kind as keyof typeof knownRuntimeValues, wire)).not.toMatch(/^Valore sconosciuto/i);
    }
  });

  it('marks unknown and unsafe backend values without treating them as translated copy', () => {
    expect(runtimeLabel(translate(itTranslation), 'status', 'FutureState')).toBe('Valore sconosciuto (FutureState)');
    expect(runtimeLabel(translate(enTranslation), 'reason', '<script>')).toBe('Unknown value (invalid)');
  });
});

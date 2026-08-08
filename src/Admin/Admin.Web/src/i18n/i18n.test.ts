import { describe, expect, it } from 'vitest';
import { enTranslation } from './en';
import { itTranslation } from './it';

describe('administrative localization contract', () => {
  it('M5_UI_I18N_EN_IT_have_exactly_the_same_keys', () => {
    expect(Object.keys(itTranslation).sort()).toEqual(Object.keys(enTranslation).sort());
  });

  it('M5_UI_I18N_Italian_has_no_known_English_fallbacks', () => {
    const critical = ['access', 'reject', 'decisionComment', 'role', 'assignRole', 'approvalArtifacts', 'authorityEndpoint', 'authorityRole.authorization', 'authorityRole.token', 'canonicalDiff', 'pagination', 'unsavedTitle', 'bindingsHelp', 'concurrencyConflict', 'errorSummary', 'health', 'activationCode', 'addGrant'] as const;
    for (const key of critical) expect(itTranslation[key], key).not.toBe(enTranslation[key]);
  });
});

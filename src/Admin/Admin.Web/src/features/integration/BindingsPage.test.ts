import { describe, expect, it } from 'vitest';
import { buildBindingRequest, parseBindingMap } from './BindingsPage';

describe('binding editor', () => {
  it('submits multiple complete binding maps without secret values', () => {
    const request = buildBindingRequest({ connectorId: 'sample', connectorVersion: '1.0.0', environmentId: 'env', endpointsJson: '{"secondary":"https://b.example","primary":"https://a.example"}', secretReferencesJson: '{"apiKey":"synthetic://vendor-key","backup":"synthetic://backup"}', certificateReferencesJson: '{"mtls":"synthetic://client-cert"}' });
    expect(Object.keys(request.endpoints)).toEqual(['primary', 'secondary']);
    expect(request.secretReferences).toEqual({ apiKey: 'synthetic://vendor-key', backup: 'synthetic://backup' });
    expect(JSON.stringify(request)).not.toContain('secretValue');
  });
  it('rejects arrays and non-string binding values', () => {
    expect(() => parseBindingMap('[]', 'Endpoints')).toThrow(/object/);
    expect(() => parseBindingMap('{"primary":42}', 'Endpoints')).toThrow(/non-empty/);
  });
});

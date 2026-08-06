import { describe, expect, it } from 'vitest';
import { buildBindingRequest, parseBindingMap, parseResourceMap } from './BindingsPage';

describe('binding editor', () => {
  it('submits multiple complete binding maps without secret values', () => {
    const request = buildBindingRequest({ connectorId: 'sample', connectorVersion: '1.0.0', environmentId: 'env', endpointsJson: '{"secondary":"https://b.example","primary":"https://a.example"}', secretReferencesJson: '{"apiKey":{"providerId":"synthetic","resourceId":"vendor-key","resourceType":"Secret"}}', certificateReferencesJson: '{"mtls":{"providerId":"synthetic","resourceId":"client-cert","resourceType":"ClientCertificate","publicMetadataRevision":1}}' });
    expect(Object.keys(request.endpoints)).toEqual(['primary', 'secondary']);
    expect(request.secretResources.apiKey.resourceId).toBe('vendor-key');
    expect(JSON.stringify(request)).not.toContain('secretValue');
  });
  it('rejects arrays and non-string binding values', () => {
    expect(() => parseBindingMap('[]', 'Endpoints')).toThrow(/object/);
    expect(() => parseBindingMap('{"primary":42}', 'Endpoints')).toThrow(/non-empty/);
  });
  it('rejects opaque, URI, PEM and credential-like resource identifiers before submission', () => {
    const privateKeyMarker = ['-----BEGIN', 'PRIVATE KEY-----'].join(' ');
    expect(() => parseResourceMap('{"apiKey":"ACTUAL_API_KEY_CANARY"}', 'Secret resources', 'Secret')).toThrow(/catalog/);
    expect(() => parseResourceMap('{"apiKey":{"providerId":"synthetic","resourceId":"https://vault/secret","resourceType":"Secret"}}', 'Secret resources', 'Secret')).toThrow(/identifier/);
    expect(() => parseResourceMap(JSON.stringify({ cert: { providerId: 'synthetic', resourceId: privateKeyMarker, resourceType: 'ClientCertificate' } }), 'Certificate resources', 'ClientCertificate')).toThrow(/identifier/);
  });
});

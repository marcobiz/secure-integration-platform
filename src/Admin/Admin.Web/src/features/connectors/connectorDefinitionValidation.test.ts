import { describe, expect, it } from 'vitest';
import { validateConnectorDefinition } from './connectorDefinitionValidation';
import schema from '../../../../../../docs/connectors/connector-definition.schema.json';
import sample from '../../../../../../docs/connectors/examples/sample-secure-service.connector.json';

describe('canonical Connector Definition client validation', () => {
  it('accepts the authoritative sample with Draft 2020-12 AJV', () => {
    expect(validateConnectorDefinition(schema, sample)).toEqual([]);
  });

  it('reports stable codes and JSON Pointer locations', () => {
    const invalid: Record<string, unknown> = structuredClone(sample);
    delete invalid.connectorId;
    expect(validateConnectorDefinition(schema, invalid)).toContainEqual({
      code: 'CONNECTOR_SCHEMA_REQUIRED',
      location: '/',
      message: 'Connector definition validation failed.',
    });
  });
});

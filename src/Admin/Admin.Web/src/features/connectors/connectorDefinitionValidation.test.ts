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
      code: 'BGW-CONNECTOR-SCHEMA-REQUIRED',
      location: '/',
      message: 'Connector definition validation failed.',
    });
  });

  it('accepts exactly one Published path form under strict AJV validation', () => {
    const templated: Record<string, unknown> = structuredClone(sample);
    const templatedOperation = (templated.operations as Array<Record<string, unknown>>)[0];
    delete templatedOperation.path;
    templatedOperation.pathTemplate = '/bounded/{tenant}';
    expect(validateConnectorDefinition(schema, templated)).toEqual([]);

    const ambiguous: Record<string, unknown> = structuredClone(sample);
    const ambiguousOperation = (ambiguous.operations as Array<Record<string, unknown>>)[0];
    ambiguousOperation.pathTemplate = '/bounded/{tenant}';
    expect(validateConnectorDefinition(schema, ambiguous)).toContainEqual({
      code: 'BGW-CONNECTOR-SCHEMA-ONEOF',
      location: '/operations/0',
      message: 'Connector definition validation failed.',
    });
  });
});

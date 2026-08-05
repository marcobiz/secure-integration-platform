import Ajv2020, { type ErrorObject } from 'ajv/dist/2020';
import type { components } from '../../api/schema';

export type ConnectorValidationIssue = components['schemas']['ConnectorValidationIssue'];

export function validateConnectorDefinition(schema: object, definition: unknown): ConnectorValidationIssue[] {
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  if (validate(definition)) return [];
  return (validate.errors ?? []).map((error: ErrorObject) => ({
    code: `BGW-CONNECTOR-SCHEMA-${error.keyword.toUpperCase().replaceAll('_', '-').replaceAll(' ', '-').replaceAll('--', '-')}`,
    location: error.instancePath || '/',
    message: 'Connector definition validation failed.',
  }));
}

import Ajv2020, { type ErrorObject } from 'ajv/dist/2020';

export type ConnectorValidationIssue = { code: string; location: string };

export function validateConnectorDefinition(schema: object, definition: unknown): ConnectorValidationIssue[] {
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  if (validate(definition)) return [];
  return (validate.errors ?? []).map((error: ErrorObject) => ({
    code: `CONNECTOR_SCHEMA_${error.keyword.toUpperCase().replaceAll('-', '_')}`,
    location: error.instancePath || '/',
  }));
}

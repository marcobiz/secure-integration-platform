# Public analysis of architectural inputs

## Scope

Public architectural decisions are based on official service documentation, public standards and synthetic fixtures maintained in the repository. Assessments outside this scope are not normative inputs to the public product specification.

Public documentation must contain no credentials, private cryptographic material, personal or health data, nonpublic operational endpoints or artifacts unnecessary for design.

## Public normative inputs

- current official specifications for FSE 2.0, Sistema TS, VetInfo and relevant regional healthcare services;
- public standards for SOAP, REST, OAuth 2.0, mTLS, JWT, PKCE, Basic Authentication and session management;
- synthetic fixtures and characterizations without real data;
- generic architectural requirements of Connector Runtime, connector lifecycle and provider abstractions.

## Architectural requirements

1. Outbound credentials, certificates and tokens are resolved and managed by server-owned components through separate providers for secrets, certificates and key operations.
2. Identity, tenant, installation and authorization derive from authenticated server-side state, not client parameters treated as authoritative.
3. Operations exposed to clients are limited by explicit connector/operation grants; endpoints and credential bindings remain server-side configuration.
4. Exportable keys can be held centrally; truly non-exportable keys require a controlled local capability without exposing private material.
5. Tokens and session references are opaque runtime state, with lifetime, renewal and invalidation governed by the connector.
6. Transport, egress, logging and audit enforce TLS validation, data minimization and fail-closed behavior.
7. Connector lifecycle separates definition, validation, approval, immutable publication and execution.

## Protocols to cover

- SOAP/XML with Basic Authentication or session references when specified by the official specification;
- REST/JSON and SOAP/XML protected by OAuth 2.0;
- Authorization Code with PKCE and user interaction when required by the service;
- mTLS with certificates resolved through a central provider or controlled local capability;
- JWT with algorithm, claims, issuer, audience and lifetime constrained by the connector definition.

## Public traceability and synthetic characterization

- Each public specification declares provenance as `OFFICIAL_SPEC`, `PUBLIC_STANDARD` or `SYNTHETIC_CHARACTERIZATION`.
- Fixtures describe only synthetic request, response and fault shapes and state transitions.
- A conclusion unsupported by a public source or synthetic characterization is not normative for the public product.
- Synthetic characterization includes no real data, operational identifiers, credentials or private cryptographic material.

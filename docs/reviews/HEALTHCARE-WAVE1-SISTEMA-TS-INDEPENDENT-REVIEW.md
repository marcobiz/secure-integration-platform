# Healthcare Wave 1 - Sistema TS independent review request

Status: **PENDING INDEPENDENT REVIEW**

Review only the connector delta; the generic Core/Auth/Runtime foundation is out of scope.

Checklist:

- compare create/checkToken nesting, namespaces, cardinalities and outcomes with frozen ID-session
  XSD/manual digests;
- compare the four business request/response sequences and SOAP actions with the frozen 2026-04-28
  WSDL/XSD digests, including the published suspend action namespace;
- verify nested element order/cardinality, simple-versus-complex shape and lexical/value facets,
  including child-in-simple and unexpected nested-element negatives;
- verify server-owned create/checkToken input exactness, no plaintext getter and no caller authority;
- verify successful create requires authenticated external admission and checkToken before promotion;
- verify the four business operations are absent from the Published definition and explicitly fail
  closed with zero transport; do not request or accept a raw-payload workaround;
- verify the direct synthetic server covers exact Basic + `Authorization2F: Bearer` SOAP wire shape
  for all four operations, while remaining classified as fixture rather than product E2E evidence;
- verify exact Published A freshness and generic A-to-B zero-effect regressions apply unchanged;
- verify redaction and that canonical PostgreSQL CI requires execution of the vertical admission test;
- preserve `SERVER_OWNED_BUSINESS_FIELDS`, `BUSINESS_SOAP` and
  `POSTGRESQL_FULL_BUSINESS_E2E` as `BLOCKED_BY_CORE`;
- confirm accreditation/live conformance remains unclaimed.

The reviewer should record the exact candidate commit and return GO or actionable connector-focused
findings. This document is not itself an approval.

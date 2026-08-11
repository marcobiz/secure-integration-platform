# Healthcare Wave 1 - Sistema TS independent review request

Status: **PENDING INDEPENDENT REVIEW**

Review only the connector delta; the generic Core/Auth/Runtime foundation is out of scope.

Checklist:

- compare create/checkToken nesting, namespaces, cardinalities and outcomes with frozen ID-session
  XSD/manual digests;
- compare the four business request/response sequences and SOAP actions with the frozen 2026-04-28
  WSDL/XSD digests, including the published suspend action namespace;
- verify server-owned input exactness, no plaintext getter and no caller authority;
- verify successful create requires authenticated external admission and checkToken before promotion;
- verify the promoted generation is reused by composed Basic + `Authorization2F: Bearer` SOAP;
- verify exact Published A freshness and generic A-to-B zero-effect regressions apply unchanged;
- verify redaction and the PostgreSQL hosted test counters/evidence;
- confirm accreditation/live conformance remains unclaimed.

The reviewer should record the exact candidate commit and return GO or actionable connector-focused
findings. This document is not itself an approval.

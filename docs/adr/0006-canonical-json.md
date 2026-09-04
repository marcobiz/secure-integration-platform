# ADR-0006: Canonical JSON

**Status:** Accepted

## Decision

JSON Schema Draft 2020-12 for validation and RFC 8785 for canonicalization/checksum. YAML is only for import/export, converted and validated; custom tags and executable constructs are prohibited.

## Consequences

Diffs, checksums, signatures and promotion are deterministic. Numbers and Unicode must strictly follow RFC 8785. Published versions retain immutable canonical JSON.

## Rejected alternatives

YAML as the source of truth introduces ambiguous parsing; a purely relational schema constrains Connector evolution.

# Licensing policy

Copyright 2026 ApoCert S.r.l.

This repository uses a deterministic path-based licensing model. SPDX expressions in this document are exact: `OR` means a recipient may choose either license, while `AND` is used only for an aggregate that contains material under both licenses.

## Precedence and path map

The first applicable row wins. Rows are intentionally disjoint after precedence is applied.

| Precedence | Git-tracked path | License |
|---:|---|---|
| 1 | `docs/connectors/examples/**` | `MPL-2.0 OR Apache-2.0` |
| 2 | `sdk/**` | `Apache-2.0` |
| 2 | `src/Shared/SecureIntegration.Contracts/**` | `Apache-2.0` |
| 2 | `samples/**` | `Apache-2.0` |
| 2 | `src/Providers/Synthetic/**` | `Apache-2.0` |
| 2 | `docs/api/broker-ipc.md` | `Apache-2.0` |
| 2 | `docs/api/gateway-api.md` | `Apache-2.0` |
| 2 | `docs/api/gateway-openapi.yaml` | `Apache-2.0` |
| 2 | `docs/api/runtime-wire-codes.json` | `Apache-2.0` |
| 2 | `docs/connectors/connector-definition.schema.json` | `Apache-2.0` |
| 2 | `docs/connectors/connector-specification.md` | `Apache-2.0` |
| 3 | Every other project-authored Git-tracked path | `MPL-2.0` |

The default row includes, without limitation, `src/Gateway/**`, `src/Broker/**`, `src/Authentication/**`, `src/Providers/Abstractions/**`, `src/Admin/**`, `src/ConnectorPacks/**`, `packs/deployment/**`, `tools/fse2/**`, Core tooling, tests, and documentation not listed above. Current FSE2 reference code, the current local PKCS#12 pack, and the current Azure pack are therefore `MPL-2.0`. Tests follow the default unless an exact override above applies. Generated files follow the license of their output subtree.

`docs/connectors/examples/LICENSE.md` is the canonical metadata for the generic reference Connector/configuration examples and records the exact expression `MPL-2.0 OR Apache-2.0`.

## Adding, moving, and relicensing files

A new project-authored file receives the license of its path under the table above. Moving a file across a boundary does not automatically relicense existing material. A license change requires authorization from every applicable copyright holder and, where needed, an exact policy exception reviewed with the change. There are no current exceptions.

Third-party dependencies, vendored texts, and attributed documents remain governed by their respective licenses and notices. In particular, the official license texts, Developer Certificate of Origin, and Contributor Covenant retain their own terms; the repository path map does not replace them. Dependency notices and the generated SBOM are the authoritative inventory for third-party components.

## Aggregates and excluded repositories

The Core source archive contains files under both repository licenses and is described as `MPL-2.0 AND Apache-2.0`; this does not change the license of any individual file. The SDK package is `Apache-2.0`; Gateway and Migrations images and the Admin Web archive are `MPL-2.0`.

Future customer-specific packs may be commercial or contractual work in separate private repositories. Those repositories are not present here, are not included in this repository's open-source grant, and do not receive a license automatically or retroactively from this policy. This statement creates no commercial terms for any external repository.

The unmodified MPL 2.0 text is in [LICENSE](LICENSE). The unmodified Apache License 2.0 text is in [LICENSE-APACHE-2.0](LICENSE-APACHE-2.0).

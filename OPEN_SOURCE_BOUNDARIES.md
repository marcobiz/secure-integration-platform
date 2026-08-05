# Open-source boundaries

## Core tree

The public-preview candidate comprises `src` (including Admin UI and provider abstractions), `sdk`, Core tests, local/synthetic deployment files, Connector CLI and schemas, build/security scripts and public documentation. It builds and runs without Azure, AWS, HashiCorp Vault or a commercial pack.

## Separate packs

Deployment packs may provide qualified cloud composition, managed identity integration, operational support and provider implementations. Connector packs may contain maintained vertical integrations. Legacy adapter packs may contain COM, C ABI, VB6/Delphi/COBOL/Java compatibility. These modules consume Core contracts; essential Core functionality is not artificially disabled when they are absent.

The current Azure experiment remains under `packs/deployment/azure` and is excluded from the Core export. No AWS, HashiCorp, healthcare connector or commercial legacy adapter is implemented in M5.

## Publication exclusions

`eng/Export-OpenSourceCore.ps1` copies an allowlisted tree to a new temporary directory and rejects raw evidence, private reports, dumps, Event Logs, DPAPI blobs, credentials, private certificates, provider packs and reserved vertical content. It runs secret/boundary/license checks and builds/tests both .NET Core and Admin Web before emitting a SHA-256 manifest. The source repository and history are never rewritten.

The definitive open-source license remains pending; see [the license decision](docs/legal/OPEN-SOURCE-LICENSE-DECISION.md).

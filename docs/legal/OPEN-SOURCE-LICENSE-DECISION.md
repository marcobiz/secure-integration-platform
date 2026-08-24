# Open-source licensing and contribution decision

Status: **approved inputs implemented in the public-technical-preview candidate; pending independent review and integration**.

The project-authored repository default is Mozilla Public License 2.0. The .NET SDK, reusable contracts/protocol surfaces, samples, and explicitly enumerated synthetic implementations use Apache License 2.0. Generic reference Connector/configuration examples use the exact dual-license expression `MPL-2.0 OR Apache-2.0`. The authoritative precedence and exact paths are in [`LICENSING.md`](../../LICENSING.md).

Copyright holder and year: **ApoCert S.r.l., 2026**. Inbound contributions use Developer Certificate of Origin 1.1 with commit sign-off. No Contributor License Agreement is required.

The current FSE2 reference, local PKCS#12 deployment pack, and Azure deployment pack are `MPL-2.0`. Their optional placement does not change Core dependency direction or create a production qualification. Future customer-specific packs may be governed commercially or contractually in separate private repositories; those repositories are absent from this repository and receive no automatic or retroactive grant from it.

The Core source ZIP is an aggregate containing files under both licenses and is therefore described as `MPL-2.0 AND Apache-2.0`. Individual files retain the license assigned by path. Third-party dependencies and attributed texts retain their own licenses and notices.

This decision authorizes candidate implementation of licensing metadata and governance. It does not authorize a merge, tag, GitHub Release, package feed, container registry publication, production claim, trademark grant, or terms for an external repository. `PUBLIC_RELEASE_GO` remains `NO` until independent review, integration, and the later publication gate.

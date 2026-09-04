# User guide

**Audience:** adopters, operators and administrators.
**Status:** CURRENT for the baseline in
[IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md).

## Where to start

- [Quick start](quickstart.md): distinct synthetic Core, Windows boundary and FSE2 pack paths.
- [Local Core pilot](local-pilot.md): primary Docker-first path without cloud,
  external credentials, application SDKs or curl on the host.
- [Windows / Local Broker](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/history/README.md#windows--local-broker-evidence):
  historical service and isolation tests, with their own laboratory prerequisites.
- [FSE2 validation and status](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md):
  current optional pilot entry point, requiring a host .NET SDK and previously
  authorized OfficialTest access/material; shipped runner for bootstrap, roles and bounded invocation.
- [Administration](administration.md): lifecycle, bindings, grants, four-eyes, audit and health.
- [Guided Connector onboarding](guided-connector-onboarding.md): five actions across
  three roles, one-time handoff, safe resume and first invocation.
- [Troubleshooting](troubleshooting.md): code → likely cause → authorized action.
- [Known limitations](known-limitations.md): what the private preview does not promise.

Capability status is summarized only in
[IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md#product-status). The
[previous FSE2 validate-only pilot](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-officialtest.md)
is historical for first adoption; qualifications do not transfer between profiles.

These guides require no SQL, direct store access or reading tests. If an ordinary
onboarding, recovery or testing procedure requires specialist intervention, the
adoption experience has failed: record the blocker as a product/UX problem,
not mandatory operator knowledge.

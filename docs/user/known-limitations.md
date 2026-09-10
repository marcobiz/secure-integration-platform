# Known limitations

**Audience:** evaluators, administrators and decision-makers.
**Status:** CURRENT.

## Local pilot and private preview

- This is a local synthetic test, not an installer, a stable release or production qualification.
- The sample Direct client's key is process-local; a real consumer needs an
  appropriate protected/non-exportable key store.
- DevelopmentAuth, CAs, providers and mocks are laboratory-only.
- The runner cannot resume midway: after interruption, use ownership-checked cleanup
  and a new run.
- Live cloud use, MSI, C ABI/COM adapters, HA/DR, restore/load/soak, penetration testing
  and artifact signing are not qualified.
- Open-source licensing and self-managed deployment do not by themselves establish legal
  exclusion from CRA, NIS2, sector rules, procurement duties or customer supply-chain
  review. Users must assess their own role, jurisdiction, sector and operating model.
- Checksums, Git commits, DCO sign-off, SBOMs and manifests help identify reviewed
  content, but current artifacts are not signed and no cryptographic publisher-origin
  guarantee is claimed.

## FSE2

The [authoritative capability summary](../../IMPLEMENTATION_STATUS.md#product-status)
separates the 14 routes complete offline within the frozen specification from the
only live-qualified cases: CDA `VERIFICA` and workflow `FOUND` after restart.
The [current pilot](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md)
is optional and not a Core prerequisite.

- FHIR `VERIFICA` is not live-qualified: upstream 500 / Gateway 502 `generic-error`,
  cause undetermined. Do not infer a format or accreditation problem.
- Live document publication is not qualified. The runner permits only VERIFICA and
  lookup; publishing a Connector configuration does not publish a document.
  `FOUND` does not prove clinical completion or publication.
- The status mapper intentionally discards non-technical content from
  `transactionData[]` and accepts only bounded types/outcomes/timestamps.
  Correlation is durable in PostgreSQL for restart and scale-out, without clinical data.
- Human Actor, inbound callbacks, confirmed direct FHIR publication, accreditation,
  production custody, general monitoring and production are out of scope.
- The shipped runner handles local bootstrap, enrollment and role sessions, reusing
  the resumable provisioner. It requires a host .NET SDK, OfficialTest access,
  previously provisioned A1/S1 material and external organization configuration.
  It is not the Core's container-only tooling path; it neither imports material
  nor creates external accounts.
- The [old validate-only profile](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-officialtest.md)
  retains its own qualifications and immutable Published versions; it does not
  automatically transfer qualification to `fse2-organization-current-spec@1.0.0`.

## Windows / Local Broker

[M0/M1 and M3A evidence](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/history/README.md#windows--local-broker-evidence)
proves the boundary using a real Windows Service on historical baselines, not an
installer or a current adopter-facing demo. The Direct Core pilot does not exercise
that path. C ABI/COM adapters are not qualified; Administrator and SYSTEM remain
privileged residual threats, not subjects fully isolated from the Broker.
Local Broker recovery is bounded by Windows identity and DPAPI behavior. A useful backup
must preserve the complete protected data directory, installation metadata, policy,
ciphertext, ACLs and the Windows/service identity state needed by DPAPI; copied blobs
alone are not a portable recovery package.

## Adoption rule

If ordinary onboarding, recovery or testing requires specialist intervention, direct
store access, SQL, knowledge of tests or invented sequences, the adoption experience
has failed. The remedy is a bounded product/UX change or an explicit external
precondition, not more mandatory operator knowledge.

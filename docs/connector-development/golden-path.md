# Connector golden path

**Audience:** end-to-end Connector owners.
**Status:** CURRENT as an adoption contract for new Connectors.

Before implementation, freeze one visible outcome and the negative tests that protect
it. The golden path starts with an empty deployment and ends with a bounded call,
not a validated definition or an isolated synthetic suite.

```text
prerequisite preflight
→ environment/provider bootstrap
→ Installation enrollment
→ definition validate/import
→ binding + grant
→ editor proposal
→ distinct approval + publish
→ verify Published/Active
→ first bounded invocation
→ sanitized result + metadata-only audit
→ owned cleanup or resumable terminal state
```

## Plan

`plan` is read-only and describes:

- current state observed through supported surfaces;
- the earliest missing prerequisite;
- the proposed difference and server-owned authorities involved;
- the role authorized for the next action;
- whether the same operation can be safely repeated.

Do not read stores, construct authority from untrusted external files or print
endpoints, provider locators, secrets, certificates, cookies or payloads.

## Apply

`apply` performs only the next missing transition, then reads back state.
It must be idempotent and monotonic. A 429 or expired session pauses the same workflow;
it does not trigger hidden retries, reimport, cleanup or a new state machine.

Four-eyes approval remains real: distinct proposer and approver, exact checksum/digest
and server-side authorization. A guided workflow may carry state and revisions,
but cannot merge principals or allow self-approval.

## Verify

Verify through Admin API/UI:

- active Installation and server-derived Environment;
- exact Connector/version, `Published/Active` and expected checksum;
- complete bindings with current provider revisions;
- enabled Installation/operation grant;
- valid distinct approval for the current artifact;
- health/readiness required for the call.

## First call and negative set

The black-box test uses the public API/SDK, the effective server-resolved endpoint and
an authorized synthetic fixture. It measures **time to first successful call** from
clean state and verifies at least:

- exactly one invocation/outbound within budget;
- a bounded, sanitized response;
- correlated metadata-only audit;
- denial before effects for missing grants, binding/provider drift and invalid input;
- resume after the last persisted phase and cleanup limited to task-owned resources.

Do not use a total test count as proof, create production instrumentation solely
for evidence or replace the product path with fixtures, SQL or test hosts.

## Stop rule

If a second exception, procedure or test apparatus exists mainly to compensate for an
earlier choice, stop and re-examine the authoritative cause before adding a third layer.
If ordinary onboarding, recovery or testing requires specialist support, the golden
path is not complete.

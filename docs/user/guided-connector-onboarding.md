# Guided Connector onboarding

**Audience:** Security Administrator, Connector Editor and Connector Approver.
**Status:** CURRENT for the integrated Admin UI; the local laboratory uses only
synthetic data and does not qualify a production deployment.

The **Guided onboarding** page (`/admin/onboarding`) takes a new Installation from
empty state to a `Published`, invocable Connector version. The normal path requires
no UUIDs, checksums, binding JSON, provider references, SQL or store access.
The page always reads authoritative state and shows:

- current state and missing prerequisite;
- the role that must continue;
- the next authorized action;
- confirmation that reloading and retrying the same action are safe.

## The five actions

| # | Role | Primary action | Outcome |
|---|---|---|---|
| 1 | Security Administrator | Select Tenant, Application and Environment by name and create the Installation. | The one-time enrollment handoff appears. |
| 2 | Connector Editor | Choose a normal `.json` file and press **Validate and import**. | The Gateway computes and verifies ID, version and checksum, then stores a `Validated` version. |
| 3 | Security Administrator | If needed, select endpoints and credentials from the catalog and press **Configure binding and grants**. | Complete bindings and exact grants are created from server-owned selections for the version reread by the server. |
| 4 | Connector Editor | Press **Request approval**. | The request is frozen for the exact version and binding digest. |
| 5 | Connector Approver | Read the actual review and press **Verify, approve and publish**. | The same Approver approves and publishes that exact version. |

The **Connectors** page retains the full JSON editor as an advanced path; it is
not required for the guided flow.

## One-time enrollment handoff

After the first action, the dialog shows these together:

- **Activation code ID**;
- **Activation code**;
- expiry.

ID and code have separate copy buttons. Hand them to the enrollment operator through
the approved secure channel and close the dialog after use. Do not put them in URLs,
logs, screenshots, tickets or evidence files. The browser does not save them in Web
Storage, and the Gateway does not allow them to be retrieved later.

## Resume and recovery

Each action rereads server-side state before mutating it. If a request is interrupted:

1. reload the same page;
2. check the displayed state, prerequisite and role;
3. repeat only the same indicated action.

A retry does not recreate an existing binding. The page rereads the authoritative
version and resubmits each canonical grant to the Admin API: an identical, already
enabled tuple with the same expiry is a no-op, not a second mutation or audit event.
A missing, different, `Draft`/`Retired` version or non-canonical operation is denied
before mutation. Do not wait for a window, log in again or restart from the beginning
unless the page reports a genuinely expired session. Endpoint or provider-resource
drift is denied: reload the authoritative catalog and submit a new configuration
through normal four-eyes approval.

## Final verification

The final banner proves that the version is `Published`; the selected Installation
must be `Active` and have an operation grant. Finish with one bounded invocation
through the supported Runtime API and check metadata-only audit. The page does not
turn the Admin UI into a proxy to arbitrary destinations.

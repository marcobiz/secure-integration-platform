# In-app Admin guide: ownership and integration

The canonical UI guide is bundled at `/admin/documentation`, inside the authenticated
layout. Its single English content resource is
[adminGuide.en.ts](../../src/Admin/Admin.Web/src/i18n/adminGuide.en.ts).
The English/Italian menu, contents and navigation labels remain in the existing i18n
resources. The guide is rendered as ordinary React text and MUI elements: no Markdown
engine, unsafe HTML, external document fetch, service or database is involved.

Use the in-app guide for the complete screen reference. Existing
[administration](administration.md) and [guided onboarding](guided-connector-onboarding.md)
documents remain concise deployment/workflow entry points, not copies of this guide.
The lifecycle and security descriptions were reconciled with those documents,
ADR-0012, ADR-0018 and the current UI/API implementation. Update the canonical resource
when a screen changes; do not create a translated or separate Markdown copy of it.

## Inventoried surface

Inventory base: `de743638a03dcb5b0166a6a7f82285e01f6377e6`, reconciled with the
Admin layout, date formatting and first-session fixes in this change.

| Source page/component | Guide anchors | Exposed controls and limits checked |
|---|---|---|
| LoginPage, SessionContext, AdminLayout, DirtyStateContext | session, roles | OIDC/Development login, expiry, logout, EN/IT, theme, mobile menu, skip link, transient forms, Stay/Discard |
| DashboardPage | dashboard | Totals, readiness, UTC update time, 30-second refresh and Retry |
| TenantsPage | tenants | Paged list, add/edit dialogs, immutable code, validation, disable, conflict read-back |
| ApplicationsPage | applications | Version range, add/edit/cancel, direct disable, full conflict comparison |
| InstallationsPage, ActivationHandoffDialog | installations, activation-handoff | Tenant/application/Environment selectors, Broker/Direct, create, public metadata, one-time ID/code copies, expiry, close, direct revoke; hidden reason is not documented as an editable field |
| GuidedOnboardingPage | onboarding | Paged target selections, shared Broker/Direct selector (Direct default), URL resume, selected Installation authority and immutable kind, file import, stored validation, catalog choices, complete binding/grants, request, approve/publish, bounded history and completion limit |
| ConnectorsPage | connectors | Filter, timeline pagination, canonical version diff, sample editor, validate/import Draft, stored validate, publish/rollback/retire, configuration-only test |
| BindingsPage | bindings | Advanced complete JSON form, resource catalog, version/Environment, save/history, validation/conflict/drift |
| GrantsPage | grants | Tenant/Installation/version selectors, operation entry, create/list; no expiry/revoke editor |
| ApprovalsPage | approvals | Target, comment, request/approve/reject, semantic review including authorization endpoints/certificates, canonical diff, paged history; separate publication |
| AccessPage | access | Issuer/subject identity, role/global or tenant scope, assign/revoke, session consequence |
| TenantDataPage (audit route) | audit | Tenant selector, pagination, action/target/outcome/reason, tenant-authorized safe failure diagnostics; no export or replay |
| HealthPage | health | Reused summary; no repair/provisioning control |

## Implementation boundaries

The guide reuses the existing authenticated shell:

- `src/app/App.tsx`: lazy DocumentationPage and `/documentation` route before the
  fallback, within SessionProvider/AdminLayout.
- `src/layouts/AdminLayout.tsx`: Documentation in Operations, available to every
  authenticated Admin role; it grants no additional API permissions.
- `src/i18n/en.ts` and `src/i18n/it.ts`: localized `documentation` / `guide*` labels.

All paths above are relative to `src/Admin/Admin.Web`. Keep content in the single
English resource and rendering in the dedicated component. Display instructions
describe English month names and explicit UTC timestamps; API timestamps remain
ISO 8601. Neither navigation nor documentation changes authorization.

## Focused verification contract

- `documentation.test.tsx` maps every current explicit page route to a guide section,
  checks unique anchors, and verifies searchable content and anchor targets.
- `GUIDE-01` checks menu entry and direct/reloaded fragment navigation for all five
  roles using mocked sessions.
- `GUIDE-02` checks the mobile drawer, keyboard fragment focus, no horizontal overflow,
  English/light and Italian/dark rendering, no serious/critical axe violations on the
  guide, and no document/data API requests from the guide.
- `GUIDE-03` verifies the existing unauthenticated session boundary.

These are frontend mock/render tests, not live enrollment, provider or external-service
qualification. Use a separate test port (for example `ADMIN_WEB_TEST_PORT=5187`) and
the existing Playwright configuration without restarting an operator's Compose
preview. Run lint, API parity, relevant Vitest tests, build, documentation validation,
secret scan and `git diff --check`; no dependency change or full-stack laboratory is
required for this bounded content/UI change.

GUIDE-03 verifies redirect to `/admin/login` and absence of guide content. First-entry
login rendering is covered separately by SessionContext and browser regressions;
the session query must settle after a 401 rather than being removed while pending.
Record execution results on the converged commit, not as permanent claims that
every future build or deployment has already passed.

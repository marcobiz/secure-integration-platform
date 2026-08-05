# M5 — Admin UI MVP: piano di implementazione

## Baseline e vincoli

Baseline immutabile: tag `m4-connector-configuration-baseline-20260805`, commit `49f81cb37dcd5bf8956638fe4af53c3c5cf39b2b`.

Branch: `m5/admin-ui-mvp`. M3B, cloud reale, Connector sanitari reali, adapter legacy commerciali e M6+ sono fuori scope. La PR M5 non sarà unita automaticamente.

## Incrementi verificabili

1. **Boundary OSS/provider**: astrazioni per capability, provider sintetico separato, Azure pack opzionale, solution filter Core, architecture test ed export allowlist.
2. **Schema amministrativo**: AdminPrincipal `(issuer, subject)`, ruoli tenant-scoped, bootstrap auditato, approval records checksum-specific, migrazione additiva e RLS.
3. **Autenticazione**: OIDC authorization-code server-side con PKCE/state/nonce, cookie sicuro, CSRF, logout e scadenza; fixture Development isolata e fail-closed in Production.
4. **Admin API v1**: DTO provider-neutral, RBAC, ProblemDetails, correlation ID, ETag/If-Match, paginazione, audit e four-eyes.
5. **Frontend**: React/TypeScript strict, routing, query cache, form/schema validation, editor JSON e diff, i18n IT/EN, temi e accessibilità.
6. **Pagine operative**: dashboard, tenant, application, installation/enrollment/revoca, Connector lifecycle, binding, grant, test controllato, audit e health.
7. **Packaging locale**: asset same-origin, container non-root, no sourcemap pubbliche, quickstart Compose provider-neutral e dati sintetici.
8. **Gate**: backend/frontend/E2E/a11y, PostgreSQL 18, scansioni, SBOM, clean-clone, open-source boundary, evidence redatta esterna e PR #5.

Ogni incremento termina con build/test pertinenti e commit tematico. Una failure viene corretta sul commit successivo con regressione automatica; non si riscrive la storia.

## Criteri fail-closed principali

- Production non parte con DevelopmentAuth, API key admin o OIDC incompleto.
- Mutazioni senza sessione, CSRF, ruolo o `If-Match` valido sono negate e auditate.
- Il requester/editor non approva il proprio checksum; modifica successiva invalida l'approvazione.
- Pubblicazione senza approvazione distinta è negata nella policy production predefinita.
- Tenant scope deriva dal principal e non da dati client non autorizzati.
- API/UI non restituiscono valori segreti, activation code dopo la risposta one-time o riferimenti provider arbitrari.
- UI non usa CDN, telemetry, `dangerouslySetInnerHTML`, `eval` o `new Function`.

## Strategia di test

- Unit test di policy e dominio per ogni ruolo, tenant scope, bootstrap e four-eyes.
- Integration test HTTP per cookie/OIDC/CSRF/security headers/ProblemDetails/ETag/paginazione/audit.
- Integration test PostgreSQL 18 per migrazione apply/no-op, RLS e concorrenza.
- Vitest/Testing Library per componenti, i18n, temi, validazione e gestione errori.
- Playwright per i 20 scenari richiesti e axe per WCAG 2.1 AA automatizzabile.
- Container/quickstart/clean-clone e regressione completa M0–M4.

## Evidenze

Le evidenze raw sono temporanee e ignorate. Il bundle redatto è scritto fuori repository in `C:\SecureEvidence\m5-gate-<timestamp>`, include commit, runtime/tool versions, job, hash immagini/SBOM/migrazioni, test nominativi, cleanup e manifest hashato.

## Decisioni non incluse

- Licenza finale: scelta proprietario ancora aperta tra Apache-2.0 e MPL-2.0.
- Provider OIDC di produzione specifico: deployment concern; il Core resta standard OIDC.
- Azure smoke M3B e pack sanitari reali: milestone successive e non bloccanti per l'implementazione M5, salvo la relativa readiness dichiarata.


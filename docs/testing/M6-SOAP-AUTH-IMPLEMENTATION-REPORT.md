# M6 SOAP/Basic/Session authentication primitives — implementation report

## Baseline e scope

- baseline frozen: `f34275096b4960bb5f31840553444935defc3d2d` (`origin/main` al 2026-08-07);
- branch: `m6/auth-soap-session`;
- implementato: AP-01 HTTP Basic server-side, AP-02 opaque interaction/session, AP-07 SOAP/XML boundary, login, cache, expiry, una reacquisition controllata, retry policy, logout/invalidation e Fault mapping;
- escluso: OAuth, inbound Gateway authentication, certificate/signing, connector healthcare production, generic WS-Security/SAML/XML-DSig e arbitrary SOAP scripting.

## Confine implementato

`Gateway.ConnectorRuntime.Auth.Soap` è un assembly Core separato. Dipende da
`Gateway.Application` esclusivamente per clock, DNS, restricted transport e policy
egress e da `Providers.Abstractions` per secret use. Non dipende da Infrastructure,
Gateway API, Broker, database, provider cloud o pack healthcare.

Il connector-facing profile è dichiarativo e bounded:

- operation ID, SOAP 1.1/1.2, action e request/response QName esatti;
- allowlist di campi logici con QName e limite caratteri;
- login/challenge/business/logout operations;
- session extraction e SOAP header placement esatti;
- fault code mapping e retry-after-reacquisition esplicito.

Non esiste un input caller per endpoint, Basic header, username/password, session ID,
SOAPAction, namespace policy, certificate o provider locator. L'endpoint HTTPS e le
revisioni derivano dal binding server-side.

## Basic e session lifecycle

`ServerBoundBasicAuthentication` recupera username e password soltanto immediatamente
prima del send, rifiuta header preesistenti e azzera il buffer UTF-8 temporaneo. Nessun
plaintext entra in cache, eccezioni o metadata.

Il lifecycle è:

```text
credential binding -> login -> opaque session ref -> business call
-> local/upstream expiry -> invalidate -> at most one reacquisition
-> business retry only when compiled operation policy permits -> logout/invalidate
```

La cache key comprende Tenant, Installation, Application, Connector/version,
Environment, endpoint revision, credential revision e auth/session profile. Reference
cross-context, expired, rotated, disabled o logged-out falliscono prima del transport.
La challenge completion usa uno state opaco, bounded, context-bound e one-time; il
modulo non assume Broker o UX.

## SOAP/XML boundary

- deterministic UTF-8 serialization senza XML declaration o indentation;
- SOAP 1.1 `text/xml` più header `SOAPAction` quoted;
- SOAP 1.2 `application/soap+xml` con action parameter e senza header SOAPAction;
- HTTPS restricted transport, DNS/IP pinning, no redirect/proxy/cookie, timeout e cancellation;
- response e request bounded;
- `DtdProcessing.Prohibit`, resolver nullo, entity/document limits;
- limiti espliciti di depth, node count, attributes per element e total attributes;
- Envelope/Body/response/fault QName esatti, elementi duplicati/inaspettati negati;
- Fault detail mai propagato: soltanto categoria tipizzata sanitizzata.

## Synthetic SOAP server

`tools/m6/SyntheticSoapServer` avvia Kestrel su una porta loopback HTTPS dinamica con
certificati sintetici per-run. Implementa Login, optional challenge completion,
BusinessOperation, Logout, session expiry/invalid session, typed Fault, malformed XML,
oversize e timeout, con contatori login/challenge/business/logout. Il client di test usa
trust root e certificate pinning; non disabilita TLS validation.

## Evidenza locale mirata

| Suite | Casi | Esito |
|---|---:|---|
| `SoapAuthenticationTests` | 8 | PASS |
| `SoapRealHttpIntegrationTests` | 4 | PASS |
| `SoapAuthBoundaryTests` | 2 | PASS |
| Totale mirato iniziale | 14 | PASS |

I test coprono Basic/session redaction, stale/fixation, rotate/disable, DTD/XXE/external
entity, oversize, malformed XML, namespace confusion, SOAPAction/Content-Type mismatch,
timeout/cancellation, binding manipulation, SSRF, SOAP 1.1/1.2, challenge, logout e
Fault. I totali completi e l'esito CI vengono aggiornati sul commit finale candidato.

## Review

GO per review del writer sintetico AP-01/AP-02/AP-07. NO-GO per connector SOGEI o altro
healthcare production finché WSDL/schema, auth profile, lifecycle, fault taxonomy,
environment e MFA semantics non sono caratterizzati e approvati separatamente.

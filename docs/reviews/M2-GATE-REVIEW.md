# M2 Gateway baseline — Gate Review conclusiva

**Data:** 2026-08-04

**Esito:** M2 **Done**; nessuna attività M3 avviata.

## Baseline ed evidenze CI

Il commit candidato di codice e gate è `b6e1e46aebbd005d1bacf20943b358f6ccb6ea1a`.
La run GitHub Actions `30896803567` ha eseguito tutti i job sul medesimo SHA tramite
checkout esplicito. Il commit documentale conclusivo è un discendente docs-only e deve
replicare lo stesso gate prima dell'applicazione del tag annotato.

| Job | Esito | Evidenza |
|---|---|---|
| `build-test (windows-latest)` | PASS | Release, 77 test, document validation, secret scan, vulnerability scan e SBOM |
| `gateway-postgresql-18` | PASS | PostgreSQL 18 reale, migration apply/no-op, checksum, ruoli, FORCE RLS, tenant isolation e cleanup |
| `gateway-container` | PASS | build/esecuzione, non-root, read-only, live/ready, fail-closed, Trivy secret scan, SBOM e shutdown |
| `gitleaks` | PASS | storia della PR; un falso positivo storico è escluso soltanto tramite fingerprint esatto |

Evidenze container del commit candidato:

- Gateway image content digest: `sha256:613507c2cc914cbe41fa0164cce6893d1fa92489bfcf4a473395d8d435c574d9`;
- migration image content digest: `sha256:d05ec2be0334a0105f31dae11c3df185f6f5bc962ca13f41cce240445bae6830`;
- migration SQL SHA-256: `182CC690E16BB986638A4B52EE1554A4B540A8E58FD673F2111A79D194C66A98`;
- image SBOM artifact SHA-256: `38ad96f4bc04fb9a515980277451d4a2b6deb484fdcfab283a7e72c2125960be`.

Il tag annotato contiene i digest prodotti dalla replica CI sul commit finale, che è
l'evidenza normativa se differisce dai valori del candidato sopra per la label revision.

## Review delle aree critiche

| Area | Esito e prova |
|---|---|
| Tenant autenticato | PASS. `RuntimeIdentityService` risolve il digest SHA-256 del certificato registrato e restituisce Tenant/Application/Installation server-side. |
| `tenantId` client-side | PASS. `GatewayInvokeRequest` non espone Tenant, URL o secret reference; il test `UT_GTW_Invoke_contract_has_no_client_controlled_endpoint_or_secret_reference` blocca regressioni. |
| PostgreSQL e RLS | PASS. Composite FK, `ENABLE/FORCE ROW LEVEL SECURITY`, contesto tenant transazionale e locator stretti; test cross-Tenant locale e CI PostgreSQL 18. |
| Activation/enrollment | PASS. Activation code casuale a 256 bit conservato come HMAC, 24 ore, massimo cinque tentativi e consumo monouso. |
| PoP | PASS. Challenge a scadenza e firma ECDSA P-256 in formato deterministico verificata prima dell'attivazione. |
| Replay | PASS. Timestamp UTC limitato, nonce da 16 byte e digest persistito con TTL; il riuso è negato. |
| Renewal/overlap | PASS. Renewal negli ultimi 30 giorni e overlap massimo sette giorni; scadenza della credenziale precedente testata. |
| Revoca | PASS. Stato Installation/credential controllato prima di grant, Vault, DNS e trasporto; revoca immediata testata. |
| Grant | PASS. Catalogo server-side immutabile e deny-by-default; il diniego avviene prima di ogni side effect. |
| URI/DNS/IP | PASS. Solo HTTPS, risoluzione filtrata, loopback/private/link-local/multicast/ULA negate e IP validato passato al trasporto. |
| SSRF/DNS rebinding | PASS. `ConnectCallback` apre il socket sull'indirizzo già validato, impedendo una seconda risoluzione non controllata. |
| Redirect/header | PASS. Redirect, proxy, cookie e decompressione implicita sono disabilitati; nome header API key e metodo sono catalogo server-side. |
| Basic/API key/mTLS | PASS. I valori sono letti dal provider server-side solo dopo identity e grant e applicati esclusivamente alla richiesta outbound. |
| URL/secret arbitrari | PASS. Il client seleziona soltanto Connector/operation; endpoint e riferimenti Vault non appartengono al contratto invoke. |
| Key Vault boundary | PASS per il codice. Azure SDK e Managed Identity appartengono al Gateway; il Broker dipende soltanto da `IGatewayInvoker`. La prova live Azure resta debito ambientale. |
| Redazione | PASS. Audit solo metadata, Problem Details sanitizzati, canary log negativo, source scan, Gitleaks e secret scan immagine verdi. |
| Assenza GetSecret | PASS. Nessuna route o contratto pubblico restituisce secret; `GetSecretAsync` è un'astrazione infrastrutturale interna usata soltanto per comporre l'egress. |

## Criteri M2

- FR-001, FR-002, FR-007 e la porzione M2 di FR-016: soddisfatti.
- NFR-001, NFR-002, NFR-003, NFR-005, NFR-006 e NFR-010: soddisfatti nel perimetro M2.
- AC-007, AC-009, AC-010, AC-011, AC-012 e AC-018: PASS.
- AC-013: revoca immediata M2 PASS; la propagazione Broker→Gateway production-like resta intenzionalmente nel gate M3.
- AC-027: SBOM repository e SBOM dell'immagine PASS.

## Run fallite conservate e correzioni

| Run | Causa | Correzione regressiva |
|---|---|---|
| `30895783874` | action Trivy non risolvibile, token Gitleaks assente, `rg` implicito sul runner Windows | tag action corretto, token/permessi espliciti, fallback Git PCRE provato in PowerShell pulito |
| `30896092242` | permesso PR Gitleaks e quoting Docker label | `pull-requests: read` e lookup label con `jq` |
| `30896294941` | falso positivo Gitleaks esatto e installer Trivy obsoleto | rename della fixture, fingerprint storico puntuale e Trivy ufficiale aggiornato |
| `30896531326` | tutti i job PASS, ma artefatti marcati con merge SHA sintetico | checkout e label vincolati all'HEAD reale della PR |

Non sono stati usati squash, rebase, amend o force push. Nessuna ADR è stata modificata:
la review non ha rilevato deviazioni architetturali.

## Rischi residui non bloccanti

- Key Vault/Managed Identity non è stato provato live senza una subscription autorizzata;
- challenge store ancora single-node/in-memory secondo ADR-0008;
- deduplicazione idempotency operativa completa rinviata a M4;
- Gateway HTTP v1 e IPC v1 restano provvisori fino alla validazione M3;
- Local Administrator e identità cloud privilegiate restano nel rischio residuo operativo.

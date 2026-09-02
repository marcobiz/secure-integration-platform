# Security model

## Obiettivi di protezione

1. Impedire estrazione e distribuzione di Vendor Secret.
2. Limitare una compromissione locale alla singola Installation e alle capability
   autorizzate.
3. Impedire uso del Local Broker da Application non autorizzate.
4. Impedire impersonazione cross-Tenant/cross-Installation.
5. Impedire al client di trasformare il Gateway in proxy, signer o secret oracle.
6. Proteggere dati/chiavi locali contro copia offline e processi non privilegiati.
7. Fornire revoca, rotazione, audit metadata-only e provenance verificabile.

## Authority e identità

Broker e Direct client usano ClientAuth mTLS, BGW1, timestamp e nonce. Il Gateway
risolve la credential nel registry e deriva Installation, Application, Tenant,
Environment e caller kind dallo stato autenticato. Campi client con la stessa semantica
non sono autorità.

Il grant Connector/operation è server-side e deny-by-default. La Published authority
stabilisce execution strategy, endpoint, metodo/path/body mode, binding e profilo auth.
Una reread può confermare la stessa authority A ma non adottare B durante l'invocazione.

## Provider capability boundary

I provider espongono capability separate:

- `ISecretValueProvider` per uso server-side bounded;
- `IClientCertificateProvider` per attachment mTLS one-shot;
- metadata e materiale certificato pubblico;
- `IKeyOperationProvider`/signing senza export della private key;
- `IMacProvider`;
- health e capability discovery.

Non esiste una generica `IKms`, né un `GetSecret` client/Broker/UI. Il runtime non
restituisce PFX, private key, locator o authenticated request handle. Endpoint e locator
sono risolti server-side dalla configurazione Published e dal catalogo provider.
Capability assenti non sono inferite, combinate o emulate.

Il pack local PKCS#12 dichiara `SecretValues=false`. Il suo slot
`ISecretValueProvider` è deny-only, non risolve path e non accede al filesystem. A1 e S1
sono risorse distinte; certificate use, public material e signing restano capability
separate. La repository qualifica il pack con solo materiale sintetico per-run. Il pack
non sostituisce HSM/KMS, custody, rotation/revocation, import operativo o qualifica live.

## Local Broker

- Virtual service account e service SID dedicati.
- ACL restrittive su pipe, `ProgramData` e CNG key.
- Identità Application composita: SID, registration, path, publisher/hash e process
  handle/creation time.
- Frame/payload limits, timeout, cancellation, nonce e sequence.
- Autorizzazione per operation e Connector/operation.
- Storage/delete di secret locali ammessi, protect/unprotect AES-GCM e HMAC bounded.
- Nessuna operation IPC di lettura/reveal secret o firma generica.
- Audit locale redatto e health senza valori sensibili.

La chiave Installation Broker è ECDSA P-256 CNG non esportabile e appartiene alla
service identity. Repair/upgrade/recovery completi restano target installer, non claim
dello script di laboratorio.

## Gateway e Connector Runtime

- Credential/status/revoca verificati fail-closed e nonce consumato atomicamente.
- Tenant/Application/Installation derivati dal registry.
- Grant e sola ConnectorVersion Published.
- Checksum/four-eyes e binding digest verificati nella pubblicazione.
- Stamp Published/binding/resource ricontrollato per invocazione; no stale-on-error.
- Secret/certificate/key binding logici risolti server-side.
- Provider e moduli opzionali dipendono dal Core provider-neutral, mai il contrario.
- Il Gateway image predefinito usa il Synthetic Provider e non contiene pack verticali.

I moduli di execution ricevono una authority bounded e capability invocation-bound, non
provider/store/service locator/endpoint/credential generici. Restano però codice
full-trust in-process: il boundary limita la superficie supportata, non è una sandbox.

## Egress, TLS e SSRF

- HTTPS obbligatorio sui percorsi centrali supportati.
- Scheme/host/port e path template provengono dalla Published authority.
- DNS/IP validation blocca literal, loopback, private, link-local, multicast e metadata,
  salvo allowance test exact-host/CIDR in ambienti dedicati.
- Il socket usa gli indirizzi validati; il runtime ricontrolla authority e binding dopo
  gli await pertinenti e prima del dispatch.
- Redirect, proxy ambientale, cookie e header hop-by-hop sono negati.
- Method, Content-Type, auth header, certificate, timeout e response bound sono
  server-owned.
- Retry solo per operation dichiarate idempotenti; nessun fallback stale.

Le CA sintetiche e i mock HTTPS/mTLS provano la pipeline locale. Non attestano trust,
revocation, availability o conformance di un servizio esterno reale.

## Admin plane e browser

- OIDC Authorization Code server-side con PKCE, state e nonce.
- Browser con cookie `__Host-`, HttpOnly, Secure, SameSite e sessione server-side.
- CSRF su mutazioni, CSP/frame policy, niente CORS permissivo.
- Principal stabile `(issuer, subject)` e ruoli server-side; email non è authority.
- Tenant scope, RBAC, optimistic concurrency e four-eyes checksum-specific.
- UI same-origin senza accesso a PostgreSQL, provider, Broker o filesystem.
- Nessun secret value, private key, activation code riutilizzabile o provider locator
  nel browser.

DevelopmentAuth è test-only, loopback e rifiutata in Production.

## PostgreSQL, RLS e audit

PostgreSQL conserva metadata, JSON canonico, checksum, public certificate material e
locator server-side; non conserva secret value. Composite FK e FORCE RLS difendono lo
scope tenant. Migration, runtime, admin, readonly e locator-owner sono identità distinte;
le funzioni locator `SECURITY DEFINER` hanno owner NOLOGIN e predicati operation-scoped.

Audit e invocation event sono metadata-only: nessun body, Authorization/Cookie, token,
password, private key o response raw. Il codice e `gateway_runtime` emettono solo INSERT.
La migration additiva 0017 corregge la grant ampia della 0001: revoca UPDATE/DELETE/
TRUNCATE su `audit_event` e tutti i privilegi Admin non richiesti su `invocation_event`.
Di conseguenza:

- metadata-only audit è **CURRENT** e testato;
- runtime/admin applicativi sono **CURRENT** append-only;
- `gateway_admin` conserva solo SELECT/INSERT su `audit_event`; il read-back
  SecurityAdministrator e gli insert Admin restano invariati;
- `gateway_runtime` conserva INSERT su entrambe le tabelle e nessuna SELECT implicita;
- `gateway_readonly` non riceve privilegi evento nuovi;
- owner/migration e DBA/host privilegiati restano nella TCB.

Questo controllo è la matrice dei privilegi PostgreSQL, non un trigger di immutabilità.
Non introduce firma o notarizzazione e non costituisce protezione assoluta contro un DBA.

Partizionamento, retention job, backup/PITR e restore non sono implementati/qualificati
dalla sola presenza delle tabelle.

## Parsing, bounds e redaction

- DTD, external entity e resolver XML sono disabilitati.
- Limiti per byte, depth, node, attribute e scalar input.
- QName/cardinalità, namespace e Fault structure verificati nei moduli implementati.
- JSON Schema 2020-12, additional-property denial nei contratti chiusi e checksum
  canonico.
- Exception provider/modulo sanitizzate in codici stabili; cancellation reale preservata.
- Redaction strutturale prima della serializzazione, con canary/secret scan come difesa
  aggiuntiva.

Campi vietati in log/audit/evidence redatta includono payload, Authorization/Cookie,
token, password/PIN/OTP, private key/PFX, activation code e PII non necessaria.

## Supply chain corrente e target

**CURRENT:** lock file/toolchain/base image pinned, validator fail-closed dei Dockerfile,
secret/dependency/container checks, SBOM SPDX, Core export e architecture boundary tests.
Il loader moduli verifica path locale exact, assembly identity/type/module ID e MVID sugli
stessi byte; ACL/provenance restano responsabilità del deployment.

**TARGET:** Authenticode/CMS/Cosign, publisher allowlist/hash manifest per moduli,
release publishing, provenance firmata e CycloneDX. Non sono garanzie della baseline.

Il manifest SHA grezzo dell'export contiene metadata run-specific e non è un digest
deterministico cross-run. La normalizzazione è il lavoro futuro
`P3-CORE-EXPORT-DIGEST` sotto `ALPHA-ART`.

## Evidenza e claim boundary

- test synthetic-qualified non significa OfficialTest;
- live lab con processi/container reali e fixture sintetiche non significa chiamata FSE2
  live;
- OfficialTest non significa production/accreditamento;
- certificati ricevuti e correlati non significano import operativo;
- `validate-cda` è il primo outcome OfficialTest futuro; nessuna call live è attestata.

## Rischi dichiarati

- Local Administrator e SYSTEM possono sostituire binari, leggere memoria o abusare di
  un processo autorizzato.
- Plaintext e key handle necessari esistono temporaneamente nella TCB.
- Un modulo in-process malevolo può causare compromissione/DoS nonostante il contratto
  ristretto.
- Compromissione Gateway/provider richiede incident response e rotazione esterna.
- Il sample Direct non qualifica una custody key production.
- Cache/sessioni process-local non abilitano scale-out o durability implicita.
- La piattaforma limita le capability del legacy compromesso ma non ne garantisce
  l'integrità.

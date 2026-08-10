# Threat model STRIDE

## Asset

- Vendor, Tenant, Operator e Session Secret.
- Local Data Key e dati locali cifrati.
- Installation identity e grants.
- ConnectorVersion e deployment attivi.
- Admin identities e audit trail.
- Payload applicativi in transito.
- Artefatti di release e plugin.
- Chiavi di firma provider-side, certificati client outbound e JWT compatti in memoria.
- Materiale X.509 pubblico e catene `x5c`, la cui integrita deve restare legata alla
  stessa identita di firma approvata.
- Valori runtime security trusted, validi soltanto per la invocation e policy Published
  che ne ha autorizzato la source tipizzata.

## Attori e livelli di fiducia

- Operator legittimo.
- Application legacy autorizzata, considerata potenzialmente vulnerabile.
- Processo locale non autorizzato/malware same-user.
- Amministratore locale/SYSTEM.
- Local Broker e Gateway trusted computing base.
- Amministratore della piattaforma con ruolo limitato.
- Insider privilegiato/collusivo.
- Servizio esterno e rete non fidati.
- Pipeline e publisher degli artefatti.

## Matrice delle minacce

| ID | Categoria | Scenario | Controlli | Stato/residuo |
|---|---|---|---|---|
| TM-001 | S/E | Legacy compromesso invoca operation lecite per scopo malevolo. | Operation grants, payload constraints, rate limit, audit. | Parziale: può abusare delle capability legittime. |
| TM-002 | S/E | Malware same-user apre la pipe. | Pipe ACL, PID, handle, path, publisher/hash, manifest. | Parziale: injection nell'app autorizzata resta possibile. |
| TM-003 | S | Nome processo o registration ID falsificati. | Identità composita e manifest service-only. | Mitigato contro processi non privilegiati. |
| TM-004 | I/D | Copia di DB/blob locali. | ACL, DPAPI CurrentUser, AES-GCM per Installation. | Mitigato; perdita profilo impatta recovery. |
| TM-005 | T/E | Sostituzione Broker o DLL. | Program Files ACL, Authenticode, installer firmato. | Admin/SYSTEM fuori scope forte. |
| TM-006 | S | Clonazione della Installation. | CNG non esportabile, PoP, registry e reinstall enrollment. | Mitigato salvo clone completo con privilegi elevati. |
| TM-007 | S/R | Replay di richiesta Gateway. | Timestamp, nonce, body hash, ECDSA signature, idempotency. | Mitigato entro limiti di cache/clock. |
| TM-008 | S/E | Client dichiara altro Tenant/Installation. | Identità derivata dal certificato; campi ignorati/rifiutati. | Mitigato. |
| TM-009 | I/E | Query cross-Tenant per bug. | Composite FK, RLS, query filters, negative tests. | Mitigato con defense in depth. |
| TM-010 | I | Furto database Gateway. | Nessun secret value, encryption at rest, DB roles. | Metadata/audit restano sensibili. |
| TM-011 | I/E | Gateway compromesso usa Vault. | Managed Identity least privilege, secret scope, alert e rotation. | Parziale: TCB compromessa. |
| TM-012 | I/E | Vault compromesso. | RBAC, versioning, network restriction, audit e revocation. | Rischio residuo esterno alla piattaforma. |
| TM-013 | E/I | SSRF verso rete privata/metadata. | Config server-side, DNS/IP validation, no redirect, restricted client. | Mitigato; eccezioni private richiedono review. |
| TM-014 | T | Header/path injection. | Typed builder, encoding, allowlist e limits. | Mitigato. |
| TM-015 | T/I | XXE, entity expansion o signature wrapping. | Parser sicuro, limits, schema, ID uniqueness e tests. | Mitigato per moduli implementati. |
| TM-016 | E | Plugin malevolo. | Pipeline-only, CMS signature, publisher allowlist, review. | Parziale: plugin in-process è full-trust. |
| TM-017 | T/E | Update o MSI manomesso/rollback. | Signature, manifest, anti-rollback e secure updater. | MVP manuale; completo in hardening. |
| TM-018 | I/R | Secret o PII nei log. | Structured redaction, prohibited-field tests e scanning. | Mitigato; nuove integrazioni richiedono test. |
| TM-019 | E | Insider pubblica endpoint o binding malevolo. | RBAC, four-eyes, security validation e audit append-only. | Collusione privilegiata resta residua. |
| TM-020 | D | Flood IPC o Gateway. | Concurrency, size/time/rate limits e circuit breaker. | DDoS volumetrico richiede protezione infrastrutturale. |
| TM-021 | R | Operator nega un'operazione. | Correlation e audit metadata. | Non equivale a firma legale dell'Operator. |
| TM-022 | I | Backup rubato. | Stesse protezioni del dato, Vault escluso dal DB, backup encryption. | Metadata exposure residua. |
| TM-023 | T/E | Versione Draft/Retired o cache stale invocata dopo revoca. | Published-only catalog, stamp store a ogni invoke, TTL, invalidazione e no stale-on-error. | PostgreSQL indisponibile causa fail-closed/disponibilità ridotta. |
| TM-024 | T/R | Publish concorrenti o modifica di una versione già Published. | Row version, publication revision, unique Published e trigger DB di immutabilità. | Un amministratore DB privilegiato resta parte della TCB. |
| TM-025 | I/E | Connector/export/client seleziona URI o provider reference arbitrari. | Definition solo logica, binding server-side, export senza binding, runtime request chiusa. | Un amministratore binding autorizzato può configurare destinazioni approvate errate. |
| TM-026 | S/I | Furto o fixation della sessione Admin. | Cookie `__Host-`, HttpOnly/Secure/SameSite, session expiry/sliding, state/nonce/PKCE e logout server-side. | Browser o account amministrativo compromesso restano rischio residuo. |
| TM-027 | T/E | CSRF induce una mutazione amministrativa. | Antiforgery cookie/header same-origin su tutte le mutazioni e niente CORS permissivo. | Mitigato salvo compromissione same-origin/XSS. |
| TM-028 | T/I | XSS o stored XSS in nomi/commenti/JSON. | React escaping, niente raw HTML/markdown, CSP nonce/self, no `eval`, output DTO. | Parziale: dipendenze frontend richiedono patching continuo. |
| TM-029 | E | Clickjacking dell'Admin UI. | CSP `frame-ancestors 'none'` e frame policy. | Mitigato nei browser conformi. |
| TM-030 | S/E | OIDC misconfiguration/open redirect/claim spoofing. | Authority/client/callback espliciti, issuer/audience/signature/lifetime/state/nonce validation, local return path. | Configurazione del provider e recovery account sono deployment risk. |
| TM-031 | E | Ruolo inviato dal frontend o email usata per escalation. | Autorizzazione server-side da `(issuer, subject)` e assignment persistito; UI è solo presentation. | Amministratore ruoli compromesso può abusare dei privilegi. |
| TM-032 | E/R | Bypass four-eyes o self-approval. | Approval separata checksum-specific; creator/editor/requester distinti; publish ricontrolla in application service. | Collusione fra due account privilegiati non è eliminata. |
| TM-033 | E/I | Tenant scope bypass tramite query/body. | Scope verificato server-side su ogni risorsa; test cross-tenant; RLS defense in depth. | Nuove API richiedono la stessa review. |
| TM-034 | I | Export/audit/UI espongono secret, cookie o activation code. | DTO allowlist, activation one-time/no-store, audit metadata-only, canary/secret scans. | Compromissione memoria del Gateway/browser resta fuori dalla garanzia. |
| TM-035 | T/R | Audit alterato o operazione non auditata. | Audit append-only applicativo/DB e correlation ID per mutazioni. | DBA/host privilegiato è parte della TCB; firma notarile fuori scope. |
| TM-036 | T/D | Connector JSON malevolo o oversized. | Limiti body, JSON Schema 2020-12, canonicalization, no executable content, stable errors. | Parser/runtime dependencies devono restare aggiornati. |
| TM-037 | E | Operator usa il test connector come proxy arbitrario. | API accetta solo connector/environment/operation id e risolve Published binding server-side. | Un binding amministrativo già compromesso resta utilizzabile. |
| TM-038 | E | Autorizzazione stale dopo revoca ruolo. | Assignment riletto server-side per richiesta e sessione breve. | Finestra di cookie/OIDC provider e cache future da rivalutare. |
| TM-039 | S/E | DevelopmentAuth raggiunge produzione. | Abilitazione esplicita, identità fisse, host locale e startup failure in Production. | Errore di classificazione ambiente non-Production richiede controllo deployment. |

| TM-040 | E/I | Un editor combina endpoint controllato e secret/certificate reference per esfiltrare credenziali. | Revisioni binding immutabili per ConnectorVersion/Environment; scope logici esatti; digest combinato Connector+endpoint+secret+certificate; approvatore distinto; runtime solo su revisioni attive incluse nel digest Published. | Due amministratori collusi o un host/DBA privilegiato restano nella TCB. |
| TM-041 | S/E | Un peer remoto falsifica Host o forwarded headers per usare DevelopmentAuth. | RemoteIpAddress deve essere loopback, il listener Compose e fissato a 127.0.0.1 e i forwarded headers sono elaborati solo da proxy allowlistati. | Una classificazione errata dell'ambiente Development resta deployment risk. |
| TM-042 | T/R | Approval viene invalidata fra controllo e publish. | ConnectorVersion, binding revisions e approval sono bloccati e verificati con publish, supersede e audit nella stessa transazione PostgreSQL serializable. | Contention concorrente viene negata con conflitto stabile e richiede retry esplicito. |
| TM-043 | I/E | Un valore segreto, PEM/PFX o connection string viene inserito come reference opaca e riflesso nell'artefatto di approval. | Request strutturata, identificatori logici bounded, risoluzione obbligatoria nel catalogo server-owned, metadata/locator separati, metadata certificato pubblico e nessun fallback da input a ResourceId; approval e publish rileggono revisioni correnti sotto lock transazionale. | Un amministratore catalogo e un approvatore collusi, oppure host/DBA privilegiati, restano nella TCB. |
| TM-044 | S/E | Furto della chiave privata di una Direct Installation o uso da un client non autorizzato. | Chiave generata lato client, ClientAuth mTLS, PoP ECDSA P-256, binding certificato/SPKI, BGW1, nonce/timestamp, grant minimo, rotation e revoca immediata. | L'endpoint client e il suo key store sono nella TCB; una chiave valida rubata opera fino a detection/revoca. |
| TM-045 | S/T/E | Un Direct client tenta di falsificare Tenant/Application o selezionare destinazione, provider o credential binding. | `GatewayClientPrincipal` derivato dal registry; request runtime chiusa; publication/binding server-owned; grant deny-by-default; stesso restricted egress del Broker. | Un amministratore autorizzato puo ancora configurare un binding errato; host/DBA privilegiati restano nella TCB. |
| TM-046 | S/T/I | OAuth outbound subisce authority/profile substitution, state fixation, code replay, callback cross-context o token vending verso il caller. | Il consumer seleziona solo un logical profile ID; resolver su principal autenticato + Published snapshot produce una capability non costruibile esternamente e secret-use scoped. State casuale conservato solo come hash, attempt breve/one-time e correlation verificata su begin/poll/completion; token-session reference opaca. | Il processo Gateway e la composition root che possiede store/provider restano nella TCB; l'external-user-agent presentation adapter deve navigare solo l'URL approvato. |
| TM-047 | I/E/D | Token/resource endpoint, refresh o cache vengono usati per SSRF, redirect, bearer exfiltration, scope escalation, stale token dopo rotation/disable o leakage diagnostico. | Endpoint/scopes/audience derivati dallo snapshot; tutte le authority destinations entrano nel digest four-eyes; query OAuth riservata non duplicabile, DNS/IP policy e `IRestrictedTransport`, nessun attach API, dispatch endpoint-bound, cache stamp completo, generation tombstone per security key/Connector + revalidation dopo await, refresh single-flight/no stale fallback, tipi sensibili non-record con JSON/ToString redatti. | Cache in-process perde le sessioni al restart; scale-out e revocation endpoint richiedono una decisione futura, non Redis implicito. |
| TM-048 | S/I/T/D | Fixation, furto, replay, crescita illimitata o riuso stale di una sessione/interaction SOAP upstream. | Reference casuali opache; raw session interna; una interaction e una generation corrente per security key; completion atomica; cap globale 256 ed eviction lazy; digest precedente negato; stamp server-side `Active` e revisioni binding/endpoint/credential verificati prima dell'uso; logout/invalidation. | Una compromissione della memoria del Gateway resta nella TCB; la cache M6 è in-process e non abilita scale-out. |
| TM-049 | T/I/D | SOAP/XML malevolo usa DTD, external entity, namespace/Fault confusion, body stalled o risposta oversized per esfiltrare, provocare re-login o degradare il Gateway. | SOAP 1.1/1.2 e action compilate; DTD/entity/resolver disabilitati; QName/cardinalità Fault esatti; ambiguità negata; size/depth/node/attribute limits; deadline su header/body/parsing; Fault sanitizzati e restricted egress. | Schemi healthcare reali non sono ancora caratterizzati; nessun connector production è autorizzato. |
| TM-050 | T/E | Algorithm confusion (`none`, HS/RS), policy substitution, key substitution o claim privilegiati trasformano una firma JWT in un signing oracle. | RS256 hard-coded; il Connector passa solo policy ID e business claim; policy server-owned con revision/checksum ricalcolato e identity esatta nel resource binding; allowlist/reserved denial; fingerprint e digest SPKI approvati; la stessa SPKI verifica la firma. | Il provider e il Gateway restano nella TCB; un profilo ufficiale errato richiede nuova characterization e approval. |
| TM-051 | S/T/E | Un certificato di firma viene sostituito al certificato mTLS, oppure una revisione ruotata/disabilitata o un handle trattenuto viene usato verso altro endpoint. | Sender mTLS one-shot senza handle pubblico; purpose e binding esatti; DER fingerprint e SPKI digest; policy/binding/status/revision/endpoint rivalidati subito prima di DNS/dispatch; zero stale-on-error. | Revocation online della CA non è introdotta dal profilo sintetico; la policy autoritativa resta da caratterizzare. |
| TM-052 | I/E | La primitive esporta una private key/PFX o esegue un fallback automatico al Broker quando manca custody centrale. | `IKeyOperationProvider` espone solo metadata pubblici e `SignDigestAsync`; il certificato mTLS resta interno alla singola chiamata transport-bound ed è disposed dopo dispatch; failure capability esplicito e nessun fallback/local handoff. | Gateway/provider host privilegiati possono osservare o usare handle in memoria; Administrator/SYSTEM resta rischio residuo dichiarato. |
| TM-053 | I/R | JWT, claim, locator, certificate bytes o dettagli provider compaiono in errori/log/evidence. | Qualunque exception provider non-cancellation a metadata/sign/certificate diventa un codice stabile senza message/inner; cancellazione reale preservata; test canary e secret scan; materiale TLS per-run non persistito. | Dump di processo privilegiato e tracing aggiunto in futuro richiedono nuova review/redaction test. |
| TM-054 | S/T/I | Authorization Code viene degradato a PKCE plain/assente, oppure il verifier viene esposto, sostituito, separato da state/correlation, riusato o trattenuto dopo expiry. | La policy Published ammette solo `NONE` o `S256_REQUIRED`; verifier CSPRNG RFC-valid, attempt-bound, S256-only, interno, one-time e azzerato su ogni terminal path; state hash confrontato fixed-time. | La memoria del processo Gateway resta nella TCB; `NONE` resta solo per profili backward-compatible esplicitamente Published. |
| TM-055 | S/T/I/E/D | Client Credentials usa endpoint/secret/scope/audience/resource scelti dal caller, cache identity stale, redirect/SSRF, acquisizione duplicata, invalidazione cross-tenant o diagnostica contenente credenziali. | Context Published non costruibile dal consumer e secret capability scoped; `client_secret_basic` allowlisted; cache key grant/profile/revision completa; initial single-flight e invalidation generation per security key, expiry gate per session; revalidation dopo await; restricted transport; nessun secret in URI; raw response zeroing anche su revalidation stale e redaction test. | La cache in-process non abilita scale-out; provider e processo Gateway restano nella TCB. |
| TM-056 | S/T/I/E | Una sessione opaque viene proiettata con autorità caller-forgeable, in un header di tracing/forwarding o con CR/LF, verso altra operation/destinazione, oppure stale nella finestra finale dopo disable/rotate. | Handoff e resolved context senza costruttori pubblici; resolver concreto da principal autenticato + Published ConnectorVersion/operation/`OperationBindingDependencies`/binding/resource correnti; facade generica nel modulo HTTP; field-name token senza trim con denylist security/hop-by-hop/tracing/`X-Forwarded-*`; nessun header bag/attach API; cache SOAP M6 multi-operation invariata; HTTP identity separata; body/request preparati prima della revalidation finale; lease generation/expiry e Published authority verificati adiacenti al dispatch one-shot `IRestrictedTransport`; race deterministici e real HTTPS rotate/disable con zero network. | La memoria, lo store e la composition root del Gateway restano nella TCB; una revoca che avviene dopo l'inizio effettivo del network dispatch non può ritirare byte già trasmessi. |
| TM-057 | S/T/E | Un provider o una revisione stale sostituisce leaf/chain `x5c`, SPKI o chiave dopo l'approvazione, producendo un JWT che dichiara un'identita pubblica diversa da quella che firma. | Capability pubblica separata e risolta dalla stessa binding `JwtSigning`; limiti leaf/entry/count/total verificati prima delle copie; snapshot copy-on-read; parsing DER; fingerprint e digest SPKI confrontati constant-time con catalogo e signing metadata; stessa SPKI DER verifica la firma; chain bounded e ordinata; policy/catalog/resource rivalidati prima della firma e prima del ritorno. | Provider e Gateway restano nella TCB; trust/revocation del destinatario e qualificazione della CA sono responsabilita del profilo/connector autorizzato. |
| TM-058 | T/E | Header JWS, temporal claim o trusted identity source scelti dal caller trasformano la primitive in un signing oracle o permettono sostituzione di subject/claim privilegiati. | Header writer tipizzato senza mappe; `alg=RS256` e `typ=JWT` fissi; `x5c` solo da policy; due soli temporal mode validi; source built-in autenticate o runtime source chiuse selezionate dalla Published policy; business allowlist separata e reserved-field denial. | Una policy Published errata richiede review/approval e nuova caratterizzazione; non esiste un expression engine Core. |
| TM-059 | S/T/E | Business input viene promosso a `sub`, un resolver/source viene sostituito, oppure un valore trusted di una invocation/revisione viene riusato in un'altra. | Il signing caller non passa subject o trusted value; request del resolver non costruibile dal consumer; source enum policy-owned; resolver registrato server-side; provenance chiusa; exact binding a Tenant/Application/Installation/ConnectorVersion/operation/profile/correlation e revisioni policy/catalog/resource; mismatch negato prima del provider. | Resolver registrato, policy publisher e Gateway restano nella TCB; la validazione domain-specific di una futura source appartiene al pack autorizzato. |
| TM-060 | T | Array DER/metadata o binding trusted mutabili vengono modificati dopo snapshot/checksum, anche con flip/restore durante un await. | Public material con storage privato bounded e copie non condivise sui getter; metadata collection copy-safe; trusted binding in collezione read-only non-array; checksum, autorizzazione e payload consumano lo stesso snapshot strutturalmente immutabile. | Reflection o memory corruption in-process richiedono compromissione della TCB e non sono mitigazioni dichiarate. |
| TM-061 | S/T/E | Un caller tenta di scegliere Regione/profilo, schema estensioni, endpoint, auth policy o credential, oppure un binding del profilo A usa risorse del profilo B. | Il command Healthcare non contiene selector di autorità né schema; Core consuma il principal già autenticato, verifica stato e grant exact anche con zero credential e produce `AuthorizedGatewayInvocation` opaca; test architetturale vieta al pack DER/certificato/registry identity lookup; l'adapter usa `PublishedConnectorAccessContext`, snapshot Published validato e `OperationBindingDependencies`; confronto exact Installation/Tenant/Application/Environment/Connector/operation; endpoint/auth/credential, schema e safe-code allowlist sono verificati contro catalogo compilato con chiave composita; fingerprint length-prefixed e resource stamp ricontrollati; mismatch/stale/disabled/null/enum invalidi negati. | Pipeline inbound Core, registry, store Published e compiled profile approvati restano nella TCB; una configurazione Published errata richiede four-eyes e audit operativo. |
| TM-062 | T/I/R | Una caratterizzazione storica o incompleta viene esposta come profilo regionale corrente, causando invio su wire/auth inventati o leakage di payload/fault. | Readiness `BlockedBySpec`, nessun handler regionale compilato, nessun endpoint/auth mapping, sentinelle HTTPS a zero request, errori inattesi di resolver/stamp/dispatcher normalizzati senza inner exception, safe code bounded, provenance ufficiale pubblica e GO/NO-GO esplicito. | La documentazione tecnica ufficiale può essere non pubblica o cambiare; serve nuovo gate di caratterizzazione e conformance prima del supporto. |
| TM-063 | S/T/I/E | Un caller o una configurazione stale combina Basic, SOAPAction/Content-Type e sessione opaque appartenenti a operation, endpoint o revisioni diverse, duplica Authorization/SOAPAction, sceglie la strategia runtime o colloca la sessione in un header infrastrutturale. | Dopo principal/grant e operation Published il runtime deriva la execution key server-owned e seleziona esattamente una strategia, senza caller selector né fallback; handoff non costruibile; resolver unico da snapshot Published; schema chiuso `soapBasicOpaqueSession`; helper/binding Basic internal non esportati; metadata SOAP tipizzati; Basic unico; denylist auth-placement include Authorization/SOAPAction/Content-Type, hop-by-hop, proxy, forwarding e tracing mentre la semantica v1 storica di `allowedClientHeaders` resta invariata; checksum/fingerprint coprono action, risorse e revisioni; final Published/lease revalidation adiacente a `SendSoapAsync`; E2E store→four-eyes publish→runtime→TLS e race rotate/disable/endpoint/action/session provano SOAP/generic zero rete sulle negazioni. | Processo Gateway, provider, store, publisher e registrazione DI approvati restano nella TCB; una revoca successiva all'avvio effettivo del dispatch non ritira byte già trasmessi. |
| TM-064 | T/I/D | Un envelope con versione diversa, action/content type incoerenti o un HTTP 500 Fault ambiguo induce dispatch scorretto, perdita del body o classificazione/retry non autorizzati. | Envelope bounded e parser XML hardened prima delle credenziali; Content-Type/action derivati dal tipo Published; `SendSoapAsync` preserva non-2xx; parser Fault M6 impone namespace, cardinalità e struttura esatti; Fault duplicati/malformed negati; timeout/cancellation e diagnostica sanitizzati. | Il mapping XML applicativo e la tassonomia Fault di un futuro connector richiedono una characterization separata; questa capability non qualifica connector production. |
| TM-065 | S/T/E | Un caller sceglie adapter, QName, SOAP version, endpoint, credenziali o valori security del bootstrap/validator, oppure un adapter registrato diverso viene sostituito al profilo approvato. | Resolver accetta solo invocation gia autorizzata e logical profile ID; profilo request/response/validation unico nel Connector Published; exact adapter ID/type, QName, action, endpoint binding/path, deadline, bounds, ConnectorVersion/checksum/revision/resource stamp nel fingerprint e nel digest four-eyes; registry bounded exact senza reflection; Core risolve le credential binding server-side ed e l'unico proprietario di HTTPS/DNS pinning/no proxy/no redirect/deadline/bounds; adapter senza HttpClient, URL, locator o secret. | Publisher, registry composition, provider e processo Gateway restano nella TCB; un adapter compilato malevolo richiede compromissione della supply chain approvata, ma non puo scegliere una rete o credenziale. |
| TM-066 | T/I/D | XML handshake nested usa DTD/entity, namespace/body confusion, duplicati, ordine/cardinalita errati, mixed content, un singolo valore enorme o output adapter illimitato per provocare parsing ambiguo, leakage o consumo memoria. | Writer Core byte-bounded durante la scrittura; first scan prima di `XDocument` con DTD proibito, resolver nullo, entity/document/depth/node/attribute limits e bound individuale su text/CDATA/attribute; Envelope/Body, payload cardinality e QName esatti prima dell'adapter; adapter sintetico nega ordine, cardinalita, domain, nested, duplicati, unexpected e mixed content; outcome chiuso senza raw XML/XElement/dictionary. | La semantica nested di ogni futuro protocollo resta responsabilita dell'adapter compilato e richiede test negativi propri. |
| TM-067 | S/T/I/R/D | Un candidate esterno viene iniettato come business input, fissato o riusato con intent/proof errato, scaduto o cross-context, promosso dopo publish/rotate/disable, conservato in stato illimitato o esposto in diagnostica. | Boundary runtime autenticata accetta solo principal, reference opaca e bytes; `ExternalSessionCandidate` internal owned/zeroed; intent server-side TTL/single-use con provenance chiusa e binding exact; stesso cache cap 256/lazy sweep/64 lock/current generation; validation adapter senza cache/rete; proof legata al digest candidate e alle generazioni; Published/binding/resource mutation aprono una lease a 64 stripe e avanzano generation a begin/end senza lock durante I/O; compare-and-promote sincrona dopo tutti gli await richiede generation exact e zero mutation attive, quindi verifica e consuma intent, proof e session generation senza gap anche se il resolver inizia durante la mutation; fake OCE ed eccezioni extension sanitizzate; remote expiry futura/capped e canary redaction. | Memoria, composition root Gateway e mutation authority single-node restano nella TCB; revoca successiva a un dispatch gia iniziato non ritira byte gia trasmessi; scale-out richiede authority distribuita. |
| TM-068 | S/T/E | Il caller sceglie una execution key tramite payload/header/query/metadata, altera la key Published, oppure una key mancante/duplicata ottiene fallback o first-wins. | La key proviene solo dalla operation Published, e schema/canonical checksum/four-eyes coprono il valore; mapping legacy server-side senza rewrite; registry startup bounded exact-one; duplicati negano startup, missing/unknown negano runtime senza default fallback; grant e Published resolution precedono il lookup. | Publisher e configurazione deployment autorizzati restano nella TCB; due amministratori collusi possono approvare una key errata ma il modulo deve essere anche installato dal deployment. |
| TM-069 | T/E | Un Connector o tenant induce il caricamento di un modulo non autorizzato, traversal/search di assembly, path UNC/device/reparse, swap TOCTOU o dipendenza verticale inversa nel Core. | Allowlist deployment-only con path assoluto canonico su drive locale fixed, assembly full name, type e module ID esatti; UNC/mapped/device/traversal/symlink/reparse negati; immagine max 64 MiB letta una volta, metadata e MVID verificati e gli stessi byte passati a `LoadFromStream`; path/type/ID unici e bounded; nessuna directory/AppDomain discovery, companion probing, download o reload; architecture e Core-export gate negano dipendenze inverse. | Un modulo allowlisted è codice full-trust in-process; ACL, provenance e review del deployment devono proteggere i byte prima dell'apertura, e Administrator/SYSTEM resta rischio residuo. |
| TM-070 | S/T/I/E | Una strategy raggiunge il service locator o altre strategy via constructor injection, costruisce/muta il contesto, auto-asserisce identity/grant, modifica il payload o reinterpreta autenticazione inbound/outbound. | Registrar buffered con max 128 registrazioni/64 strategy/depth 32, un solo costruttore pubblico e grafo ricorsivo limitato a servizi esplicitamente registrati e module-owned; safe host dependencies vuote, quindi `IServiceProvider`, scope, collection/delegate/cross-module e varianti annidate negate prima del commit DI. `AuthorizedConnectorExecution` internal-construct, identity/operation Core-derived, payload owned/read-only; auth kinds dichiarati, validati e snapshottati a startup e mismatch negato prima di `ExecuteAsync`; synthetic assembly senza friend access o `AuthenticateAsync`. | Una strategy allowlisted è trusted in-process e può usare direttamente API pubbliche o stato statico; memory corruption/reflection privilegiata non sono sandboxate e la review del modulo resta obbligatoria. |
| TM-071 | I/R/D/E | Una strategy propaga message/inner/stack/provider data, forgia `GatewayException`/status/retryability o usa una falsa `OperationCanceledException` per simulare la cancellazione del caller. | Solo strategy Core con marker internal possono preservare failure qualificate; qualsiasi eccezione external, incluso `GatewayException`, diventa `BGW-EGRESS-UPSTREAM-REJECTED` senza inner/message e non retryable. Le failure capability usano un marker internal non costruibile, legato per reference all'esatto bridge corrente. Cancellation è conservata solo quando il token effettivo del caller risulta cancellato; risultato/content type/body restano bounded e copiati. | Un modulo full-trust può bloccare il processo, restituire intenzionalmente un risultato applicativo falso o usare reflection; isolamento di codice non fidato richiederebbe un processo separato ed è fuori scope. |
| TM-072 | S/T/E | Una strategy conserva il bridge autorizzato dell'invocazione A, lo riusa per B, seleziona un profilo/endpoint/credential diverso o concatena più capability per ampliare l'autorità. | `IAuthorizedConnectorCapabilityBridge` espone solo typed handshake e composed SOAP sulla current handoff, senza selector di identity/operation/profile/endpoint/credential/provider/transport; implementazione privata, scope attivo mutabile, exact-reference check e consumo one-shot. Typed profile deriva dal Published corrente; admission resta sul boundary autenticato esistente; SOAP riusa il medesimo `SoapSessionClient`/lease provider. Replay retained produce solo failure non autorevole e viene sanitizzato. | Il modulo è comunque full-trust nel processo e può rifiutare servizio o chiamare proprie reti/API se la supply chain approvata è malevola; il bridge limita l'autorità supportata, non crea una sandbox. |

## Analisi degli scenari obbligatori

### Amministratore locale/SYSTEM

Non è una minaccia completamente mitigata. Può sostituire binari, effettuare debugging, leggere memoria o abusare di un processo autorizzato. Il prodotto dichiara esplicitamente questo limite e protegge soprattutto contro processi non privilegiati, malware same-user non iniettato e furto offline.

### Cross-Tenant

Il client non fornisce un Tenant autorevole. Certificato/SPKI → Installation → Tenant costituisce la catena server-side. Composite foreign key e RLS impediscono associazioni incoerenti anche in presenza di errori applicativi.

### Gateway/Vault compromise

Il Gateway è trusted computing base e necessariamente vede temporaneamente i segreti che usa. Si riduce il blast radius con Managed Identity, permission per namespace, memoria breve, niente persistence/log e rotazione. Non è possibile dichiarare la minaccia eliminata.

### Plugin

La firma prova provenienza, non innocuità. Un plugin approvato viene trattato come parte del Gateway. Plugin third-party non fidati richiederebbero processo/container isolato e non sono supportati nell'MVP.

### Insider amministrativo

M5 applica OIDC provider-neutral, RBAC server-side, tenant scope, optimistic concurrency, four-eyes checksum-specific e audit redatto. Un amministratore autorizzato dei binding può comunque configurare una destinazione approvata errata e due account privilegiati possono colludere: review operativa e audit restano necessari.

### Direct client endpoint

M5.5 non trasferisce vendor credential al client. Una Direct Installation possiede pero
la chiave privata della propria identita inbound: la protezione del key store client e
responsabilita del deployment. Compromissione della chiave non consente di scegliere
Tenant, Application, endpoint o secret binding, ma consente le operation gia concesse
fino a revoca. Grant minimo, rotation e monitoraggio audit restano obbligatori.

### M6 certificate, signing and outbound mTLS primitives

La primitive non implementa il lifecycle FVG/Umbria e non rende production-ready alcun
Connector sanitario. `SEC-M6-001` mappa la matrice claim/algoritmo, policy/SPKI
substitution, wrong-key, replay e lifetime sui test
`M6_RS256_positive_resolves_server_owned_policy_and_remote_signs`,
`M6_JWT_policy_substitution_with_same_policy_id_is_denied_before_provider`,
`M6_JWT_approved_scalar_fingerprint_with_substituted_SPKI_is_denied_before_sign` e
`M6_JWT_replayed_identifier_and_missing_capability_fail_closed`. `SEC-M6-002` mappa
purpose/scope/rotation/disable sui test `M6_MTLS_scope_and_purpose_mismatch_deny_before_provider_or_network`,
`M6_MTLS_retained_revision_one_provider_result_after_rotate_causes_zero_connection`,
`M6_MTLS_disable_during_one_shot_revalidation_causes_zero_dispatch` e
`M6_MTLS_endpoint_substitution_is_denied_before_handshake`. `SEC-M6-003`
mappa handshake, hostname e certificate rejection sui test del server mTLS locale.
`SEC-M6-004` mappa non-exportability e redaction sui test public-API e sugli unexpected
provider exception test per metadata/sign/certificate, oltre al secret scan repository.

`SEC-W1-001` mappa `TM-057` sui test `Wave1_x5c_leaf_and_chain_are_verified_leaf_first_and_standard_base64`,
`Wave1_substituted_certificate_identity_is_denied_before_sign`,
`Wave1_retained_revision_one_public_material_cannot_authenticate_revision_two` e sulla
matrice rotate/disable. `SEC-W1-002` mappa `TM-058` sui test temporal/trusted-source,
same-ID policy substitution, reserved claim e public-API/arbitrary-header boundary.
`SEC-W1-003` mappa `TM-059` sui test generic runtime-subject positivo, business
promotion, source substitution, invocation A/B e matrice provenance/revision/context.
`SEC-W1-004` mappa `TM-060` sui test di mutazione input/getter/metadata e limiti del
public material, oltre al flip/restore deterministico di `TrustedClaims` durante la firma.

`SEC-W1-HS-001` mappa `TM-065` sui test Published adapter ID/type request/response/validation,
four-eyes digest, Core-owned restricted HTTPS e credential binding, e sul named production-host E2E
che attraversa `Program`, HTTP, `AuthenticateAsync`, grant, PostgreSQL store e registry DI; i replay
cross-Tenant/Application/Installation hanno grant valido e zero validator network.
`SEC-W1-HS-002` mappa `TM-066` sulle matrici strict nested response, DTD/QName/Body,
request byte bound, text/CDATA/attribute individuali e aggregate prima dell'adapter, e real HTTPS.
`SEC-W1-HS-003` mappa `TM-067` sui test wrong/reused/expired intent, presentation principal-bound,
proof/candidate/context/generation replay, simultaneous double completion, validator failure,
real/fake cancellation, remote expiry, rotate/disable durante validation e nella final window,
store mutation generation, 256-entry lazy sweep, candidate zeroing/redaction e production E2E. La
race PostgreSQL aggiuntiva sospende esattamente prima della CAS e usa publish/disable reali sullo
stesso `RoutingConnectorConfigurationStore`, con validator count uno e promotion count zero.

`SEC-W1-EXEC-001` mappa `TM-068` sui test schema/checksum/four-eyes, override
payload/query/header/metadata, grant-before-lookup, missing/unknown senza rete e duplicate startup.
`SEC-W1-EXEC-002` mappa `TM-069` sui test del modulo sintetico separato senza friend access,
allowlist path/identity/type/ID esatti, bounded registry, assenza di scanning e Core senza dipendenze
opzionali. `SEC-W1-EXEC-003` mappa `TM-070` sui test public non-constructible/no-setter,
context identity dal production host, payload snapshot copy/read-only e assenza di inbound re-auth.
`SEC-W1-EXEC-004` mappa `TM-071` sui canary exception/fake-cancellation e sulla preservazione del
token realmente cancellato.

## Criteri di revisione

Il threat model deve essere riesaminato quando:

- viene aggiunto un auth/protocol adapter;
- compare un nuovo execution handoff ibrido;
- si modifica enrollment/recovery;
- si accettano plugin third-party;
- cambia hosting o TLS termination;
- si introduce persistenza di payload o Operator Secret;
- viene selezionato un pilot reale.

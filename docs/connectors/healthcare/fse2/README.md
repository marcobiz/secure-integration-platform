# FSE2 National Connector — Organization profile

**Current entry point:** [validation and workflow status pilot](../../../user/fse2-validation-status.md).
The opt-in `fse2-organization-current-spec@1.0.0` is integrated through PR #65.
The [capability summary](../../../../IMPLEMENTATION_STATUS.md#stato-prodotto) owns current
status; the [14-route current-spec contract](current-spec.md) owns the frozen offline
scope, request/response matrix and acceptance limits.

Offline completeness does not mean full live qualification. The current pilot records
CDA VERIFICA and workflow FOUND after a Gateway restart in OfficialTest. FHIR is not
live-qualified (upstream 500, undetermined cause); live document publication, production
and overall accreditation are not qualified. Healthcare remains an optional pack, never
a Core dependency.

## Historical profiles

The [validate-only guide](../../../user/fse2-officialtest.md) retains the earlier
`fse2-officialtest-validate-cda@1.0.1` path and shared provisioner reference. Its
bootstrap/session/runner gaps do not describe the current distributed pilot.
The [history index](../../../history/README.md#percorsi-fse2-precedenti) preserves the
11-operation profile matrix and the earlier trace/NOT_FOUND observation. Historical
Published definitions and their evidence remain immutable; qualifications do not
transfer to the current profile.

## Authority model

Il solo actor profile implementato è `ORGANIZATION`; Human Actor è differito. Core
autentica il caller, deriva Tenant/Application/Installation/Environment, verifica grant
e Published operation e poi consegna al modulo `healthcare-fse2` una authority bounded.
Il pack dipende da contratti provider-neutral e non riceve store/provider access,
`GetSecret`, signing oracle, endpoint selector o HTTP generico.

La configurazione Published contiene identità Organization e binding logici. Metodo,
path, content type, endpoint, audience, claim policy, signing slot, certificati e
revisioni sono server-owned. `person_id` resta dato business validato e non diventa
identità autenticata.

## OfficialTest `validate-cda` — riferimento storico

La source pubblica canonica è
`Definitions/fse2-officialtest-validate-cda.connector.json` e contiene una sola
operation. Non contiene endpoint concreto, identità organizzative operative, provider
locator, P12, password o token. Il provisioner verticale
`tools/fse2/OfficialTestProvisioner` usa le Admin API autenticate per
`plan → configure/grant → propose → approve/publish → verify` e risolve A1/S1 dal
catalogo pubblico server-side.

Il provisioner non esegue la call live. La qualifica di questo profilo validate-only è
stata ottenuta da un runner esterno controllato e redatto. Per la prima adozione usare
ora il [runner current-spec distribuito](../../../user/fse2-validation-status.md), con
i suoi prerequisiti e limiti, non test integration, fixture o request ricostruite a mano.

La parity è esclusiva di `fse2-officialtest-validate-cda@1.0.1`: entrambi i JWT usano la
sola leaf S1 in `x5c` e il body `VERIFICA` contiene soltanto `healthDataFormat=CDA` e
`activity=VERIFICA`, senza `mode` o `attachment_hash`. La versione `1.0.0` è
compatibilità storica immutabile, non contract-parity qualified.

## Provider, claim e transport

- A1 è distinto e autorizzato per mTLS; S1 alimenta i due slot `authorization` e
  `integrity` con RS256 e `ContentCommitment`.
- Endpoint, origin, path composition, method, timeout, response bound, DNS/restricted
  egress e redirect deny restano autorità Published/Core.
- Organization/locality/application, `iss`, `aud`, `sub`, `iat`, `exp` e `jti` sono
  server-owned; purpose/action e hash necessari sono derivati; i soli business claim
  ammessi restano allowlisted.
- Errori e audit conservano soltanto categorie e safe code bounded; non payload, response
  raw, JWT, header, endpoint o certificati.

## Workflow correlation e limiti

La correlation tecnica PostgreSQL è scoped esattamente a Tenant, Application,
Installation, Environment, Connector/versione e configurazione Published. Conserva solo
operation originaria, action, purpose, checksum profilo, workflow/trace e timestamp
tecnico; non conserva contenuto clinico. Restart e repliche condividono lo stesso stato.

Il mapper status non espone l’intero `transactionData[]` ufficiale: è una riduzione di
sicurezza intenzionale. Accetta al massimo 1.000 eventi ordinati e soltanto i tipi
`VALIDATION`, `PUBLICATION`, `SEND_TO_INI`, `SEND_TO_UAR`, `UAR_FINAL_STATUS`, con esito
`SUCCESS` o `BLOCKING_ERROR` e timestamp valido. Message, subject, document ID, issuer,
extra e response raw vengono scartati; valori sconosciuti o malformati falliscono chiusi.
Il 404 previsto dal contratto status è una risposta tecnica valida soltanto quando il reducer
bounded riconosce l'exact code RFC7807 allowlisted `record-not-found`: viene ridotto a
`statusCode=404`, `statusClassification=NOT_FOUND` ed eventi vuoti, scartando l'intero
problem body. Body assente, non JSON, malformato, code sconosciuto e ogni altro 404 seguono
il normale upstream failure bounded. Nessun 404 attiva retry automatici; il primo caso produce
un solo audit success, il secondo un solo audit failure.

## Esempio minimo create → status — profilo storico

Questo esempio conserva la factory storica. Per il profilo corrente usare il
[consumer contract current-spec](current-spec.md#consumer-contract), che richiede
il workflow della precedente VALIDATION per la pubblicazione ordinaria. Il runner
di valutazione VERIFICA/status non abilita queste operazioni di pubblicazione.

Con Installation, grant e configurazione Published già attivi, il payload applicativo
`create` resta quello canonico già usato dal client Gateway:

```csharp
byte[] createPayload = Fse2Request.Create(
    pdfBytes,
    publicationRequestJson,
    clinicalClaims).SerializeAuthorizedPayload();
```

Dalla risposta normalizzata conservare `workflowInstanceId`. La richiesta status non
richiede di reinviare patient, action, purpose, profilo o scope:

```csharp
byte[] statusPayload = Fse2Request
    .GetStatusByWorkflow(workflowInstanceId)
    .SerializeAuthorizedPayload();
// JSON prodotto: {"resourceIdentifier":"<workflowInstanceId>"}
```

Inviare entrambi i payload al normale endpoint Published del Gateway con
l'autenticazione runtime già prevista. Non servono nuovo login, binding, grant, SQL,
accesso store o comando di recovery tra le due invocazioni.

Lo stesso modello vale per la trace restituita da `validate-cda`: la richiesta seguente
contiene unicamente il valore opaco, mentre action, purpose e scope sono risolti dalla
correlazione durevole prima di firma, DNS e trasporto:

```csharp
byte[] traceStatusPayload = Fse2Request
    .GetStatusByTrace(traceId)
    .SerializeAuthorizedPayload();
// JSON prodotto: {"resourceIdentifier":"<traceId>"}
```

La definition Published deve contenere entrambe le operation nella stessa esatta
Tenant/Application/Installation/Environment/Connector/versione e configurazione che ha
registrato la trace; non esiste fallback in-memory o cross-scope.

Local PKCS#12 è un pack/laboratorio opzionale, non HSM/KMS o custody production.
Accreditamento, produzione, Human Actor, callback inbound, direct FHIR publication
confermata e qualifica live complessiva restano fuori scope. La copertura offline
corrente è limitata alle 14 route e alle risoluzioni esplicite di current-spec.

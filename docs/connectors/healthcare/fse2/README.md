# FSE2 National Connector — Organization profile

**Stato CURRENT:** `validate-cda` LIVE_QUALIFIED in OfficialTest sulla baseline
`613b28558fc9aeef13b60381b4fc49b59e2ad5c2`. La claim non implica accreditamento,
produzione o copertura completa del Gateway FSE 2.0. La procedura adopter-facing e i
blocchi correnti sono in [docs/user/fse2-officialtest.md](../../../user/fse2-officialtest.md).

## Capability matrix

| Operation | Stato prodotto | Utilità/limite |
|---|---|---|
| `validate-cda` | `LIVE_QUALIFIED` | Pilot qualità CDA disponibile; una chiamata applicativa bounded OfficialTest ha restituito Gateway 200. |
| `delete` | `PRODUCT_PATH_OFFLINE_QUALIFIED` | Wire/no-body/claim/ack qualificati contro mock; non productizzata né live. |
| `validate-fhir` | `IMPLEMENTED_PARTIAL` | Foundation runtime; DTO/response e provisioning OfficialTest non qualificati. |
| `create` | `PRODUCT_PATH_OFFLINE_QUALIFIED` | Published path, exact PDF/CDA, A1/S1, risposta bounded e correlazione durevole qualificati contro upstream sintetico; nessuna qualifica live. |
| `replace` | `IMPLEMENTED_PARTIAL` | Foundation con document ID e hash; non necessaria alla prima pubblicazione. |
| `update-metadata` | `IMPLEMENTED_PARTIAL` | JSON pass-through non qualificato contro DTO ufficiale completo. |
| `update-metadata-chain-concealment` | `IMPLEMENTED_PARTIAL` | Test-only e contratto insufficiente per una claim operativa. |
| `validate-and-create` | `IMPLEMENTED_PARTIAL` | Recovery eccezionale, non flusso normale. |
| `validate-and-replace` | `IMPLEMENTED_PARTIAL` | Recovery eccezionale e documento esistente. |
| `get-status-by-workflow` | `PRODUCT_PATH_OFFLINE_QUALIFIED` | Risolve il workflow durevole prima degli effetti e restituisce solo eventi tecnici bounded; nessuna qualifica live. |
| `get-status-by-trace` | `IMPLEMENTED_PARTIAL` | Diagnostica successiva; stessi limiti di status/correlation. |

`FULL_FSE2_GATEWAY_COVERAGE = NO`. Il product path offline copre ora
`validate-cda → create → get-status-by-workflow`; un `202` di create senza lo status
successivo non dimostra il completamento verso INI/EDS, e nessuna call create/status
OfficialTest è qualificata da questa copertura sintetica.

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

## OfficialTest `validate-cda`

La source pubblica canonica è
`Definitions/fse2-officialtest-validate-cda.connector.json` e contiene una sola
operation. Non contiene endpoint concreto, identità organizzative operative, provider
locator, P12, password o token. Il provisioner verticale
`tools/fse2/OfficialTestProvisioner` usa le Admin API autenticate per
`plan → configure/grant → propose → approve/publish → verify` e risolve A1/S1 dal
catalogo pubblico server-side.

Il provisioner non esegue la call live. La qualifica di `validate-cda` è stata ottenuta
da un runner esterno controllato e redatto; un runner adopter-facing riproducibile non è
ancora distribuito. Non sostituirlo con test integration, fixture o una request costruita
a mano.

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

## Esempio minimo create → status

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

Local PKCS#12 è un pack/laboratorio opzionale, non HSM/KMS o custody production.
Accreditamento, produzione, Human Actor, callback inbound, direct FHIR publication
confermata e full operation coverage restano fuori scope.

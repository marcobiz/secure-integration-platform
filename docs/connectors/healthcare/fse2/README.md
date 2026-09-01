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
| `create` | `IMPLEMENTED_PARTIAL` | Richiesta/hashing foundation; definition/provisioning canonici e qualifica live mancanti. È blocker del pilot pubblicazione. |
| `replace` | `IMPLEMENTED_PARTIAL` | Foundation con document ID e hash; non necessaria alla prima pubblicazione. |
| `update-metadata` | `IMPLEMENTED_PARTIAL` | JSON pass-through non qualificato contro DTO ufficiale completo. |
| `update-metadata-chain-concealment` | `IMPLEMENTED_PARTIAL` | Test-only e contratto insufficiente per una claim operativa. |
| `validate-and-create` | `IMPLEMENTED_PARTIAL` | Recovery eccezionale, non flusso normale. |
| `validate-and-replace` | `IMPLEMENTED_PARTIAL` | Recovery eccezionale e documento esistente. |
| `get-status-by-workflow` | `IMPLEMENTED_PARTIAL` | Necessaria al pilot pubblicazione; response/correlation/provisioning non completi. |
| `get-status-by-trace` | `IMPLEMENTED_PARTIAL` | Diagnostica successiva; stessi limiti di status/correlation. |

`FULL_FSE2_GATEWAY_COVERAGE = NO`. Per un pilot di pubblicazione minimo servono
`validate-cda → create → get-status-by-workflow`; un `202` di create senza
riconciliazione non dimostra il completamento verso INI/EDS.

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

La correlation tecnica è scoped a Tenant, Application, Installation, Environment,
Connector/versione e profilo comune. Non conserva contenuto clinico, ma lo store corrente
è bounded e process-local: durability cross-process/restart/scale-out non è qualificata.
Il mapper status non proietta ancora l’intero `transactionData[]` ufficiale.

Local PKCS#12 è un pack/laboratorio opzionale, non HSM/KMS o custody production.
Accreditamento, produzione, Human Actor, callback inbound, direct FHIR publication
confermata e full operation coverage restano fuori scope.

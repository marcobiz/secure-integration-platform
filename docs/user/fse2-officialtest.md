# Pilot FSE2 OfficialTest

Per il nuovo percorso current-spec limitato a VERIFICA e consultazione, vedere
[FSE2 Organization: validazione e status](fse2-validation-status.md). La presente
guida conserva il contesto del precedente profilo validate-cda 1.0.1.

**Pubblico:** organizzazione autorizzata a usare l’ambiente OfficialTest.
**Stato:** CURRENT per il solo `fse2-officialtest-validate-cda@1.0.1` /
`validate-cda`.
**Claim:** `validate-cda` è LIVE_QUALIFIED sulla baseline exact; il percorso completo
non è ancora self-service né riproducibile dalla documentazione sola.

Questa guida mette i passaggi nell’ordine reale e segnala dove il prodotto si ferma. Non
autorizza nuove chiamate live, non crea account o materiale A1/S1 e non qualifica
produzione o accreditamento.

## Validazione CDA e abilitazione alla pubblicazione

In OfficialTest le operazioni hanno finalità distinte:

- `VERIFICA` controlla il CDA, ma non lo abilita alla pubblicazione;
- `VALIDATION` è la validazione propedeutica alla pubblicazione e deve restituire il
  `workflowInstanceId` da usare nel passaggio successivo;
- `validate-and-create` combina validazione e pubblicazione in una sola operazione.

I certificati di test e l’accreditamento usati per la validazione non garantiscono
automaticamente l’ammissione alle operazioni di pubblicazione. Non è necessario avere già
l’accreditamento definitivo di produzione per provarle nell’ambiente di test; può tuttavia
essere necessaria un’abilitazione OfficialTest specifica per `VALIDATION`, `create` e
`validate-and-create`.

Se `VERIFICA` risponde HTTP 200, ma sia il percorso di pubblicazione separato sia
`validate-and-create`, costruiti conformemente, ricevono HTTP 404, classificare il caso
come possibile anomalia di admission/routing e chiedere conferma a Sogei/Ministero. Se
l’esito di `create` è ambiguo, riconciliare prima tramite workflow, trace o status: non
ripetere `create` alla cieca.

Riferimenti ufficiali:

- [Processo di accreditamento al FSE 2.0](https://github.com/ministero-salute/it-fse-support/blob/main/doc/accreditamento/README.md)
- [Integrazione con il Gateway FSE](https://github.com/ministero-salute/it-fse-support/blob/main/doc/integrazione-gateway/README.md)

## Prima di iniziare: risultato e hard stop

Il pilot disponibile verifica la qualità di un CDA con una singola `validate-cda`. Non
pubblica un documento. `create + get-status-by-workflow` sono qualificati offline sul
product path con correlazione PostgreSQL durevole, ma non sono inclusi nella definition
OfficialTest canonica né in una qualifica live.

Fermarsi se manca anche uno solo di questi elementi:

- accesso OfficialTest e budget di una chiamata autorizzati dall’organizzazione;
- dataset CDA sintetico approvato per l’uso nel test;
- deployment exact della vertical image FSE2, modulo allowlisted e migrazioni
  PostgreSQL 18 correnti;
- Tenant, Application, Environment OfficialTest e una Installation Direct attiva,
  derivati e verificati server-side;
- risorse A1 e S1 distinte, attive, scoped al Connector/operation, con custody e metadata
  pubblici gestiti dal provider autorizzato;
- tre sessioni Admin separate: Security Administrator, Connector Editor e un Connector
  Approver distinto;
- HTTPS Gateway e, se necessaria, sola CA pubblica DER pinned;
- piano operativo protetto, fuori Git, conforme allo
  [schema chiuso](../connectors/healthcare/fse2/fse2-officialtest-operational-plan.schema.json).

La repository non offre ancora un workflow supportato per creare da zero il deployment
FSE2 reale, importare il materiale provider operativo, creare/assegnare i principal o
acquisire le tre sessioni. Sono prerequisiti esterni espliciti. Il laboratorio Local
PKCS#12 usa materiale sintetico e non sostituisce custody o import OfficialTest.

## Confine del piano

Il piano contiene selector Tenant/Installation, un’asserzione Environment, identità
organizzazione/località e riferimenti pubblici A1/S1 con revisioni attese. Non contiene
P12 o relativi path, password, chiavi private, token, header Authorization, cookie,
identità dei principal o authority runtime scelte dal client.

Usare un path assoluto protetto fuori dalla repository:

```powershell
$protectedPlan = '<percorso-assoluto-protetto-fuori-repository>'
```

## 1. Plan — zero effetti

Da exact product HEAD:

```powershell
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- plan $protectedPlan
```

`plan` viene eseguito prima della costruzione del client Admin e stampa soltanto
identità fisse/digest redatti. Un esito plan non prova che gli ID dichiarati siano
autorevoli: `configure` deve risolvere l’Installation autenticata e derivare da essa
l’Environment. Qualunque codice `FSE2_OFFICIALTEST_*` è un hard stop.

## 2. Apply — Security Administrator

In un processo dedicato alla sessione Security Administrator, valorizzare senza usare la
command line o il piano:

```powershell
$env:FSE2_GATEWAY_URL = 'https://<gateway-amministrativo>'
$env:FSE2_ADMIN_SESSION_COOKIE = '<cookie-di-sessione-protetto>'
$env:FSE2_GATEWAY_CA_FILE = '<ca-pubblica-der-opzionale>'
```

Il meccanismo di autenticazione del deployment deve fornire la sessione; questa
repository non documenta un metodo generico per estrarla o copiarla. Eseguire:

```powershell
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- configure $protectedPlan
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- grant $protectedPlan
```

`configure` valida/importa la definition canonica, valida lo stato persistito e applica
il binding esatto. `grant` crea o verifica il grant Installation/Connector/
`validate-cda`. Entrambi ricostruiscono lo stato dalle Admin API e saltano soltanto fasi
già persistite e identiche.

## 3. Apply — Connector Editor

Rimuovere la sessione Security Administrator dal processo. In una sessione separata di
Connector Editor:

```powershell
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- plan $protectedPlan
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- propose $protectedPlan
```

Conservare nel passaggio di ruolo soltanto approval request ID, approval digest e i
checksum/digest redatti restituiti. Non conservare definition compilata, risposte Admin,
cookie o metadata provider.

## 4. Apply — approvatore distinto e publish

Rimuovere la sessione editor. In un nuovo processo autenticato come Connector Approver
distinto, ripetere `plan`, confrontare i digest del passaggio di ruolo, quindi usare i
valori redatti restituiti da `propose`:

```powershell
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- approve $protectedPlan <approval-request-id> <approval-digest-sha256>
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- publish $protectedPlan <expected-publication-revision>
```

Self-approval, checksum/revision drift, binding/provider drift o publisher diverso
dall’approvatore exact falliscono chiusi. Non modificare il piano o la versione per
aggirare l’errore.

## 5. Verify

Nella stessa sessione dell’approvatore:

```powershell
dotnet run --project tools/fse2/OfficialTestProvisioner/OfficialTestProvisioner.csproj -- verify $protectedPlan
```

Procedere soltanto se il read-back è `Published/Active`, la versione è `1.0.1`, esiste
una sola operation `validate-cda`, A1 è il certificato mTLS, S1 alimenta entrambi gli slot
JWT, non esistono ordinary secret binding e tutti i digest/revisioni coincidono.

## 6. Invocation — blocco self-service corrente

La baseline ha una qualifica live redatta: una richiesta applicativa `validate-cda` ha
attraversato il Gateway verso OfficialTest e ha ricevuto Gateway 200, con un solo
dispatch, zero retry e zero redirect. Questo qualifica la capability sulla configurazione
attestata; non rende riproducibile il pilot per un nuovo adottante.

La repository non distribuisce ancora un runner adopter-facing che:

1. usi una Installation già enrolled e il grant esatto;
2. acquisisca l’input CDA sintetico autorizzato senza dipendere da fixture/test Git;
3. costruisca il payload FSE2 pubblico previsto;
4. verifichi clock, budget di una chiamata e Published read-back;
5. esegua una sola invocation e produca risultato/audit redatti;
6. possa riprendere in sicurezza dopo pubblicazione ma prima della call.

Di conseguenza il percorso supportato termina a `verify` per un adottante indipendente.
Non usare test integration, fixture M3, Git object, payload ricostruiti a mano o endpoint
letti da evidence come runner operativo. La prossima slice di prodotto deve consegnare
quel runner/guided workflow e chiudere il gate black-box **time to first successful
call**. Solo un owner già autorizzato del runner esterno usato per la qualifica può
eseguire una nuova call, con una nuova autorizzazione live.

## Resume, errori e cleanup

- Un 429 non attiva retry automatici. Attendere l’eventuale `Retry-After` bounded e
  ripetere lo stesso comando con lo stesso piano/sessione; il risultato indica
  `currentState`, `nextRequiredPhase` e `retrySafe`.
- Un drift di Installation, Environment, binding, provider o approval richiede
  riconciliazione dell’autorità server-side; non SQL, flag force o modifica in-place.
- Una versione Published è immutabile. Il decommissioning usa retire; rollback riattiva
  soltanto una versione Superseded già pubblicata.
- Non eliminare volumi o materiale provider per “ripartire”. Una configurazione Published
  nell’Environment sbagliato richiede un nuovo stato pulito supportato e preserva la
  precedente come evidenza storica.

La tabella codice → azione è in [troubleshooting.md](troubleshooting.md). La reference
tecnica del profilo è nel [README FSE2](../connectors/healthcare/fse2/README.md).

## Criterio di successo futuro

Con i prerequisiti esterni già presenti, una persona senza conoscenza della repository
deve arrivare a una `validate-cda` sanificata e auditabile senza SQL, accesso store,
cookie copiati, sequenze inventate o supporto ordinario. Il tempo, i passaggi e la
recovery vanno misurati black-box; la qualifica live già ottenuta non sostituisce questa
prova di adozione.

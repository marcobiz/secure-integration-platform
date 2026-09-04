# FSE2 Organization: validazione e consultazione OfficialTest

Questo percorso locale utilizza il normale Gateway, PostgreSQL e il profilo
`fse2-organization-current-spec@1.0.0` Published. Non abilita la pubblicazione di
documenti: il runner permette soltanto `VERIFICA` e consultazioni. Le 14 operazioni
del profilo rimangono qualificate offline; ciò non equivale alla disponibilità live.

## Prerequisiti

- Distribuzione del repository con Docker Desktop Linux e SDK .NET indicato da
  `global.json`; Windows PowerShell 5.1 o PowerShell 7.
- Root LocalPkcs12 già predisposto e autorizzato per OfficialTest, con
  `manifest.json`, `material`, risorse `fse2-auth` A1 e `fse2-sign` S1 valide.
  Non si crea, copia o modifica materiale operativo. Il mount è read-only.
- Accesso HTTPS a GitHub per gli esempi ufficiali congelati e al servizio
  OfficialTest. Nessuna deroga TLS, redirect o retry automatico.
- Nessun altro stack `secure-integration-m5-quickstart` attivo. Il comando rifiuta
  risorse di altri checkout; non tenta di liberare porte o container altrui.
- Configurazione amministrativa dell'organizzazione/località, conservata fuori
  dal repository. Il modello
  [officialtest-pilot.example.json](../../tools/fse2/officialtest-pilot.example.json)
  contiene soltanto valori sintetici: usare quelli ammessi dal proprio accesso test.
  Il dominio è il codice organizzativo ufficiale a tre cifre e la descrizione
  corrispondente (§16.3.7), **non** l'identificativo della ASL/struttura. Il modello
  usa il profilo di prova già qualificato (`190` / `Regione Sicilia`,
  `LABORATORIO DI PROVA`), non assegna quel dominio a un'altra organizzazione.

Non servono SQL, accesso diretto allo store, cookie copiati, UUID/checksum ricostruiti
o certificati operativi forniti al caller. Il bootstrap esistente crea le identità
locali sintetiche; l'enrollment Direct usa challenge e proof-of-possession reali.

## Comandi e ruoli

Da una distribuzione pulita e committata, impostare i tre percorsi locali:

```powershell
$runner = '.\tools\fse2\Invoke-Fse2ValidationStatus.ps1'
$provider = 'C:\SecureRuntime\fse2-officialtest-v1'
$settings = 'C:\SecureRuntime\fse2-pilot-settings.json'
$sdk = (Get-Command dotnet).Source

# Copiare una volta il modello fuori dal repository e verificarne i valori
# organizzativi/località rispetto al proprio accesso test prima di Configure.
Copy-Item '.\tools\fse2\officialtest-pilot.example.json' $settings
& $runner -Phase Start -ProviderRoot $provider -DotNetPath $sdk
& $runner -Phase Configure -SettingsPath $settings
& $runner -Phase Propose -SettingsPath $settings
& $runner -Phase Approve -SettingsPath $settings
& $runner -Phase Verify -SettingsPath $settings
```

`Configure` usa Security Administrator; `Propose` Connector Editor;
`Approve` un Connector Approver distinto e pubblica **la configurazione**, non un
documento sanitario. Il checksum approvato e la revisione corrente sono letti dalle
API. Solo quattro grant: validazione FHIR/CDA e status workflow/trace.
Le sessioni si acquisiscono normalmente in memoria con il login DevelopmentAuth
già supportato, esclusivamente dal loopback reale dello stack M5Testing. Non è un
metodo di autenticazione per produzione o per un Gateway remoto.

I comandi amministrativi riusano il provisioner e la sua ripresa fail-closed:
configurazione già corretta non viene ricreata; drift e autorizzazioni insufficienti
richiedono una correzione esplicita, non vengono aggirati.
`Verify` controlla anche mTLS/BGW1 sulla lettura Broker già esistente: per un Direct
autenticato il diniego di ruolo è atteso e distinto da un errore di autenticazione.
Questo controllo non invia richieste OfficialTest.

## Validazione e seconda istanza

Ogni comando seguente invia **una sola invocation**, mai un ciclo automatico:

```powershell
& $runner -Phase Validate-Fhir -SettingsPath $settings
& $runner -Phase Audit -SettingsPath $settings
& $runner -Phase Restart
& $runner -Phase Status-Workflow -SettingsPath $settings
& $runner -Phase Audit -SettingsPath $settings
```

Il runner scarica in memoria l'esempio ufficiale `RAP.json` al commit
`4d2691dcdc051fa5a842e2cac074226bb50373d2`, verifica SHA-256
`5FBEB57A5250FBFB3E6F028C834316CCA1546109CB5A2EE34A748E22C0F880DF` e il paziente
esplicitamente di test `PROVA…`. Invia il Bundle invariato come file JSON multipart,
con `{"mode":"RESOURCE","activity":"VERIFICA"}`, secondo l'OpenAPI congelata.
Non deduce il formato dal nome della route e non salva il documento.

`Status-Workflow` prende l'identificativo tecnico restituito dall'ultima validazione.
Si può specificare `-Identifier` con un workflow precedentemente osservato. Il payload
runtime contiene soltanto l'identificativo; tutte le altre autorità sono risolte dal
Gateway. Ogni comando parte in un processo nuovo; `Restart` riavvia anche il Gateway,
senza toccare PostgreSQL. Nessun fallback in-memory.

Se la validazione FHIR non restituisce un workflow, **non inventarne uno**. È possibile
eseguire intenzionalmente `-Phase Validate-Cda`, quindi Audit, Restart e Status-Workflow:
usa PDF PSS476 e XML corrispondente dal commit di accreditamento
`d937255fd7e9c079c5641c537da17fe98a2f2259`, entrambi verificati con hash, senza
riscrivere il PDF. Questa è una prova CDA separata, non un PASS FHIR.
`Status-Trace` è riservato a una necessità concreta di diagnosi/regressione.

## Esiti, ripresa e cleanup

- `VALIDATED`: successo upstream e mapping Gateway; non significa pubblicazione.
- `FOUND`: transazione trovata; `eventCount` indica gli eventi bounded restituiti.
- `NOT_FOUND`: esclusivamente il `record-not-found` allowlisted riconosciuto dal
  prodotto. Non dimostra un workflow completato.
- `FAILURE_CHECK_AUDIT`: interrogare Audit. Un generico 404 rimane failure; da solo
  non dimostra un problema di accreditamento. Audit mostra una sola success/failure e,
  quando disponibili, fase, HTTP upstream e codice allowlisted, mai body o detail.
- `DISPATCH_PENDING`: esito ancora non noto; leggere Audit, non reinviare alla cieca.
- `WORKFLOW_MISSING…`: manca il prerequisito; usare un workflow realmente restituito
  oppure valutare la validazione CDA consentita. Non c'è inserimento manuale nello store.
- Errori locali: controllare prerequisiti, stato/ruolo e codice stabile riportato.
  Se l'attivazione è scaduta prima dell'enrollment, fermare e riavviare il proprio
  stack; nessuna richiesta OfficialTest è necessaria per ripristinare il bootstrap.
  Anche una configurazione test già Published con valori organizzativi errati va
  ricreata in un nuovo stack temporaneo: non si sovrascrive la definizione immutabile.

Gli identificativi e l'ultimo risultato ridotto sono in
`.artifacts/m5/fse2-validation-status/fse2-last-call.json`; `fse2-build.json` lega
codice eseguito, immagine Gateway e provisioner. I file `raw` del bootstrap esistente
contengono solo identità locali temporanee e non sono evidence da pubblicare.
Non esportarli. Conservare soltanto il ledger ridotto prima dello Stop.

```powershell
& $runner -Phase Stop
```

Stop riusa ownership e cleanup M5: rimuove il solo stack posseduto, database temporaneo
e materiale locale temporaneo. Il root operativo A1/S1 resta invariato. La build
ignorata del provisioner può restare come cache locale non sensibile.

## Qualifica osservata il 4 settembre 2026

Codice eseguito live: `ac115fef76344dc4857204830b6badbc154a03d4`, su deployment
temporaneo pulito, configurazione Published e identità Direct normalmente enrolled.
Le successive modifiche di documentazione e la rinomina di un parametro C# per un
falso positivo Gitleaks non cambiano il comportamento e non richiedono altre richieste live.

| Percorso con configurazione corretta | HTTP upstream / Gateway | Risultato | Audit per invocation |
| --- | --- | --- | --- |
| FHIR RAP JSON, VERIFICA | 500 / 502, in due richieste intenzionali | `generic-error`; **non qualificato live** | 0 success, 1 failure |
| CDA PSS476, VERIFICA | 200 / 200 | `VALIDATED`, workflow e trace restituiti | 1 success, 0 failure |
| Workflow CDA dopo riavvio reale Gateway | 200 / 200 | `FOUND`, 1 evento bounded | 1 success, 0 failure |

Il secondo tentativo FHIR, dopo alcuni minuti, ha verificato la possibile
transitorietà del 500; non era un retry automatico. La fonte congelata documenta
questo formato JSON e non fornisce un PDF FHIR alternativo pronto all'uso. Il codice
allowlisted `generic-error` non identifica la causa: non dimostra un problema di
accreditamento, di formato o di autorizzazione. Non si dichiara PASS FHIR e non si
eseguono variazioni speculative.

Il workflow usato dallo status è quello realmente restituito dalla validazione CDA.
Il client nuovo invia soltanto `resourceIdentifier` e l'autenticazione ordinaria;
PostgreSQL conserva l'autorità della correlazione durante il riavvio del Gateway.
`FOUND` prova la consultazione con eventi, non pubblicazione né completamento clinico.

Totale della sessione di sviluppo: 7 invocation HTTP locali, 6 richieste FSE2 upstream.
La prima invocation locale si è fermata con 401 prima dell'autenticazione e senza
audit di operazione: il nuovo client ometteva `traceparent`, poi corretto e testato.
Due richieste upstream iniziali (FHIR/CDA) hanno dato 403 `jwt-validation` con il
dominio ASL errato nel modello, poi corretto dal profilo già qualificato. Un ulteriore
comando CDA si è fermato localmente sul controllo dataset, senza invocation: è stata
rimossa l'assunzione non pertinente che il caso CDA ufficiale avesse il prefisso FHIR
`PROVA`. Le altre quattro richieste sono quelle della tabella. I controlli Admin,
enrollment, salute e autenticazione locale non sono richieste FSE2 upstream.
Retry automatici, redirect, status-by-trace e pubblicazioni documentali: **zero**.

Verifica mirata: 28 test `Fse2PilotTests` / `Fse2ProvisionerResumabilityIntegrationTests`
passati; firma BGW1/traceparent, dataset congelati, comandi di pubblicazione negati,
riduzione senza raw, quattro grant e ripresa del provisioner. Le CI complete sono
associate al successivo HEAD finale della PR, senza duplicazione locale. Il ledger
di sessione conserva solo metadati e hash, non JWT, certificati operativi, documenti
o response body. Stop rimuove stack e bootstrap temporanei; il root A1/S1 non cambia.

Restano distinte la qualifica offline delle 14 route e questa qualifica live parziale
di validazione CDA/consultazione workflow. Nessuna conclusione su produzione,
accreditamento o pubblicazione deriva da questo percorso.

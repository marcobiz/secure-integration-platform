# Gate Review conclusiva M0/M1 e primo vertical slice

**Data:** 2026-08-03  
**Baseline congelata:** commit `7f68442ceb9adcc47bb1b1a534ad64e23bd26bac`  
**Tag annotato:** `baseline-m0-m1-vslice-2026-08-03`  
**Esito del gate:** **NO-GO per M2 finché i blocker live non sono chiusi**  
**IPC:** **provvisorio**, non congelato per COM/C ABI/CLI

Questa review usa `IMPLEMENTATION_STATUS.md` e il rapporto del vertical slice come baseline, ma registra soltanto evidenze aggiuntive, finding e decisioni di gate.

## 1. Cosa è stato realmente eseguito

### Baseline e clean checkout

- repository inizializzato e baseline committata/taggata prima delle modifiche di review;
- clone separato del tag in `.artifacts/gate-clean-clone`, detached su `7f68442`;
- nel clone: restore/build Release con SDK 10.0.302, zero warning/errori;
- nel clone: 6 unit, 9 integration e 1 E2E passati;
- validazione documenti e scansione contenutistica secret passate;
- trovato un difetto M0: `scan-secrets.ps1` poteva lasciare exit code 1 dopo un `rg` senza match pur stampando successo. Corretto nella review insieme all'exit esplicito del validator documentale.

Il clean checkout è stato eseguito sullo stesso host usando un SDK installato fuori dal clone: prova l'indipendenza dal working tree, non qualifica l'OS come macchina pulita.

### Hardening aggiunto durante la review

La review ha aggiunto test/controlli per:

- layout network del frame, magic/version/type/flags, EOF/troncamento e limiti esatti/oversize;
- handshake sequence e nonce malformato;
- nonce AES-GCM, AAD completa, malformed envelope e key version sconosciuta;
- delete idempotente, cross-Application e grant HMAC;
- ACL esplicite di pipe e storage;
- persistenza dopo riapertura dei repository;
- wire/error/audit redaction per normal path, autenticazione negata, payload invalido e failure crittografico;
- process creation time, chiusura del process handle e del file handle;
- protezione della race image/path mantenendo aperto il file eseguibile read-only per tutta la connessione;
- classificazione deterministica tra deadline, cancel client e shutdown;
- mapping redatto dei record storage con Base64 corrotta.

I quattro test critici IPC/identity/cancel/redaction sono passati in **20/20 iterazioni**, 80 esecuzioni complessive senza failure.

Sullo stato finale della review: build Release dell'intera solution con **0 warning/0 errori**; **26 unit + 14 integration + 1 E2E = 41/41 test passati**; documentation gate, secret scan, NuGet vulnerability scan e SBOM tutti passati.

## 2. Qualificazione dell'ambiente live

L'ambiente disponibile è:

| Proprietà | Valore osservato |
|---|---|
| OS | Windows 10 Pro 10.0.19045 |
| Tipo | workstation, non Windows Server |
| Sessione elevata | no |
| Hyper-V/Get-VM | non disponibile |
| Windows Sandbox executable | assente |
| Docker/Podman | non disponibile |
| Broker service preesistente | assente |

La lettura delle Windows optional features è stata rifiutata perché richiede elevazione. Non esiste quindi un percorso autorizzato e ripetibile per creare utenti locali, registrare un servizio, usare un virtual account o avviare una VM pulita. Una simulazione in-process non soddisferebbe gli obiettivi richiesti.

### Matrice live A–F

| Matrice | Evidenza live | Evidenza automatica sostitutiva disponibile | Esito gate |
|---|---|---|---|
| A — applicazione autorizzata | **NON ESEGUITA**: nessun servizio/legacy identity reale | pipe+SDK, operation grants, Protect/Unprotect, local secret/HMAC, repository reopen | OPEN-LIVE |
| B — processo non autorizzato stesso utente | **NON ESEGUITA** con processo distinto | wrong hash/publisher e operation grant denied; ACL storage descriptor | OPEN-LIVE |
| C — utente Windows differente | **NON ESEGUITA** | security descriptor pipe/storage verificato, ma stesso SID del testhost | OPEN-LIVE |
| D — account gestionale | **NON ESEGUITA** | API surface senza GetSecret/KEK/DEK e storage cifrato ispezionato | OPEN-LIVE |
| E — riavvio servizio | **NON ESEGUITO** | repository dispose/reopen recupera key, HMAC ed envelope; tamper/unknown version rifiutati | OPEN-LIVE |
| F — Windows Service logging | **NON ESEGUITO** | wire e audit sink in-memory redatti per quattro path | OPEN-LIVE |

Non sono stati creati utenti, servizi o ACL di sistema e quindi non esiste cleanup live da dichiarare.

Il transcript qualificato e la checklist dell'evidence pack sono in `docs/reviews/evidence/M0-M1-LIVE-MATRIX-EVIDENCE.md`.

### Evidenze richieste per chiudere il live gate

Su una VM snapshot/revert Windows supportata, con runner elevato:

1. pubblicare il Broker self-contained o installare il runtime pinned;
2. creare un account legacy e un account estraneo; registrare il servizio come `NT SERVICE\SecureIntegrationBroker`;
3. materializzare Installation ID univoco e manifest con SID/path/publisher/hash del simulatore;
4. catturare `sc.exe qc`, `Win32_Service.StartName`, token SID del processo servizio, SDDL pipe e `icacls` ProgramData;
5. eseguire A–F e conservare command transcript, exit code, Event Log export e hash degli artefatti;
6. ripristinare lo snapshot, evitando di conservare password/certificati di test.

## 3. Riesame mirato delle superfici critiche

### Framing e limiti IPC

Il frame a 36 byte, byte order, GUID, sequence, hard limit control 1 MiB e data frame 64 KiB sono testati ai bordi. Magic, major, type, flags, troncamento e unknown JSON falliscono chiusi. Handshake richiede control frame, sequence zero, correlation non vuota e nonce Base64 16–64 byte.

Finding residuo: i limiti aggregati dichiarati 16/64 MiB non sono implementati end-to-end; gli SDK request correnti usano Base64 nel control frame e hanno quindi capienza effettiva inferiore a 1 MiB. Questo blocca il freeze IPC, non l'avvio delle componenti centrali M2 con payload piccoli.

### Multiplexing e cancellation

Più richieste sulla stessa connessione, risposte potenzialmente fuori ordine, limite 16, deadline e Cancel frame sono implementati. La review ha separato esplicitamente cancel client, deadline e shutdown, eliminando una classificazione temporale flaky. Lo SDK apre ancora una connessione per chiamata.

### PID reuse, handle e race di autorizzazione

Il PID arriva da `GetNamedPipeClientProcessId`; il SID dal primary token del processo. Sono catturati creation time, canonical path, SHA-256 e publisher trusted. Process handle e file handle dell'eseguibile restano aperti fino alla chiusura della connessione; creation time viene ricontrollata. Il test verifica che entrambi gli handle siano chiusi da `Dispose`.

Questo riduce PID reuse e sostituzione path/image, ma non elimina code injection in un processo autorizzato né compromissione da amministratore. Manca un test deterministico che forzi PID reuse o replacement durante la finestra capture/authorize.

### ACL pipe/storage e DPAPI

Le security descriptor sono protette dall'ereditarietà e senza World grant. La pipe include service SID più SID applicativi configurati; storage include service identity corrente, SYSTEM e Administrators. I test automatici verificano la costruzione, non l'enforcement tra identità reali.

DPAPI usa `CurrentUser`, mai `LocalMachine`. La root effettiva della virtual service identity e il comportamento del suo profilo non sono stati osservati live: AC-002/004 restano aperti.

### AES-GCM, metadata e key versioning

- key 256 bit per Installation, nonce casuale 96 bit e tag 128 bit;
- AAD include protocol marker, Installation, Application, purpose e content type;
- envelope contiene key version; unknown version non prova fallback;
- tamper di tag/ciphertext, malformed envelope, key DPAPI corrotta e record secret corrotto sono rifiutati;
- 512 protezioni ripetute non hanno prodotto nonce duplicati.

Resta non atomica la scrittura di `active.txt` e manca il workflow operativo di rotation.

### Logging ed eccezioni

Le response IPC espongono solo code/category/retryable. Gli audit normal/denied/error usano operation/application/correlation e code sanitizzati; path, payload, Base64, stack ed exception type non vengono emessi. L'autenticazione negata produce ora un audit metadata-only.

Il test non copre il vero provider Windows Event Log, crash non gestiti o telemetry futura. Questo è parte del live blocker F.

## 4. Criteri AC-002 e AC-004

- **AC-002 — NON SODDISFATTO / blocker:** esistono host, install script e configurazione virtual account, ma non è stata osservata una vera istanza `SecureIntegrationBroker` con `StartName = NT SERVICE\SecureIntegrationBroker` e token/profile effettivi.
- **AC-004 — NON SODDISFATTO / blocker:** ACL e DPAPI CurrentUser passano nello stesso test account, ma non è provato che gestionale/altro utente non possano leggere storage o usare `CryptUnprotectData` sui blob prodotti dalla service identity.

La precedente qualificazione “parziale” non è sufficiente per questo gate conclusivo.

## 5. Decisioni aperte valutate, non implementate

| Tema | Decisione consigliata | Motivazione | Milestone/ADR | Blocca M2? |
|---|---|---|---|---|
| Upgrade application policy | Default `SID + canonical path + trusted publisher`; hash opzionale per pinning ad alta garanzia/emergenza. Vietare publisher-only senza file handle/chain policy. | Publisher permette upgrade controllati; hash-only è fragile; path/SID limitano scope. | Chiarire ADR-0016 entro M6, validare signed positive path in M9. | No per iniziare M2. |
| Recovery profilo virtual service identity | MVP: reinstall/re-enroll e perdita dichiarata dei soli dati locali non recuperabili; niente escrow universale della DPAPI root. Definire backup supportato solo se protegge l'intero profilo/host. | Evita una KEK globale e promesse di recovery non sostenibili. | Aggiornare ADR-0014 e ADR-0004 entro M9, prima del pilot. | No per sviluppo M2; blocca pilot/production. |
| Provisioning Installation ID/manifest via MSI | Installation ID random univoco generato una volta; config atomica sotto ACL; manifest validato e firmato/proveniente dal control plane; repair non rigenera ID. | AC-005 e M2 identity dipendono da identità stabile e non clonata. | ADR-0017 Accepted; implementazione MSI M9. | Il blocker documentale è chiuso; la conformità resta obbligatoria per identity integration M2. |
| API streaming adapter legacy | Mantenere frame Data/End sperimentali; definire backpressure, cancellation, ownership buffer e x86 limits solo dopo M2/M3. | Evita congelare ABI su assunzioni non validate end-to-end. | Aggiornare ADR-0003 durante M3, freeze in M6. | No. |
| Key rotation operativa | Active version atomica, retention delle versioni leggibili, rotazione amministrativa auditata e migrazione lazy; mai fallback silenzioso su versioni ignote. | Mantiene decryptability e rende rollback/recovery verificabili. | Estendere ADR-0004 prima di M7/M9. | No per M2. |

ADR-0017 è stato successivamente accettato e formalizza il provisioning MSI/Installation identity senza implementare M2. Le altre raccomandazioni restano pianificate nelle milestone indicate.

## 6. Stato IPC

Il protocollo corrente è **provvisorio/stabile solo per uso interno M1**. Non è “experimental throwaway”, perché framing e semantiche base hanno test regressivi; non è però “frozen”, perché mancano:

- aggregate streaming 16/64 MiB e backpressure;
- validazione con Installation identity/revocation M2;
- vertical slice M3 production-like;
- compatibility .NET Framework, x86, COM e C ABI;
- fuzzing stateful e long-running connection tests.

Nessun adapter M6 deve assumere ABI definitiva prima di questi gate.

## 7. Blocker per M2

1. **Matrice live A–F non eseguita su macchina pulita/VM elevata.**
2. **AC-002 non soddisfatto:** virtual service account non osservato live.
3. **AC-004 non soddisfatto:** separazione gestionale/service/altro utente e DPAPI cross-user non provate.
4. **Provider Windows Event Log non verificato live** sui failure path obbligatori.

Il precedente blocker documentale sul provisioning è chiuso da ADR-0017. È inoltre disponibile un harness idempotente in `tools/live-matrix` con runbook `docs/operations/M0-M1-LIVE-MATRIX-RUNBOOK.md`. La sua disponibilità rende ripetibile la chiusura dei blocker 1-4, ma non li chiude senza una run PASS su VM.

## 8. Non-blocker

1. SDK senza connessione persistente condivisa.
2. Authenticode positive test con chain sintetica controllata.
3. PID reuse/replacement fault injection dedicato.
4. CI remote non eseguita, purché venga resa obbligatoria prima del merge/release M2.
5. Recovery del profilo service identity, purché chiusa prima del pilot.

## 9. Debito rinviato

1. streaming aggregato e backpressure;
2. key rotation operativa e atomicità `active.txt`;
3. MSI install/repair/upgrade/uninstall e artifact signing;
4. .NET Framework, COM, C ABI e CLI;
5. fuzzing stateful, EventLog/telemetry corpus e performance soak;
6. Gateway/Vault/Installation identity production, intenzionalmente M2+.

## 10. Rischio residuo Administrator/SYSTEM

Local Administrator e SYSTEM possono leggere memoria, impersonare il servizio, cambiare ACL/policy, sostituire binari o acquisire il profilo DPAPI. M0/M1 non li considerano minacce pienamente mitigabili. ACL, DPAPI e process authorization proteggono da utenti/processi non privilegiati e da copie offline; non costituiscono una barriera contro il controllo amministrativo dell'host. Non vengono proposti driver, TPM obbligatorio, anti-debug o altri meccanismi sproporzionati.

## 11. Decisione finale

Il codice automatico M0/M1 è sufficientemente solido per continuare hardening e preparare la validazione, ma il gate richiesto **non è chiuso**. M2 non deve iniziare finché almeno i blocker 1–4 non hanno evidenze live firmate/archiviate e AC-002/004 non passano. Questa review non implementa alcuna funzionalità M2.

La matrice completa requisito/test/evidenza è in `docs/reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md`.

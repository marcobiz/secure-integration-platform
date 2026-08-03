# Gate Review conclusiva M0/M1 e primo vertical slice

**Data:** 2026-08-03  
**Baseline congelata:** commit `7f68442ceb9adcc47bb1b1a534ad64e23bd26bac`  
**Tag annotato:** `baseline-m0-m1-vslice-2026-08-03`  
**SUT baseline M0/M1:** `39ac4eae23d6a4c43729863ca345fdbf10af0ee6`

**Harness baseline:** `f33bf910b9f7c1f5b8a4ea47476c26f7c49c2170`

**Commit live testato:** `24288dbe065ecedc21c0018e8ed37ca844bc8caf`

**Esito del gate:** **NO-GO per M2: matrice live PASS, integrazione canonica pendente**

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

Sullo stato live finale: build Release dell'intera solution con **0 warning/0 errori**; **26 unit + 22 integration + 1 E2E = 49/49 test passati**; parsing PowerShell 5.1, `ValidateHarness`, documentation gate e secret scan passati.

## 2. Qualificazione dell'ambiente live

L'ambiente qualificato per la run live è:

| Proprietà | Valore osservato |
|---|---|
| OS | Windows 11 Pro 10.0.26200, build 26200 |
| Tipo | Microsoft Virtual Machine, UUID `864384BD-9128-4F51-A741-001485E7DF72` |
| Runner elevato | sì, verificato con `WindowsPrincipal.IsInRole(Administrator)` |
| PowerShell | Windows PowerShell 5.1.26100.7920, processo `-NoProfile` |
| Commit repository | `24288dbe065ecedc21c0018e8ed37ca844bc8caf` |
| RunId | `m0-m1-20260803-232955` |
| Reboot osservato | boot UTC `2026-08-03T21:38:33.1818970Z` |

Il runner elevato ha creato account locali distinti, installato il servizio con virtual account, applicato ACL reali e predisposto un task post-reboot eseguito come SYSTEM. Nessuna prova simulata è stata usata.

### Matrice live A–F

| Matrice | Evidenza live | Esito gate |
|---|---|---|
| A — applicazione autorizzata | pipe, grants, HMAC, Protect/Unprotect e persistenza | PASS-LIVE |
| B — processo non autorizzato stesso utente | processo/path distinto negato dalla policy; storage negato | PASS-LIVE |
| C — utente Windows differente | pipe, storage e DPAPI negati | PASS-LIVE |
| D — account gestionale | DB legacy cifrato leggibile; nessuna API per secret o key material | PASS-LIVE |
| E — restart e reboot | tamper envelope/key rifiutato, restore riuscito, HMAC e protected data persistenti | PASS-LIVE |
| F — Windows Service logging | Event Log reale presente e scansione di 11 canary senza leakage | PASS-LIVE |

Il servizio è rimasto installato e `Running` come stato finale osservabile del SUT. Il task post-reboot è stato rimosso automaticamente; il bundle e le run bloccate sono conservati in `C:\ProgramData\SecureIntegration\LiveMatrix`.

Il transcript qualificato e la checklist dell'evidence pack sono in `docs/reviews/evidence/M0-M1-LIVE-MATRIX-EVIDENCE.md`.

### Evidenze acquisite

Il bundle `M0-M1-live-matrix-m0-m1-20260803-232955.zip` contiene 24 file dichiarati nel manifest più il manifest stesso. Tutte le dimensioni e gli SHA-256 sono stati verificati; lo SHA-256 del ZIP è `5B6E9997EF0C5C482B27B7DB63323BA54C96D5C2B083DAAEB4A47255D156C52C` e coincide con il sidecar.

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

La run live copre il provider Windows Event Log sui path normal, denied, invalid payload, authentication failure e key unwrap failure. Crash non gestiti e telemetry futura restano debito non bloccante.

## 4. Criteri AC-002 e AC-004

- **AC-002 — PASS-LIVE sul commit testato:** istanza reale `SecureIntegrationBroker` osservata con `StartName = NT SERVICE\SecureIntegrationBroker`, service SID, restart SCM e persistenza post-reboot.
- **AC-004 — PASS-LIVE sul commit testato:** pipe/storage negati all'altro utente e DPAPI `CurrentUser` non sbloccabile dagli account autorizzato, same-user untrusted e altro utente.

Il risultato è attribuibile esclusivamente al commit `24288dbe065ecedc21c0018e8ed37ca844bc8caf` registrato nel manifest.

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

1. **Integrazione canonica pendente:** la run PASS è sul commit locale `24288dbe065ecedc21c0018e8ed37ca844bc8caf`; `origin/main` punta ancora a `f33bf910b9f7c1f5b8a4ea47476c26f7c49c2170`.

La lineage correttiva deve essere revisionata e integrata mantenendo esattamente lo SHA testato. Se l'integrazione usa squash, rebase o qualsiasi riscrittura, la matrice completa deve essere rieseguita sul nuovo commit da stato pulito. I precedenti blocker live A-F, AC-002, AC-004 ed Event Log sono chiusi per il commit testato.

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

La matrice tecnica M0/M1 è **PASS** e AC-002/AC-004 sono soddisfatti per il commit testato. La decisione operativa resta **NO-GO per M2** finché la medesima lineage non è revisionata e integrata nel branch canonico; se lo SHA cambia, serve una nuova run completa. Questa review non implementa né avvia alcuna funzionalità M2.

La matrice completa requisito/test/evidenza è in `docs/reviews/M0-M1-REQUIREMENTS-TEST-EVIDENCE.md`.

# M3A split-host — run bloccata 2026-08-05

RunId: `m3a-live-20260805-091023`

Commit candidato ed effettivamente eseguito nella VM:
`febd8b33201c9827e5e28fcfdd70db1c04d6fce6`.

Esito: **BLOCKED — HOST SECURITY DRIVER SCHANNEL INCOMPATIBILITY**.
La run non costituisce un PASS M3A e nessun suo activation code, certificato,
handoff o RunId può essere riutilizzato.

## Evidenza positiva ottenuta prima del blocco

Il percorso VM ha prodotto evidenze originali redatte coerenti e non ricostruite:

- Broker installato come vero Windows Service, stato `Running`;
- `StartName` `NT SERVICE\SecureIntegrationBroker` e service SID effettivo;
- Legacy Simulator eseguito come utente standard con token `Limited`;
- P02 Legacy → SDK → Named Pipe → Broker Service → Gateway → PostgreSQL 18 →
  synthetic Vault → vendor mock HTTPS/mTLS completato con risposta sanitizzata;
- applicazione locale non autorizzata negata;
- operation grant non concesso negato con `gateway_operation_not_granted`;
- nessun endpoint backend o vendor secret distribuito alla VM;
- Event Log e canary scan VM PASS;
- cleanup VM PASS con zero servizi, task e utenti sintetici residui.

Le quattro evidenze VM originali sono state trasferite fuori dal repository nel bundle
privato `m3a-live-20260805-091023-vm-redacted-recovered.zip`, SHA-256
`69432D0BA1FFF34FE551DE64FFA4A8DBFC47270C6E198F499F3B3E19DFC4FC22`.
Gli hash per-file sono stati verificati sull'HOST. Il bundle non sostituisce il bundle
finale HOST e non trasforma la run in PASS.

## Blocco HOST

Durante `Finalize`, `SecureIntegration.M3.SecurityDriver.exe` è terminato prima della
matrice negativa HOST. Il record `.NET Runtime` 1026 attesta:

`AuthenticationException: Authentication failed because the platform does not support ephemeral keys`.

La causa è il caricamento del certificato client sintetico tramite
`X509KeyStorageFlags.EphemeralKeySet`. Windows Schannel non può presentare quella chiave
come credenziale TLS client. Non sono quindi stati completati N01–N14, la correlazione
HOST, il canary scan complessivo e il bundle finale. Il wrapper di controllo ha registrato
`M3A_FINALIZE_FAILED` senza dichiarare PASS.

Il `Finalize` ha invocato il cleanup ufficiale nel proprio percorso di errore. La verifica
successiva ha rilevato zero container, volumi e network Docker della run, assenza
dell'adattatore `M3A-Isolated` e ripristino dei tre profili Firewall allo stato originario
disabilitato. Le evidenze esistenti non sono state cancellate.

## Correzioni

I commit `678aa07ca20802d342d00772c019b233869e7639` e
`2dd70e8` correggono e verificano esclusivamente il laboratorio:

1. il SecurityDriver usa `UserKeySet` su Windows, senza `PersistKeySet`, e conserva
   `EphemeralKeySet` sugli altri sistemi;
2. il packaging VM accetta esplicitamente il suffisso vuoto richiesto dall'archive di
   successo in Windows PowerShell 5.1;
3. regressioni statiche fail-closed impediscono il ritorno dei due difetti;
4. un integration test Windows esegue un handshake mTLS Schannel reale con certificato
   client importato tramite `UserKeySet`.

Nessun file di produzione Broker o Gateway è modificato. Prima di una nuova run sono
obbligatori CI verde sul commit correttivo, RunId/materiale sintetico nuovi e una nuova
finestra operativa. M3B e M4 restano non iniziati.

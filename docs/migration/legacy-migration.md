# Strategia di migrazione dei legacy

## Principio

Non riscrivere un'integrazione funzionante senza beneficio concreto. Individuare il punto in cui il legacy legge o usa un segreto, sostituirlo con una capability del Local Broker/Gateway e conservare il resto del flusso.

## Fasi per prodotto

1. Inventario segreti, certificati, token e chiavi dati.
2. Classificazione Vendor/Tenant/Operator/Session/Local Data Key.
3. Mappa dei punti di lettura, uso, log e persistenza.
4. Test di caratterizzazione con fixture sintetiche.
5. Decisione local/Gateway/hybrid.
6. Decisione Secure Layer/Managed Connector.
7. Definizione Application manifest e operation grants.
8. Implementazione del seam minimo.
9. Migrazione configurazioni e dati locali.
10. Test regressione e security negative path.
11. Rotazione/revoca dei segreti compromessi.
12. Rimozione del vecchio materiale e codice raggiungibile.
13. Blocco egress/bypass diretto.
14. Pilot, rollback plan ed evidence di completamento.

## Integration Seam Map

Template obbligatorio:

| Campo | Descrizione |
|---|---|
| Product/version | Prodotto e build analizzata. |
| Module/method | Punto di aggancio, senza copiare codice proprietario. |
| Source finding | Documento, finding ID e livello di certezza. |
| Secret class | Vendor/Tenant/Operator/Session/Local Data Key. |
| Current source | Config, binary, DB, user input, certificate store o log. |
| Target location | Broker/Vault/memory. |
| Execution | broker/gateway/hybrid. |
| Mode | Secure Layer/Managed Connector. |
| Replacement call | Operazione IPC/Connector. |
| Behavior test | Fixture e expected interaction. |
| Legacy removal | File/config/code/egress da eliminare. |
| Rotation/revocation | Azione esterna richiesta. |
| Residual risk | Rischio non eliminato. |
| Rollback | Percorso sicuro senza ripristinare secret compromesso. |

## Regole per scegliere la modalità

Secure Layer quando:

- il legacy costruisce correttamente SOAP/XML/JSON;
- la modifica può limitarsi a credential injection, mTLS, HMAC o token exchange;
- la logica dipende fortemente dalla UI/prodotto;
- è il primo utilizzo del protocollo.

Managed Connector quando:

- la stessa integrazione serve più prodotti/vendor;
- il protocollo cambia frequentemente;
- la normalizzazione centralizzata riduce duplicazioni;
- la logica tecnica è separabile dalla UI e dall'hardware locale.

Hybrid quando browser/MFA/firma sono locali e token exchange/chiamata sono centrali. Nuovi handoff non tipizzati richiedono ADR.

## Migrazione dei segreti

### Vendor Secret

1. Predisporre nuova versione nel Vault.
2. Creare SecretBinding.
3. Testare con Connector sintetico/test Environment.
4. Migrare il prodotto al Gateway.
5. Disabilitare egress diretto.
6. Revocare il vecchio valore distribuito.
7. Scansionare package, backup di release e log.

### Tenant Secret locale

1. Acquisizione tramite UI/utility autorizzata senza command line.
2. `PutLocalSecret` e ritorno opaque ref.
3. Aggiornare configurazione legacy con il ref, non il valore.
4. Rimuovere valore originario e backup temporanei.
5. Verificare ACL, offline use e deletion.

### Chiavi dati locali

- Nuovo formato versionato AES-GCM.
- Reader supporta vecchio e nuovo durante la finestra di migrazione.
- Scritture solo nel nuovo formato.
- Batch/lazy re-encryption con checkpoint e backup.
- Auth failure blocca uso del dato e produce diagnostica redatta.

## Characterization test

La specifica ricostruita dai report/decompilazione viene trasformata in test black-box:

- ordine chiamate;
- method/path/header names sanificati;
- formato payload con valori sintetici;
- token/session lifetime e handoff;
- error mapping;
- retry/idempotency osservati.

Ogni test conserva provenance e livello di certezza, non codice decompilato.

## Rollback

Rollback non significa ripristinare credenziali già compromesse. Opzioni ammesse:

- rollback ConnectorVersion mantenendo il Gateway;
- rollback applicativo a una build che usa comunque il Broker;
- sospensione dell'operation;
- fallback manuale autorizzato del servizio esterno.

Riattivare secret hardcoded, trust-all o egress diretto è vietato.

## Criterio di finding risolto

Un finding non è chiuso se:

- il secret resta nel package/config/log;
- il vecchio codice è raggiungibile;
- l'Application può bypassare Broker/Gateway;
- l'egress diretto è ancora consentito;
- certificato/secret precedente non è revocato;
- i test non coprono negative path e regressione.

## Pilot acceptance pack

- Integration Seam Map firmata/reviewata.
- Test behavior/regression/security.
- Evidence di secret removal e scanning.
- Evidence di rotation/revocation.
- Network/egress evidence.
- Rollback test.
- Residual risk acceptance.
- Runbook support e incident response.


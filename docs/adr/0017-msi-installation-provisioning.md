# ADR-0017: Provisioning MSI dell'identità Installation

**Stato:** Accepted
**Data:** 2026-08-03

## Contesto

L'identità di una Installation deve essere unica per host e deve sopravvivere a repair e upgrade senza essere condivisa tra installazioni. Il package MSI, invece, è un artefatto replicabile e distribuibile: incorporare nel package un Installation ID definitivo, una chiave privata, un activation code o altro materiale segreto clonerebbe l'identità su più macchine e trasformerebbe la supply chain in un canale di distribuzione di credenziali.

L'installazione viene eseguita con privilegi amministrativi, mentre la root crittografica deve appartenere al Broker eseguito come virtual service identity. La semantica di install, repair, upgrade, uninstall e reinstall deve quindi distinguere gli artefatti di prodotto dallo stato per-host.

## Decisione

### Artefatti MSI e manifest prodotto

- L'MSI di release è firmato Authenticode e contiene un **manifest prodotto firmato** con firma CMS separata, verificabile anche dal Broker dopo l'installazione.
- Il manifest contiene soltanto dati di prodotto: product identifier, versione, compatibility range, schema version, identità dei publisher ammessi e hash degli artefatti distribuiti. Il suo hash e la sua firma sono riportati nel release manifest.
- La firma viene verificata durante install/upgrade e nuovamente prima che il Broker accetti il manifest. In produzione sono accettate soltanto catene/publisher previsti dalla policy di release; i build di test usano una trust root di test esplicita e non promuovibile.
- MSI, transform, response file e manifest non contengono segreti, activation code, chiavi private, credenziali né un Installation ID definitivo. Tali valori non devono essere passati come proprietà MSI o comparire nei log di Windows Installer.
- L'MSI installa binari, configurazione non sensibile, manifest prodotto, servizio e ACL. Non genera l'identità Installation in una custom action privilegiata.

### Primo avvio sotto la service identity

Al primo avvio valido, il Broker in esecuzione come virtual service identity:

1. verifica firma, schema e compatibility del manifest prodotto;
2. verifica che storage e key container abbiano le ACL attese;
3. genera un Installation ID casuale univoco mediante CSPRNG;
4. genera una coppia ECDSA P-256 nel provider Windows CNG;
5. marca la chiave privata come non esportabile e ne limita l'accesso alla service identity, ferma restando la capacità residua di SYSTEM/Local Administrator;
6. persiste in modo atomico il record locale che associa Installation ID, nome della chiave CNG, public key, versione dello schema e stato di enrollment.

Installation ID e public key non sono segreti, ma sono dati di integrità e restano nello storage protetto del Broker. La chiave privata non viene esportata, serializzata nel filesystem applicativo o restituita tramite IPC.

L'inizializzazione è idempotente. Un crash prima del commit lascia uno stato riconoscibile e ripetibile; un record incompleto o incoerente non viene interpretato come una nuova Installation. Dopo l'avvio dell'enrollment, la perdita di ID o chiave produce un errore fail-closed e richiede il percorso di recovery/reinstall, senza rigenerazione silenziosa.

Le immagini VM devono essere sigillate prima del primo avvio del Broker. Clonare una macchina già inizializzata non è un metodo supportato di provisioning.

### Enrollment futuro

L'enrollment previsto da ADR-0008 usa un activation code casuale monouso e proof-of-possession della chiave CNG. L'activation code viene fornito a runtime tramite un flusso amministrativo dedicato, mai mediante MSI, command line pubblica, transform o file persistente non protetto.

Un enrollment riuscito lega lato Gateway l'Installation ID alla public key dimostrata. Reinstallazione e perdita della chiave generano una nuova identità e richiedono un nuovo activation code. La revoca della precedente Installation è un'operazione esplicita del control plane e non viene presunta dall'uninstall locale.

### Semantica del ciclo di vita MSI

| Operazione | Identità e stato | Comportamento obbligatorio |
|---|---|---|
| **Install** | Nessuna identità nel package. | Installa artefatti firmati, servizio e ACL. Il primo avvio del Broker crea una sola volta Installation ID e chiave CNG sotto la service identity. Un rollback MSI rimuove gli artefatti creati dall'installazione fallita senza lasciare un'identità utilizzabile a metà. |
| **Repair** | Preserva Installation ID, chiave CNG, stato DPAPI ed enrollment. | Ripristina/verifica binari, manifest e ACL. Non genera una nuova identità e non tenta enrollment. Stato identity mancante o incoerente causa health failure esplicita e richiede recovery o reinstallazione. |
| **Upgrade** | Preserva Installation ID, chiave CNG, dati protetti ed enrollment. | Accetta soltanto MSI/manifest firmati e compatibili. Le migrazioni di stato sono versionate, atomiche e rollback-aware. Un major upgrade non deve attivare la pulizia identity prevista per un uninstall autonomo. Downgrade incompatibili sono rifiutati. |
| **Uninstall** | Revoca solo lo stato locale; non implica revoca centrale. | Arresta e rimuove il servizio, quindi elimina Installation ID, private key CNG, materiale DPAPI, secret locali e stato di enrollment. Eventuali audit redatti seguono la retention operativa definita. L'eliminazione fisica sicura su SSD non è garantita; la protezione si basa su crittografia e distruzione delle chiavi. Failure di cleanup viene segnalata e non è riportata come successo completo. |
| **Reinstall** | Crea una nuova Installation. | Dopo un uninstall completo, il primo avvio genera nuovo Installation ID e nuova coppia CNG e richiede un nuovo activation code. Non recupera automaticamente l'identità precedente. Residui incoerenti bloccano il provisioning finché non viene eseguito un recovery/cleanup esplicito. |

Repair e upgrade sono gli unici percorsi che preservano automaticamente l'identità. Backup/restore e recovery seguono ADR-0014 e non possono rendere esportabile la chiave privata.

## Invarianti verificabili

- Due installazioni dello stesso MSI producono Installation ID e public key differenti.
- Package, manifest e log MSI non contengono Installation ID definitivo, activation code o materiale privato.
- La private key CNG non è esportabile e viene creata dal processo Broker sotto la virtual service identity.
- Repair e upgrade non cambiano Installation ID o public key.
- Reinstall dopo uninstall produce valori differenti e torna allo stato non enrolled.
- Firma o compatibility del manifest non valide, ACL troppo permissive e stato identity corrotto causano un fallimento esplicito.
- Nessuna operation IPC restituisce private key, KEK, DEK, materiale DPAPI o activation code.

Queste invarianti devono essere coperte dalla matrice installer/live Windows prima della release production. L'ADR definisce il contratto richiesto dall'integrazione identity; non implementa M2 né anticipa l'installer hardening di M9.

## Conseguenze

- Un singolo MSI può essere distribuito su più host senza clonare credenziali.
- La chiave nasce nel corretto security context e non attraversa il processo MSI o il gestionale.
- Repair e upgrade sono trasparenti per l'identità; uninstall/reinstall richiedono una nuova enrollment ceremony.
- Il manifest firmato protegge origine e integrità della configurazione di prodotto, non la sua riservatezza.
- La perdita del profilo della service identity o della chiave CNG può rendere irrecuperabili dati locali e richiede re-enrollment, coerentemente con ADR-0004 e ADR-0014.
- Local Administrator e SYSTEM restano capaci di compromettere servizio, ACL o key store; non sono considerati minacce pienamente mitigabili dal package.

## Milestone

- **Prima dell'integrazione identity M2:** il modello dati e il protocollo di enrollment devono rispettare questo contratto.
- **M2:** enrollment con activation code monouso e proof-of-possession, senza implementare scorciatoie MSI.
- **M9:** implementazione e validazione completa di install, repair, upgrade, rollback, uninstall/reinstall, signing di produzione e installer matrix.

## Alternative escluse

- Installation ID pre-generato o definitivo nell'MSI: clonerebbe l'identità tra host.
- Activation code o secret come proprietà MSI/transform: esporrebbe il valore a log, process inspection e sistemi di software distribution.
- Chiave privata importata dal package, condivisa o esportabile: eliminerebbe la proof-of-possession per-host.
- Generazione della chiave in una custom action amministrativa: collocherebbe la chiave nel security context errato e allargherebbe l'accesso.
- Rigenerazione automatica durante repair o upgrade: romperebbe enrollment, decryptability e correlazione audit.
- Riutilizzo automatico dell'identità dopo reinstall: renderebbe ambigua la revoca e favorirebbe il ripristino non autorizzato di state copiato.

## Relazioni

- ADR-0004 definisce DPAPI CurrentUser, CNG non esportabile e protezione locale.
- ADR-0008 definisce identità, proof-of-possession, mTLS e rinnovo.
- ADR-0014 definisce i limiti di recovery della service identity.
- ADR-0016 definisce l'identificazione dei processi applicativi e l'uso dei manifest locali.

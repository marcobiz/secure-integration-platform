# ADR-0029: provider PKCS#12 locale per laboratori offline

**Stato:** Accepted

## Contesto

Il quickstart open source deve poter qualificare il Gateway e il Connector Runtime senza un
account cloud. Il provider sintetico copre i flussi funzionali, ma non prova il caricamento di
identità X.509 server-owned con chiave privata, la firma RS256 mediante S1 e l'uso mTLS di A1.
Inserire PEM, P12, password, locator o fingerprint reali nel repository violerebbe il confine dei
segreti; rendere Azure obbligatorio eliminerebbe invece la proprietà locale del quickstart.

## Decisione

- `packs/deployment/local-pkcs12` è un deployment pack opzionale e dipende soltanto dai contratti
  provider-neutral. Core, immagine Gateway predefinita e quickstart predefinito non dipendono dal
  pack.
- Il pack accetta un manifest server-owned a schema chiuso e una directory di materiale montata
  read-only. I riferimenti runtime sono URI logici exact-match; il caller non seleziona path,
  file, password, certificato o chiave.
- Leaf, chain, fingerprint, SPKI e versione sono vincolati nel manifest. I P12 vengono caricati
  con `EphemeralKeySet`; il pack espone soltanto certificato client, metadata/materiale pubblico e
  operazioni di firma bounded. Prima di ogni firma e di ogni restituzione del certificato client
  rilegge manifest, P12, leaf e chain, exact-matching versione/ruolo/fingerprint/SPKI/byte della
  chain; verifica ordine leaf-first e firme con `CustomRootTrust`, root pinned esatta, download AIA
  disabilitato e nessun fallback al trust store ambientale. L'operazione usa soltanto gli oggetti
  già caricati e verificati in memoria. Non esiste export della chiave privata.
- Il pack non offre secret retrieval generico e dichiara `SecretValues=false`. Lo slot
  `ISecretValueProvider` richiesto dal factory contract è deny-only, non risolve path e non accede al
  filesystem; il Gateway provider-neutral non richiede la capability secret a un pack che espone
  il certificato client richiesto.
- A1 e S1 sono risorse distinte. Il ruolo A1 richiede `clientAuth` e `DigitalSignature`; S1 è una
  risorsa di firma RSA e la policy Published FSE2 continua a imporre separatamente
  `ContentCommitment` nei due slot.
- L'importer è offline e fail-closed. La modalità predefinita verifica la firma dei due CSR e il
  triple binding exact-SPKI `key ↔ CSR ↔ leaf`, oltre a fingerprint, trust, ruoli e distinzione
  A1/S1, prima di creare output. Sorgenti, output e temp devono essere path assoluti locali esterni
  al repository, senza UNC/device/ADS/reparse point in alcun ancestor; target e identity del parent
  sono ricontrollati prima delle letture, scritture, ACL e cleanup. La creazione richiede `-Execute`,
  fingerprint attese out-of-band, runtime principal risolvibile e directory nuova. Produce password
  casuali indipendenti e ACL exact: inheritance disabilitata, SYSTEM/Administrators FullControl e
  runtime identity read/execute minimo, senza FullControl interattivo residuo non necessario.
- L'overlay Compose FSE2 è opt-in. Non pubblica un profilo, non invoca endpoint FSE2 e non cambia il
  quickstart ordinario. Il container resta non-root/read-only e riceve il materiale esclusivamente
  tramite bind mount read-only.
- Il profilo è destinato a sviluppo, demo e qualifica test controllata. Non sostituisce HSM/KMS,
  revocation monitoring, rotation, backup o custody di produzione.

## Conseguenze

La demo tecnica locale può attraversare la stessa superficie provider usata dal Gateway reale
senza Azure e senza inserire materiale riutilizzabile in Git. Il nuovo Dockerfile entra
nell'inventario supply-chain, nei build exact-head, nello scan segreti e nello SBOM. Import e call
live restano gate operativi separati e richiedono un mandato esplicito dopo review.

Administrator/SYSTEM e un operatore che riottenga accesso privilegiato alla directory esterna
restano nella TCB. Un bind
mount non è un HSM: durante una firma la chiave esiste nella memoria del processo e un host
privilegiato può osservarla. La difesa contro sostituzioni usa ACL, path senza link, fingerprint e
SPKI. Le operazioni private riducono la finestra rileggendo e validando lo snapshot completo nello
stesso uso, ma un compromesso privilegiato del processo/host resta rischio residuo del laboratorio.

## Alternative escluse

- Commit di PEM/P12/password o fingerprint operative nel repository.
- Uso del provider sintetico come prova di import/custody reale.
- Dipendenza obbligatoria da Azure per il quickstart open source.
- Selezione di file o chiavi dal Connector Published o dalla request caller-owned.
- Rilassamento globale del signer o inferenza FSE2 nel Core.
- Dichiarare il profilo locale equivalente a un provider HSM/KMS di produzione.

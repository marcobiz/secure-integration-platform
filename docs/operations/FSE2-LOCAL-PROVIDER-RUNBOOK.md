# FSE2 local PKCS#12 provider runbook

## Scopo e limite

Questo runbook abilita un laboratorio locale con PostgreSQL, Gateway/Admin UI, Connector Runtime,
Synthetic Provider e il pack FSE2. Aggiunge un provider file-mounted per A1 mTLS e S1 signing senza
richiedere Azure. Non accredita l'installazione, non pubblica automaticamente un Connector FSE2 e
non effettua chiamate live.

Certificati, chiavi, CSR, P12, password, manifest runtime ed evidenze devono restare fuori dal
repository. Le estensioni sensibili sono già negate da `.gitignore`, ma questo non sostituisce ACL
e controllo operatore.

## Prerequisiti

- Docker Desktop con Compose;
- Windows PowerShell 5.1;
- OpenSSL 1.1.1 o successivo;
- A1, CSR A1, chiave A1, S1, CSR S1, chiave S1 e trust anchor ufficiale in una directory protetta
  esterna a Git, soltanto quando esiste un mandato operativo separato;
- fingerprint SHA-256 attese di A1, S1 e trust anchor ottenute da un canale autorizzato;
- directory di output nuova, esterna al repository.

Il processo non supporta chiavi sorgente cifrate in modo interattivo: evita prompt e fallisce. Le
chiavi sorgente ricevute restano temporanee e devono essere eliminate o archiviate secondo la
policy di custody solo dopo aver verificato import, backup e rollback.

## 1. Preflight read-only

La modalità predefinita non crea output. Verifica crittograficamente la firma dei CSR, exact SPKI
`key ↔ CSR ↔ certificate`, fingerprint, distinzione A1/S1, chain diretta alla root fornita, validità
temporale e Key Usage/EKU. Tutti i path devono essere assoluti, locali, esterni al repository e
senza UNC, device path, ADS, junction/symlink/reparse point nel leaf o negli ancestor.

```powershell
$arguments = @{
  AuthCertificatePath = 'C:\SecureInput\A1.pem'
  AuthPrivateKeyPath = 'C:\SecureInput\AUTH.key'
  AuthCsrPath = 'C:\SecureInput\AUTH.csr'
  SignCertificatePath = 'C:\SecureInput\S1.pem'
  SignPrivateKeyPath = 'C:\SecureInput\SIGN.key'
  SignCsrPath = 'C:\SecureInput\SIGN.csr'
  TrustAnchorPath = 'C:\SecureInput\ministero-test-root.pem'
  ExpectedAuthFingerprintSha256 = '<64 hex ottenuti out-of-band>'
  ExpectedSignFingerprintSha256 = '<64 hex ottenuti out-of-band>'
  ExpectedTrustAnchorFingerprintSha256 = '<64 hex ottenuti out-of-band>'
  OutputDirectory = 'C:\SecureRuntime\fse2-local'
  RuntimePrincipal = 'NT SERVICE\SecureIntegrationGateway'
}
./tools/fse2/New-Fse2LocalPkcs12Material.ps1 @arguments
```

L'esito richiesto è `PASS_READ_ONLY_PREFLIGHT` e `outputCreated=false`. Un mismatch non va corretto
abbassando il controllo: occorre verificare la provenienza del materiale.

## 2. Creazione del materiale runtime

Solo dopo review del preflight:

```powershell
./tools/fse2/New-Fse2LocalPkcs12Material.ps1 @arguments -Execute -Confirm:$false
```

L'importer crea una directory con ACL ristrette, manifest con sidecar SHA-256, due P12 con password
casuali indipendenti, leaf A1/S1 e trust anchor pubblico. Non stampa password o chiavi. Verificare
che `status=PASS_CREATED`, `privateKeysExportedByProvider=false` e `liveFse2Calls=0`.

Su Windows `RuntimePrincipal` deve risolvere a un account utente o service SID specifico; Everyone,
Anonymous, Authenticated Users, Users, Administrators e gruppi non esplicitamente autorizzati sono
negati. Le ACL finali sono protette ed exact: SYSTEM/Administrators FullControl e runtime identity
soltanto Read/Execute sulle directory e Read sui file. Su Linux si usa un utente/`uid:N` non-root,
owner runtime, directory `0550` e file `0440`. Per Docker Desktop il laboratorio sintetico mappa
l'UID container dichiarato da `FSE2_CONTAINER_RUNTIME_UID`; ciò dimostra solo leggibilità bounded
del bind mount locale e non equivale a HSM, Key Vault o storage production-grade.

Il manifest e la directory `material` costituiscono materiale operativo sensibile anche se alcuni
file sono pubblici. Non copiarli nella repo, negli artifact CI o nei log.

## 3. Validazione e avvio

```powershell
$manifest = 'C:\SecureRuntime\fse2-local\manifest.json'
$material = 'C:\SecureRuntime\fse2-local\material'
$labArtifacts = 'C:\SecureEvidence\fse2-lab-per-run'

./tools/fse2/Invoke-Fse2LocalProviderLab.ps1 `
  -Phase Validate -ProviderManifestPath $manifest -MaterialDirectory $material

./tools/fse2/Invoke-Fse2LocalProviderLab.ps1 `
  -Phase Start -ProviderManifestPath $manifest -MaterialDirectory $material `
  -QuickstartArtifactRoot $labArtifacts
```

Se il pinned SDK non è sotto `.dotnet` nel worktree e non è il `dotnet` di sistema, indicare
esplicitamente il relativo eseguibile con `-DotNetPath`.

`Validate` ripete build/test del pack e richiama l'unico validator Compose canonico, con valori
sintetici process-local non stampati e senza `--no-interpolate`. `Start` usa l'overlay opt-in
`deploy/fse2/docker-compose.fse2-local.yml`, verifica utente non-root, filesystem read-only, mount
read-only, presenza dei due pack e health live/ready via TLS con CA sintetica. Il quickstart
ordinario resta invariato. La fixture canonica per-run è:

```powershell
./tools/fse2/Test-Fse2PathPolicy.ps1
./tools/fse2/Test-Fse2LocalPkcs12Material.ps1 -ValidateCompose -StartLab
```

Questa genera soltanto key/CSR/certificati/P12 sintetici per-run, prova firma e certificato client,
tamper con `live=200`/`ready=503`, stop degradato e cleanup; rimuove fixture e artefatti temporanei.

La presenza dei pack e delle identità non autorizza un outbound reale. Pubblicazione del profilo,
endpoint ufficiale, grant e invocazione FSE2 richiedono un piano e un mandato separati con evidenza
redatta.

## 4. Arresto e cleanup

```powershell
./tools/fse2/Invoke-Fse2LocalProviderLab.ps1 -Phase Stop
```

`Stop` non legge né richiede manifest, P12, chain, password, env file o readiness. Enumera soltanto
container, network e volume con label project exact-match, riverifica l'ownership di ciascun target,
li rimuove e deve restituire `FSE2_LOCAL_PROVIDER_STOP_PASS` con container/network/volume/helper a
zero. Una risorsa con nome simile ma project label diversa deve essere preservata. Conservare solo
manifest di evidenza redatti fuori Git; non includere P12, password, chiavi, token, header o payload.

## Criteri prima di una call live

- review indipendente del candidate exact-head;
- fingerprint e chain riesaminate prima dell'import;
- binding server-owned: A1 soltanto mTLS, la stessa S1 per authorization e integrity;
- endpoint/profilo Published approvati four-eyes e exact checksum;
- piano revoca/rotazione, logging redatto e cleanup;
- autorizzazione esplicita alla chiamata e perimetro dell'accreditamento.

Il profilo locale resta inadatto alla custody production: Administrator/SYSTEM e chi controlla la
directory host possono leggere o sostituire il materiale, e la chiave è in memoria durante l'uso.
La remediation e i suoi test usano esclusivamente fixture sintetiche: nessun certificato/CSR/chiave
reale è stato consultato, nessun P12 reale è stato creato o importato e nessun endpoint FSE2 è stato
chiamato. Custody operativa, revoca/rotazione, accreditamento e qualifica live restano blocker esterni.

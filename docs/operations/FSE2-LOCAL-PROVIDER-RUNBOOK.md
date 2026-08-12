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
- A1, chiave A1, S1, chiave S1 e trust anchor ufficiale in una directory protetta esterna a Git;
- fingerprint SHA-256 attese di A1, S1 e trust anchor ottenute da un canale autorizzato;
- directory di output nuova, esterna al repository.

Il processo non supporta chiavi sorgente cifrate in modo interattivo: evita prompt e fallisce. Le
chiavi sorgente ricevute restano temporanee e devono essere eliminate o archiviate secondo la
policy di custody solo dopo aver verificato import, backup e rollback.

## 1. Preflight read-only

La modalità predefinita non crea output. Verifica fingerprint, key/certificate SPKI, distinzione
A1/S1, chain diretta alla root fornita, validità temporale e Key Usage/EKU.

```powershell
$arguments = @{
  AuthCertificatePath = 'C:\SecureInput\A1.pem'
  AuthPrivateKeyPath = 'C:\SecureInput\AUTH.key'
  SignCertificatePath = 'C:\SecureInput\S1.pem'
  SignPrivateKeyPath = 'C:\SecureInput\SIGN.key'
  TrustAnchorPath = 'C:\SecureInput\ministero-test-root.pem'
  ExpectedAuthFingerprintSha256 = '<64 hex ottenuti out-of-band>'
  ExpectedSignFingerprintSha256 = '<64 hex ottenuti out-of-band>'
  ExpectedTrustAnchorFingerprintSha256 = '<64 hex ottenuti out-of-band>'
  OutputDirectory = 'C:\SecureRuntime\fse2-local'
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

Il manifest e la directory `material` costituiscono materiale operativo sensibile anche se alcuni
file sono pubblici. Non copiarli nella repo, negli artifact CI o nei log.

## 3. Validazione e avvio

```powershell
$manifest = 'C:\SecureRuntime\fse2-local\manifest.json'
$material = 'C:\SecureRuntime\fse2-local\material'

./tools/fse2/Invoke-Fse2LocalProviderLab.ps1 `
  -Phase Validate -ProviderManifestPath $manifest -MaterialDirectory $material

./tools/fse2/Invoke-Fse2LocalProviderLab.ps1 `
  -Phase Start -ProviderManifestPath $manifest -MaterialDirectory $material
```

Se il pinned SDK non è sotto `.dotnet` nel worktree e non è il `dotnet` di sistema, indicare
esplicitamente il relativo eseguibile con `-DotNetPath`.

`Validate` ripete build/test del pack e valida la composizione. `Start` usa l'overlay opt-in
`deploy/fse2/docker-compose.fse2-local.yml`, verifica utente non-root, filesystem read-only e
presenza dei due pack. Il quickstart ordinario resta invariato.

La presenza dei pack e delle identità non autorizza un outbound reale. Pubblicazione del profilo,
endpoint ufficiale, grant e invocazione FSE2 richiedono un piano e un mandato separati con evidenza
redatta.

## 4. Arresto e cleanup

```powershell
./tools/fse2/Invoke-Fse2LocalProviderLab.ps1 `
  -Phase Stop -ProviderManifestPath $manifest -MaterialDirectory $material
```

Lo stop deve restituire `FSE2_LOCAL_PROVIDER_STOP_PASS`. Verificare zero container, network e
volumi del progetto. Conservare solo manifest di evidenza redatti fuori Git; non includere P12,
password, chiavi, token, header o payload.

## Criteri prima di una call live

- review indipendente del candidate exact-head;
- fingerprint e chain riesaminate prima dell'import;
- binding server-owned: A1 soltanto mTLS, la stessa S1 per authorization e integrity;
- endpoint/profilo Published approvati four-eyes e exact checksum;
- piano revoca/rotazione, logging redatto e cleanup;
- autorizzazione esplicita alla chiamata e perimetro dell'accreditamento.

Il profilo locale resta inadatto alla custody production: Administrator/SYSTEM e chi controlla la
directory host possono leggere o sostituire il materiale, e la chiave è in memoria durante l'uso.

# M3 — schema delle evidenze redatte

Il bundle M3 è una prova riproducibile, non un archivio dei dati grezzi. Il manifest JSON
usa proprietà ordinate e contiene:

- `schemaVersion`, `runId`, `environment` (`M3A`, `M3A-CI` o `M3B`) e `scope`;
- `commitSha`, `m2BaselineTag`, `startedAtUtc`, `completedAtUtc`;
- digest SHA-256 di immagini e migration; il digest del bundle è nel sidecar esterno per
  evitare un riferimento circolare;
- identità pubbliche (SID service/account o resource ID Managed Identity), mai token;
- lista scenario con ID, stato e codice osservato; durata ed evidence file sono richiesti
  per i gate live M3A/M3B e facoltativi nel sotto-gate `M3A-CI`;
- contatori Vault/mock/DB prima e dopo i negative path;
- esito canary scan e cleanup verificato prima della finalizzazione;
- tool/runtime versions.

File ammessi: manifest, report Markdown, JUnit/TRX senza payload, ACL/config pubblica,
query di audit metadata-only, SBOM, digest e sidecar. File vietati: chiavi private, PFX,
activation code, API key, body raw, DPAPI blob, token, environment dump, EVTX non redatto,
core dump e log non redatti.

La redazione sostituisce valori con identificatori stabili (`[REDACTED:<kind>]`) e poi
esegue una ricerca byte-for-byte delle undici canary originali. Il bundle è creato solo
dopo tale ricerca e il suo hash viene calcolato su byte finali immutabili.

# Definition of Done

## Story DoD

Una story è Done solo se:

- implementazione e test sono completi;
- build locale e CI sono verdi;
- analyzer/security warning sono risolti o motivati con scadenza;
- contratti, schema, esempi e documentazione sono aggiornati insieme;
- negative authorization/security path sono testate;
- log ed errori sono verificati per assenza di secret/PII;
- dependency e secret scan sono verdi;
- fixture esclusivamente sintetiche;
- compatibility/backward impact è documentato;
- migration e rollback sono definiti quando necessari;
- ADR/threat model sono aggiornati se cambia una decisione;
- review tecnica e security review proporzionata al rischio sono completate;
- requirement/test/evidence sono collegati nella matrice di tracciabilità.

## Milestone DoD

- Tutte le story P0 della milestone rispettano la Story DoD.
- Artefatto installabile/eseguibile prodotto dalla pipeline.
- Integration/E2E test della milestone verdi.
- Runbook minimo e diagnostica disponibili.
- Nessun bypass noto lasciato aperto nell'ambito dichiarato.
- Rischi residui e differenze dal piano documentati.
- Demo ripetibile con servizi mock e nessuna credenziale reale.

## Release DoD tecnica

- Tutti gli AC applicabili superati.
- MSI install/upgrade/repair/uninstall testato.
- Container avviabile, health/readiness e graceful shutdown verificati.
- Migrations e restore testati.
- SDK/adapter e sample inclusi.
- OpenAPI, IPC e Connector schema versionati e pubblicati.
- Source build instructions verificate da clean environment.
- SBOM, release manifest e artifact hashes allegati.
- Artefatti firmati o, nella build comunitaria, signature hooks verificati con certificati sintetici.

## Release DoD security

- Threat model aggiornato e reviewato.
- Secret/SAST/dependency/container scan verdi o risk-accepted.
- Security E2E e fuzz corpus regressivo verdi.
- Cross-Tenant, revocation, SSRF, replay e redaction test verdi.
- Plugin/package signature e tamper test verdi.
- Penetration test per release production e finding critici/alti chiusi o formalmente accettati.
- Nessun Vendor Secret in client, database o log.

## Pilot DoD

- Integration Seam Map completa.
- Segreti legacy ruotati/revocati.
- Vecchi file/config/log sanificati.
- Bypass e direct egress disabilitati.
- Regression/security/rollback test completati.
- Operations e support formati sul runbook.
- Residual risk accettato dal responsabile autorizzato.


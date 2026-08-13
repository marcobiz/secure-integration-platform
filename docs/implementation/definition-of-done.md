# Definition of Done

Aggiornato: 2026-08-13

La DoD è proporzionata allo scope e alla classe di evidenza. Una developer alpha o un
gate sintetico non può essere presentato come official-test o production.

## Change/Story DoD

Una story è Done solo quando:

- comportamento richiesto e negative case pertinenti sono implementati;
- build e test nominativi della superficie modificata passano;
- authorization, provider e Core/pack boundary restano fail-closed;
- quando una modifica introduce o cambia una decisione architetturale durevole, l'ADR
  pertinente viene aggiunto o aggiornato; non è richiesto un ADR per ogni modifica;
- quando cambia la superficie di minaccia, un trust boundary, una capability sensibile o
  una mitigazione security, il threat model viene aggiornato e i cambiamenti
  security-sensitive conservano test positivi e negativi proporzionati;
- migration, OpenAPI, generated client, schema ed esempi sono sincronizzati quando
  applicabili;
- log, Problem Details, audit ed evidence sono verificati per assenza di secret, token,
  cookie, authorization header, payload sensibili e stack trace;
- documentazione e traceability distinguono CURRENT, TARGET e HISTORICAL e non
  sovrastimano test live o conformance;
- requisiti interessati, test nominativi ed evidence sono collegati nella requirements
  traceability, distinguendo automated PASS, evidence esterna, verifica manuale,
  deferred, blocked e non verificato;
- l'assenza di test o evidence non viene convertita in PASS tramite documentazione o
  conteggi aggregati;
- secret/dependency/artifact check proporzionati passano;
- fixture ed evidence raw restano sintetiche e fuori Git;
- rischio residuo, lavoro deferred e compatibility impact sono espliciti;
- review tecnica/security proporzionata è registrata quando il rischio o il gate la
  richiede.

Una story integrata non è automaticamente un prodotto pubblicabile.
ADR, threat model e traceability sono aggiornati quando applicabile; la decisione di non
aggiornarli deve essere coerente con la superficie realmente modificata. Una modifica
documentation-only che non cambia decisioni, minacce o capability non richiede per
questo solo fatto una security review completa.

## Documentation DoD

- ogni claim è classificabile come **CURRENT**, **TARGET** o **HISTORICAL**;
- ogni qualifica è esplicitamente **synthetic**, **live lab**, **official-test** o
  **production**;
- dashboard e roadmap non duplicano cronologie complete di branch o PR;
- link relativi e riferimenti a gate sono validi;
- conteggi aggregati non sono l'unica evidence;
- input del maintainer non viene trasformato in evidence repository;
- documenti API machine-readable, guide e parity test evolvono nello stesso change set
  quando la superficie API cambia;
- `validate-docs`, secret scan e `git diff --check` passano;
- CI General e M5/Admin passano sul final exact HEAD prima dell'handoff della PR.

## DOC-01 DoD

La slice ALPHA-DOC-01 è Done soltanto se:

- parte dall'exact main `eec2fa5556eccc7e8e3b47fc7d7b127bcac1ed9e`;
- preserva senza modifiche il dirty truth source locale e riconcilia semanticamente
  baseline pre-PR #33, truth pass dirty e risultato integrato;
- modifica solo dashboard, scope, piano, backlog e DoD autorizzati;
- registra PR #33 come integrata e synthetic-qualified senza dichiarare custody o call
  live;
- definisce soltanto Track A Core alpha e Track B FSE2 Organization OfficialTest;
- registra `P3-CORE-EXPORT-DIGEST` come outcome futuro di ALPHA-ART, separando raw
  manifest run-specific e normalized inventory digest;
- mantiene `SecretValues=false` e generic secret retrieval deny-only per Local PKCS12;
- lascia architecture/security/deployment, API/generated types e documentazione FSE2 di
  dettaglio alle slice DOC-02/03/04;
- passa i gate documentation-only e la CI exact-head senza modificare source code o Core
  export.

## `0.1.0-alpha` DoD

Si applicano ALPHA-01..08 in
[`0.1.0-alpha-scope.md`](0.1.0-alpha-scope.md). In sintesi:

- versione comune `0.1.0-alpha`, tag exact commit e artifact/checksum/SPDX coerenti;
- licenza OSS approvata e canale security/governance minimi operativi;
- clean clone e quickstart ripetibili;
- unico golden path supportato: Direct .NET → Gateway → REST Connector Published →
  Synthetic Provider → mock HTTPS/mTLS → risposta sanificata e audit metadata-only;
- configuration/enrollment/publish/grant/invoke documentati e provati da un secondo
  utilizzatore;
- limiti non-production e key storage del sample espliciti;
- gate Core, Admin, PostgreSQL 18, container/export, scan e cleanup verdi sull'exact
  release commit;
- Core export con raw manifest run-specific e digest normalizzato dell'inventario
  riproducibile come artefatti distinti.

MSI, C ABI/COM, fuzzing, performance, Azure live, FSE2, HA/DR e API stability non
bloccano l'alpha perché sono fuori scope; non possono essere dichiarati inclusi.

## FSE2 OfficialTest DoD

Esistono due livelli di claim, entrambi configuration-specific.

### Primo outcome: `validate-cda`

Richiede FSE2-T01..T04 e T06:

- accesso test, software accreditation applicabile e piano autorizzato sono distinti e
  verificati fuori Git;
- custody/import e composition server-owned provano S1 `contentCommitment`, public chain,
  A1 mTLS distinta ed eventuale activation HMAC separata;
- l'exact vertical image/configuration completa E2E sintetico e negativi zero-network;
- warning mapping è bounded e non conserva testo raw;
- `validate-cda` OfficialTest completa su dataset sintetico autorizzato;
- exact commit/image/Connector/binding/provider revision ed evidence redatta sono
  attestati.

La claim ammessa è: **qualified for `validate-cda` in the official FSE2 test environment
on the attested configuration**. Non implica create/status, 11/11 live, production o
Human Actor.

### Outcome successivo: create/status

Richiede anche FSE2-T05:

- `attachment_hash` è SHA-256 degli exact input-file bytes, non del multipart HTTP;
- create/replace sono autorizzati dal piano;
- status espone soltanto outcome tecnici bounded/redatti;
- limiti process-local/cross-restart sono espliciti;
- cleanup ed evidence restano conformi a FSE2-T06.

Solo gli specifici workflow attestati possono essere dichiarati official-test qualified.
I test sintetici delle 11 operation non autorizzano una claim 11/11 live.

## Legacy e production DoD

Queste track sono deferred e non sono attive. Se autorizzate in futuro, aggiungono test
installer/native su host reali, provider/cloud reali, artifact signing/provenance,
backup/restore, HA/DR, rotation/recovery, load/soak, fuzzing, pentest, observability,
support ownership, pilot e acceptance/risk sign-off. Nessuna di queste proprietà si
deduce dall'alpha o da OfficialTest.

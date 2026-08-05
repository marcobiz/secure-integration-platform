# M3A — chiusura del product gate split-host

Data: 2026-08-05

RunId: `m3a-live-20260805-094131`

Commit candidato: `86b4e0f56d2b1f6f1ee28cc669362177007e896b`

Esito: **PASS — M3A PRODUCT GATE**.

Il finalizzatore del laboratorio rimane separatamente **BLOCKED**. Questa distinzione è
intenzionale: il gate misura le proprietà del prodotto elencate nella Gate Review, non la
capacità dell'harness di produrre autonomamente un singolo riepilogo formale.

## Evidenze originali

La VM ha prodotto un archive redatto originale, non ricostruito:

- `m3a-live-20260805-094131-vm-redacted.zip`;
- SHA-256 `966C9B301B3F6E3E6679B0C00408391E736B9BBCC0808F45EC9C3ED188FA2CAA`;
- `RESULT.json` interno `PASS`, classification `COMPLETED`;
- `vm-manifest.json` `PASS` sul commit candidato;
- cleanup VM `PASS`, zero servizi, task e utenti sintetici residui.

Il manifest dimostra:

- Broker reale `Running` con StartName `NT SERVICE\SecureIntegrationBroker` e service SID;
- Legacy Simulator standard user, token `Limited` e batch logon assegnato;
- P02 Legacy → SDK → Named Pipe → Windows Service → Gateway HOST → PostgreSQL 18 →
  synthetic Vault → vendor mock HTTPS/mTLS `PASS`;
- operation grant negato e applicazione locale non autorizzata negata;
- vendor secret e backend endpoint assenti dalla VM;
- Event Log/canary scan VM `PASS`.

Il `SecurityDriver` HOST ha prodotto `security-scenarios.json` prima del cleanup. P01,
P03–P07 e tutti gli scenari obbligatori N01–N14 sono `PASS`, inclusi revoca, firma
invalida, replay, tenant alterato, connector/operation grant, URL/secret reference,
SSRF, redirect, certificato client errato, Vault e PostgreSQL indisponibili.

La CI deterministica `30985805020` sullo stesso commit è interamente verde: Windows
build/test, Gitleaks, Gateway container, PostgreSQL 18 e M3 deterministic container
slice. Il canary scan container completo è `PASS-CI`.

## Blocco del finalizzatore

Il controllo opzionale `M3-TLS-SELF-SIGNED-APPLICATION-BOUNDARY` ha restituito
`TLS-HANDSHAKE-REJECTED` sull'HOST Windows: il probe creava ancora la propria chiave
self-signed come effimera, non presentabile da Schannel. Non è un rifiuto prodotto del
certificato dopo il TLS e non invalida P02 o gli scenari obbligatori. Il fix è nel commit
`d0e235e` ed è coperto da validazione source fail-closed e dall'integration test Schannel.
La run non è stata ripetuta.

Anche il wrapper operatore aveva rifiutato la stringa vuota usata per scrivere il
riepilogo canonico PASS, benché `ValidateVm=PASS` e `Run=PASS`; il fix è `b869a33`.
Entrambi sono difetti del laboratorio, non di Broker, SDK o Gateway.

## Evidence bundle correlato

Le evidenze originali sono state correlate senza alterarle nel bundle redatto:

`C:\SecureEvidence\m3a-live-20260805-094131\m3a-live-20260805-094131-product-gate-redacted-evidence.zip`

SHA-256:
`FCDC09ED215949E82D2C0955A930F5C70D964E61B6D9E463E86FC876019CD5AF`.

Il sidecar coincide. La scansione byte-for-byte dei valori sintetici conosciuti non trova
activation code, API key, token, password o HMAC key. Il manifest dichiara esplicitamente
`productGateStatus: PASS` e `laboratoryFinalizerStatus: BLOCKED`; non presenta il
finalizzatore come PASS.

## Cleanup e limite residuo

Cleanup HOST verificato: zero container, volumi, network e adattatori M3A della run;
profili Firewall ripristinati allo stato originario. Cleanup VM attestato nel manifest.

Il canary scan aggregato dei log container di questa specifica run non è stato raggiunto
dal finalizzatore dopo il probe opzionale. La proprietà di redazione è coperta dal canary
VM live e dalla CI deterministica sullo stesso commit. Questo limite di evidence del
laboratorio è non bloccante e resta dichiarato nel bundle.

M3A è chiuso come product gate. M3B non è iniziato; M3 non è Done, non viene creato alcun
tag M3 e M4 resta vietata.

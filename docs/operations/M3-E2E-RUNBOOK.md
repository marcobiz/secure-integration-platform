# Runbook M3 — M3A deterministico e M3B Azure smoke

## Prerequisiti comuni

- checkout pulito del commit candidato, discendente dal tag M2;
- PowerShell 5.1 e 7, .NET SDK fissato da `global.json`;
- nessun file di credenziali o certificato in Git;
- directory raw sotto `.artifacts/m3/<run-id>`;
- clock sincronizzato e outbound HTTPS controllato.

## M3A — runner Windows elevato

Il runner deve avere Windows Service Control Manager accessibile, Docker con container
Linux, almeno 8 GiB liberi e label GitHub `self-hosted`, `Windows`, `X64`, `m3-e2e`.

1. eseguire preflight e verificare elevazione, engine, porte e commit;
2. generare CA, certificato Gateway/mock e certificati client esclusivamente sintetici;
3. avviare PostgreSQL 18, migration runner, synthetic Vault, mock vendor e Gateway;
4. applicare seed Tenant/Application/Installation/activation/grant con tool separato;
5. installare Broker come `NT SERVICE\\BrokerGateway` e verificare service identity/ACL;
6. eseguire il Legacy Simulator sotto l'identità autorizzata;
7. eseguire P01–P07 e N01–N15, controllando contatori Vault/mock e audit;
8. fermare servizio/container, redigere i log, cercare tutte le canary;
9. produrre bundle redatto, manifest e sidecar SHA-256;
10. rimuovere account/servizio/container e verificare zero task/processi residui.

La run fallisce se usa fixture in-process al posto del servizio/container, se una
credential non autorizzata ottiene accesso, se i contatori mostrano side effect prima
dell'autorizzazione, se compare una canary o se il cleanup è incompleto.

## M3B — GitHub Environment `azure-dev`

L'Environment deve usare OIDC (`id-token: write`) e variabili non segrete per tenant,
subscription, resource group e location. Non sono ammessi client secret Azure. Un
reviewer approva il deployment dev.

1. autenticare l'Action tramite federated credential;
2. creare/aggiornare con Bicep risorse dev nominate dal RunId;
3. assegnare alla Managed Identity del Gateway soltanto i permessi Key Vault necessari;
4. inserire API key e PFX sintetici in Key Vault tramite la sessione OIDC;
5. pubblicare l'immagine identificata dal digest del commit candidato;
6. applicare migration da identity/ruolo separato e avviare il Gateway;
7. eseguire enrollment e P01–P07/N01–N15 applicabili al cloud;
8. raccogliere deployment output, digest, audit/log query redatti e risultati;
9. cercare le canary anche in Application Insights/Log Analytics;
10. eliminare i valori sintetici e le risorse effimere secondo la retention dev.

La Managed Identity è l'unica identità del Gateway verso Key Vault. Il Broker non ha
route, token o ruolo Key Vault. I token OIDC/Azure non sono inclusi negli artifact.

## Evidence e diagnosi

Un risultato è valido solo se il manifest riporta commit esatto, RunId, ambiente,
identità servizio, digest immagini, migration checksum, test IDs, timestamp UTC e hash
dei file redatti. In caso di failure preservare raw evidence nell'area protetta del
runner/Azure, pubblicare soltanto un report redatto `BLOCKED` e non creare il tag M3.

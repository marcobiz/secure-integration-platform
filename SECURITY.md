# Security policy

## Segnalazioni

Non aprire issue pubbliche contenenti vulnerabilità sfruttabili, segreti o dati personali. Fino alla pubblicazione di un canale security dedicato, contattare privatamente i maintainer tramite la funzione GitHub Security Advisories del repository.

## Ambito

Sono particolarmente rilevanti bypass di Named Pipe/ACL, auth Installation/PoP, tenant isolation/RLS, grants, SSRF/DNS rebinding, TLS/mTLS, Connector publication/rollback/cache, redazione e disclosure di secret.

Local Administrator e SYSTEM non sono considerati minacce pienamente mitigabili. Il Gateway è parte della trusted computing base e vede temporaneamente i secret necessari all'invocazione; non deve persisterli, loggarli o restituirli.

Non allegare evidence raw, dump, EVTX, blob DPAPI, token o chiavi. Usare artefatti sintetici e redatti.

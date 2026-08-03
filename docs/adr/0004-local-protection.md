# ADR-0004: DPAPI CurrentUser e cifratura locale

**Stato:** Accepted

## Contesto

I dati locali devono resistere a copia offline, backup rubato e processi non privilegiati senza introdurre una PKI locale complessa.

## Decisione

- DPAPI CurrentUser sotto la virtual service identity per piccoli segreti e wrapping delle data key.
- AES-256-GCM per dati, con key version per Installation e AAD scoped.
- ECDSA P-256 non esportabile in Windows CNG per l'identità Installation.
- Nessun `CRYPTPROTECT_LOCAL_MACHINE` come root predefinita.

## Conseguenze

Le chiavi sono isolate dal processo legacy e differiscono per Installation. SYSTEM/amministratore locale resta capace di compromettere il servizio. La perdita completa del profilo servizio limita il recovery MVP.

## Alternative escluse

TPM obbligatorio ridurrebbe compatibilità; chiave universale centrale introdurrebbe rischio sistemico; crittografia custom è vietata.


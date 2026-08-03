# ADR-0016: Identificazione Application locale

**Stato:** Accepted

## Decisione

Combinare Windows identity, pipe ACL, Application registration ID, processo/PID, canonical path, publisher Authenticode e hash opzionale. Mantenere un process handle e creation time per ridurre PID reuse/TOCTOU.

## Conseguenze

Lo stesso utente non autorizza automaticamente ogni processo. Publisher/path consentono upgrade controllati; hash pinning resta opzionale perché fragile. Code injection nel processo autorizzato è rischio residuo.

## Alternative escluse

Nome processo o token statico in file non sono identità sufficienti.


# Limitazioni note

**Pubblico:** valutatori, amministratori e decisori.
**Stato:** CURRENT.

## Pilot locale e private preview

- È una prova sintetica locale, non un installer, una release stabile o una qualifica di
  produzione.
- La chiave del client Direct di esempio è process-local; un consumer reale richiede un
  key store protetto/non esportabile appropriato.
- DevelopmentAuth, CA, provider e mock sono soltanto per laboratorio.
- Il runner non riprende a metà: dopo un’interruzione esegue cleanup ownership-checked e
  una nuova run.
- Cloud live, MSI, adapter C ABI/COM, HA/DR, restore/load/soak, pentest e firma artefatti
  non sono qualificati.

## FSE2

| Capacità | Stato | Limite |
|---|---|---|
| `validate-cda` | `LIVE_QUALIFIED` | Solo OfficialTest e solo quality pilot CDA; non pubblica un documento. |
| `delete` | `PRODUCT_PATH_OFFLINE_QUALIFIED` | Mock/product path, senza definition/provisioner/live qualification. |
| `create + get-status-by-workflow` | `PRODUCT_PATH_OFFLINE_QUALIFIED` | Gateway reale, PostgreSQL 18 e upstream sintetico; nessuna qualifica live. |
| Altre sette operation | `IMPLEMENTED_PARTIAL` | Non productizzate o qualificate end-to-end. |
| Gateway FSE 2.0 completo | `NO` | Una sola operation su undici è live-qualified. |

- Il product path del pilot minimo `validate-cda + create + get-status-by-workflow` è
  completo offline; create/status non sono stati invocati o qualificati in OfficialTest.
- Lo status mapper scarta intenzionalmente il contenuto non tecnico di
  `transactionData[]` e accetta solo tipi/esiti/timestamp bounded. La correlazione è
  PostgreSQL durevole per restart e scale-out, senza dati clinici.
- Human Actor, callback inbound, direct FHIR publication confermata, accreditamento,
  custody production, monitoraggio generale e produzione sono fuori scope.
- Il provisioner configura/pubbblica in modo resumable, ma bootstrap provider reale,
  principal/session acquisition e live runner self-service non sono forniti dalla
  repository. Perciò il pilot FSE2 non è riproducibile dalla documentazione sola.
- `1.0.0` resta una compatibilità Published storica; la parity qualificata è
  esclusivamente `fse2-officialtest-validate-cda@1.0.1`.

## Regola di adozione

Se onboarding, recovery o test ordinari richiedono intervento specialistico, accesso
diretto agli store, SQL, conoscenza dei test o sequenze inventate, l’esperienza di
adozione è fallita. Il rimedio è una modifica bounded di prodotto/UX o una precondizione
esterna esplicita, non ulteriore conoscenza obbligatoria dell’operatore.

# Onboarding guidato di un Connector

**Pubblico:** Security Administrator, Connector Editor e Connector Approver.
**Stato:** CURRENT per l’Admin UI integrata; il laboratorio locale usa soltanto dati
sintetici e non qualifica un deployment production.

La pagina **Onboarding guidato** (`/admin/onboarding`) porta una nuova Installation da
stato vuoto a una versione Connector `Published` e invocabile. Il percorso normale non
richiede UUID, checksum, JSON di binding, riferimenti provider, SQL o accesso allo store.
La pagina legge sempre lo stato autorevole e mostra:

- stato corrente e prerequisito mancante;
- ruolo che deve proseguire;
- prossima azione autorizzata;
- conferma che reload e retry della stessa azione sono sicuri.

## Le cinque azioni

| # | Ruolo | Azione primaria | Risultato |
|---|---|---|---|
| 1 | Security Administrator | Selezionare Tenant, Application ed Environment per nome e creare l’Installation. | Compare il passaggio di enrollment monouso. |
| 2 | Connector Editor | Scegliere un normale file `.json` e premere **Valida e importa**. | Il Gateway calcola e verifica ID, versione e checksum, poi conserva una versione `Validated`. |
| 3 | Security Administrator | Scegliere, se necessario, endpoint e credenziali dal catalogo e premere **Configura binding e autorizzazioni**. | Binding completo e grant esatti vengono creati da selezioni server-owned per la versione riletta dal server. |
| 4 | Connector Editor | Premere **Richiedi approvazione**. | Viene congelata la richiesta per la versione e il digest di binding esatti. |
| 5 | Connector Approver | Leggere la review effettiva e premere **Verifica, approva e pubblica**. | Lo stesso Approver approva e pubblica quella versione esatta. |

La pagina **Connettori** conserva l’editor JSON completo come percorso avanzato; non è
necessario nel flusso guidato.

## Handoff di enrollment monouso

Dopo la prima azione il dialog mostra insieme:

- **ID codice di attivazione**;
- **codice di attivazione**;
- scadenza.

ID e codice hanno pulsanti di copia separati. Consegnarli all’operatore di enrollment
attraverso il canale sicuro approvato e chiudere il dialog dopo l’uso. Non inserirli in
URL, log, screenshot, ticket o file di evidenza. Il browser non li salva in Web Storage
e il Gateway non consente di recuperarli in seguito.

## Ripresa e recovery

Ogni azione rilegge lo stato server-side prima di mutare. Se una richiesta si interrompe:

1. ricaricare la stessa pagina;
2. verificare stato, prerequisito e ruolo mostrati;
3. ripetere soltanto la stessa azione indicata.

Il retry non ricrea un binding già presente. La pagina rilegge la versione autorevole e
presenta di nuovo ogni grant canonico alla Admin API: una tupla identica già enabled con
la stessa scadenza è un no-op, non una seconda mutazione o un secondo audit. Una versione
mancante, diversa, `Draft`/`Retired` o un’operation non canonica viene negata prima della
mutazione. Non
attendere una finestra, non rifare login e non ripartire dall’inizio salvo che la pagina
segnali una sessione realmente scaduta. Un drift di endpoint o risorsa provider viene
negato: ricaricare il catalogo autorevole e sottoporre una nuova configurazione alla
normale four-eyes approval.

## Verifica finale

Il banner finale prova che la versione è `Published`; l’Installation selezionata deve
essere `Active` e avere il grant per l’operazione. Concludere con una sola invocation
bounded tramite la Runtime API supportata e controllare l’audit metadata-only. La pagina
non trasforma l’Admin UI in un proxy verso destinazioni arbitrarie.

# Governance di adozione e complessità

**Pubblico:** product owner, maintainer, reviewer e agenti.
**Stato:** CURRENT; sintetizza le regole operative vincolanti di [AGENTS.md](../../AGENTS.md).

## Outcome prima della macchina

Costruire il più piccolo sistema coerente che chiude un problema dimostrato. Sicurezza e
usabilità sono criteri congiunti: un controllo non è completo se il percorso normale
richiede attese evitabili, login ripetuti, conoscenza della repository, SQL, accesso
store o supporto ordinario.

Per ogni slice congelare:

- outcome visibile e non-goal;
- authority/confini da preservare;
- negative set minimo;
- metrica black-box di adozione;
- criteri di stop e di review.

Stimare separatamente prodotto, laboratorio/test ed evidence. Se test+evidence superano
probabilmente l’implementazione o la stessa slice entra in due cicli consecutivi di
remediation/re-review, eseguire un checkpoint esplicito di scope e complessità.

## Compensation stop rule

Una soluzione temporanea deve avere confine, owner e condizione di rimozione. Quando una
seconda eccezione, procedura, coordinazione o macchina di test serve soprattutto a
compensare una scelta precedente, fermarsi prima di aggiungere un terzo livello.

Chiedere:

1. qual è la causa autorevole più precoce;
2. quali componenti, stati e procedure sparirebbero cambiando quell’assunzione;
3. se la nuova astrazione rimuove duplicazione misurata in casi correnti;
4. se l’instrumentation ha valore operativo indipendente dall’evidence;
5. se il laboratorio è più semplice del comportamento che verifica.

Non normalizzare un difetto di prodotto come conoscenza dell’operatore. Se onboarding,
recovery o test ordinari richiedono intervento specialistico, l’esperienza di adozione è
fallita. Documentare il blocker e proporre una correzione bounded; non aggiungere un
runbook di workaround salvo vincolo esterno inevitabile ed esplicito.

## Minimalismo e riuso

- Preferire flusso diretto, stato esplicito e strutture ordinarie a framework,
  reflection o indirection.
- Aggiungere un’astrazione solo quando riduce complessità o duplicazione corrente
  misurata.
- Tenere bassi layer, interface, servizi, configurazioni e dipendenze longeve.
- Ottimizzare prima architettura, round-trip e rappresentazione; misurare prima delle
  micro-ottimizzazioni.
- Rimuovere path morti, compatibilità senza consumer ed evidence-only machinery dopo
  aver preservato l’autorità necessaria.
- Risolvere il secondo caso di attrito al più stretto confine condiviso, non con due
  runbook verticali.

## Ownership e parallelizzazione

Un owner capace mantiene responsabilità end-to-end fino all’outcome. Le iterazioni
purposeful testano ipotesi diverse, validano una correzione o confermano un esito
transiente; retry identici e non spiegati sono vietati.

Parallelizzare solo task indipendenti con file/output disgiunti e piano di integrazione
esplicito. Non moltiplicare writer su contratti, migrazioni, client generati,
documentazione centrale o lo stesso runtime path: il costo di merge e riqualifica supera
spesso il guadagno. I worker paralleli restituiscono normalmente finding/evidence a un
solo writer designato.

## Review e closure

La review avviene a punti di convergenza. P0/P1 bloccano; un P2 blocca solo se invalida un
criterio concordato o dimostra rischio concreto di sicurezza, correttezza, adozione od
operabilità. Gli altri P2/P3 sono follow-up e non riaprono un ciclo indefinito.

L’evidence è minima e veritiera: niente contatori costruiti come prova di comportamento
più ampio, niente dati sensibili e nessun overclaim da synthetic a live/production.

# Golden path di un Connector

**Pubblico:** owner end-to-end del Connector.
**Stato:** CURRENT come contratto di adozione per nuovi Connector.

Congelare prima dell’implementazione un solo outcome visibile e i negativi che lo
proteggono. Il golden path parte da deployment vuoto e termina con una chiamata bounded,
non con una definition validata o una suite sintetica isolata.

```text
prerequisite preflight
→ environment/provider bootstrap
→ Installation enrollment
→ definition validate/import
→ binding + grant
→ editor proposal
→ distinct approval + publish
→ verify Published/Active
→ first bounded invocation
→ sanitized result + metadata-only audit
→ owned cleanup or resumable terminal state
```

## Plan

`plan` è read-only e descrive:

- stato corrente osservato da superfici supportate;
- prerequisito mancante più precoce;
- differenza proposta e authority server-owned coinvolte;
- ruolo autorizzato alla prossima azione;
- se la stessa operazione può essere ripetuta in sicurezza.

Non leggere store, non compilare authority da file esterni non fidati e non stampare
endpoint, provider locator, secret, certificati, cookie o payload.

## Apply

`apply` esegue soltanto la prossima transizione mancante e poi fa read-back. Deve essere
idempotente e monotono. Un 429 o una sessione scaduta mette in pausa lo stesso workflow;
non attiva retry nascosti, reimport, cleanup o una nuova state machine.

Four-eyes resta reale: proposer e approver distinti, checksum/digest esatto e
autorizzazione server-side. Un workflow guidato può trasportare stato e revisioni, ma
non fondere i principal o permettere self-approval.

## Verify

Verificare da Admin API/UI:

- Installation attiva e Environment server-derived;
- Connector/versione esatti, `Published/Active` e checksum atteso;
- binding completo con revisioni provider correnti;
- grant enabled per Installation/operation;
- approval distinta valida per l’artefatto corrente;
- health/readiness necessarie alla call.

## First call e negative set

La prova black-box usa l’API/SDK pubblico, l’endpoint effettivo risolto dal server e una
fixture sintetica autorizzata. Misura **time to first successful call** da stato pulito e
verifica almeno:

- una sola invocation/outbound entro il budget;
- risposta bounded e sanificata;
- un audit correlato metadata-only;
- denial prima degli effetti per grant assente, binding/provider drift e input invalido;
- resume dopo l’ultima fase persistita e cleanup limitato a risorse task-owned.

Non usare un totale test come prova, non creare instrumentation production solo per
l’evidence e non sostituire il product path con fixture, SQL o test host.

## Stop rule

Se una seconda eccezione, procedura o macchina di test esiste soprattutto per
compensare una scelta precedente, fermarsi e riesaminare la causa autorevole prima di
aggiungere un terzo livello. Se onboarding, recovery o test normali richiedono supporto
specialistico, il golden path non è chiuso.

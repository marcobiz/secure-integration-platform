# Guida utente

**Pubblico:** adottanti, operatori e amministratori.
**Stato:** CURRENT per la baseline indicata in
[IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md).

## Da dove iniziare

- [Quick start](quickstart.md): Core sintetico, confine Windows e pack FSE2 distinti.
- [Pilot Core locale](local-pilot.md): percorso principale Docker-first senza cloud,
  credenziali esterne, SDK applicativi o curl sull'host.
- [Windows / Local Broker](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/history/README.md#prove-windows--local-broker):
  prove storiche del servizio e dell'isolamento, con prerequisiti di laboratorio propri.
- [FSE2 validazione e status](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-validation-status.md):
  ingresso al pilot opzionale corrente, con SDK .NET host e accesso/materiale OfficialTest
  già autorizzati; bootstrap, ruoli e invocation bounded tramite runner distribuito.
- [Amministrazione](administration.md): lifecycle, binding, grant, four-eyes, audit e
  health.
- [Onboarding guidato Connector](guided-connector-onboarding.md): cinque azioni su tre
  ruoli, handoff monouso, ripresa sicura e prima invocation.
- [Troubleshooting](troubleshooting.md): codice → causa probabile → azione autorizzata.
- [Limitazioni note](known-limitations.md): cosa non è promesso dalla private preview.

Lo stato delle capability è riassunto soltanto in
[IMPLEMENTATION_STATUS.md](../../IMPLEMENTATION_STATUS.md#stato-prodotto). Il
[precedente pilot FSE2 validate-only](https://github.com/marcobiz/secure-integration-platform/blob/main/docs/user/fse2-officialtest.md)
è storico per la prima adozione; le sue qualifiche non si trasferiscono tra profili.

Queste guide non richiedono SQL, accesso diretto agli store o lettura dei test. Se una
procedura ordinaria di onboarding, recovery o test richiede intervento specialistico,
l’esperienza di adozione è fallita: registrare il blocco come problema di prodotto/UX,
non trasformarlo in conoscenza obbligatoria dell’operatore.

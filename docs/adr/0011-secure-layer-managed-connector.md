# ADR-0011: Secure Layer e Managed Connector

**Stato:** Accepted

## Decisione

Ogni integrazione parte in Secure Layer salvo beneficio dimostrato. Managed Connector quando il protocollo è riutilizzato, frequentemente variabile o conviene centralizzarne la manutenzione. Entrambe le modalità condividono grants, egress e binding.

## Conseguenze

La migrazione iniziale richiede modifiche minime. Il legacy può continuare a costruire payload, ma non sceglie endpoint o secret. L'estrazione Managed avviene senza cambiare il contratto di sicurezza.


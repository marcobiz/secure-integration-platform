# Quick start

**Pubblico:** nuovo adottante.
**Stato:** CURRENT.

## Vuoi vedere il prodotto funzionare?

Usa il [pilot locale](local-pilot.md). È il solo percorso canonico di prima adozione:
non richiede cloud, FSE2, `.env`, SQL, accesso agli store o una CA installata sull’host.

Risultato: una chiamata Direct .NET attraversa il Gateway e un Connector Published,
raggiunge un mock HTTPS/mTLS e torna con risposta sanificata e audit metadata-only.

## Vuoi provare FSE2 OfficialTest?

Leggi prima [FSE2 OfficialTest](fse2-officialtest.md). `validate-cda` è live-qualified
sulla baseline, ma il percorso non è ancora self-service: deployment/provider bootstrap,
sessioni di ruolo e runner live adopter-facing hanno prerequisiti o gap espliciti.

Non sostituire i passaggi mancanti con SQL, accesso diretto al catalogo, endpoint copiati
da evidence, test integration o un `curl` costruito a mano.

## Vuoi soltanto esplorare l’Admin UI?

Completa prima il pilot locale, poi usa la
[guida di amministrazione](administration.md). Il quickstart Admin di milestone è un
laboratorio di ispezione, non un secondo percorso di adozione.

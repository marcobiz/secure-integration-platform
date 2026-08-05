# Contributing

Il progetto è in preparazione per una preview open source. Prima di proporre modifiche:

1. aprire un issue o descrivere chiaramente scope e threat model impact;
2. mantenere Domain/Application e contratti pubblici provider-neutral;
3. non aggiungere segreti, evidence raw, certificati privati o connector proprietari;
4. aggiungere test positivi e negativi proporzionati al rischio;
5. eseguire `eng/build.ps1`, `eng/test.ps1`, `eng/validate-docs.ps1`, `eng/scan-secrets.ps1` e `eng/generate-sbom.ps1`;
6. usare commit revisionabili e non riscrivere una baseline attestata.

I Connector Definition devono usare riferimenti logici: URI, credential e provider reference appartengono ai binding server-side. Nuovi provider cloud o connector commerciali devono vivere in pack separati dal Core.

Le contribution non implicano ancora una licenza definitiva: vedere [LICENSE-PENDING.md](LICENSE-PENDING.md).

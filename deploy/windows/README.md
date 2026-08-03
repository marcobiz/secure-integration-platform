# Windows packaging boundary

M0 riserva questa directory per WiX/MSI. M1 fornisce servizio e script di installazione verificabile; l'MSI firmato e l'hardening completo appartengono alla milestone enterprise indicata dal piano.

`install-service.ps1` registra `SecureIntegrationBroker` con la virtual service identity `NT SERVICE\SecureIntegrationBroker`. L'Installation ID, i manifest applicativi e gli eventuali endpoint/certificati Gateway devono essere materializzati dal futuro installer; non inserire segreti in `appsettings.json`.

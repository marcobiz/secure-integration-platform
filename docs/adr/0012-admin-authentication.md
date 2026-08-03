# ADR-0012: Autenticazione Admin

**Stato:** Accepted

## Decisione

Microsoft Entra ID via OIDC, app roles e authorization policies. Nessun account/password locale. Four-eyes obbligatorio in produzione: autore e approvatore di una ConnectorVersion sono distinti.

## Conseguenze

MFA e lifecycle identità sono delegati a Entra. Il deployment deve configurare bootstrap administrator object IDs/app roles. Un futuro provider OIDC standard può sostituire Entra nel self-hosted.


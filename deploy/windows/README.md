# Windows packaging boundary

The standalone local candidate uses [Invoke-LocalBroker.ps1](Invoke-LocalBroker.ps1)
and the [Local Broker guide](../../docs/user/local-broker.md), with exact owned
installation paths, explicit first-use key initialization, context grants and
state-preserving Stop/update. Real service qualification is pending. The older
minimal registration scripts below are not the complete adoption workflow.

M0 reserves this directory for WiX/MSI. M1 provides the service and a verifiable installation script; the signed MSI and full hardening belong to the enterprise milestone identified by the plan.

`install-service.ps1` registers `SecureIntegrationBroker` with virtual service identity `NT SERVICE\SecureIntegrationBroker`. The future installer must materialize the Installation ID, application manifests and any Gateway endpoints/certificates; do not put secrets in `appsettings.json`.

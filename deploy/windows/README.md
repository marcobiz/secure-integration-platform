# Windows packaging boundary

M0 reserves this directory for WiX/MSI. M1 provides the service and a verifiable installation script; the signed MSI and full hardening belong to the enterprise milestone identified by the plan.

`install-service.ps1` registers `SecureIntegrationBroker` with virtual service identity `NT SERVICE\SecureIntegrationBroker`. The future installer must materialize the Installation ID, application manifests and any Gateway endpoints/certificates; do not put secrets in `appsettings.json`.

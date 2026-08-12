# Local PKCS#12 deployment pack

Optional self-hosted provider pack for controlled offline laboratories. It supplies server-owned
secret, client-certificate, public-certificate and RS256 signing capabilities through the narrow
provider contracts. The default Gateway image and Core solution do not depend on this pack.

The repository contains no operational certificate, private key, PKCS#12 file, password or
provider manifest. Runtime material must be generated outside Git with
`tools/fse2/New-Fse2LocalPkcs12Material.ps1`, mounted read-only and addressed only by the exact
logical references declared in the manifest.

Use `docs/operations/FSE2-LOCAL-PROVIDER-RUNBOOK.md` for the bounded workflow. This pack is not an
HSM/KMS and is not approved as production custody.

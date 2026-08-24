# Contributing

Thank you for contributing to Secure Integration Platform. Contributions use the Developer Certificate of Origin 1.1; this project does not use a Contributor License Agreement.

## Developer Certificate of Origin

Read [DCO.md](DCO.md). Sign off every commit with:

```text
git commit -s
```

The resulting `Signed-off-by: Name <email>` trailer certifies the statements in DCO 1.1. It must match the commit author's name and email. The pull-request gate checks only commits introduced by that pull request; it does not impose a retroactive sign-off requirement on existing history.

Contributions are submitted under the license indicated by the file or path in [LICENSING.md](LICENSING.md). Do not relicense third-party material, or move it across a licensing boundary as a way to relicense it, unless you have the necessary authority and the change is explicitly approved.

## Before opening a pull request

1. Describe the scope, security impact, and tests in the pull request.
2. Keep Domain, Application, and public contracts provider-neutral. Optional cloud, vertical, or commercial packs may depend on Core contracts; Core never depends on them.
3. Never commit secrets, credentials, tokens, authorization headers, cookies, private keys, certificates with private material, `.env` files, raw evidence, dumps, EVTX, DPAPI blobs, or customer data. Use minimal per-test synthetic material.
4. Add positive and negative tests proportional to risk. Connector contributions include synthetic examples and negative validation cases.
5. Run the relevant build, test, documentation, license, secret, dependency, and SBOM gates described in `AGENTS.md`.
6. Keep commits focused, signed off, and reviewable. Do not rewrite an attested baseline.

Pull requests require independent review before integration. A contributor does not approve their own checksum-specific publication or other four-eyes action. A passing pull request check does not itself authorize a merge, tag, release, registry publication, or production claim.

## Development setup

```powershell
./eng/build.ps1
./eng/test.ps1
./eng/Test-LicensePolicy.ps1
./eng/validate-docs.ps1
./eng/scan-secrets.ps1
./eng/generate-sbom.ps1
```

For Admin Web changes, install with the pinned lock file and run lint, OpenAPI parity, unit/accessibility/browser tests, build, E2E, and audit. TypeScript remains strict; application text belongs in the English and Italian i18n resources. Do not add CDNs, analytics, unsafe HTML rendering, or sensitive browser storage.

Report vulnerabilities according to [SECURITY.md](SECURITY.md). Report conduct concerns according to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md); the two channels have different purposes even though they currently use the same address.

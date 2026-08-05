# Contributing

The project is preparing a private open-source preview. Before proposing a change:

1. describe scope and threat-model impact;
2. keep Domain/Application and public contracts provider-neutral;
3. never add secrets, raw evidence, private certificates or proprietary connectors;
4. add positive and negative tests proportional to risk;
5. run build, test, docs, secret, license and SBOM gates;
6. use reviewable commits and never rewrite an attested baseline.

## Setup

```powershell
./eng/build.ps1
./eng/test.ps1
cd src/Admin/Admin.Web
npm ci --ignore-scripts
npm run lint
npm test
npm run build
npm run test:e2e
```

TypeScript is strict. Application text belongs in i18n. Do not add CDNs, analytics, unsafe HTML rendering or sensitive browser storage. Change the OpenAPI first and run `npm run check:api`. Every mutating API needs authentication, CSRF, RBAC, tenant scope, audit and concurrency tests where applicable.

Branches start from an approved baseline; pull requests and commits should have a focused scope, security rationale, tests and no raw artefacts. Connector contributions include a synthetic sample and negative validation corpus; endpoint URLs and secret values remain server-side bindings.

New cloud providers, vertical connectors and commercial adapters belong in separate packs and may depend on Core contracts, never the reverse. Inbound DCO/CLA policy remains pending with the final license; see [LICENSE-PENDING.md](LICENSE-PENDING.md) and [the license decision](docs/legal/OPEN-SOURCE-LICENSE-DECISION.md).

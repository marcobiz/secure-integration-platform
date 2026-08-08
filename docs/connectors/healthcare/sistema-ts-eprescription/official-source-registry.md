# Sistema TS ePrescription official source registry

Freeze date: 2026-08-08
Evidence label: `OFFICIAL_CURRENT` unless explicitly stated otherwise.

This registry records only public material published by Sistema Tessera Sanitaria,
MEF/RGS or Gazzetta Ufficiale. The artifacts were inspected outside Git under
`C:\SecureEvidence\wave1-sistema-ts-20260808`; official PDFs, ZIPs, certificates,
test identities, endpoints and SOAP projects are not vendored in the repository.

`Current` means that the artifact was the one linked by the official portal on the
freeze date. It is not a promise that Sistema TS will keep that artifact unchanged.
Publication must revalidate the portal metadata and the SHA-256 digest.

## Registry

| Service | Version | WSDL/XSD | Published or portal date | Status | Environment | Official source |
|---|---|---|---|---|---|---|
| SSN dematerialized prescription - dispenser | Specification 1.5.1 | Companion development kit contains current WSDL/XSD | specification 2026-08-05; kit 2026-04-28 | Current | Test and production | [Sistema TS - Erogatore](https://sistemats1.sanita.finanze.it/portale/ricetta-elettronica/documenti-e-specifiche-tecniche-erogatore) |
| SSN dispenser - retrieve/take in charge | Kit dated 2026-04-28 | `demVisualizzaErogato.wsdl` plus request/response XSD | 2026-04-28 | Current | Test and production | [Sistema TS - Erogatore](https://sistemats1.sanita.finanze.it/portale/ricetta-elettronica/documenti-e-specifiche-tecniche-erogatore) |
| SSN dispenser - dispense/close | Kit dated 2026-04-28 | `demInvioErogato.wsdl` plus request/response XSD | 2026-04-28 | Current | Test and production | [Sistema TS - Erogatore](https://sistemats1.sanita.finanze.it/portale/ricetta-elettronica/documenti-e-specifiche-tecniche-erogatore) |
| SSN dispenser - suspend | Kit dated 2026-04-28 | `demSospendiErogato.wsdl` plus request/response XSD | 2026-04-28 | Current | Test and production | [Sistema TS - Erogatore](https://sistemats1.sanita.finanze.it/portale/ricetta-elettronica/documenti-e-specifiche-tecniche-erogatore) |
| SSN dispenser - cancel/correct dispensation | Kit dated 2026-04-28 | `demAnnullaErogato.wsdl` plus request/response XSD | 2026-04-28 | Current | Test and production | [Sistema TS - Erogatore](https://sistemats1.sanita.finanze.it/portale/ricetta-elettronica/documenti-e-specifiche-tecniche-erogatore) |
| Sistema TS strong-authentication profile | 1.1 | Narrative profile; no business schema | 2026-01-12 | Current | Test and production | [Sistema TS - two-factor documentation](https://sistemats1.sanita.finanze.it/portale/documenti-e-specifiche-tecniche6) |
| Sistema TS ID-session management | Kit dated 2025-09-02; schema namespace version 0.1 | `sts-a2f-service.wsdl`, `sts-a2f-service.v0.1.xsd`, data-type XSD | 2025-09-02 | Current | Test and production | [Sistema TS - two-factor documentation](https://sistemats1.sanita.finanze.it/portale/documenti-e-specifiche-tecniche6) |
| MFA extension for SSN dematerialized prescriptions | 1.1 | Narrative profile; uses SSN business WSDL/XSD | 2025-06-03 | Current | Test and production | [Sistema TS - two-factor documentation](https://sistemats1.sanita.finanze.it/portale/documenti-e-specifiche-tecniche6) |
| SSN MFA legal basis | Decree 27 February 2025 | Not applicable | 2025-03-10 | Current | National | [Gazzetta Ufficiale, GU 57/2025](https://www.gazzettaufficiale.it/atto/vediMenuHTML?atto.codiceRedazionale=25A01494&atto.dataPubblicazioneGazzetta=2025-03-10&tipoSerie=serie_generale&tipoVigenza=originario) |
| RBE/non-SSN prescription - dispenser | Specification dated 2023-06-28; official portal copy observed current | Companion kit contains four WSDL families and XSD | portal says 2026-06-28; kit 2024-02-19 | Current on portal; artifact version is older | Test and production | [Sistema TS - RBE Erogatore](https://sistemats1.sanita.finanze.it/portale/web/guest/erogatore-ricetta-non-carico-ssn) |
| RBE strong authentication | specification dated 2023-12-18; kit 2024-04-10 | RBE-specific MFA kit | 2023-12-18 / 2024-04-10 | Current on portal | Test and production | [Sistema TS - RBE technical documents](https://sistemats1.sanita.finanze.it/portale/documenti-e-specifiche-tecniche-ricetta-non-a-carico-ssn) |

## Frozen artifact digests

| Artifact | SHA-256 |
|---|---|
| SSN dispenser specification 1.5.1 PDF | `19F6AA6E948248941D25A064181D6395D79123803B34B1431D74A1082F8C44AE` |
| SSN dispenser development kit ZIP | `DEB416227EE87B202CF56AEADEC1E720D2638D4AFCD278739B7733F792FE4496` |
| Strong-authentication profile 1.1 PDF | `A583AE9748ACE235142BEE7BA78DE0B1C229A442991086DB0500DFF6EDD5C76A` |
| SSN MFA profile 1.1 PDF | `8D36E7E0DCE74F9814F62DCA930B4661D54E350A4E0C3B1975DD665D5F6C3496` |
| ID-session development kit ZIP | `CAA1C6F9C6C3D304F8CD4D12C6EA3FEA8FF983E61FBACED1C20CBA64E7DA9DD3` |
| RBE dispenser specification PDF | `37927375990CC9F352F8E2162EB19C8B05A78608845E86A0213F0BBEDAB539A7` |
| RBE dispenser development kit ZIP | `E4E606A9081609F717A22531DA3AF95F52EA3C7C83FB6914A9733075F5E02A94` |

## Confirmed contract identities

| Contract | Operation | SOAP action | WSDL SHA-256 | Request XSD SHA-256 | Response XSD SHA-256 |
|---|---|---|---|---|---|
| SSN retrieve/take in charge | `visualizzaErogato` | `http://visualizzaerogato.wsdl.dem.sanita.finanze.it/VisualizzaErogato` | `C422FA65020753D895EBA8F1F02AEC2E45679E10C452C8B57E76D474024231B5` | `BB0A22B73DB15FE2B4017B6E8B0458399D4DE7B09CCC2C1C9086937D1A44C4CA` | `D206A0AB1D2055E5CAEC7022A76B5AC8032CA3F1546C614B4F73AE5E47B8CDE8` |
| SSN dispense/close | `invioErogato` | `http://invioerogato.wsdl.dem.sanita.finanze.it/InvioErogato` | `DC17F2ABFDFD286FF655D4974CD85E20EFC9EC3875F9BFC64F79ECA9B0678BF3` | `62EC82BEE84184BB60E77CD89F2F2F643D08E01BC9F7534AA13C4A4A4DB8A3FB` | `E6604DA26016A4B9BBF1035827FC20BBA55535841D14358AFB61A00935866283` |
| SSN suspend | `sospendiErogato` | `http://visualizzaerogato.wsdl.dem.sanita.finanze.it/SospendiErogato` | `7CB0C549D7D6E9F93B1F9C3ADECADD014BB81541FA721C6A965ED34E052566B7` | `C7FA75CA5DA90DBB162F312076B234B5262D66C7923D7D003129662156D91CB6` | `D25399F16DD5ED21896BCAF1ECE60DFC64DA9F428334CF1F8E9AE4422A09BEBF` |
| SSN cancel/correct dispensation | `annullaErogato` | `http://annullaerogato.wsdl.dem.sanita.finanze.it/AnnullaErogato` | `CEB27681E0D06591309E176D1FA6C78AAA1655557E5B34CDCCAC16A313840883` | `CBDE0E4ED80BCB88DF50CB59264CE02F640E2D7D1539B45D25C20A3A05F49112` | `BE33DAB9575C0D8D7D02D0F10074C802715F512FCEA99087CCB881E4AFC39AA6` |
| ID-session lifecycle | `create`, `revoke`, `checkToken` | actions under `http://wsdl.auth.a2f.sts.sanita.finanze.it/` | `2BE186D78F333389FD866ABCC2CC36DDF99B6F3E4E33376D3A2468A1842BC082` | `4F70A000CEFCCFAFD7A7D7D3A76FCBAFC0BD352EC2FCAC8F68193D2EF8A79210` | same schema |

The apparently surprising SOAP action namespace of `sospendiErogato` is copied from
the current official WSDL and must not be normalized or corrected by inference.

## Not authoritative for implementation

- search-engine mirrors, federation or vendor summaries;
- historical local characterization marked `KNOWN`;
- customer/private research, captured traffic or credentials;
- SOAP UI examples as a replacement for the WSDL/XSD;
- the test-only wildcard ID-session format as a production lifecycle rule.

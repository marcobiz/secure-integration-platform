# Open-source license decision — pending

No final license is granted by this document. Legal and business review is required before public publication.

| Topic | Apache-2.0 | MPL-2.0 |
|---|---|---|
| Commercial adoption | Very permissive; easy vendor embedding | Permissive use, with file-level copyleft |
| Core modifications | May remain proprietary if notices are preserved | Modified MPL-covered files must remain available under MPL |
| Proprietary modules/packs | Straightforward separation | Allowed when kept in separate files/modules |
| Patent grant | Explicit contributor patent grant and termination | Explicit patent grant and defensive termination |
| Upstream incentive | Social/process incentive | Stronger requirement to publish changes to covered files |
| Proprietary fork risk | Higher | Lower for modifications to Core files |
| Adoption friction | Lowest | Moderate review needed for file boundaries |

Both choices allow proprietary healthcare connectors, deployment packs and legacy adapters when they are physically separate. Dependency inventory currently includes permissive licenses and MPL-2.0 development/runtime tooling; neither candidate is inherently blocked by the inspected dependency set.

Technical recommendation: **MPL-2.0** if the business priority is keeping fixes to Core files available while selling separate packs; **Apache-2.0** if frictionless platform/vendor adoption is the overriding priority. The current architectural separation makes either viable. Final choice, notice policy, inbound contribution model (DCO versus CLA) and trademark policy remain explicitly open for legal/business approval.

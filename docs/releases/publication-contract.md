# Release publication contract

This contract applies to releases after `v0.1.0-alpha.1`. It does not rebuild, replace,
or reinterpret the immutable assets of that release.

## Candidate state and publication event

The release builder produces a pre-publication candidate snapshot. Its manifest records
`publication.state = pre-publication-candidate` and `publication.occurred = false`.
Those fields describe when the snapshot was produced; they are not a later statement
about whether a GitHub Release exists. The ambiguous `claims.publicReleaseGo` field is
not part of the future contract.

Publication is a separate, authorized event. The publisher must verify the exact tag
target and candidate source revision, upload the approved inventory without substitution,
and then capture the immutable public release metadata and GitHub-provided SHA-256 digest
for every uploaded asset.

## Names and SBOM inventory

The candidate file `manifest.json` is uploaded as `release-manifest.json`. Public release
instructions and verification commands must use the public name. `SHA256SUMS` binds the
five product artifacts and retains their candidate-relative `artifacts/` paths.

The manifest publication object distinguishes:

- `publicSbomAssets`: SBOM files selected for upload as public release assets;
- `internalEvidenceSboms`: SBOM and aggregate records retained in the complete candidate
  release set and described by the manifest, but not implicitly uploaded.

The two collections are not interchangeable. A manifest record does not claim that the
corresponding file is a public GitHub Release asset.

## Post-upload integrity closure

Before a future release is declared publication-complete, the public inventory must be
closed by either checksum sidecars or a repository-reviewed public publication
attestation. The closure must bind the public manifest, `SHA256SUMS`, every public SBOM,
and any other auxiliary asset by exact name, byte count, and SHA-256. A publication
attestation must also record the tag target, release ID and URL, publication timestamp,
and exact source commit.

Product checksums, candidate validation, and GitHub upload completion are separate facts.
No candidate flag may be reused as the post-publication status, and no production or
external-service qualification follows from publication.

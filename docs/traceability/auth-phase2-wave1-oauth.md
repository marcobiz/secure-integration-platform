# Auth Phase 2 / Wave 1 OAuth traceability

| Requirement | Named automated evidence | Status |
|---|---|---|
| PKCE CSPRNG, RFC verifier and S256-only navigation/exchange | `W1_IT_PKCE_S256_is_server_generated_bound_single_use_and_NONE_remains_compatible`; `W1_ARCH_PKCE_and_client_credentials_are_server_owned_S256_only_and_share_restricted_token_acquisition` | PASS local |
| Verifier/state/correlation/expiry/single-use/replay | `W1_SEC_PKCE_wrong_or_missing_verifier_is_denied_and_attempt_cannot_be_reused`; `W1_SEC_PKCE_plain_invalid_challenge_expiry_state_correlation_and_stale_revision_fail_closed`; existing state/replay and correlation tests | PASS local |
| Published profile authority and no caller policy override | Existing Published authority substitution test; Client Credentials substitution theory; HTTP/OAuth architecture boundary | PASS local |
| Authorization Code compatibility with omitted PKCE field | `W1_IT_PKCE_S256_is_server_generated_bound_single_use_and_NONE_remains_compatible`; connector schema validation in `W1_CT_Published_OAuth_profiles_validate_and_downgrade_or_endpoint_substitution_is_rejected` | PASS local |
| Client Credentials server-owned endpoint/client/secret/scope/audience/resource | `W1_SEC_Client_credentials_profile_endpoint_secret_scope_audience_and_auth_method_substitution_is_denied` | PASS local |
| Shared bounded cache, complete key and per-key single-flight | `W1_IT_Client_credentials_cache_is_shared_revision_bound_and_single_flight`; `W1_IT_Client_credentials_single_flight_is_per_security_key_without_cross_tenant_head_of_line_blocking`; `W1_IT_Client_credentials_expiry_and_explicit_acquisition_share_one_security_key_flight`; `W1_SEC_Explicit_acquisition_winning_expiry_race_replaces_the_old_reference_without_duplicate_dispatch`; cache architecture test | PASS local |
| Bounded attempt/generation bookkeeping | `W1_UT_Attempt_capacity_eviction_cleans_key_and_connector_generation_state` | PASS local |
| Connector schema/runtime OAuth profile parity | `W1_CT_Published_OAuth_profiles_validate_and_downgrade_or_endpoint_substitution_is_rejected` covers omitted PKCE, downgrade, client auth, controls/C1, whitespace-only client IDs, redirect user-info/query/fragment and malformed absolute redirect URI | PASS local |
| Rotate/disable/stale denial without cross-tenant invalidation | `W1_SEC_Client_credentials_disabled_rotated_stale_cache_and_SSRF_fail_before_dispatch`; `W1_SEC_Client_credentials_reacquisition_failure_invalidates_only_its_security_key`; existing refresh tombstone test | PASS local |
| Restricted egress, redirect and SSRF | Client Credentials response/SSRF tests; existing redirect, endpoint manipulation, navigation and bearer-destination tests | PASS local |
| Malformed/expired response denial | `W1_SEC_Client_credentials_malformed_expired_and_redirect_responses_fail_sanitized` | PASS local |
| Redaction and metadata-only audit fail-closed | `W1_SEC_PKCE_and_client_credentials_diagnostics_redact_verifier_challenge_state_secret_authorization_and_raw_token_response`; `W1_SEC_Client_credentials_audit_failure_does_not_publish_a_token_session`; existing diagnostic test | PASS local |
| Post-transport raw response zeroization on stale state | `W1_SEC_Token_response_is_zeroed_when_snapshot_revalidation_fails_after_transport_returns` | PASS local |
| OAuth authority endpoints in four-eyes dependencies/digest/diff/risks | `W1_UT_OAuth_authority_endpoints_are_complete_in_approval_dependencies_digest_and_risks` | PASS local |
| PostgreSQL validation, approval, publication and scoped locator resolution | `W1_IT_DAT_PostgreSQL18_OAuth_validation_approval_publication_and_operation_locator_resolution_when_configured` | PASS PostgreSQL 18 local |
| Provider-neutral architecture and one synthetic server | HTTP/OAuth architecture test; extended `SyntheticOAuthServer` integration suite | PASS local |

`PASS local` records the named deterministic product evidence. PR #17 product candidate `857810a04d1be86905bda26156e9660cf82f8bab` additionally completed PostgreSQL 18 qualification, release scans, SBOM, Core export, exact-head CI 21/21 (run `31262148895` and `31262148897`) and repeated independent review with GO. A later documentation-only closure commit does not change these product results, but must retain green PR checks before any merge.

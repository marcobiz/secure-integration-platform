using System.Security.Cryptography;
using System.Text;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

internal sealed class SoapSessionCache
{
    internal const int MaximumEntries = 256;
    private readonly object sync = new();
    private readonly Dictionary<SoapSessionCacheKey, KeyState> entries = [];

    internal int EntryCount { get { lock (sync) return entries.Count; } }
    internal int CurrentSessionCount { get { lock (sync) return entries.Values.Count(value => value.Current is not null); } }
    internal int PendingInteractionCount { get { lock (sync) return entries.Values.Count(value => value.Interaction is not null); } }

    public OpaqueSoapSessionReference Store(SoapSessionCacheKey key, string upstreamSession, DateTimeOffset now, DateTimeOffset expiresAt)
    {
        string reference = NewReference();
        string digest = Digest(reference);
        lock (sync)
        {
            SweepExpired(now);
            KeyState state = GetOrCreate(key);
            state.Generation = checked(state.Generation + 1);
            state.Current = new StoredSession(state.Generation, reference, digest, upstreamSession, expiresAt);
            state.Interaction = null;
        }
        return new OpaqueSoapSessionReference(reference);
    }

    public (OpaqueSoapSessionReference Reference, string UpstreamSession)? ResolveCurrent(SoapSessionCacheKey key, DateTimeOffset now)
    {
        lock (sync)
        {
            SweepExpired(now);
            if (!entries.TryGetValue(key, out KeyState? state) || state.Current is not StoredSession stored) return null;
            return (new OpaqueSoapSessionReference(stored.Reference), stored.UpstreamSession);
        }
    }

    public (OpaqueSoapSessionReference Reference, DateTimeOffset ExpiresAt)? ResolveCurrentMetadata(SoapSessionCacheKey key, DateTimeOffset now)
    {
        lock (sync)
        {
            SweepExpired(now);
            if (!entries.TryGetValue(key, out KeyState? state) || state.Current is not StoredSession stored) return null;
            return (new OpaqueSoapSessionReference(stored.Reference), stored.ExpiresAt);
        }
    }

    public string? Resolve(SoapSessionCacheKey key, OpaqueSoapSessionReference reference, DateTimeOffset now)
    {
        ValidateReference(reference.Value);
        string digest = Digest(reference.Value);
        lock (sync)
        {
            SweepExpired(now);
            if (!entries.TryGetValue(key, out KeyState? state) || state.Current is not StoredSession stored || !string.Equals(stored.Digest, digest, StringComparison.Ordinal)) return null;
            return stored.UpstreamSession;
        }
    }

    internal OpaqueSessionDispatchLease ResolveDispatchLease(SoapSessionCacheKey key, OpaqueSoapSessionReference? reference, DateTimeOffset now)
    {
        string? digest = null;
        if (reference is not null)
        {
            ValidateReference(reference.Value);
            digest = Digest(reference.Value);
        }
        lock (sync)
        {
            SweepExpired(now);
            if (!entries.TryGetValue(key, out KeyState? state) || state.Current is not StoredSession stored ||
                (digest is not null && !string.Equals(stored.Digest, digest, StringComparison.Ordinal)))
                throw new SoapAuthException("SESSION-HTTP-SESSION-INVALID");
            return new(key, stored.Generation, stored.Digest, stored.UpstreamSession, stored.ExpiresAt);
        }
    }

    internal bool IsCurrent(OpaqueSessionDispatchLease lease, DateTimeOffset now)
    {
        lock (sync)
        {
            SweepExpired(now);
            return entries.TryGetValue(lease.Key, out KeyState? state) && state.Current is StoredSession stored &&
                stored.Generation == lease.Generation && string.Equals(stored.Digest, lease.ReferenceDigest, StringComparison.Ordinal) && stored.ExpiresAt > now;
        }
    }

    public void Invalidate(SoapSessionCacheKey key, OpaqueSoapSessionReference? reference = null)
    {
        lock (sync)
        {
            if (!entries.TryGetValue(key, out KeyState? state)) return;
            if (reference is not null)
            {
                ValidateReference(reference.Value);
                string digest = Digest(reference.Value);
                if (state.Current is not null && string.Equals(state.Current.Digest, digest, StringComparison.Ordinal)) state.Current = null;
            }
            else state.Current = null;
            RemoveIfEmpty(key, state);
        }
    }

    public SoapInteractiveChallenge StoreInteraction(SoapSessionCacheKey key, string upstreamChallenge, DateTimeOffset now, DateTimeOffset expiresAt)
    {
        string reference = NewReference();
        lock (sync)
        {
            SweepExpired(now);
            KeyState state = GetOrCreate(key);
            state.InteractionGeneration = checked(state.InteractionGeneration + 1);
            state.Interaction = new StoredInteraction(state.InteractionGeneration, Digest(reference), InteractionKind.Challenge,
                upstreamChallenge, null, null, null, state.Generation, expiresAt, null);
        }
        return new SoapInteractiveChallenge(reference, upstreamChallenge, expiresAt);
    }

    public InteractionCompletion BeginInteractionCompletion(SoapSessionCacheKey key, string interactionReference, DateTimeOffset now)
    {
        ValidateReference(interactionReference);
        string digest = Digest(interactionReference);
        lock (sync)
        {
            SweepExpired(now);
            if (!entries.TryGetValue(key, out KeyState? state) || state.Interaction is not StoredInteraction interaction ||
                interaction.Kind != InteractionKind.Challenge || interaction.CompletionId is not null || !string.Equals(interaction.Digest, digest, StringComparison.Ordinal))
                throw new SoapAuthException("SOAP-INTERACTION-INVALID");
            Guid completionId = Guid.NewGuid();
            state.Interaction = interaction with { CompletionId = completionId };
            return new InteractionCompletion(key, interaction.Generation, completionId,
                interaction.SensitiveState ?? throw new SoapAuthException("SOAP-INTERACTION-INVALID"));
        }
    }

    public OpaqueSoapSessionReference CompleteInteraction(InteractionCompletion completion, string upstreamSession, DateTimeOffset now, DateTimeOffset expiresAt)
    {
        string reference = NewReference();
        string digest = Digest(reference);
        lock (sync)
        {
            SweepExpired(now);
            if (!entries.TryGetValue(completion.Key, out KeyState? state) || state.Interaction is not StoredInteraction interaction ||
                interaction.Kind != InteractionKind.Challenge || interaction.Generation != completion.InteractionGeneration || interaction.CompletionId != completion.CompletionId)
                throw new SoapAuthException("SOAP-INTERACTION-INVALID");
            state.Generation = checked(state.Generation + 1);
            state.Current = new StoredSession(state.Generation, reference, digest, upstreamSession, expiresAt);
            state.Interaction = null;
        }
        return new OpaqueSoapSessionReference(reference);
    }

    public void AbandonInteraction(InteractionCompletion completion)
    {
        lock (sync)
        {
            if (!entries.TryGetValue(completion.Key, out KeyState? state) || state.Interaction is not StoredInteraction interaction ||
                interaction.Kind != InteractionKind.Challenge || interaction.Generation != completion.InteractionGeneration || interaction.CompletionId != completion.CompletionId) return;
            state.Interaction = null;
            RemoveIfEmpty(completion.Key, state);
        }
    }

    public ExternalSessionAdmissionIntent StoreAdmissionIntent(
        SoapSessionCacheKey key,
        string authorityFingerprint,
        string operationId,
        string profileId,
        ExternalSessionProvenance provenance,
        DateTimeOffset now,
        DateTimeOffset expiresAt)
    {
        if (string.IsNullOrWhiteSpace(authorityFingerprint) || !TypedSessionHandshakeValidation.Identifier(operationId)) throw TypedSessionHandshakeFailures.Configuration();
        string reference = NewReference();
        lock (sync)
        {
            SweepExpired(now);
            KeyState state = GetOrCreate(key);
            if (state.Current is not null) throw TypedSessionHandshakeFailures.AdmissionIntentInvalid();
            state.InteractionGeneration = checked(state.InteractionGeneration + 1);
            state.Interaction = new StoredInteraction(state.InteractionGeneration, Digest(reference), InteractionKind.ExternalAdmission,
                null, authorityFingerprint, operationId, provenance, state.Generation, expiresAt, null);
        }
        return new(reference, profileId, provenance, expiresAt, authorityFingerprint);
    }

    internal ExternalAdmissionPresentation ResolveAdmissionPresentation(
        string reference,
        GatewayClientPrincipal principal,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(principal);
        ValidateReference(reference);
        string digest = Digest(reference);
        lock (sync)
        {
            SweepExpired(now);
            foreach ((SoapSessionCacheKey key, KeyState state) in entries)
            {
                StoredInteraction? interaction = state.Interaction;
                if (interaction is null || interaction.Kind != InteractionKind.ExternalAdmission || interaction.CompletionId is not null ||
                    !string.Equals(interaction.Digest, digest, StringComparison.Ordinal) || key.TenantId != principal.TenantId ||
                    key.InstallationId != principal.InstallationId || key.ApplicationId != principal.ApplicationId ||
                    key.EnvironmentId != principal.Identity.EnvironmentId || interaction.SessionGeneration != state.Generation)
                    continue;
                return new(key, reference, interaction.OperationId ?? throw TypedSessionHandshakeFailures.AdmissionIntentInvalid(),
                    interaction.AuthorityFingerprint ?? throw TypedSessionHandshakeFailures.AdmissionIntentInvalid(),
                    interaction.Provenance ?? throw TypedSessionHandshakeFailures.AdmissionIntentInvalid(), interaction.ExpiresAt);
            }
        }
        throw TypedSessionHandshakeFailures.AdmissionIntentInvalid();
    }

    public AdmissionCompletion BeginAdmission(
        ExternalAdmissionPresentation presentation,
        string authorityFingerprint,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(presentation);
        SoapSessionCacheKey key = presentation.Key;
        ValidateReference(presentation.Reference);
        string digest = Digest(presentation.Reference);
        lock (sync)
        {
            SweepExpired(now);
            if (!entries.TryGetValue(key, out KeyState? state) || state.Interaction is not StoredInteraction interaction ||
                interaction.Kind != InteractionKind.ExternalAdmission || interaction.CompletionId is not null ||
                !string.Equals(interaction.Digest, digest, StringComparison.Ordinal) ||
                !string.Equals(interaction.AuthorityFingerprint, authorityFingerprint, StringComparison.Ordinal) ||
                !string.Equals(presentation.AuthorityFingerprint, authorityFingerprint, StringComparison.Ordinal) ||
                !string.Equals(presentation.OperationId, interaction.OperationId, StringComparison.Ordinal) ||
                interaction.Provenance != presentation.Provenance || interaction.SessionGeneration != state.Generation)
                throw TypedSessionHandshakeFailures.AdmissionIntentInvalid();
            Guid completionId = Guid.NewGuid();
            state.Interaction = interaction with { CompletionId = completionId };
            return new(key, interaction.Generation, completionId, interaction.SessionGeneration, presentation.Provenance, authorityFingerprint);
        }
    }

    public OpaqueSoapSessionReference CompleteAdmission(
        AdmissionValidationProof proof,
        string upstreamSession,
        DateTimeOffset now,
        DateTimeOffset expiresAt)
    {
        if (!TypedSessionHandshakeValidation.SessionValue(upstreamSession)) throw TypedSessionHandshakeFailures.CandidateInvalid();
        AdmissionCompletion completion = proof.Completion;
        byte[] actualCandidateDigest = SHA256.HashData(Encoding.UTF8.GetBytes(upstreamSession));
        if (proof.CandidateDigestSha256.Length != 32 || !CryptographicOperations.FixedTimeEquals(proof.CandidateDigestSha256, actualCandidateDigest))
            throw TypedSessionHandshakeFailures.AdmissionIntentInvalid();
        string reference = NewReference();
        string digest = Digest(reference);
        lock (sync)
        {
            SweepExpired(now);
            if (!entries.TryGetValue(completion.Key, out KeyState? state) || state.Interaction is not StoredInteraction interaction ||
                interaction.Kind != InteractionKind.ExternalAdmission || interaction.Generation != completion.InteractionGeneration ||
                interaction.CompletionId != completion.CompletionId || state.Generation != completion.SessionGeneration ||
                !string.Equals(interaction.AuthorityFingerprint, completion.AuthorityFingerprint, StringComparison.Ordinal) ||
                interaction.Provenance != completion.Provenance)
                throw TypedSessionHandshakeFailures.AdmissionIntentInvalid();
            state.Generation = checked(state.Generation + 1);
            state.Current = new StoredSession(state.Generation, reference, digest, upstreamSession, expiresAt);
            state.Interaction = null;
        }
        return new(reference);
    }

    public void AbandonAdmission(AdmissionCompletion completion)
    {
        lock (sync)
        {
            if (!entries.TryGetValue(completion.Key, out KeyState? state) || state.Interaction is not StoredInteraction interaction ||
                interaction.Kind != InteractionKind.ExternalAdmission || interaction.Generation != completion.InteractionGeneration ||
                interaction.CompletionId != completion.CompletionId) return;
            state.Interaction = null;
            RemoveIfEmpty(completion.Key, state);
        }
    }

    private KeyState GetOrCreate(SoapSessionCacheKey key)
    {
        if (entries.TryGetValue(key, out KeyState? existing)) return existing;
        if (entries.Count >= MaximumEntries) throw new SoapAuthException("SOAP-CACHE-CAPACITY");
        KeyState created = new();
        entries.Add(key, created);
        return created;
    }

    private void SweepExpired(DateTimeOffset now)
    {
        foreach ((SoapSessionCacheKey key, KeyState state) in entries.ToArray())
        {
            if (state.Current?.ExpiresAt <= now) state.Current = null;
            if (state.Interaction?.ExpiresAt <= now) state.Interaction = null;
            RemoveIfEmpty(key, state);
        }
    }

    private void RemoveIfEmpty(SoapSessionCacheKey key, KeyState state)
    {
        if (state.Current is null && state.Interaction is null) entries.Remove(key);
    }

    private static string NewReference() => Base64Url.Encode(RandomNumberGenerator.GetBytes(32));
    private static string Digest(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static void ValidateReference(string value)
    {
        if (value.Length is < 40 or > 64 || value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '-' or '_')))
            throw new SoapAuthException("SOAP-OPAQUE-REFERENCE-INVALID");
    }

    private sealed class KeyState
    {
        public long Generation { get; set; }
        public long InteractionGeneration { get; set; }
        public StoredSession? Current { get; set; }
        public StoredInteraction? Interaction { get; set; }
    }

    private sealed record StoredSession(long Generation, string Reference, string Digest, string UpstreamSession, DateTimeOffset ExpiresAt);
    private enum InteractionKind
    {
        Challenge,
        ExternalAdmission
    }

    private sealed record StoredInteraction(
        long Generation,
        string Digest,
        InteractionKind Kind,
        string? SensitiveState,
        string? AuthorityFingerprint,
        string? OperationId,
        ExternalSessionProvenance? Provenance,
        long SessionGeneration,
        DateTimeOffset ExpiresAt,
        Guid? CompletionId);
}

internal sealed record InteractionCompletion(SoapSessionCacheKey Key, long InteractionGeneration, Guid CompletionId, string UpstreamChallenge);

internal sealed record AdmissionCompletion(
    SoapSessionCacheKey Key,
    long InteractionGeneration,
    Guid CompletionId,
    long SessionGeneration,
    ExternalSessionProvenance Provenance,
    string AuthorityFingerprint);

internal sealed class AdmissionValidationProof
{
    internal AdmissionValidationProof(AdmissionCompletion completion, byte[] candidateDigestSha256)
    {
        Completion = completion ?? throw new ArgumentNullException(nameof(completion));
        if (candidateDigestSha256 is null || candidateDigestSha256.Length != 32) throw TypedSessionHandshakeFailures.ValidationFailed();
        CandidateDigestSha256 = candidateDigestSha256.ToArray();
    }

    internal AdmissionCompletion Completion { get; }
    internal byte[] CandidateDigestSha256 { get; }

    public override string ToString() => $"AdmissionValidationProof(InteractionGeneration={Completion.InteractionGeneration}, SessionGeneration={Completion.SessionGeneration}, Redacted=True)";
}

internal sealed record ExternalAdmissionPresentation(
    SoapSessionCacheKey Key,
    string Reference,
    string OperationId,
    string AuthorityFingerprint,
    ExternalSessionProvenance Provenance,
    DateTimeOffset ExpiresAt)
{
    public override string ToString() => $"ExternalAdmissionPresentation(OperationId={OperationId}, Provenance={Provenance}, ExpiresAt={ExpiresAt:O}, Redacted=True)";
}

internal sealed record SoapSessionCacheKey(
    Guid TenantId,
    Guid InstallationId,
    Guid ApplicationId,
    Guid EnvironmentId,
    string ConnectorId,
    string ConnectorVersion,
    long BindingRevision,
    long EndpointRevision,
    long CredentialRevision,
    string ProfileId);

internal sealed record OpaqueSessionDispatchLease(
    SoapSessionCacheKey Key,
    long Generation,
    string ReferenceDigest,
    string UpstreamSession,
    DateTimeOffset ExpiresAt)
{
    public override string ToString() => $"{nameof(OpaqueSessionDispatchLease)}(Generation={Generation}, ExpiresAt={ExpiresAt:O}, Redacted=True)";
}

internal sealed class SoapOpaqueSessionLeaseProvider(SoapSessionCache cache) : OpaqueSessionLeaseProvider
{
    internal override SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OpaqueSessions.OpaqueSessionDispatchLease AcquireFinalLease(
        OpaqueSessionReference? reference,
        OpaqueSessionLifecycleBinding binding,
        DateTimeOffset now)
    {
        SoapSessionCacheKey key = new(binding.TenantId, binding.InstallationId, binding.ApplicationId, binding.EnvironmentId, binding.ConnectorId,
            binding.ConnectorVersion, binding.BindingRevision, binding.EndpointRevision, binding.CredentialRevision, binding.ProfileId);
        OpaqueSessionDispatchLease lease;
        try
        {
            lease = cache.ResolveDispatchLease(key, reference is null ? null : new OpaqueSoapSessionReference(reference.Value), now);
        }
        catch (SoapAuthException)
        {
            throw OpaqueSessionHttpFailures.SessionInvalid();
        }

        return new(lease.UpstreamSession, lease.ExpiresAt, currentNow =>
        {
            if (!cache.IsCurrent(lease, currentNow)) throw OpaqueSessionHttpFailures.SessionStale();
        });
    }
}

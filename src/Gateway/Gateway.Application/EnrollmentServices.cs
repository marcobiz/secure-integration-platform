using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Application;

/// <summary>Security parameters for Installation enrollment.</summary>
public sealed class EnrollmentSecurityOptions
{
    /// <summary>Server-only HMAC key for activation material.</summary>
    public required byte[] ActivationHmacKey { get; init; }
    /// <summary>Activation-code lifetime.</summary>
    public TimeSpan ActivationLifetime { get; init; } = TimeSpan.FromHours(24);
    /// <summary>Proof challenge lifetime.</summary>
    public TimeSpan ChallengeLifetime { get; init; } = TimeSpan.FromMinutes(5);
    /// <summary>Maximum accepted certificate lifetime.</summary>
    public TimeSpan MaximumCredentialLifetime { get; init; } = TimeSpan.FromDays(93);
    /// <summary>Window before expiry in which renewal is allowed.</summary>
    public TimeSpan RenewalWindow { get; init; } = TimeSpan.FromDays(30);
    /// <summary>Maximum previous-credential overlap after renewal.</summary>
    public TimeSpan RenewalOverlap { get; init; } = TimeSpan.FromDays(7);
}

/// <summary>Creates registry records and one-time activation material without exposing it again.</summary>
public sealed class GatewayProvisioningService(IGatewayRegistry registry, IGatewayClock clock, EnrollmentSecurityOptions options)
{
    /// <summary>Creates the registry aggregate and its first one-time activation.</summary>
    public async Task<ProvisionedActivation> CreateInstallationAsync(
        TenantRecord tenant,
        ApplicationRecord application,
        GatewayEnvironmentRecord environment,
        Guid installationId,
        string createdBy,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(createdBy);
        DateTimeOffset now = clock.UtcNow;
        await registry.AddTenantAsync(tenant, cancellationToken).ConfigureAwait(false);
        await registry.AddApplicationAsync(application, cancellationToken).ConfigureAwait(false);
        await registry.AddEnvironmentAsync(environment, cancellationToken).ConfigureAwait(false);
        await registry.AddInstallationAsync(new InstallationRecord(installationId, tenant.Id, application.Id, environment.Id, InstallationStatus.Pending, null, now), cancellationToken).ConfigureAwait(false);
        return await CreateActivationCodeAsync(installationId, createdBy, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates a new one-time activation for a pending Installation.</summary>
    public async Task<ProvisionedActivation> CreateActivationCodeAsync(Guid installationId, string createdBy, CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.UtcNow;
        byte[] rawCode = RandomNumberGenerator.GetBytes(32);
        string code = Base64Url.Encode(rawCode);
        byte[] hmac = HMACSHA256.HashData(options.ActivationHmacKey, Encoding.UTF8.GetBytes(code));
        ActivationCodeRecord activation = new(Guid.NewGuid(), installationId, hmac, now.Add(options.ActivationLifetime), now, createdBy);
        await registry.AddActivationCodeAsync(activation, cancellationToken).ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(rawCode);
        return new ProvisionedActivation(installationId, activation.Id, code, activation.ExpiresAt);
    }
}

/// <summary>Enrollment, renewal and revocation service implementing ADR-0008.</summary>
public sealed class InstallationEnrollmentService(IGatewayRegistry registry, IEnrollmentChallengeStore challengeStore, IGatewayClock clock, EnrollmentSecurityOptions options)
{
    /// <summary>Creates a challenge after validating activation state and the proposed P-256 key.</summary>
    public async Task<EnrollmentChallengeResponse> CreateChallengeAsync(EnrollmentChallengeRequest request, CancellationToken cancellationToken)
    {
        ActivationCodeRecord? activation = await registry.FindActivationCodeAsync(request.ActivationCodeId, cancellationToken).ConfigureAwait(false);
        DateTimeOffset now = clock.UtcNow;
        if (activation is null || activation.UsedAt is not null || activation.ExpiresAt <= now || activation.AttemptCount >= 5) throw new GatewayException("BGW-AUTHN-ENROLLMENT-DENIED", 401);
        byte[] spki;
        try
        {
            spki = Convert.FromBase64String(request.PublicKeySpki);
            using ECDsa key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(spki, out int read);
            if (read != spki.Length || key.KeySize != 256) throw new CryptographicException();
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException)
        {
            throw new GatewayException("BGW-AUTHN-INVALID-PUBLIC-KEY", 400);
        }
        EnrollmentChallenge challenge = challengeStore.Create(request.ActivationCodeId, spki, now, options.ChallengeLifetime);
        return new EnrollmentChallengeResponse(challenge.Id, Base64Url.Encode(challenge.Challenge), challenge.ExpiresAt);
    }

    /// <summary>Consumes a challenge and activation code after proof-of-possession validation.</summary>
    public async Task<EnrollmentResult> ActivateAsync(ActivationRequest request, CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.UtcNow;
        EnrollmentChallenge? challenge = challengeStore.Consume(request.ChallengeId, now);
        if (challenge is null) throw new GatewayException("BGW-AUTHN-CHALLENGE-INVALID", 401);
        ActivationCodeRecord? activation = await registry.FindActivationCodeAsync(challenge.ActivationCodeId, cancellationToken).ConfigureAwait(false);
        byte[] presentedHmac = HMACSHA256.HashData(options.ActivationHmacKey, Encoding.UTF8.GetBytes(request.ActivationCode));
        if (activation is null || activation.UsedAt is not null || activation.ExpiresAt <= now || activation.AttemptCount >= 5 || !CryptographicOperations.FixedTimeEquals(activation.CodeHmac, presentedHmac))
        {
            await registry.RecordActivationFailureAsync(challenge.ActivationCodeId, cancellationToken).ConfigureAwait(false);
            throw new GatewayException("BGW-AUTHN-ENROLLMENT-DENIED", 401);
        }
        X509Certificate2 certificate;
        try { certificate = LoadAndValidateClientCertificate(request.ClientCertificate, now, options.MaximumCredentialLifetime); }
        catch (GatewayException)
        {
            await registry.RecordActivationFailureAsync(challenge.ActivationCodeId, cancellationToken).ConfigureAwait(false);
            throw;
        }
        using (certificate)
        using (ECDsa publicKey = certificate.GetECDsaPublicKey() ?? throw new GatewayException("BGW-AUTHN-INVALID-CERTIFICATE", 400))
        {
            byte[] certificateSpki = publicKey.ExportSubjectPublicKeyInfo();
            if (!CryptographicOperations.FixedTimeEquals(certificateSpki, challenge.PublicKeySpki))
            {
                await registry.RecordActivationFailureAsync(challenge.ActivationCodeId, cancellationToken).ConfigureAwait(false);
                throw new GatewayException("BGW-AUTHN-KEY-MISMATCH", 401);
            }
            byte[] signature;
            try { signature = Base64Url.Decode(request.ProofSignature); }
            catch (FormatException)
            {
                await registry.RecordActivationFailureAsync(challenge.ActivationCodeId, cancellationToken).ConfigureAwait(false);
                throw new GatewayException("BGW-AUTHN-INVALID-PROOF", 401);
            }
            byte[] proof = BuildActivationProof(challenge);
            if (!publicKey.VerifyData(proof, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            {
                await registry.RecordActivationFailureAsync(challenge.ActivationCodeId, cancellationToken).ConfigureAwait(false);
                throw new GatewayException("BGW-AUTHN-INVALID-PROOF", 401);
            }
            byte[] certificateHash = SHA256.HashData(certificate.RawData);
            byte[] spkiHash = SHA256.HashData(certificateSpki);
            InstallationCredentialRecord credential = new(Guid.NewGuid(), activation.InstallationId, certificateHash, spkiHash, certificate.RawData, certificate.SerialNumber, certificate.NotBefore.ToUniversalTime(), certificate.NotAfter.ToUniversalTime(), CredentialStatus.Active, now);
            bool activated = await registry.ActivateAsync(activation.Id, presentedHmac, credential, ValidateBrokerVersion(request.BrokerVersion), now, cancellationToken).ConfigureAwait(false);
            if (!activated) throw new GatewayException("BGW-AUTHN-ENROLLMENT-CONFLICT", 409);
            RegisteredInstallationIdentity identity = await registry.FindIdentityByCertificateAsync(certificateHash, cancellationToken).ConfigureAwait(false) ?? throw new GatewayException("BGW-AUTHN-ENROLLMENT-CONFLICT", 409);
            return new EnrollmentResult(identity.InstallationId, identity.TenantId, identity.ApplicationId, credential.NotAfter, credential.NotAfter.Subtract(options.RenewalWindow));
        }
    }

    /// <summary>Registers a replacement credential inside the configured renewal window.</summary>
    public async Task<EnrollmentResult> RenewAsync(RegisteredInstallationIdentity currentIdentity, RenewalRequest request, CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.UtcNow;
        if (currentIdentity.InstallationStatus != InstallationStatus.Active || currentIdentity.CredentialStatus != CredentialStatus.Active || currentIdentity.CredentialNotAfter - now > options.RenewalWindow) throw new GatewayException("BGW-INSTALLATION-RENEWAL-NOT-ALLOWED", 403);
        X509Certificate2 replacementCertificate = LoadAndValidateClientCertificate(request.NewClientCertificate, now, options.MaximumCredentialLifetime);
        using (replacementCertificate)
        using (ECDsa replacementKey = replacementCertificate.GetECDsaPublicKey() ?? throw new GatewayException("BGW-AUTHN-INVALID-CERTIFICATE", 400))
        {
            byte[] spki = replacementKey.ExportSubjectPublicKeyInfo();
            byte[] proof = BuildRenewalProof(currentIdentity.InstallationId, currentIdentity.CredentialId, SHA256.HashData(spki));
            byte[] signature;
            try { signature = Base64Url.Decode(request.ProofSignature); }
            catch (FormatException) { throw new GatewayException("BGW-AUTHN-INVALID-PROOF", 401); }
            if (!replacementKey.VerifyData(proof, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw new GatewayException("BGW-AUTHN-INVALID-PROOF", 401);
            InstallationCredentialRecord replacement = new(Guid.NewGuid(), currentIdentity.InstallationId, SHA256.HashData(replacementCertificate.RawData), SHA256.HashData(spki), replacementCertificate.RawData, replacementCertificate.SerialNumber, replacementCertificate.NotBefore.ToUniversalTime(), replacementCertificate.NotAfter.ToUniversalTime(), CredentialStatus.Active, now);
            bool renewed = await registry.RenewCredentialAsync(currentIdentity.InstallationId, currentIdentity.CredentialId, replacement, now.Add(options.RenewalOverlap), cancellationToken).ConfigureAwait(false);
            if (!renewed) throw new GatewayException("BGW-INSTALLATION-RENEWAL-CONFLICT", 409);
            return new EnrollmentResult(currentIdentity.InstallationId, currentIdentity.TenantId, currentIdentity.ApplicationId, replacement.NotAfter, replacement.NotAfter.Subtract(options.RenewalWindow));
        }
    }

    /// <summary>Immediately revokes an Installation.</summary>
    public async Task RevokeAsync(Guid installationId, string reason, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Length is < 3 or > 1000) throw new GatewayException("BGW-VALIDATION-REASON", 400);
        if (!await registry.RevokeInstallationAsync(installationId, reason, clock.UtcNow, cancellationToken).ConfigureAwait(false)) throw new GatewayException("BGW-INSTALLATION-NOT-FOUND", 404);
    }

    /// <summary>Builds the canonical activation proof bytes.</summary>
    public static byte[] BuildActivationProof(EnrollmentChallenge challenge) => Encoding.UTF8.GetBytes(FormattableString.Invariant($"BGW-ENROLL1\n{challenge.Id:D}\n{Base64Url.Encode(challenge.Challenge)}\n{challenge.ActivationCodeId:D}"));
    /// <summary>Builds the canonical renewal proof bytes.</summary>
    public static byte[] BuildRenewalProof(Guid installationId, Guid currentCredentialId, byte[] newSpkiSha256) => Encoding.UTF8.GetBytes(FormattableString.Invariant($"BGW-RENEW1\n{installationId:D}\n{currentCredentialId:D}\n{Base64Url.Encode(newSpkiSha256)}"));

    private static string ValidateBrokerVersion(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 64 || !Version.TryParse(value, out _)) throw new GatewayException("BGW-INSTALLATION-BROKER-VERSION", 400);
        return value;
    }

    private static X509Certificate2 LoadAndValidateClientCertificate(string base64Der, DateTimeOffset now, TimeSpan maximumLifetime)
    {
        X509Certificate2 certificate;
        try { certificate = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(base64Der)); }
        catch (Exception exception) when (exception is FormatException or CryptographicException) { throw new GatewayException("BGW-AUTHN-INVALID-CERTIFICATE", 400); }
        bool valid = certificate.NotBefore.ToUniversalTime() <= now.AddMinutes(5) && certificate.NotAfter.ToUniversalTime() > now.AddDays(1) && certificate.NotAfter.ToUniversalTime() <= now.Add(maximumLifetime);
        bool clientAuth = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().Any(extension => extension.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2"));
        using ECDsa? key = certificate.GetECDsaPublicKey();
        if (!valid || !clientAuth || key is null || key.KeySize != 256)
        {
            certificate.Dispose();
            throw new GatewayException("BGW-AUTHN-INVALID-CERTIFICATE", 400);
        }
        return certificate;
    }
}

using System.Collections.Concurrent;
using System.Security.Cryptography;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>Test/development server-side session store with the same expiry and revocation semantics as PostgreSQL.</summary>
public sealed class InMemoryAdminSessionStore : IAdminSessionStore
{
    private readonly IAdminSecurityStore security;
    private readonly ConcurrentDictionary<string, AdminSessionRecord> sessions = new(StringComparer.Ordinal);

    /// <summary>Subscribes Development/Testing sessions to sensitive privilege changes.</summary>
    public InMemoryAdminSessionStore(IAdminSecurityStore security)
    {
        this.security = security;
        if (security is InMemoryAdminSecurityStore inMemory)
            inMemory.PrincipalPrivilegesChanged += RevokePrincipal;
    }

    /// <inheritdoc />
    public async Task<(string Handle, AdminSessionRecord Session)> CreateAsync(AdminExternalIdentity identity, DateTimeOffset now, TimeSpan absoluteLifetime, TimeSpan idleLifetime, CancellationToken cancellationToken)
    {
        AdminPrincipalRecord principal = await security.EnsurePrincipalAsync(identity, cancellationToken).ConfigureAwait(false);
        string handle = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        string key = Hash(handle);
        DateTimeOffset absolute = now.Add(absoluteLifetime);
        AdminSessionRecord session = new(Guid.NewGuid(), principal, now, absolute, Min(absolute, now.Add(idleLifetime)), now, null);
        if (!sessions.TryAdd(key, session)) throw new InvalidOperationException("Session handle collision.");
        return (handle, session);
    }

    /// <inheritdoc />
    public Task<AdminSessionRecord?> ValidateAsync(string handle, DateTimeOffset now, TimeSpan idleLifetime, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string key = Hash(handle);
        while (sessions.TryGetValue(key, out AdminSessionRecord? current))
        {
            if (current.RevokedAt is not null || !current.Principal.Active || current.AbsoluteExpiresAt <= now || current.IdleExpiresAt <= now)
                return Task.FromResult<AdminSessionRecord?>(null);
            AdminSessionRecord touched = current with { LastSeenAt = now, IdleExpiresAt = Min(current.AbsoluteExpiresAt, now.Add(idleLifetime)) };
            if (sessions.TryUpdate(key, touched, current)) return Task.FromResult<AdminSessionRecord?>(touched);
        }
        return Task.FromResult<AdminSessionRecord?>(null);
    }

    /// <inheritdoc />
    public Task RevokeAsync(string handle, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string key = Hash(handle);
        if (sessions.TryGetValue(key, out AdminSessionRecord? current)) sessions[key] = current with { RevokedAt = now };
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RevokePrincipalAsync(Guid principalId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RevokePrincipal(principalId, now);
        return Task.CompletedTask;
    }

    private void RevokePrincipal(Guid principalId, DateTimeOffset now)
    {
        foreach ((string key, AdminSessionRecord value) in sessions.Where(value => value.Value.Principal.Id == principalId && value.Value.RevokedAt is null))
            sessions[key] = value with { RevokedAt = now };
    }

    private static string Hash(string handle) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(handle)));
    private static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right) => left <= right ? left : right;
}

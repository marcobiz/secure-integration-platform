using System.Data;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Infrastructure;

/// <summary>PostgreSQL-backed revocable administrative sessions; only SHA-256 handle digests are persisted.</summary>
public sealed class PostgresAdminSessionStore(AdminPostgresDataSource dataSource, IAdminSecurityStore security) : IAdminSessionStore
{
    /// <inheritdoc />
    public async Task<(string Handle, AdminSessionRecord Session)> CreateAsync(AdminExternalIdentity identity, DateTimeOffset now, TimeSpan absoluteLifetime, TimeSpan idleLifetime, CancellationToken cancellationToken)
    {
        AdminPrincipalRecord principal = await security.EnsurePrincipalAsync(identity, cancellationToken).ConfigureAwait(false);
        string handle = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        byte[] digest = Hash(handle);
        DateTimeOffset absolute = now.Add(absoluteLifetime);
        DateTimeOffset idle = Min(absolute, now.Add(idleLifetime));
        Guid id = Guid.NewGuid();
        await using NpgsqlConnection connection = await dataSource.Value.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("INSERT INTO gateway.admin_session(id,handle_sha256,principal_id,created_at,absolute_expires_at,idle_expires_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$4)", connection);
        command.Parameters.AddWithValue(id); command.Parameters.AddWithValue(digest); command.Parameters.AddWithValue(principal.Id); command.Parameters.AddWithValue(now); command.Parameters.AddWithValue(absolute); command.Parameters.AddWithValue(idle);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        return (handle, new(id, principal, now, absolute, idle, now, null));
    }

    /// <inheritdoc />
    public async Task<AdminSessionRecord?> ValidateAsync(string handle, DateTimeOffset now, TimeSpan idleLifetime, CancellationToken cancellationToken)
    {
        byte[] digest = Hash(handle);
        await using NpgsqlConnection connection = await dataSource.Value.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new("""
            SELECT s.id,p.id,p.issuer,p.subject,p.display_name,p.email,p.active,p.created_at,s.created_at,s.absolute_expires_at,s.idle_expires_at,s.last_seen_at,s.revoked_at
            FROM gateway.admin_session s JOIN gateway.admin_principal p ON p.id=s.principal_id
            WHERE s.handle_sha256=$1 FOR UPDATE OF s
            """, connection, transaction);
        command.Parameters.AddWithValue(digest);
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(CommandBehavior.SingleRow, cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;
        AdminPrincipalRecord principal = new(reader.GetGuid(1), reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.IsDBNull(5) ? null : reader.GetString(5), reader.GetBoolean(6), reader.GetFieldValue<DateTimeOffset>(7));
        AdminSessionRecord current = new(reader.GetGuid(0), principal, reader.GetFieldValue<DateTimeOffset>(8), reader.GetFieldValue<DateTimeOffset>(9), reader.GetFieldValue<DateTimeOffset>(10), reader.GetFieldValue<DateTimeOffset>(11), reader.IsDBNull(12) ? null : reader.GetFieldValue<DateTimeOffset>(12));
        await reader.DisposeAsync().ConfigureAwait(false);
        if (!principal.Active || current.RevokedAt is not null || current.AbsoluteExpiresAt <= now || current.IdleExpiresAt <= now) return null;
        DateTimeOffset idle = Min(current.AbsoluteExpiresAt, now.Add(idleLifetime));
        await using NpgsqlCommand touch = new("UPDATE gateway.admin_session SET last_seen_at=$2,idle_expires_at=$3 WHERE id=$1", connection, transaction);
        touch.Parameters.AddWithValue(current.Id); touch.Parameters.AddWithValue(now); touch.Parameters.AddWithValue(idle);
        await touch.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return current with { LastSeenAt = now, IdleExpiresAt = idle };
    }

    /// <inheritdoc />
    public Task RevokeAsync(string handle, DateTimeOffset now, CancellationToken cancellationToken) => ExecuteAsync("UPDATE gateway.admin_session SET revoked_at=coalesce(revoked_at,$2) WHERE handle_sha256=$1", cancellationToken, Hash(handle), now);
    /// <inheritdoc />
    public Task RevokePrincipalAsync(Guid principalId, DateTimeOffset now, CancellationToken cancellationToken) => ExecuteAsync("UPDATE gateway.admin_session SET revoked_at=coalesce(revoked_at,$2) WHERE principal_id=$1", cancellationToken, principalId, now);

    private async Task ExecuteAsync(string sql, CancellationToken cancellationToken, params object[] values)
    {
        await using NpgsqlConnection connection = await dataSource.Value.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlCommand command = new(sql, connection);
        for (int index = 0; index < values.Length; index++) command.Parameters.AddWithValue(values[index]);
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static byte[] Hash(string handle) => SHA256.HashData(Encoding.UTF8.GetBytes(handle));
    private static DateTimeOffset Min(DateTimeOffset left, DateTimeOffset right) => left <= right ? left : right;
}

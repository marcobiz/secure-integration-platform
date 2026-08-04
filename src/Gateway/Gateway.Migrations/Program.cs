using System.Security.Cryptography;
using Npgsql;

if (args.Length != 1 || !string.Equals(args[0], "apply", StringComparison.Ordinal))
{
    Console.Error.WriteLine("Usage: SecureIntegration.Gateway.Migrations apply");
    return 2;
}

string? connectionString = Environment.GetEnvironmentVariable("GATEWAY_MIGRATION_CONNECTION");
if (string.IsNullOrWhiteSpace(connectionString))
{
    Console.Error.WriteLine("GATEWAY_MIGRATION_CONNECTION is required.");
    return 2;
}

string migrationsPath = Path.Combine(AppContext.BaseDirectory, "Migrations");
string[] migrations = Directory.GetFiles(migrationsPath, "*.sql").Order(StringComparer.Ordinal).ToArray();
if (migrations.Length == 0)
{
    Console.Error.WriteLine("No migrations found.");
    return 3;
}

await using NpgsqlConnection connection = new(connectionString);
await connection.OpenAsync().ConfigureAwait(false);
await using (NpgsqlCommand bootstrap = new("CREATE SCHEMA IF NOT EXISTS gateway; CREATE TABLE IF NOT EXISTS gateway.schema_migration(name text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());", connection))
    await bootstrap.ExecuteNonQueryAsync().ConfigureAwait(false);

foreach (string path in migrations)
{
    string name = Path.GetFileName(path);
    string sql = await File.ReadAllTextAsync(path).ConfigureAwait(false);
    string hash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sql)));
    await using NpgsqlCommand existing = new("SELECT sha256 FROM gateway.schema_migration WHERE name=$1", connection);
    existing.Parameters.AddWithValue(name);
    string? recorded = (string?)await existing.ExecuteScalarAsync().ConfigureAwait(false);
    if (recorded is not null)
    {
        if (!string.Equals(recorded, hash, StringComparison.Ordinal)) throw new InvalidOperationException($"Applied migration changed: {name}");
        continue;
    }
    await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync().ConfigureAwait(false);
    await using (NpgsqlCommand apply = new(sql, connection, transaction)) await apply.ExecuteNonQueryAsync().ConfigureAwait(false);
    await using (NpgsqlCommand record = new("INSERT INTO gateway.schema_migration(name,sha256) VALUES($1,$2)", connection, transaction))
    {
        record.Parameters.AddWithValue(name);
        record.Parameters.AddWithValue(hash);
        await record.ExecuteNonQueryAsync().ConfigureAwait(false);
    }
    await transaction.CommitAsync().ConfigureAwait(false);
    Console.WriteLine($"Applied {name} ({hash})");
}

return 0;

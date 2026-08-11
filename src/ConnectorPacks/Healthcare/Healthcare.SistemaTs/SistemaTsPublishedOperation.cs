using System.Text.Json;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.ConnectorPacks.Healthcare.SistemaTs;

internal sealed record SistemaTsPublishedOperation(string OperationId)
{
    private const string Profile = "ricetta-dem-erogatore";
    private static readonly string[] RequiredProperties = ["contractVersion", "operation", "profile"];

    internal static SistemaTsPublishedOperation Read(AuthorizedConnectorExecution execution)
    {
        try
        {
            AuthorizedPublishedExtensionConfiguration configuration = execution.OpenPublishedExtensionConfiguration();
            using Stream json = configuration.OpenJsonStream();
            using JsonDocument document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                root.EnumerateObject().Select(value => value.Name).OrderBy(value => value, StringComparer.Ordinal)
                    .SequenceEqual(RequiredProperties, StringComparer.Ordinal) is false ||
                !string.Equals(root.GetProperty("profile").GetString(), Profile, StringComparison.Ordinal))
                throw new JsonException();

            string operation = root.GetProperty("operation").GetString() ?? throw new JsonException();
            string version = root.GetProperty("contractVersion").GetString() ?? throw new JsonException();
            string expectedVersion = string.Equals(operation, SistemaTsOperationCatalog.SessionCreate.OperationId, StringComparison.Ordinal)
                ? "id-session-0.1"
                : "ssn-erogatore-1.5.1";
            if (!string.Equals(version, expectedVersion, StringComparison.Ordinal) ||
                !string.Equals(operation, execution.OperationId, StringComparison.Ordinal))
                throw new JsonException();
            return new(operation);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or KeyNotFoundException)
        {
            throw new InvalidOperationException("Sistema TS Published extension configuration is invalid.");
        }
    }
}

internal static class SistemaTsBoundedContent
{
    internal static async Task<byte[]> ReadAsync(Stream source, int expectedLength, CancellationToken cancellationToken)
    {
        if (expectedLength is < 1 or > 16 * 1024 * 1024)
            throw new InvalidOperationException("Sistema TS payload length is invalid.");
        byte[] bytes = GC.AllocateUninitializedArray<byte>(expectedLength);
        int offset = 0;
        while (offset < bytes.Length)
        {
            int read = await source.ReadAsync(bytes.AsMemory(offset), cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new InvalidOperationException("Sistema TS payload ended unexpectedly.");
            offset += read;
        }
        if (source.ReadByte() != -1) throw new InvalidOperationException("Sistema TS payload exceeded its authorized length.");
        return bytes;
    }
}

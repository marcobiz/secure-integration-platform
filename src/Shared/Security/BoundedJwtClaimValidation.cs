using System.Buffers;
using System.Text;
using System.Text.Json;

namespace SecureIntegration.Security;

internal enum BoundedJwtClaimFailure
{
    Count,
    Name,
    Value,
    Aggregate
}

internal sealed class BoundedJwtClaimValidationException(BoundedJwtClaimFailure failure) : Exception
{
    internal BoundedJwtClaimFailure Failure { get; } = failure;
}

internal static class BoundedJwtClaimValidation
{
    internal const int MaximumClaims = 32;
    internal const int MaximumNameCharacters = 64;
    internal const int MaximumSerializedValueCharacters = 4_096;
    internal const int MaximumStringCharacters = 1_024;
    internal const int MaximumAggregateCharacters = MaximumClaims * MaximumSerializedValueCharacters;
    private const int MaximumSerializedValueBytes = MaximumSerializedValueCharacters * 4 + 2;

    internal static void ValidateNext(
        string? name,
        JsonElement value,
        ref int actualCount,
        ref int aggregateCharacters)
    {
        actualCount = checked(actualCount + 1);
        if (actualCount > MaximumClaims)
            throw new BoundedJwtClaimValidationException(BoundedJwtClaimFailure.Count);
        if (!ValidName(name))
            throw new BoundedJwtClaimValidationException(BoundedJwtClaimFailure.Name);
        if (value.ValueKind is not (JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null))
            throw new BoundedJwtClaimValidationException(BoundedJwtClaimFailure.Value);

        int serializedCharacters = MeasureSerializedCharacters(value);
        if (serializedCharacters > MaximumSerializedValueCharacters)
            throw new BoundedJwtClaimValidationException(BoundedJwtClaimFailure.Value);
        if (value.ValueKind == JsonValueKind.String && value.GetString()!.Length > MaximumStringCharacters)
            throw new BoundedJwtClaimValidationException(BoundedJwtClaimFailure.Value);

        aggregateCharacters = checked(aggregateCharacters + name!.Length + serializedCharacters);
        if (aggregateCharacters > MaximumAggregateCharacters)
            throw new BoundedJwtClaimValidationException(BoundedJwtClaimFailure.Aggregate);
    }

    internal static bool ValidName(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= MaximumNameCharacters &&
        value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.');

    private static int MeasureSerializedCharacters(JsonElement value)
    {
        FixedBufferWriter output = new(MaximumSerializedValueBytes);
        try
        {
            using Utf8JsonWriter writer = new(output, new JsonWriterOptions { Indented = false, SkipValidation = false });
            value.WriteTo(writer);
            writer.Flush();
            return Encoding.UTF8.GetCharCount(output.WrittenSpan);
        }
        catch (BoundedJwtClaimValidationException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or JsonException)
        {
            throw new BoundedJwtClaimValidationException(BoundedJwtClaimFailure.Value);
        }
    }

    private sealed class FixedBufferWriter(int capacity) : IBufferWriter<byte>
    {
        private readonly byte[] buffer = new byte[capacity];
        private int written;

        internal ReadOnlySpan<byte> WrittenSpan => buffer.AsSpan(0, written);

        public void Advance(int count)
        {
            if (count < 0 || count > buffer.Length - written)
                throw new BoundedJwtClaimValidationException(BoundedJwtClaimFailure.Value);
            written += count;
        }

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            Ensure(sizeHint);
            return buffer.AsMemory(written);
        }

        public Span<byte> GetSpan(int sizeHint = 0)
        {
            Ensure(sizeHint);
            return buffer.AsSpan(written);
        }

        private void Ensure(int sizeHint)
        {
            if (sizeHint < 0 || sizeHint > buffer.Length - written || (sizeHint == 0 && written == buffer.Length))
                throw new BoundedJwtClaimValidationException(BoundedJwtClaimFailure.Value);
        }
    }
}

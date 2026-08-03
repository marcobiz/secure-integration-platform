using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

#pragma warning disable CA1835 // Keep the netstandard2.0-compatible Stream overloads in the shared codec.
#pragma warning disable CA1510 // ThrowIfNull is unavailable on the netstandard2.0 target.
#pragma warning disable CA1846 // Span parsing is unavailable on the netstandard2.0 target.
#pragma warning disable CA2263 // Generic Enum.IsDefined is unavailable on the netstandard2.0 target.

namespace SecureIntegration.Contracts;

/// <summary>Version and hard limits for Local Broker IPC protocol v1.</summary>
public static class IpcProtocol
{
    /// <summary>Protocol magic bytes.</summary>
    public static readonly byte[] Magic = Encoding.ASCII.GetBytes("BGR1");

    /// <summary>Protocol major version.</summary>
    public const byte Major = 1;

    /// <summary>Protocol minor version.</summary>
    public const byte Minor = 0;

    /// <summary>Fixed frame header size.</summary>
    public const int HeaderSize = 36;

    /// <summary>Maximum JSON control frame bytes.</summary>
    public const int MaxControlBytes = 1_048_576;

    /// <summary>Maximum data frame chunk bytes.</summary>
    public const int MaxDataFrameBytes = 65_536;

    /// <summary>Maximum standard aggregate payload bytes.</summary>
    public const int MaxPayloadBytes = 16_777_216;

    /// <summary>Maximum streamed aggregate payload bytes.</summary>
    public const int MaxStreamBytes = 67_108_864;

    /// <summary>Shared JSON serialization options for the wire protocol.</summary>
    public static JsonSerializerOptions JsonOptions { get; } = CreateJsonOptions();

    private static JsonSerializerOptions CreateJsonOptions()
    {
        JsonSerializerOptions options = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            MaxDepth = 32,
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
        return options;
    }
}

/// <summary>IPC frame kinds.</summary>
public enum IpcFrameType : byte
{
    /// <summary>JSON control frame.</summary>
    Control = 1,

    /// <summary>Binary data chunk.</summary>
    Data = 2,

    /// <summary>End of a binary stream.</summary>
    End = 3,

    /// <summary>Cancellation request.</summary>
    Cancel = 4,

    /// <summary>Protocol-level error.</summary>
    Error = 5,
}

/// <summary>An immutable IPC frame.</summary>
public sealed class IpcFrame
{
    /// <summary>Creates an IPC frame.</summary>
    public IpcFrame(IpcFrameType type, Guid correlationId, ulong sequence, byte[] body)
    {
        Type = type;
        CorrelationId = correlationId;
        Sequence = sequence;
        Body = body ?? throw new ArgumentNullException(nameof(body));
    }

    /// <summary>Frame type.</summary>
    public IpcFrameType Type { get; }

    /// <summary>Request correlation identifier.</summary>
    public Guid CorrelationId { get; }

    /// <summary>Monotonic sequence within a connection.</summary>
    public ulong Sequence { get; }

    /// <summary>Raw frame body.</summary>
    public byte[] Body { get; }
}

/// <summary>Reads and writes the versioned IPC frame format.</summary>
public static class IpcFrameCodec
{
    /// <summary>Writes one complete frame.</summary>
    public static async Task WriteAsync(Stream stream, IpcFrame frame, CancellationToken cancellationToken)
    {
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }

        if (frame is null)
        {
            throw new ArgumentNullException(nameof(frame));
        }
        ValidateBodyLength(frame.Type, frame.Body.Length);

        byte[] header = new byte[IpcProtocol.HeaderSize];
        Buffer.BlockCopy(IpcProtocol.Magic, 0, header, 0, IpcProtocol.Magic.Length);
        header[4] = IpcProtocol.Major;
        header[5] = IpcProtocol.Minor;
        header[6] = (byte)frame.Type;
        header[7] = 0;
        WriteUInt32(header, 8, checked((uint)frame.Body.Length));
        byte[] guidBytes = GuidToNetworkBytes(frame.CorrelationId);
        Buffer.BlockCopy(guidBytes, 0, header, 12, guidBytes.Length);
        WriteUInt64(header, 28, frame.Sequence);

        await stream.WriteAsync(header, 0, header.Length, cancellationToken).ConfigureAwait(false);
        if (frame.Body.Length > 0)
        {
            await stream.WriteAsync(frame.Body, 0, frame.Body.Length, cancellationToken).ConfigureAwait(false);
        }

        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads one complete frame or returns null on a clean EOF before a header.</summary>
    public static async Task<IpcFrame?> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        if (stream is null)
        {
            throw new ArgumentNullException(nameof(stream));
        }
        byte[] header = new byte[IpcProtocol.HeaderSize];
        int first = await stream.ReadAsync(header, 0, 1, cancellationToken).ConfigureAwait(false);
        if (first == 0)
        {
            return null;
        }

        await ReadExactlyAsync(stream, header, 1, header.Length - 1, cancellationToken).ConfigureAwait(false);
        for (int index = 0; index < IpcProtocol.Magic.Length; index++)
        {
            if (header[index] != IpcProtocol.Magic[index])
            {
                throw new InvalidDataException("Invalid IPC frame magic.");
            }
        }

        if (header[4] != IpcProtocol.Major || header[5] > IpcProtocol.Minor)
        {
            throw new InvalidDataException("Unsupported IPC frame version.");
        }

        if (header[7] != 0)
        {
            throw new InvalidDataException("Reserved IPC flags must be zero.");
        }

        IpcFrameType type = (IpcFrameType)header[6];
        if (!Enum.IsDefined(typeof(IpcFrameType), type))
        {
            throw new InvalidDataException("Unknown IPC frame type.");
        }

        int length = checked((int)ReadUInt32(header, 8));
        ValidateBodyLength(type, length);
        Guid correlationId = NetworkBytesToGuid(header, 12);
        ulong sequence = ReadUInt64(header, 28);
        byte[] body = new byte[length];
        await ReadExactlyAsync(stream, body, 0, length, cancellationToken).ConfigureAwait(false);
        return new IpcFrame(type, correlationId, sequence, body);
    }

    /// <summary>Serializes a JSON control payload.</summary>
    public static IpcFrame JsonFrame<T>(Guid correlationId, ulong sequence, T value)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(value, IpcProtocol.JsonOptions);
        return new IpcFrame(IpcFrameType.Control, correlationId, sequence, body);
    }

    /// <summary>Deserializes a JSON control payload.</summary>
    public static T Deserialize<T>(IpcFrame frame)
    {
        if (frame.Type != IpcFrameType.Control && frame.Type != IpcFrameType.Error)
        {
            throw new InvalidDataException("Expected a JSON control frame.");
        }

        return JsonSerializer.Deserialize<T>(frame.Body, IpcProtocol.JsonOptions)
            ?? throw new InvalidDataException("IPC JSON body was null.");
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        byte[] buffer,
        int offset,
        int count,
        CancellationToken cancellationToken)
    {
        while (count > 0)
        {
            int read = await stream.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF in IPC frame.");
            }

            offset += read;
            count -= read;
        }
    }

    private static void ValidateBodyLength(IpcFrameType type, int length)
    {
        int maximum = type == IpcFrameType.Data
            ? IpcProtocol.MaxDataFrameBytes
            : IpcProtocol.MaxControlBytes;
        if (length < 0 || length > maximum)
        {
            throw new InvalidDataException($"IPC frame exceeds the {maximum.ToString(CultureInfo.InvariantCulture)} byte limit.");
        }
    }

    private static void WriteUInt32(byte[] target, int offset, uint value)
    {
        target[offset] = (byte)(value >> 24);
        target[offset + 1] = (byte)(value >> 16);
        target[offset + 2] = (byte)(value >> 8);
        target[offset + 3] = (byte)value;
    }

    private static uint ReadUInt32(byte[] source, int offset)
    {
        return ((uint)source[offset] << 24)
            | ((uint)source[offset + 1] << 16)
            | ((uint)source[offset + 2] << 8)
            | source[offset + 3];
    }

    private static void WriteUInt64(byte[] target, int offset, ulong value)
    {
        for (int index = 7; index >= 0; index--)
        {
            target[offset + index] = (byte)value;
            value >>= 8;
        }
    }

    private static ulong ReadUInt64(byte[] source, int offset)
    {
        ulong value = 0;
        for (int index = 0; index < 8; index++)
        {
            value = (value << 8) | source[offset + index];
        }

        return value;
    }

    private static byte[] GuidToNetworkBytes(Guid value)
    {
        string hex = value.ToString("N", CultureInfo.InvariantCulture);
        byte[] bytes = new byte[16];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = byte.Parse(hex.Substring(index * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        }

        return bytes;
    }

    private static Guid NetworkBytesToGuid(byte[] source, int offset)
    {
        StringBuilder hex = new(32);
        for (int index = 0; index < 16; index++)
        {
            _ = hex.Append(source[offset + index].ToString("x2", CultureInfo.InvariantCulture));
        }

        string value = hex.ToString();
        return Guid.ParseExact(
            value.Substring(0, 8) + "-" +
            value.Substring(8, 4) + "-" +
            value.Substring(12, 4) + "-" +
            value.Substring(16, 4) + "-" +
            value.Substring(20, 12),
            "D");
    }
}

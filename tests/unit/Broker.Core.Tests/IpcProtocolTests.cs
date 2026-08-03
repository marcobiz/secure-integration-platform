using SecureIntegration.Contracts;
using Xunit;

namespace SecureIntegration.Broker.Core.Tests;

public sealed class IpcProtocolTests
{
    [Fact]
    public async Task IPC_frame_round_trip_preserves_network_header_and_payload()
    {
        Guid correlation = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
        await using MemoryStream stream = new();
        IpcFrame expected = new(IpcFrameType.Data, correlation, 0x0102030405060708, [1, 2, 3]);
        await IpcFrameCodec.WriteAsync(stream, expected, TestContext.Current.CancellationToken);
        byte[] wire = stream.ToArray();

        Assert.Equal("BGR1"u8.ToArray(), wire[..4]);
        Assert.Equal([0, 0, 0, 3], wire[8..12]);
        Assert.Equal(Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), wire[12..28]);
        Assert.Equal(Convert.FromHexString("0102030405060708"), wire[28..36]);
        stream.Position = 0;
        IpcFrame actual = Assert.IsType<IpcFrame>(await IpcFrameCodec.ReadAsync(stream, TestContext.Current.CancellationToken));
        Assert.Equal(expected.Type, actual.Type);
        Assert.Equal(expected.CorrelationId, actual.CorrelationId);
        Assert.Equal(expected.Sequence, actual.Sequence);
        Assert.Equal(expected.Body, actual.Body);
    }

    [Theory]
    [InlineData(IpcFrameType.Control, IpcProtocol.MaxControlBytes)]
    [InlineData(IpcFrameType.Data, IpcProtocol.MaxDataFrameBytes)]
    public async Task IPC_frame_accepts_exact_hard_limit(IpcFrameType type, int length)
    {
        await using MemoryStream stream = new();
        await IpcFrameCodec.WriteAsync(stream, new IpcFrame(type, Guid.NewGuid(), 1, new byte[length]), TestContext.Current.CancellationToken);
        Assert.Equal(IpcProtocol.HeaderSize + length, stream.Length);
    }

    [Theory]
    [InlineData(IpcFrameType.Control, IpcProtocol.MaxControlBytes + 1)]
    [InlineData(IpcFrameType.Data, IpcProtocol.MaxDataFrameBytes + 1)]
    public async Task IPC_frame_rejects_body_above_hard_limit(IpcFrameType type, int length)
    {
        await using MemoryStream stream = new();
        await Assert.ThrowsAsync<InvalidDataException>(() => IpcFrameCodec.WriteAsync(stream, new IpcFrame(type, Guid.NewGuid(), 1, new byte[length]), TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(0, 0x58)]
    [InlineData(4, 0x02)]
    [InlineData(6, 0xFF)]
    [InlineData(7, 0x01)]
    public async Task IPC_frame_rejects_invalid_magic_version_type_and_flags(int offset, int replacement)
    {
        await using MemoryStream valid = new();
        await IpcFrameCodec.WriteAsync(valid, new IpcFrame(IpcFrameType.Control, Guid.NewGuid(), 0, []), TestContext.Current.CancellationToken);
        byte[] malformed = valid.ToArray();
        malformed[offset] = checked((byte)replacement);
        await using MemoryStream stream = new(malformed);
        await Assert.ThrowsAsync<InvalidDataException>(() => IpcFrameCodec.ReadAsync(stream, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task IPC_frame_distinguishes_clean_EOF_from_truncated_frame()
    {
        await using MemoryStream empty = new();
        Assert.Null(await IpcFrameCodec.ReadAsync(empty, TestContext.Current.CancellationToken));
        await using MemoryStream truncated = new("BGR1"u8.ToArray());
        await Assert.ThrowsAsync<EndOfStreamException>(() => IpcFrameCodec.ReadAsync(truncated, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void IPC_control_JSON_rejects_unknown_properties()
    {
        byte[] json = "{\"logicalName\":\"x\",\"secretClass\":\"Tenant\",\"valueBase64\":\"AQ==\",\"allowedOperations\":[],\"unexpected\":true}"u8.ToArray();
        IpcFrame frame = new(IpcFrameType.Control, Guid.NewGuid(), 1, json);
        Assert.Throws<System.Text.Json.JsonException>(() => IpcFrameCodec.Deserialize<PutLocalSecretRequest>(frame));
    }
}

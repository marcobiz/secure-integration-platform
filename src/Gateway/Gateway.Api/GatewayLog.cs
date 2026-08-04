namespace SecureIntegration.Gateway.Api;

internal static class GatewayLog
{
    private static readonly Action<ILogger, string, string, Exception?> Rejected = LoggerMessage.Define<string, string>(
        LogLevel.Warning, new EventId(1001, "GatewayRequestRejected"), "Gateway request rejected. Code {Code}; correlation {CorrelationId}");
    private static readonly Action<ILogger, string, string, Exception?> Failed = LoggerMessage.Define<string, string>(
        LogLevel.Error, new EventId(1002, "GatewayRequestFailed"), "Gateway request failed. Code {Code}; correlation {CorrelationId}");

    internal static void RequestRejected(ILogger logger, string code, string correlationId) => Rejected(logger, code, correlationId, null);
    internal static void RequestFailed(ILogger logger, string code, string correlationId) => Failed(logger, code, correlationId, null);
}

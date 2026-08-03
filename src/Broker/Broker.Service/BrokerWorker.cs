using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureIntegration.Broker.Core;
using SecureIntegration.Broker.Infrastructure.Windows;

namespace SecureIntegration.Broker.Service;

internal sealed class BrokerWorker(NamedPipeBrokerServer server) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => server.RunAsync(stoppingToken);
}

internal sealed partial class LoggerAuditSink(ILogger<LoggerAuditSink> logger) : IBrokerAuditSink
{
    public Task WriteAsync(string operation, string applicationId, Guid correlationId, bool succeeded, string? errorCode, CancellationToken cancellationToken)
    {
        WriteAudit(logger, operation, applicationId, correlationId, succeeded, errorCode);
        return Task.CompletedTask;
    }

    [LoggerMessage(EventId = 1000, Level = LogLevel.Information, Message = "Broker operation {Operation} application {ApplicationId} correlation {CorrelationId} succeeded {Succeeded} error {ErrorCode}")]
    private static partial void WriteAudit(ILogger logger, string operation, string applicationId, Guid correlationId, bool succeeded, string? errorCode);
}

using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Integration.Tests;

/// <summary>Test-only process-local double; product workflow correlation is PostgreSQL-only.</summary>
internal sealed class TestConnectorWorkflowContextStore(IGatewayClock clock) : IConnectorWorkflowContextStore
{
    private readonly object synchronization = new();
    private readonly List<ConnectorWorkflowContextStorageRecord> records = [];

    public Task<ConnectorWorkflowContextRecordResult> RecordAsync(
        ConnectorWorkflowContextStorageRecord record,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (synchronization)
        {
            ConnectorWorkflowContextStorageRecord[] matches = records.Where(existing => SameAuthority(existing.Authority, record.Authority) &&
                (record.Context.WorkflowInstanceId is not null && string.Equals(existing.Context.WorkflowInstanceId, record.Context.WorkflowInstanceId, StringComparison.Ordinal) ||
                 record.Context.TraceId is not null && string.Equals(existing.Context.TraceId, record.Context.TraceId, StringComparison.Ordinal)))
                .ToArray();
            if (matches.Length == 0)
            {
                records.Add(record with { RecordedAtUtc = clock.UtcNow });
                return Task.FromResult(ConnectorWorkflowContextRecordResult.Created);
            }
            return Task.FromResult(matches.Length == 1 && SameContext(matches[0].Context, record.Context)
                ? ConnectorWorkflowContextRecordResult.Unchanged
                : ConnectorWorkflowContextRecordResult.Conflict);
        }
    }

    public Task<AuthorizedConnectorWorkflowContext?> ResolveAsync(
        ConnectorWorkflowContextAuthorityScope authority,
        ConnectorWorkflowContextLookup lookup,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (synchronization)
        {
            ConnectorWorkflowContextStorageRecord? record = records.SingleOrDefault(existing =>
                SameAuthority(existing.Authority, authority) &&
                (lookup.Kind == ConnectorWorkflowIdentifierKind.WorkflowInstanceId
                    ? string.Equals(existing.Context.WorkflowInstanceId, lookup.Identifier, StringComparison.Ordinal)
                    : string.Equals(existing.Context.TraceId, lookup.Identifier, StringComparison.Ordinal)));
            return Task.FromResult(record is null ? null : new AuthorizedConnectorWorkflowContext(
                record.Context.OriginatingOperationId,
                record.Context.ActionCode,
                record.Context.PurposeOfUseCode,
                record.Context.OperationProfileChecksumSha256,
                record.Context.WorkflowInstanceId,
                record.Context.TraceId,
                record.RecordedAtUtc));
        }
    }

    private static bool SameAuthority(
        ConnectorWorkflowContextAuthorityScope left,
        ConnectorWorkflowContextAuthorityScope right) =>
        left.TenantId == right.TenantId && left.ApplicationId == right.ApplicationId &&
        left.InstallationId == right.InstallationId && left.EnvironmentId == right.EnvironmentId &&
        string.Equals(left.ConnectorId, right.ConnectorId, StringComparison.Ordinal) &&
        string.Equals(left.ConnectorVersion, right.ConnectorVersion, StringComparison.Ordinal) &&
        left.PublishedContextSha256.AsSpan().SequenceEqual(right.PublishedContextSha256);

    private static bool SameContext(ConnectorWorkflowContextRecord left, ConnectorWorkflowContextRecord right) =>
        string.Equals(left.OriginatingOperationId, right.OriginatingOperationId, StringComparison.Ordinal) &&
        string.Equals(left.ActionCode, right.ActionCode, StringComparison.Ordinal) &&
        string.Equals(left.PurposeOfUseCode, right.PurposeOfUseCode, StringComparison.Ordinal) &&
        string.Equals(left.OperationProfileChecksumSha256, right.OperationProfileChecksumSha256, StringComparison.Ordinal) &&
        string.Equals(left.WorkflowInstanceId, right.WorkflowInstanceId, StringComparison.Ordinal) &&
        string.Equals(left.TraceId, right.TraceId, StringComparison.Ordinal);
}

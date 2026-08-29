using Npgsql;
using SecureIntegration.Gateway.Domain;

namespace SecureIntegration.Gateway.Infrastructure;

internal static class GatewayAuditFailureDiagnosticsStorage
{
    internal static (object Phase, object Status, object Category, object UpstreamCode, object LocalCode) Values(
        GatewayAuditFailureDiagnostics? diagnostics) => diagnostics is null
        ? (DBNull.Value, DBNull.Value, DBNull.Value, DBNull.Value, DBNull.Value)
        : (
            Phase(diagnostics.FailurePhase),
            diagnostics.UpstreamStatus is int status ? status : DBNull.Value,
            Category(diagnostics.StatusCategory),
            diagnostics.SafeUpstreamCode is string upstreamCode ? upstreamCode : DBNull.Value,
            diagnostics.LocalSafeCode is string localCode ? localCode : DBNull.Value);

    internal static GatewayAuditFailureDiagnostics? Read(NpgsqlDataReader reader, int offset)
    {
        if (reader.IsDBNull(offset))
        {
            if (!reader.IsDBNull(offset + 1) || !reader.IsDBNull(offset + 2) ||
                !reader.IsDBNull(offset + 3) || !reader.IsDBNull(offset + 4))
                throw new InvalidOperationException("Incomplete audit failure diagnostics were persisted.");
            return null;
        }

        GatewayAuditFailurePhase phase = reader.GetString(offset) switch
        {
            "DNS_FAILURE" => GatewayAuditFailurePhase.DnsFailure,
            "TCP_CONNECT_FAILURE" => GatewayAuditFailurePhase.TcpConnectFailure,
            "TLS_SERVER_VALIDATION_FAILURE" => GatewayAuditFailurePhase.TlsServerValidationFailure,
            "MTLS_CLIENT_AUTH_FAILURE" => GatewayAuditFailurePhase.MutualTlsClientAuthenticationFailure,
            "TIMEOUT" => GatewayAuditFailurePhase.Timeout,
            "TRANSPORT_FAILURE_OTHER" => GatewayAuditFailurePhase.TransportFailureOther,
            "UPSTREAM_HTTP_RESPONSE" => GatewayAuditFailurePhase.UpstreamHttpResponse,
            "LOCAL_RESPONSE_MAPPING_FAILURE" => GatewayAuditFailurePhase.LocalResponseMappingFailure,
            _ => throw new InvalidOperationException("Unknown persisted audit failure phase.")
        };
        GatewayAuditStatusCategory category = reader.GetString(offset + 2) switch
        {
            "NO_UPSTREAM_RESPONSE" => GatewayAuditStatusCategory.NoUpstreamResponse,
            "INFORMATIONAL" => GatewayAuditStatusCategory.Informational,
            "SUCCESS" => GatewayAuditStatusCategory.Success,
            "REDIRECTION" => GatewayAuditStatusCategory.Redirection,
            "CLIENT_ERROR" => GatewayAuditStatusCategory.ClientError,
            "SERVER_ERROR" => GatewayAuditStatusCategory.ServerError,
            _ => throw new InvalidOperationException("Unknown persisted audit status category.")
        };
        return GatewayAuditFailureDiagnostics.Create(
            phase,
            reader.IsDBNull(offset + 1) ? null : reader.GetInt32(offset + 1),
            category,
            reader.IsDBNull(offset + 3) ? null : reader.GetString(offset + 3),
            reader.IsDBNull(offset + 4) ? null : reader.GetString(offset + 4));
    }

    internal static string Phase(GatewayAuditFailurePhase value) => value switch
    {
        GatewayAuditFailurePhase.DnsFailure => "DNS_FAILURE",
        GatewayAuditFailurePhase.TcpConnectFailure => "TCP_CONNECT_FAILURE",
        GatewayAuditFailurePhase.TlsServerValidationFailure => "TLS_SERVER_VALIDATION_FAILURE",
        GatewayAuditFailurePhase.MutualTlsClientAuthenticationFailure => "MTLS_CLIENT_AUTH_FAILURE",
        GatewayAuditFailurePhase.Timeout => "TIMEOUT",
        GatewayAuditFailurePhase.TransportFailureOther => "TRANSPORT_FAILURE_OTHER",
        GatewayAuditFailurePhase.UpstreamHttpResponse => "UPSTREAM_HTTP_RESPONSE",
        GatewayAuditFailurePhase.LocalResponseMappingFailure => "LOCAL_RESPONSE_MAPPING_FAILURE",
        _ => throw new ArgumentOutOfRangeException(nameof(value))
    };

    internal static string Category(GatewayAuditStatusCategory value) => value switch
    {
        GatewayAuditStatusCategory.NoUpstreamResponse => "NO_UPSTREAM_RESPONSE",
        GatewayAuditStatusCategory.Informational => "INFORMATIONAL",
        GatewayAuditStatusCategory.Success => "SUCCESS",
        GatewayAuditStatusCategory.Redirection => "REDIRECTION",
        GatewayAuditStatusCategory.ClientError => "CLIENT_ERROR",
        GatewayAuditStatusCategory.ServerError => "SERVER_ERROR",
        _ => throw new ArgumentOutOfRangeException(nameof(value))
    };
}

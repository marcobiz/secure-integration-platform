using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Http.OAuth;

internal static class OAuthFailures
{
    internal static GatewayException Configuration() => new("BGW-EGRESS-AUTHENTICATION", 500);
    internal static GatewayException Rejected() => new("BGW-EGRESS-AUTHENTICATION", 502);
    internal static GatewayException ReacquisitionRequired() => new("BGW-EGRESS-AUTHENTICATION", 401);
}

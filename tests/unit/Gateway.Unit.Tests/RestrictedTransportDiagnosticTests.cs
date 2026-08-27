using SecureIntegration.Gateway.Application;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class RestrictedTransportDiagnosticTests
{
    [Theory]
    [InlineData(RestrictedTransportFailurePhase.DnsFailure, "DNS_FAILURE")]
    [InlineData(RestrictedTransportFailurePhase.TcpConnectFailure, "TCP_CONNECT_FAILURE")]
    [InlineData(RestrictedTransportFailurePhase.TlsServerValidationFailure, "TLS_SERVER_VALIDATION_FAILURE")]
    [InlineData(RestrictedTransportFailurePhase.MutualTlsClientAuthenticationFailure, "MTLS_CLIENT_AUTH_FAILURE")]
    [InlineData(RestrictedTransportFailurePhase.Timeout, "TIMEOUT")]
    [InlineData(RestrictedTransportFailurePhase.TransportFailureOther, "TRANSPORT_FAILURE_OTHER")]
    public void FSE2_TRANSPORT_all_safe_failure_phases_are_closed_and_metadata_only(
        RestrictedTransportFailurePhase phase,
        string expected)
    {
        SafeUpstreamFailureDiagnostics diagnostics = SafeUpstreamFailureDiagnostics.Transport(phase);

        Assert.Equal(expected, diagnostics.FailurePhase);
        Assert.Null(diagnostics.UpstreamStatus);
        Assert.Null(diagnostics.SafeUpstreamCode);
        Assert.Null(new RestrictedTransportFailureException(phase).InnerException);
    }

    [Fact]
    public void FSE2_TRANSPORT_HTTP_diagnostics_retain_only_status_phase_and_allowlisted_code()
    {
        SafeUpstreamFailureDiagnostics diagnostics = SafeUpstreamFailureDiagnostics.HttpResponse(400, "syntax");

        Assert.Equal("UPSTREAM_HTTP_RESPONSE", diagnostics.FailurePhase);
        Assert.Equal(400, diagnostics.UpstreamStatus);
        Assert.Equal("syntax", diagnostics.SafeUpstreamCode);
        Assert.Equal(
            [nameof(SafeUpstreamFailureDiagnostics.FailurePhase), nameof(SafeUpstreamFailureDiagnostics.SafeUpstreamCode), nameof(SafeUpstreamFailureDiagnostics.UpstreamStatus)],
            typeof(SafeUpstreamFailureDiagnostics).GetProperties().Select(value => value.Name).Order(StringComparer.Ordinal));
    }
}

using System.Reflection;
using System.Security.Authentication;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using Xunit;

namespace SecureIntegration.Gateway.Unit.Tests;

public sealed class RestrictedTransportDiagnosticTests
{
    [Fact]
    public void FSE2_TRANSPORT_all_safe_failure_phases_are_closed_and_metadata_only()
    {
        (GatewayAuditFailurePhase Expected, SafeUpstreamFailureDiagnostics Diagnostics)[] cases =
        [
            (GatewayAuditFailurePhase.DnsFailure, SafeUpstreamFailureDiagnostics.Transport(RestrictedTransportFailurePhase.DnsFailure)),
            (GatewayAuditFailurePhase.TcpConnectFailure, SafeUpstreamFailureDiagnostics.Transport(RestrictedTransportFailurePhase.TcpConnectFailure)),
            (GatewayAuditFailurePhase.TlsServerValidationFailure, SafeUpstreamFailureDiagnostics.Transport(RestrictedTransportFailurePhase.TlsServerValidationFailure)),
            (GatewayAuditFailurePhase.MutualTlsClientAuthenticationFailure, SafeUpstreamFailureDiagnostics.Transport(RestrictedTransportFailurePhase.MutualTlsClientAuthenticationFailure)),
            (GatewayAuditFailurePhase.Timeout, SafeUpstreamFailureDiagnostics.Transport(RestrictedTransportFailurePhase.Timeout)),
            (GatewayAuditFailurePhase.TransportFailureOther, SafeUpstreamFailureDiagnostics.Transport(RestrictedTransportFailurePhase.TransportFailureOther)),
            (GatewayAuditFailurePhase.UpstreamHttpResponse, SafeUpstreamFailureDiagnostics.HttpResponse(400, "syntax")),
            (GatewayAuditFailurePhase.LocalResponseMappingFailure, SafeUpstreamFailureDiagnostics.LocalResponseMapping(200, "FSE2_RESPONSE_INVALID"))
        ];

        Assert.Equal(Enum.GetValues<GatewayAuditFailurePhase>(), cases.Select(value => value.Expected));
        foreach ((GatewayAuditFailurePhase expected, SafeUpstreamFailureDiagnostics diagnostics) in cases)
        {
            GatewayAuditFailureDiagnostics audit = diagnostics.ToAuditDiagnostics();
            Assert.Equal(expected, diagnostics.FailurePhase);
            Assert.Equal(5, typeof(GatewayAuditFailureDiagnostics).GetProperties().Length);
            string serialized = System.Text.Json.JsonSerializer.Serialize(audit);
            foreach (string forbidden in new[] { "rawBody", "headers", "Authorization", "JWT", "cookie", "certificate", "P12", "exception", "stack", "hostname", "message" })
                Assert.DoesNotContain(forbidden, serialized, StringComparison.OrdinalIgnoreCase);
        }

        Assert.All(cases.Take(6), value =>
        {
            Assert.Null(value.Diagnostics.UpstreamStatus);
            Assert.Null(value.Diagnostics.SafeUpstreamCode);
            Assert.Null(value.Diagnostics.LocalSafeCode);
            Assert.Equal(GatewayAuditStatusCategory.NoUpstreamResponse, value.Diagnostics.ToAuditDiagnostics().StatusCategory);
        });
        Assert.All(Enum.GetValues<RestrictedTransportFailurePhase>(), phase =>
            Assert.Null(new RestrictedTransportFailureException(phase).InnerException));
    }

    [Fact]
    public void FSE2_TRANSPORT_HTTP_diagnostics_retain_only_status_phase_and_allowlisted_code()
    {
        SafeUpstreamFailureDiagnostics diagnostics = SafeUpstreamFailureDiagnostics.HttpResponse(400, "syntax");

        Assert.Equal(GatewayAuditFailurePhase.UpstreamHttpResponse, diagnostics.FailurePhase);
        Assert.Equal(400, diagnostics.UpstreamStatus);
        Assert.Equal("syntax", diagnostics.SafeUpstreamCode);
        Assert.Equal(
            [nameof(SafeUpstreamFailureDiagnostics.FailurePhase), nameof(SafeUpstreamFailureDiagnostics.LocalSafeCode), nameof(SafeUpstreamFailureDiagnostics.SafeUpstreamCode), nameof(SafeUpstreamFailureDiagnostics.UpstreamStatus)],
            typeof(SafeUpstreamFailureDiagnostics).GetProperties().Select(value => value.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void FSE2_TRANSPORT_local_mapping_diagnostics_are_closed_and_status_bounded()
    {
        GatewayAuditFailureDiagnostics diagnostics = SafeUpstreamFailureDiagnostics
            .LocalResponseMapping(200, "FSE2_RESPONSE_INVALID")
            .ToAuditDiagnostics();

        Assert.Equal(GatewayAuditFailurePhase.LocalResponseMappingFailure, diagnostics.FailurePhase);
        Assert.Equal(200, diagnostics.UpstreamStatus);
        Assert.Equal(GatewayAuditStatusCategory.Success, diagnostics.StatusCategory);
        Assert.Null(diagnostics.SafeUpstreamCode);
        Assert.Equal("FSE2_RESPONSE_INVALID", diagnostics.LocalSafeCode);
        Assert.Throws<ArgumentOutOfRangeException>(() => GatewayAuditFailureDiagnostics.Create(
            GatewayAuditFailurePhase.UpstreamHttpResponse, 600, GatewayAuditStatusCategory.ServerError, null, null));
    }

    [Fact]
    public void FSE2_TRANSPORT_caller_cancellation_wins_over_timeout_race()
    {
        using CancellationTokenSource callerCancellation = new();
        callerCancellation.Cancel();

        Exception classified = Classify(
            new OperationCanceledException(),
            timeoutCancellationRequested: true,
            callerCancellation.Token);

        OperationCanceledException cancellation = Assert.IsType<OperationCanceledException>(classified);
        Assert.Equal(callerCancellation.Token, cancellation.CancellationToken);
    }

    [Fact]
    public void FSE2_TRANSPORT_HttpRequestException_after_caller_cancellation_propagates_cancellation()
    {
        using CancellationTokenSource callerCancellation = new();
        callerCancellation.Cancel();

        Exception classified = Classify(
            new HttpRequestException("Synthetic structured wrapper."),
            timeoutCancellationRequested: false,
            callerCancellation.Token);

        Assert.IsType<OperationCanceledException>(classified);
    }

    [Fact]
    public void FSE2_TRANSPORT_IOException_after_caller_cancellation_propagates_cancellation()
    {
        using CancellationTokenSource callerCancellation = new();
        callerCancellation.Cancel();

        Exception classified = Classify(
            new IOException("Synthetic stream wrapper."),
            timeoutCancellationRequested: true,
            callerCancellation.Token);

        Assert.IsType<OperationCanceledException>(classified);
    }

    [Fact]
    public void FSE2_TRANSPORT_timeout_without_caller_cancellation_is_timeout()
    {
        Exception classified = Classify(
            new OperationCanceledException(),
            timeoutCancellationRequested: true,
            CancellationToken.None);

        RestrictedTransportFailureException failure = Assert.IsType<RestrictedTransportFailureException>(classified);
        Assert.Equal(RestrictedTransportFailurePhase.Timeout, failure.Phase);
    }

    [Fact]
    public void FSE2_TRANSPORT_mtls_failure_requires_pre_header_structural_evidence()
    {
        Exception classified = Classify(
            new HttpRequestException(
                "Synthetic wrapper whose text is not inspected.",
                new AuthenticationException("Synthetic structured authentication failure.")),
            timeoutCancellationRequested: false,
            CancellationToken.None);

        RestrictedTransportFailureException failure = Assert.IsType<RestrictedTransportFailureException>(classified);
        Assert.Equal(RestrictedTransportFailurePhase.MutualTlsClientAuthenticationFailure, failure.Phase);
    }

    [Fact]
    public void FSE2_TRANSPORT_generic_pre_header_HttpRequestException_is_transport_other()
    {
        Exception classified = Classify(
            new HttpRequestException("Synthetic ambiguous connection failure."),
            timeoutCancellationRequested: false,
            CancellationToken.None);

        RestrictedTransportFailureException failure = Assert.IsType<RestrictedTransportFailureException>(classified);
        Assert.Equal(RestrictedTransportFailurePhase.TransportFailureOther, failure.Phase);
    }

    private static Exception Classify(
        Exception exception,
        bool timeoutCancellationRequested,
        CancellationToken callerCancellation)
    {
        MethodInfo classifier = typeof(SystemRestrictedTransport).GetMethod(
            "ClassifiedFailureOrCallerCancellation",
            BindingFlags.NonPublic | BindingFlags.Static) ??
            throw new InvalidOperationException("Restricted transport classifier was not found.");

        object? result = classifier.Invoke(null,
        [
            exception,
            timeoutCancellationRequested,
            2,
            1,
            1,
            0,
            1,
            1,
            callerCancellation
        ]);
        return Assert.IsAssignableFrom<Exception>(result);
    }
}

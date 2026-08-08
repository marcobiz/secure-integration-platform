using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SecureIntegration.ConnectorPacks.Healthcare.RegionalEPrescription;
using SecureIntegration.Gateway.Application;
using Xunit;

namespace SecureIntegration.ConnectorPacks.Healthcare.RegionalEPrescription.Tests;

public sealed class SyntheticRegionalServerTests
{
    [Fact]
    public async Task HC_W1_BLOCKED_regional_synthetic_HTTPS_sentinels_receive_zero_requests()
    {
        await using SyntheticLombardiaEPrescriptionServer lombardia = await SyntheticLombardiaEPrescriptionServer.StartAsync();
        await using SyntheticEmiliaRomagnaEPrescriptionServer emiliaRomagna = await SyntheticEmiliaRomagnaEPrescriptionServer.StartAsync();
        GatewayClientPrincipal principal = RegionalEPrescriptionFoundationTests.Principal(Guid.NewGuid(), Guid.NewGuid());

        await AssertSyntheticTlsAsync(lombardia);
        await AssertSyntheticTlsAsync(emiliaRomagna);

        foreach (RegionalProfileReadiness readiness in new[] { RegionalEPrescriptionWave1Readiness.Lombardia, RegionalEPrescriptionWave1Readiness.EmiliaRomagna })
        {
            RegionalEPrescriptionProfileBinding blocked = new(
                principal.TenantId,
                principal.ApplicationId,
                principal.InstallationId,
                principal.Identity.EnvironmentId,
                "healthcare.regional-rx",
                "0.0.0-blocked",
                "prescription.lookup",
                readiness.ProfileId,
                readiness.Availability,
                string.Empty,
                string.Empty,
                [],
                0,
                0,
                0,
                "blocked",
                readiness.BlockCode);
            RegionalEPrescriptionFoundationTests.InMemoryPublishedSource source = new(blocked);
            RegionalEPrescriptionFoundationTests.RecordingDispatcher dispatcher = new();
            RegionalEPrescriptionRouter router = new(
                new RegionalEPrescriptionFoundationTests.AllowingAuthorizer(),
                new PublishedRegionalEPrescriptionProfileResolver(source),
                new RegionalEPrescriptionCompiledProfileCatalog([]),
                dispatcher);

            RegionalEPrescriptionException error = await Assert.ThrowsAsync<RegionalEPrescriptionException>(() =>
                router.InvokeAsync(principal, "healthcare.regional-rx", "prescription.lookup", new PrescriptionLookupRequest(new("012345678901234"), RegionalExtensionSet.Empty), TestContext.Current.CancellationToken));

            Assert.Equal(RegionalEPrescriptionErrorCategory.ProfileUnavailable, error.Category);
            Assert.Equal(readiness.BlockCode, error.SafeRegionalCode?.Value);
            Assert.Empty(dispatcher.Executions);
        }

        Assert.StartsWith("https://127.0.0.1:", lombardia.BaseAddress.AbsoluteUri, StringComparison.Ordinal);
        Assert.StartsWith("https://127.0.0.1:", emiliaRomagna.BaseAddress.AbsoluteUri, StringComparison.Ordinal);
        Assert.Equal(0, lombardia.RequestCount);
        Assert.Equal(0, emiliaRomagna.RequestCount);
    }

    private static async Task AssertSyntheticTlsAsync(SyntheticBlockedRegionalEPrescriptionServer server)
    {
        using HttpClientHandler handler = new()
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
                certificate is not null && string.Equals(certificate.GetCertHashString(HashAlgorithmName.SHA256), server.CertificateSha256, StringComparison.Ordinal)
        };
        using HttpClient client = new(handler) { BaseAddress = server.BaseAddress, Timeout = TimeSpan.FromSeconds(5) };
        using HttpResponseMessage response = await client.GetAsync("/health", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}

internal abstract class SyntheticBlockedRegionalEPrescriptionServer : IAsyncDisposable
{
    private readonly WebApplication application;
    private readonly X509Certificate2 certificate;
    private int requestCount;

    protected SyntheticBlockedRegionalEPrescriptionServer(WebApplication application, Uri baseAddress, X509Certificate2 certificate)
    {
        this.application = application;
        this.certificate = certificate;
        BaseAddress = baseAddress;
    }

    public Uri BaseAddress { get; }
    public string CertificateSha256 => certificate.GetCertHashString(HashAlgorithmName.SHA256);
    public int RequestCount => Volatile.Read(ref requestCount);

    protected static async Task<(WebApplication Application, Uri BaseAddress, X509Certificate2 Certificate)> StartCoreAsync(Action increment)
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new("CN=127.0.0.1", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        SubjectAlternativeNameBuilder names = new();
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        using X509Certificate2 generated = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(30));
        X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12(
            generated.Export(X509ContentType.Pfx),
            null,
            X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);

        WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(certificate)));
        WebApplication application = builder.Build();
        application.MapGet("/health", () => Results.Ok());
        application.MapFallback(async context =>
        {
            increment();
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.ContentType = "application/problem+json";
            await context.Response.WriteAsync("{\"code\":\"BLOCKED_BY_SPEC\"}");
        });
        await application.StartAsync();

        IServer server = application.Services.GetRequiredService<IServer>();
        string address = server.Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        return (application, new Uri(address, UriKind.Absolute), certificate);
    }

    protected void Increment() => Interlocked.Increment(ref requestCount);

    public async ValueTask DisposeAsync()
    {
        await application.StopAsync();
        await application.DisposeAsync();
        certificate.Dispose();
    }
}

internal sealed class SyntheticLombardiaEPrescriptionServer : SyntheticBlockedRegionalEPrescriptionServer
{
    private SyntheticLombardiaEPrescriptionServer(WebApplication application, Uri baseAddress, X509Certificate2 certificate) : base(application, baseAddress, certificate) { }

    public static async Task<SyntheticLombardiaEPrescriptionServer> StartAsync()
    {
        SyntheticLombardiaEPrescriptionServer? server = null;
        (WebApplication application, Uri baseAddress, X509Certificate2 certificate) = await StartCoreAsync(() => server!.Increment());
        server = new SyntheticLombardiaEPrescriptionServer(application, baseAddress, certificate);
        return server;
    }
}

internal sealed class SyntheticEmiliaRomagnaEPrescriptionServer : SyntheticBlockedRegionalEPrescriptionServer
{
    private SyntheticEmiliaRomagnaEPrescriptionServer(WebApplication application, Uri baseAddress, X509Certificate2 certificate) : base(application, baseAddress, certificate) { }

    public static async Task<SyntheticEmiliaRomagnaEPrescriptionServer> StartAsync()
    {
        SyntheticEmiliaRomagnaEPrescriptionServer? server = null;
        (WebApplication application, Uri baseAddress, X509Certificate2 certificate) = await StartCoreAsync(() => server!.Increment());
        server = new SyntheticEmiliaRomagnaEPrescriptionServer(application, baseAddress, certificate);
        return server;
    }
}

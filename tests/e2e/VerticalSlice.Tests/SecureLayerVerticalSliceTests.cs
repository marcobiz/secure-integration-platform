using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureIntegration.Broker.Core;
using SecureIntegration.Broker.Infrastructure.Windows;
using SecureIntegration.Broker.Sdk;
using SecureIntegration.Contracts;
using Xunit;

namespace SecureIntegration.Broker.VerticalSlice.Tests;

public sealed class SecureLayerVerticalSliceTests
{
    [Fact]
    public async Task E2E_CON_SecureLayer_success_boundaries_failures_timeout_and_replay()
    {
        await using VerticalSliceHarness harness = await VerticalSliceHarness.CreateAsync();
        byte[] legacyPayload = "{\"patient\":\"synthetic-001\"}"u8.ToArray();
        InvokeGatewayResult result = await harness.Client.InvokeGatewayAsync(new InvokeGatewayRequest
        {
            ConnectorId = "secure-layer-demo",
            OperationId = "submit",
            ContentType = "application/json",
            PayloadBase64 = Convert.ToBase64String(legacyPayload),
        }, TestContext.Current.CancellationToken);

        Assert.Equal("1.0.0", result.ConnectorVersion);
        Assert.Contains("accepted", Encoding.UTF8.GetString(Convert.FromBase64String(result.PayloadBase64)), StringComparison.Ordinal);
        Assert.Equal(harness.VendorApiKey, harness.ExternalApiKeySeen);
        Assert.Equal(harness.GatewayClientCertificate.Thumbprint, harness.ExternalClientCertificateSeen, ignoreCase: true);
        Assert.Equal(harness.BrokerClientCertificate.Thumbprint, harness.GatewayClientCertificateSeen, ignoreCase: true);
        Assert.Equal(legacyPayload, harness.GatewayPayloadSeen);
        Assert.DoesNotContain(harness.VendorApiKey, Encoding.UTF8.GetString(harness.GatewayPayloadSeen), StringComparison.Ordinal);
        Assert.DoesNotContain(harness.VendorApiKey, result.PayloadBase64, StringComparison.Ordinal);
        Assert.DoesNotContain(harness.VendorApiKey, string.Join("\n", harness.PlatformAudit), StringComparison.Ordinal);

        BrokerClientException denied = await Assert.ThrowsAsync<BrokerClientException>(() => harness.Client.InvokeGatewayAsync(new InvokeGatewayRequest
        {
            ConnectorId = "secure-layer-demo",
            OperationId = "client-selected-operation",
            PayloadBase64 = "e30=",
        }, TestContext.Current.CancellationToken));
        Assert.Equal("gateway_operation_not_granted", denied.Code);
        Assert.Equal(1, harness.ExternalRequestCount);

        BrokerClientException timeout = await Assert.ThrowsAsync<BrokerClientException>(() => harness.ShortDeadlineClient.InvokeGatewayAsync(new InvokeGatewayRequest
        {
            ConnectorId = "secure-layer-demo",
            OperationId = "submit",
            PayloadBase64 = Convert.ToBase64String("{\"simulateDelay\":true}"u8),
        }, TestContext.Current.CancellationToken));
        Assert.Equal("deadline_exceeded", timeout.Code);

        BrokerException tlsFailure = await Assert.ThrowsAsync<BrokerException>(() => harness.InvokeWithUntrustedTlsAsync(TestContext.Current.CancellationToken));
        Assert.Equal("gateway_transport_failed", tlsFailure.Code);
        await harness.AssertReplayIsRejectedAsync(TestContext.Current.CancellationToken);

        string[] clientControlledProperties = typeof(InvokeGatewayRequest).GetProperties().Select(static property => property.Name).ToArray();
        Assert.DoesNotContain(clientControlledProperties, static name => name.Contains("Url", StringComparison.OrdinalIgnoreCase) || name.Contains("Secret", StringComparison.OrdinalIgnoreCase));
    }

    private sealed class VerticalSliceHarness : IAsyncDisposable
    {
        private readonly TestDirectory temporary;
        private readonly WebApplication external;
        private readonly WebApplication gateway;
        private readonly NamedPipeBrokerServer broker;
        private readonly CancellationTokenSource stopped;
        private readonly Task brokerTask;
        private readonly FileLocalSecretRepository secrets;
        private readonly FileDataKeyRepository keys;
        private readonly Uri gatewayAddress;
        private readonly string pipeName;

        private VerticalSliceHarness(TestDirectory temporary, WebApplication external, WebApplication gateway, NamedPipeBrokerServer broker, CancellationTokenSource stopped, Task brokerTask, FileLocalSecretRepository secrets, FileDataKeyRepository keys, Uri gatewayAddress, string pipeName, BrokerClient client, BrokerClient shortDeadlineClient, X509Certificate2 brokerClientCertificate, X509Certificate2 gatewayClientCertificate, X509Certificate2 gatewayServerCertificate, X509Certificate2 externalServerCertificate)
        {
            this.temporary = temporary;
            this.external = external;
            this.gateway = gateway;
            this.broker = broker;
            this.stopped = stopped;
            this.brokerTask = brokerTask;
            this.secrets = secrets;
            this.keys = keys;
            this.gatewayAddress = gatewayAddress;
            this.pipeName = pipeName;
            Client = client;
            ShortDeadlineClient = shortDeadlineClient;
            BrokerClientCertificate = brokerClientCertificate;
            GatewayClientCertificate = gatewayClientCertificate;
            GatewayServerCertificate = gatewayServerCertificate;
            ExternalServerCertificate = externalServerCertificate;
        }

        public string VendorApiKey { get; } = "synthetic-vendor-key-e2e-only";
        public BrokerClient Client { get; }
        public BrokerClient ShortDeadlineClient { get; }
        public X509Certificate2 BrokerClientCertificate { get; }
        public X509Certificate2 GatewayClientCertificate { get; }
        public X509Certificate2 GatewayServerCertificate { get; }
        public X509Certificate2 ExternalServerCertificate { get; }
        public string? ExternalApiKeySeen { get; private set; }
        public string? ExternalClientCertificateSeen { get; private set; }
        public string? GatewayClientCertificateSeen { get; private set; }
        public byte[] GatewayPayloadSeen { get; private set; } = [];
        public int ExternalRequestCount { get; private set; }
        public List<string> PlatformAudit { get; } = [];

        public static async Task<VerticalSliceHarness> CreateAsync()
        {
            TestDirectory temporary = new();
            X509Certificate2 externalServerCertificate = CreateCertificate("localhost", server: true);
            X509Certificate2 gatewayServerCertificate = CreateCertificate("localhost", server: true);
            X509Certificate2 gatewayClientCertificate = CreateCertificate("gateway-e2e", server: false);
            X509Certificate2 brokerClientCertificate = CreateCertificate("broker-e2e", server: false);
            VerticalSliceHarness? harness = null;

            WebApplication external = BuildMutualTlsServer(externalServerCertificate, gatewayClientCertificate, async context =>
            {
                harness!.ExternalRequestCount++;
                harness.ExternalApiKeySeen = context.Request.Headers["X-Api-Key"].ToString();
                harness.ExternalClientCertificateSeen = (await context.Connection.GetClientCertificateAsync())!.Thumbprint;
                using StreamReader reader = new(context.Request.Body, Encoding.UTF8);
                string body = await reader.ReadToEndAsync(context.RequestAborted);
                if (body.Contains("simulateDelay", StringComparison.Ordinal)) await Task.Delay(TimeSpan.FromSeconds(5), context.RequestAborted);
                if (harness.ExternalApiKeySeen != harness.VendorApiKey)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                }

                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"accepted\":true}", context.RequestAborted);
            });
            await external.StartAsync();
            Uri externalAddress = AddressOf(external);

            HttpClientHandler externalHandler = TrustedMutualTlsHandler(gatewayClientCertificate, externalServerCertificate);
            HttpClient externalClient = new(externalHandler) { BaseAddress = externalAddress };
            WebApplication gateway = BuildMutualTlsServer(gatewayServerCertificate, brokerClientCertificate, async context =>
            {
                string connectorId = context.Request.RouteValues["connectorId"]?.ToString() ?? string.Empty;
                string operationId = context.Request.RouteValues["operationId"]?.ToString() ?? string.Empty;
                if (connectorId != "secure-layer-demo" || operationId != "submit")
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                harness!.GatewayClientCertificateSeen = (await context.Connection.GetClientCertificateAsync())!.Thumbprint;
                using MemoryStream payload = new();
                await context.Request.Body.CopyToAsync(payload, context.RequestAborted);
                harness.GatewayPayloadSeen = payload.ToArray();
                harness.PlatformAudit.Add($"gateway connector={connectorId} operation={operationId}");
                using HttpRequestMessage outbound = new(HttpMethod.Post, "vendor/submit");
                outbound.Headers.TryAddWithoutValidation("X-Api-Key", harness.VendorApiKey);
                outbound.Content = new ByteArrayContent(harness.GatewayPayloadSeen);
                outbound.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
                using HttpResponseMessage vendorResponse = await externalClient.SendAsync(outbound, context.RequestAborted);
                byte[] response = await vendorResponse.Content.ReadAsByteArrayAsync(context.RequestAborted);
                context.Response.StatusCode = (int)vendorResponse.StatusCode;
                context.Response.ContentType = "application/json";
                context.Response.Headers["X-Connector-Version"] = "1.0.0";
                await context.Response.Body.WriteAsync(response, context.RequestAborted);
            }, "/runtime/connectors/{connectorId}/operations/{operationId}:invoke");
            await gateway.StartAsync();
            Uri gatewayAddress = AddressOf(gateway);

            HttpClientHandler brokerHandler = TrustedMutualTlsHandler(brokerClientCertificate, gatewayServerCertificate);
            FixedGatewayHttpInvoker gatewayInvoker = new(new HttpClient(brokerHandler) { BaseAddress = gatewayAddress });
            string pipeName = "SecureIntegration.VerticalSlice." + Guid.NewGuid().ToString("N");
            string executable = Environment.ProcessPath ?? throw new InvalidOperationException("Test host path unavailable.");
            string sid = WindowsIdentity.GetCurrent().User!.Value;
            string executableHash = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(executable)));
            ApplicationPolicy policy = new()
            {
                RegistrationId = "legacy-simulator",
                AllowedUserSids = [sid],
                ExecutablePaths = [executable],
                ExecutableSha256 = [executableHash],
                AllowedOperations = [BrokerOperations.InvokeGateway, BrokerOperations.GetBrokerStatus],
                GatewayGrants = ["secure-layer-demo:submit"],
            };
            BrokerOptions brokerOptions = new() { PipeName = pipeName, InstallationId = "installation-e2e", DataDirectory = temporary.Path, Applications = [policy] };
            WindowsDpapiProtectionProvider protection = new();
            FileLocalSecretRepository secrets = new(temporary.Path);
            FileDataKeyRepository keys = new(temporary.Path, protection);
            CapturingAudit audit = new();
            BrokerApplicationService service = new(secrets, protection, new AeadDataProtector(keys, brokerOptions.InstallationId), audit, brokerOptions.InstallationId, gatewayInvoker);
            NamedPipeBrokerServer broker = new(brokerOptions, new ApplicationAuthorizer(brokerOptions.Applications), new BrokerRequestDispatcher(service));
            CancellationTokenSource stopped = new();
            Task brokerTask = broker.RunAsync(stopped.Token);
            BrokerClient client = new(new BrokerClientOptions { PipeName = pipeName, ApplicationRegistrationId = policy.RegistrationId, OperationTimeout = TimeSpan.FromSeconds(3) });
            BrokerClient shortClient = new(new BrokerClientOptions { PipeName = pipeName, ApplicationRegistrationId = policy.RegistrationId, OperationTimeout = TimeSpan.FromMilliseconds(150) });
            harness = new VerticalSliceHarness(temporary, external, gateway, broker, stopped, brokerTask, secrets, keys, gatewayAddress, pipeName, client, shortClient, brokerClientCertificate, gatewayClientCertificate, gatewayServerCertificate, externalServerCertificate);
            harness.PlatformAudit.AddRange(audit.Events);
            return harness;
        }

        public async Task InvokeWithUntrustedTlsAsync(CancellationToken cancellationToken)
        {
            using HttpClient untrustedClient = new() { BaseAddress = gatewayAddress };
            FixedGatewayHttpInvoker invoker = new(untrustedClient);
            _ = await invoker.InvokeAsync("legacy-simulator", "secure-layer-demo", "submit", "application/json", "{}"u8.ToArray(), Guid.NewGuid(), cancellationToken);
        }

        public async Task AssertReplayIsRejectedAsync(CancellationToken cancellationToken)
        {
            await using NamedPipeClientStream pipe = new(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(cancellationToken);
            Guid handshakeId = Guid.NewGuid();
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(handshakeId, 0, new HandshakeRequest { ApplicationRegistrationId = "legacy-simulator", ClientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }), cancellationToken);
            HandshakeResponse handshake = IpcFrameCodec.Deserialize<HandshakeResponse>((await IpcFrameCodec.ReadAsync(pipe, cancellationToken))!);
            string nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
            BrokerRequest Request(Guid id) => new()
            {
                Operation = BrokerOperations.GetBrokerStatus,
                CorrelationId = id,
                ConnectionChallenge = handshake.ServerChallenge,
                RequestNonce = nonce,
                DeadlineUtc = DateTimeOffset.UtcNow.AddSeconds(3),
                Body = JsonSerializer.SerializeToElement(new { }, IpcProtocol.JsonOptions),
            };
            Guid firstId = Guid.NewGuid();
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(firstId, 1, Request(firstId)), cancellationToken);
            Assert.NotNull(await IpcFrameCodec.ReadAsync(pipe, cancellationToken));
            Guid replayId = Guid.NewGuid();
            await IpcFrameCodec.WriteAsync(pipe, IpcFrameCodec.JsonFrame(replayId, 2, Request(replayId)), cancellationToken);
            Assert.Null(await IpcFrameCodec.ReadAsync(pipe, cancellationToken));
        }

        public async ValueTask DisposeAsync()
        {
            stopped.Cancel();
            await brokerTask;
            await broker.DisposeAsync();
            await gateway.StopAsync();
            await external.StopAsync();
            await gateway.DisposeAsync();
            await external.DisposeAsync();
            keys.Dispose();
            secrets.Dispose();
            stopped.Dispose();
            BrokerClientCertificate.Dispose();
            GatewayClientCertificate.Dispose();
            GatewayServerCertificate.Dispose();
            ExternalServerCertificate.Dispose();
            temporary.Dispose();
        }

        private static WebApplication BuildMutualTlsServer(X509Certificate2 serverCertificate, X509Certificate2 requiredClientCertificate, RequestDelegate handler, string pattern = "/vendor/submit")
        {
            WebApplicationBuilder builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(https =>
            {
                https.ServerCertificate = serverCertificate;
                https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                https.ClientCertificateValidation = (certificate, _, _) => string.Equals(certificate.Thumbprint, requiredClientCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase);
            })));
            WebApplication app = builder.Build();
            app.MapPost(pattern, handler);
            return app;
        }

        private static HttpClientHandler TrustedMutualTlsHandler(X509Certificate2 clientCertificate, X509Certificate2 serverCertificate)
        {
            HttpClientHandler handler = new();
            handler.ClientCertificateOptions = ClientCertificateOption.Manual;
            handler.ClientCertificates.Add(clientCertificate);
            handler.ServerCertificateCustomValidationCallback = (_, certificate, _, _) => string.Equals(certificate?.Thumbprint, serverCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase);
            return handler;
        }

        private static Uri AddressOf(WebApplication app)
        {
            IServer server = app.Services.GetRequiredService<IServer>();
            string address = server.Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            return new Uri(address.EndsWith('/') ? address : address + "/");
        }

        private static X509Certificate2 CreateCertificate(string name, bool server)
        {
            using RSA key = RSA.Create(2048);
            CertificateRequest request = new($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            OidCollection usages = new();
            usages.Add(new Oid(server ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2"));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, true));
            if (server)
            {
                SubjectAlternativeNameBuilder san = new();
                san.AddDnsName("localhost");
                san.AddIpAddress(IPAddress.Loopback);
                request.CertificateExtensions.Add(san.Build());
            }

            using X509Certificate2 created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
            return X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
        }

        private sealed class CapturingAudit : IBrokerAuditSink
        {
            public List<string> Events { get; } = [];
            public Task WriteAsync(string operation, string applicationId, Guid correlationId, bool succeeded, string? errorCode, CancellationToken cancellationToken)
            {
                Events.Add($"broker operation={operation} application={applicationId} success={succeeded} error={errorCode}");
                return Task.CompletedTask;
            }
        }

        private sealed class TestDirectory : IDisposable
        {
            public TestDirectory()
            {
                Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "broker-gateway-e2e", Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(Path);
            }
            public string Path { get; }
            public void Dispose() { if (Directory.Exists(Path)) Directory.Delete(Path, recursive: true); }
        }
    }
}

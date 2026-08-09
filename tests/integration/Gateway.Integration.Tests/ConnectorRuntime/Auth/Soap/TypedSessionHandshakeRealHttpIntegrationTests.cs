using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;
using SecureIntegration.Gateway.Domain;
using SecureIntegration.Gateway.Infrastructure;
using SecureIntegration.M6.SyntheticSoapServer;
using SecureIntegration.Providers.Abstractions;
using Xunit;

namespace SecureIntegration.Gateway.Integration.Tests.ConnectorRuntime.Auth.Soap;

public sealed class TypedSessionHandshakeRealHttpIntegrationTests
{
    private const string TypedNamespace = "urn:synthetic:typed-session";
    private const string LegacyNamespace = "urn:synthetic:session";
    private const string SoapNamespace = "http://schemas.xmlsoap.org/soap/envelope/";

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Wave1_IT_Real_HTTPS_typed_handshake_direct_or_external_admission_promotes_and_supports_session_use(bool externalAdmission)
    {
        using CertificateFixture certificates = CertificateFixture.Create();
        const string externalCandidate = "synthetic-external-session";
        await using SyntheticSoapServerInstance server = await SyntheticSoapServerHost.StartAsync(
            new("synthetic-user", "synthetic-password", false, TimeSpan.FromMinutes(5), TimeSpan.FromSeconds(2), externalAdmission, externalCandidate),
            certificates.Server, TestContext.Current.CancellationToken);

        Uri baseEndpoint = new(server.Endpoint, "/");
        SystemRestrictedTransport transport = new(new X509Certificate2Collection(certificates.Root), Convert.ToHexString(SHA256.HashData(certificates.Server.RawData)));
        TypedValidator validator = new(transport, "synthetic-user", "synthetic-password");
        TypedSessionHandshakeAdapterRegistry registry = new([new RequestAdapter()], [new ResponseAdapter()], [validator]);
        SnapshotFixture snapshot = new(baseEndpoint);
        SystemGatewayClock clock = new();
        PublishedTypedSessionHandshakeResolver authority = new(snapshot.ResolveAsync, registry, clock);
        SoapSessionClient client = new(new FixedSecrets(), new LoopbackResolver(), transport, clock, new MatchingStampProvider(), new LoopbackAllowance(baseEndpoint.DnsSafeHost));
        ResolvedTypedSessionHandshake resolved = await authority.ResolveAsync(snapshot.Invocation(clock), new("typed-session"), TestContext.Current.CancellationToken);

        TypedSessionHandshakeResult result = await client.AcquireTypedSessionAsync(resolved, TestContext.Current.CancellationToken);
        if (externalAdmission)
        {
            Assert.Equal(TypedSessionHandshakeResultKind.ExternalAdmissionRequired, result.Kind);
            result = await client.CompleteExternalAdmissionAsync(resolved, result.AdmissionIntent!,
                ExternalSessionCandidate.FromPresentation(Encoding.UTF8.GetBytes(externalCandidate)), TestContext.Current.CancellationToken);
            Assert.Equal(1, server.Counters.ValidateSession);
        }
        else
        {
            Assert.Equal(0, server.Counters.ValidateSession);
        }

        Assert.Equal(TypedSessionHandshakeResultKind.Issued, result.Kind);
        SoapBusinessResult business = await client.InvokeAsync(resolved.State.ExecutionContext, resolved.State.Endpoint, BusinessProfile(),
            new Dictionary<string, string> { ["payload"] = "normal" }, result.Session, TestContext.Current.CancellationToken);
        Assert.Equal("accepted", business.Values["result"]);
        Assert.Equal(1, server.Counters.CreateSession);
        Assert.Equal(1, server.Counters.Business);
    }

    private static SoapSessionProfile BusinessProfile()
    {
        SoapOperationProfile login = new("unused-login", SoapEnvelopeVersion.Soap11, "urn:synthetic:Login",
            new("Login", LegacyNamespace), new("LoginResponse", LegacyNamespace));
        SoapOperationProfile business = new("session-bootstrap", SoapEnvelopeVersion.Soap11, "urn:synthetic:BusinessOperation",
            new("BusinessOperation", LegacyNamespace), new("BusinessOperationResponse", LegacyNamespace),
            [new("payload", new("Payload", LegacyNamespace))], [new("result", new("Result", LegacyNamespace))]);
        return new("typed-session", new("provider/username", "provider/password"), login, new("SessionId", LegacyNamespace),
            new("Session", LegacyNamespace), [business], TimeSpan.FromMinutes(5), []);
    }

    private sealed class RequestAdapter : ITypedSessionHandshakeRequestAdapter
    {
        public string AdapterId => "synthetic-create-session-request";
        public string AdapterType => "compiled-typed-request";
        public void WriteRequest(XmlWriter writer, TypedSessionHandshakeRequestContext context)
        {
            writer.WriteStartElement("s", "ClientContext", TypedNamespace);
            writer.WriteStartElement("s", "Identity", TypedNamespace);
            writer.WriteElementString("s", "Tenant", TypedNamespace, context.TenantId.ToString("D"));
            writer.WriteElementString("s", "Installation", TypedNamespace, context.InstallationId.ToString("D"));
            writer.WriteElementString("s", "Application", TypedNamespace, context.ApplicationId.ToString("D"));
            writer.WriteEndElement();
            writer.WriteStartElement("s", "Policy", TypedNamespace);
            writer.WriteElementString("s", "Profile", TypedNamespace, context.ProfileId);
            writer.WriteElementString("s", "PublishedChecksum", TypedNamespace, context.PublishedPolicyChecksum);
            writer.WriteEndElement();
            writer.WriteEndElement();
        }
    }

    private sealed class ResponseAdapter : ITypedSessionHandshakeResponseAdapter
    {
        public string AdapterId => "synthetic-create-session-response";
        public string AdapterType => "compiled-typed-response";
        public TypedSessionHandshakeAdapterOutcome ReadResponse(XmlReader payload, TypedSessionHandshakeResponseContext context)
        {
            payload.ReadStartElement("CreateSessionResponse", TypedNamespace);
            payload.ReadStartElement("Result", TypedNamespace);
            string status = payload.ReadElementContentAsString("Status", TypedNamespace);
            TypedSessionHandshakeAdapterOutcome result;
            if (string.Equals(status, "issued", StringComparison.Ordinal))
            {
                payload.ReadStartElement("Session", TypedNamespace);
                string session = payload.ReadElementContentAsString("Value", TypedNamespace);
                DateTimeOffset expiry = DateTimeOffset.ParseExact(payload.ReadElementContentAsString("ExpiresAt", TypedNamespace), "O", CultureInfo.InvariantCulture);
                payload.ReadEndElement();
                result = TypedSessionHandshakeAdapterOutcome.Issued(session, expiry);
            }
            else if (string.Equals(status, "external_admission_required", StringComparison.Ordinal))
            {
                payload.ReadStartElement("Admission", TypedNamespace);
                if (!string.Equals(payload.ReadElementContentAsString("Provenance", TypedNamespace), "interactive_handoff", StringComparison.Ordinal)) throw new XmlException();
                payload.ReadEndElement();
                result = TypedSessionHandshakeAdapterOutcome.ExternalAdmissionRequired();
            }
            else throw new XmlException();
            payload.ReadEndElement();
            payload.ReadEndElement();
            return result;
        }
    }

    private sealed class TypedValidator(IRestrictedTransport transport, string username, string password) : IAuthorizedExternalSessionValidator
    {
        public string ValidatorId => "synthetic-session-validator";
        public string ValidatorType => "compiled-typed-validator";

        public async Task<ExternalSessionValidationResult> ValidateAsync(ExternalSessionValidationContext context, ExternalSessionCandidate candidate, CancellationToken cancellationToken)
        {
            byte[] envelope;
            using (MemoryStream output = new())
            {
                using (XmlWriter writer = XmlWriter.Create(output, new() { Encoding = new UTF8Encoding(false, true), OmitXmlDeclaration = true }))
                {
                    writer.WriteStartElement("soap", "Envelope", SoapNamespace);
                    writer.WriteStartElement("soap", "Body", SoapNamespace);
                    writer.WriteStartElement("s", "ValidateSessionRequest", TypedNamespace);
                    writer.WriteStartElement("s", "Candidate", TypedNamespace);
                    writer.WriteElementString("s", "Provenance", TypedNamespace, "interactive_handoff");
                    writer.WriteElementString("s", "OpaqueValue", TypedNamespace, Encoding.UTF8.GetString(candidate.SensitiveValue.Span));
                    writer.WriteEndElement();
                    writer.WriteEndElement();
                    writer.WriteEndElement();
                    writer.WriteEndElement();
                }
                envelope = output.ToArray();
            }
            using HttpRequestMessage request = new(HttpMethod.Post, context.Endpoint);
            request.Content = new ByteArrayContent(envelope);
            request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("text/xml; charset=utf-8");
            request.Headers.TryAddWithoutValidation("SOAPAction", "\"urn:synthetic:ValidateSession\"");
            byte[] basic = Encoding.UTF8.GetBytes(username + ":" + password);
            try { request.Headers.Authorization = new("Basic", Convert.ToBase64String(basic)); }
            finally { CryptographicOperations.ZeroMemory(basic); }
            ExternalResponse response = await transport.SendSoapAsync(request, [IPAddress.Loopback], context.Timeout, context.MaximumResponseBytes, cancellationToken);
            if (response.StatusCode != 200 || response.Body.LongLength > context.MaximumResponseBytes) return ExternalSessionValidationResult.Invalid(ExternalSessionValidationStatus.Unavailable);
            XmlReaderSettings settings = new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersFromEntities = 0, MaxCharactersInDocument = context.MaximumResponseBytes };
            using MemoryStream input = new(response.Body, writable: false);
            using XmlReader reader = XmlReader.Create(input, settings);
            XDocument document = XDocument.Load(reader, LoadOptions.None);
            XNamespace soap = SoapNamespace;
            XNamespace typed = TypedNamespace;
            XElement payload = document.Root?.Element(soap + "Body")?.Elements().SingleOrDefault() ?? throw new XmlException();
            if (payload.Name != typed + "ValidateSessionResponse") throw new XmlException();
            XElement validation = payload.Elements().Single();
            XElement[] fields = validation.Elements().ToArray();
            if (validation.Name != typed + "Validation" || fields.Length is < 1 or > 2 || fields[0].Name != typed + "Status") throw new XmlException();
            if (fields[0].Value == "rejected" && fields.Length == 1) return ExternalSessionValidationResult.Invalid(ExternalSessionValidationStatus.Rejected);
            if (fields[0].Value != "valid" || fields.Length != 2 || fields[1].Name != typed + "ExpiresAt") throw new XmlException();
            return ExternalSessionValidationResult.Valid(DateTimeOffset.ParseExact(fields[1].Value, "O", CultureInfo.InvariantCulture));
        }
    }

    private sealed class SnapshotFixture
    {
        private readonly Guid connectorId = Guid.NewGuid();
        private readonly Guid versionId = Guid.NewGuid();
        private readonly Guid environmentId = Guid.NewGuid();
        private readonly Guid tenantId = Guid.NewGuid();
        private readonly Guid applicationId = Guid.NewGuid();
        private readonly Guid installationId = Guid.NewGuid();
        private readonly PublishedConnectorSnapshot snapshot;

        internal SnapshotFixture(Uri baseEndpoint)
        {
            object definition = new
            {
                operations = new[] { new { operationId = "session-bootstrap", endpointBinding = "soap", method = "POST", path = "/service",
                    request = new { contentType = "text/xml", maximumBytes = 32_768 }, response = new { maximumBytes = 32_768 }, timeoutMs = 5_000,
                    authentication = new { kind = "basic", usernameBinding = "username", passwordBinding = "password" },
                    typedSessionHandshake = new { profileId = "typed-session", soapVersion = "1.1", action = "urn:synthetic:CreateSession",
                        requestElement = new { localName = "CreateSessionRequest", namespaceUri = TypedNamespace },
                        responseElement = new { localName = "CreateSessionResponse", namespaceUri = TypedNamespace },
                        requestAdapter = new { id = "synthetic-create-session-request", type = "compiled-typed-request" },
                        responseAdapter = new { id = "synthetic-create-session-response", type = "compiled-typed-response" }, sessionLifetimeSeconds = 300,
                        externalAdmission = new { validator = new { id = "synthetic-session-validator", type = "compiled-typed-validator" },
                            endpointBinding = "soap", path = "/service", intentLifetimeSeconds = 60, timeoutMs = 5_000, maximumResponseBytes = 32_768 } } } }
            };
            string canonical = JsonSerializer.Serialize(definition);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            ConnectorVersionRecord version = new(versionId, connectorId, "synthetic-typed-session", "1.0.0", "1.0", ConnectorVersionState.Published,
                canonical, SHA256.HashData(Encoding.UTF8.GetBytes(canonical)), "publisher", now.AddMinutes(-10), 1, now.AddMinutes(-5), now.AddMinutes(-4));
            ProviderResourceBinding username = Resource("username", 9);
            ProviderResourceBinding password = Resource("password", 9);
            ConnectorBindingSet bindings = new(Guid.NewGuid(), connectorId, versionId, environmentId,
                new Dictionary<string, Uri> { ["soap"] = baseEndpoint }, new Dictionary<string, ProviderResourceBinding> { ["username"] = username, ["password"] = password },
                new Dictionary<string, ProviderResourceBinding>(), 7, "binding-checksum", ConnectorBindingState.Active, now, "publisher");
            snapshot = new(version, bindings, new(versionId, 3, 7, "binding-checksum", "resource-stamp-9"),
                new Dictionary<string, string> { ["username"] = "provider/username", ["password"] = "provider/password" }, new Dictionary<string, string>());
        }

        internal Task<PublishedConnectorSnapshot?> ResolveAsync(string connectorIdValue, Guid environmentIdValue, PublishedConnectorAccessContext access, CancellationToken cancellationToken) =>
            Task.FromResult<PublishedConnectorSnapshot?>(snapshot);

        internal AuthorizedGatewayInvocation Invocation(SystemGatewayClock clock)
        {
            RegisteredInstallationIdentity identity = new(installationId, tenantId, applicationId, environmentId, TenantStatus.Active, ApplicationStatus.Active, InstallationStatus.Active,
                Guid.NewGuid(), CredentialStatus.Active, [1, 2, 3], clock.UtcNow.AddMinutes(-1), clock.UtcNow.AddHours(1), "1.0.0", null);
            return new(new(identity, Guid.NewGuid()), "synthetic-typed-session", "session-bootstrap");
        }

        private ProviderResourceBinding Resource(string id, long revision) => new("synthetic", "Synthetic", "Synthetic", id, ProviderResourceType.Secret, id,
            environmentId, "synthetic-typed-session", "session-bootstrap", "per-run", revision, null, null, "catalog-" + id);
    }

    private sealed class FixedSecrets : ISecretValueProvider
    {
        public Task<string> GetSecretAsync(string logicalReference, CancellationToken cancellationToken) =>
            Task.FromResult(logicalReference.Contains("username", StringComparison.Ordinal) ? "synthetic-user" : "synthetic-password");
    }

    private sealed class LoopbackResolver : IHostResolver
    {
        public Task<IPAddress[]> ResolveAsync(string host, CancellationToken cancellationToken) => Task.FromResult(new[] { IPAddress.Loopback });
    }

    private sealed class LoopbackAllowance(string host) : IPrivateDestinationAllowance
    {
        public bool IsAllowed(string candidateHost, IPAddress address) => string.Equals(host, candidateHost, StringComparison.OrdinalIgnoreCase) && IPAddress.IsLoopback(address);
    }

    private sealed class MatchingStampProvider : ISoapSessionResourceStampProvider
    {
        public Task<SoapSessionResourceStamp?> GetCurrentAsync(ConnectorAuthExecutionContext context, CancellationToken cancellationToken) =>
            Task.FromResult<SoapSessionResourceStamp?>(new(context.CredentialRevision, SoapCredentialResourceStatus.Active, context.BindingRevision, context.EndpointRevision));
    }

    private sealed class CertificateFixture(X509Certificate2 root, X509Certificate2 server) : IDisposable
    {
        internal X509Certificate2 Root { get; } = root;
        internal X509Certificate2 Server { get; } = server;

        internal static CertificateFixture Create()
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            using RSA rootKey = RSA.Create(2048);
            CertificateRequest rootRequest = new("CN=Synthetic Typed Session Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddHours(1));
            using RSA serverKey = RSA.Create(2048);
            CertificateRequest serverRequest = new("CN=127.0.0.1", serverKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            SubjectAlternativeNameBuilder san = new();
            san.AddIpAddress(IPAddress.Loopback);
            serverRequest.CertificateExtensions.Add(san.Build());
            using X509Certificate2 publicServer = serverRequest.Create(root, now.AddMinutes(-1), now.AddMinutes(30), RandomNumberGenerator.GetBytes(16));
            using X509Certificate2 serverWithKey = publicServer.CopyWithPrivateKey(serverKey);
            X509Certificate2 server = X509CertificateLoader.LoadPkcs12(serverWithKey.Export(X509ContentType.Pkcs12), null,
                X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
            return new(root, server);
        }

        public void Dispose() { Server.Dispose(); Root.Dispose(); }
    }
}

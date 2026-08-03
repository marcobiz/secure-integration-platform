using System.Text.Json;
using SecureIntegration.Broker.Core;
using SecureIntegration.Contracts;

namespace SecureIntegration.Broker.Infrastructure.Windows;

/// <summary>Validates and dispatches wire requests to the Broker application service.</summary>
public sealed class BrokerRequestDispatcher
{
    private readonly BrokerApplicationService service;

    /// <summary>Creates the dispatcher.</summary>
    public BrokerRequestDispatcher(BrokerApplicationService service) => this.service = service;

    /// <summary>Dispatches one authorized request.</summary>
    public async Task<JsonElement> DispatchAsync(string applicationId, ApplicationPolicy policy, BrokerRequest request, CancellationToken cancellationToken)
    {
        switch (request.Operation)
        {
            case BrokerOperations.PutLocalSecret:
                ApplicationAuthorizer.AuthorizeOperation(policy, request.Operation);
                PutLocalSecretRequest put = Deserialize<PutLocalSecretRequest>(request.Body);
                byte[] secret = Decode(put.ValueBase64);
                try
                {
                    string secretRef = await service.PutLocalSecretAsync(applicationId, put.LogicalName, put.SecretClass, put.AllowedOperations, secret, request.CorrelationId, cancellationToken).ConfigureAwait(false);
                    return Serialize(new LocalSecretReference { SecretRef = secretRef });
                }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret); }
            case BrokerOperations.DeleteLocalSecret:
                ApplicationAuthorizer.AuthorizeOperation(policy, request.Operation);
                DeleteLocalSecretRequest delete = Deserialize<DeleteLocalSecretRequest>(request.Body);
                await service.DeleteLocalSecretAsync(applicationId, delete.SecretRef, request.CorrelationId, cancellationToken).ConfigureAwait(false);
                return Serialize(new { deleted = true });
            case BrokerOperations.ProtectData:
                ApplicationAuthorizer.AuthorizeOperation(policy, request.Operation);
                ProtectDataRequest protect = Deserialize<ProtectDataRequest>(request.Body);
                byte[] plaintext = Decode(protect.PlaintextBase64);
                try
                {
                    byte[] envelope = await service.ProtectDataAsync(applicationId, protect.Purpose, protect.ContentType, plaintext, cancellationToken).ConfigureAwait(false);
                    return Serialize(new ProtectedDataResult { EnvelopeBase64 = Convert.ToBase64String(envelope) });
                }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext); }
            case BrokerOperations.UnprotectData:
                ApplicationAuthorizer.AuthorizeOperation(policy, request.Operation);
                UnprotectDataRequest unprotect = Deserialize<UnprotectDataRequest>(request.Body);
                byte[] unprotected = await service.UnprotectDataAsync(applicationId, unprotect.Purpose, unprotect.ContentType, Decode(unprotect.EnvelopeBase64), cancellationToken).ConfigureAwait(false);
                try { return Serialize(new UnprotectedDataResult { PlaintextBase64 = Convert.ToBase64String(unprotected) }); }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(unprotected); }
            case BrokerOperations.ComputeHmac:
                ApplicationAuthorizer.AuthorizeOperation(policy, request.Operation);
                ComputeHmacRequest hmac = Deserialize<ComputeHmacRequest>(request.Body);
                byte[] digest = await service.ComputeHmacAsync(applicationId, hmac.SecretRef, Decode(hmac.MessageBase64), request.CorrelationId, cancellationToken).ConfigureAwait(false);
                return Serialize(new ComputeHmacResult { DigestBase64 = Convert.ToBase64String(digest) });
            case BrokerOperations.InvokeGateway:
                InvokeGatewayRequest invoke = Deserialize<InvokeGatewayRequest>(request.Body);
                ApplicationAuthorizer.AuthorizeOperation(policy, request.Operation, invoke.ConnectorId, invoke.OperationId);
                GatewayInvocationResult result = await service.InvokeGatewayAsync(applicationId, invoke.ConnectorId, invoke.OperationId, invoke.ContentType, Decode(invoke.PayloadBase64), request.CorrelationId, cancellationToken).ConfigureAwait(false);
                return Serialize(new InvokeGatewayResult { ContentType = result.ContentType, PayloadBase64 = Convert.ToBase64String(result.Payload), ConnectorVersion = result.ConnectorVersion });
            case BrokerOperations.GetBrokerStatus:
                ApplicationAuthorizer.AuthorizeOperation(policy, request.Operation);
                return Serialize(new BrokerStatus { Version = typeof(BrokerRequestDispatcher).Assembly.GetName().Version?.ToString() ?? "unknown", GatewayConfigured = service.GatewayConfigured });
            default:
                throw new BrokerException("operation_not_supported", "validation");
        }
    }

    private static T Deserialize<T>(JsonElement element) => element.Deserialize<T>(IpcProtocol.JsonOptions) ?? throw new BrokerException("invalid_request", "validation");
    private static JsonElement Serialize<T>(T value) => JsonSerializer.SerializeToElement(value, IpcProtocol.JsonOptions);
    private static byte[] Decode(string value)
    {
        try { return Convert.FromBase64String(value); }
        catch (FormatException exception) { throw new BrokerException("invalid_base64", "validation", innerException: exception); }
    }
}

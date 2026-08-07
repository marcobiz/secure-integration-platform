using System.Buffers;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.Application;

/// <summary>Applies HTTP Basic only from an exact server-resolved credential binding.</summary>
public sealed class ServerBoundBasicAuthentication(ISecretValueProvider secrets)
{
    /// <summary>
    /// Resolves username and password at the moment of use and applies exactly one Authorization header.
    /// Plaintext and encoded credential buffers are not retained after this call.
    /// </summary>
    public async Task ApplyAsync(HttpRequestMessage request, ResolvedBasicCredentialBinding binding, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(binding);
        if (request.Headers.Authorization is not null || request.Headers.Contains("Authorization"))
            throw new SoapAuthException("BASIC-AUTHORIZATION-ALREADY-PRESENT");

        string username;
        string password;
        try
        {
            username = await secrets.GetSecretAsync(binding.UsernameProviderReference, cancellationToken).ConfigureAwait(false);
            password = await secrets.GetSecretAsync(binding.PasswordProviderReference, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is not SoapAuthException)
        {
            _ = exception;
            throw new SoapAuthException("BASIC-CREDENTIAL-UNAVAILABLE");
        }

        ValidateCredential(username, password);
        int byteCount = Encoding.UTF8.GetByteCount(username) + 1 + Encoding.UTF8.GetByteCount(password);
        byte[] rented = ArrayPool<byte>.Shared.Rent(byteCount);
        try
        {
            int written = Encoding.UTF8.GetBytes(username, rented);
            rented[written++] = (byte)':';
            written += Encoding.UTF8.GetBytes(password, rented.AsSpan(written));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(rented, 0, written));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rented);
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static void ValidateCredential(string username, string password)
    {
        if (string.IsNullOrEmpty(username) || username.Length > 1024 || username.Contains(':', StringComparison.Ordinal) || ContainsControl(username))
            throw new SoapAuthException("BASIC-CREDENTIAL-INVALID");
        if (password.Length > 4096 || ContainsControl(password)) throw new SoapAuthException("BASIC-CREDENTIAL-INVALID");
    }

    private static bool ContainsControl(string value) => value.Any(character => char.IsControl(character));
}

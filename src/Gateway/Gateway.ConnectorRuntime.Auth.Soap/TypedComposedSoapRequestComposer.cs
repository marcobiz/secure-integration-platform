using SecureIntegration.Providers.Abstractions;

namespace SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

/// <summary>Resolves only Published-approved inputs and materializes one exact request snapshot.</summary>
internal sealed class TypedComposedSoapRequestComposer(ISecretValueProvider secrets)
{
    internal async Task<TypedComposedSoapRequestSnapshot?> ComposeAsync(
        ComposedSoapResolvedExecutionContext resolvedContext,
        ReadOnlyMemory<byte> businessPayload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolvedContext);
        ComposedSoapAuthorityState expected = resolvedContext.State;
        TypedComposedSoapRequestAuthority? authority = expected.TypedRequest;
        if (authority is null) return null;

        Dictionary<string, string> resolved = new(StringComparer.Ordinal);
        AuthorizedConnectorBindingInputs? inputs = null;
        try
        {
            foreach (ServerOwnedBindingInputReference reference in authority.BindingInputs)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string value;
                try
                {
                    value = await secrets.GetSecretAsync(reference.ProviderReference, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw new OperationCanceledException(cancellationToken);
                }
                catch (Exception)
                {
                    throw TypedComposedSoapRequestFailures.BindingInputUnavailable();
                }
                if (!resolved.TryAdd(reference.Name, value))
                    throw TypedComposedSoapRequestFailures.BindingInputUnavailable();
                _ = await RevalidateAsync(resolvedContext, expected, cancellationToken).ConfigureAwait(false);
            }

            try
            {
                inputs = new(resolved);
            }
            catch (Exception)
            {
                throw TypedComposedSoapRequestFailures.BindingInputUnavailable();
            }

            ComposedSoapAuthorityState current = await RevalidateAsync(resolvedContext, expected, cancellationToken).ConfigureAwait(false);
            return TypedComposedSoapRequestXmlBoundary.Serialize(current, businessPayload, inputs, cancellationToken);
        }
        finally
        {
            inputs?.Clear();
            resolved.Clear();
        }
    }

    private static async Task<ComposedSoapAuthorityState> RevalidateAsync(
        ComposedSoapResolvedExecutionContext context,
        ComposedSoapAuthorityState expected,
        CancellationToken cancellationToken)
    {
        ComposedSoapAuthorityState current;
        try
        {
            current = await context.Revalidate(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SoapAuthException)
        {
            throw;
        }
        catch (Exception)
        {
            throw new SoapAuthException("SOAP-AUTHORITY-REJECTED");
        }
        if (!string.Equals(current.SecurityFingerprint, expected.SecurityFingerprint, StringComparison.Ordinal))
            throw new SoapAuthException("SOAP-AUTHORITY-STALE");
        return current;
    }
}

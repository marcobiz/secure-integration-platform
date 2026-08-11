using System.Collections.Frozen;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

namespace SecureIntegration.ConnectorPacks.Healthcare.SistemaTs;

internal static class SistemaTsSessionProtocol
{
    internal const string AuthenticationNamespace = "http://authservice.xsd.wsdl.auth.a2f.sts.sanita.finanze.it";
    internal const string DataNamespace = "http://datatype.xsd.wsdl.auth.a2f.sts.sanita.finanze.it";
    internal const string Context = "RICETTA-DEM";
    internal const string Application = "EROGATORE";

    internal const string UserId = "user-id";
    internal const string IdentifierType = "identificativo-tipo";
    internal const string IdentifierValue = "identificativo-valore";
    internal const string TaxCode = "codice-fiscale";
    internal const string RegionCode = "codice-regione";
    internal const string HealthAuthorityCode = "codice-asl";
    internal const string FacilityCode = "codice-ssa";

    internal static readonly IReadOnlySet<string> CreateInputs = new[]
    {
        UserId, IdentifierType, IdentifierValue, TaxCode, RegionCode, HealthAuthorityCode, FacilityCode
    }.ToFrozenSet(StringComparer.Ordinal);

    internal static readonly IReadOnlySet<string> CheckTokenInputs = new[]
    {
        UserId, IdentifierType, IdentifierValue, TaxCode
    }.ToFrozenSet(StringComparer.Ordinal);

    internal static void WriteInputElement(XmlWriter writer, string prefix, string localName, string namespaceUri,
        AuthorizedConnectorBindingInputs inputs, string inputName)
    {
        writer.WriteStartElement(prefix, localName, namespaceUri);
        inputs.WriteRequiredXmlValue(inputName);
        writer.WriteEndElement();
    }
}

/// <summary>Writes the official Sistema TS CreateAuthReq children for RICETTA-DEM/EROGATORE.</summary>
public sealed class SistemaTsCreateSessionRequestAdapter : ITypedSessionHandshakeRequestAdapter
{
    /// <inheritdoc />
    public string AdapterId => "sistema-ts-create-session-request";
    /// <inheritdoc />
    public string AdapterType => "compiled-sistema-ts-create-v0.1";
    /// <inheritdoc />
    public IReadOnlySet<string> RequiredServerOwnedInputs => SistemaTsSessionProtocol.CreateInputs;

    /// <inheritdoc />
    public void WriteRequest(XmlWriter writer, TypedSessionHandshakeRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(context);
        AuthorizedConnectorBindingInputs inputs = context.ServerOwnedInputs;
        if (inputs.Count != SistemaTsSessionProtocol.CreateInputs.Count)
            throw new XmlException("Sistema TS create binding input set is incomplete.");

        SistemaTsSessionProtocol.WriteInputElement(writer, "aut", "userId", SistemaTsSessionProtocol.AuthenticationNamespace,
            inputs, SistemaTsSessionProtocol.UserId);
        writer.WriteStartElement("aut", "identificativo", SistemaTsSessionProtocol.AuthenticationNamespace);
        SistemaTsSessionProtocol.WriteInputElement(writer, "dat", "tipo", SistemaTsSessionProtocol.DataNamespace,
            inputs, SistemaTsSessionProtocol.IdentifierType);
        SistemaTsSessionProtocol.WriteInputElement(writer, "dat", "valore", SistemaTsSessionProtocol.DataNamespace,
            inputs, SistemaTsSessionProtocol.IdentifierValue);
        writer.WriteEndElement();
        SistemaTsSessionProtocol.WriteInputElement(writer, "aut", "cfUtente", SistemaTsSessionProtocol.AuthenticationNamespace,
            inputs, SistemaTsSessionProtocol.TaxCode);
        SistemaTsSessionProtocol.WriteInputElement(writer, "aut", "codRegione", SistemaTsSessionProtocol.AuthenticationNamespace,
            inputs, SistemaTsSessionProtocol.RegionCode);
        SistemaTsSessionProtocol.WriteInputElement(writer, "aut", "codAslAo", SistemaTsSessionProtocol.AuthenticationNamespace,
            inputs, SistemaTsSessionProtocol.HealthAuthorityCode);
        SistemaTsSessionProtocol.WriteInputElement(writer, "aut", "codSsa", SistemaTsSessionProtocol.AuthenticationNamespace,
            inputs, SistemaTsSessionProtocol.FacilityCode);
        writer.WriteElementString("aut", "contesto", SistemaTsSessionProtocol.AuthenticationNamespace, SistemaTsSessionProtocol.Context);
        writer.WriteElementString("aut", "applicazione", SistemaTsSessionProtocol.AuthenticationNamespace, SistemaTsSessionProtocol.Application);
    }
}

/// <summary>Parses the exact nested Sistema TS CreateAuthRes response.</summary>
public sealed class SistemaTsCreateSessionResponseAdapter : ITypedSessionHandshakeResponseAdapter
{
    /// <inheritdoc />
    public string AdapterId => "sistema-ts-create-session-response";
    /// <inheritdoc />
    public string AdapterType => "compiled-sistema-ts-create-v0.1";

    /// <inheritdoc />
    public TypedSessionHandshakeAdapterOutcome ReadResponse(XmlReader payload, TypedSessionHandshakeResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(context);
        SistemaTsSessionResponse response = SistemaTsSessionXml.ReadCreateResponse(payload);
        return response.Success
            ? TypedSessionHandshakeAdapterOutcome.ExternalAdmissionRequired(ExternalSessionProvenance.InteractiveHandoff)
            : TypedSessionHandshakeAdapterOutcome.Rejected(TypedSessionHandshakeRejection.Rejected);
    }
}

/// <summary>Writes and parses the official Sistema TS CheckToken contract for external admission.</summary>
public sealed class SistemaTsCheckTokenAdapter : ITypedExternalSessionValidationAdapter
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <inheritdoc />
    public string AdapterId => "sistema-ts-check-token";
    /// <inheritdoc />
    public string AdapterType => "compiled-sistema-ts-check-token-v0.1";
    /// <inheritdoc />
    public IReadOnlySet<string> RequiredServerOwnedInputs => SistemaTsSessionProtocol.CheckTokenInputs;

    /// <inheritdoc />
    public void WriteValidationRequest(XmlWriter writer, ExternalSessionValidationRequestContext context)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(context);
        if (context.Provenance != ExternalSessionProvenance.InteractiveHandoff ||
            context.ServerOwnedInputs.Count != SistemaTsSessionProtocol.CheckTokenInputs.Count)
            throw new XmlException("Sistema TS checkToken context is invalid.");

        AuthorizedConnectorBindingInputs inputs = context.ServerOwnedInputs;
        SistemaTsSessionProtocol.WriteInputElement(writer, "aut", "userId", SistemaTsSessionProtocol.AuthenticationNamespace,
            inputs, SistemaTsSessionProtocol.UserId);
        writer.WriteStartElement("aut", "identificativo", SistemaTsSessionProtocol.AuthenticationNamespace);
        SistemaTsSessionProtocol.WriteInputElement(writer, "dat", "tipo", SistemaTsSessionProtocol.DataNamespace,
            inputs, SistemaTsSessionProtocol.IdentifierType);
        SistemaTsSessionProtocol.WriteInputElement(writer, "dat", "valore", SistemaTsSessionProtocol.DataNamespace,
            inputs, SistemaTsSessionProtocol.IdentifierValue);
        writer.WriteEndElement();
        SistemaTsSessionProtocol.WriteInputElement(writer, "aut", "cfUtente", SistemaTsSessionProtocol.AuthenticationNamespace,
            inputs, SistemaTsSessionProtocol.TaxCode);

        char[] candidate = GC.AllocateUninitializedArray<char>(36);
        try
        {
            int written = StrictUtf8.GetChars(context.SensitiveCandidate.Span, candidate);
            if (written != 36 || !Guid.TryParseExact(candidate, "D", out _))
                throw new XmlException("Sistema TS ID-session candidate is malformed.");
            writer.WriteStartElement("aut", "token", SistemaTsSessionProtocol.AuthenticationNamespace);
            writer.WriteChars(candidate, 0, written);
            writer.WriteEndElement();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(System.Runtime.InteropServices.MemoryMarshal.AsBytes(candidate.AsSpan()));
        }

        writer.WriteElementString("aut", "contesto", SistemaTsSessionProtocol.AuthenticationNamespace, SistemaTsSessionProtocol.Context);
        writer.WriteElementString("aut", "applicazione", SistemaTsSessionProtocol.AuthenticationNamespace, SistemaTsSessionProtocol.Application);
    }

    /// <inheritdoc />
    public ExternalSessionValidationResult ReadValidationResponse(XmlReader payload, ExternalSessionValidationResponseContext context)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(context);
        SistemaTsCheckTokenResponse response = SistemaTsSessionXml.ReadCheckTokenResponse(payload);
        return response.Valid && response.ExpiresAt is not null
            ? ExternalSessionValidationResult.Valid(response.ExpiresAt.Value)
            : ExternalSessionValidationResult.Invalid(ExternalSessionValidationStatus.Rejected);
    }
}

internal sealed record SistemaTsSessionResponse(bool Success);
internal sealed record SistemaTsCheckTokenResponse(bool Valid, DateTimeOffset? ExpiresAt);

using System.Globalization;
using System.Text;
using System.Xml;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

namespace SecureIntegration.Gateway.Api;

internal static class SyntheticTypedSessionProtocol
{
    internal const string Namespace = "urn:synthetic:typed-session";
}

internal sealed class SyntheticTypedSessionRequestAdapter : ITypedSessionHandshakeRequestAdapter
{
    public string AdapterId => "synthetic-create-session-request";
    public string AdapterType => "compiled-typed-request";

    public void WriteRequest(XmlWriter writer, TypedSessionHandshakeRequestContext context)
    {
        writer.WriteStartElement("s", "ClientContext", SyntheticTypedSessionProtocol.Namespace);
        writer.WriteStartElement("s", "Identity", SyntheticTypedSessionProtocol.Namespace);
        writer.WriteElementString("s", "Tenant", SyntheticTypedSessionProtocol.Namespace, context.TenantId.ToString("D"));
        writer.WriteElementString("s", "Installation", SyntheticTypedSessionProtocol.Namespace, context.InstallationId.ToString("D"));
        writer.WriteElementString("s", "Application", SyntheticTypedSessionProtocol.Namespace, context.ApplicationId.ToString("D"));
        writer.WriteEndElement();
        writer.WriteStartElement("s", "Policy", SyntheticTypedSessionProtocol.Namespace);
        writer.WriteElementString("s", "Profile", SyntheticTypedSessionProtocol.Namespace, context.ProfileId);
        writer.WriteElementString("s", "PublishedChecksum", SyntheticTypedSessionProtocol.Namespace, context.PublishedPolicyChecksum);
        writer.WriteEndElement();
        writer.WriteEndElement();
    }
}

internal sealed class SyntheticTypedSessionResponseAdapter : ITypedSessionHandshakeResponseAdapter
{
    public string AdapterId => "synthetic-create-session-response";
    public string AdapterType => "compiled-typed-response";

    public TypedSessionHandshakeAdapterOutcome ReadResponse(XmlReader payload, TypedSessionHandshakeResponseContext context)
    {
        payload.ReadStartElement("CreateSessionResponse", SyntheticTypedSessionProtocol.Namespace);
        payload.ReadStartElement("Result", SyntheticTypedSessionProtocol.Namespace);
        string status = payload.ReadElementContentAsString("Status", SyntheticTypedSessionProtocol.Namespace);
        TypedSessionHandshakeAdapterOutcome outcome;
        if (string.Equals(status, "issued", StringComparison.Ordinal))
        {
            payload.ReadStartElement("Session", SyntheticTypedSessionProtocol.Namespace);
            string value = payload.ReadElementContentAsString("Value", SyntheticTypedSessionProtocol.Namespace);
            DateTimeOffset expiry = DateTimeOffset.ParseExact(payload.ReadElementContentAsString("ExpiresAt", SyntheticTypedSessionProtocol.Namespace), "O", CultureInfo.InvariantCulture);
            payload.ReadEndElement();
            outcome = TypedSessionHandshakeAdapterOutcome.Issued(value, expiry);
        }
        else if (string.Equals(status, "external_admission_required", StringComparison.Ordinal))
        {
            payload.ReadStartElement("Admission", SyntheticTypedSessionProtocol.Namespace);
            if (!string.Equals(payload.ReadElementContentAsString("Provenance", SyntheticTypedSessionProtocol.Namespace), "interactive_handoff", StringComparison.Ordinal)) throw new XmlException();
            payload.ReadEndElement();
            outcome = TypedSessionHandshakeAdapterOutcome.ExternalAdmissionRequired();
        }
        else if (string.Equals(status, "rejected", StringComparison.Ordinal))
        {
            outcome = TypedSessionHandshakeAdapterOutcome.Rejected(TypedSessionHandshakeRejection.Rejected);
        }
        else throw new XmlException();
        payload.ReadEndElement();
        payload.ReadEndElement();
        return outcome;
    }
}

internal sealed class SyntheticExternalSessionValidationAdapter : ITypedExternalSessionValidationAdapter
{
    public string AdapterId => "synthetic-session-validator";
    public string AdapterType => "compiled-typed-validator";

    public void WriteValidationRequest(XmlWriter writer, ExternalSessionValidationRequestContext context)
    {
        writer.WriteStartElement("s", "Candidate", SyntheticTypedSessionProtocol.Namespace);
        writer.WriteElementString("s", "Provenance", SyntheticTypedSessionProtocol.Namespace, "interactive_handoff");
        writer.WriteElementString("s", "OpaqueValue", SyntheticTypedSessionProtocol.Namespace, Encoding.UTF8.GetString(context.SensitiveCandidate.Span));
        writer.WriteEndElement();
    }

    public ExternalSessionValidationResult ReadValidationResponse(XmlReader payload, ExternalSessionValidationResponseContext context)
    {
        payload.ReadStartElement("ValidateSessionResponse", SyntheticTypedSessionProtocol.Namespace);
        payload.ReadStartElement("Validation", SyntheticTypedSessionProtocol.Namespace);
        string status = payload.ReadElementContentAsString("Status", SyntheticTypedSessionProtocol.Namespace);
        if (string.Equals(status, "rejected", StringComparison.Ordinal))
        {
            payload.ReadEndElement();
            payload.ReadEndElement();
            return ExternalSessionValidationResult.Invalid(ExternalSessionValidationStatus.Rejected);
        }
        if (!string.Equals(status, "valid", StringComparison.Ordinal)) throw new XmlException();
        DateTimeOffset expiry = DateTimeOffset.ParseExact(payload.ReadElementContentAsString("ExpiresAt", SyntheticTypedSessionProtocol.Namespace), "O", CultureInfo.InvariantCulture);
        payload.ReadEndElement();
        payload.ReadEndElement();
        return ExternalSessionValidationResult.Valid(expiry);
    }
}

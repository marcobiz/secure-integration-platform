using System.Collections.Frozen;
using System.Text.Json;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2;

/// <summary>Opt-in contracts frozen at it-fse-support 4d2691d; historical Published profiles are unchanged.</summary>
public static class Fse2CurrentSpec
{
    public const string ProfileId = "fse2-organization-current-spec-v1";
    public const string ConnectorId = "fse2-organization-current-spec";
    public const string ConnectorVersion = "1.0.0";
    public const string OfficialSpecCommit = "4d2691dcdc051fa5a842e2cac074226bb50373d2";
    private static readonly FrozenSet<string> OrganizationalSettings = (
        "001 002 003 004 005 006 007 008 009 010 011 012 013 014 015 018 019 020 021 " +
        "024 025 026 027 028 029 030 031 032 033 034 035 036 037 038 039 040 041 042 043 " +
        "046 047 048 049 050 051 052 054 055 056 057 058 060 061 062 064 065 066 067 " +
        "068 069 070 071 072 073 074 075 076 077 078 094 096 097 098 099 100 101 102 " +
        "103 104 107 109 121 122 126 129 130 131 199 999")
        .Split(' ').Select(value => "AD_PSC" + value).ToFrozenSet(StringComparer.Ordinal);

    /// <summary>Checks the closed operation schema without transforming or retaining the caller's JSON.</summary>
    public static void ValidateRequestBody(Fse2Operation operation, ReadOnlyMemory<byte> body, string? publishedActivity = null)
    {
        try
        {
            if (body.IsEmpty || body.Length > 1024 * 1024) throw new JsonException();
            using JsonDocument document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 4 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new JsonException();
            HashSet<string> names = new(StringComparer.Ordinal);
            foreach (JsonProperty property in root.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new JsonException();
                ValidateProperty(operation, property);
            }
            if (operation is Fse2Operation.ValidateCda or Fse2Operation.ValidateFhir)
            {
                Require(names, "activity");
                if (operation == Fse2Operation.ValidateFhir) Require(names, "mode");
                string activity = root.GetProperty("activity").GetString()!;
                if (operation == Fse2Operation.ValidateFhir && activity != "VERIFICA" ||
                    operation == Fse2Operation.ValidateCda && publishedActivity is not null && activity != publishedActivity)
                    throw new JsonException();
            }
            else if (operation == Fse2Operation.UpdateMetadataChainConcealment)
            {
                Require(names, "attiCliniciRegoleAccesso");
                if (!root.GetProperty("attiCliniciRegoleAccesso").EnumerateArray().Any(value => value.GetString() == "P99"))
                    throw new JsonException();
            }
            else
            {
                Require(names, "assettoOrganizzativo", "identificativoSottomissione", "tipoAttivitaClinica", "tipoDocumentoLivAlto", "tipologiaStruttura");
                if (Fse2OperationCatalog.Get(operation).HasDocument)
                    Require(names, "identificativoDoc", "identificativoRep");
                // Guide 16.2 requires the validation workflow for ordinary publication. Recovery routes omit it.
                if (IsPublication(operation)) Require(names, "workflowInstanceId");
            }
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or ArgumentException or KeyNotFoundException)
        {
            throw new ArgumentException("FSE2_CURRENT_SPEC_REQUEST_DENIED");
        }
    }

    private static bool IsPublication(Fse2Operation operation) => operation is
        Fse2Operation.Create or Fse2Operation.Replace or Fse2Operation.CreateFhir or Fse2Operation.ReplaceFhir;

    private static void ValidateProperty(Fse2Operation operation, JsonProperty property)
    {
        string name = property.Name;
        JsonElement value = property.Value;
        bool validation = operation is Fse2Operation.ValidateCda or Fse2Operation.ValidateFhir;
        if (validation)
        {
            switch (name)
            {
                case "activity": Enum(value, "VERIFICA", "VALIDATION"); return;
                case "mode": Enum(value, "ATTACHMENT", "RESOURCE"); return;
                case "healthDataFormat" when operation == Fse2Operation.ValidateCda: Enum(value, "CDA"); return;
                default: throw new JsonException();
            }
        }
        if (operation == Fse2Operation.UpdateMetadataChainConcealment)
        {
            if (name != "attiCliniciRegoleAccesso") throw new JsonException();
            Strings(value, 100, 1000);
            return;
        }
        bool document = Fse2OperationCatalog.Get(operation).HasDocument;
        bool metadata = operation is Fse2Operation.UpdateMetadata or Fse2Operation.UpdateMetadataLegacy;
        if (!document && !metadata) throw new JsonException();
        switch (name)
        {
            case "tipologiaStruttura": Enum(value, "Ospedale", "Prevenzione", "Territorio", "SistemaTS", "Cittadino", "MdsPN_DGC"); break;
            case "tipoDocumentoLivAlto": Enum(value, "WOR", "REF", "LDO", "RIC", "SUM", "TAC", "PRS", "PRE", "ESE", "PDC", "VAC", "CER", "VRB", "CON", "CNT", "CRT", "LET", "PRO", "COL"); break;
            case "assettoOrganizzativo": if (!OrganizationalSettings.Contains(Text(value, 9))) throw new JsonException(); break;
            case "tipoAttivitaClinica": Enum(value, "PHR", "CON", "DIS", "ERP", "Sistema_TS", "INI", "PN_DGC", "OBS"); break;
            case "dataInizioPrestazione": case "dataFinePrestazione": case "conservazioneANorma":
            case "identificativoSottomissione": Text(value, 100); break;
            case "attiCliniciRegoleAccesso": case "descriptions": Strings(value, 100, 1000); break;
            case "administrativeRequest":
                Strings(value, 1000, 1000);
                foreach (JsonElement item in value.EnumerateArray()) Enum(item, "SSN", "INPATIENT", "NOSSN", "SSR", "DONOR", "AUTO");
                break;
            case "identificativoDoc" when document: Text(value, 256); break;
            case "identificativoRep" when document: Text(value, 100); break;
            case "mode" when document: Enum(value, "ATTACHMENT", "RESOURCE"); break;
            case "healthDataFormat" when document: Enum(value, "CDA"); break;
            case "workflowInstanceId" when IsPublication(operation): Fse2Validation.ValidateWorkflowId(Text(value, 256)); break;
            case "priorita" when operation is Fse2Operation.Create or Fse2Operation.CreateFhir:
                if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new JsonException();
                break;
            default: throw new JsonException();
        }
    }

    private static void Require(HashSet<string> names, params string[] required)
    {
        if (required.Any(name => !names.Contains(name))) throw new JsonException();
    }

    private static string Text(JsonElement value, int maximum)
    {
        if (value.ValueKind != JsonValueKind.String) throw new JsonException();
        string text = value.GetString()!;
        if (text.Length > maximum) throw new JsonException();
        return text;
    }

    private static void Enum(JsonElement value, params string[] allowed)
    {
        if (!allowed.Contains(Text(value, 100), StringComparer.Ordinal)) throw new JsonException();
    }

    private static void Strings(JsonElement value, int maximumItems, int maximumLength)
    {
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > maximumItems) throw new JsonException();
        foreach (JsonElement item in value.EnumerateArray()) Text(item, maximumLength);
    }
}

namespace SecureIntegration.ConnectorPacks.Healthcare.RegionalEPrescription;

/// <summary>Public-safe characterization status. These records are not runtime-selectable profiles.</summary>
public sealed record RegionalProfileReadiness(string ProfileId, RegionalEPrescriptionProfileAvailability Availability, string BlockCode);

/// <summary>Current Wave 1 profile status based solely on reviewed official public material.</summary>
public static class RegionalEPrescriptionWave1Readiness
{
    /// <summary>Lombardia is not supported until the current prescription API/auth/accreditation contract is available.</summary>
    public static RegionalProfileReadiness Lombardia { get; } = new(
        "healthcare.regional-eprescription.lombardia",
        RegionalEPrescriptionProfileAvailability.BlockedBySpec,
        "BLOCKED-BY-SPEC-LOMBARDIA");

    /// <summary>Emilia-Romagna is not supported until the current SOLE application-to-application contract is available.</summary>
    public static RegionalProfileReadiness EmiliaRomagna { get; } = new(
        "healthcare.regional-eprescription.emilia-romagna",
        RegionalEPrescriptionProfileAvailability.BlockedBySpec,
        "BLOCKED-BY-SPEC-EMILIA-ROMAGNA");
}

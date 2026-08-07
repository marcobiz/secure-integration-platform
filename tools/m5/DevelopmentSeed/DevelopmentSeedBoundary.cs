namespace SecureIntegration.M5.DevelopmentSeed;

/// <summary>Fail-closed boundary for the local-only demonstration seed.</summary>
public static class DevelopmentSeedBoundary
{
    /// <summary>Returns true only for an explicit Development invocation.</summary>
    public static bool IsEnabled(string? environment, string? explicitOptIn) =>
        string.Equals(environment, "Development", StringComparison.Ordinal) &&
        string.Equals(explicitOptIn, "true", StringComparison.Ordinal);
}

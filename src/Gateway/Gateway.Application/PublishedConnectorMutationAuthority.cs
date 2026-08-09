namespace SecureIntegration.Gateway.Application;

/// <summary>
/// Generation captured from the single-node Connector runtime mutation authority.
/// It is opaque to callers and can be used only by the authority that created it.
/// </summary>
public readonly record struct PublishedConnectorAuthorityGeneration(int Stripe, long Value);

/// <summary>Exposes the mutation authority shared by runtime reads and administrative writes.</summary>
public interface IPublishedConnectorMutationAuthoritySource
{
    /// <summary>Process-local authority used to linearize final runtime promotion with mutations.</summary>
    PublishedConnectorMutationAuthority RuntimeMutationAuthority { get; }
}

/// <summary>
/// Fixed-size striped generation/CAS authority for the single-node runtime. Administrative
/// mutation paths mark a stripe active before changing Published, binding or provider-resource
/// state and advance it again after completion; a runtime promotion executes synchronously only
/// while its captured generation is current and no relevant mutation is in progress.
/// </summary>
public sealed class PublishedConnectorMutationAuthority
{
    private const int StripeCount = 64;
    private readonly StripeState[] stripes = Enumerable.Range(0, StripeCount).Select(_ => new StripeState()).ToArray();

    /// <summary>Captures the current generation for one Connector and Environment.</summary>
    public PublishedConnectorAuthorityGeneration Capture(string connectorId, Guid environmentId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectorId);
        if (environmentId == Guid.Empty) throw new ArgumentException("Environment identity is required.", nameof(environmentId));
        int index = Stripe(connectorId, environmentId);
        lock (stripes[index].Sync)
            return new(index, stripes[index].Generation);
    }

    /// <summary>Invalidates one Connector/Environment authority before a mutation is attempted.</summary>
    public void Invalidate(string connectorId, Guid environmentId)
    {
        int index = Stripe(connectorId, environmentId);
        lock (stripes[index].Sync)
            stripes[index].Generation = checked(stripes[index].Generation + 1);
    }

    /// <summary>
    /// Conservatively invalidates every stripe when a mutation affects multiple environments or
    /// its exact runtime scope is not yet known. Stripes remain independent; there is no global lock.
    /// </summary>
    public void InvalidateAll()
    {
        foreach (StripeState stripe in stripes)
        {
            lock (stripe.Sync)
                stripe.Generation = checked(stripe.Generation + 1);
        }
    }

    /// <summary>Marks one Connector/Environment mutation active until the returned lease is disposed.</summary>
    public MutationLease BeginMutation(string connectorId, Guid environmentId) => BeginMutation([Stripe(connectorId, environmentId)]);

    /// <summary>Marks every stripe active for a mutation whose exact runtime scope is not yet known.</summary>
    public MutationLease BeginMutationAll() => BeginMutation(Enumerable.Range(0, StripeCount).ToArray());

    /// <summary>
    /// Executes a synchronous promotion while holding the exact stripe only if the captured
    /// generation is still current. The callback must not block or perform asynchronous work.
    /// </summary>
    public bool TryPromoteIfCurrent<T>(PublishedConnectorAuthorityGeneration expected, Func<T> promotion, out T? result)
    {
        ArgumentNullException.ThrowIfNull(promotion);
        if (expected.Stripe is < 0 or >= StripeCount)
        {
            result = default;
            return false;
        }
        StripeState stripe = stripes[expected.Stripe];
        lock (stripe.Sync)
        {
            if (stripe.Generation != expected.Value || stripe.ActiveMutations != 0)
            {
                result = default;
                return false;
            }
            result = promotion();
            return true;
        }
    }

    private static int Stripe(string connectorId, Guid environmentId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectorId);
        if (environmentId == Guid.Empty) throw new ArgumentException("Environment identity is required.", nameof(environmentId));
        return (HashCode.Combine(StringComparer.Ordinal.GetHashCode(connectorId), environmentId) & int.MaxValue) % StripeCount;
    }

    private MutationLease BeginMutation(int[] indexes)
    {
        foreach (int index in indexes)
        {
            StripeState stripe = stripes[index];
            lock (stripe.Sync)
            {
                stripe.Generation = checked(stripe.Generation + 1);
                stripe.ActiveMutations = checked(stripe.ActiveMutations + 1);
            }
        }
        return new MutationLease(this, indexes);
    }

    private void CompleteMutation(int[] indexes)
    {
        foreach (int index in indexes)
        {
            StripeState stripe = stripes[index];
            lock (stripe.Sync)
            {
                if (stripe.ActiveMutations <= 0) throw new InvalidOperationException("Published mutation lease is not active.");
                stripe.Generation = checked(stripe.Generation + 1);
                stripe.ActiveMutations--;
            }
        }
    }

    private sealed class StripeState
    {
        internal object Sync { get; } = new();
        internal long Generation { get; set; }
        internal int ActiveMutations { get; set; }
    }

    /// <summary>Non-constructible lease delimiting one in-progress authoritative mutation.</summary>
    public sealed class MutationLease : IDisposable
    {
        private readonly PublishedConnectorMutationAuthority owner;
        private readonly int[] indexes;
        private int disposed;

        internal MutationLease(PublishedConnectorMutationAuthority owner, int[] indexes)
        {
            this.owner = owner;
            this.indexes = indexes;
        }

        /// <inheritdoc />
        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) == 0) owner.CompleteMutation(indexes);
        }
    }
}

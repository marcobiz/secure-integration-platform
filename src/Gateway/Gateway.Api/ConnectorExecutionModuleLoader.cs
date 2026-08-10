using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.Loader;
using Microsoft.Extensions.DependencyInjection;
using SecureIntegration.Gateway.Application;
using SecureIntegration.Gateway.ConnectorRuntime.Auth.Soap;

namespace SecureIntegration.Gateway.Api;

internal static class ConnectorExecutionModuleLoader
{
    private const int MaximumModules = 32;
    private const int MaximumAssemblyBytes = 64 * 1024 * 1024;

    internal static void Register(
        IServiceCollection services,
        IReadOnlyCollection<GatewayExecutionModuleOptions> configuredModules,
        Action<string>? afterAssemblyIdentityVerified = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuredModules);
        if (configuredModules.Count > MaximumModules)
            throw new InvalidOperationException("Too many Connector execution modules are configured.");

        HashSet<string> paths = new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        HashSet<ConnectorExecutionModuleId> moduleIds = [];
        HashSet<string> moduleTypes = new(StringComparer.Ordinal);
        foreach (GatewayExecutionModuleOptions configured in configuredModules)
        {
            ConnectorExecutionModuleId expectedId;
            try { expectedId = ConnectorExecutionModuleId.Parse(configured.ModuleId); }
            catch (ArgumentException) { throw new InvalidOperationException("Configured Connector execution module ID is invalid."); }

            string canonicalPath = RequiredLocalCanonicalPath(configured.AssemblyPath);
            if (!paths.Add(canonicalPath))
                throw new InvalidOperationException("Connector execution module assembly path is duplicated.");
            if (string.IsNullOrWhiteSpace(configured.AssemblyFullName) || string.IsNullOrWhiteSpace(configured.ModuleType) ||
                !moduleTypes.Add(configured.ModuleType))
                throw new InvalidOperationException("Connector execution module identity is incomplete or duplicated.");

            Assembly assembly = LoadVerifiedBytes(canonicalPath, configured.AssemblyFullName, afterAssemblyIdentityVerified);

            Type moduleType;
            IConnectorExecutionModule module;
            try
            {
                moduleType = assembly.GetType(configured.ModuleType, throwOnError: true, ignoreCase: false)!;
                if (!moduleType.IsVisible || moduleType.IsAbstract || !typeof(IConnectorExecutionModule).IsAssignableFrom(moduleType) ||
                    moduleType.GetConstructor(Type.EmptyTypes) is null)
                    throw new InvalidOperationException();
                module = (IConnectorExecutionModule)Activator.CreateInstance(moduleType)!;
            }
            catch (Exception)
            {
                throw new InvalidOperationException("Connector execution module type does not implement the required startup contract.");
            }
            if (module.Id != expectedId || !moduleIds.Add(module.Id))
                throw new InvalidOperationException("Connector execution module ID does not match deployment configuration or is duplicated.");

            ConnectorExecutionStrategyRegistrar registrar = new(services, assembly);
            try
            {
                module.RegisterExecutionStrategies(registrar);
                if (registrar.StrategyCount == 0)
                    throw new InvalidOperationException("Connector execution module registered no execution strategy.");
                registrar.ValidateAndCommit();
            }
            catch (Exception)
            {
                throw new InvalidOperationException("Connector execution module registration or constructor dependency graph is invalid.");
            }
        }
    }

    private static string RequiredLocalCanonicalPath(string configuredPath)
    {
        if (string.IsNullOrWhiteSpace(configuredPath) || !Path.IsPathFullyQualified(configuredPath) ||
            HasTraversalSegment(configuredPath))
            throw new InvalidOperationException("Connector execution module assembly path must be an absolute canonical local path.");

        string canonicalPath;
        try { canonicalPath = Path.GetFullPath(configuredPath); }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new InvalidOperationException("Connector execution module assembly path must be an absolute canonical local path.");
        }
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!string.Equals(configuredPath, canonicalPath, comparison) ||
            !string.Equals(Path.GetExtension(canonicalPath), ".dll", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Connector execution module assembly path must be an absolute canonical local path.");

        if (OperatingSystem.IsWindows())
        {
            string? root = Path.GetPathRoot(canonicalPath);
            bool driveRoot = root is { Length: 3 } && char.IsAsciiLetter(root[0]) && root[1] == ':' &&
                (root[2] == Path.DirectorySeparatorChar || root[2] == Path.AltDirectorySeparatorChar);
            if (!driveRoot || canonicalPath.AsSpan(2).Contains(':'))
                throw new InvalidOperationException("UNC, mapped-network and device paths are not allowed for Connector execution modules.");
            try
            {
                if (new DriveInfo(root!).DriveType != DriveType.Fixed)
                    throw new InvalidOperationException("UNC, mapped-network and device paths are not allowed for Connector execution modules.");
            }
            catch (InvalidOperationException) { throw; }
            catch (Exception)
            {
                throw new InvalidOperationException("Connector execution module drive type could not be verified as local and fixed.");
            }
        }

        RequireDirectNonReparsePath(canonicalPath);

        return canonicalPath;
    }

    private static void RequireDirectNonReparsePath(string canonicalPath)
    {
        try
        {
            string? root = Path.GetPathRoot(canonicalPath);
            FileSystemInfo? current = new FileInfo(canonicalPath);
            while (current is not null && !string.Equals(current.FullName, root, OperatingSystem.IsWindows()
                       ? StringComparison.OrdinalIgnoreCase
                       : StringComparison.Ordinal))
            {
                if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("Connector execution module paths may not traverse symbolic links or reparse points.");
                current = current switch
                {
                    FileInfo file => file.Directory,
                    DirectoryInfo directory => directory.Parent,
                    _ => null
                };
            }
        }
        catch (InvalidOperationException) { throw; }
        catch (Exception)
        {
            throw new InvalidOperationException("Connector execution module assembly path is unavailable or cannot be verified.");
        }
    }

    private static bool HasTraversalSegment(string path) => path
        .Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries)
        .Any(segment => segment is "." or "..");

    private static Assembly LoadVerifiedBytes(
        string canonicalPath,
        string expectedFullName,
        Action<string>? afterAssemblyIdentityVerified)
    {
        byte[] bytes;
        try
        {
            using FileStream source = new(canonicalPath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024,
                FileOptions.SequentialScan);
            if (source.Length is < 1 or > MaximumAssemblyBytes)
                throw new InvalidOperationException("Connector execution module assembly size is invalid.");
            bytes = GC.AllocateUninitializedArray<byte>(checked((int)source.Length));
            source.ReadExactly(bytes);

            ModuleMetadata metadata = ReadMetadata(bytes);
            if (!string.Equals(metadata.Identity.FullName, expectedFullName, StringComparison.Ordinal))
                throw new InvalidOperationException("Connector execution module assembly identity does not match deployment configuration.");

            afterAssemblyIdentityVerified?.Invoke(canonicalPath);

            using MemoryStream exactBytes = new(bytes, writable: false);
            Assembly loaded = AssemblyLoadContext.Default.LoadFromStream(exactBytes);
            if (!string.Equals(loaded.FullName, expectedFullName, StringComparison.Ordinal) ||
                loaded.ManifestModule.ModuleVersionId != metadata.ModuleVersionId)
                throw new InvalidOperationException("Loaded Connector execution module is not the verified assembly image.");
            return loaded;
        }
        catch (InvalidOperationException) { throw; }
        catch (Exception)
        {
            throw new InvalidOperationException("Connector execution module assembly could not be opened, verified and loaded from one image.");
        }
    }

    private static ModuleMetadata ReadMetadata(byte[] bytes)
    {
        try
        {
            using MemoryStream metadataBytes = new(bytes, writable: false);
            using PEReader pe = new(metadataBytes, PEStreamOptions.LeaveOpen);
            if (!pe.HasMetadata) throw new BadImageFormatException();
            MetadataReader reader = pe.GetMetadataReader();
            AssemblyDefinition definition = reader.GetAssemblyDefinition();
            AssemblyName identity = new(reader.GetString(definition.Name))
            {
                Version = definition.Version,
                Flags = (AssemblyNameFlags)(int)definition.Flags,
                CultureName = definition.Culture.IsNil ? string.Empty : reader.GetString(definition.Culture)
            };
            if (!definition.PublicKey.IsNil)
                identity.SetPublicKey(reader.GetBlobBytes(definition.PublicKey));
            else
                identity.SetPublicKeyToken([]);
            ModuleDefinition module = reader.GetModuleDefinition();
            return new(identity, reader.GetGuid(module.Mvid));
        }
        catch (Exception)
        {
            throw new InvalidOperationException("Connector execution module assembly identity could not be read from the verified image.");
        }
    }

    private sealed record ModuleMetadata(AssemblyName Identity, Guid ModuleVersionId);

    private sealed class ConnectorExecutionStrategyRegistrar : IConnectorExecutionStrategyRegistrar
    {
        private const int MaximumStrategiesPerModule = 64;
        private const int MaximumRegistrationsPerModule = 128;
        private const int MaximumConstructorDepth = 32;
        private readonly IServiceCollection services;
        private readonly Assembly moduleAssembly;
        private readonly List<ServiceDescriptor> descriptors = [];
        private readonly Dictionary<Type, Type> moduleServices = [];
        private readonly List<Type> implementations = [];
        private readonly HashSet<Type> adapterImplementations = [];
        private int validatedNodes;
        private int requestAdapterCount;
        private int responseAdapterCount;
        private int validationAdapterCount;

        internal ConnectorExecutionStrategyRegistrar(IServiceCollection services, Assembly moduleAssembly)
        {
            this.services = services;
            this.moduleAssembly = moduleAssembly;
        }

        internal int StrategyCount { get; private set; }

        public void AddSingleton<TService>() where TService : class
        {
            Type service = typeof(TService);
            RegisterService(service, service);
        }

        public void AddSingleton<TService, TImplementation>()
            where TService : class
            where TImplementation : class, TService =>
            RegisterService(typeof(TService), typeof(TImplementation));

        public void AddStrategy<TStrategy>() where TStrategy : class, IConnectorExecutionStrategy
        {
            Type implementation = typeof(TStrategy);
            RequireRegistrationCapacity();
            RequireModuleOwned(implementation);
            RequireConstructible(implementation);
            if (StrategyCount >= MaximumStrategiesPerModule)
                throw new InvalidOperationException("Connector execution module strategy registration is full.");
            descriptors.Add(ServiceDescriptor.Singleton(typeof(IConnectorExecutionStrategy), implementation));
            implementations.Add(implementation);
            StrategyCount++;
        }

        public void AddTypedSessionHandshakeRequestAdapter<TAdapter>() where TAdapter : class =>
            RegisterAdapter(typeof(ITypedSessionHandshakeRequestAdapter), typeof(TAdapter), ref requestAdapterCount);

        public void AddTypedSessionHandshakeResponseAdapter<TAdapter>() where TAdapter : class =>
            RegisterAdapter(typeof(ITypedSessionHandshakeResponseAdapter), typeof(TAdapter), ref responseAdapterCount);

        public void AddExternalSessionValidationAdapter<TAdapter>() where TAdapter : class =>
            RegisterAdapter(typeof(ITypedExternalSessionValidationAdapter), typeof(TAdapter), ref validationAdapterCount);

        internal void ValidateAndCommit()
        {
            HashSet<Type> validated = [];
            foreach (Type implementation in implementations.Distinct())
                ValidateConstructorGraph(implementation, validated, [], depth: 0);
            foreach (ServiceDescriptor descriptor in descriptors)
                services.Add(descriptor);
        }

        private void RegisterService(Type service, Type implementation)
        {
            RequireRegistrationCapacity();
            RequireModuleOwned(service);
            RequireModuleOwned(implementation);
            RequireConstructible(implementation);
            if (typeof(IConnectorExecutionStrategy).IsAssignableFrom(service) ||
                typeof(IConnectorExecutionStrategy).IsAssignableFrom(implementation) ||
                service.IsGenericTypeDefinition || implementation.IsGenericTypeDefinition ||
                !moduleServices.TryAdd(service, implementation))
                throw new InvalidOperationException("Connector execution module service registration is invalid or duplicated.");
            descriptors.Add(ServiceDescriptor.Singleton(service, implementation));
            implementations.Add(implementation);
        }

        private void RegisterAdapter(Type contract, Type implementation, ref int categoryCount)
        {
            RequireRegistrationCapacity();
            RequireModuleOwned(implementation);
            RequireConstructible(implementation);
            if (!contract.IsAssignableFrom(implementation) || categoryCount >= MaximumStrategiesPerModule ||
                !adapterImplementations.Add(implementation))
                throw new InvalidOperationException("Connector execution module adapter registration is invalid, duplicated or full.");
            descriptors.Add(ServiceDescriptor.Singleton(contract, implementation));
            implementations.Add(implementation);
            categoryCount++;
        }

        private void ValidateConstructorGraph(
            Type implementation,
            HashSet<Type> validated,
            HashSet<Type> active,
            int depth)
        {
            if (validated.Contains(implementation)) return;
            if (depth > MaximumConstructorDepth || ++validatedNodes > MaximumRegistrationsPerModule || !active.Add(implementation))
                throw new InvalidOperationException("Connector execution module constructor dependency graph is cyclic or too deep.");

            ConstructorInfo[] constructors = implementation.GetConstructors(BindingFlags.Instance | BindingFlags.Public);
            if (constructors.Length != 1)
                throw new InvalidOperationException("Connector execution module services must expose exactly one public constructor.");
            foreach (ParameterInfo parameter in constructors[0].GetParameters())
            {
                Type dependency = parameter.ParameterType;
                if (dependency.Assembly != moduleAssembly || !moduleServices.TryGetValue(dependency, out Type? dependencyImplementation))
                    throw new InvalidOperationException("Connector execution module constructors may depend only on explicitly registered module-owned services.");
                ValidateConstructorGraph(dependencyImplementation, validated, active, depth + 1);
            }

            active.Remove(implementation);
            validated.Add(implementation);
        }

        private void RequireRegistrationCapacity()
        {
            if (descriptors.Count >= MaximumRegistrationsPerModule)
                throw new InvalidOperationException("Connector execution module registration is full.");
        }

        private void RequireModuleOwned(Type type)
        {
            if (type.Assembly != moduleAssembly)
                throw new InvalidOperationException("Connector execution modules may register only module-owned services.");
        }

        private static void RequireConstructible(Type implementation)
        {
            if (!implementation.IsVisible || implementation.IsAbstract || implementation.IsInterface || implementation.ContainsGenericParameters)
                throw new InvalidOperationException("Connector execution module implementation type is not constructible.");
        }
    }
}

using System.Reflection;
using System.Runtime.Loader;
using Microsoft.Extensions.DependencyInjection;
using SecureIntegration.Gateway.Application;

namespace SecureIntegration.Gateway.Api;

internal static class ConnectorExecutionModuleLoader
{
    private const int MaximumModules = 32;

    internal static void Register(IServiceCollection services, IReadOnlyCollection<GatewayExecutionModuleOptions> configuredModules)
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

            if (string.IsNullOrWhiteSpace(configured.AssemblyPath) || !Path.IsPathFullyQualified(configured.AssemblyPath))
                throw new InvalidOperationException("Connector execution module assembly path must be absolute and canonical.");
            string canonicalPath = Path.GetFullPath(configured.AssemblyPath);
            StringComparison pathComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (!string.Equals(configured.AssemblyPath, canonicalPath, pathComparison) || !File.Exists(canonicalPath) ||
                !paths.Add(canonicalPath))
                throw new InvalidOperationException("Connector execution module assembly path is unavailable, non-canonical or duplicated.");
            if (string.IsNullOrWhiteSpace(configured.AssemblyFullName) || string.IsNullOrWhiteSpace(configured.ModuleType) ||
                !moduleTypes.Add(configured.ModuleType))
                throw new InvalidOperationException("Connector execution module identity is incomplete or duplicated.");

            AssemblyName diskIdentity;
            try { diskIdentity = AssemblyName.GetAssemblyName(canonicalPath); }
            catch (Exception) { throw new InvalidOperationException("Connector execution module assembly identity could not be read."); }
            if (!string.Equals(diskIdentity.FullName, configured.AssemblyFullName, StringComparison.Ordinal))
                throw new InvalidOperationException("Connector execution module assembly identity does not match deployment configuration.");

            Assembly assembly;
            try { assembly = AssemblyLoadContext.Default.LoadFromAssemblyPath(canonicalPath); }
            catch (Exception) { throw new InvalidOperationException("Connector execution module assembly could not be loaded."); }
            string loadedPath = Path.GetFullPath(assembly.Location);
            if (!string.Equals(assembly.FullName, configured.AssemblyFullName, StringComparison.Ordinal) ||
                !string.Equals(loadedPath, canonicalPath, pathComparison))
                throw new InvalidOperationException("Loaded Connector execution module assembly identity or path is not the configured identity.");

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
            catch (Exception) { throw new InvalidOperationException("Connector execution module type does not implement the required startup contract."); }
            if (module.Id != expectedId || !moduleIds.Add(module.Id))
                throw new InvalidOperationException("Connector execution module ID does not match deployment configuration or is duplicated.");

            ConnectorExecutionStrategyRegistrar registrar = new(services, assembly);
            try { module.RegisterExecutionStrategies(registrar); }
            catch (Exception) { throw new InvalidOperationException("Connector execution module registration failed."); }
            if (registrar.StrategyCount == 0)
                throw new InvalidOperationException("Connector execution module registered no execution strategy.");
        }
    }

    private sealed class ConnectorExecutionStrategyRegistrar(IServiceCollection services, Assembly moduleAssembly) : IConnectorExecutionStrategyRegistrar
    {
        private const int MaximumStrategiesPerModule = 64;
        internal int StrategyCount { get; private set; }

        public void AddSingleton<TService>() where TService : class
        {
            RequireModuleOwned(typeof(TService));
            services.AddSingleton<TService>();
        }

        public void AddSingleton<TService, TImplementation>()
            where TService : class
            where TImplementation : class, TService
        {
            RequireModuleOwned(typeof(TService));
            RequireModuleOwned(typeof(TImplementation));
            services.AddSingleton<TService, TImplementation>();
        }

        public void AddStrategy<TStrategy>() where TStrategy : class, IConnectorExecutionStrategy
        {
            RequireModuleOwned(typeof(TStrategy));
            if (StrategyCount >= MaximumStrategiesPerModule)
                throw new InvalidOperationException("Connector execution module strategy registration is full.");
            services.AddSingleton<IConnectorExecutionStrategy, TStrategy>();
            StrategyCount++;
        }

        private void RequireModuleOwned(Type type)
        {
            if (type.Assembly != moduleAssembly)
                throw new InvalidOperationException("Connector execution modules may register only module-owned services.");
        }
    }
}

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.EventLog;
using SecureIntegration.Broker.Core;
using SecureIntegration.Broker.Infrastructure.Windows;
using SecureIntegration.Broker.Service;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);
BrokerOptions brokerOptions = builder.Configuration.GetSection("Broker").Get<BrokerOptions>() ?? new BrokerOptions();
builder.Services.AddWindowsService(options => options.ServiceName = brokerOptions.ServiceName);
builder.Services.Configure<EventLogSettings>(settings =>
{
    settings.LogName = "Application";
    settings.SourceName = "SecureIntegrationBroker";
    if (brokerOptions.ServiceName != "SecureIntegrationBroker") settings.SourceName = brokerOptions.ServiceName;
});

if (string.IsNullOrWhiteSpace(brokerOptions.InstallationId) || string.Equals(brokerOptions.InstallationId, "replace-during-installation", StringComparison.Ordinal))
{
    throw new InvalidOperationException("Broker:InstallationId must be provisioned uniquely during installation.");
}

if (string.IsNullOrWhiteSpace(brokerOptions.DataDirectory))
{
    brokerOptions.DataDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SecureIntegration", "Broker");
}

WindowsStorageSecurity.HardenDirectory(brokerOptions.DataDirectory);
builder.Services.AddSingleton(brokerOptions);
builder.Services.AddSingleton<ILocalProtectionProvider, WindowsDpapiProtectionProvider>();
builder.Services.AddSingleton<ILocalSecretRepository>(provider => new FileLocalSecretRepository(brokerOptions.DataDirectory));
builder.Services.AddSingleton<IDataKeyRepository>(provider => new FileDataKeyRepository(brokerOptions.DataDirectory, provider.GetRequiredService<ILocalProtectionProvider>()));
builder.Services.AddSingleton(provider => new AeadDataProtector(provider.GetRequiredService<IDataKeyRepository>(), brokerOptions.InstallationId));
builder.Services.AddSingleton<IBrokerAuditSink, LoggerAuditSink>();
builder.Services.AddSingleton(new ApplicationAuthorizer(brokerOptions.Applications));
if (brokerOptions.Gateway.Enabled)
{
    builder.Services.AddSingleton<IGatewayInvoker>(_ => new ProductionGatewayInvoker(brokerOptions.Gateway, brokerOptions.DataDirectory));
}
builder.Services.AddSingleton<BrokerApplicationService>(provider => new BrokerApplicationService(
    provider.GetRequiredService<ILocalSecretRepository>(),
    provider.GetRequiredService<ILocalProtectionProvider>(),
    provider.GetRequiredService<AeadDataProtector>(),
    provider.GetRequiredService<IBrokerAuditSink>(),
    brokerOptions.InstallationId,
    provider.GetService<IGatewayInvoker>()));
builder.Services.AddSingleton<BrokerRequestDispatcher>();
builder.Services.AddSingleton<NamedPipeBrokerServer>();
builder.Services.AddHostedService<BrokerWorker>();

using IHost host = builder.Build();
try
{
    if (brokerOptions.Applications.Any(application => application.AllowedOperations.Contains("ProtectData") || application.AllowedOperations.Contains("UnprotectData")))
    {
        FileDataKeyRepository keys = (FileDataKeyRepository)host.Services.GetRequiredService<IDataKeyRepository>();
        if (brokerOptions.InitializeDataKeys) await keys.InitializeAsync(CancellationToken.None).ConfigureAwait(false);
        DataKey active = await keys.GetActiveAsync(CancellationToken.None).ConfigureAwait(false);
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(active.Value);
    }
}
catch (BrokerException exception)
{
    // Fail startup without exposing paths, DPAPI exceptions or key material to service logs.
    Console.Error.WriteLine(exception.Code);
    Environment.ExitCode = 1;
    return;
}
await host.RunAsync().ConfigureAwait(false);

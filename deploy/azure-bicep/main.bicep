targetScope = 'subscription'

@description('Short lowercase environment name, for example dev or test.')
@minLength(2)
@maxLength(12)
param environmentName string

@description('Azure region selected by the deployment pipeline.')
param location string

@description('Immutable container image digest; mutable tags are not accepted by the release pipeline.')
@minLength(71)
param gatewayImageDigest string

// M2 publishes only the validated contract surface for the future Azure deployment.
// Resource modules, private networking and observability are implemented in DEP-02/M9.
output deploymentContract object = {
  environmentName: environmentName
  location: location
  gatewayImageDigest: gatewayImageDigest
  requiredServices: [
    'AppServiceLinuxContainer'
    'AzureContainerRegistry'
    'KeyVault'
    'PostgreSQLFlexibleServer18'
    'ManagedIdentity'
  ]
}

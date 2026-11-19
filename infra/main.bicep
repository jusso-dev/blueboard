// blueboard on Azure, in Australia: React front end on App Service + C# Azure Functions back end.
//
//   web    App Service Web App (Linux, .NET 10). A small ASP.NET Core host serves the React build with strict
//          security headers. It has no identity, no secrets and no data access: the browser signs in with
//          Microsoft Entra ID (MSAL, auth code + PKCE) and calls the Function App directly with an access token.
//   api    Azure Functions, Flex Consumption, .NET 10 isolated. REST for the web app (CORS: the web origin only),
//          the MCP endpoint for agents (/runtime/webhooks/mcp), timer triggers for the Defender incident poller
//          and stuck-action recovery. Every request carries an Entra bearer token, validated in code.
//   data   Azure Database for PostgreSQL Flexible Server 16, Entra authentication only.
//
// Every resource is created in one Australian region (location), so board data, logs and the deployment
// package stay in Australia. Microsoft Graph and Defender are tenant services (their data location is set
// by your Microsoft 365 / Defender tenant), and Claude on Microsoft Foundry is not offered in an Australian
// region yet: see docs/architecture.md § Data residency.
//
// Identities (no stored secrets anywhere):
//   id-api   Function App: Graph + Defender application permissions (infra/grant-permissions.sh),
//            PostgreSQL Entra admin, host storage data roles, Application Insights publisher.

targetScope = 'resourceGroup'

@description('Australian region for every resource. Flex Consumption is offered in Australia East and Australia Southeast.')
@allowed(['australiaeast', 'australiasoutheast'])
param location string = 'australiaeast'
param namePrefix string = 'blueboard'
param tenantId string = tenant().tenantId
@description('Client id of the board app registration (infra/entra-app.sh). Also the web app\'s MSAL client id.')
param boardApiClientId string
@description('App ID URI of the board API, e.g. api://blueboard-prod.')
param boardApiAudience string
@description('Leave false until policy.json is reviewed: approved actions are recorded as dry runs.')
param brokerExecute bool = false
param ingestEnabled bool = true
@description('Contents of policy.json. Stored as a Function App setting, written to a private temp file at start-up. Kept out of deployment history.')
@secure()
param policyJson string
@description('Maximum Function App instances (Flex Consumption).')
param maximumInstanceCount int = 40
@description('App Service plan for the web front end. B1 is enough for a SOC; P0v3 adds zone support and more headroom.')
param webSkuName string = 'B1'

var suffix = uniqueString(resourceGroup().id)
var storageName = take('${replace(namePrefix, '-', '')}st${suffix}', 24)
var deployContainer = 'app-package'
var roles = {
  storageBlobDataOwner: 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
  storageQueueDataContributor: '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
  storageTableDataContributor: '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
  monitoringMetricsPublisher: '3913510d-42f4-4e42-8a64-420c390055eb'
}

// ── observability ────────────────────────────────────────────────────────────────────────────
resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-logs-${suffix}'
  location: location
  properties: { sku: { name: 'PerGB2018' }, retentionInDays: 90 }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${namePrefix}-ai-${suffix}'
  location: location
  kind: 'web'
  properties: { Application_Type: 'web', WorkspaceResourceId: logs.id, DisableLocalAuth: true }
}

// ── identities ───────────────────────────────────────────────────────────────────────────────
resource idApi 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id-api'
  location: location
}

// ── host storage (identity only, no shared keys) ─────────────────────────────────────────────
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowSharedKeyAccess: false
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    defaultToOAuthAuthentication: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource packageContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: deployContainer
}

resource storageRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for r in [roles.storageBlobDataOwner, roles.storageQueueDataContributor, roles.storageTableDataContributor]: {
    name: guid(storage.id, idApi.id, r)
    scope: storage
    properties: {
      principalId: idApi.properties.principalId
      principalType: 'ServicePrincipal'
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', r)
    }
  }
]

resource aiRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appInsights.id, idApi.id, roles.monitoringMetricsPublisher)
  scope: appInsights
  properties: {
    principalId: idApi.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.monitoringMetricsPublisher)
  }
}

// ── PostgreSQL (Entra auth only) ─────────────────────────────────────────────────────────────
resource pg 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' = {
  name: '${namePrefix}-pg-${suffix}'
  location: location
  sku: { name: 'Standard_B1ms', tier: 'Burstable' }
  properties: {
    version: '16'
    storage: { storageSizeGB: 32 }
    authConfig: { activeDirectoryAuth: 'Enabled', passwordAuth: 'Disabled', tenantId: tenantId }
    backup: { backupRetentionDays: 14, geoRedundantBackup: 'Disabled' }
    highAvailability: { mode: 'Disabled' }
  }
}

resource pgDb 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: pg
  name: 'blueboard'
}

// Flex Consumption egress isn't a fixed IP without VNet integration. Production: VNet + private endpoint.
resource pgAllowAzure 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2024-08-01' = {
  parent: pg
  name: 'AllowAzureServices'
  properties: { startIpAddress: '0.0.0.0', endIpAddress: '0.0.0.0' }
}

module pgAdmin 'pg-admin.bicep' = {
  name: 'pg-admin'
  params: {
    serverName: pg.name
    principalId: idApi.properties.principalId
    principalName: idApi.name
    tenantId: tenantId
  }
  dependsOn: [pgDb]
}

// ── Function App (Flex Consumption, .NET 10 isolated) ────────────────────────────────────────
resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: '${namePrefix}-plan'
  location: location
  kind: 'functionapp'
  sku: { name: 'FC1', tier: 'FlexConsumption' }
  properties: { reserved: true }
}

resource api 'Microsoft.Web/sites@2024-04-01' = {
  name: '${namePrefix}-api-${suffix}'
  location: location
  kind: 'functionapp,linux'
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${idApi.id}': {} } }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      http20Enabled: true
      // The browser calls the API cross-origin with a bearer token (no cookies), so only the web origin is allowed.
      cors: { allowedOrigins: ['https://${web.properties.defaultHostName}'], supportCredentials: false }
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}${deployContainer}'
          authentication: { type: 'UserAssignedIdentity', userAssignedIdentityResourceId: idApi.id }
        }
      }
      scaleAndConcurrency: { maximumInstanceCount: maximumInstanceCount, instanceMemoryMB: 2048 }
      runtime: { name: 'dotnet-isolated', version: '10.0' }
    }
  }
  dependsOn: [storageRoles, packageContainer]
}

resource apiSettings 'Microsoft.Web/sites/config@2024-04-01' = {
  parent: api
  name: 'appsettings'
  properties: {
    AzureWebJobsStorage__accountName: storage.name
    AzureWebJobsStorage__credential: 'managedidentity'
    AzureWebJobsStorage__clientId: idApi.properties.clientId
    APPLICATIONINSIGHTS_CONNECTION_STRING: appInsights.properties.ConnectionString
    APPLICATIONINSIGHTS_AUTHENTICATION_STRING: 'ClientId=${idApi.properties.clientId};Authorization=AAD'
    AZURE_CLIENT_ID: idApi.properties.clientId
    PGHOST: pg.properties.fullyQualifiedDomainName
    PGDATABASE: 'blueboard'
    PGUSER: idApi.name
    PG_ENTRA_AUTH: 'true'
    AZURE_TENANT_ID: tenantId
    BOARD_API_AUDIENCE: boardApiAudience
    BOARD_API_CLIENT_ID: boardApiClientId
    INGEST_ENABLED: string(ingestEnabled)
    BROKER_EXECUTE: string(brokerExecute)
    BLUEBOARD_POLICY_JSON: policyJson
  }
}

// Publishing with FTP or basic auth is off: deployments use Entra (az functionapp deploy / az webapp deploy).
resource apiFtp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: api
  name: 'ftp'
  properties: { allow: false }
}

resource apiScm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: api
  name: 'scm'
  properties: { allow: false }
}

// ── Web App (React, served by web/host) ──────────────────────────────────────────────────────
resource webPlan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: '${namePrefix}-web-plan'
  location: location
  kind: 'linux'
  sku: { name: webSkuName }
  properties: { reserved: true }
}

resource web 'Microsoft.Web/sites@2024-04-01' = {
  name: '${namePrefix}-web-${suffix}'
  location: location
  kind: 'app,linux'
  properties: {
    serverFarmId: webPlan.id
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    clientAffinityEnabled: false
    siteConfig: {
      linuxFxVersion: 'DOTNETCORE|10.0'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      http20Enabled: true
      alwaysOn: true
      healthCheckPath: '/healthz'
    }
  }
}

resource webSettings 'Microsoft.Web/sites/config@2024-04-01' = {
  parent: web
  name: 'appsettings'
  properties: {
    // Public values only: the SPA reads them from /config.json to sign in and find the API.
    BLUEBOARD_TENANT_ID: tenantId
    BLUEBOARD_CLIENT_ID: boardApiClientId
    BLUEBOARD_API_URL: 'https://${api.properties.defaultHostName}'
    BLUEBOARD_API_SCOPE: '${boardApiAudience}/Board.Access'
    BLUEBOARD_AUTHORITY_HOST: environment().authentication.loginEndpoint
  }
}

resource webFtp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: web
  name: 'ftp'
  properties: { allow: false }
}

resource webScm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: web
  name: 'scm'
  properties: { allow: false }
}

output webHostname string = web.properties.defaultHostName
output webName string = web.name
output apiName string = api.name
output apiHostname string = api.properties.defaultHostName
output apiIdentityPrincipalId string = idApi.properties.principalId
output pgServerName string = pg.name

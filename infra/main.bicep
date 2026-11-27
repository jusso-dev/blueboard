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
// Profiles (param profile):
//   mvp         the default. Public endpoints with Entra auth everywhere, Burstable PostgreSQL. Output unchanged.
//   production  VNet + Function App VNet integration, private endpoints for PostgreSQL, storage and Key Vault (no
//               public PostgreSQL endpoint, no AllowAzureServices rule), policy.json and notification secrets in Key
//               Vault (RBAC mode) as Key Vault references, PostgreSQL General Purpose with HA (zone-redundant in
//               Australia East, same-zone in Australia Southeast, which has no availability zones), one
//               always-ready http instance, P0v3 for the web app, and audit_log shipped to the BlueboardAudit_CL
//               table through a Data Collection Endpoint and Rule (see docs/OPERATIONS.md).
//
// Identities (no stored secrets anywhere):
//   id-api   Function App: Graph + Defender application permissions (infra/grant-permissions.sh),
//            PostgreSQL Entra admin (applies migrations at start-up), host storage data roles, Application Insights publisher.
//   id-db    Function App: the PostgreSQL role every request runs as (dbRuntimeRole, on by default). A member of
//            blueboard_app with no ownership: it can't change tables, and audit_log is append-only (db/migrations/009).

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
@description('App Service plan for the web front end. B1 is enough for a SOC; P0v3 adds zone support and more headroom. The production profile always uses P0v3.')
param webSkuName string = 'B1'
@description('mvp (default): public endpoints with Entra auth. production: private networking, Key Vault, high-availability PostgreSQL, audit export to Sentinel.')
@allowed(['mvp', 'production'])
param profile string = 'mvp'
@description('Public URL of the web app for deep links in notifications. Empty: the deployed web app\'s default host name.')
param webBaseUrl string = ''

// Approver notifications (docs/OPERATIONS.md). Secure: never in deployment history. In the production profile they are
// stored in Key Vault and the Function App reads them through Key Vault references.
@secure()
@description('Teams incoming webhook or Workflows URL. Empty: no Teams notifications.')
param notifyTeamsWebhookUrl string = ''
@secure()
@description('Generic HTTPS webhook URL. Empty: no webhook notifications.')
param notifyWebhookUrl string = ''
@secure()
@description('HMAC-SHA256 key for X-Blueboard-Signature (at least 32 characters). Required with notifyWebhookUrl.')
param notifyWebhookSecret string = ''
@description('Exact host names the Teams and webhook URLs may use, comma separated (https only).')
param notifyAllowedHosts string = ''
@description('Shared mailbox approver email is sent from (needs Mail.Send: NOTIFY_MAIL=1 ./infra/grant-permissions.sh). Empty: no email.')
param notifyMailFrom string = ''
@description('Approver addresses, comma separated.')
param notifyMailTo string = ''
param notifyRemindMinutes int = 15

// Agent webhooks (docs/AGENTS.md): off unless both are set. The signing key is a Key Vault reference in production.
@description('Exact host names agents may subscribe webhooks on, comma separated. Empty: webhooks off.')
param webhookAllowedHosts string = ''
@secure()
@description('Base64 of at least 32 random bytes; signs webhook deliveries (HMAC-SHA256). Empty: webhooks off.')
param webhookSigningKey string = ''
@description('More browser origins allowed to call the API, e.g. [\'https://board.example.com\'] for a custom domain. The web app\'s default host is always allowed.')
param extraCorsOrigins array = []

// Threat intel and CVE sources (docs/THREAT_INTEL.md, docs/ti/sources.md). All off by default.
@description('Outside feeds: pwn.watch, CISA KEV (scheduled); FIRST EPSS, NVD, OSV (on demand). Outbound https to each host only.')
param tiPwnwatchEnabled bool = false
param tiKevEnabled bool = false
param tiEpssEnabled bool = false
param tiNvdEnabled bool = false
param tiOsvEnabled bool = false
@description('Tenant intel through the board identity: Sentinel TI and Defender exposure use advanced hunting (ThreatHunting.Read.All, already granted).')
param tiSentinelEnabled bool = false
param tiExposureEnabled bool = false
@description('Microsoft Threat Intelligence (Graph). Grant ThreatIntelligence.Read.All first: TI_MSTI=1 ./infra/grant-permissions.sh.')
param tiMstiEnabled bool = false
@description('Optional NVD API key (raises the rate limit from 5 to 50 requests per 30 seconds). Not a Microsoft credential.')
@secure()
param nvdApiKey string = ''
@description('publish_ti_indicator: resource id of the Log Analytics workspace that has Microsoft Sentinel. Empty: the action dry-runs with no workspace and fails if executed.')
param sentinelWorkspaceResourceId string = ''
@description('publish_ti_indicator: assign Microsoft Sentinel Contributor on that workspace to the board identity. Needs Owner or User Access Administrator on the workspace.')
param assignSentinelContributor bool = false

@description('Data retention in days: 0 keeps everything (default); otherwise at least 30. A daily job removes resolved incidents, threads and finished actions older than this; audit_log is never removed (docs/assurance/DATA-FLOWS.md).')
param retentionDays int = 0
@description('Disable people and agents not seen for this many days: 0 is off (default); otherwise at least 30.')
param inactiveDisableDays int = 0
@description('Sign the browser out after this many idle minutes (0 off, max 480). Browser-only safeguard; does not revoke access tokens.')
@minValue(0)
@maxValue(480)
param sessionIdleMinutes int = 15

@description('Serve requests as a separate, least-privilege PostgreSQL role (id-db) instead of the Entra admin. Migrations still run as the admin (id-api).')
param dbRuntimeRole bool = true
@description('PostgreSQL automated backup retention in days (7 to 35).')
@minValue(7)
@maxValue(35)
param pgBackupRetentionDays int = profile == 'production' ? 35 : 14
@description('Geo-redundant PostgreSQL backups (to the paired Australian region). Fixed when the server is created: on an existing server keep the value it was created with, or the deployment fails.')
param pgGeoRedundantBackup bool = profile == 'production'
@description('Email addresses that receive operational alerts (Function errors, stalled ingest, audit export, database health). Empty: alert rules are created with no recipients.')
param alertEmails array = []
@description('Create the operational alert rules and action group (infra/alerts.bicep).')
param alertsEnabled bool = true

@description('Put Azure Front Door Premium with a WAF in front of the web app and the API, and accept traffic only from it (infra/front-door.bicep). Browsers and agents then use the Front Door host names.')
param frontDoor bool = false
@description('Front Door WAF mode: Prevention blocks, Detection only logs (use while tuning).')
@allowed(['Prevention', 'Detection'])
param wafMode string = 'Prevention'
@description('Inspect API request bodies with the WAF managed rules. Off by default: SOC content (command lines, KQL, URLs) looks like attacks.')
param apiWafBodyCheck bool = false
@description('Two-letter country codes allowed through Front Door; empty allows all.')
param allowedCountries array = []
@description('With Front Door: CIDR ranges allowed to the sites\' deployment (scm/Kudu) endpoints, for az functionapp/webapp deploy. Empty keeps scm open to the internet (Entra-authenticated only).')
param deployerIpRanges array = []

@description('Minimum TLS version for the web app, the Function App (and their scm endpoints) and PostgreSQL. 1.3 in production by default.')
@allowed(['1.2', '1.3'])
param tlsMinVersion string = profile == 'production' ? '1.3' : '1.2'
@description('pgaudit statement classes logged to the PostgreSQL server log (pgaudit.log), e.g. ddl,role,misc_set. Empty: pgaudit off.')
param pgAuditLog string = 'ddl,role,misc_set'

var isProd = profile == 'production'
// Australia East has availability zones; Australia Southeast doesn't, so HA there is same-zone.
var hasZones = location == 'australiaeast'
var suffix = uniqueString(resourceGroup().id)
var storageName = take('${replace(namePrefix, '-', '')}st${suffix}', 24)
var deployContainer = 'app-package'
var roles = {
  storageBlobDataOwner: 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
  storageQueueDataContributor: '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
  storageTableDataContributor: '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
  monitoringMetricsPublisher: '3913510d-42f4-4e42-8a64-420c390055eb'
  keyVaultSecretsUser: '4633458b-17de-408a-b874-0445c86b69e6'
  sentinelContributor: 'ab8e14d6-4a74-4f29-9ba8-549422addade'
}
// /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}; a placeholder when unset (never deployed).
var sentinelWorkspaceParts = split(empty(sentinelWorkspaceResourceId) ? '/subscriptions/none/resourceGroups/none/providers/x/workspaces/none' : sentinelWorkspaceResourceId, '/')

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

// The PostgreSQL role requests run as (dbRuntimeRole). It holds no Azure or Microsoft permissions at all.
resource idDb 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (dbRuntimeRole) {
  name: '${namePrefix}-id-db'
  location: location
}

// ── host storage (identity only, no shared keys) ─────────────────────────────────────────────
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: union({
    allowSharedKeyAccess: false
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    defaultToOAuthAuthentication: true
  }, isProd ? { publicNetworkAccess: 'Disabled', networkAcls: { defaultAction: 'Deny', bypass: 'None' } } : {})
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
  sku: isProd ? { name: 'Standard_D2ds_v5', tier: 'GeneralPurpose' } : { name: 'Standard_B1ms', tier: 'Burstable' }
  properties: union({
    version: '16'
    authConfig: { activeDirectoryAuth: 'Enabled', passwordAuth: 'Disabled', tenantId: tenantId }
    storage: { storageSizeGB: 32, autoGrow: 'Enabled' }
    backup: { backupRetentionDays: pgBackupRetentionDays, geoRedundantBackup: pgGeoRedundantBackup ? 'Enabled' : 'Disabled' }
    highAvailability: isProd ? { mode: hasZones ? 'ZoneRedundant' : 'SameZone' } : { mode: 'Disabled' }
  }, isProd ? { network: { publicNetworkAccess: 'Disabled' } } : {})
}

resource pgDb 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2024-08-01' = {
  parent: pg
  name: 'blueboard'
}

// Flex Consumption egress isn't a fixed IP without VNet integration. The production profile uses a private endpoint instead.
resource pgAllowAzure 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2024-08-01' = if (!isProd) {
  parent: pg
  name: 'AllowAzureServices'
  properties: { startIpAddress: '0.0.0.0', endIpAddress: '0.0.0.0' }
}

// TLS and audit logging on the server. pgaudit must be preloaded (shared_preload_libraries), which takes effect only
// after a server restart; the configuration resources below set it, but Azure doesn't restart for you (see
// docs/DEPLOYMENT.md § Network and TLS hardening). Applied one at a time: concurrent configuration updates conflict.
var pgConfig = [
  { name: 'require_secure_transport', value: 'ON' }
  { name: 'ssl_min_protocol_version', value: tlsMinVersion == '1.3' ? 'TLSv1.3' : 'TLSv1.2' }
  { name: 'log_connections', value: 'ON' }
  { name: 'log_disconnections', value: 'ON' }
  { name: 'azure.extensions', value: 'PGAUDIT,PGCRYPTO' }
  { name: 'shared_preload_libraries', value: 'pgaudit' }
  // Explicit none clears an earlier deployment's audit classes. Omitting the resource would leave them active.
  { name: 'pgaudit.log', value: empty(pgAuditLog) ? 'none' : pgAuditLog }
]

@batchSize(1)
resource pgSettings 'Microsoft.DBforPostgreSQL/flexibleServers/configurations@2024-08-01' = [for c in pgConfig: {
  parent: pg
  name: c.name
  properties: { value: c.value, source: 'user-override' }
  dependsOn: [pgDb]
}]

// Server logs (connections, errors, pgaudit) and session data to the board's Log Analytics workspace.
resource pgDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: pg
  name: 'to-log-analytics'
  properties: {
    workspaceId: logs.id
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

module pgAdmin 'pg-admin.bicep' = {
  name: 'pg-admin'
  params: {
    serverName: pg.name
    principalId: idApi.properties.principalId
    principalName: idApi.name
    tenantId: tenantId
  }
  dependsOn: [pgDb, pgSettings]
}

// ── Function App (Flex Consumption, .NET 10 isolated) ────────────────────────────────────────
resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: '${namePrefix}-plan'
  location: location
  kind: 'functionapp'
  sku: { name: 'FC1', tier: 'FlexConsumption' }
  properties: { reserved: true }
}

// ── optional edge: Front Door Premium + WAF ──────────────────────────────────────────────────
module edge 'front-door.bicep' = if (frontDoor) {
  name: 'front-door'
  params: {
    namePrefix: namePrefix
    suffix: suffix
    logsWorkspaceId: logs.id
    wafMode: wafMode
    apiWafBodyCheck: apiWafBodyCheck
    allowedCountries: allowedCountries
  }
}

// With Front Door, each site accepts only Front Door's backend addresses carrying this profile's id (X-Azure-FDID),
// so the WAF can't be bypassed through the azurewebsites.net host. The deployment (scm) endpoint keeps its own,
// Entra-authenticated access so az functionapp/webapp deploy still work.
var deployerScmRules = [for (cidr, i) in deployerIpRanges: { name: 'Deployer${i}', priority: 100 + i, action: 'Allow', ipAddress: cidr }]
var edgeOnly = frontDoor ? {
  ipSecurityRestrictionsDefaultAction: 'Deny'
  ipSecurityRestrictions: [
    { name: 'FrontDoorOnly', priority: 100, action: 'Allow', tag: 'ServiceTag', ipAddress: 'AzureFrontDoor.Backend', headers: { 'x-azure-fdid': [edge!.outputs.frontDoorId] } }
  ]
  scmIpSecurityRestrictionsUseMain: false
  // With deployerIpRanges, the deployment endpoint accepts only those ranges; az functionapp/webapp deploy go through
  // it, so the deploying machine must be inside them. Without, scm stays reachable (still Entra-authenticated).
  scmIpSecurityRestrictionsDefaultAction: empty(deployerIpRanges) ? 'Allow' : 'Deny'
  scmIpSecurityRestrictions: deployerScmRules
} : {}

resource api 'Microsoft.Web/sites@2024-04-01' = {
  name: '${namePrefix}-api-${suffix}'
  location: location
  kind: 'functionapp,linux'
  identity: { type: 'UserAssigned', userAssignedIdentities: dbRuntimeRole ? { '${idApi.id}': {}, '${idDb.id}': {} } : { '${idApi.id}': {} } }
  properties: union({
    serverFarmId: plan.id
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    siteConfig: union({
      minTlsVersion: tlsMinVersion
      scmMinTlsVersion: tlsMinVersion
      ftpsState: 'Disabled'
      http20Enabled: true
      // The browser calls the API cross-origin with a bearer token (no cookies), so only the web origin is allowed.
      cors: { allowedOrigins: union(['https://${web.properties.defaultHostName}'], frontDoor ? ['https://${edge!.outputs.webHostname}'] : [], extraCorsOrigins), supportCredentials: false }
    }, isProd ? { vnetRouteAllEnabled: true } : {}, edgeOnly)
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}${deployContainer}'
          authentication: { type: 'UserAssignedIdentity', userAssignedIdentityResourceId: idApi.id }
        }
      }
      scaleAndConcurrency: union({ maximumInstanceCount: maximumInstanceCount, instanceMemoryMB: 2048 },
        isProd ? { alwaysReady: [{ name: 'http', instanceCount: 1 }] } : {})
      runtime: { name: 'dotnet-isolated', version: '10.0' }
    }
  }, isProd ? { keyVaultReferenceIdentity: idApi.id, virtualNetworkSubnetId: network!.outputs.functionsSubnetId } : {})
  dependsOn: [storageRoles, packageContainer, storagePrivate]
}

// Notification settings: plain app settings in mvp (secure params, never logged), Key Vault references in production.
var notifySecretSettings = isProd
  ? {
      NOTIFY_TEAMS_WEBHOOK_URL: empty(notifyTeamsWebhookUrl) ? '' : '@Microsoft.KeyVault(VaultName=${vaultName};SecretName=notify-teams-webhook-url)'
      NOTIFY_WEBHOOK_URL: empty(notifyWebhookUrl) ? '' : '@Microsoft.KeyVault(VaultName=${vaultName};SecretName=notify-webhook-url)'
      NOTIFY_WEBHOOK_SECRET: empty(notifyWebhookSecret) ? '' : '@Microsoft.KeyVault(VaultName=${vaultName};SecretName=notify-webhook-secret)'
    }
  : {
      NOTIFY_TEAMS_WEBHOOK_URL: notifyTeamsWebhookUrl
      NOTIFY_WEBHOOK_URL: notifyWebhookUrl
      NOTIFY_WEBHOOK_SECRET: notifyWebhookSecret
    }
// Threat intel (docs/THREAT_INTEL.md). The NVD key is not a Microsoft credential, but it is still kept out of
// deployment history (secure param) and, in production, in Key Vault.
var tiSettings = {
  TI_PWNWATCH_ENABLED: string(tiPwnwatchEnabled)
  TI_KEV_ENABLED: string(tiKevEnabled)
  TI_EPSS_ENABLED: string(tiEpssEnabled)
  TI_NVD_ENABLED: string(tiNvdEnabled)
  TI_OSV_ENABLED: string(tiOsvEnabled)
  TI_SENTINEL_ENABLED: string(tiSentinelEnabled)
  TI_EXPOSURE_ENABLED: string(tiExposureEnabled)
  TI_MSTI_ENABLED: string(tiMstiEnabled)
  NVD_API_KEY: isProd && !empty(nvdApiKey) ? '@Microsoft.KeyVault(VaultName=${vaultName};SecretName=nvd-api-key)' : nvdApiKey
  SENTINEL_WORKSPACE_ID: empty(sentinelWorkspaceResourceId) ? '' : sentinelWorkspace!.properties.customerId
  SENTINEL_WORKSPACE_RESOURCE_ID: sentinelWorkspaceResourceId
}
var notifySettings = union(notifySecretSettings, {
  NOTIFY_ALLOWED_HOSTS: notifyAllowedHosts
  NOTIFY_MAIL_FROM: notifyMailFrom
  NOTIFY_MAIL_TO: notifyMailTo
  NOTIFY_REMIND_MINUTES: string(notifyRemindMinutes)
  BOARD_WEB_URL: empty(webBaseUrl) ? 'https://${publicWebHost}' : webBaseUrl
  WEBHOOK_ALLOWED_HOSTS: webhookAllowedHosts
  WEBHOOK_SIGNING_KEY: isProd && !empty(webhookSigningKey) ? '@Microsoft.KeyVault(VaultName=${vaultName};SecretName=webhook-signing-key)' : webhookSigningKey
})
// Requests run as id-db (a member of blueboard_app); migrations run as id-api, the Entra admin, which creates the
// id-db role from its object id on first start (db/migrations/009, Data/Migrator.cs).
var dbSettings = dbRuntimeRole
  ? {
      PGUSER: idDb!.name
      PG_CLIENT_ID: idDb!.properties.clientId
      PG_RUNTIME_PRINCIPAL_ID: idDb!.properties.principalId
      PG_MIGRATE_USER: idApi.name
    }
  : { PGUSER: idApi.name }
var productionSettings = isProd
  ? {
      // Read through a Key Vault reference with the Function App's identity (keyVaultReferenceIdentity below).
      BLUEBOARD_POLICY_JSON: '@Microsoft.KeyVault(VaultName=${vaultName};SecretName=policy-json)'
      AUDIT_DCE_ENDPOINT: auditExport!.outputs.ingestionEndpoint
      AUDIT_DCR_ID: auditExport!.outputs.dcrImmutableId
      AUDIT_STREAM: 'Custom-BlueboardAudit_CL'
    }
  : {
      BLUEBOARD_POLICY_JSON: policyJson
    }

resource apiSettings 'Microsoft.Web/sites/config@2024-04-01' = {
  parent: api
  name: 'appsettings'
  properties: union({
    AzureWebJobsStorage__accountName: storage.name
    AzureWebJobsStorage__credential: 'managedidentity'
    AzureWebJobsStorage__clientId: idApi.properties.clientId
    APPLICATIONINSIGHTS_CONNECTION_STRING: appInsights.properties.ConnectionString
    APPLICATIONINSIGHTS_AUTHENTICATION_STRING: 'ClientId=${idApi.properties.clientId};Authorization=AAD'
    AZURE_CLIENT_ID: idApi.properties.clientId
    PGHOST: pg.properties.fullyQualifiedDomainName
    PGDATABASE: 'blueboard'
    PG_ENTRA_AUTH: 'true'
    AZURE_TENANT_ID: tenantId
    BOARD_API_AUDIENCE: boardApiAudience
    BOARD_API_CLIENT_ID: boardApiClientId
    INGEST_ENABLED: string(ingestEnabled)
    BROKER_EXECUTE: string(brokerExecute)
    RETENTION_DAYS: string(retentionDays)
    INACTIVE_DISABLE_DAYS: string(inactiveDisableDays)
    SESSION_IDLE_MINUTES: string(sessionIdleMinutes)
    // Read-only facts for Admin → Posture (what this deployment enforces); not used for any decision.
    BOARD_PROFILE: profile
    BOARD_EDGE: frontDoor ? 'front_door_waf' : 'none'
    BOARD_WAF_MODE: frontDoor ? wafMode : 'none'
  }, dbSettings, productionSettings, notifySettings, tiSettings)
  dependsOn: isProd ? [kvSecretsRole, kvPolicySecret] : []
}

// publish_ti_indicator (optional): the upload API needs Microsoft Sentinel Contributor on the workspace.
// The workspace may live in another resource group, so the assignment is a module scoped there.
resource sentinelWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = if (!empty(sentinelWorkspaceResourceId)) {
  name: last(sentinelWorkspaceParts)
  scope: resourceGroup(sentinelWorkspaceParts[2], sentinelWorkspaceParts[4])
}

module sentinelRole 'sentinel-role.bicep' = if (assignSentinelContributor && !empty(sentinelWorkspaceResourceId)) {
  name: 'blueboard-sentinel-contributor'
  scope: resourceGroup(sentinelWorkspaceParts[2], sentinelWorkspaceParts[4])
  params: {
    workspaceName: last(sentinelWorkspaceParts)
    principalId: idApi.properties.principalId
    roleDefinitionId: roles.sentinelContributor
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
  sku: { name: isProd ? 'P0v3' : webSkuName }
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
    siteConfig: union({
      linuxFxVersion: 'DOTNETCORE|10.0'
      minTlsVersion: tlsMinVersion
      scmMinTlsVersion: tlsMinVersion
      ftpsState: 'Disabled'
      http20Enabled: true
      alwaysOn: true
      healthCheckPath: '/healthz'
    }, edgeOnly)
  }
}

resource webSettings 'Microsoft.Web/sites/config@2024-04-01' = {
  parent: web
  name: 'appsettings'
  properties: {
    // Public values only: the SPA reads them from /config.json to sign in and find the API.
    BLUEBOARD_TENANT_ID: tenantId
    BLUEBOARD_CLIENT_ID: boardApiClientId
    BLUEBOARD_API_URL: 'https://${publicApiHost}'
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

// ── production profile ───────────────────────────────────────────────────────────────────────
var vaultName = take('${replace(namePrefix, '-', '')}kv${suffix}', 24)

module network 'network.bicep' = if (isProd) {
  name: 'network'
  params: { location: location, namePrefix: namePrefix, zoneRedundant: hasZones }
}

// Key Vault in RBAC mode, private only: policy.json, the notification secrets and the webhook signing key.
// The name is fixed per resource group and purge protection is on, so after a teardown the deleted vault keeps the
// name for 90 days: redeploy the production profile into a new resource group name (infra/teardown.sh says so).
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = if (isProd) {
  name: vaultName
  location: location
  properties: {
    tenantId: tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    publicNetworkAccess: 'Disabled'
    networkAcls: { defaultAction: 'Deny', bypass: 'None' }
  }
}

resource kvPolicySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (isProd) {
  parent: kv
  name: 'policy-json'
  properties: { value: policyJson, contentType: 'application/json' }
}

resource kvTeamsSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (isProd && !empty(notifyTeamsWebhookUrl)) {
  parent: kv
  name: 'notify-teams-webhook-url'
  properties: { value: notifyTeamsWebhookUrl }
}

resource kvWebhookSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (isProd && !empty(notifyWebhookUrl)) {
  parent: kv
  name: 'notify-webhook-url'
  properties: { value: notifyWebhookUrl }
}

resource kvWebhookHmac 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (isProd && !empty(notifyWebhookSecret)) {
  parent: kv
  name: 'notify-webhook-secret'
  properties: { value: notifyWebhookSecret }
}

resource kvNvdSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (isProd && !empty(nvdApiKey)) {
  parent: kv
  name: 'nvd-api-key'
  properties: { value: nvdApiKey }
}

resource kvSigningKeySecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (isProd && !empty(webhookSigningKey)) {
  parent: kv
  name: 'webhook-signing-key'
  properties: { value: webhookSigningKey }
}

resource kvSecretsRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (isProd) {
  name: guid(resourceGroup().id, vaultName, idApi.id, roles.keyVaultSecretsUser)
  scope: kv
  properties: {
    principalId: idApi.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.keyVaultSecretsUser)
  }
}

// Private endpoints: PostgreSQL, storage (blob, queue, table) and Key Vault, each with its private DNS zone.
module pgPrivate 'private-endpoint.bicep' = if (isProd) {
  name: 'pe-pg'
  params: {
    location: location
    name: '${namePrefix}-pe-pg'
    subnetId: network!.outputs.endpointsSubnetId
    targetId: pg.id
    groupId: 'postgresqlServer'
    dnsZoneId: network!.outputs.dnsZoneIds.postgres
  }
}

module storagePrivate 'private-endpoint.bicep' = [
  for g in (isProd ? ['blob', 'queue', 'table'] : []): {
    name: 'pe-st-${g}'
    params: {
      location: location
      name: '${namePrefix}-pe-st-${g}'
      subnetId: network!.outputs.endpointsSubnetId
      targetId: storage.id
      groupId: g
      dnsZoneId: network!.outputs.dnsZoneIds[g]
    }
  }
]

module kvPrivate 'private-endpoint.bicep' = if (isProd) {
  name: 'pe-kv'
  params: {
    location: location
    name: '${namePrefix}-pe-kv'
    subnetId: network!.outputs.endpointsSubnetId
    targetId: kv.id
    groupId: 'vault'
    dnsZoneId: network!.outputs.dnsZoneIds.vault
  }
}

// Audit export: custom table, Data Collection Endpoint + Rule, and Monitoring Metrics Publisher on the rule.
module auditExport 'audit-export.bicep' = if (isProd) {
  name: 'audit-export'
  params: {
    location: location
    namePrefix: namePrefix
    workspaceName: logs.name
    principalId: idApi.properties.principalId
  }
}

// The host names people and agents use: Front Door's when it's on (the sites themselves then refuse direct traffic).
var publicWebHost = frontDoor ? edge!.outputs.webHostname : web.properties.defaultHostName
var publicApiHost = frontDoor ? edge!.outputs.apiHostname : api.properties.defaultHostName

module edgeOrigins 'front-door-origins.bicep' = if (frontDoor) {
  name: 'front-door-origins'
  params: {
    profileName: edge!.outputs.profileName
    webEndpointName: edge!.outputs.webEndpointName
    apiEndpointName: edge!.outputs.apiEndpointName
    webOriginHost: web.properties.defaultHostName
    apiOriginHost: api.properties.defaultHostName
  }
}

output webHostname string = publicWebHost
output webName string = web.name
output apiName string = api.name
output apiHostname string = publicApiHost
output frontDoorEnabled bool = frontDoor
output apiIdentityPrincipalId string = idApi.properties.principalId
output pgServerName string = pg.name
@description('True in the mvp profile: PostgreSQL has a public endpoint (Entra auth only, firewall AllowAzureServices). Use production for real data.')
output pgPublic bool = !isProd
output tlsMinVersion string = tlsMinVersion
output dbIdentityName string = dbRuntimeRole ? idDb!.name : idApi.name

// ── operational alerts ───────────────────────────────────────────────────────────────────────
module alerts 'alerts.bicep' = if (alertsEnabled) {
  name: 'alerts'
  params: {
    location: location
    namePrefix: namePrefix
    appInsightsId: appInsights.id
    logsWorkspaceId: logs.id
    pgServerId: pg.id
    webSiteId: web.id
    emails: alertEmails
    auditExportEnabled: isProd
  }
}

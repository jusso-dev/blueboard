// blueboard on Azure Container Apps.
//
//   board         Next.js (UI, REST, SSE, MCP, ingest poller, action broker). Easy Auth (Entra) for humans;
//                 /api/mcp and /.well-known are excluded so agents authenticate with bearer tokens.
//   migrate       Container Apps job that applies db/migrations.
//   enrichment    Reference Claude agent. Talks only to the board's MCP endpoint and to Foundry.
//
// Identities (no secrets for Microsoft APIs):
//   id-board      Graph + Defender application permissions, Postgres Entra admin. Granted by infra/grant-permissions.sh.
//   id-agent      Board.Post / Board.Hunt / Board.RequestActions app roles on the board API, and
//                 "Cognitive Services User" on the Foundry resource. Nothing in Defender/Entra.

targetScope = 'resourceGroup'

param location string = resourceGroup().location
param namePrefix string = 'blueboard'
@description('Container image for the board (Dockerfile target "board").')
param boardImage string
@description('Container image for the migrate job and agent (Dockerfile target "tools").')
param toolsImage string
@description('Entra tenant id.')
param tenantId string = tenant().tenantId
@description('Application (client) id of the board API app registration (audience for agent tokens and Easy Auth).')
param boardApiClientId string
@description('App ID URI of the board API, e.g. api://blueboard.')
param boardApiAudience string
@description('Foundry resource name hosting the Claude deployments.')
param foundryResource string
@description('Resource id of the Foundry (AI Services) account in this resource group, for the agent role assignment. Empty to skip (assign Cognitive Services User yourself).')
param foundryAccountId string = ''
param claudeModel string = 'claude-opus-5-5'
param claudeFallbackModel string = 'claude-opus-4-8'
@description('Leave false until policy.json is reviewed: approved actions are recorded as dry runs.')
param brokerExecute bool = false
param ingestEnabled bool = true

var suffix = uniqueString(resourceGroup().id)

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-logs-${suffix}'
  location: location
  properties: { sku: { name: 'PerGB2018' }, retentionInDays: 90 }
}

resource idBoard 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id-board'
  location: location
}

resource idAgent 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id-agent'
  location: location
}

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

// Container Apps reach Postgres over the Azure backbone. For production, prefer VNet integration + private endpoint.
resource pgAllowAzure 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2024-08-01' = {
  parent: pg
  name: 'AllowAzureServices'
  properties: { startIpAddress: '0.0.0.0', endIpAddress: '0.0.0.0' }
}

// The administrator resource name must be known at deployment start, so the board identity's
// principal id is deployed through a module (its params are evaluated after the identity exists).
module pgAdmin 'pg-admin.bicep' = {
  name: 'pg-admin'
  params: {
    serverName: pg.name
    principalId: idBoard.properties.principalId
    principalName: idBoard.name
    tenantId: tenantId
  }
  dependsOn: [pgDb]
}

resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${namePrefix}-env'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: { customerId: logs.properties.customerId, sharedKey: logs.listKeys().primarySharedKey }
    }
  }
}

var dbEnv = [
  { name: 'PGHOST', value: pg.properties.fullyQualifiedDomainName }
  { name: 'PGDATABASE', value: 'blueboard' }
  { name: 'PGUSER', value: idBoard.name }
  { name: 'PG_ENTRA_AUTH', value: 'true' }
  { name: 'AZURE_CLIENT_ID', value: idBoard.properties.clientId }
]

resource board 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${namePrefix}-board'
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${idBoard.id}': {} } }
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      ingress: { external: true, targetPort: 3000, transport: 'auto', allowInsecure: false }
    }
    template: {
      containers: [
        {
          name: 'board'
          image: boardImage
          resources: { cpu: json('1.0'), memory: '2Gi' }
          env: concat(dbEnv, [
            { name: 'AZURE_TENANT_ID', value: tenantId }
            { name: 'BOARD_API_AUDIENCE', value: boardApiAudience }
            { name: 'EASY_AUTH', value: 'true' }
            { name: 'INGEST_ENABLED', value: string(ingestEnabled) }
            { name: 'BROKER_EXECUTE', value: string(brokerExecute) }
          ])
          probes: [
            { type: 'Liveness', httpGet: { path: '/api/healthz', port: 3000 }, periodSeconds: 30 }
          ]
        }
      ]
      // SSE and the ingest poller are fine across replicas (Postgres NOTIFY fan-out + advisory lock).
      scale: { minReplicas: 1, maxReplicas: 3 }
    }
  }
}

resource boardAuth 'Microsoft.App/containerApps/authConfigs@2024-03-01' = {
  parent: board
  name: 'current'
  properties: {
    platform: { enabled: true }
    globalValidation: {
      unauthenticatedClientAction: 'RedirectToLoginPage'
      redirectToProvider: 'azureactivedirectory'
      // Agents use bearer tokens validated by the app itself.
      excludedPaths: ['/api/mcp', '/.well-known/oauth-protected-resource', '/api/healthz']
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          clientId: boardApiClientId
          openIdIssuer: '${environment().authentication.loginEndpoint}${tenantId}/v2.0'
        }
        validation: { allowedAudiences: [boardApiAudience, boardApiClientId] }
      }
    }
    login: { tokenStore: { enabled: false } }
  }
}

resource migrate 'Microsoft.App/jobs@2024-03-01' = {
  name: '${namePrefix}-migrate'
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${idBoard.id}': {} } }
  properties: {
    environmentId: env.id
    configuration: { triggerType: 'Manual', replicaTimeout: 600, replicaRetryLimit: 1, manualTriggerConfig: { parallelism: 1, replicaCompletionCount: 1 } }
    template: {
      containers: [
        {
          name: 'migrate'
          image: toolsImage
          command: ['npx', 'tsx', 'scripts/migrate.ts']
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: dbEnv
        }
      ]
    }
  }
}

resource enrichment 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${namePrefix}-agent-enrichment'
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${idAgent.id}': {} } }
  properties: {
    managedEnvironmentId: env.id
    configuration: {}
    template: {
      containers: [
        {
          name: 'agent'
          image: toolsImage
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: [
            { name: 'AZURE_CLIENT_ID', value: idAgent.properties.clientId }
            { name: 'BOARD_URL', value: 'https://${board.properties.configuration.ingress.fqdn}' }
            { name: 'BOARD_API_AUDIENCE', value: boardApiAudience }
            { name: 'ANTHROPIC_FOUNDRY_RESOURCE', value: foundryResource }
            { name: 'CLAUDE_MODEL', value: claudeModel }
            { name: 'CLAUDE_FALLBACK_MODEL', value: claudeFallbackModel }
          ]
        }
      ]
      scale: { minReplicas: 1, maxReplicas: 1 }
    }
  }
}

// Cognitive Services User on the Foundry account for the agent identity.
resource foundry 'Microsoft.CognitiveServices/accounts@2024-10-01' existing = if (!empty(foundryAccountId)) {
  name: last(split(foundryAccountId, '/'))
}
resource agentFoundryRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(foundryAccountId)) {
  name: guid(foundryAccountId, idAgent.id, 'a97b65f3-24c7-4388-baec-2e87135dc908')
  scope: foundry
  properties: {
    principalId: idAgent.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'a97b65f3-24c7-4388-baec-2e87135dc908')
  }
}

output boardUrl string = 'https://${board.properties.configuration.ingress.fqdn}'
output boardIdentityPrincipalId string = idBoard.properties.principalId
output agentIdentityPrincipalId string = idAgent.properties.principalId

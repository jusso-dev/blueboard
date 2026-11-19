// Audit export to Microsoft Sentinel (production profile): the BlueboardAudit_CL custom table in the board's Log
// Analytics workspace, a Data Collection Endpoint and Rule for the Logs Ingestion API, and Monitoring Metrics
// Publisher on the rule for the Function App's identity (the only right it needs to send rows).
// Enable Microsoft Sentinel on this workspace (or point the rule at your Sentinel workspace) to run the analytics
// rules in infra/sentinel/.

param location string
param namePrefix string
param workspaceName string
param principalId string

var monitoringMetricsPublisher = '3913510d-42f4-4e42-8a64-420c390055eb'
var columns = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'AuditId', type: 'long' }
  { name: 'Event', type: 'string' }
  { name: 'Actor', type: 'string' }
  { name: 'ActorKind', type: 'string' }
  { name: 'Subject', type: 'string' }
  { name: 'Detail', type: 'dynamic' }
]

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource table 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'BlueboardAudit_CL'
  properties: {
    plan: 'Analytics'
    retentionInDays: 365
    schema: { name: 'BlueboardAudit_CL', columns: columns }
  }
}

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: '${namePrefix}-dce'
  location: location
  properties: { networkAcls: { publicNetworkAccess: 'Enabled' } }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: '${namePrefix}-dcr-audit'
  location: location
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: { 'Custom-BlueboardAudit_CL': { columns: columns } }
    destinations: { logAnalytics: [{ name: 'workspace', workspaceResourceId: workspace.id }] }
    dataFlows: [
      {
        streams: ['Custom-BlueboardAudit_CL']
        destinations: ['workspace']
        transformKql: 'source'
        outputStream: 'Custom-BlueboardAudit_CL'
      }
    ]
  }
  dependsOn: [table]
}

resource publisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, principalId, monitoringMetricsPublisher)
  scope: dcr
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisher)
  }
}

output ingestionEndpoint string = dce.properties.logsIngestion.endpoint
output dcrImmutableId string = dcr.properties.immutableId

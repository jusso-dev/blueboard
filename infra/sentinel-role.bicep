// Optional (publish_ti_indicator): Microsoft Sentinel Contributor for the board identity on one Sentinel workspace,
// so the broker can call the threat intelligence upload API. Deployed into the workspace's resource group.
targetScope = 'resourceGroup'

param workspaceName string
param principalId string
param roleDefinitionId string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource assignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(workspace.id, principalId, roleDefinitionId)
  scope: workspace
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleDefinitionId)
  }
}

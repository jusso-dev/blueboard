// Stage 1 of 2: things that must exist before images can be pushed and the apps deployed.
//   - Azure Container Registry (admin user disabled; pulls use managed identity)
//   - The two user-assigned managed identities, with AcrPull on the registry
// Deploy with infra/deploy.sh, or: az deployment group create -g <rg> -f infra/foundation.bicep

targetScope = 'resourceGroup'

param location string = resourceGroup().location
param namePrefix string = 'blueboard'

var suffix = uniqueString(resourceGroup().id)
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: take('${replace(namePrefix, '-', '')}acr${suffix}', 50)
  location: location
  sku: { name: 'Standard' }
  properties: {
    adminUserEnabled: false
  }
}

resource idBoard 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id-board'
  location: location
}

resource idAgent 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${namePrefix}-id-agent'
  location: location
}

resource boardPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, idBoard.id, acrPullRoleId)
  scope: acr
  properties: {
    principalId: idBoard.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
  }
}

resource agentPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, idAgent.id, acrPullRoleId)
  scope: acr
  properties: {
    principalId: idAgent.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
  }
}

output acrName string = acr.name
output acrLoginServer string = acr.properties.loginServer
output boardIdentityPrincipalId string = idBoard.properties.principalId
output agentIdentityPrincipalId string = idAgent.properties.principalId

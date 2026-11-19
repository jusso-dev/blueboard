param serverName string
param principalId string
param principalName string
param tenantId string

resource pg 'Microsoft.DBforPostgreSQL/flexibleServers@2024-08-01' existing = {
  name: serverName
}

resource admin 'Microsoft.DBforPostgreSQL/flexibleServers/administrators@2024-08-01' = {
  parent: pg
  name: principalId
  properties: { principalName: principalName, principalType: 'ServicePrincipal', tenantId: tenantId }
}

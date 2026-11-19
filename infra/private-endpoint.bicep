// One private endpoint and its private DNS zone group (production profile).
param location string
param name string
param subnetId string
param targetId string
@description('postgresqlServer, blob, queue, table or vault')
param groupId string
param dnsZoneId string

resource pe 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: name
  location: location
  properties: {
    subnet: { id: subnetId }
    privateLinkServiceConnections: [{ name: name, properties: { privateLinkServiceId: targetId, groupIds: [groupId] } }]
  }
}

resource dns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: pe
  name: 'default'
  properties: { privateDnsZoneConfigs: [{ name: groupId, properties: { privateDnsZoneId: dnsZoneId } }] }
}

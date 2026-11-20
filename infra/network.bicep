// Production profile networking: one VNet with a subnet for Function App VNet integration (Flex Consumption delegates
// it to Microsoft.App/environments) and one for private endpoints, plus the private DNS zones those endpoints need.
// Outbound traffic from the Function App (Graph, Defender, notifications, Azure Monitor) leaves through a NAT gateway,
// so it has one fixed public IP and doesn't depend on default outbound access.

param location string
param namePrefix string
param addressSpace string = '10.40.0.0/16'
param functionsPrefix string = '10.40.1.0/24'
param endpointsPrefix string = '10.40.2.0/24'
@description('Zone-redundant NAT public IP (regions with availability zones).')
param zoneRedundant bool = true

resource natIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${namePrefix}-nat-ip'
  location: location
  sku: { name: 'Standard' }
  zones: zoneRedundant ? ['1', '2', '3'] : null
  properties: { publicIPAllocationMethod: 'Static', publicIPAddressVersion: 'IPv4' }
}

resource nat 'Microsoft.Network/natGateways@2024-05-01' = {
  name: '${namePrefix}-nat'
  location: location
  sku: { name: 'Standard' }
  properties: { publicIpAddresses: [{ id: natIp.id }], idleTimeoutInMinutes: 10 }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${namePrefix}-vnet'
  location: location
  properties: {
    addressSpace: { addressPrefixes: [addressSpace] }
    subnets: [
      {
        name: 'functions'
        properties: {
          addressPrefix: functionsPrefix
          natGateway: { id: nat.id }
          defaultOutboundAccess: false
          delegations: [{ name: 'flex', properties: { serviceName: 'Microsoft.App/environments' } }]
        }
      }
      {
        name: 'endpoints'
        properties: {
          addressPrefix: endpointsPrefix
          defaultOutboundAccess: false
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

var zoneNames = {
  postgres: 'privatelink.postgres.database.azure.com'
  blob: 'privatelink.blob.${environment().suffixes.storage}'
  queue: 'privatelink.queue.${environment().suffixes.storage}'
  table: 'privatelink.table.${environment().suffixes.storage}'
  vault: 'privatelink.vaultcore.azure.net'
}

resource zones 'Microsoft.Network/privateDnsZones@2024-06-01' = [
  for z in items(zoneNames): {
    name: z.value
    location: 'global'
  }
]

resource links 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [
  for (z, i) in items(zoneNames): {
    parent: zones[i]
    name: '${namePrefix}-link'
    location: 'global'
    properties: { registrationEnabled: false, virtualNetwork: { id: vnet.id } }
  }
]

output vnetId string = vnet.id
output functionsSubnetId string = vnet.properties.subnets[0].id
output endpointsSubnetId string = vnet.properties.subnets[1].id
output natPublicIp string = natIp.properties.ipAddress
output dnsZoneIds object = {
  postgres: zones[0].id
  blob: zones[1].id
  queue: zones[2].id
  table: zones[3].id
  vault: zones[4].id
}

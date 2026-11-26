// Origins and routes for the Front Door profile from front-door.bicep: the web app and the Function App, HTTPS only,
// no caching. Separate from front-door.bicep so the sites can depend on the profile id without a cycle.

param profileName string
param webEndpointName string
param apiEndpointName string
param webOriginHost string
param apiOriginHost string

resource profile 'Microsoft.Cdn/profiles@2024-02-01' existing = {
  name: profileName
}

resource webEndpoint 'Microsoft.Cdn/profiles/afdEndpoints@2024-02-01' existing = {
  parent: profile
  name: webEndpointName
}

resource apiEndpoint 'Microsoft.Cdn/profiles/afdEndpoints@2024-02-01' existing = {
  parent: profile
  name: apiEndpointName
}

var sites = [
  { key: 'web', host: webOriginHost, probe: '/healthz', endpoint: webEndpoint.name }
  { key: 'api', host: apiOriginHost, probe: '/api/healthz', endpoint: apiEndpoint.name }
]

resource groups 'Microsoft.Cdn/profiles/originGroups@2024-02-01' = [for s in sites: {
  parent: profile
  name: '${s.key}-origins'
  properties: {
    loadBalancingSettings: { sampleSize: 4, successfulSamplesRequired: 3, additionalLatencyInMilliseconds: 50 }
    healthProbeSettings: { probePath: s.probe, probeRequestType: 'GET', probeProtocol: 'Https', probeIntervalInSeconds: 100 }
    sessionAffinityState: 'Disabled'
  }
}]

resource origins 'Microsoft.Cdn/profiles/originGroups/origins@2024-02-01' = [for (s, i) in sites: {
  parent: groups[i]
  name: s.key
  properties: {
    hostName: s.host
    originHostHeader: s.host
    httpPort: 80
    httpsPort: 443
    priority: 1
    weight: 1000
    enabledState: 'Enabled'
    enforceCertificateNameCheck: true
  }
}]

resource routes 'Microsoft.Cdn/profiles/afdEndpoints/routes@2024-02-01' = [for (s, i) in sites: {
  name: '${profileName}/${s.endpoint}/${s.key}'
  properties: {
    originGroup: { id: groups[i].id }
    supportedProtocols: ['Https']
    patternsToMatch: ['/*']
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Disabled'
    enabledState: 'Enabled'
  }
  dependsOn: [origins[i]]
}]

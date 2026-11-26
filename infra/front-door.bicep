// Azure Front Door Premium with a Web Application Firewall in front of the web app and the API (frontDoor=true).
//
// This module is the edge only: the profile, one endpoint each for the web app and the API, the WAF policies and their
// association, and logs. Origins and routes are in front-door-origins.bicep, because they need the sites' host names
// while the sites need this profile's id (to accept only traffic from it), and splitting the two avoids a cycle.
//
// WAF:
//   web endpoint  Microsoft_DefaultRuleSet 2.1 (OWASP) and Microsoft_BotManagerRuleSet 1.1, request bodies inspected,
//                 a per-client-IP rate limit, Prevention mode
//   API endpoint  the same rule sets and rate limit, but request bodies are NOT inspected by default: board posts,
//                 hunting queries and MCP calls carry attacker-looking text by design (command lines, KQL, URLs, script
//                 fragments from incidents), which the OWASP rules would block. Headers, the URL and the query string
//                 are still checked. apiWafBodyCheck=true turns body inspection on (expect to tune exclusions).
//   Optional allowed countries: every other country is blocked at the edge (both endpoints).
//
// Front Door is a global service: TLS from browsers and agents ends at the nearest Microsoft edge location, then
// travels on Microsoft's network to the Australian origins. Nothing is cached (routes don't enable caching) and no
// board data is stored at the edge; access and WAF logs go to the board's Log Analytics workspace.

param namePrefix string
param suffix string
param logsWorkspaceId string
@description('WAF mode for both endpoints: Prevention blocks, Detection only logs.')
@allowed(['Prevention', 'Detection'])
param wafMode string = 'Prevention'
@description('Inspect API request bodies with the managed rule sets (expect false positives on SOC content).')
param apiWafBodyCheck bool = false
@description('Requests per minute from one client IP before the WAF blocks it for the rest of the minute.')
@minValue(100)
param webRateLimitPerMinute int = 1000
@minValue(100)
param apiRateLimitPerMinute int = 3000
@description('ISO 3166 two-letter country codes allowed through; empty allows every country.')
param allowedCountries array = []

resource profile 'Microsoft.Cdn/profiles@2024-02-01' = {
  name: '${namePrefix}-afd-${suffix}'
  location: 'global'
  sku: { name: 'Premium_AzureFrontDoor' }
  properties: {
    // MCP over streamable HTTP keeps responses open while a tool runs: allow the longest origin response time.
    originResponseTimeoutSeconds: 240
  }
}

resource webEndpoint 'Microsoft.Cdn/profiles/afdEndpoints@2024-02-01' = {
  parent: profile
  name: '${namePrefix}-web-${suffix}'
  location: 'global'
  properties: { enabledState: 'Enabled' }
}

resource apiEndpoint 'Microsoft.Cdn/profiles/afdEndpoints@2024-02-01' = {
  parent: profile
  name: '${namePrefix}-api-${suffix}'
  location: 'global'
  properties: { enabledState: 'Enabled' }
}

var geoRule = empty(allowedCountries) ? [] : [
  {
    name: 'AllowedCountriesOnly'
    priority: 10
    enabledState: 'Enabled'
    ruleType: 'MatchRule'
    action: 'Block'
    matchConditions: [
      { matchVariable: 'SocketAddr', operator: 'GeoMatch', negateCondition: true, matchValue: allowedCountries }
    ]
  }
]

func rateRule(limit int) object => {
  name: 'RateLimitPerClientIp'
  priority: 100
  enabledState: 'Enabled'
  ruleType: 'RateLimitRule'
  rateLimitDurationInMinutes: 1
  rateLimitThreshold: limit
  action: 'Block'
  groupBy: [{ variableName: 'SocketAddr' }]
  matchConditions: [{ matchVariable: 'RequestUri', operator: 'Any', negateCondition: false, matchValue: [] }]
}

var managedRules = {
  managedRuleSets: [
    { ruleSetType: 'Microsoft_DefaultRuleSet', ruleSetVersion: '2.1', ruleSetAction: 'Block' }
    { ruleSetType: 'Microsoft_BotManagerRuleSet', ruleSetVersion: '1.1' }
  ]
}

resource webWaf 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies@2024-02-01' = {
  name: replace('${namePrefix}webwaf${suffix}', '-', '')
  location: 'Global'
  sku: { name: 'Premium_AzureFrontDoor' }
  properties: {
    policySettings: { enabledState: 'Enabled', mode: wafMode, requestBodyCheck: 'Enabled' }
    customRules: { rules: concat(geoRule, [rateRule(webRateLimitPerMinute)]) }
    managedRules: managedRules
  }
}

resource apiWaf 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies@2024-02-01' = {
  name: replace('${namePrefix}apiwaf${suffix}', '-', '')
  location: 'Global'
  sku: { name: 'Premium_AzureFrontDoor' }
  properties: {
    policySettings: { enabledState: 'Enabled', mode: wafMode, requestBodyCheck: apiWafBodyCheck ? 'Enabled' : 'Disabled' }
    customRules: { rules: concat(geoRule, [rateRule(apiRateLimitPerMinute)]) }
    managedRules: managedRules
  }
}

resource webSecurity 'Microsoft.Cdn/profiles/securityPolicies@2024-02-01' = {
  parent: profile
  name: 'web-waf'
  properties: {
    parameters: {
      type: 'WebApplicationFirewall'
      wafPolicy: { id: webWaf.id }
      associations: [{ domains: [{ id: webEndpoint.id }], patternsToMatch: ['/*'] }]
    }
  }
}

resource apiSecurity 'Microsoft.Cdn/profiles/securityPolicies@2024-02-01' = {
  parent: profile
  name: 'api-waf'
  properties: {
    parameters: {
      type: 'WebApplicationFirewall'
      wafPolicy: { id: apiWaf.id }
      associations: [{ domains: [{ id: apiEndpoint.id }], patternsToMatch: ['/*'] }]
    }
  }
}

resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: profile
  name: 'to-log-analytics'
  properties: {
    workspaceId: logsWorkspaceId
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
    metrics: [{ category: 'AllMetrics', enabled: true }]
  }
}

output profileName string = profile.name
output frontDoorId string = profile.properties.frontDoorId
output webEndpointName string = webEndpoint.name
output apiEndpointName string = apiEndpoint.name
output webHostname string = webEndpoint.properties.hostName
output apiHostname string = apiEndpoint.properties.hostName

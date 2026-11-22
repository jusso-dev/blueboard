// Operational alerts: is the board running, and is it healthy? Security detections (approval bursts, identity
// misuse, …) are Sentinel analytics rules in infra/sentinel/; these are the uptime and failure signals an operator
// needs. Each rule is independent and can be tuned in the portal. docs/OPERATIONS.md § Alerts lists what each means.
//
// Signals come from Application Insights (Functions host request telemetry, never sampled: host.json excludes
// Request), PostgreSQL and Web App platform metrics, and, in the production profile, BlueboardAudit_CL.

param location string
param namePrefix string
param appInsightsId string
param logsWorkspaceId string
param pgServerId string
param webSiteId string
@description('Email recipients. Empty: the rules fire into the portal only (no action group).')
param emails array = []
@description('BlueboardAudit_CL exists (production profile): alert on failed brokered actions.')
param auditExportEnabled bool = false

var timerFunctions = [
  'ingest-incidents'
  'recover-actions'
  'agent-wakeups'
  'notify-approvers'
  'export-audit'
  'unlock-playbook-steps'
  'ti-feeds'
  'ti-sentinel-auto'
  'ti-daily'
  'ti-cvewatch-recheck'
]

resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = if (!empty(emails)) {
  name: '${namePrefix}-ops'
  location: 'global'
  properties: {
    groupShortName: take('bb-ops', 12)
    enabled: true
    emailReceivers: [for (e, i) in emails: { name: 'ops-${i}', emailAddress: e, useCommonAlertSchema: true }]
  }
}

var actions = empty(emails) ? [] : [actionGroup.id]

// ── log alerts (Application Insights / Log Analytics) ──────────────────────────────────────────
var logRules = concat([
  {
    // recover-actions runs every minute whatever the configuration, so silence means the API is down, can't reach
    // the database, or isn't sending telemetry.
    name: 'heartbeat'
    displayName: 'blueboard: background jobs stopped running'
    description: 'No successful recover-actions run in 15 minutes. The Function App is stopped, failing to start, or cannot reach PostgreSQL. Check /api/healthz and the Setup page.'
    severity: 1
    scope: appInsightsId
    query: 'requests\n| where name == "recover-actions" and success == true'
    operator: 'LessThan'
    threshold: 1
    window: 'PT15M'
    frequency: 'PT5M'
    dimensions: []
  }
  {
    name: 'job-failures'
    displayName: 'blueboard: background job failing'
    description: 'A timer function (incident ingest, notifications, audit export, threat intel, …) failed repeatedly. Ingest failures usually mean a missing Graph permission or a Defender outage; the Setup page shows the last error.'
    severity: 2
    scope: appInsightsId
    query: 'requests\n| where success == false and name in (${join(map(timerFunctions, f => '"${f}"'), ', ')})'
    operator: 'GreaterThan'
    threshold: 2
    window: 'PT15M'
    frequency: 'PT5M'
    dimensions: [{ name: 'name', operator: 'Include', values: ['*'] }]
  }
  {
    name: 'api-5xx'
    displayName: 'blueboard: API server errors'
    description: 'The REST API or MCP endpoint returned more than 10 server errors (HTTP 5xx) in 15 minutes. Authentication failures (401/403) are not counted.'
    severity: 2
    scope: appInsightsId
    query: 'requests\n| where toint(resultCode) >= 500'
    operator: 'GreaterThan'
    threshold: 10
    window: 'PT15M'
    frequency: 'PT5M'
    dimensions: []
  }
  {
    name: 'migration-failed'
    displayName: 'blueboard: database migration failed'
    description: 'The Function App could not apply db/migrations at start-up, so it may be running against an old schema. The Setup page lists pending migrations; run `blueboard migrate` or fix the database identity.'
    severity: 1
    scope: appInsightsId
    // LogError with an exception lands in exceptions, without one in traces: search both.
    query: 'union isfuzzy=true traces, exceptions\n| where * has "database migration failed"'
    operator: 'GreaterThan'
    threshold: 0
    window: 'PT15M'
    frequency: 'PT5M'
    dimensions: []
  }
], auditExportEnabled ? [
  {
    name: 'action-failed'
    displayName: 'blueboard: brokered action failed'
    description: 'An approved action (isolate, disable user, block indicator, …) failed when it ran. The incident thread has the error; the target may be unchanged.'
    severity: 2
    scope: logsWorkspaceId
    query: 'BlueboardAudit_CL\n| where Event == "action.failed"'
    operator: 'GreaterThan'
    threshold: 0
    window: 'PT15M'
    frequency: 'PT5M'
    dimensions: []
  }
] : [])

resource logAlerts 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = [
  for r in logRules: {
    name: '${namePrefix}-${r.name}'
    location: location
    properties: {
      displayName: r.displayName
      description: r.description
      severity: r.severity
      enabled: true
      scopes: [r.scope]
      evaluationFrequency: r.frequency
      windowSize: r.window
      criteria: {
        allOf: [
          {
            query: r.query
            timeAggregation: 'Count'
            dimensions: r.dimensions
            operator: r.operator
            threshold: r.threshold
            failingPeriods: { numberOfEvaluationPeriods: 1, minFailingPeriodsToAlert: 1 }
          }
        ]
      }
      autoMitigate: true
      actions: { actionGroups: actions }
    }
  }
]

// ── metric alerts (PostgreSQL, Web App) ─────────────────────────────────────────────────────────
var metricRules = [
  {
    name: 'pg-down'
    displayName: 'blueboard: PostgreSQL not available'
    description: 'The database reports it is not alive. Every board request and job fails until it is back.'
    severity: 0
    scope: pgServerId
    metric: 'is_db_alive'
    aggregation: 'Minimum'
    operator: 'LessThan'
    threshold: 1
    window: 'PT5M'
  }
  {
    name: 'pg-storage'
    displayName: 'blueboard: PostgreSQL storage above 85%'
    description: 'Storage autogrow is on, but check growth: at 100% the server goes read-only and the board stops writing.'
    severity: 2
    scope: pgServerId
    metric: 'storage_percent'
    aggregation: 'Maximum'
    operator: 'GreaterThan'
    threshold: 85
    window: 'PT15M'
  }
  {
    name: 'pg-cpu'
    displayName: 'blueboard: PostgreSQL CPU above 85%'
    description: 'Sustained high CPU on the database. Scale the SKU up, or look for a heavy search or report query.'
    severity: 3
    scope: pgServerId
    metric: 'cpu_percent'
    aggregation: 'Average'
    operator: 'GreaterThan'
    threshold: 85
    window: 'PT30M'
  }
  {
    name: 'web-health'
    displayName: 'blueboard: web app health check failing'
    description: 'App Service health checks on /healthz are failing, so analysts may not be able to load the board.'
    severity: 1
    scope: webSiteId
    metric: 'HealthCheckStatus'
    aggregation: 'Average'
    operator: 'LessThan'
    threshold: 100
    window: 'PT5M'
  }
]

resource metricAlerts 'Microsoft.Insights/metricAlerts@2018-03-01' = [
  for r in metricRules: {
    name: '${namePrefix}-${r.name}'
    location: 'global'
    properties: {
      description: '${r.displayName}. ${r.description}'
      severity: r.severity
      enabled: true
      scopes: [r.scope]
      evaluationFrequency: 'PT5M'
      windowSize: r.window
      criteria: {
        'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
        allOf: [
          {
            criterionType: 'StaticThresholdCriterion'
            name: r.metric
            metricName: r.metric
            timeAggregation: r.aggregation
            operator: r.operator
            threshold: r.threshold
          }
        ]
      }
      autoMitigate: true
      actions: [for a in actions: { actionGroupId: a }]
    }
  }
]

output actionGroupId string = empty(emails) ? '' : actionGroup.id

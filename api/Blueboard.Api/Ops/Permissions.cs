using Blueboard.Api.Graph;

namespace Blueboard.Api.Ops;

/// <summary>
/// The Microsoft application permission each brokered action needs. Keep in sync with perm_for() in
/// infra/grant-permissions.sh (a unit test compares the two).
/// </summary>
public static class Permissions
{
    public sealed record Perm(MsApi Api, string Name)
    {
        public string ApiName => Api == MsApi.Graph ? "Microsoft Graph" : "Defender for Endpoint";
    }

    public static readonly IReadOnlyDictionary<string, Perm> WriteFor = new Dictionary<string, Perm>
    {
        ["isolate_device"] = new(MsApi.Defender, "Machine.Isolate"),
        ["release_device"] = new(MsApi.Defender, "Machine.Isolate"),
        ["run_av_scan"] = new(MsApi.Defender, "Machine.Scan"),
        ["collect_investigation_package"] = new(MsApi.Defender, "Machine.CollectForensics"),
        ["restrict_app_execution"] = new(MsApi.Defender, "Machine.RestrictExecution"),
        ["unrestrict_app_execution"] = new(MsApi.Defender, "Machine.RestrictExecution"),
        ["stop_and_quarantine_file"] = new(MsApi.Defender, "Machine.StopAndQuarantine"),
        ["tag_device"] = new(MsApi.Defender, "Machine.ReadWrite.All"),
        ["block_indicator"] = new(MsApi.Defender, "Ti.ReadWrite.All"),
        ["unblock_indicator"] = new(MsApi.Defender, "Ti.ReadWrite.All"),
        ["disable_user"] = new(MsApi.Graph, "User.EnableDisableAccount.All"),
        ["enable_user"] = new(MsApi.Graph, "User.EnableDisableAccount.All"),
        ["revoke_sessions"] = new(MsApi.Graph, "User.RevokeSessions.All"),
        ["reset_password"] = new(MsApi.Graph, "User-PasswordProfile.ReadWrite.All"),
        ["confirm_user_compromised"] = new(MsApi.Graph, "IdentityRiskyUser.ReadWrite.All"),
        ["dismiss_user_risk"] = new(MsApi.Graph, "IdentityRiskyUser.ReadWrite.All"),
        ["disable_service_principal"] = new(MsApi.Graph, "Application.ReadWrite.All"),
        ["purge_email"] = new(MsApi.Graph, "SecurityAnalyzedMessage.ReadWrite.All"),
        ["update_incident"] = new(MsApi.Graph, "SecurityIncident.ReadWrite.All"),
        ["add_incident_comment"] = new(MsApi.Graph, "SecurityIncident.ReadWrite.All"),
        // target defender; target sentinel needs an Azure role instead (AlsoAzureRoleFor).
        ["create_detection_rule"] = new(MsApi.Graph, "CustomDetection.ReadWrite.All"),
        ["disable_detection_rule"] = new(MsApi.Graph, "CustomDetection.ReadWrite.All"),
        ["intune_sync_device"] = new(MsApi.Graph, "DeviceManagementManagedDevices.PrivilegedOperations.All"),
        ["intune_update_defender_signatures"] = new(MsApi.Graph, "DeviceManagementManagedDevices.PrivilegedOperations.All"),
        ["intune_expedite_quality_update"] = new(MsApi.Graph, "WindowsUpdates.ReadWrite.All"),
    };

    /// <summary>
    /// Kinds that need an Azure role as well, for one of their targets: Sentinel analytics rules are ARM resources, so
    /// create/disable with target sentinel need Microsoft Sentinel Contributor on the workspace.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> AlsoAzureRoleFor = new Dictionary<string, string>
    {
        ["create_detection_rule"] = "Microsoft Sentinel Contributor on the Sentinel workspace (target sentinel)",
        ["disable_detection_rule"] = "Microsoft Sentinel Contributor on the Sentinel workspace (target sentinel)",
    };

    /// <summary>
    /// Reads the Intune kinds make before policy runs (managed device ↔ Entra device ↔ MDE id), granted with any Intune
    /// action. SecurityRecommendation.Read.All (MDE) backs list_exposure_recommendations (EXPOSURE=1).
    /// </summary>
    public static readonly Perm IntuneDeviceRead = new(MsApi.Graph, "DeviceManagementManagedDevices.Read.All");
    public static readonly Perm RecommendationRead = new(MsApi.Defender, "SecurityRecommendation.Read.All");

    /// <summary>
    /// Kinds that need an Azure role rather than a Graph or Defender application permission. publish_ti_indicator needs
    /// Microsoft Sentinel Contributor on the Sentinel workspace, which no token roles claim can show, so the setup page
    /// lists it as a note instead of checking it.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> AzureRoleFor = new Dictionary<string, string>
    {
        ["publish_ti_indicator"] = "Microsoft Sentinel Contributor on the Sentinel workspace",
    };

    /// <summary>Optional: email notifications to approvers (NOTIFY_MAIL=1 in grant-permissions.sh).</summary>
    public static readonly Perm MailSend = new(MsApi.Graph, "Mail.Send");
}

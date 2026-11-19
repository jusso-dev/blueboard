/** Normalised entity view of a Graph security incident's alert evidence. */
export type IncidentEntities = {
  devices: { mdeDeviceId?: string; name?: string }[];
  users: { upn?: string; aadUserId?: string; name?: string }[];
  ips: string[];
  urls: string[];
  domains: string[];
  files: { sha256?: string; sha1?: string; name?: string }[];
  emails: { networkMessageId?: string; recipient?: string; sender?: string; subject?: string }[];
  mitre: string[];
};

type Evidence = Record<string, any> & { "@odata.type"?: string };
type Alert = { evidence?: Evidence[]; mitreTechniques?: string[] };

const uniq = <T>(items: T[], key: (t: T) => string | undefined) => {
  const seen = new Map<string, T>();
  for (const i of items) {
    const k = key(i);
    if (k && !seen.has(k)) seen.set(k, i);
  }
  return [...seen.values()];
};

export function extractEntities(incident: { alerts?: Alert[] }): IncidentEntities {
  const e: IncidentEntities = { devices: [], users: [], ips: [], urls: [], domains: [], files: [], emails: [], mitre: [] };
  for (const alert of incident.alerts ?? []) {
    e.mitre.push(...(alert.mitreTechniques ?? []));
    for (const ev of alert.evidence ?? []) {
      const t = (ev["@odata.type"] ?? "").replace("#microsoft.graph.security.", "");
      switch (t) {
        case "deviceEvidence":
          e.devices.push({ mdeDeviceId: ev.mdeDeviceId, name: ev.deviceDnsName ?? ev.hostName });
          break;
        case "userEvidence":
          e.users.push({
            upn: ev.userAccount?.userPrincipalName,
            aadUserId: ev.userAccount?.azureAdUserId,
            name: ev.userAccount?.displayName ?? ev.userAccount?.accountName,
          });
          break;
        case "ipEvidence":
          if (ev.ipAddress) e.ips.push(ev.ipAddress);
          break;
        case "urlEvidence":
          if (ev.url) e.urls.push(ev.url);
          break;
        case "fileEvidence":
        case "fileHashEvidence":
          e.files.push({
            sha256: ev.fileDetails?.sha256 ?? (ev.algorithm === "sha256" ? ev.value : undefined),
            sha1: ev.fileDetails?.sha1 ?? (ev.algorithm === "sha1" ? ev.value : undefined),
            name: ev.fileDetails?.fileName,
          });
          break;
        case "processEvidence":
          if (ev.imageFile) e.files.push({ sha256: ev.imageFile.sha256, sha1: ev.imageFile.sha1, name: ev.imageFile.fileName });
          break;
        case "analyzedMessageEvidence":
          e.emails.push({
            networkMessageId: ev.networkMessageId,
            recipient: ev.recipientEmailAddress,
            sender: ev.p1Sender?.emailAddress ?? ev.p2Sender?.emailAddress,
            subject: ev.subject,
          });
          for (const u of ev.urls ?? []) e.urls.push(u);
          break;
        case "mailboxEvidence":
          e.users.push({ upn: ev.primaryAddress ?? ev.userAccount?.userPrincipalName, aadUserId: ev.userAccount?.azureAdUserId });
          break;
        case "cloudLogonSessionEvidence":
        case "oauthApplicationEvidence":
        default:
          break;
      }
    }
  }
  for (const u of e.urls) {
    try {
      e.domains.push(new URL(u).hostname.toLowerCase());
    } catch {
      /* ignore malformed */
    }
  }
  e.devices = uniq(e.devices, (d) => d.mdeDeviceId ?? d.name);
  e.users = uniq(e.users, (u) => (u.aadUserId ?? u.upn)?.toLowerCase());
  e.files = uniq(e.files, (f) => f.sha256 ?? f.sha1);
  e.emails = uniq(e.emails, (m) => `${m.networkMessageId}|${m.recipient}`);
  e.ips = [...new Set(e.ips)];
  e.urls = [...new Set(e.urls)];
  e.domains = [...new Set(e.domains)];
  e.mitre = [...new Set(e.mitre)];
  return e;
}

/** All identifiers in the entity set, lower-cased, for "is this action target part of the incident" checks. */
export function entityKeys(e: IncidentEntities): Set<string> {
  const keys = new Set<string>();
  const add = (v?: string) => v && keys.add(v.toLowerCase());
  e.devices.forEach((d) => (add(d.mdeDeviceId), add(d.name)));
  e.users.forEach((u) => (add(u.upn), add(u.aadUserId)));
  e.ips.forEach(add);
  e.urls.forEach(add);
  e.domains.forEach(add);
  e.files.forEach((f) => (add(f.sha256), add(f.sha1)));
  e.emails.forEach((m) => (add(m.networkMessageId), add(m.recipient), add(m.sender)));
  return keys;
}

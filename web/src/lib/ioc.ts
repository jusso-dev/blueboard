/** The composer's IOC form. Mirrors the API's Payloads.Ioc validation; the API checks again on post. */
export const IOC_KINDS = ["ip", "domain", "url", "sha256", "sha1", "md5", "email", "user", "device"] as const;
export const IOC_VERDICTS = ["malicious", "suspicious", "benign", "unknown"] as const;
export type IocDraft = { kind: (typeof IOC_KINDS)[number]; value: string; verdict: (typeof IOC_VERDICTS)[number] };

/** The ioc payload to post, or an error to show next to the form. */
export function iocPayload(d: IocDraft): { indicators: IocDraft[] } | string {
  const value = d.value.trim();
  if (!(IOC_KINDS as readonly string[]).includes(d.kind)) return "Choose an indicator kind";
  if (value.length < 1) return "Enter the indicator value";
  if (value.length > 2048) return "The indicator value is too long (2048 characters at most)";
  if (!(IOC_VERDICTS as readonly string[]).includes(d.verdict)) return "Choose a verdict";
  return { indicators: [{ kind: d.kind, value, verdict: d.verdict }] };
}

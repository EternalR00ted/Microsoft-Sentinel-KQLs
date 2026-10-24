# Storm-0940 - ARTEX-Driven Detections

Detections for the AI-driven Storm-0940 campaign that abused ConnectWise Cloud Backup (SkyKick) app credentials in October 2026. None of them use the published IPs, app IDs or user agent strings. They look for what a stolen app credential and an agent driving it do, so they should still fire on the next vendor.

## The rules

| File | Catches | Table | Run | Severity | MITRE |
|---|---|---|---|---|---|
| 00 Check log sources first | Which tables and fields you have | All below | Once | n/a | n/a |
| 01 Password spray from one source | One IP failing across many accounts, or hammering a few into smart lockout | SigninLogs, AADNonInteractiveUserSignInLogs | 1h / 1h | Medium, High if a password worked | T1110.003 |
| 02 App signed in from a new network | App sign-in from a new ASN, first public IP, new APIs, new client or credential | AADServicePrincipalSignInLogs | 1h / 14d | Scored | T1078.004, T1199 |
| 03 App made unusual Graph calls | App-only identity calling new endpoints, failing across endpoints, switching clients | MicrosoftGraphActivityLogs | 1h / 14d | Scored | T1087.004, T1069.003, T1526 |
| 04 App token has new high-risk permissions | App token carries a high-risk permission it never had | MicrosoftGraphActivityLogs | 1h / 14d | High for escalation permissions | T1098.003 |
| 05 App assigned an admin role | An app assigning any role (self or others), or any privileged role landing on an app | AuditLogs | 5m / 5m | High | T1098.003 |
| 06 App added credentials to an app | An app adding or trying to add secrets or certs to an app | AuditLogs | 5m / 5m | High | T1098.001 |
| 07 App granted API permissions | An app granting permissions or consent, or anyone granting high-risk permissions | AuditLogs | 5m / 5m | High or Medium | T1098.003 |
| 08 App changed the directory in a new way | An app making a high-impact change it never made, or writing with a new client | AuditLogs | 1h / 14d | High or Medium | T1098, T1556.009, T1484.002 |
| 09 Planted app credential used to sign in | A sign-in using a credential another app planted | AuditLogs, AADServicePrincipalSignInLogs | 1h / 7d | High | T1098.001, T1078.004 |
| 10 App reading many mailboxes | An app reading far more mailboxes than its busiest hour, or Teams chat folders | OfficeActivity | 1h / 14d | High or Medium | T1114.002 |

Run is frequency / look back. Set the `Window` value in each query to the frequency you pick.

## Before you turn them on

1. Run `00 - Check log sources first`. Rules 02 and 09 need `AADServicePrincipalSignInLogs`. Rules 03 and 04 need `MicrosoftGraphActivityLogs`. Both are categories on the Entra ID diagnostic setting. Graph activity logs need Entra ID P1 or P2, and Microsoft estimates about 15 GiB a month per 1,000 users.
2. Run 05, 06, 07 and 08 over 14 days in Advanced hunting first. Whatever comes back is likely your own automation. Confirm it, then add its display name to the `Approved...` list at the top of the query.
3. Replace `<Company>` in the alert titles. `{{Column}}` placeholders work in Defender custom detection titles (up to three per title) and in Sentinel alert details.
4. Map entities by hand. Custom detections on Sentinel data don't map them for you. Each file lists the columns to use.

## Where to run them

All of them read Sentinel tables only, so they work as Sentinel analytics rules or as Defender custom detections with **Custom** frequency. The 14-day baselines need that. A custom detection that reads Defender XDR tables and runs hourly only looks back 4 hours, so don't port 02, 03, 04, 08 or 10 to `EntraIdSpnSignInEvents` or `GraphAPIAuditEvents`.

05, 06 and 07 have no baseline. Run them every 5 minutes. In the tenant Huntress looked at, the whole sequence (Global Administrator, then secrets on two other apps) took about five minutes.

None of them qualify for NRT. NRT custom detections can't have joins, unions or comment lines.

## Gap in the built-in rules

Microsoft's Sentinel rules "New access credential added to Application or Service Principal" and "First access credential added to Application or Service Principal where no credential was present" (scheduled and NRT versions) only keep events where the initiator has `@` in its name. A credential added by an application has no `@`, so it's dropped. They also only keep `Application` targets, so a credential added to a service principal object is dropped too. That is the exact persistence step in this campaign. Rule 06 covers it.

## Known blind spots

- Rule 02 skips apps with under 3 days of history, and can't see an attacker who runs in the same cloud ASN as the vendor. Rules 03 to 09 watch what the app does after it signs in.
- Graph directory reads leave no Entra audit record. Without `MicrosoftGraphActivityLogs`, recon is invisible.
- Rule 09 matches on the credential key ID. If `SecretSignInsWithKeyId` is 0 in rule 00 while `SecretSignIns` isn't, your secret sign-ins don't log a key ID and rule 09 only covers certificates.
- Key Vault isn't covered here. Microsoft's Key Vault hunting query in the blog (bulk SecretGet across vaults) is already behavior-based, and `KV_AccountVolumeAccessDeniedAnomaly` from Defender for Key Vault is the alert Microsoft lists for that part of the campaign.

## How these were checked

Microsoft's Kusto parser couldn't be installed in the sandbox they were written in. Instead, every query was checked by script against the Microsoft Learn schemas for each table and the function list in Microsoft's Kusto.Language source: brackets and strings balanced, every column real, every function real, every operator real. Patterns that are easy to get wrong (audit log key parsing, PIM exclusion, Graph URI normalization) follow Microsoft's own Sentinel rules and docs. They haven't run against live data yet. Run each one in Advanced hunting before you save it as a rule.

## Sources

- Microsoft Security Blog, AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise (Oct 21, 2026)
- [Huntress, ConnectWise (SkyKick) Vendor Credentials Abused in M365 Attacks](https://www.huntress.com/blog/vendor-credential-enables-unauthorized-access)
- [Todyl, Investigation: Unauthorized Access Through the ConnectWise Cloud Backup Microsoft 365 App](https://www.todyl.com/blog/investigation-unauthorized-access-through-the-connectwise-cloud-backup-microsoft-365-app)
- [Microsoft Learn, Create custom detection rules](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)
- [Microsoft Learn, Microsoft Graph activity logs](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview)
- [Microsoft Learn, AADServicePrincipalSignInLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs)
- [Microsoft Learn, Microsoft Entra built-in roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference)
- [Azure-Sentinel on GitHub, Microsoft Entra ID analytic rules](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules)

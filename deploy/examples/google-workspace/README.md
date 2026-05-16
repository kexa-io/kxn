# Google Workspace security audit

Audit your Google Workspace for the issues that actually get organizations
breached:

- **Users without 2-Step Verification (2FA/MFA)** — accounts that can be taken
  over with just a stolen password. Admins without 2FA are flagged as critical.
- **Over-shared Google Drive files** — documents shared with a public link or
  with people outside your organization.
- **Risky third-party OAuth apps** — apps granted broad access to mail or Drive.
- **Groups, devices, domains** — external group membership, unencrypted phones,
  unverified domains, dormant accounts.

It uses the native `googleworkspace` kxn provider — no Terraform, no extra
tooling. One command, one pass/fail report.

## Which mode do I want?

| Mode | Scans | Needs admin rights? | Setup |
|------|-------|---------------------|-------|
| **A — my account** | Your Drive, your OAuth apps, your 2FA | Drive/OAuth: no — directory checks: yes | `gcloud` login |
| **B — whole domain** | Every user, group, device + everyone's Drive | Yes — a service account with domain-wide delegation | Service account key |

Start with Mode A to try it; use Mode B for a real organization-wide audit.

## Prerequisites (both modes)

In a [Google Cloud project](https://console.cloud.google.com/), enable the
three APIs kxn calls:

- **Admin SDK API** — users, groups, devices, domains, roles, OAuth grants
- **Google Drive API** — Drive files and their sharing
- **Groups Settings API** — group external-membership and posting policy

```
https://console.cloud.google.com/apis/library/admin.googleapis.com
https://console.cloud.google.com/apis/library/drive.googleapis.com
https://console.cloud.google.com/apis/library/groupssettings.googleapis.com
```

All nine OAuth scopes used are **read-only**:

```
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.user.security
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.domain.readonly
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly
https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly
https://www.googleapis.com/auth/apps.groups.settings
https://www.googleapis.com/auth/drive.metadata.readonly
```

---

## Mode A — audit my own account (OAuth)

Authenticate once with the gcloud CLI. This opens a browser consent screen and
stores a local token; kxn reuses it.

```bash
gcloud auth application-default login --scopes=\
https://www.googleapis.com/auth/admin.directory.user.readonly,\
https://www.googleapis.com/auth/admin.directory.user.security,\
https://www.googleapis.com/auth/admin.directory.group.readonly,\
https://www.googleapis.com/auth/admin.directory.domain.readonly,\
https://www.googleapis.com/auth/admin.directory.device.mobile.readonly,\
https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly,\
https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly,\
https://www.googleapis.com/auth/apps.groups.settings,\
https://www.googleapis.com/auth/drive.metadata.readonly
```

Then run the audit:

```bash
# one-shot report
kxn gather -p googleworkspace -t all | kxn scan -R rules --include "gws-*"
```

- The **Drive** and **OAuth apps** checks work for any user.
- The **directory** checks (users/2FA, groups, devices, domains) need your
  account to be a Workspace admin — the Admin SDK only exposes that data to
  admins. If you are not an admin those parts return a permission error; the
  rest still works. To scan Drive only:
  `kxn gather -p googleworkspace -t drive_files | kxn scan -R rules --include "gws-drive-*"`.

---

## Mode B — audit the whole domain (service account)

This impersonates users through **domain-wide delegation** so it can read every
account, group, device and Drive.

### 1. Create a service account + key

In your Google Cloud project: *IAM & Admin → Service Accounts → Create*. Then
*Keys → Add key → JSON* and download the key file.

### 2. Authorize domain-wide delegation

Copy the service account's **Client ID** (numeric, on the service account
details page). In the [Admin console](https://admin.google.com/):

*Security → Access and data control → API controls → Domain-wide delegation →
Add new*

- **Client ID**: the service account client ID
- **OAuth scopes**: the nine scopes listed above, comma-separated

### 3. Run the audit

`subject` is a Workspace **admin** email the service account impersonates.
`scan_all_users` then walks every user's Drive and OAuth grants.

```bash
kxn gather -p googleworkspace -t all \
  -C '{"credentials_file":"/path/to/service-account.json","subject":"admin@yourcompany.com","domain":"yourcompany.com","scan_all_users":true}' \
  | kxn scan -R rules --include "gws-*"
```

For continuous monitoring, copy `kxn.toml.example` from this directory to
`kxn.toml`, fill in the Mode B target, and run `kxn watch --config kxn.toml`.

---

## What the rules check

| Rule | Severity | Flags |
|------|----------|-------|
| `gws-user-2sv-enrolled` | error | An active user has not enabled 2-Step Verification |
| `gws-admin-2sv-enrolled` | fatal | An **admin** account has not enabled 2-Step Verification |
| `gws-admin-2sv-enforced` | warning | An **admin** has 2SV enrolled but not enforced |
| `gws-user-not-inactive` | warning | An active account has not logged in for 90+ days |
| `gws-domain-verified` | error | A registered domain is not verified |
| `gws-group-no-external-members` | warning | A group allows members from outside the org |
| `gws-group-no-public-posting` | warning | A group lets anyone on the internet post messages |
| `gws-group-no-public-join` | warning | A group can be joined by anyone on the internet |
| `gws-group-not-publicly-viewable` | warning | A group's content is viewable by anyone on the internet |
| `gws-group-membership-not-public` | info | A group's member list is publicly visible |
| `gws-oauth-no-high-risk-app` | warning | A third-party app holds broad mail/Drive/directory access |
| `gws-mobile-device-encrypted` | warning | A mobile device with Workspace access is not encrypted |
| `gws-chromeos-device-active` | info | A ChromeOS device is deprovisioned but still enrolled |
| `gws-drive-no-public-discoverable` | fatal | A Drive file is public **and** search-indexed |
| `gws-drive-no-public-link` | error | A Drive file is shared via "anyone with the link" |
| `gws-drive-no-external-share` | warning | A Drive file is shared outside the organization |
| `gws-drive-no-external-edit` | error | A Drive file grants **edit** access outside the organization |

Suspended accounts are not flagged for missing 2FA or dormancy (they cannot
sign in). The `role_assignments` resource is gathered as report data — review
admin role grants for least privilege.

Full provider and rule reference: [`docs/google-workspace.md`](../../../docs/google-workspace.md).

## What kxn cannot check

Some Workspace settings have no read API — org-wide Gmail/Drive/Calendar
policies, Marketplace restrictions, less-secure-app access, context-aware
access. Google exposes those only in the Admin console; no tool can audit them.

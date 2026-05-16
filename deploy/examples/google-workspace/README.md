# Google Workspace security audit

Check your Google Workspace for two common, high-impact problems:

1. **Users without 2-Step Verification (2FA/MFA)** — accounts that can be taken
   over with just a stolen password. Admin accounts without 2FA are flagged as
   critical.
2. **Over-shared Google Drive files** — documents shared with a public link or
   with people outside your organization.

It uses the native `googleworkspace` kxn provider — no Terraform, no extra
tooling. One command and you get a pass/fail report.

## Which mode do I want?

| Mode | Scans | Needs admin rights? | Setup |
|------|-------|---------------------|-------|
| **A — my account** | Your own Drive files + your 2FA status | No (Drive); yes (for the `users` check) | `gcloud` login |
| **B — whole domain** | Every user's 2FA + every user's Drive | Yes — a service account with domain-wide delegation | Service account key |

Start with Mode A to try it out; use Mode B for a real organization-wide audit.

## Prerequisites (both modes)

In a [Google Cloud project](https://console.cloud.google.com/), enable the two
APIs kxn calls:

- **Admin SDK API** — reads the user directory (2FA status)
- **Google Drive API** — reads Drive files and their sharing

```
https://console.cloud.google.com/apis/library/admin.googleapis.com
https://console.cloud.google.com/apis/library/drive.googleapis.com
```

The two OAuth scopes used are read-only:

```
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/drive.metadata.readonly
```

---

## Mode A — audit my own account (OAuth)

Authenticate once with the gcloud CLI. This opens a browser consent screen and
stores a local token; kxn reuses it.

```bash
gcloud auth application-default login \
  --scopes=https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/drive.metadata.readonly
```

Then run the audit:

```bash
# one-shot report
kxn gather -p googleworkspace -t all | kxn scan -R rules --include "gws-*"
```

- The **Drive** check works for any user.
- The **`users` / 2FA** check needs your account to be a Workspace admin
  (the Admin SDK only exposes 2FA status to admins). If you are not an admin,
  that part returns a permission error — use Mode B, or scan Drive only:
  `kxn gather -p googleworkspace -t drive_files | kxn scan -R rules --include "gws-drive-*"`.

---

## Mode B — audit the whole domain (service account)

This impersonates users through **domain-wide delegation** so it can read every
account's 2FA status and every user's Drive.

### 1. Create a service account + key

In your Google Cloud project: *IAM & Admin → Service Accounts → Create*. Then
*Keys → Add key → JSON* and download the key file.

### 2. Authorize domain-wide delegation

Copy the service account's **Client ID** (numeric, on the service account
details page). In the [Admin console](https://admin.google.com/):

*Security → Access and data control → API controls → Domain-wide delegation →
Add new*

- **Client ID**: the service account client ID
- **OAuth scopes**:
  ```
  https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/drive.metadata.readonly
  ```

### 3. Run the audit

`subject` is a Workspace **admin** email the service account impersonates for
the directory listing. `scan_all_users` then walks every user's Drive.

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
| `gws-drive-no-public-discoverable` | fatal | A Drive file is public **and** search-indexed (open to the internet) |
| `gws-drive-no-public-link` | error | A Drive file is shared via "anyone with the link" |
| `gws-drive-no-external-share` | warning | A Drive file is shared with someone outside the organization |

Suspended accounts are not flagged for missing 2FA (they cannot sign in).

Full provider and rule reference: [`docs/google-workspace.md`](../../../docs/google-workspace.md).

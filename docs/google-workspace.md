# Google Workspace audit

The `googleworkspace` native provider audits a Google Workspace organization
across the configuration surface that Google exposes through read APIs:

- **2-Step Verification (2FA/MFA)** — users, and especially admins, protected
  by a password alone.
- **Google Drive sharing** — files exposed through public links or shared
  outside the organization.
- **Third-party OAuth apps** — applications granted broad access to mail,
  Drive or the directory.
- **Groups, devices and domains** — external group membership, unencrypted
  mobile devices, unverified domains, dormant accounts.

It calls the Google **Admin SDK**, **Drive API** and **Groups Settings API**
directly. No Terraform provider and no extra tooling are involved.

A ready-to-run example lives in
[`deploy/examples/google-workspace/`](../deploy/examples/google-workspace/) —
that directory's `README.md` is the quickest path to a first scan. This page is
the full reference.

> **Note** — the separate `rules/google-workspace-cis.toml` file targets the
> Terraform `workspace` profile and a different data shape. The rules described
> here are in `rules/google-workspace-audit.toml`, the file that works with
> this native provider.

## What cannot be audited

Several Workspace security settings have **no read API** — org-wide Gmail
policies (forwarding, attachment scanning), Drive sharing policy at the domain
level, Marketplace and OAuth app restrictions, less-secure-app access,
context-aware access. Google exposes these only in the Admin console. No
tool — native or Terraform — can read them, so they are out of scope. The CIS
Google Workspace benchmark itself classifies those controls as manual.

## How it works

```
gather (Admin SDK + Drive + Groups APIs)  ──▶  JSON resources  ──▶  scan (rules)  ──▶  report
```

`kxn gather -p googleworkspace` collects the resource types below;
`kxn scan` evaluates the `google-workspace-audit.toml` rules against them.

## Authentication

The provider picks its mode from the config it is given.

### Mode A — OAuth / Application Default Credentials

Used when no service account is configured. The provider obtains a token from
Application Default Credentials, exactly like the `gcloud` CLI. Authenticate
once with all read scopes:

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

- Scans the **authenticated account**.
- `drive_files` and `oauth_tokens` work for any user.
- `users`, `domains`, `groups`, `*_devices`, `role_assignments` require the
  account to be a **Workspace admin** — the Admin SDK only exposes that data
  to admins. If the account is not an admin those resource types return a
  permission error; the others still produce results.

### Mode B — service account with domain-wide delegation

Used when `credentials_file` (or `credentials`) is provided. The provider signs
a JWT assertion and exchanges it for an access token that **impersonates** a
user — which is what lets it read directory and Drive data across the domain.

1. Create a service account and a JSON key in a Google Cloud project.
2. Enable the **Admin SDK API**, **Google Drive API** and
   **Groups Settings API** in that project.
3. In the [Admin console](https://admin.google.com/) → *Security → Access and
   data control → API controls → Domain-wide delegation*, authorize the
   service account's **Client ID** for the nine scopes listed above
   (comma-separated).

`subject` must be a Workspace admin — the provider impersonates it for the
directory listings. With `scan_all_users`, per-user resources (`drive_files`,
`oauth_tokens`) impersonate every active user in turn.

## Configuration

Config keys are passed via `-C '{...}'` on `kxn gather`, the `[targets.config]`
table in `kxn.toml`, or `GOOGLE_WORKSPACE_*` environment variables.

| Key | Env | Description |
|-----|-----|-------------|
| `credentials_file` | `GOOGLE_WORKSPACE_CREDENTIALS_FILE` | Path to a service account key JSON — selects Mode B |
| `credentials` | `GOOGLE_WORKSPACE_CREDENTIALS` | Inline service account key JSON (alternative to the file) |
| `subject` | `GOOGLE_WORKSPACE_SUBJECT` | Admin email to impersonate (required in Mode B) |
| `customer` | `GOOGLE_WORKSPACE_CUSTOMER` | Directory customer ID (default `my_customer`) |
| `domain` | `GOOGLE_WORKSPACE_DOMAIN` | Primary domain — classifies external Drive sharing. Defaults to the file owner's domain |
| `scan_all_users` | `GOOGLE_WORKSPACE_SCAN_ALL_USERS` | `true` to scan every user's Drive and OAuth grants (Mode B only) |
| `access_token` | `GOOGLE_WORKSPACE_ACCESS_TOKEN` | Use a pre-obtained OAuth access token directly |

## Resource types

| Type | API | Per-user? |
|------|-----|-----------|
| `users` | Admin SDK Directory | no |
| `domains` | Admin SDK Directory | no |
| `groups` | Admin SDK Directory + Groups Settings | no |
| `oauth_tokens` | Admin SDK Directory | yes |
| `mobile_devices` | Admin SDK Directory | no |
| `chromeos_devices` | Admin SDK Directory | no |
| `role_assignments` | Admin SDK Directory | no |
| `drive_files` | Drive API v3 | yes |

"Per-user" resources are gathered for the authenticated account (Mode A), for
`subject` (Mode B), or for every active user (Mode B with `scan_all_users`).

### `users`

| Field | Description |
|-------|-------------|
| `email` | Primary email |
| `full_name` | Display name |
| `is_admin` | Super administrator |
| `is_delegated_admin` | Has a delegated admin role |
| `is_enrolled_2sv` | 2-Step Verification is set up |
| `is_enforced_2sv` | 2SV is enforced by policy |
| `suspended` / `archived` | Account state |
| `last_login_time` | Last login timestamp |
| `days_since_last_login` | Days since last login (`-1` if unknown) |
| `creation_time` | Account creation timestamp |
| `org_unit_path` | Organizational unit |

### `domains`

`domain_name`, `verified`, `is_primary`, `creation_time`.

### `groups`

`email`, `name`, `description`, `direct_members_count`,
`allow_external_members`, `who_can_post_message`, `who_can_join`,
`who_can_view_group`, `who_can_view_membership`, `who_can_contact_owner`.

### `oauth_tokens`

One object per third-party app a user has authorized:
`user`, `app`, `client_id`, `native_app`, `anonymous`, `scope_count`,
`scopes`, `has_high_risk_scope` (true when the app holds mail/Drive/directory
access).

### `mobile_devices`

`device_id`, `user`, `model`, `os`, `type`, `status`, `encryption_status`,
`encrypted`, `security_patch_level`, `last_sync`.

`encrypted` is `false` only when the Admin SDK explicitly reports the device
as not encrypted. iOS devices (hardware-encrypted by default, with an empty
`encryption_status` in the API) and devices with an unknown status are
reported as `encrypted: true` to avoid false positives.

### `chromeos_devices`

`device_id`, `serial_number`, `status`, `os_version`, `model`,
`annotated_user`, `last_sync`.

### `role_assignments`

`assigned_to`, `role_id`, `role_name`, `is_super_admin_role`, `scope_type`,
`org_unit_id`. Exposed as report data — least-privilege review is a manual
judgement, so no pass/fail rule ships for this type.

### `drive_files`

One object per Drive file owned by the scanned user(s):
`id`, `name`, `mime_type`, `owner`, `scanned_user`, `web_view_link`,
`modified_time`, `shared`, `shared_with_anyone`, `public_discoverable`,
`shared_externally`, `externally_writable`, `external_recipients`,
`permission_count`.

## Rules

Defined in `rules/google-workspace-audit.toml`. Severity: `info` (0),
`warning` (1), `error` (2), `fatal` (3).

| Rule | Severity | Flags |
|------|----------|-------|
| `gws-user-2sv-enrolled` | error | An active user has not enabled 2-Step Verification |
| `gws-admin-2sv-enrolled` | fatal | An **admin** account has not enabled 2-Step Verification |
| `gws-admin-2sv-enforced` | warning | An **admin** account has 2SV enrolled but not enforced (it could be turned off) |
| `gws-user-not-inactive` | warning | An active account has not logged in for 90+ days |
| `gws-domain-verified` | error | A registered domain is not verified |
| `gws-group-no-external-members` | warning | A group allows members from outside the org |
| `gws-group-no-public-posting` | warning | A group lets anyone on the internet post messages |
| `gws-group-no-public-join` | warning | A group can be joined by anyone on the internet |
| `gws-group-not-publicly-viewable` | warning | A group's content is viewable by anyone on the internet |
| `gws-group-membership-not-public` | info | A group's member list is visible to anyone on the internet |
| `gws-oauth-no-high-risk-app` | warning | A third-party app holds broad mail/Drive/directory access |
| `gws-mobile-device-encrypted` | warning | A mobile device with Workspace access is not encrypted |
| `gws-chromeos-device-active` | info | A ChromeOS device is deprovisioned/disabled but still enrolled |
| `gws-drive-no-public-discoverable` | fatal | A Drive file is public **and** search-indexed |
| `gws-drive-no-public-link` | error | A Drive file is shared via "anyone with the link" |
| `gws-drive-no-external-share` | warning | A Drive file is shared outside the organization |
| `gws-drive-no-external-edit` | error | A Drive file grants **edit** access outside the organization |

### Notes on selected rules

- **`gws-user-2sv-enrolled` / `gws-user-not-inactive`** — suspended accounts are
  treated as compliant; they cannot sign in. Fix missing 2SV by enrolling a
  second factor or enforcing 2SV org-wide (*Admin console → Security →
  Authentication*). Fix dormant accounts by suspending them.
- **`gws-admin-2sv-enrolled`** — fatal: a compromised admin without 2FA exposes
  the entire domain. Prefer a hardware security key for administrators.
- **`gws-drive-no-public-discoverable`** — fatal: "anyone with the link" *plus*
  link discovery means the file is reachable by search crawlers, not just by
  people given the link. Change the share setting back to "Restricted".
- **`gws-oauth-no-high-risk-app`** — review each flagged app in
  `oauth_tokens`; revoke grants for apps that no longer need that access
  (*Admin console → Security → API controls → App access control*).

## Running it

```bash
# One-shot audit of your own account (after the gcloud login above)
kxn gather -p googleworkspace -t all | kxn scan -R rules --include "gws-*"

# Drive only (no admin rights needed)
kxn gather -p googleworkspace -t drive_files | kxn scan -R rules --include "gws-drive-*"

# Whole-domain audit via a service account
kxn gather -p googleworkspace -t all \
  -C '{"credentials_file":"sa.json","subject":"admin@corp.com","domain":"corp.com","scan_all_users":true}' \
  | kxn scan -R rules --include "gws-*"

# Continuous monitoring (copy the example template in place first)
cd deploy/examples/google-workspace && cp kxn.toml.example kxn.toml
kxn watch --config kxn.toml
```

## Limitations

- Both modes use **read-only** scopes; kxn never modifies Workspace data.
- `drive_files` lists files **owned by** the scanned user (`'me' in owners`). It
  does not enumerate shared drives or files owned by others.
- `scan_all_users` makes one Drive and one token API pass per active user; on
  large domains it is bound by Google's per-project quota — run it on a daily
  interval.
- The `users`, device, group, domain and role resources are only visible to
  Workspace admins, by Google's design.

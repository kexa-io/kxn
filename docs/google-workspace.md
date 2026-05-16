# Google Workspace audit

The `googleworkspace` native provider audits a Google Workspace organization
for two high-impact security issues:

- **2-Step Verification (2FA/MFA)** — users, and especially admins, whose
  accounts are protected by a password alone.
- **Google Drive sharing** — files exposed through public links or shared with
  people outside the organization.

It calls the Google **Admin SDK** and **Drive API** directly. No Terraform
provider and no extra tooling are involved.

A ready-to-run example lives in
[`deploy/examples/google-workspace/`](../deploy/examples/google-workspace/) —
that directory's `README.md` is the quickest path to a first scan. This page is
the full reference.

> **Note** — the separate `rules/google-workspace-cis.toml` file targets the
> Terraform `workspace` profile and a different data shape. The rules described
> here are in `rules/google-workspace-audit.toml`, which is the file that works
> with this native provider.

## How it works

`kxn gather -p googleworkspace` collects two resource types and emits JSON;
`kxn scan` then evaluates the `google-workspace-audit.toml` rules against it.

```
gather (Admin SDK + Drive API)  ──▶  JSON resources  ──▶  scan (rules)  ──▶  pass/fail report
```

## Authentication

The provider supports two modes. It picks the mode from the config it is given.

### Mode A — OAuth / Application Default Credentials

Used when no service account is configured. The provider obtains a token from
Application Default Credentials, exactly like the `gcloud` CLI. Authenticate
once:

```bash
gcloud auth application-default login \
  --scopes=https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/drive.metadata.readonly
```

- Scans the **authenticated account**.
- `drive_files` works for any user.
- `users` (2FA status) requires the account to be a **Workspace admin** — the
  Admin SDK only exposes 2SV status to admins.

### Mode B — service account with domain-wide delegation

Used when `credentials_file` (or `credentials`) is provided. The provider signs
a JWT assertion and exchanges it for an access token that **impersonates** a
user, which is what lets it read directory and Drive data across the domain.

Setup:

1. Create a service account and a JSON key in a Google Cloud project.
2. In the [Admin console](https://admin.google.com/) → *Security → Access and
   data control → API controls → Domain-wide delegation*, authorize the service
   account's **Client ID** for these scopes:
   ```
   https://www.googleapis.com/auth/admin.directory.user.readonly
   https://www.googleapis.com/auth/drive.metadata.readonly
   ```
3. Enable the **Admin SDK API** and **Google Drive API** in the Cloud project.

`subject` must be a Workspace admin — the provider impersonates it for the
directory listing.

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
| `scan_all_users` | `GOOGLE_WORKSPACE_SCAN_ALL_USERS` | `true` to walk every user's Drive (Mode B only) |
| `drive_user` | `GOOGLE_WORKSPACE_DRIVE_USER` | Scan one specific user's Drive instead of `subject` |
| `access_token` | `GOOGLE_WORKSPACE_ACCESS_TOKEN` | Use a pre-obtained OAuth access token directly |

## Resource types

### `users`

One object per directory user.

| Field | Description |
|-------|-------------|
| `email` | Primary email |
| `full_name` | Display name |
| `is_admin` | Super administrator |
| `is_delegated_admin` | Has a delegated admin role |
| `is_enrolled_2sv` | 2-Step Verification is set up on the account |
| `is_enforced_2sv` | 2SV is enforced on the account by policy |
| `suspended` | Account is suspended |
| `archived` | Account is archived |
| `last_login_time` | Last login timestamp |
| `creation_time` | Account creation timestamp |
| `org_unit_path` | Organizational unit |

### `drive_files`

One object per Drive file owned by the scanned user(s).

| Field | Description |
|-------|-------------|
| `id` | Drive file ID |
| `name` | File name |
| `mime_type` | MIME type |
| `owner` | Owner email |
| `scanned_user` | The account whose Drive this file came from |
| `web_view_link` | Link to open the file |
| `modified_time` | Last modified timestamp |
| `shared` | The file is shared with anyone other than the owner |
| `shared_with_anyone` | Has an "anyone with the link" permission |
| `public_discoverable` | Public **and** indexable by search engines |
| `shared_externally` | Shared publicly or with a domain/account outside the org |
| `external_recipients` | List of external emails/domains the file is shared with |
| `permission_count` | Number of permission entries on the file |

## Rules

Defined in `rules/google-workspace-audit.toml`. Severity levels: `info` (0),
`warning` (1), `error` (2), `fatal` (3).

### `gws-user-2sv-enrolled` — error

**Checks:** every active user has 2-Step Verification enabled
(`is_enrolled_2sv`). Suspended accounts are treated as compliant because they
cannot sign in.

**Why:** an account protected only by a password is the most common entry point
for an attacker — a single phished or reused password is enough.

**Fix:** ask the user to enroll a second factor, or enforce 2SV org-wide in the
Admin console (*Security → Authentication → 2-step verification*).

### `gws-admin-2sv-enrolled` — fatal

**Checks:** every administrator account has 2-Step Verification enabled.

**Why:** a compromised admin account exposes the entire domain — it can read any
mailbox, change any setting, and create new accounts. Admins without 2FA are the
single highest-value target.

**Fix:** enroll 2SV on the admin account immediately; prefer a hardware security
key for administrators.

### `gws-drive-no-public-discoverable` — fatal

**Checks:** no Drive file is public *and* search-indexed (`public_discoverable`)
— an "anyone with the link" permission where link discovery is allowed.

**Why:** such files can be found by anyone on the open internet, including
search crawlers — not just people who were given the link.

**Fix:** in the file's *Share* dialog, change "Anyone with the link" back to
"Restricted", or to a specific audience.

### `gws-drive-no-public-link` — error

**Checks:** no Drive file has an "anyone with the link" permission
(`shared_with_anyone`).

**Why:** anyone who obtains the link — forwarded, leaked, or guessed — can open
the file with no authentication.

**Fix:** restrict the file to named users or your organization.

### `gws-drive-no-external-share` — warning

**Checks:** no Drive file is shared with a user, group, or domain outside the
organization (`shared_externally`). The `external_recipients` field lists who.

**Why:** external sharing is often legitimate (partners, contractors) but should
be reviewed — stale external grants are a slow data leak.

**Fix:** review `external_recipients`; remove access that is no longer needed.

## Running it

```bash
# One-shot audit of your own account
gcloud auth application-default login --scopes=https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/drive.metadata.readonly
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

- The provider reads only what its scopes allow — both scopes are **read-only**;
  kxn never modifies Workspace data.
- `drive_files` lists files **owned by** the scanned user (`'me' in owners`). It
  does not enumerate shared drives or files owned by others.
- `scan_all_users` makes one Drive API pass per active user; on large domains it
  is rate-limited by Google's per-project quota — run it on a daily interval.
- 2FA status (`users`) is only visible to Workspace admins, by Google's design.

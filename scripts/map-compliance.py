#!/usr/bin/env python3
"""Tag every security rule of rules/*.toml with NIS2, SOC 2 and GDPR controls.

Usage: python3 scripts/map-compliance.py [--check] [--report]

Each rule is sorted into one control category from its name, description,
object and condition properties (CATEGORIES below, first match wins). The
category gives the NIS2 art. 21(2) measure, the SOC 2 Trust Services Criterion
and the GDPR article; a [[rules.compliance]] block is appended for each
framework the rule does not carry yet. A NIS2 control a rule already has is
kept, never replaced.

Only security rules are tagged. Performance and capacity rules (the
*-monitoring and *-dba packs: CPU, connections, cache hits...) match no
category and keep no new block, unless their text is about security (audit
logs, failed logins, TLS...).

--check   exit 1 when a file would change (CI: every rule is mapped)
--report  print the category of every rule instead of writing files

The mapping is kept with the rules rather than generated at scan time so that
a reviewer can read, and override, every control of every rule: a hand-written
block for a framework is never touched.
"""
import glob
import re
import sys
import tomllib
from pathlib import Path

RULES = Path(__file__).resolve().parent.parent / "rules"

NIS2 = {
    "b": ("21.2.b", "Incident handling"),
    "c": ("21.2.c", "Business continuity"),
    "d": ("21.2.d", "Supply chain security"),
    "e": ("21.2.e", "Security in acquisition, development and maintenance"),
    "h": ("21.2.h", "Cryptography"),
    "i": ("21.2.i", "Access control and asset management"),
    "j": ("21.2.j", "Multi-factor authentication"),
}

# One wording per control, close to the text of the framework.
SOC2 = {
    "CC6.1": "Logical access security and encryption",
    "CC6.6": "Protection against threats from outside system boundaries",
    "CC6.7": "Protection of data in transmission",
    "CC7.1": "Detection of configuration changes and vulnerabilities",
    "CC7.2": "Monitoring of system components for anomalies",
    "CC8.1": "Change management",
    "CC9.2": "Vendor and business partner risk",
    "A1.2": "Backup and recovery infrastructure",
}
GDPR = {
    "25": "Data protection by design and by default",
    "32.1.a": "Pseudonymisation and encryption of personal data",
    "32.1.b": "Confidentiality, integrity, availability and resilience of processing systems",
    "32.1.c": "Ability to restore availability and access to personal data",
    "33": "Notification of a personal data breach (detection)",
}

# category: (NIS2 key, SOC 2 control, GDPR article or None)
MAP = {
    "mfa": ("j", "CC6.1", "32.1.b"),
    "backup": ("c", "A1.2", "32.1.c"),
    "transit": ("h", "CC6.7", "32.1.a"),
    "rest": ("h", "CC6.1", "32.1.a"),
    "exposure": ("i", "CC6.6", "25"),
    "logging": ("b", "CC7.2", "33"),
    "vuln": ("e", "CC7.1", "32.1.b"),
    "change": ("e", "CC8.1", None),
    "supply": ("d", "CC9.2", None),
    "access": ("i", "CC6.1", "32.1.b"),
    "hardening": ("e", "CC7.1", "32.1.b"),
}

# Ordered: the first category whose pattern matches the rule's text wins.
CATEGORIES = [
    ("mfa", r"\bmfa\b|multi.?factor|2fa|two.?factor|two.?step|2sv|phishing.?resistant|fido|authenticator app"),
    ("access", r"privileg|\bgrants?\b|password.?(polic|age|length|complex|expir|reuse|history|lockout|set|exist)|"
               r"(max|min).?password|have.?passwords?|lockout|activation.?approval|signup"),
    ("exposure", r"public.?(access|network|ip|endpoint|bucket|read|acl|blob|fork|binding|project)|"
                 r"anonymous|allusers|allauthenticated|internet"),
    ("backup", r"(?<!max)backup|snapshot|versioning|soft.?delete|point.?in.?time|\bpitr\b|archive_mode|archive_command|"
               r"geo.?redundan|multi.?az|purge.?protection|deletion.?protection|recovery|replica"),
    ("transit", r"\btls\b|dkim|dmarc|\bspf\b|\bssl|https|hsts|cipher|certificate|\bcerts?\b|x509|secure.?transport|"
                r"in.?transit|starttls|smtp.?auth"),
    ("rest", r"encrypt|\bkms\b|cmek|\bcmk\b|csek|\btde\b|(key|secret|credential|kms).{0,20}rotat|rotat.{0,20}(key|secret|credential)|rotation.?period|expir|secret|scram|md5|"
             r"password_encryption|hsm|key.?vault"),
    ("vuln", r"\bscan(s|ning)?\b|\bcve|vulnerab|\bkev\b|epss|patch|outdated|end.?of.?life|\beol\b|upgrade|updates?\b|"
             r"packages?\b|defender|malware|antivirus|secret.?scanning"),
    ("logging", r"\blogs?\b|logging|\blog_|_log\b|audit|alert|cloudtrail|\btrail|flow.?log|syslog|journal|"
                r"diagnostic|monitor|siem|activity|failed.?login|auth.?fail|sign.?in.?risk|user.?risk"),
    ("change", r"branch|pull.?request|merge.?request|code.?review|codeowner|force.?push|signed.?commit|"
               r"protected.?tag|status.?check"),
    ("exposure", r"public|private.?(nodes|cluster|endpoint|access)|anonymous|internet|0\.0\.0\.0|\bbind|listen|expos|firewall|ingress|egress|"
                 r"network.?polic|\bports?\b|external.?sharing|sharing|allusers|allauthenticated|cors|"
                 r"guest|\bopen\b|whitelist|allowlist|authorized.?network|private.?endpoint|ip.?restrict"),
    ("supply", r"third.?party|marketplace|consent|outside.?collaborator|external.?collaborator|"
               r"image.?(digest|tag|provenance)|\bregistry\b|dependabot|oauth.?app|app.?registration|"
               r"cross.?tenant|supply"),
    ("access", r"user|role|admin|privileg|permission|grant|auth|password|passwd|account|root|sudo|superuser|"
               r"rbac|\biam\b|login|logon|session|token|api.?key|service.?account|owner|access|"
               r"wildcard|member|identity|\bsu\b|ssh.?key|least|device|compliant"),
]

# Packs whose rules are hardening controls even when no keyword matches.
HARDENING_PACK = re.compile(r"(cis|security|scuba|best-practices|hardening)", re.I)
# Packs of performance / capacity rules: only an explicit security match counts.
OPS_PACK = re.compile(r"(monitoring|dba|resources|^kubernetes\.toml$|proxmox)", re.I)
SKIP_FILES = {"compliance-mapping.toml"}
# In those ops packs, a rule is tagged only when its text names a security
# subject; "sessions high", "work_mem" or "schema size" are not controls.
OPS_SECURITY = re.compile(
    r"auth|password|\btls\b|\bssl|\bcerts?\b|certificate|cipher|hsts|anonymous|cors|\broot\b|scram|"
    r"permission|fail2ban|failed.?login|\bcve|\bkev\b|epss|backup|recovery.?dest|archive.?mode|"
    r"replication|version.?leak|default.?password|admin.?password", re.I)
# ... unless it measures speed or load: replication lag, a slow backup.
OPS_PERF = re.compile(r"\blag\b|slow|unavailable|directory.?per|max.?wal.?senders", re.I)


def norm_fw(name):
    return re.sub(r"[^a-z0-9]", "", name.lower())


def rule_text(rule):
    props = []

    def walk(conds):
        for c in conds or []:
            if isinstance(c, dict):
                if "property" in c:
                    props.append(str(c["property"]))
                walk(c.get("rules"))
                walk(c.get("conditions"))

    walk(rule.get("conditions"))
    obj = rule.get("object", "")
    # `user_audit` is the SSH provider's account inventory, not an audit log.
    if obj == "user_audit":
        obj = "users"
    parts = [rule.get("name", ""), rule.get("description", ""), obj, " ".join(props)]
    return " ".join(parts).replace("_", " ").replace("-", " ").lower() + " " + " ".join(props).lower()


def classify(rule, fname):
    text = rule_text(rule)
    # Workload health checks that sit in a CIS pack are not controls either.
    if re.search(r"pending.?pods|crash.?loop|oom.?kill", text):
        return None
    ops = bool(OPS_PACK.search(fname))
    if ops and (not OPS_SECURITY.search(text) or OPS_PERF.search(text)):
        return None
    for cat, pat in CATEGORIES:
        if re.search(pat, text, re.I):
            return cat
    if HARDENING_PACK.search(fname) and not ops:
        return "hardening"
    return None


def block(indent, fw, control, section):
    return (f"\n{indent}[[rules.compliance]]\n{indent}framework = \"{fw}\"\n"
            f"{indent}control = \"{control}\"\n{indent}section = \"{section}\"\n")


def process(path, report=False):
    text = path.read_text()
    data = tomllib.loads(text)
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        return text, text, []
    # Start offset of each [[rules]] header, in file order.
    starts = [m.start() for m in re.finditer(r"(?m)^[ \t]*\[\[rules\]\][ \t]*$", text)]
    if len(starts) != len(rules):
        raise SystemExit(f"{path.name}: {len(starts)} [[rules]] headers for {len(rules)} rules")
    m = re.search(r"(?m)^([ \t]*)\[\[rules\.compliance\]\]", text)
    indent = m.group(1) if m else ""

    # Rename the SOC-2 spelling to SOC2 everywhere first.
    new_text = text.replace('framework = "SOC-2"', 'framework = "SOC2"')
    starts = [m.start() for m in re.finditer(r"(?m)^[ \t]*\[\[rules\]\][ \t]*$", new_text)]
    bounds = starts + [len(new_text)]
    out, rows = [new_text[: bounds[0]]], []
    for i, rule in enumerate(rules):
        seg = new_text[bounds[i] : bounds[i + 1]]
        cat = classify(rule, path.name)
        rows.append((path.name, rule.get("name", "?"), cat))
        add = ""
        if cat is not None:
            have = {norm_fw(c.get("framework", "")) for c in rule.get("compliance", []) or []}
            nis2_key, soc2, gdpr = MAP[cat]
            if "nis2" not in have:
                add += block(indent, "NIS2", *NIS2[nis2_key])
            if "soc2" not in have:
                add += block(indent, "SOC2", soc2, SOC2[soc2])
            if gdpr and "gdpr" not in have:
                add += block(indent, "GDPR", gdpr, GDPR[gdpr])
        if add:
            # Append after the rule's last line, keep the blank lines that
            # separated it from the next rule.
            body = seg.rstrip("\n")
            gap = seg[len(body):]
            seg = body + "\n" + add + gap[1:]
        out.append(seg)
    return text, "".join(out), rows


def strip_compliance(data):
    for r in data.get("rules", []) or []:
        r.pop("compliance", None)
    return data


def main():
    check = "--check" in sys.argv
    report = "--report" in sys.argv
    changed = []
    for f in sorted(RULES.glob("*.toml")):
        if f.name in SKIP_FILES:
            continue
        old, new, rows = process(f)
        if report:
            for r in rows:
                print(f"{r[2] or '-':10} {r[0]:36} {r[1]}")
            continue
        if old == new:
            continue
        # The rewrite may only add compliance blocks: the rules are unchanged.
        if strip_compliance(tomllib.loads(old)) != strip_compliance(tomllib.loads(new)):
            raise SystemExit(f"{f.name}: rewrite changed more than compliance blocks")
        changed.append(f.name)
        if not check:
            f.write_text(new)
    if check and changed:
        print("not mapped, run scripts/map-compliance.py:", ", ".join(changed))
        sys.exit(1)
    if not report:
        print(f"{len(changed)} file(s) {'to update' if check else 'updated'}")


if __name__ == "__main__":
    main()

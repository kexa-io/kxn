# Claude Code skills for kxn

Drop-in [Claude Code skills](https://docs.claude.com/en/docs/claude-code/skills) that turn natural-language prompts into the right kxn commands — **no manual `kxn init`, no MCP setup, no shell expertise**.

## What's a skill?

A Claude Code skill is a small Markdown file that Claude Code loads on demand when its description matches what you're asking. Skills live in `~/.claude/skills/` (per-user) or `.claude/skills/` (per-project).

## Available skills

| Skill | When Claude loads it | What it does |
|---|---|---|
| [`kxn-scan`](kxn-scan/SKILL.md) | "scan / audit / check / harden / list CVEs / remediate" + a target | Picks the right URI, runs `kxn`, parses the output, summarizes by severity, proposes fixes (always dry-run first). |

## Install

### Per user (recommended)

```bash
git clone https://github.com/kexa-io/kxn /tmp/kxn-source
mkdir -p ~/.claude/skills
cp -r /tmp/kxn-source/skills/kxn-scan ~/.claude/skills/
```

That's it. Next time you run `claude -p "audit my server at root@prod-01"` Claude Code will detect the request, load the skill, and drive `kxn` for you.

### Per project

If you only want the skill in one repository:

```bash
mkdir -p .claude/skills
cp -r path/to/kxn/skills/kxn-scan .claude/skills/
```

Commit `.claude/skills/kxn-scan/` so your teammates get the skill on their machines too.

## Verify it loaded

```bash
claude -p "what kxn skills do you have access to?"
# Expected: a list including `kxn-scan` with a description matching the SKILL.md frontmatter.
```

If Claude says it doesn't see the skill, check the file path matches `~/.claude/skills/<skill-name>/SKILL.md` (note the uppercase `SKILL.md`).

## Usage examples

After install, just ask:

```bash
claude -p "audit my server at root@prod-01 against CIS"
claude -p "is my postgres at db.prod:5432 properly hardened?"
claude -p "any installed package on prod-01 matching CISA KEV?"
claude -p "scan my k8s cluster for privileged pods or wildcard RBAC"
claude -p "propose a remediation plan for all CIS errors on prod-01"
```

Claude picks the right kxn invocation, parses the JSON output, surfaces what matters, and waits for you to approve before applying any remediation.

## Updating

Pull the latest version of the skill any time:

```bash
cd /tmp/kxn-source && git pull
cp -r /tmp/kxn-source/skills/kxn-scan ~/.claude/skills/
```

## Contributing

PRs welcome on <https://github.com/kexa-io/kxn>. New skills (e.g. `kxn-monitor` for setting up the watch loop, `kxn-fleet` for multi-target scans) are encouraged — keep the SKILL.md frontmatter description tight so Claude loads it only when relevant.

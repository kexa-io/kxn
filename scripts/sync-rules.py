#!/usr/bin/env python3
"""Mirror rules/*.toml into a checkout of kexa-io/kxn-rules.

`kxn <uri>` and `kxn rules pull` download rule packs from kexa-io/kxn-rules,
laid out as <provider>/<name>.toml. This repository keeps them flat in rules/
as <provider>-<name>.toml. This script maps one layout onto the other:

  rules/aws-cis.toml          -> aws/cis.toml        (provider prefix dropped)
  rules/packages-cve.toml     -> ssh/packages-cve.toml (no prefix: name kept)
  rules/ssh-monitoring.toml   -> ssh/ssh-monitoring.toml (would collide with
                                 rules/monitoring.toml -> ssh/monitoring.toml)

The provider comes from each pack's `metadata.provider`.

kxn-rules also holds packs that live only there, so a file is deleted only
when this script wrote it on an earlier run and kxn no longer has it: the
files written are recorded in `.kxn-sync-manifest.json` at the root of the
checkout (a dot-file, which `kxn rules pull` never downloads). A pack
renamed or removed in kxn is then removed from kxn-rules too, instead of
being loaded forever next to its replacement.

Usage: sync-rules.py <rules-dir> <kxn-rules-checkout>

kexa-io/kxn-rules runs it daily from its own workflow
(.github/workflows/sync-from-kxn.yml there), against the latest kxn release.
"""

import json
import sys
import tomllib
from pathlib import Path

MANIFEST = ".kxn-sync-manifest.json"


def destinations(rules_dir: Path) -> dict[str, Path]:
    packs = []
    for src in sorted(rules_dir.glob("*.toml")):
        with src.open("rb") as f:
            provider = (tomllib.load(f).get("metadata") or {}).get("provider")
        if not provider:
            print(f"skip {src.name}: no metadata.provider")
            continue
        packs.append((src, provider))

    mapping: dict[str, Path] = {}
    # Unprefixed names first, so they keep their name and a prefixed pack that
    # would land on the same path keeps its full name instead.
    for src, provider in sorted(packs, key=lambda p: p[0].name.startswith(p[1] + "-")):
        name = src.name
        short = name[len(provider) + 1:] if name.startswith(provider + "-") else name
        dst = f"{provider}/{short}"
        if dst in mapping:
            dst = f"{provider}/{name}"
        if dst in mapping:
            sys.exit(f"collision on {dst}: {mapping[dst].name} and {name}")
        mapping[dst] = src
    return mapping


def previously_synced(out_dir: Path) -> set[str]:
    path = out_dir / MANIFEST
    if not path.exists():
        return set()
    return set(json.loads(path.read_text()).get("files", []))


def sync(rules_dir: Path, out_dir: Path) -> int:
    mapping = destinations(rules_dir)
    if not mapping:
        # An empty or unreadable rules/ must not wipe kxn-rules.
        sys.exit(f"no rule pack found in {rules_dir}")
    changed = 0
    for dst, src in sorted(mapping.items()):
        target = out_dir / dst
        content = src.read_bytes()
        if target.exists() and target.read_bytes() == content:
            continue
        action = "update" if target.exists() else "add"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        print(f"{action} {dst} <- rules/{src.name}")
        changed += 1
    for dst in sorted(previously_synced(out_dir) - set(mapping)):
        target = out_dir / dst
        if target.exists():
            target.unlink()
            print(f"delete {dst} (no longer in kxn)")
            changed += 1
    (out_dir / MANIFEST).write_text(json.dumps({"files": sorted(mapping)}, indent=1) + "\n")
    return changed


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    changed = sync(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"{changed} file(s) changed")


if __name__ == "__main__":
    main()

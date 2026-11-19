#!/usr/bin/env python3
"""Mirror rules/*.toml into a checkout of kexa-io/kxn-rules.

`kxn <uri>` and `kxn rules pull` download rule packs from kexa-io/kxn-rules,
laid out as <provider>/<name>.toml. This repository keeps them flat in rules/
as <provider>-<name>.toml. This script maps one layout onto the other:

  rules/aws-cis.toml          -> aws/cis.toml        (provider prefix dropped)
  rules/packages-cve.toml     -> ssh/packages-cve.toml (no prefix: name kept)
  rules/ssh-monitoring.toml   -> ssh/ssh-monitoring.toml (would collide with
                                 rules/monitoring.toml -> ssh/monitoring.toml)

The provider comes from each pack's `metadata.provider`. Files are written or
overwritten, never deleted: kxn-rules also holds packs that live only there.

Usage: sync-rules.py <rules-dir> <kxn-rules-checkout>
"""

import sys
import tomllib
from pathlib import Path


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


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    rules_dir, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    changed = 0
    for dst, src in sorted(destinations(rules_dir).items()):
        target = out_dir / dst
        content = src.read_bytes()
        if target.exists() and target.read_bytes() == content:
            continue
        action = "update" if target.exists() else "add"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        print(f"{action} {dst} <- rules/{src.name}")
        changed += 1
    print(f"{changed} file(s) changed")


if __name__ == "__main__":
    main()

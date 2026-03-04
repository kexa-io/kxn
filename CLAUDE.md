# kxn — Kexa Next Generation

## Vision

kxn (CLI) / kexang (projet) est un scanner de compliance multi-cloud en Rust. Successeur de [Kexa](https://github.com/kexa-io/Kexa) (TypeScript).

Différences clés avec Kexa :
- **Rust** au lieu de TypeScript — performance, binaire unique, pas de runtime
- **TOML** au lieu de YAML — config typée, lisible, interpolation de variables
- **Terraform providers natifs via gRPC** — au lieu de 17 gatherers maintenus à la main
- **MCP server intégré** — Claude Code / Claude Desktop comme interface naturelle
- **Stateless** — pas de state file, discovery via tags

## POC existant

Un POC fonctionnel existe à `/Users/patrick/dev/pszymkowiak/icl/` (projet ICL — Infrastructure Configuration Language). Ce POC implémente :
- Bridge gRPC vers Terraform providers (`tfplugin5.proto` + `tfplugin6.proto`) via tonic/prost
- Lancement de providers Terraform comme subprocess (go-plugin handshake)
- `ReadDataSource` pour gatherer des resources
- Config TOML avec interpolation de variables
- Tests fonctionnels : `azurerm`, `azure`, `null`, `random`

**Le bridge gRPC de ICL est la base de kxn-providers.** Le copier et l'adapter.

## Architecture

```
kxn scan --provider aws --rules cis.toml
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                        kxn-cli                              │
│  Commands: scan, check, gather, list-rules, list-providers  │
│            serve --mcp (MCP server stdio)                   │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌──────────────────┐ ┌────────────────┐ ┌──────────────────┐
│   kxn-rules      │ │   kxn-core     │ │  kxn-providers   │
│                  │ │                │ │                  │
│ TOML parser      │ │ Rules engine   │ │ gRPC bridge to   │
│ Rule validation  │ │ Conditions:    │ │ Terraform        │
│ Rule index       │ │  EQUAL         │ │ providers        │
│                  │ │  DIFFERENT     │ │                  │
│                  │ │  SUP/INF       │ │ Custom:          │
│                  │ │  SUP_OR_EQUAL  │ │  SSH (direct)    │
│                  │ │  INF_OR_EQUAL  │ │  PostgreSQL      │
│                  │ │  REGEX         │ │  MySQL           │
│                  │ │  INCLUDE/IN    │ │                  │
│                  │ │  ParentRules   │ │ ReadDataSource   │
│                  │ │  (AND/OR/NAND/ │ │ ReadResource     │
│                  │ │   NOR nested)  │ │                  │
└──────────────────┘ └────────────────┘ └──────────────────┘
                              │
                              ▼
                     ┌────────────────┐
                     │   kxn-mcp      │
                     │                │
                     │ MCP server     │
                     │ stdio/SSE      │
                     │ 5 tools        │
                     └────────────────┘
```

## Structure du projet

```
kxn/
├── Cargo.toml                  # Workspace
├── CLAUDE.md
├── crates/
│   ├── kxn-cli/                # Binary (clap)
│   ├── kxn-core/               # Rules engine, conditions, scan logic
│   ├── kxn-rules/              # TOML rule parser, validation
│   ├── kxn-providers/          # Terraform gRPC bridge + custom gatherers
│   └── kxn-mcp/                # MCP server (stdio transport)
├── proto/
│   ├── tfplugin5.proto
│   └── tfplugin6.proto
├── rules/                      # Example TOML rules
│   ├── ssh-cis.toml
│   ├── postgresql-cis.toml
│   └── mysql-cis.toml
└── tests/
    ├── integration/
    └── fixtures/
```

## Format des règles (TOML)

```toml
[metadata]
version = "1.0.0"
provider = "ssh"

[[rules]]
name = "ssh-cis-5.2.10-no-root-login"
description = "CIS 5.2.10 - Ensure SSH root login is disabled"
level = 2                       # 0=info, 1=warning, 2=error, 3=fatal
object = "sshd_config"

  [[rules.conditions]]
  property = "permitrootlogin"
  condition = "EQUAL"
  value = "no"

[[rules]]
name = "ssh-cis-5.2.19-disable-empty-passwords"
description = "CIS 5.2.19 - Ensure SSH PermitEmptyPasswords is disabled"
level = 2
object = "sshd_config"

  [[rules.conditions]]
  operator = "OR"
  criteria = [
    { property = "permitemptypasswords", condition = "EQUAL", value = "no" },
    { property = "permitemptypasswords", condition = "EQUAL", value = "" },
  ]
```

## Conditions supportées (portées de Kexa)

| Condition | Description |
|-----------|-------------|
| `EQUAL` | `actual == expected` |
| `DIFFERENT` | `actual != expected` |
| `SUP` | `actual > expected` |
| `INF` | `actual < expected` |
| `SUP_OR_EQUAL` | `actual >= expected` |
| `INF_OR_EQUAL` | `actual <= expected` |
| `INCLUDE` | `actual` contient `expected` (string/array) |
| `NOT_INCLUDE` | inverse |
| `INCLUDE_NOT_SENSITIVE` | case-insensitive |
| `REGEX` | regex match |
| `STARTS_WITH` | prefix |
| `NOT_STARTS_WITH` | inverse |
| `ENDS_WITH` | suffix |
| `NOT_ENDS_WITH` | inverse |
| `DATE_INF` | date comparison |
| `DATE_SUP` | date comparison |

### ParentRules (nested conditions with operators)

```toml
[[rules.conditions]]
operator = "OR"           # AND, OR, NAND, NOR, XOR
criteria = [
  { property = "name", condition = "DIFFERENT", value = "avahi-daemon" },
  { property = "state", condition = "EQUAL", value = "disabled" },
]
```

Imbrication illimitée : un `criteria` peut lui-même contenir un `operator` + `criteria`.

## MCP Tools (5, identiques à Kexa MCP)

1. **`kxn_list_providers`** — Liste les providers configurés + leurs resources types
2. **`kxn_list_rules`** — Parse et liste les règles TOML
3. **`kxn_gather`** — Collecte les ressources via providers (Terraform gRPC ou custom)
4. **`kxn_scan`** — Gather + évalue les règles → violations
5. **`kxn_check_resource`** — Évalue un JSON arbitraire contre des conditions (zero infra)

## Dépendances Rust

```toml
[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
clap = { version = "4", features = ["derive"] }
thiserror = "2"
anyhow = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tonic = "0.12"
prost = "0.13"
tonic-build = "0.12"
regex = "1"
chrono = { version = "0.4", features = ["serde"] }
ssh2 = "0.9"
```

## Référence Kexa (TypeScript) à porter

Le code source Kexa est à `/Users/patrick/dev/kexa-io/Kexa/`. Fichiers clés :

- `Kexa/services/analyse.service.ts` — `checkRules()`, `checkRule()`, `gatheringRules()`, toute la logique d'évaluation des conditions
- `Kexa/models/settingFile/conditions.models.ts` — `RulesConditions`, `ParentRules`
- `Kexa/models/resultScan.models.ts` — `ResultScan`, `SubResultScan`
- `Kexa/services/addOn.service.ts` — `loadAddOns()` (gathering)
- `Kexa/mcp-server.ts` — MCP server de référence (5 tools, stdio, alert silencing)
- `Kexa/services/addOn/sshGathering.service.ts` — gatherer SSH custom

## Conventions

- **Runtime** : `cargo` pour build/test. Pas de npm/bun/node.
- **Erreurs** : `thiserror` pour les types, `anyhow` dans le CLI. Jamais `panic!` sauf `unreachable!`.
- **Async** : Tout I/O est async (tokio).
- **Tests** : `cargo test`. Tests unitaires dans chaque module, integration tests dans `tests/`.
- **Max** : 500 lignes par fichier, 50 lignes par fonction.
- **Logs** : `tracing` avec spans structurés.

## Phase 1 — MVP

1. **kxn-core** : Rules engine (conditions + ParentRules) — porter `checkRule()` de Kexa
2. **kxn-rules** : Parser TOML → modèle de règles
3. **kxn-cli** : `kxn check` (zero infra, JSON + conditions en args)
4. **kxn-providers** : Bridge gRPC Terraform (copier de ICL) + gatherer SSH
5. **kxn-cli** : `kxn scan` + `kxn gather`
6. **kxn-mcp** : MCP server stdio (5 tools)

Objectif phase 1 : scanner SSH CIS identique au Kexa MCP actuel, en Rust.

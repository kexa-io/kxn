# Changelog

## [0.28.0](https://github.com/kexa-io/kxn/compare/kxn-v0.27.2...kxn-v0.28.0) (2026-04-03)


### Features

* add --json flag to scan command ([#5](https://github.com/kexa-io/kxn/issues/5)) ([2f9744f](https://github.com/kexa-io/kxn/commit/2f9744f9fb61c70d756df6a9beeaa1e121becbcf))
* add --save flag with URI-based save backends ([#21](https://github.com/kexa-io/kxn/issues/21)) ([ca86277](https://github.com/kexa-io/kxn/commit/ca862775fe563e475ca8abd074962e7f7d5a9659))
* add 7 event-driven save backends (Kafka, Event Hubs, SNS, Pub/Sub, Redis, Splunk HEC, InfluxDB) ([d25e14d](https://github.com/kexa-io/kxn/commit/d25e14d15a9786a329c5a3457d9dd8a2d68814c3))
* add 8 alert backends (email, SMS, Teams, Jira, PagerDuty, Opsgenie, ServiceNow, Linear) ([#22](https://github.com/kexa-io/kxn/issues/22)) ([4ab5380](https://github.com/kexa-io/kxn/commit/4ab5380ccc7f56df535f6914aa2da49aedaf2f5d))
* add 885 compliance rules, gRPC provider, and multi-framework mapping ([7d34e50](https://github.com/kexa-io/kxn/commit/7d34e50a22ffd2eaaae7857467fe0c29439362db))
* add apply_to filter on rules to target specific resources by name ([#23](https://github.com/kexa-io/kxn/issues/23)) ([52a424c](https://github.com/kexa-io/kxn/commit/52a424c7251bb77635b6cae7277de0e36506c9e4))
* add CIS rules for AWS/Azure/GCP/GitHub + enhance MCP scan ([8eff94c](https://github.com/kexa-io/kxn/commit/8eff94cfa85294fef4438cd5774b494a662e63f7))
* add CLI remediate command ([f23de9f](https://github.com/kexa-io/kxn/commit/f23de9f4b34a27de3fb1c3e26cb6b2cf93f45a09))
* add compliance framework mapping and remediation actions ([#11](https://github.com/kexa-io/kxn/issues/11)) ([ec8d54a](https://github.com/kexa-io/kxn/commit/ec8d54ae144f8dfe62653fb291c6c7c9ec37ef34))
* add HTML output format with dark theme report ([2526d44](https://github.com/kexa-io/kxn/commit/2526d44e72048a48b5faba120314568b6dd267cc))
* add install.sh for private repo distribution ([372a30e](https://github.com/kexa-io/kxn/commit/372a30e2e97f4d850117f86a2c2b95a1d8b0c254))
* add K8s metrics, logs, jobs, HPA + fix scan exit flush ([b5de51f](https://github.com/kexa-io/kxn/commit/b5de51f1a034ab4ddcf6cead7dc900c7f2bcb373))
* add Kubernetes and Helm profiles, fix msgpack DynamicPseudoType decoding ([715e7bf](https://github.com/kexa-io/kxn/commit/715e7bf61c427c7d44177db0801fa611c9a71207))
* add monitoring, cloud providers, save backends, init, watch webhooks ([6bd2ac9](https://github.com/kexa-io/kxn/commit/6bd2ac99bd837b1bd3392d7c23d531ae4ae66d5e))
* add monitoring, cloud providers, save backends, init, watch webhooks ([#1](https://github.com/kexa-io/kxn/issues/1)) ([729fb93](https://github.com/kexa-io/kxn/commit/729fb93b68d18e7078fbd6549356f0b168e67fbf))
* add native GitHub provider with 8 resource types ([260e74b](https://github.com/kexa-io/kxn/commit/260e74b6cd2ae418a367ff56109ba94afb26682f))
* add oracle:// URI support in parse_target_uri and fix MONGODB_URI ([4aa75fc](https://github.com/kexa-io/kxn/commit/4aa75fcf6481f38465517ceb3b60e6379cdfc804))
* add output formats — json, csv, toml, minimal (colorized) ([775ea58](https://github.com/kexa-io/kxn/commit/775ea581070d29438be7e0b60fd97452cafe9368))
* add provider profiles for AWS, Azure, GCP, GitHub, Cloudflare, Datadog ([0677d1d](https://github.com/kexa-io/kxn/commit/0677d1ddbbdcca8e91e8082ca19e6a9bc513dd8c))
* add provider profiles for O365 and Google Workspace ([3e7d7a5](https://github.com/kexa-io/kxn/commit/3e7d7a544ffb8ff61f6302ffcff0eacb386b6362))
* add Proxmox support, SSH packages, fix NOT_ANY condition ([#7](https://github.com/kexa-io/kxn/issues/7)) ([3dd4e3a](https://github.com/kexa-io/kxn/commit/3dd4e3af27ccd99e09ba2ee72253c5e5c43dd374))
* add README.md and monitor unit tests (19 tests) ([70129fa](https://github.com/kexa-io/kxn/commit/70129fac7d87f455bbf25e78e43f68b5e6627b0e))
* add SARIF output format for GitHub Security integration ([#14](https://github.com/kexa-io/kxn/issues/14)) ([e93f331](https://github.com/kexa-io/kxn/commit/e93f3318c58479eb6b598b3d115481e052a1c04c))
* add Splunk On-Call, Zendesk, and Kafka alert backends ([934bfb3](https://github.com/kexa-io/kxn/commit/934bfb38e0c7fcfdebe4be40f2b7c5084b6f3b29))
* add URI-based quick scan and monitoring daemon ([6f6a5ba](https://github.com/kexa-io/kxn/commit/6f6a5baf51c0860d46737027630a2520a001a3b5))
* add Vault profile (4 types: auth_backends, namespaces, kv_secrets, pki_issuers) ([2a10a0a](https://github.com/kexa-io/kxn/commit/2a10a0ac22173ccb75c07270b855ace85723e8bf))
* add webhook server for reactive compliance (kxn serve --webhook) ([a0a4609](https://github.com/kexa-io/kxn/commit/a0a46094b49fb3d71647e6db15646b8347881832))
* add Windows x86_64 build target ([8bf74b7](https://github.com/kexa-io/kxn/commit/8bf74b727195f5c0fe9844ab991f06e076a19a27))
* add Windows x86_64 build target ([526eb6b](https://github.com/kexa-io/kxn/commit/526eb6b750769063ff5711ee74a9e2ab35db98f9))
* agent tools integration — 9 agents + tool schema export ([91f9df0](https://github.com/kexa-io/kxn/commit/91f9df03277e48ce9e5f40e2acde29b01adf3506))
* colorized remediate output + scanning spinner ([413b8ba](https://github.com/kexa-io/kxn/commit/413b8ba801d86e5ac0b9ac34f5b3aa6edf4993d9))
* CVE detection + output formats ([a46aaa6](https://github.com/kexa-io/kxn/commit/a46aaa68b8716769b096be4c3954cb04b41eea34))
* CVE detection on SSH packages via local SQLite DB ([48d4536](https://github.com/kexa-io/kxn/commit/48d45360173b743c1f91e24362a5526beb312f3e))
* DBA administration mode for PostgreSQL, MySQL, Oracle, MongoDB ([08c260e](https://github.com/kexa-io/kxn/commit/08c260e5fc003606c81537be06b749e45e1d4571))
* enrich profiles with comprehensive data sources from agent research ([0857d9a](https://github.com/kexa-io/kxn/commit/0857d9af0281bd1ac31b96ee1b92d5a7ec36434c))
* expand Kubernetes native provider with 9 new resource types + CIS rules ([#13](https://github.com/kexa-io/kxn/issues/13)) ([b2f4136](https://github.com/kexa-io/kxn/commit/b2f413631d1efa593c12ab9d3892b176ef15d33b))
* **github:** expand native provider to 25 resource types ([408bfdc](https://github.com/kexa-io/kxn/commit/408bfdce94ed051e1c5715a19cdc44d84f08dc37))
* kxn MVP - rules engine, providers, CLI, MCP server ([f711952](https://github.com/kexa-io/kxn/commit/f71195282a04669e219a5d63884cdbbbe464fb34))
* kxn_remediate MCP tool, multi-client init, URI credential redaction ([6ab5157](https://github.com/kexa-io/kxn/commit/6ab5157710c86e9d62c71b3e0ad87c24628722b4))
* kxn.toml config with mandatory/optional rule sets ([4badd1e](https://github.com/kexa-io/kxn/commit/4badd1eff55ac59285be94bd3aed82e3f0a2d798))
* kxn.toml config with secret interpolation, list-targets, MCP integration ([832fcd9](https://github.com/kexa-io/kxn/commit/832fcd9a66fbc9f68e318e270a5bdec162fdcf95))
* MCP scan with target parameter — auto gather + filter rules from kxn.toml ([becc429](https://github.com/kexa-io/kxn/commit/becc4295b791b8cad619267035cc494d5140f1bc))
* **mcp:** expose all 26 Kubernetes resource types in tool discovery ([377c754](https://github.com/kexa-io/kxn/commit/377c754ea75410da810071bc47f55d7fdabb4ea4))
* parse X.509 certificates in HTTP provider (subject, issuer, days_remaining, SANs) ([1ee1faf](https://github.com/kexa-io/kxn/commit/1ee1faf97da82a278994dc2cbd884a4357c28b5e))
* rule filtering with tags, include/exclude globs, and min-level ([42b290a](https://github.com/kexa-io/kxn/commit/42b290aa5874f4e5dae75e809581e89d462fd41e))
* S3-compatible save backends, Oracle provider fixes, 56 Oracle rules ([e7afad5](https://github.com/kexa-io/kxn/commit/e7afad522377bbfd1b4aa47b4bfc7dca8976f92b))
* table-formatted output for scan and remediate ([a858320](https://github.com/kexa-io/kxn/commit/a858320b9a9ce843313e019a4fc23a90495f9091))
* table-formatted output for scan and remediate ([0a0905d](https://github.com/kexa-io/kxn/commit/0a0905dcdbd64e645bfa48bdab052e720db30df7))
* wrap webhook payloads for Discord and Slack compatibility ([cd29f7f](https://github.com/kexa-io/kxn/commit/cd29f7fa355bd1e5660ec0c22d84b9c7e24445e5))


### Bug Fixes

* 2 remaining P1 — shared HTTP client + gather_all error logging ([1c3fb88](https://github.com/kexa-io/kxn/commit/1c3fb88913487717270bfb7255cbb8cb9397f7f8))
* 3 red-team findings — timing attack, bounded caches, integer overflow ([23beef6](https://github.com/kexa-io/kxn/commit/23beef6d71f0b9215732bbb3a4f0b362543d326a))
* 4 P0 fixes — input validation + unwrap removal ([deee1ff](https://github.com/kexa-io/kxn/commit/deee1ff076a617c455a6e0f99273c8e2776f970a))
* 4 P0 security and UX fixes ([17b98f2](https://github.com/kexa-io/kxn/commit/17b98f26549b24853c111e858ed76cd41bf3745f))
* 7 P1 — K8s TLS, regex cache, webhook rules cache, NVD retry, signals ([8c670e6](https://github.com/kexa-io/kxn/commit/8c670e6f1bcc81737338555346d595101e937d87))
* 7 P1 fixes — security, performance, reliability ([bc08b67](https://github.com/kexa-io/kxn/commit/bc08b673f64e24e7c041152dc55d902e115b0707))
* 8 P0 security and performance fixes (round 3) ([547b886](https://github.com/kexa-io/kxn/commit/547b886c2f04c14db611b84be86793231a8d5d2d))
* add missing apply_to field in test helper ([6a49f62](https://github.com/kexa-io/kxn/commit/6a49f6215ca4dc32d8ac6904bdc0c4f7343b1d71))
* auto-detect data sources and support --resource-type all for Terraform providers ([#10](https://github.com/kexa-io/kxn/issues/10)) ([66c294c](https://github.com/kexa-io/kxn/commit/66c294c79729254f7ec86bd9b4f4c7c4958ef122))
* auto-detect SSH key from ~/.ssh when no password in URI ([adc49d8](https://github.com/kexa-io/kxn/commit/adc49d8ab6c433b1eb6c749d02bd6c42153c38e7))
* check/scan use rule.object to extract resources + type coercion ([ab019a7](https://github.com/kexa-io/kxn/commit/ab019a7d89fefa53aa278c5a3ce84b36f50e5ca2))
* **ci:** add protobuf-compiler to cross-build for ARM64 ([72c873f](https://github.com/kexa-io/kxn/commit/72c873f7e8d1cace8116014c2cb00caa86d83ede))
* **ci:** install protoc v28 for cross-build (proto3 optional support) ([4c0c6ce](https://github.com/kexa-io/kxn/commit/4c0c6ce5e2b1823c496692e2176a6b10c1f5f135))
* clippy ptr_arg in monitor.rs ([b9b9ff5](https://github.com/kexa-io/kxn/commit/b9b9ff57be2b2ef196052d8d60e3b1de192fdff1))
* clippy single_match in pod_logs gatherer ([3962949](https://github.com/kexa-io/kxn/commit/396294946d29e78c21001b1e88fa9c4529400893))
* clippy trim_split_whitespace and collapsible_str_replace in ssh.rs ([c8c8d9e](https://github.com/kexa-io/kxn/commit/c8c8d9ec91d1ba2ed261730da7e5d09f72a32e0c))
* config simplification, MCP tools update, SSH provider improvements ([23cdc0e](https://github.com/kexa-io/kxn/commit/23cdc0ebd56e36c1d50e9098c58800680582cdb3))
* configure release-please for Cargo workspace ([#2](https://github.com/kexa-io/kxn/issues/2)) ([cc21ed8](https://github.com/kexa-io/kxn/commit/cc21ed89b21ffabeecd22aff199c0fdf8b6ebb0f))
* CVE lookup — support wildcard vendor + show vulnerable packages ([9329b0e](https://github.com/kexa-io/kxn/commit/9329b0eb28aacbc9d18cd720fe525a7861cc4398))
* gate UnixStream and service_fn imports behind #[cfg(unix)] for Windows build ([0e318d9](https://github.com/kexa-io/kxn/commit/0e318d91411efb320a738ac6f350e9968ea3b10d))
* host binaries on public homebrew-tap releases ([9a0554a](https://github.com/kexa-io/kxn/commit/9a0554a3bf7bb1dfb8d814f96d757f62c2784d50))
* HTTP gather returns clear errors instead of null values ([#15](https://github.com/kexa-io/kxn/issues/15)) ([7939ce7](https://github.com/kexa-io/kxn/commit/7939ce7ba8d4d9c121f446162f6d01361f063fda))
* last 2 P1 — shared HTTP client + gather error logging ([8a803cc](https://github.com/kexa-io/kxn/commit/8a803cc30aeb5b3c4a94869ba8239ca1325684f7))
* P0 round 2 — input validation + panic prevention ([4861e8f](https://github.com/kexa-io/kxn/commit/4861e8f6744d53265d2b5cad934e2b99d30b13e6))
* P0 round 3 — zip/tar traversal, webhook auth, TF timeout, DB transactions ([9b8efc5](https://github.com/kexa-io/kxn/commit/9b8efc56cc4e4fed4aff4cfbf239495a89221c5f))
* P0 security — TLS, SSH host key, SQL injection, UX ([b5276f4](https://github.com/kexa-io/kxn/commit/b5276f44c70f6684ace52f6a8d520ab1648a48e3))
* red-team — timing attack, bounded caches, integer overflow ([3641759](https://github.com/kexa-io/kxn/commit/36417599290293841ca8a1bf736d658385543e1a))
* release workflow cross-compilation and macos runner ([55f983e](https://github.com/kexa-io/kxn/commit/55f983eaae47186a5ee820f09688dad7c9f3503e))
* remediate accepts numbers (--rule 1 --rule 3) in addition to rule names ([1d2a855](https://github.com/kexa-io/kxn/commit/1d2a8559e4636f543d5ab495b6a1368a7c944d9d))
* remove aarch64-linux target from release (needs cross toolchain) ([5d49f34](https://github.com/kexa-io/kxn/commit/5d49f348619803879e62651217e95b8d5fe2bc71))
* rename watch config field to avoid clap global arg conflict ([ab14fe3](https://github.com/kexa-io/kxn/commit/ab14fe33c18cdad3db9cd867e0fcf4286a04a5d2))
* replace remaining 5 reqwest::Client::new() with shared_client() ([ec283d9](https://github.com/kexa-io/kxn/commit/ec283d9d9aa2a89ece5c18dc0668aa63e8938a5f))
* resolve ${ENV} vars in MCP server and move secrets out of kxn.toml ([cb05333](https://github.com/kexa-io/kxn/commit/cb05333028d4a360a150f89cf0ead505c4cf7c77))
* resolve all clippy warnings for CI ([a46b32f](https://github.com/kexa-io/kxn/commit/a46b32faf7a96b0c658b85adc11c3327dba9aac7))
* resolve clap conflict between global --config and watch --config ([94a02c2](https://github.com/kexa-io/kxn/commit/94a02c270030677c070c52acb7b7cbf17d68ab61))
* resolve clippy warnings breaking CI ([#8](https://github.com/kexa-io/kxn/issues/8)) ([2130e4a](https://github.com/kexa-io/kxn/commit/2130e4a167852dda1383da53d9352235da167923))
* tolerant TOML parsing and flexible ComplianceRef fields for MCP scan ([7f07f5c](https://github.com/kexa-io/kxn/commit/7f07f5c49e35ab255b2bc3efef499c94d88a7cc8))
* try sudo sshd -T first for effective sshd config ([d4bfa26](https://github.com/kexa-io/kxn/commit/d4bfa268e2bc366a46d14f8cdfb9c6804b2d9698))
* use GitHubPrivateRepositoryReleaseDownloadStrategy for homebrew ([4c8c6bf](https://github.com/kexa-io/kxn/commit/4c8c6bf7cd095f36803256b08d8a17f8883a3874))
* use MONGODB_URI instead of MONGO_URI in parse_target_uri ([6badcb9](https://github.com/kexa-io/kxn/commit/6badcb93bc57a446d5a48c5686d4568f0fd9a011))
* use simple release-type for Cargo workspace compatibility ([#3](https://github.com/kexa-io/kxn/issues/3)) ([e8e432f](https://github.com/kexa-io/kxn/commit/e8e432fdbf42510ea5aefb3c24b71369d8e07a6b))


### Performance Improvements

* fix 3 P1 performance issues ([8a520b0](https://github.com/kexa-io/kxn/commit/8a520b0197871c4a3f78d879a6f715191e47e4db))
* MySQL regex cache, glob cache, CVE JOIN query ([dea3ee7](https://github.com/kexa-io/kxn/commit/dea3ee78d611dc0d4d1aed7d92a199aaba88e479))

## [0.16.0](https://github.com/kexa-io/kxn/compare/v0.15.0...v0.16.0) (2026-03-10)


### Features

* **remediation**: kxn_remediate MCP tool with 2-step workflow (list violations, then apply selected fixes)
* **remediation**: shell command batching — single service restart instead of one per rule
* **remediation**: SQL remediation support (ALTER SYSTEM SET for PostgreSQL, SET GLOBAL for MySQL)
* **remediation**: 200+ remediation actions across 15+ rule files (SSH, PostgreSQL, MySQL, Oracle, Linux, Kubernetes, Nginx, Apache, Docker, MongoDB)
* **init**: multi-client MCP setup — support for Claude Desktop, Claude Code, Gemini CLI, Cursor, Windsurf, OpenCode, Codex
* **init**: `kxn init --client gemini` to configure a specific AI client
* **security**: redact URI credentials (user:password) in kxn_list_targets and scan output
* **rules**: all 27 ssh-cis rules now have shell remediations (idempotent sed+echo pattern)
* **rules**: monitoring rules with remediations for NTP, zombies, swap, OOM


### Bug Fixes

* **security**: `redact()` now masks passwords in URIs (postgresql://user:pass@host → postgresql://***:***@host)
* **ssh**: remediation no longer breaks SSH by doing multiple service restarts — batched into one
* **remediation**: non-exhaustive pattern match on RemediationAction::Sql variant

## [0.8.0](https://github.com/kexa-io/kxn/compare/kxn-v0.7.0...kxn-v0.8.0) (2026-03-06)


### Features

* add URI-based quick scan and monitoring daemon ([6f6a5ba](https://github.com/kexa-io/kxn/commit/6f6a5baf51c0860d46737027630a2520a001a3b5))


### Bug Fixes

* clippy ptr_arg in monitor.rs ([b9b9ff5](https://github.com/kexa-io/kxn/commit/b9b9ff57be2b2ef196052d8d60e3b1de192fdff1))
* clippy trim_split_whitespace and collapsible_str_replace in ssh.rs ([c8c8d9e](https://github.com/kexa-io/kxn/commit/c8c8d9ec91d1ba2ed261730da7e5d09f72a32e0c))

## [0.7.0](https://github.com/kexa-io/kxn/compare/kxn-v0.6.1...kxn-v0.7.0) (2026-03-06)


### Features

* add 885 compliance rules, gRPC provider, and multi-framework mapping ([7d34e50](https://github.com/kexa-io/kxn/commit/7d34e50a22ffd2eaaae7857467fe0c29439362db))

## [0.6.1](https://github.com/kexa-io/kxn/compare/kxn-v0.6.0...kxn-v0.6.1) (2026-03-06)


### Bug Fixes

* HTTP gather returns clear errors instead of null values ([#15](https://github.com/kexa-io/kxn/issues/15)) ([7939ce7](https://github.com/kexa-io/kxn/commit/7939ce7ba8d4d9c121f446162f6d01361f063fda))

## [0.6.0](https://github.com/kexa-io/kxn/compare/kxn-v0.5.0...kxn-v0.6.0) (2026-03-06)


### Features

* add native GitHub provider with 8 resource types ([260e74b](https://github.com/kexa-io/kxn/commit/260e74b6cd2ae418a367ff56109ba94afb26682f))
* **github:** expand native provider to 25 resource types ([408bfdc](https://github.com/kexa-io/kxn/commit/408bfdce94ed051e1c5715a19cdc44d84f08dc37))
* **mcp:** expose all 26 Kubernetes resource types in tool discovery ([377c754](https://github.com/kexa-io/kxn/commit/377c754ea75410da810071bc47f55d7fdabb4ea4))

## [0.5.0](https://github.com/kexa-io/kxn/compare/kxn-v0.4.0...kxn-v0.5.0) (2026-03-06)


### Features

* add K8s metrics, logs, jobs, HPA + fix scan exit flush ([b5de51f](https://github.com/kexa-io/kxn/commit/b5de51f1a034ab4ddcf6cead7dc900c7f2bcb373))


### Bug Fixes

* clippy single_match in pod_logs gatherer ([3962949](https://github.com/kexa-io/kxn/commit/396294946d29e78c21001b1e88fa9c4529400893))

## [0.4.0](https://github.com/kexa-io/kxn/compare/kxn-v0.3.1...kxn-v0.4.0) (2026-03-06)


### Features

* add CIS rules for AWS/Azure/GCP/GitHub + enhance MCP scan ([8eff94c](https://github.com/kexa-io/kxn/commit/8eff94cfa85294fef4438cd5774b494a662e63f7))
* add compliance framework mapping and remediation actions ([#11](https://github.com/kexa-io/kxn/issues/11)) ([ec8d54a](https://github.com/kexa-io/kxn/commit/ec8d54ae144f8dfe62653fb291c6c7c9ec37ef34))
* add SARIF output format for GitHub Security integration ([#14](https://github.com/kexa-io/kxn/issues/14)) ([e93f331](https://github.com/kexa-io/kxn/commit/e93f3318c58479eb6b598b3d115481e052a1c04c))
* expand Kubernetes native provider with 9 new resource types + CIS rules ([#13](https://github.com/kexa-io/kxn/issues/13)) ([b2f4136](https://github.com/kexa-io/kxn/commit/b2f413631d1efa593c12ab9d3892b176ef15d33b))

## [0.3.1](https://github.com/kexa-io/kxn/compare/kxn-v0.3.0...kxn-v0.3.1) (2026-03-06)


### Bug Fixes

* auto-detect data sources and support --resource-type all for Terraform providers ([#10](https://github.com/kexa-io/kxn/issues/10)) ([66c294c](https://github.com/kexa-io/kxn/commit/66c294c79729254f7ec86bd9b4f4c7c4958ef122))
* resolve clippy warnings breaking CI ([#8](https://github.com/kexa-io/kxn/issues/8)) ([2130e4a](https://github.com/kexa-io/kxn/commit/2130e4a167852dda1383da53d9352235da167923))

## [0.3.0](https://github.com/kexa-io/kxn/compare/kxn-v0.2.0...kxn-v0.3.0) (2026-03-06)


### Features

* add --json flag to scan command ([#5](https://github.com/kexa-io/kxn/issues/5)) ([2f9744f](https://github.com/kexa-io/kxn/commit/2f9744f9fb61c70d756df6a9beeaa1e121becbcf))
* add Proxmox support, SSH packages, fix NOT_ANY condition ([#7](https://github.com/kexa-io/kxn/issues/7)) ([3dd4e3a](https://github.com/kexa-io/kxn/commit/3dd4e3af27ccd99e09ba2ee72253c5e5c43dd374))

## [0.2.0](https://github.com/kexa-io/kxn/compare/kxn-v0.1.0...kxn-v0.2.0) (2026-03-05)


### Features

* add install.sh for private repo distribution ([372a30e](https://github.com/kexa-io/kxn/commit/372a30e2e97f4d850117f86a2c2b95a1d8b0c254))
* add Kubernetes and Helm profiles, fix msgpack DynamicPseudoType decoding ([715e7bf](https://github.com/kexa-io/kxn/commit/715e7bf61c427c7d44177db0801fa611c9a71207))
* add monitoring, cloud providers, save backends, init, watch webhooks ([6bd2ac9](https://github.com/kexa-io/kxn/commit/6bd2ac99bd837b1bd3392d7c23d531ae4ae66d5e))
* add monitoring, cloud providers, save backends, init, watch webhooks ([#1](https://github.com/kexa-io/kxn/issues/1)) ([729fb93](https://github.com/kexa-io/kxn/commit/729fb93b68d18e7078fbd6549356f0b168e67fbf))
* add provider profiles for AWS, Azure, GCP, GitHub, Cloudflare, Datadog ([0677d1d](https://github.com/kexa-io/kxn/commit/0677d1ddbbdcca8e91e8082ca19e6a9bc513dd8c))
* add provider profiles for O365 and Google Workspace ([3e7d7a5](https://github.com/kexa-io/kxn/commit/3e7d7a544ffb8ff61f6302ffcff0eacb386b6362))
* add Vault profile (4 types: auth_backends, namespaces, kv_secrets, pki_issuers) ([2a10a0a](https://github.com/kexa-io/kxn/commit/2a10a0ac22173ccb75c07270b855ace85723e8bf))
* enrich profiles with comprehensive data sources from agent research ([0857d9a](https://github.com/kexa-io/kxn/commit/0857d9af0281bd1ac31b96ee1b92d5a7ec36434c))
* kxn MVP - rules engine, providers, CLI, MCP server ([f711952](https://github.com/kexa-io/kxn/commit/f71195282a04669e219a5d63884cdbbbe464fb34))
* kxn.toml config with mandatory/optional rule sets ([4badd1e](https://github.com/kexa-io/kxn/commit/4badd1eff55ac59285be94bd3aed82e3f0a2d798))
* rule filtering with tags, include/exclude globs, and min-level ([42b290a](https://github.com/kexa-io/kxn/commit/42b290aa5874f4e5dae75e809581e89d462fd41e))


### Bug Fixes

* check/scan use rule.object to extract resources + type coercion ([ab019a7](https://github.com/kexa-io/kxn/commit/ab019a7d89fefa53aa278c5a3ce84b36f50e5ca2))
* configure release-please for Cargo workspace ([#2](https://github.com/kexa-io/kxn/issues/2)) ([cc21ed8](https://github.com/kexa-io/kxn/commit/cc21ed89b21ffabeecd22aff199c0fdf8b6ebb0f))
* host binaries on public homebrew-tap releases ([9a0554a](https://github.com/kexa-io/kxn/commit/9a0554a3bf7bb1dfb8d814f96d757f62c2784d50))
* release workflow cross-compilation and macos runner ([55f983e](https://github.com/kexa-io/kxn/commit/55f983eaae47186a5ee820f09688dad7c9f3503e))
* remove aarch64-linux target from release (needs cross toolchain) ([5d49f34](https://github.com/kexa-io/kxn/commit/5d49f348619803879e62651217e95b8d5fe2bc71))
* resolve all clippy warnings for CI ([a46b32f](https://github.com/kexa-io/kxn/commit/a46b32faf7a96b0c658b85adc11c3327dba9aac7))
* use GitHubPrivateRepositoryReleaseDownloadStrategy for homebrew ([4c8c6bf](https://github.com/kexa-io/kxn/commit/4c8c6bf7cd095f36803256b08d8a17f8883a3874))
* use simple release-type for Cargo workspace compatibility ([#3](https://github.com/kexa-io/kxn/issues/3)) ([e8e432f](https://github.com/kexa-io/kxn/commit/e8e432fdbf42510ea5aefb3c24b71369d8e07a6b))

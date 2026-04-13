# Changelog

## [0.32.0](https://github.com/kexa-io/kxn/compare/v0.31.0...v0.32.0) (2026-04-13)


### Features

* parse HTTP security headers (HSTS, CSP, cookies) + http_version ([0e1a456](https://github.com/kexa-io/kxn/commit/0e1a456e926096fad3bdfc9e5374595232f40dfc))
* RHEL family support via AlmaLinux errata (covers RHEL/Rocky/Alma/CentOS/Oracle) ([3c4b789](https://github.com/kexa-io/kxn/commit/3c4b789f72f6e00d2f73f29cece885e0c5788c0e))

## [0.31.0](https://github.com/kexa-io/kxn/compare/v0.30.0...v0.31.0) (2026-04-13)


### Features

* add Alpine + Ubuntu security tracker sync (Ubuntu endpoint unreliable, Alpine works) ([74d91f7](https://github.com/kexa-io/kxn/commit/74d91f7da73667f9531a9d7dceaf8a209830ed5c))
* auto-download rules on first run + rules cached in ~/.cache/kxn/rules ([d4412d2](https://github.com/kexa-io/kxn/commit/d4412d2f1374b16fbcb229f03a187490ab7266b2))
* Debian security tracker integration for accurate CVE detection ([630a18c](https://github.com/kexa-io/kxn/commit/630a18c36a3c6138bc1896fee38d6fb7399b8360))
* kxn rules update command + clearer rule count output ([b2ec9de](https://github.com/kexa-io/kxn/commit/b2ec9de6393e7e4d5b70ed75fb3eb05e703e168f))
* kxn update command — binary + rules + CVE DB ([a12b67c](https://github.com/kexa-io/kxn/commit/a12b67ca844e81fc1189869c27ac2052311155a4))
* numbered rules in compact output + logs demo GIF ([38e57c2](https://github.com/kexa-io/kxn/commit/38e57c2604bdcb7114484f3239c3d1f9ce220273))
* per-target CVE exclusions (CVE_EXCLUDE_PACKAGES / CVE_EXCLUDE_PATTERNS) ([b64d001](https://github.com/kexa-io/kxn/commit/b64d0011fd8e8890d81281d2aad932abc1d4f36b))
* token-optimized output modes + demo GIFs ([c2403d5](https://github.com/kexa-io/kxn/commit/c2403d5fcbebf1616fd69e553845e070c27c4abe))
* Ubuntu OVAL XML ingestion (29K advisories for bionic/focal/jammy/noble) ([73a00df](https://github.com/kexa-io/kxn/commit/73a00df67b4b3f9292193eda306d92783f1513f7))


### Bug Fixes

* CVE lookup uses exact package name match (no more false positives) ([fb86dfc](https://github.com/kexa-io/kxn/commit/fb86dfc3e2e43d0f7fe328504b9b21b48076e955))
* global rules dir + load all provider rules by default ([a9995de](https://github.com/kexa-io/kxn/commit/a9995dedafd0c48e5aeda43c84d4849bee5dadba))
* k8s_master_config returns empty when not installed + fix remediate data flattening ([5c1efa8](https://github.com/kexa-io/kxn/commit/5c1efa8ca4676deb1d7d5aa9a577378596d8e13a))
* lookup_product returns 'id' not 'cve_id' — filter was never triggering ([ac80cc5](https://github.com/kexa-io/kxn/commit/ac80cc500961bd9b70535ae2abf6069475ebfea5))
* redesign remediate output — grouped by category, descriptions, cleaner format ([971f2a6](https://github.com/kexa-io/kxn/commit/971f2a6c1c02dc65c32cae70d987d38afeb199f5))
* remediate executes on remote target via SSH + colors + ia output mode ([d28e095](https://github.com/kexa-io/kxn/commit/d28e09505efdb1dc883de9b9e0c3805274b6b070))
* remediate now finds rules in ~/.cache + update README with real scan output ([1bf369d](https://github.com/kexa-io/kxn/commit/1bf369d54073dea91570d0087af844c6df7638b9))
* rules cache in ~/.cache/kxn/rules + show resource type in output ([6d1bc0a](https://github.com/kexa-io/kxn/commit/6d1bc0a05f9aa08c8d207caefd2b3eb344f829f9))
* skip CVEs tracked for a different package in the same distro release ([3ee20d9](https://github.com/kexa-io/kxn/commit/3ee20d978c9ba09fdb5f39d7008a783663ec3eb3))
* skip rules for resources not present (don't flag uninstalled tools) ([7c138fd](https://github.com/kexa-io/kxn/commit/7c138fd644f19b75d991182e9862aae503eba1c2))
* use Debian source package name for distro CVE filtering ([eb999d3](https://github.com/kexa-io/kxn/commit/eb999d30ff67bc7def1f54c4aca75ecebd4a188a))

## [0.30.0](https://github.com/kexa-io/kxn/compare/v0.29.0...v0.30.0) (2026-04-12)


### Features

* add --json flag to scan command ([#5](https://github.com/kexa-io/kxn/issues/5)) ([a660ebd](https://github.com/kexa-io/kxn/commit/a660ebdcf20425870958b3060b6b617078cfcd45))
* add --save flag with URI-based save backends ([#21](https://github.com/kexa-io/kxn/issues/21)) ([cf9722f](https://github.com/kexa-io/kxn/commit/cf9722f529b78d1228d468c4262c6b48bb0b58ef))
* add `kxn logs` command for centralized log collection from SSH fleet ([#44](https://github.com/kexa-io/kxn/issues/44)) ([3ff8c14](https://github.com/kexa-io/kxn/commit/3ff8c14595497d92f53e2035b5f84aca910e88bc))
* add 7 event-driven save backends (Kafka, Event Hubs, SNS, Pub/Sub, Redis, Splunk HEC, InfluxDB) ([c1d1b0b](https://github.com/kexa-io/kxn/commit/c1d1b0b04fc2991983239992a3487988ec8dbaeb))
* add 8 alert backends (email, SMS, Teams, Jira, PagerDuty, Opsgenie, ServiceNow, Linear) ([#22](https://github.com/kexa-io/kxn/issues/22)) ([1ac7a42](https://github.com/kexa-io/kxn/commit/1ac7a4209297691da6cb789f1df5a511942bd218))
* add 885 compliance rules, gRPC provider, and multi-framework mapping ([7e651c9](https://github.com/kexa-io/kxn/commit/7e651c9910776a56e1a615ca5d470b2cd79dfbeb))
* add apply_to filter on rules to target specific resources by name ([#23](https://github.com/kexa-io/kxn/issues/23)) ([f85b447](https://github.com/kexa-io/kxn/commit/f85b447b68c7abcaae8940dfdb01ead0ab9fb085))
* add CIS rules for AWS/Azure/GCP/GitHub + enhance MCP scan ([7e3f99e](https://github.com/kexa-io/kxn/commit/7e3f99ef2462239dbc36ab17ecda30e6eb5e9077))
* add CLI remediate command ([6a98400](https://github.com/kexa-io/kxn/commit/6a9840022fd6a390ad04fcf43f3ecc0e34a6d270))
* add compliance framework mapping and remediation actions ([#11](https://github.com/kexa-io/kxn/issues/11)) ([fb189b3](https://github.com/kexa-io/kxn/commit/fb189b31a89dae9f60b3c584f5360a44aa0e699c))
* add HTML output format with dark theme report ([7abc2ac](https://github.com/kexa-io/kxn/commit/7abc2ac6d5bed7815835a3d645b4b42d344b0766))
* add install.sh for private repo distribution ([cf380f4](https://github.com/kexa-io/kxn/commit/cf380f4a1c33df0951af8a84acab3431813f54f0))
* add K8s metrics, logs, jobs, HPA + fix scan exit flush ([48162e8](https://github.com/kexa-io/kxn/commit/48162e8b0f37a2fb15481cea02203119e28cd3ec))
* add Kubernetes and Helm profiles, fix msgpack DynamicPseudoType decoding ([94134a0](https://github.com/kexa-io/kxn/commit/94134a03082ac987f9e60622cc33fdae99be05a8))
* add monitoring, cloud providers, save backends, init, watch webhooks ([fcbd1cc](https://github.com/kexa-io/kxn/commit/fcbd1ccb42f021cfdfe5ccc2a7c8e598c6ba7519))
* add monitoring, cloud providers, save backends, init, watch webhooks ([#1](https://github.com/kexa-io/kxn/issues/1)) ([80055c0](https://github.com/kexa-io/kxn/commit/80055c0fc789f18bc1f84dc3b705732a737fb477))
* add native GitHub provider with 8 resource types ([c30b861](https://github.com/kexa-io/kxn/commit/c30b861da5e914ebb2d8ebe789ab6fa7099932ee))
* add oracle:// URI support in parse_target_uri and fix MONGODB_URI ([c8ad7e8](https://github.com/kexa-io/kxn/commit/c8ad7e82c72a86c119fb1d45174d0a44d0dfa23c))
* add output formats — json, csv, toml, minimal (colorized) ([f749d27](https://github.com/kexa-io/kxn/commit/f749d2763e29a37c4b9d3cfeb901b76787a96200))
* add provider profiles for AWS, Azure, GCP, GitHub, Cloudflare, Datadog ([470fa43](https://github.com/kexa-io/kxn/commit/470fa43bf9c21df941aca00a633211e06d76150e))
* add provider profiles for O365 and Google Workspace ([4c83ad7](https://github.com/kexa-io/kxn/commit/4c83ad7c6881bb148fcad72c24b94200a4bdf58a))
* add Proxmox support, SSH packages, fix NOT_ANY condition ([#7](https://github.com/kexa-io/kxn/issues/7)) ([8c8347a](https://github.com/kexa-io/kxn/commit/8c8347a7c6d4e9288f18afb9fc0656ca03cf08b3))
* add README.md and monitor unit tests (19 tests) ([4202df3](https://github.com/kexa-io/kxn/commit/4202df3da9b79f3070290da17c8d42bdd7b4fb7a))
* add SARIF output format for GitHub Security integration ([#14](https://github.com/kexa-io/kxn/issues/14)) ([e45a387](https://github.com/kexa-io/kxn/commit/e45a3873fab5e0c5eb131a0a2df33c0cbd622f00))
* add Splunk On-Call, Zendesk, and Kafka alert backends ([20b391e](https://github.com/kexa-io/kxn/commit/20b391e5031cef9532f1f8ad8a3af1e42f83a937))
* add URI-based quick scan and monitoring daemon ([5f1ec68](https://github.com/kexa-io/kxn/commit/5f1ec68be40139bb37c6704c25070a1935d736aa))
* add Vault profile (4 types: auth_backends, namespaces, kv_secrets, pki_issuers) ([4dc207c](https://github.com/kexa-io/kxn/commit/4dc207cff7bcec0fdea190a5591d6a2f66ec956d))
* add webhook server for reactive compliance (kxn serve --webhook) ([9754d82](https://github.com/kexa-io/kxn/commit/9754d82ceba51691f50dfc9989138ac8e93b5eae))
* add Windows x86_64 build target ([ea35011](https://github.com/kexa-io/kxn/commit/ea350112cdf68bd0d305f549525a5f480fe616bf))
* add Windows x86_64 build target ([65fc406](https://github.com/kexa-io/kxn/commit/65fc4069c3b52659a4188e3a5eba5f80b8645067))
* agent tools integration — 9 agents + tool schema export ([1d1be05](https://github.com/kexa-io/kxn/commit/1d1be05510a2551848a9da2e5733cdeb8e0b8337))
* colorized remediate output + scanning spinner ([0dc441a](https://github.com/kexa-io/kxn/commit/0dc441aa396dc5f01a06a2875a3cae1893e27741))
* CVE detection + output formats ([af8703a](https://github.com/kexa-io/kxn/commit/af8703aaf593c2338db01892b68c3d95a6a6d5a2))
* CVE detection on SSH packages via local SQLite DB ([ed92138](https://github.com/kexa-io/kxn/commit/ed92138e4c45f538552a88fb2e18ae2bda64e524))
* DBA administration mode for PostgreSQL, MySQL, Oracle, MongoDB ([06d5869](https://github.com/kexa-io/kxn/commit/06d5869a2b88be365926073a8d3ef43a9dc93f19))
* enrich profiles with comprehensive data sources from agent research ([0dce4ec](https://github.com/kexa-io/kxn/commit/0dce4ec7f0dc34ee38f0fbe2b9e098963d877729))
* expand Kubernetes native provider with 9 new resource types + CIS rules ([#13](https://github.com/kexa-io/kxn/issues/13)) ([5e8953e](https://github.com/kexa-io/kxn/commit/5e8953eb04e1b2c481528f692e35beb7ea5e0348))
* **github:** expand native provider to 25 resource types ([e266bc0](https://github.com/kexa-io/kxn/commit/e266bc0f72aacdb2ecefa5cb625fc7a36e93ddb5))
* kxn MVP - rules engine, providers, CLI, MCP server ([1d3312f](https://github.com/kexa-io/kxn/commit/1d3312fa35e7311d03dd87b094014967fe4dad38))
* kxn_remediate MCP tool, multi-client init, URI credential redaction ([4fad889](https://github.com/kexa-io/kxn/commit/4fad8890f72919e09fa16ebdfc493db07f71f58f))
* kxn.toml config with mandatory/optional rule sets ([b1cdb39](https://github.com/kexa-io/kxn/commit/b1cdb39a4836f458460f166558f97dfec456ea78))
* kxn.toml config with secret interpolation, list-targets, MCP integration ([e49c7b9](https://github.com/kexa-io/kxn/commit/e49c7b90a01b2ead8b46db1ec619fd25d2d3a076))
* MCP scan with target parameter — auto gather + filter rules from kxn.toml ([d80f126](https://github.com/kexa-io/kxn/commit/d80f126ac01295d3c9aacf84c16e9269e9da2ebc))
* **mcp:** expose all 26 Kubernetes resource types in tool discovery ([d48d9c4](https://github.com/kexa-io/kxn/commit/d48d9c41aea70a7c1ce3f11eedec0a3357c71add))
* parse X.509 certificates in HTTP provider (subject, issuer, days_remaining, SANs) ([7e8e38a](https://github.com/kexa-io/kxn/commit/7e8e38a39585c6f9a0a2516fede7a3856c2fafe8))
* rule filtering with tags, include/exclude globs, and min-level ([d4ee76a](https://github.com/kexa-io/kxn/commit/d4ee76ad11bbf55b375cd7c0be10f1ec850105c4))
* S3-compatible save backends, Oracle provider fixes, 56 Oracle rules ([52a0149](https://github.com/kexa-io/kxn/commit/52a0149c601caf95722196c4f94d23a74e4c7b1a))
* table-formatted output for scan and remediate ([85abc25](https://github.com/kexa-io/kxn/commit/85abc2503583ab05cd5b70ccb4f3107f0020d19f))
* table-formatted output for scan and remediate ([57557ee](https://github.com/kexa-io/kxn/commit/57557eecf69b6818c05d9b9961c653f0a50642c1))
* wrap webhook payloads for Discord and Slack compatibility ([ee97c5b](https://github.com/kexa-io/kxn/commit/ee97c5b9851eb6e99c33019fe3cd55d57371f849))


### Bug Fixes

* 2 remaining P1 — shared HTTP client + gather_all error logging ([6ecbb96](https://github.com/kexa-io/kxn/commit/6ecbb9621f24322e723ed77330cc5577ced84978))
* 3 red-team findings — timing attack, bounded caches, integer overflow ([446b1a5](https://github.com/kexa-io/kxn/commit/446b1a542f4816cacbf8f5174bd813c0b41b3936))
* 4 P0 fixes — input validation + unwrap removal ([8d6e636](https://github.com/kexa-io/kxn/commit/8d6e636dbeeb3d04b13704fce065c70b3de04806))
* 4 P0 security and UX fixes ([0ebdd33](https://github.com/kexa-io/kxn/commit/0ebdd33b31cbb954265113124653e16e10935653))
* 7 P1 — K8s TLS, regex cache, webhook rules cache, NVD retry, signals ([f581def](https://github.com/kexa-io/kxn/commit/f581defcc53447b4497ecf8a5cd0d4dade21fedb))
* 7 P1 fixes — security, performance, reliability ([a9cb242](https://github.com/kexa-io/kxn/commit/a9cb242278202d0e15228f1ca66f54492ac3b297))
* 8 P0 security and performance fixes (round 3) ([fb10115](https://github.com/kexa-io/kxn/commit/fb10115b53bbc7e0742340792909393dbd818060))
* add missing apply_to field in test helper ([5f0932c](https://github.com/kexa-io/kxn/commit/5f0932cb56a5ff3f152459df282b5216df524aeb))
* auto-detect data sources and support --resource-type all for Terraform providers ([#10](https://github.com/kexa-io/kxn/issues/10)) ([39e71b2](https://github.com/kexa-io/kxn/commit/39e71b2d1bcacc07547e0920382cf624a61061cc))
* auto-detect SSH key from ~/.ssh when no password in URI ([92c8d30](https://github.com/kexa-io/kxn/commit/92c8d30478e2f5fc119e9783241dccb432f6680b))
* check/scan use rule.object to extract resources + type coercion ([85b19ea](https://github.com/kexa-io/kxn/commit/85b19eac76d5483461419408a13fa499b499ff31))
* **ci:** add protobuf-compiler to cross-build for ARM64 ([c27f36c](https://github.com/kexa-io/kxn/commit/c27f36cc824b236aaedd6223de5321e58a2a8c6e))
* **ci:** install protoc v28 for cross-build (proto3 optional support) ([1dd0328](https://github.com/kexa-io/kxn/commit/1dd0328b8f412a4e198cfb9cb8cf045673697493))
* clippy ptr_arg in monitor.rs ([acd4526](https://github.com/kexa-io/kxn/commit/acd4526ec4ba98425da70cb5990776d041edc60d))
* clippy single_match in pod_logs gatherer ([8de60fe](https://github.com/kexa-io/kxn/commit/8de60fef9c60cfc4bfe6f695768c4b9e41d629a6))
* clippy trim_split_whitespace and collapsible_str_replace in ssh.rs ([db1d78a](https://github.com/kexa-io/kxn/commit/db1d78adadf86347e9d945e4e26bcff87448c040))
* config simplification, MCP tools update, SSH provider improvements ([976fe83](https://github.com/kexa-io/kxn/commit/976fe8380699ce1d20cb9ed72f62be81ccc05d13))
* configure release-please for Cargo workspace ([#2](https://github.com/kexa-io/kxn/issues/2)) ([561718c](https://github.com/kexa-io/kxn/commit/561718c13d14e60ccaecfae5bd780b21e52387c1))
* CVE lookup — support wildcard vendor + show vulnerable packages ([f2bbcf9](https://github.com/kexa-io/kxn/commit/f2bbcf9a794b76248fd75624b3d2e44074bb00fd))
* gate UnixStream and service_fn imports behind #[cfg(unix)] for Windows build ([63339a9](https://github.com/kexa-io/kxn/commit/63339a9dade922b5e1c8beaf025f737e3742b0b0))
* host binaries on public homebrew-tap releases ([3e3b9de](https://github.com/kexa-io/kxn/commit/3e3b9de0e857e84c18caff90d170feb814f83db5))
* HTTP gather returns clear errors instead of null values ([#15](https://github.com/kexa-io/kxn/issues/15)) ([eaac16d](https://github.com/kexa-io/kxn/commit/eaac16dfb7dffe8ef0a7786045eb804b30691983))
* last 2 P1 — shared HTTP client + gather error logging ([035e8e1](https://github.com/kexa-io/kxn/commit/035e8e158cdeed80dbe0bafd4296d1ff4daf620b))
* P0 round 2 — input validation + panic prevention ([ecb320b](https://github.com/kexa-io/kxn/commit/ecb320ba4ee5d75f2ada13b3710752fdd745b157))
* P0 round 3 — zip/tar traversal, webhook auth, TF timeout, DB transactions ([373ccbc](https://github.com/kexa-io/kxn/commit/373ccbc3104f5d797c722970f9b892c02d660488))
* P0 security — TLS, SSH host key, SQL injection, UX ([a9f52e3](https://github.com/kexa-io/kxn/commit/a9f52e3baf237ce98936be574337c96314ed0455))
* red-team — timing attack, bounded caches, integer overflow ([e85c805](https://github.com/kexa-io/kxn/commit/e85c805ee3599ea34b363465a6b39f246b39b553))
* release workflow cross-compilation and macos runner ([b2f9654](https://github.com/kexa-io/kxn/commit/b2f96542a7a4e4f2325d02ac285dcf94255683b1))
* release-please tag format ([f314b51](https://github.com/kexa-io/kxn/commit/f314b5182b5c45436f6bfa8cdaa9d3d329fbca8a))
* release-please tag format — remove component prefix, handle kxn-v prefix in version ([76e8318](https://github.com/kexa-io/kxn/commit/76e83185bcaab83908decfb230ddbdc398e05c23))
* remediate accepts numbers (--rule 1 --rule 3) in addition to rule names ([d2deaff](https://github.com/kexa-io/kxn/commit/d2deaff5c9b1c516c460763ff20c9321672023d5))
* remove aarch64-linux target from release (needs cross toolchain) ([24af3d6](https://github.com/kexa-io/kxn/commit/24af3d6dc47590290934351db67bd113b55122ec))
* rename watch config field to avoid clap global arg conflict ([d566669](https://github.com/kexa-io/kxn/commit/d5666693069a59e8c6fc306e58be8e4be186b0d8))
* replace remaining 5 reqwest::Client::new() with shared_client() ([653e889](https://github.com/kexa-io/kxn/commit/653e8896227973d69f4b23cdd1c5196a6938ef64))
* resolve ${ENV} vars in MCP server and move secrets out of kxn.toml ([1e05ce5](https://github.com/kexa-io/kxn/commit/1e05ce54ce90e6a18f2ae2e904a7a365e8aaca38))
* resolve all clippy warnings for CI ([f4e4e25](https://github.com/kexa-io/kxn/commit/f4e4e257061934493a42cefdd46f156df6660b5d))
* resolve clap conflict between global --config and watch --config ([2a1eab2](https://github.com/kexa-io/kxn/commit/2a1eab239a9e630f2459781a81d1632e58d8bd06))
* resolve clippy warnings breaking CI ([#8](https://github.com/kexa-io/kxn/issues/8)) ([3a62d12](https://github.com/kexa-io/kxn/commit/3a62d12dda6ddf506d4bb8e73653071a58fbbbce))
* round 2 audit — security, error handling, dedup ([6b06fce](https://github.com/kexa-io/kxn/commit/6b06fceafe222262007d8424a649de3973245da2))
* security, performance, and error handling fixes from 5-agent audit ([38fc72f](https://github.com/kexa-io/kxn/commit/38fc72f1d08db4f8e8cf5eee3a791171188cded9))
* tolerant TOML parsing and flexible ComplianceRef fields for MCP scan ([d418c38](https://github.com/kexa-io/kxn/commit/d418c3894cde76de5478bf80c5979254448b4777))
* try sudo sshd -T first for effective sshd config ([774f83e](https://github.com/kexa-io/kxn/commit/774f83ec919cf35c2987b11d191362905ef3bff5))
* use GitHubPrivateRepositoryReleaseDownloadStrategy for homebrew ([b79d14f](https://github.com/kexa-io/kxn/commit/b79d14fdf7d3adff688983f05f040fc4fecf213b))
* use MONGODB_URI instead of MONGO_URI in parse_target_uri ([4a18f7f](https://github.com/kexa-io/kxn/commit/4a18f7f1afaac8f124133d229eea8aa4a6ce1393))
* use simple release-type for Cargo workspace compatibility ([#3](https://github.com/kexa-io/kxn/issues/3)) ([217f677](https://github.com/kexa-io/kxn/commit/217f677d2500a275a9af21e6c0dea433e9dc6e60))


### Performance Improvements

* fix 3 P1 performance issues ([59d3606](https://github.com/kexa-io/kxn/commit/59d3606a0804fec856358f118cbaeedec4f158ef))
* MySQL regex cache, glob cache, CVE JOIN query ([46da62a](https://github.com/kexa-io/kxn/commit/46da62a2ee8fee202986b61e0ba5d23425ba8b99))

## [0.29.0](https://github.com/kexa-io/kxn/compare/v0.28.0...v0.29.0) (2026-04-03)


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
* release-please tag format ([d648a40](https://github.com/kexa-io/kxn/commit/d648a407d3eedcc2b40d7b6dd6d9fd94c7b2e012))
* release-please tag format — remove component prefix, handle kxn-v prefix in version ([47d9124](https://github.com/kexa-io/kxn/commit/47d91243dc5eceb67c10026714184ad6883ba6fd))
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

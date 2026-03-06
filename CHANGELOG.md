# Changelog

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

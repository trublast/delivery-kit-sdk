# Changelog

## [1.2.1](https://github.com/deckhouse/delivery-kit-sdk/compare/v1.2.0...v1.2.1) (2026-05-27)


### Bug Fixes

* **signature, image:** align Vault ACL path with cosign attest ([#86](https://github.com/deckhouse/delivery-kit-sdk/issues/86)) ([3dc9010](https://github.com/deckhouse/delivery-kit-sdk/commit/3dc901053783261b4c6308bd81f7f6bb9e8c92c9))

## [1.2.0](https://github.com/deckhouse/delivery-kit-sdk/compare/v1.1.0...v1.2.0) (2026-05-15)


### Features

* **hashivault:** add GitHub Actions OIDC support and Vault token caching ([#83](https://github.com/deckhouse/delivery-kit-sdk/issues/83)) ([4f67b93](https://github.com/deckhouse/delivery-kit-sdk/commit/4f67b938fdc8eac4bdc78e8378c38e26610812bf))

## [1.1.0](https://github.com/deckhouse/delivery-kit-sdk/compare/v1.0.0...v1.1.0) (2026-03-27)


### Features

* **signtature:** support ED25519 with Vault Transit signing ([7f3fd53](https://github.com/deckhouse/delivery-kit-sdk/commit/7f3fd5367af71da80117e748af50bbef57409920))


### Bug Fixes

* **signver:** rename vault auth envs ([#63](https://github.com/deckhouse/delivery-kit-sdk/issues/63)) ([0cbac82](https://github.com/deckhouse/delivery-kit-sdk/commit/0cbac82233339efc3b9daf29574820a6a3a55d5b))

## 1.0.0 (2025-10-16)

### Features

* **signature**: support Vault as a remote signing provider
* **signature, file**: support signing and verifying ELF binaries
* **signature, image**: support signing and verifying image manifest
* **integrity**: add dm-verity root hash calculation for image layer
* **integrity**: add utility functions for EROFS-related operations

# Changelog

## 0.1.0

### Changed (breaking default)
- `ClientOptions.base_url` now defaults to Base **mainnet**: `https://api-mainnet.basestamp.io`
  (chain 8453, contract `0x634494cB65B17163A4ca84378900Ff53A4Bba05C`). The previous default,
  `https://api.basestamp.io`, served Base Sepolia.

### Added
- `MAINNET_*` / `SEPOLIA_*` constants (base URL, chain id, contract, RPC). To keep using testnet:
  `BasestampClient(ClientOptions(base_url=SEPOLIA_BASE_URL))`.
- `__version__` now matches the package version.

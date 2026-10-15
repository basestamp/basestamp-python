# Changelog

## Unreleased

### Fixed (security / correctness)
- Merkle verification now hashes raw 32-byte node values with sorted-pair ordering,
  as the server does. Previously it hashed concatenated *hex strings*, so it rejected
  every real multi-leaf proof from the API.
- Every hash (leaf, siblings, root, input) is validated as 64 hex characters, and proofs
  are capped at 64 levels. Malformed proofs return `False` instead of raising.
- `Stamp.verify` now binds the caller's hash to the stamped hash and checks that the proof
  root matches the API's `merkle_root`.
- `get_stamp` validates `stamp_id` and URL-quotes it (path injection), and stops at
  `status == "failed"`.
- HTTP: https is enforced (http only for localhost), TLS uses an explicit verified
  context, https→http redirects are refused, response size is capped, and
  non-object JSON is rejected.
- `submit_sha256` validates the hash and normalizes it to lowercase.

### Added
- On-chain verification: `verify_root_on_chain()`, `Stamp.verify_on_chain()`,
  `JsonRpcClient`, `OnChainVerification`, `MAINNET_SIGNER_ADDRESS`, `STAMPED_TOPIC`.
- `BasestampClient.wait_for_confirmation()`, `health()`, `get_info()`; `get_stamp(...,
  poll_interval=, require_confirmed=)`.
- `Stamp.tx_id`, `block_hash`, `merkle_root`, `network`, `message`, `raw`, `is_confirmed`.
- `verify_proof()`, `compute_leaf_hash()`, `compute_merkle_root()`, `normalize_hash()`,
  `is_valid_hash()`.
- Shared cross-SDK vectors in `testdata/vectors.json` (real mainnet proofs plus tampered
  cases), and a mainnet E2E test gated by `BASESTAMP_E2E=1`.

## 0.1.0

### Changed (breaking default)
- `ClientOptions.base_url` now defaults to Base **mainnet**: `https://api-mainnet.basestamp.io`
  (chain 8453, contract `0x634494cB65B17163A4ca84378900Ff53A4Bba05C`). The previous default,
  `https://api.basestamp.io`, served Base Sepolia.

### Added
- `MAINNET_*` / `SEPOLIA_*` constants (base URL, chain id, contract, RPC). To keep using testnet:
  `BasestampClient(ClientOptions(base_url=SEPOLIA_BASE_URL))`.
- `__version__` now matches the package version.

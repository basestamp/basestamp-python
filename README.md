# Basestamp Python Client

A Python client library for the [Basestamp](https://basestamp.io) cryptographic timestamping service. Basestamp provides trustless Merkle proof verification for digital data, allowing you to create immutable, blockchain-anchored timestamps of digital content.

## Features

- **Simple API**: Clean, intuitive interface for timestamping and verification
- **Trustless verification**: Client-side Merkle proof validation with detailed error reporting
- **On-chain verification**: Confirm the merkle root was stamped by the Basestamp contract on Base via plain JSON-RPC (no web3 dependency)
- **Type safety**: Full type hints for better development experience
- **Exception handling**: Specific error messages for verification failures
- **Comprehensive testing**: 95%+ test coverage
- **Context manager support**: Clean resource management

## Installation

```bash
pip install basestamp
```

## Quick Start

```python
from basestamp import BasestampClient, calculate_sha256

# Initialize the client
client = BasestampClient()

# Calculate hash of your data
data = "Hello, Basestamp!"
hash_value = calculate_sha256(data)

# Step 1: Submit hash for timestamping
stamp_id = client.submit_sha256(hash_value)
print(f"Stamp ID: {stamp_id}")

# Step 2: Wait until the batch is confirmed on chain (usually < 1 minute)
stamp = client.wait_for_confirmation(stamp_id, timeout=600, poll_interval=10)

# Step 3: Verify the proof locally against your original hash
is_valid = stamp.verify(hash_value)
print(f"Timestamp is valid: {is_valid}")

# Step 4: Verify the merkle root was stamped on Base mainnet
result = stamp.verify_on_chain()
print(f"Anchored in tx {result.tx_hash}, block {result.block_number}")
```

## API Reference

### BasestampClient

The main client class for interacting with the Basestamp service.

```python
from basestamp import BasestampClient, ClientOptions

# Default configuration: Base mainnet (https://api-mainnet.basestamp.io, chain 8453)
client = BasestampClient()

# Base Sepolia testnet (chain 84532)
from basestamp import SEPOLIA_BASE_URL
testnet = BasestampClient(ClientOptions(base_url=SEPOLIA_BASE_URL))

# Custom configuration
options = ClientOptions(
    base_url="https://api-mainnet.basestamp.io",
    timeout=30000  # milliseconds
)
client = BasestampClient(options)
```

#### Methods

- **`submit_sha256(hash_value: str) -> str`**
  
  Submit a SHA256 hash for timestamping. Returns the unique stamp ID.

  ```python
  stamp_id = client.submit_sha256("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3")
  ```

- **`get_stamp(stamp_id: str, wait: bool = False, timeout: float = 30, poll_interval: float = 1.0, require_confirmed: bool = False) -> Stamp`**
  
  Retrieve a stamp object with verification capability. The stamp contains all necessary data including the Merkle proof (when available) and nonce for verification.

  ```python
  # Get stamp immediately (raises exception if not ready)
  stamp = client.get_stamp(stamp_id)
  
  # Wait for stamp to be ready (polls until available)
  stamp = client.get_stamp(stamp_id, wait=True, timeout=30)
  print(f"Status: {stamp.status}")
  ```

  **Parameters:**
  - `wait`: If `False` (default), raises `BasestampError` if stamp is not ready
  - `wait`: If `True`, polls the API until stamp is ready or timeout is reached  
  - `timeout`: Maximum time to wait in seconds (default: 30)
  - `poll_interval`: Seconds between polls (default: 1)
  - `require_confirmed`: If `True`, keep polling until `status == "confirmed"`. A proof
    is already returned at `batched`, before the root is on chain.
  - A stamp whose status is `failed` raises `BasestampError` immediately.

- **`wait_for_confirmation(stamp_id, timeout=600, poll_interval=10) -> Stamp`**

  Shorthand for `get_stamp(..., wait=True, require_confirmed=True)`.

- **`health()` / `get_info()`**: return the `/health` and `/info` documents.

Hashes passed to `submit_sha256` must be 64 hex characters (an optional `0x` prefix
and uppercase are accepted and normalized to lowercase). `base_url` must use `https`
(plain `http` is only accepted for `localhost`).


### Stamp Object

The `Stamp` object returned by `get_stamp()` contains all timestamp information and verification capability.

#### Properties

- `stamp_id`: Unique identifier for the stamp
- `hash`: The original hash that was timestamped  
- `timestamp`: Unix timestamp when the stamp was created
- `status`: Current status of the stamp (pending, confirmed, etc.)
- `merkle_proof`: Merkle proof object (when available)
- `nonce`: Nonce used to build the merkle leaf (when available)
- `tx_id`, `block_hash`: Anchoring transaction and block (when confirmed)
- `merkle_root`, `network`, `message`, `raw`: Other fields from the API response

#### Methods

- **`verify(original_hash: str) -> bool`**
  
  Verify that this stamp proves the existence of the original hash. Requires a nonce for cryptographic verification (automatically included in stamps retrieved from the API). Raises specific exceptions if verification fails.

  ```python
  try:
      is_valid = stamp.verify(original_hash)
      print(f"Verification successful: {is_valid}")
  except BasestampError as e:
      print(f"Verification failed: {e}")
  ```

  **Possible exceptions:**
  - `BasestampError("No Merkle proof available for verification")` - Stamp doesn't have a proof yet
  - `BasestampError("No nonce available for verification - nonce is required")` - Stamp doesn't have the required nonce
  - `BasestampError("Invalid original hash: ...")` - Not a 64-hex-character hash
  - `BasestampError("Provided hash ... does not match stamped hash ...")` - Wrong hash provided
  - `BasestampError("Calculated leaf hash ... doesn't match proof leaf hash ...")` - Nonce/leaf mismatch
  - `BasestampError("Proof root ... does not match merkle_root ...")` - Inconsistent API response
  - `BasestampError("Merkle proof verification failed: proof structure is invalid")` - Invalid proof structure
  - `BasestampError("Stamp {id} is not yet available (status: {status}). Use wait=True to poll for availability.")` - Stamp not ready without wait
  - `BasestampError("Timeout waiting for stamp {id} after {timeout} seconds")` - Polling timeout exceeded

- **`verify_on_chain(**kwargs) -> OnChainVerification`**

  Proves that the proof's merkle root was emitted by the Basestamp contract, using the
  stamp's `tx_id`. See [On-chain verification](#on-chain-verification).

## Verification algorithm

This is what the Basestamp server does, checked against real Base mainnet proofs (see
`testdata/vectors.json`):

1. **Leaf**: `leaf_hash = SHA256(nonce + hash)`, where `nonce` and `hash` are the
   strings exactly as the API returns them, concatenated nonce first and UTF-8 encoded.
   (The server's OpenAPI description says `SHA256(file_hash + nonce)`. That order is
   wrong and does not match real proofs.) The nonce is per batch, not per stamp.
2. **Path**: starting from the leaf, for each sibling compute
   `node = SHA256(min(a, b) || max(a, b))` over the raw 32-byte values (sorted-pair
   hashing). An odd node at the end of a level is paired with itself, so a sibling can
   equal the current node.
3. **Root**: the result must equal `root_hash` (and the API's `merkle_root`).
4. **On chain**: the root must appear as an event emitted by the contract (below).

Because pairs are sorted, `directions` and `leaf_index` do not affect the result and are
informational only. The proof is still sound: changing the leaf, the nonce/hash, any
sibling, the sibling order, the proof length or the root makes verification fail.

```python
from basestamp import verify_proof

# proof is the "merkle_proof" object exactly as returned by GET /stamp/{id}
ok = verify_proof(hash_value, nonce, proof, expected_root=merkle_root)
```

## On-chain verification

The mainnet contract `0x634494cB65B17163A4ca84378900Ff53A4Bba05C` (chain 8453) is minimal:
`owner()` returns the signer `0x0a3861972b28e6be9fEB826dd809aEB4F473e753`, and
`stamp(bytes32 root)` (owner-only) emits an event
`topic0 = 0x88ad9da3…b600, topic1 = root, topic2 = stamper, data = (timestamp, blockNumber)`.
It stores nothing, so there is no `eth_call` lookup for a root. Verification works from
the event log instead:

```python
from basestamp import verify_root_on_chain

# With the transaction hash (fast: one receipt lookup)
res = verify_root_on_chain(root_hash, tx_hash, rpc_url="https://mainnet.base.org")

# Without it: searches eth_getLogs, newest blocks first
res = verify_root_on_chain(root_hash, max_log_blocks=200_000)
```

The check confirms:
- the RPC endpoint reports the expected chain id;
- `owner()` at the contract address returns the expected signer;
- the transaction succeeded and was sent to the contract;
- the contract emitted the event with `topic1 == root` and `topic2 == signer`;
- the block has at least `min_confirmations` confirmations and is still canonical.

RPC calls use TLS, timeouts, a response size cap, and retry with backoff on HTTP
429/5xx. Testnet: pass `rpc_url=SEPOLIA_RPC_URL, contract_address=SEPOLIA_CONTRACT_ADDRESS,
chain_id=SEPOLIA_CHAIN_ID, signer_address=None`.

### Utility Functions

- **`calculate_sha256(data: Union[str, bytes]) -> str`**
  
  Calculate SHA256 hash of input data.

  ```python
  from basestamp import calculate_sha256
  
  hash_value = calculate_sha256("Hello, World!")
  hash_bytes = calculate_sha256(b"Hello, World!")
  ```

## Error Handling

The library provides detailed error messages for different failure scenarios:

```python
from basestamp import BasestampClient, BasestampError, calculate_sha256

hash_value = calculate_sha256("Hello, World!")
client = BasestampClient()

try:
    stamp_id = client.submit_sha256(hash_value)
    stamp = client.wait_for_confirmation(stamp_id)
    stamp.verify(hash_value)
    stamp.verify_on_chain()
except BasestampError as e:
    print(f"Basestamp error: {e}")
    if e.status_code:
        print(f"HTTP status code: {e.status_code}")
```

## Development and Testing

### Setting up Development Environment

```bash
# Clone the repository
git clone https://github.com/basestamp/basestamp-python.git
cd basestamp-python

# Create a virtual environment
python3 -m venv .venv

# Activate the virtual environment
# On macOS/Linux:
source .venv/bin/activate
# On Windows:
# .venv\Scripts\activate

# Upgrade pip to the latest version
python -m pip install --upgrade pip

# Install development dependencies (editable mode)
pip install -e ".[dev]"
```

### Running Tests and Tools

```bash
# Run tests
python -m pytest

# Run tests with coverage report
python -m pytest --cov=basestamp

# Type checking
python -m mypy basestamp/

# Code formatting
python -m black basestamp/ tests/
python -m isort basestamp/ tests/

# Linting
python -m flake8 basestamp/ tests/
```

### Shared test vectors

`testdata/vectors.json` is shared by the Python, TypeScript and Go SDKs. It is a list of
`{name, description, hash, nonce, proof, expected_root, valid}` objects, where `proof` is
the `merkle_proof` object exactly as returned by the API. It contains real mainnet proofs
and tampered negative cases. `tests/test_vectors.py` checks every entry.

### End-to-end test (Base mainnet)

```bash
BASESTAMP_E2E=1 python -m pytest tests/test_e2e.py -s -o addopts=
```

This stamps a random hash on mainnet (**each run costs the service real ETH**), waits up
to 10 minutes for confirmation, then verifies the proof locally and on chain, and prints
the transaction hash. Set `BASESTAMP_E2E_STAMP_ID` and `BASESTAMP_E2E_HASH` to re-verify
an existing stamp without submitting a new one.

### Coverage Requirements

The project enforces at least 95% test coverage (`--cov-fail-under=95`).

## License

MIT License. See LICENSE file for details.

## Support

For issues and questions:
- GitHub Issues: [basestamp-python issues](https://github.com/basestamp/basestamp-python/issues)
- Documentation: [Basestamp API Documentation](https://docs.basestamp.io)

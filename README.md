# Basestamp Python Client

A Python client library for the [Basestamp](https://basestamp.io) cryptographic timestamping service. Basestamp provides trustless Merkle proof verification for digital data, allowing you to create immutable, blockchain-anchored timestamps of digital content.

## Features

- **Simple API**: Clean, intuitive interface for timestamping and verification
- **Trustless verification**: Client-side Merkle proof validation with detailed error reporting
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

# Step 2: Get the stamp (with proof when available)
# Note: Proofs are typically available within 5-10 seconds
stamp = client.get_stamp(stamp_id, wait=True)

# Step 3: Verify the timestamp against your original hash
is_valid = stamp.verify(hash_value)
print(f"Timestamp is valid: {is_valid}")
```

## API Reference

### BasestampClient

The main client class for interacting with the Basestamp service.

```python
from basestamp import BasestampClient, ClientOptions

# Default configuration
client = BasestampClient()

# Custom configuration
options = ClientOptions(
    base_url="https://api.basestamp.io",
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

- **`get_stamp(stamp_id: str, wait: bool = False, timeout: int = 30) -> Stamp`**
  
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


### Stamp Object

The `Stamp` object returned by `get_stamp()` contains all timestamp information and verification capability.

#### Properties

- `stamp_id`: Unique identifier for the stamp
- `hash`: The original hash that was timestamped  
- `timestamp`: Unix timestamp when the stamp was created
- `status`: Current status of the stamp (pending, confirmed, etc.)
- `merkle_proof`: Merkle proof object (when available)
- `nonce`: Cryptographic nonce for verification (when available)

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
  - `BasestampError("Calculated leaf hash ... doesn't match proof leaf hash ...")` - Wrong hash provided
  - `BasestampError("Merkle proof verification failed: proof structure is invalid")` - Invalid proof structure
  - `BasestampError("Stamp {id} is not yet available (status: {status}). Use wait=True to poll for availability.")` - Stamp not ready without wait
  - `BasestampError("Timeout waiting for stamp {id} after {timeout} seconds")` - Polling timeout exceeded

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
stamp_id = client.submit_sha256(hash_value)

stamp = client.get_stamp(stamp_id, wait=True
client = BasestampClient()
stamp_id = client.submit_sha256(hash_value)

stamp = client.get_stamp(stamp_id, wait=True))
is_valid = stamp.verify(original_hash)

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

# Upgrade pip to la1test version
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

### Coverage Requirements

The project maintains 95% test coverage. Current coverage: 90.87% (working towards 95%)

## License

MIT License. See LICENSE file for details.

## Support

For issues and questions:
- GitHub Issues: [basestamp-python issues](https://github.com/basestamp/basestamp-python/issues)
- Documentation: [Basestamp API Documentation](https://docs.basestamp.io)

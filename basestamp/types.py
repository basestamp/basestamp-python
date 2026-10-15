"""Type definitions for the Basestamp client library."""

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:  # pragma: no cover
    from .chain import OnChainVerification


class BasestampError(Exception):
    """Custom exception for Basestamp-related errors."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        """Initialize BasestampError.

        Args:
            message: Error message
            status_code: Optional HTTP status code
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.status_code:
            return f"BasestampError [{self.status_code}]: {self.message}"
        return f"BasestampError: {self.message}"


# Network endpoints and on-chain parameters.
MAINNET_BASE_URL = "https://api-mainnet.basestamp.io"
SEPOLIA_BASE_URL = "https://api-sepolia.basestamp.io"
MAINNET_CHAIN_ID = 8453
MAINNET_CONTRACT_ADDRESS = "0x634494cB65B17163A4ca84378900Ff53A4Bba05C"
MAINNET_RPC_URL = "https://mainnet.base.org"
#: Address that owns the mainnet contract and is the only account able to stamp.
MAINNET_SIGNER_ADDRESS = "0x0a3861972b28e6be9fEB826dd809aEB4F473e753"
SEPOLIA_CHAIN_ID = 84532
SEPOLIA_CONTRACT_ADDRESS = "0x15Adb2cc1aEDB6610E1C801BE7E205be3A8De5d7"
SEPOLIA_RPC_URL = "https://sepolia.base.org"
#: Default API (Base mainnet since 0.1.0).
DEFAULT_BASE_URL = MAINNET_BASE_URL


@dataclass
class ClientOptions:
    """Configuration options for the Basestamp client."""

    base_url: str = DEFAULT_BASE_URL
    timeout: int = 30000  # milliseconds, matching TypeScript implementation


@dataclass
class ServerRequest:
    """Request structure for server operations."""

    hash: str


@dataclass
class MerkleProof:
    """Merkle proof data structure."""

    leaf_hash: str
    leaf_index: int
    siblings: List[str]
    directions: List[bool]
    root_hash: str
    # Additional field for new nonce-based API
    nonce: Optional[str] = None

    def verify(self, original_hash: str) -> bool:
        """Verify the Merkle proof against an original hash.

        Args:
            original_hash: The original hash to verify against the leaf_hash

        Returns:
            True if the proof is valid and matches the original hash, False otherwise

        Raises:
            ValueError: If no nonce is available in the proof

        Example:
            >>> # Proof contains nonce automatically when retrieved from server
            >>> proof = client.get_stamp("stamp_12345", wait=True).merkle_proof
            >>> is_valid = proof.verify("original_document_hash")
            >>> print(f"Proof is valid: {is_valid}")

        Note:
            The API computes leaf_hash = SHA256(nonce + original_hash) (strings).
            The proof object must contain the nonce for verification.
        """
        # Import here to avoid circular imports
        from .merkle import compute_leaf_hash, normalize_hash, verify_merkle_proof

        # Require nonce for verification
        if self.nonce is None:
            raise ValueError("Nonce is required for Merkle proof verification")

        try:
            normalize_hash(original_hash, "original hash")
            leaf = normalize_hash(self.leaf_hash, "leaf hash")
        except ValueError:
            return False
        # The server hashes the hash string as stored; the SDK submits lowercase.
        candidates = {original_hash.strip(), original_hash.strip().lower()}
        if not any(compute_leaf_hash(c, self.nonce) == leaf for c in candidates):
            return False

        # Verify the Merkle proof structure
        return verify_merkle_proof(self)


class Stamp:
    """A timestamp stamp with verification capability."""

    def __init__(
        self,
        stamp_id: str,
        hash: str,
        timestamp: int,
        status: str,
        merkle_proof: Optional[MerkleProof] = None,
        nonce: Optional[str] = None,
        tx_id: Optional[str] = None,
        block_hash: Optional[str] = None,
        merkle_root: Optional[str] = None,
        network: Optional[str] = None,
        message: Optional[str] = None,
        raw: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a Stamp object.

        Args:
            stamp_id: Unique identifier for the stamp
            hash: The original SHA256 hash that was timestamped
            timestamp: Unix timestamp when the stamp was created
            status: Current status of the stamp (pending, batched, confirmed, failed)
            merkle_proof: Merkle proof for verification (if available)
            nonce: Nonce for verification (if available)
            tx_id: Transaction that anchored the merkle root (when confirmed)
            block_hash: Block containing ``tx_id`` (when confirmed)
            merkle_root: Merkle root reported by the API
            network: Network name reported by the API
            message: Human-readable status message
            raw: The raw JSON response from the API
        """
        self.stamp_id = stamp_id
        self.hash = hash
        self.timestamp = timestamp
        self.status = status
        self.merkle_proof = merkle_proof
        self.nonce = nonce
        self.tx_id = tx_id
        self.block_hash = block_hash
        self.merkle_root = merkle_root
        self.network = network
        self.message = message
        self.raw = raw

    @property
    def is_confirmed(self) -> bool:
        """True once the API reports the batch as confirmed on chain."""
        return self.status == "confirmed"

    def verify(self, original_hash: str) -> bool:
        """Verify that this stamp proves the existence of the original hash.

        Checks that ``original_hash`` is the stamped hash, that the proof leaf
        is ``SHA256(nonce + hash)``, and that the leaf and siblings hash up to
        the proof root (which must equal the API's ``merkle_root`` if present).
        This does not contact the blockchain; see :meth:`verify_on_chain`.

        Args:
            original_hash: The original hash to verify against

        Returns:
            True if verification succeeds

        Raises:
            BasestampError: If verification fails with specific reason
        """
        from .merkle import compute_leaf_hash, normalize_hash, verify_merkle_proof

        if not self.merkle_proof:
            raise BasestampError("No Merkle proof available for verification")

        if self.nonce is None:
            raise BasestampError(
                "No nonce available for verification - nonce is required"
            )

        try:
            provided = normalize_hash(original_hash, "original hash")
        except ValueError as e:
            raise BasestampError(str(e))

        # Bind the caller's hash to the hash the server stamped.
        stamped = self.hash if isinstance(self.hash, str) else ""
        if stamped and normalize_hash_or_none(stamped) != provided:
            raise BasestampError(
                f"Provided hash {provided} does not match stamped hash {stamped}"
            )
        expected_leaf_hash = compute_leaf_hash(stamped or provided, self.nonce)
        leaf = normalize_hash_or_none(self.merkle_proof.leaf_hash)

        if expected_leaf_hash != leaf:
            raise BasestampError(
                f"Calculated leaf hash {expected_leaf_hash} doesn't match proof "
                f"leaf hash {self.merkle_proof.leaf_hash}"
            )

        if self.merkle_root is not None and normalize_hash_or_none(
            self.merkle_root
        ) != normalize_hash_or_none(self.merkle_proof.root_hash):
            raise BasestampError(
                f"Proof root {self.merkle_proof.root_hash} does not match "
                f"merkle_root {self.merkle_root}"
            )

        if not verify_merkle_proof(self.merkle_proof):
            raise BasestampError(
                "Merkle proof verification failed: proof structure is invalid"
            )

        return True

    def verify_on_chain(self, **kwargs: Any) -> "OnChainVerification":
        """Prove the proof's merkle root was stamped by the Basestamp contract.

        Uses the stamp's ``tx_id`` (receipt lookup) and ``block_hash``.
        Keyword arguments are passed to :func:`basestamp.verify_root_on_chain`
        (e.g. ``rpc_url``, ``contract_address``, ``min_confirmations``); the
        defaults target Base mainnet.

        Raises:
            BasestampError: If the stamp has no proof or the root is not on chain.
        """
        from .chain import verify_root_on_chain

        if not self.merkle_proof:
            raise BasestampError("No Merkle proof available for verification")
        kwargs.setdefault("tx_hash", self.tx_id or None)
        if self.block_hash:
            kwargs.setdefault("expected_block_hash", self.block_hash)
        return verify_root_on_chain(self.merkle_proof.root_hash, **kwargs)

    def __repr__(self) -> str:
        """Return a clean representation of the Stamp."""
        import datetime

        # Convert timestamp to readable format - handle both string and int timestamps
        timestamp_int = (
            int(self.timestamp) if isinstance(self.timestamp, str) else self.timestamp
        )
        dt = datetime.datetime.fromtimestamp(timestamp_int, tz=datetime.timezone.utc)
        readable_time = dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Build the representation
        lines = [
            f"Stamp({self.status.upper()})",
            f"├─ ID: {self.stamp_id}",
            f"├─ Hash: {self.hash}",
            f"├─ Time: {readable_time}",
        ]

        # Add proof information
        if self.merkle_proof:
            proof_size = len(self.merkle_proof.siblings)
            lines.append(f"├─ Merkle Proof: ({proof_size} siblings)")
            lines.append(f"├─ Leaf Hash: {self.merkle_proof.leaf_hash}")
            lines.append(f"├─ Root Hash: {self.merkle_proof.root_hash}")
            if self.nonce:
                lines.append(f"└─ Nonce: {self.nonce}")
            else:
                lines[-1] = f"└─ Root Hash: {self.merkle_proof.root_hash}"
        else:
            lines.append("└─ No proof available")

        return "\n".join(lines)


def normalize_hash_or_none(value: Any) -> Optional[str]:
    """Normalize a hex hash, returning None if it is malformed."""
    from .merkle import normalize_hash

    try:
        return normalize_hash(value)
    except ValueError:
        return None

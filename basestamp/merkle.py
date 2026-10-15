"""Merkle proof verification and SHA256 utilities.

Algorithm (matches the Basestamp server, verified against mainnet proofs):

* All hashes are 32-byte SHA-256 digests transported as 64-char hex strings.
* ``leaf_hash = SHA256(utf8(nonce + hash))`` where ``nonce`` and ``hash`` are
  the hex strings exactly as returned by the API (string concatenation,
  nonce first). See :func:`compute_leaf_hash`.
* Internal nodes: ``parent = SHA256(min(a, b) || max(a, b))`` over the raw
  32-byte values (sorted pair hashing; for equal-length lowercase hex this is
  the same as comparing the hex strings). An odd node at the end of a level is
  paired with itself.
* Because pairs are sorted, ``directions`` and ``leaf_index`` do not affect
  the computed root; they are informational only. Soundness comes from the
  leaf binding, every sibling and the root, all of which are checked.
"""

import hashlib
import re
from typing import Any, Dict, List, Optional, Union

from .types import MerkleProof

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

#: Upper bound on proof length (a tree of 2**64 leaves); rejects absurd input.
MAX_PROOF_DEPTH = 64


def calculate_sha256(data: Union[str, bytes]) -> str:
    """Calculate SHA256 hash of the input data.

    Args:
        data: Input data as string (UTF-8 encoded) or bytes

    Returns:
        Lowercase hexadecimal representation of the SHA256 hash

    Example:
        >>> calculate_sha256("")
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    return hashlib.sha256(data).hexdigest()


def is_valid_hash(value: Any) -> bool:
    """Return True if ``value`` is a 32-byte hex hash (optional 0x, any case)."""
    try:
        normalize_hash(value)
        return True
    except ValueError:
        return False


def normalize_hash(value: Any, what: str = "hash") -> str:
    """Validate a 32-byte hex hash and return it lowercase without ``0x``.

    Raises:
        ValueError: if ``value`` is not 64 hex characters.
    """
    if not isinstance(value, str):
        raise ValueError(
            f"Invalid {what}: expected hex string, got {type(value).__name__}"
        )
    v = value.strip().lower()
    if v.startswith("0x"):
        v = v[2:]
    if not _HEX64_RE.match(v):
        raise ValueError(f"Invalid {what}: expected 64 hex characters, got {value!r}")
    return v


def compute_leaf_hash(original_hash: str, nonce: Optional[str]) -> str:
    """Compute the merkle leaf for a stamped hash.

    ``SHA256(nonce + original_hash)`` with string concatenation, as the server
    does. ``original_hash`` must be the hash string as stored by the server
    (the SDK always submits lowercase hex). Legacy stamps without a nonce use
    the hash itself as the leaf.
    """
    if not nonce:
        return normalize_hash(original_hash)
    return calculate_sha256(nonce + original_hash)


def compute_merkle_root(leaf_hash: str, siblings: List[str]) -> str:
    """Fold ``siblings`` into ``leaf_hash`` with sorted-pair hashing.

    Raises:
        ValueError: on malformed hashes or an over-long proof.
    """
    if len(siblings) > MAX_PROOF_DEPTH:
        raise ValueError(f"Proof too long: {len(siblings)} > {MAX_PROOF_DEPTH}")
    current = bytes.fromhex(normalize_hash(leaf_hash, "leaf hash"))
    for i, sibling in enumerate(siblings):
        sib = bytes.fromhex(normalize_hash(sibling, f"sibling {i}"))
        current = _hash_pair_bytes(current, sib)
    return current.hex()


def verify_merkle_proof(proof: Optional[MerkleProof]) -> bool:
    """Verify that a Merkle proof's leaf hashes up to its root.

    This checks only the path from ``leaf_hash`` to ``root_hash``. Use
    :meth:`Stamp.verify` / :meth:`MerkleProof.verify` to also bind the leaf to
    your original hash, and :func:`basestamp.verify_root_on_chain` to prove the
    root was anchored on chain.

    Args:
        proof: MerkleProof object

    Returns:
        True if the proof is well-formed and valid, False otherwise (never raises
        for malformed input).
    """
    if not proof:
        return False
    try:
        if not isinstance(proof.siblings, list) or not isinstance(
            proof.directions, list
        ):
            return False
        if len(proof.siblings) != len(proof.directions):
            return False
        if not all(isinstance(d, bool) for d in proof.directions):
            return False
        root = normalize_hash(proof.root_hash, "root hash")
        return compute_merkle_root(proof.leaf_hash, proof.siblings) == root
    except (ValueError, TypeError, AttributeError):
        return False


def _hash_pair_bytes(a: bytes, b: bytes) -> bytes:
    if a <= b:
        return hashlib.sha256(a + b).digest()
    return hashlib.sha256(b + a).digest()


def _hash_pair(left: str, right: str) -> str:
    """Hash two hex-encoded 32-byte nodes with sorted-pair ordering.

    Args:
        left: hex hash
        right: hex hash

    Returns:
        hex SHA256(min || max) over the decoded bytes
    """
    a = bytes.fromhex(normalize_hash(left))
    b = bytes.fromhex(normalize_hash(right))
    return _hash_pair_bytes(a, b).hex()


def verify_proof(
    original_hash: str,
    nonce: Optional[str],
    proof: Union[MerkleProof, Dict[str, Any]],
    expected_root: Optional[str] = None,
) -> bool:
    """Fully verify a proof for ``original_hash`` without raising.

    Checks the leaf binding (``leaf_hash == SHA256(nonce + original_hash)``),
    the merkle path, and (if given) that the root equals ``expected_root``
    (e.g. the API's ``merkle_root`` or the root found on chain).

    Args:
        original_hash: The stamped hash (hex string as returned by the API)
        nonce: The stamp nonce (``None``/empty for legacy nonce-less stamps)
        proof: A MerkleProof or the ``merkle_proof`` dict exactly as returned
            by the API
        expected_root: Optional root the proof must commit to
    """
    try:
        if isinstance(proof, dict):
            proof = MerkleProof(
                leaf_hash=proof["leaf_hash"],
                leaf_index=proof.get("leaf_index", 0),
                siblings=proof["siblings"],
                directions=proof["directions"],
                root_hash=proof["root_hash"],
            )
        normalize_hash(original_hash, "original hash")
        if compute_leaf_hash(original_hash, nonce) != normalize_hash(proof.leaf_hash):
            return False
        if expected_root is not None and normalize_hash(
            expected_root
        ) != normalize_hash(proof.root_hash):
            return False
        return verify_merkle_proof(proof)
    except (ValueError, TypeError, KeyError, AttributeError):
        return False

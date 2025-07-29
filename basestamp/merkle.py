"""Merkle proof verification and SHA256 utilities."""

import hashlib
from typing import List, Union

from .types import MerkleProof


def calculate_sha256(data: Union[str, bytes]) -> str:
    """Calculate SHA256 hash of the input data.

    Args:
        data: Input data as string or bytes

    Returns:
        Hexadecimal representation of the SHA256 hash

    Example:
        >>> calculate_sha256("Hello, Basestamp!")
        'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    return hashlib.sha256(data).hexdigest()


def verify_merkle_proof(proof: MerkleProof) -> bool:
    """Verify a Merkle proof.

    Args:
        proof: MerkleProof object containing leaf_hash, root_hash, siblings, and directions

    Returns:
        True if the proof is valid, False otherwise

    Raises:
        ValueError: If proof structure is invalid

    Example:
        >>> proof = MerkleProof(
        ...     leaf_hash="leaf_hash",
        ...     leaf_index=0,
        ...     siblings=["sibling1", "sibling2"],
        ...     directions=[True, False],
        ...     root_hash="root_hash"
        ... )
        >>> verify_merkle_proof(proof)
        True
    """
    if not proof:
        return False

    if not proof.leaf_hash or not proof.root_hash:
        return False

    if len(proof.siblings) != len(proof.directions):
        return False

    # Start with the leaf hash
    current_hash = proof.leaf_hash

    # Iterate through siblings and directions to reconstruct the path to root
    for sibling, direction in zip(proof.siblings, proof.directions):
        if direction:
            # Direction is True: sibling is on the right, current hash on the left
            current_hash = _hash_pair(current_hash, sibling)
        else:
            # Direction is False: sibling is on the left, current hash on the right
            current_hash = _hash_pair(sibling, current_hash)

    # Check if the computed root matches the expected root
    return current_hash == proof.root_hash


def _hash_pair(left: str, right: str) -> str:
    """Hash a pair of values in deterministic order.
    
    This function combines two hash strings and hashes them deterministically.
    It matches the TypeScript implementation's hashPair function.
    
    Args:
        left: Left hash value
        right: Right hash value
        
    Returns:
        SHA256 hash of the combined values
    """
    # Combine in lexicographic order for deterministic results
    if left <= right:
        combined = left + right
    else:
        combined = right + left
    
    return calculate_sha256(combined)



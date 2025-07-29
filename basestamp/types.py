"""Type definitions for the Basestamp client library."""

from dataclasses import dataclass
from typing import List, Optional


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


@dataclass
class ClientOptions:
    """Configuration options for the Basestamp client."""

    base_url: str = "https://api.basestamp.io"
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
            >>> proof = client.get_merkle_proof("stamp_12345", wait=True)
            >>> is_valid = proof.verify("original_document_hash")
            >>> print(f"Proof is valid: {is_valid}")
            
        Note:
            The Basestamp API computes leaf_hash = SHA256(nonce + original_hash) as strings.
            The proof object must contain the nonce for verification.
        """
        # Import here to avoid circular imports
        from .merkle import verify_merkle_proof, calculate_sha256
        
        # Require nonce for verification
        if self.nonce is None:
            raise ValueError("Nonce is required for Merkle proof verification")
        
        # Calculate expected leaf hash: SHA256(nonce + original_hash)
        concatenated = self.nonce + original_hash
        expected_leaf_hash = calculate_sha256(concatenated)
        
        # Verify leaf hash matches
        if expected_leaf_hash != self.leaf_hash:
            return False
            
        # Verify the Merkle proof structure
        return verify_merkle_proof(self)




class Stamp:
    """A timestamp stamp with verification capability."""
    
    def __init__(self, stamp_id: str, hash: str, timestamp: int, status: str, 
                 merkle_proof: Optional[MerkleProof] = None, nonce: Optional[str] = None):
        """Initialize a Stamp object.
        
        Args:
            stamp_id: Unique identifier for the stamp
            hash: The original SHA256 hash that was timestamped
            timestamp: Unix timestamp when the stamp was created
            status: Current status of the stamp
            merkle_proof: Merkle proof for verification (if available)
            nonce: Nonce for verification (if available)
        """
        self.stamp_id = stamp_id
        self.hash = hash
        self.timestamp = timestamp
        self.status = status
        self.merkle_proof = merkle_proof
        self.nonce = nonce
    
    def verify(self, original_hash: str) -> bool:
        """Verify that this stamp proves the existence of the original hash.
        
        Args:
            original_hash: The original hash to verify against
            
        Returns:
            True if verification succeeds
            
        Raises:
            BasestampError: If verification fails with specific reason
        """
        if not self.merkle_proof:
            raise BasestampError("No Merkle proof available for verification")
        
        if self.nonce is None:
            raise BasestampError("No nonce available for verification - nonce is required")
        
        # Calculate expected leaf hash: SHA256(nonce + original_hash)
        from .merkle import calculate_sha256
        concatenated = self.nonce + original_hash
        expected_leaf_hash = calculate_sha256(concatenated)
        
        if expected_leaf_hash != self.merkle_proof.leaf_hash:
            raise BasestampError(f"Calculated leaf hash {expected_leaf_hash} doesn't match proof leaf hash {self.merkle_proof.leaf_hash}")
        
        # Verify the Merkle proof structure
        from .merkle import verify_merkle_proof
        
        try:
            is_valid = verify_merkle_proof(self.merkle_proof)
            
            if not is_valid:
                raise BasestampError("Merkle proof verification failed: proof structure is invalid")
                
        except Exception as e:
            if isinstance(e, BasestampError):
                raise
            raise BasestampError(f"Merkle proof verification failed: {str(e)}")
        
        return True
    
    def __repr__(self) -> str:
        """Return a clean representation of the Stamp."""
        import datetime
        
        # Convert timestamp to readable format - handle both string and int timestamps
        timestamp_int = int(self.timestamp) if isinstance(self.timestamp, str) else self.timestamp
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



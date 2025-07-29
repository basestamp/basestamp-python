"""Tests for type definitions and error handling."""

import pytest

from basestamp.types import (
    BasestampError,
    ClientOptions,
    MerkleProof,
    ServerRequest,
    Stamp,
)


class TestBasestampError:
    """Tests for BasestampError class."""

    def test_error_creation_with_message_only(self):
        """Test creating error with message only."""
        error = BasestampError("Test error")
        assert error.message == "Test error"
        assert error.status_code is None
        assert str(error) == "BasestampError: Test error"

    def test_error_creation_with_status_code(self):
        """Test creating error with message and status code."""
        error = BasestampError("Server error", 500)
        assert error.message == "Server error"
        assert error.status_code == 500
        assert str(error) == "BasestampError [500]: Server error"

    def test_error_inheritance(self):
        """Test that BasestampError inherits from Exception."""
        error = BasestampError("Test")
        assert isinstance(error, Exception)


class TestClientOptions:
    """Tests for ClientOptions dataclass."""

    def test_default_values(self):
        """Test default client options."""
        options = ClientOptions()
        assert options.base_url == "https://api.basestamp.io"
        assert options.timeout == 30000

    def test_custom_values(self):
        """Test custom client options."""
        options = ClientOptions(base_url="https://custom.api.com", timeout=5000)
        assert options.base_url == "https://custom.api.com"
        assert options.timeout == 5000


class TestDataclassCreation:
    """Tests for dataclass creation and structure."""

    def test_server_request(self):
        """Test ServerRequest creation."""
        req = ServerRequest(hash="test_hash")
        assert req.hash == "test_hash"

    def test_merkle_proof(self):
        """Test MerkleProof creation."""
        proof = MerkleProof(
            leaf_hash="leaf_hash",
            leaf_index=0,
            siblings=["sibling1", "sibling2"],
            directions=[True, False],
            root_hash="root_hash",
        )
        assert proof.leaf_hash == "leaf_hash"
        assert proof.leaf_index == 0
        assert proof.siblings == ["sibling1", "sibling2"]
        assert proof.directions == [True, False]
        assert proof.root_hash == "root_hash"



class TestMerkleProofVerify:
    """Tests for MerkleProof.verify() method."""

    def test_verify_requires_nonce(self):
        """Test verify raises error when no nonce is provided."""
        from basestamp.merkle import _hash_pair
        
        original_hash = "original_hash"
        sibling = "sibling_hash"
        root = _hash_pair(original_hash, sibling)
        
        proof = MerkleProof(
            leaf_hash=original_hash,
            leaf_index=0,
            siblings=[sibling],
            directions=[True],
            root_hash=root,
        )
        
        # Should raise ValueError when no nonce is provided
        with pytest.raises(ValueError, match="Nonce is required for Merkle proof verification"):
            proof.verify(original_hash)

    def test_verify_non_matching_hash_with_nonce(self):
        """Test verify with non-matching original hash (with nonce)."""
        from basestamp.merkle import calculate_sha256
        
        nonce = "test_nonce"
        original_hash = "original_hash"
        wrong_hash = "wrong_hash"
        
        # Calculate leaf hash with correct original hash
        concatenated = nonce + original_hash
        leaf_hash = calculate_sha256(concatenated)
        
        proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[],
            directions=[],
            root_hash=leaf_hash,
            nonce=nonce
        )
        
        # Wrong hash should return False
        assert proof.verify(wrong_hash) == False

    def test_verify_invalid_proof_structure_with_nonce(self):
        """Test verify with invalid proof structure (with nonce)."""
        from basestamp.merkle import calculate_sha256
        
        nonce = "test_nonce"
        original_hash = "original_hash"
        
        # Calculate correct leaf hash
        concatenated = nonce + original_hash
        leaf_hash = calculate_sha256(concatenated)
        
        proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=["wrong_sibling"],
            directions=[True],
            root_hash="wrong_root",
            nonce=nonce
        )
        
        # Even though leaf hash matches, proof structure is invalid
        assert proof.verify(original_hash) == False

    def test_verify_complex_proof_with_nonce(self):
        """Test verify with a more complex valid proof (with nonce)."""
        from basestamp.merkle import _hash_pair, calculate_sha256
        
        nonce = "test_nonce"
        original_hash = "original"
        sibling1 = "sibling1"
        sibling2 = "sibling2"
        
        # Calculate leaf hash with nonce
        concatenated = nonce + original_hash
        leaf_hash = calculate_sha256(concatenated)
        
        # Build proof manually
        level1 = _hash_pair(leaf_hash, sibling1)  # leaf_hash + sibling1 (right)
        root = _hash_pair(sibling2, level1)  # sibling2 (left) + level1
        
        proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[sibling1, sibling2],
            directions=[True, False],  # sibling1 right, sibling2 left
            root_hash=root,
            nonce=nonce
        )
        
        assert proof.verify(original_hash) == True

    def test_verify_empty_proof_with_nonce(self):
        """Test verify with empty proof (leaf is root) with nonce."""
        from basestamp.merkle import calculate_sha256
        
        nonce = "test_nonce"
        original_hash = "single_leaf"
        
        # Calculate leaf hash with nonce
        concatenated = nonce + original_hash
        leaf_hash = calculate_sha256(concatenated)
        
        proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[],
            directions=[],
            root_hash=leaf_hash,  # Leaf is the root
            nonce=nonce
        )
        
        assert proof.verify(original_hash) == True

    def test_verify_with_nonce(self):
        """Test verify with nonce-based leaf hash calculation."""
        from basestamp.merkle import calculate_sha256
        
        # Test the new nonce-based approach
        nonce = "1753464136967947000"
        original_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        # Calculate leaf hash: SHA256(nonce + original_hash)
        concatenated = nonce + original_hash
        leaf_hash = calculate_sha256(concatenated)
        
        # Create a simple proof with nonce (single leaf tree)
        proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[],
            directions=[],
            root_hash=leaf_hash,  # Root equals leaf for single-leaf tree
            nonce=nonce  # Nonce is stored in the proof object
        )
        
        # Test nonce-based verification - simplified API
        assert proof.verify(original_hash) == True
        
        # Test that without nonce in proof, it should raise ValueError
        proof_no_nonce = MerkleProof(
            leaf_hash=leaf_hash,  # This won't match without nonce processing
            leaf_index=0,
            siblings=[],
            directions=[],
            root_hash=leaf_hash
        )
        with pytest.raises(ValueError, match="Nonce is required for Merkle proof verification"):
            proof_no_nonce.verify(original_hash)
        
        # Test with wrong nonce in proof
        wrong_nonce = "1234567890123456789"
        proof_wrong_nonce = MerkleProof(
            leaf_hash=leaf_hash,  # This leaf hash was calculated with correct nonce
            leaf_index=0,
            siblings=[],
            directions=[],
            root_hash=leaf_hash,
            nonce=wrong_nonce  # But proof has wrong nonce
        )
        assert proof_wrong_nonce.verify(original_hash) == False


    def test_verify_with_nonce_in_proof(self):
        """Test verify using proof's nonce field with original_hash parameter."""
        from basestamp.merkle import calculate_sha256
        
        # Test data
        nonce = "1753464136967947000"
        original_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        
        # Calculate leaf hash
        concatenated = nonce + original_hash
        leaf_hash = calculate_sha256(concatenated)
        
        # Create proof with nonce
        proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[],
            directions=[],
            root_hash=leaf_hash,  # Single leaf tree
            nonce=nonce
        )
        
        # Test new simplified API - nonce in proof, pass original_hash
        assert proof.verify(original_hash) == True
        
        # Test with wrong nonce in the proof
        wrong_proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[],
            directions=[],
            root_hash=leaf_hash,
            nonce="wrong_nonce"
        )
        assert wrong_proof.verify(original_hash) == False

    def test_verify_simplified_api(self):
        """Test the simplified API where proof contains nonce and verify takes original_hash."""
        from basestamp.merkle import calculate_sha256
        
        # Test with nonce-based verification
        nonce = "test_nonce_123"
        original_hash = "original_test_hash"
        
        # Calculate expected leaf hash using nonce + original_hash  
        expected_leaf_hash = calculate_sha256(nonce + original_hash)
        
        proof_with_nonce = MerkleProof(
            leaf_hash=expected_leaf_hash,
            leaf_index=0,
            siblings=[],
            directions=[],
            root_hash=expected_leaf_hash,  # Single leaf tree
            nonce=nonce
        )
        
        # API: proof contains nonce, verify() takes original_hash
        assert proof_with_nonce.verify(original_hash) == True
        
        # Test with wrong original hash should fail
        assert proof_with_nonce.verify("wrong_hash") == False


class TestStampVerificationErrors:
    """Test error cases for Stamp verification."""

    def test_stamp_verify_with_wrong_hash_nonce_mode(self):
        """Test Stamp.verify() raises error with wrong hash in nonce mode."""
        from basestamp.merkle import calculate_sha256
        
        original_hash = "correct_hash"
        wrong_hash = "wrong_hash"
        nonce = "test_nonce"
        leaf_hash = calculate_sha256(nonce + original_hash)
        
        merkle_proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[],
            directions=[],
            root_hash=leaf_hash
        )
        
        stamp = Stamp(
            stamp_id="test_stamp",
            hash=original_hash,
            timestamp=1640995200,
            status="confirmed",
            merkle_proof=merkle_proof,
            nonce=nonce
        )
        
        # Should raise specific error for wrong hash
        with pytest.raises(BasestampError, match="Calculated leaf hash .* doesn't match proof leaf hash"):
            stamp.verify(wrong_hash)

    def test_stamp_verify_without_nonce_raises_error(self):
        """Test Stamp.verify() raises error when no nonce is available."""
        original_hash = "correct_hash"
        
        merkle_proof = MerkleProof(
            leaf_hash=original_hash,
            leaf_index=0,
            siblings=[],
            directions=[],
            root_hash=original_hash
        )
        
        stamp = Stamp(
            stamp_id="test_stamp",
            hash=original_hash,
            timestamp=1640995200,
            status="confirmed",
            merkle_proof=merkle_proof,
            nonce=None
        )
        
        # Should raise specific error when no nonce is available
        with pytest.raises(BasestampError, match="No nonce available for verification - nonce is required"):
            stamp.verify(original_hash)

    def test_stamp_verify_invalid_proof_structure(self):
        """Test Stamp.verify() handles invalid proof structure."""
        from basestamp.merkle import calculate_sha256
        
        nonce = "test_nonce"
        original_hash = "test_hash"
        
        # Calculate correct leaf hash with nonce  
        concatenated = nonce + original_hash
        leaf_hash = calculate_sha256(concatenated)
        
        # Create a stamp with invalid proof (siblings/directions mismatch)
        merkle_proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=["sibling1"],  # 1 sibling
            directions=[True, False],  # But 2 directions - mismatch!
            root_hash="invalid_root"
        )
        
        stamp = Stamp(
            stamp_id="test_stamp",
            hash=original_hash,
            timestamp=1640995200,
            status="confirmed",
            merkle_proof=merkle_proof,
            nonce=nonce
        )
        
        # Should raise error about invalid proof structure
        with pytest.raises(BasestampError, match="Merkle proof verification failed"):
            stamp.verify(original_hash)


    def test_stamp_verify_general_exception_handling(self):
        """Test Stamp.verify() handles general exceptions during proof verification."""
        from basestamp.merkle import calculate_sha256
        
        nonce = "test_nonce"
        original_hash = "test_hash"
        
        # Calculate correct leaf hash with nonce
        concatenated = nonce + original_hash
        leaf_hash = calculate_sha256(concatenated)
        
        # Create a stamp with a proof that will cause an exception during verification
        # by having an invalid structure that the merkle verification will reject
        merkle_proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=["sibling1", "sibling2"],  # 2 siblings
            directions=[True],  # But only 1 direction - will cause error
            root_hash="invalid_root"
        )
        
        stamp = Stamp(
            stamp_id="test_stamp",
            hash=original_hash,
            timestamp=1640995200,
            status="confirmed",
            merkle_proof=merkle_proof,
            nonce=nonce
        )
        
        # Should catch the exception and re-wrap it as BasestampError
        with pytest.raises(BasestampError, match="Merkle proof verification failed"):
            stamp.verify(original_hash)

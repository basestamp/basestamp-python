"""Tests for Merkle proof verification and SHA256 utilities."""

import pytest

from basestamp.merkle import _hash_pair, calculate_sha256, verify_merkle_proof
from basestamp.types import MerkleProof


class TestCalculateSHA256:
    """Tests for SHA256 hash calculation."""

    def test_string_input(self):
        """Test SHA256 calculation with string input."""
        result = calculate_sha256("Hello, Basestamp!")
        assert len(result) == 64  # SHA256 produces 64 hex characters
        assert isinstance(result, str)
        assert all(c in "0123456789abcdef" for c in result)

    def test_bytes_input(self):
        """Test SHA256 calculation with bytes input."""
        data = b"Hello, Basestamp!"
        result = calculate_sha256(data)
        assert len(result) == 64
        assert isinstance(result, str)

    def test_empty_string(self):
        """Test SHA256 calculation with empty string."""
        result = calculate_sha256("")
        # Known SHA256 hash of empty string
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert result == expected

    def test_empty_bytes(self):
        """Test SHA256 calculation with empty bytes."""
        result = calculate_sha256(b"")
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert result == expected

    def test_unicode_string(self):
        """Test SHA256 calculation with Unicode string."""
        result = calculate_sha256("🔐 Basestamp! 🔐")
        assert len(result) == 64
        assert isinstance(result, str)

    def test_consistency(self):
        """Test that same input produces same output."""
        data = "test data"
        result1 = calculate_sha256(data)
        result2 = calculate_sha256(data)
        assert result1 == result2

    def test_string_vs_bytes_equivalence(self):
        """Test that string and equivalent bytes produce same hash."""
        text = "test"
        hash_from_string = calculate_sha256(text)
        hash_from_bytes = calculate_sha256(text.encode("utf-8"))
        assert hash_from_string == hash_from_bytes


class TestVerifyMerkleProof:
    """Tests for Merkle proof verification."""

    def test_valid_simple_proof(self):
        """Test verification of a valid simple Merkle proof."""
        # Create a simple valid proof
        leaf_hash = "leaf_hash"
        sibling = "sibling_hash"
        # Calculate what the root should be (sibling on right, direction=True)
        expected_root = _hash_pair(leaf_hash, sibling)

        proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[sibling],
            directions=[True],
            root_hash=expected_root,
        )

        assert verify_merkle_proof(proof) == True

    def test_valid_complex_proof(self):
        """Test verification of a more complex Merkle proof."""
        leaf_hash = "leaf"
        sibling1 = "sibling1"
        sibling2 = "sibling2"

        # Build the proof step by step
        # Level 1: sibling1 on right (direction=True)
        level1 = _hash_pair(leaf_hash, sibling1)
        # Level 2: sibling2 on left (direction=False)
        root = _hash_pair(sibling2, level1)

        proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[sibling1, sibling2],
            directions=[True, False],
            root_hash=root,
        )

        assert verify_merkle_proof(proof) == True

    def test_invalid_proof_wrong_root(self):
        """Test verification fails with wrong root."""
        proof = MerkleProof(
            leaf_hash="leaf",
            leaf_index=0,
            siblings=["sibling"],
            directions=[True],
            root_hash="wrong_root",
        )

        assert verify_merkle_proof(proof) == False

    def test_invalid_proof_wrong_sibling(self):
        """Test verification fails with wrong sibling."""
        leaf_hash = "leaf"
        wrong_sibling = "wrong_sibling"
        correct_sibling = "correct_sibling"

        # Calculate root with correct sibling
        correct_root = _hash_pair(leaf_hash, correct_sibling)

        # Create proof with wrong sibling but correct root
        proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[wrong_sibling],
            directions=[True],
            root_hash=correct_root,
        )

        assert verify_merkle_proof(proof) == False

    def test_empty_proof(self):
        """Test verification fails with None/empty proof."""
        assert verify_merkle_proof(None) == False

    def test_missing_leaf_hash(self):
        """Test verification fails with missing leaf_hash."""
        proof = MerkleProof(
            leaf_hash="",
            leaf_index=0,
            siblings=["sibling"],
            directions=[True],
            root_hash="root",
        )

        assert verify_merkle_proof(proof) == False

    def test_missing_root_hash(self):
        """Test verification fails with missing root_hash."""
        proof = MerkleProof(
            leaf_hash="leaf",
            leaf_index=0,
            siblings=["sibling"],
            directions=[True],
            root_hash="",
        )

        assert verify_merkle_proof(proof) == False

    def test_mismatched_siblings_directions_length(self):
        """Test verification fails when siblings and directions length don't match."""
        proof = MerkleProof(
            leaf_hash="leaf",
            leaf_index=0,
            siblings=["sibling1", "sibling2"],
            directions=[True],  # Only one direction for two siblings
            root_hash="root",
        )

        assert verify_merkle_proof(proof) == False

    def test_direction_true_sibling_right(self):
        """Test verification with direction=True (sibling on right)."""
        leaf_hash = "leaf"
        sibling = "sibling"
        # For direction=True, sibling is on right
        root = _hash_pair(leaf_hash, sibling)

        proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[sibling],
            directions=[True],
            root_hash=root,
        )

        assert verify_merkle_proof(proof) == True

    def test_direction_false_sibling_left(self):
        """Test verification with direction=False (sibling on left)."""
        leaf_hash = "leaf"
        sibling = "sibling"
        # For direction=False, sibling is on left
        root = _hash_pair(sibling, leaf_hash)

        proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[sibling],
            directions=[False],
            root_hash=root,
        )

        assert verify_merkle_proof(proof) == True

    def test_empty_siblings_and_directions(self):
        """Test proof with no siblings (leaf is root)."""
        leaf_hash = "some_hash"

        proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[],
            directions=[],
            root_hash=leaf_hash,  # Leaf is the root
        )

        assert verify_merkle_proof(proof) == True


class TestHashPair:
    """Tests for the _hash_pair function."""

    def test_lexicographic_ordering(self):
        """Test that hashes are combined in lexicographic order."""
        hash1 = "aaaa"
        hash2 = "bbbb"

        result1 = _hash_pair(hash1, hash2)
        result2 = _hash_pair(hash2, hash1)

        # Should produce the same result regardless of input order
        assert result1 == result2

    def test_same_hash_combination(self):
        """Test combining identical hashes."""
        hash1 = "same_hash"
        result = _hash_pair(hash1, hash1)

        # Should be SHA256 of "same_hashsame_hash"
        expected = calculate_sha256("same_hashsame_hash")
        assert result == expected

    def test_different_lengths(self):
        """Test combining hashes of different lengths."""
        short_hash = "abc"
        long_hash = "abcdef"

        result = _hash_pair(short_hash, long_hash)
        assert len(result) == 64  # Should always produce 64-char SHA256



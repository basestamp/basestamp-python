"""Tests for Merkle proof verification and SHA256 utilities."""

import hashlib

import pytest

from basestamp.merkle import (
    MAX_PROOF_DEPTH,
    _hash_pair,
    calculate_sha256,
    compute_leaf_hash,
    compute_merkle_root,
    is_valid_hash,
    normalize_hash,
    verify_merkle_proof,
    verify_proof,
)
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


def h(label: str) -> str:
    """Deterministic 32-byte hex hash for tests."""
    return calculate_sha256(label)


class TestVerifyMerkleProof:
    """Tests for Merkle proof verification."""

    def test_valid_simple_proof(self):
        leaf, sibling = h("leaf"), h("sibling")
        root = _hash_pair(leaf, sibling)
        proof = MerkleProof(leaf, 0, [sibling], [True], root)
        assert verify_merkle_proof(proof) is True

    def test_valid_complex_proof(self):
        leaf, s1, s2 = h("leaf"), h("s1"), h("s2")
        root = _hash_pair(s2, _hash_pair(leaf, s1))
        proof = MerkleProof(leaf, 0, [s1, s2], [True, False], root)
        assert verify_merkle_proof(proof) is True

    def test_hashes_bytes_not_hex_strings(self):
        """Regression: nodes are hashed as raw bytes, not concatenated hex text."""
        a, b = sorted([h("a"), h("b")])
        assert _hash_pair(a, b) == hashlib.sha256(bytes.fromhex(a + b)).hexdigest()
        assert _hash_pair(a, b) != calculate_sha256(a + b)

    def test_invalid_proof_wrong_root(self):
        proof = MerkleProof(h("leaf"), 0, [h("sibling")], [True], h("wrong"))
        assert verify_merkle_proof(proof) is False

    def test_invalid_proof_wrong_sibling(self):
        leaf = h("leaf")
        root = _hash_pair(leaf, h("correct"))
        proof = MerkleProof(leaf, 0, [h("wrong")], [True], root)
        assert verify_merkle_proof(proof) is False

    def test_invalid_proof_wrong_leaf(self):
        root = _hash_pair(h("leaf"), h("sibling"))
        proof = MerkleProof(h("other"), 0, [h("sibling")], [True], root)
        assert verify_merkle_proof(proof) is False

    def test_empty_proof(self):
        assert verify_merkle_proof(None) is False

    @pytest.mark.parametrize("field", ["leaf_hash", "root_hash"])
    @pytest.mark.parametrize("bad", ["", "leaf", "zz" * 32, "ab" * 31, None, 5])
    def test_malformed_leaf_or_root(self, field, bad):
        leaf, sibling = h("leaf"), h("sibling")
        proof = MerkleProof(leaf, 0, [sibling], [True], _hash_pair(leaf, sibling))
        setattr(proof, field, bad)
        assert verify_merkle_proof(proof) is False

    @pytest.mark.parametrize("bad", ["sibling", "zz" * 32, "ab" * 33, None])
    def test_malformed_sibling(self, bad):
        proof = MerkleProof(h("leaf"), 0, [bad], [True], h("root"))
        assert verify_merkle_proof(proof) is False

    def test_non_bool_direction(self):
        leaf, sibling = h("leaf"), h("sibling")
        proof = MerkleProof(leaf, 0, [sibling], ["yes"], _hash_pair(leaf, sibling))
        assert verify_merkle_proof(proof) is False

    def test_non_list_siblings(self):
        proof = MerkleProof(h("leaf"), 0, "abc", [True], h("root"))
        assert verify_merkle_proof(proof) is False

    def test_mismatched_siblings_directions_length(self):
        proof = MerkleProof(h("leaf"), 0, [h("s1"), h("s2")], [True], h("root"))
        assert verify_merkle_proof(proof) is False

    def test_directions_do_not_affect_root(self):
        """Sorted-pair hashing: directions are informational only."""
        leaf, sibling = h("leaf"), h("sibling")
        root = _hash_pair(leaf, sibling)
        assert verify_merkle_proof(MerkleProof(leaf, 0, [sibling], [True], root))
        assert verify_merkle_proof(MerkleProof(leaf, 0, [sibling], [False], root))

    def test_case_and_prefix_insensitive(self):
        leaf, sibling = h("leaf"), h("sibling")
        root = _hash_pair(leaf, sibling)
        proof = MerkleProof("0x" + leaf.upper(), 0, [sibling.upper()], [True], root)
        assert verify_merkle_proof(proof) is True

    def test_empty_siblings_and_directions(self):
        leaf = h("leaf")
        assert verify_merkle_proof(MerkleProof(leaf, 0, [], [], leaf)) is True

    def test_proof_too_long(self):
        leaf = h("leaf")
        siblings = [leaf] * (MAX_PROOF_DEPTH + 1)
        proof = MerkleProof(leaf, 0, siblings, [True] * len(siblings), leaf)
        assert verify_merkle_proof(proof) is False
        with pytest.raises(ValueError):
            compute_merkle_root(leaf, siblings)


class TestHashPair:
    """Tests for the _hash_pair function."""

    def test_order_independent(self):
        assert _hash_pair(h("a"), h("b")) == _hash_pair(h("b"), h("a"))

    def test_same_hash_combination(self):
        x = h("x")
        assert _hash_pair(x, x) == hashlib.sha256(bytes.fromhex(x) * 2).hexdigest()

    def test_rejects_non_hash_input(self):
        with pytest.raises(ValueError):
            _hash_pair("abc", "abcdef")


class TestHelpers:
    def test_normalize_hash(self):
        x = h("x")
        assert normalize_hash(" 0x" + x.upper() + " ") == x
        with pytest.raises(ValueError):
            normalize_hash(123)

    def test_is_valid_hash(self):
        assert is_valid_hash(h("x"))
        assert not is_valid_hash("nope")

    def test_compute_leaf_hash(self):
        x = h("x")
        assert compute_leaf_hash(x, "123") == calculate_sha256("123" + x)
        assert compute_leaf_hash(x.upper(), None) == x

    def test_verify_proof(self):
        x = h("x")
        leaf = compute_leaf_hash(x, "7")
        sibling = h("sib")
        root = _hash_pair(leaf, sibling)
        proof = {
            "leaf_hash": leaf,
            "siblings": [sibling],
            "directions": [True],
            "root_hash": root,
        }
        assert verify_proof(x, "7", proof, root) is True
        assert verify_proof(x, "7", MerkleProof(leaf, 0, [sibling], [True], root))
        assert verify_proof(x, "8", proof) is False
        assert verify_proof(x, "7", proof, h("other")) is False
        assert verify_proof("bad", "7", proof) is False
        assert verify_proof(x, "7", {"leaf_hash": leaf}) is False

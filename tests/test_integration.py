"""Integration tests for the Basestamp library."""

import json
import urllib.error
from unittest.mock import Mock, patch

import pytest

from basestamp import BasestampClient, calculate_sha256, verify_merkle_proof
from basestamp.merkle import _hash_pair
from basestamp.types import ClientOptions, MerkleProof


def create_mock_response(response_data: dict, status_code: int = 200):
    """Helper function to create mock urllib response."""
    mock_response = Mock()
    mock_response.read.return_value = json.dumps(response_data).encode('utf-8')
    mock_response.__enter__ = Mock(return_value=mock_response)
    mock_response.__exit__ = Mock(return_value=None)
    return mock_response


class TestBasestampIntegration:
    """Integration tests that combine multiple components."""

    @patch("basestamp.client.urllib.request.urlopen")
    def test_full_timestamp_workflow(self, mock_request):
        """Test complete workflow: timestamp creation, retrieval, and verification."""
        # Calculate the actual hash that will be used
        data = "Hello, Basestamp!"
        hash_value = calculate_sha256(data)
        nonce = "test_nonce_123"
        
        # Calculate leaf hash with nonce for proof
        leaf_hash = calculate_sha256(nonce + hash_value)
        
        # Mock timestamp creation response
        timestamp_response = Mock()
        timestamp_response.ok = True
        timestamp_response.json.return_value = {
            "stamp_id": "test_stamp_123",
            "hash": hash_value,
            "timestamp": 1234567890,
            "status": "pending",
        }

        # Mock get_stamp response with proof
        get_stamp_response = Mock()
        get_stamp_response.ok = True
        get_stamp_response.json.return_value = {
            "stamp_id": "test_stamp_123",
            "hash": hash_value,
            "timestamp": 1234567890,
            "status": "confirmed",
            "nonce": nonce,
            "merkle_proof": {
                "leaf_hash": leaf_hash,
                "leaf_index": 0,
                "siblings": ["sibling_hash"],
                "directions": [True],
                "root_hash": _hash_pair(leaf_hash, "sibling_hash"),
                "nonce": nonce,
            },
        }

        # Set up mock to return different responses for different endpoints
        def mock_urlopen_side_effect(request, **kwargs):
            url = request.get_full_url()
            method = request.get_method()
            if url.endswith("/stamp") and method == "POST":
                return create_mock_response(timestamp_response.json.return_value)
            elif "/stamp/" in url and method == "GET":
                return create_mock_response(get_stamp_response.json.return_value)
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

        mock_request.side_effect = mock_urlopen_side_effect

        # Test the workflow
        client = BasestampClient()

        # 1. Submit hash for timestamping
        stamp_id = client.submit_sha256(hash_value)

        assert stamp_id == "test_stamp_123"

        # 2. Get stamp details
        stamp_details = client.get_stamp(stamp_id)
        assert stamp_details.status == "confirmed"
        assert stamp_details.merkle_proof is not None

        # 3. Verify stamp using new API
        is_valid = stamp_details.verify(hash_value)
        assert is_valid == True

    def test_calculate_sha256_with_real_data(self):
        """Test SHA256 calculation with known test vectors."""
        # Test empty string
        assert (
            calculate_sha256("")
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

        # Test "abc"
        assert (
            calculate_sha256("abc")
            == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

        # Test with bytes
        assert (
            calculate_sha256(b"abc")
            == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

    def test_merkle_proof_construction_and_verification(self):
        """Test constructing and verifying a Merkle proof from scratch."""
        # Build a simple Merkle tree manually
        leaf1 = "data1"
        leaf2 = "data2"
        leaf3 = "data3"
        leaf4 = "data4"

        # Hash the leaves
        hash1 = calculate_sha256(leaf1)
        hash2 = calculate_sha256(leaf2)
        hash3 = calculate_sha256(leaf3)
        hash4 = calculate_sha256(leaf4)

        # Build intermediate nodes
        intermediate1 = _hash_pair(hash1, hash2)
        intermediate2 = _hash_pair(hash3, hash4)

        # Build root
        root = _hash_pair(intermediate1, intermediate2)

        # Create proof for hash1 (leaf1)
        proof = MerkleProof(
            leaf_hash=hash1,
            leaf_index=0,
            siblings=[
                hash2,
                intermediate2,
            ],  # Right sibling at level 1, right sibling at level 2
            directions=[True, True],
            root_hash=root,
        )

        # Verify the proof
        assert verify_merkle_proof(proof) == True

        # Test with wrong root
        wrong_proof = MerkleProof(
            leaf_hash=hash1,
            leaf_index=0,
            siblings=[hash2, intermediate2],
            directions=[True, True],
            root_hash="wrong_root",
        )

        assert verify_merkle_proof(wrong_proof) == False

    def test_client_with_custom_options(self):
        """Test client functionality with custom options."""
        custom_options = ClientOptions(
            base_url="https://custom.basestamp.com", timeout=10000
        )

        client = BasestampClient(custom_options)

        assert client.options.base_url == "https://custom.basestamp.com"
        assert client.options.timeout == 10000
        assert client.timeout == 10.0  # Converted to seconds

    @patch("basestamp.client.urllib.request.urlopen")
    def test_error_handling_throughout_workflow(self, mock_request):
        """Test error handling across different operations."""
        # Mock server error
        error_response = Mock()
        error_response.ok = False
        error_response.status_code = 500
        error_response.json.return_value = {"error": "Internal server error"}
        mock_request.return_value = error_response

        client = BasestampClient()

        # Test that errors are properly propagated
        with pytest.raises(Exception):  # Could be BasestampError or other
            client.timestamp("test_hash")

        with pytest.raises(Exception):
            client.get_stamp("test_stamp")


    def test_library_imports(self):
        """Test that all expected symbols can be imported."""
        # Test direct imports
        from basestamp import (
            BasestampClient,
            BasestampError,
            ClientOptions,
            MerkleProof,
            calculate_sha256,
            verify_merkle_proof,
        )

        # Test that they are the expected types
        assert callable(BasestampClient)
        assert callable(calculate_sha256)
        assert callable(verify_merkle_proof)

        # Test instantiation
        client = BasestampClient()
        assert isinstance(client, BasestampClient)

        # Test type creation
        options = ClientOptions()
        assert isinstance(options, ClientOptions)

        proof = MerkleProof(
            leaf_hash="leaf", leaf_index=0, siblings=["sib"], directions=[False], root_hash="root"
        )
        assert isinstance(proof, MerkleProof)

    def test_context_manager_integration(self):
        """Test using client as context manager in integration scenario."""
        custom_options = ClientOptions(
            base_url="https://test.basestamp.com", timeout=5000
        )

        with BasestampClient(custom_options) as client:
            # Verify client is properly configured
            assert client.options.base_url == "https://test.basestamp.com"
            assert client.timeout == 5.0

            # Verify we can call methods (will fail due to no mocking, but structure is correct)
            assert hasattr(client, "submit_sha256")
            assert hasattr(client, "get_stamp")

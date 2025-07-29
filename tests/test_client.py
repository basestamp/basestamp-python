"""Tests for the Basestamp client with new API."""

import json
import urllib.error
from unittest.mock import Mock, patch

import pytest

from basestamp import BasestampClient, Stamp, BasestampError, calculate_sha256
from basestamp.client import _parse_timestamp
from basestamp.types import (
    ClientOptions,
    MerkleProof,
)


def create_mock_response(response_data: dict, status_code: int = 200):
    """Helper function to create mock urllib response."""
    mock_response = Mock()
    mock_response.read.return_value = json.dumps(response_data).encode('utf-8')
    mock_response.__enter__ = Mock(return_value=mock_response)
    mock_response.__exit__ = Mock(return_value=None)
    return mock_response


def create_mock_http_error(status_code: int, error_data: dict = None):
    """Helper function to create mock HTTPError."""
    error_response = json.dumps(error_data or {}).encode('utf-8') if error_data else b"Bad Request"
    error = urllib.error.HTTPError(
        url="test_url", 
        code=status_code, 
        msg="Test error", 
        hdrs={}, 
        fp=None
    )
    error.read = Mock(return_value=error_response)
    return error


def create_mock_timeout_error():
    """Helper function to create mock timeout error."""
    return OSError("timed out")


def create_mock_connection_error(message="Connection failed"):
    """Helper function to create mock connection error."""
    return urllib.error.URLError(Exception(message))


class TestBasestampClientInit:
    """Tests for client initialization."""

    def test_default_initialization(self):
        """Test client initialization with default options."""
        client = BasestampClient()
        assert client.options.base_url == "https://api.basestamp.io"
        assert client.options.timeout == 30000
        assert client.timeout == 30.0  # Converted to seconds

    def test_custom_options_initialization(self):
        """Test client initialization with custom options."""
        options = ClientOptions(base_url="https://custom.api.com", timeout=5000)
        client = BasestampClient(options)
        assert client.options.base_url == "https://custom.api.com"
        assert client.options.timeout == 5000
        assert client.timeout == 5.0


class TestBasestampClientSubmitSHA256:
    """Tests for the submit_sha256 method."""

    @patch("basestamp.client.urllib.request.urlopen")
    def test_successful_submit(self, mock_urlopen):
        """Test successful hash submission."""
        # Mock successful response
        response_data = {
            "stamp_id": "test_stamp_123",
            "hash": "test_hash",
            "timestamp": 1234567890,
            "status": "pending",
        }
        mock_urlopen.return_value = create_mock_response(response_data)

        client = BasestampClient()
        stamp_id = client.submit_sha256("test_hash")
        
        assert stamp_id == "test_stamp_123"
        
        # Verify the request was made correctly
        mock_urlopen.assert_called_once()

    @patch("basestamp.client.urllib.request.urlopen")
    def test_submit_http_error(self, mock_urlopen):
        """Test HTTP error handling during submission."""
        mock_urlopen.side_effect = create_mock_http_error(400)

        client = BasestampClient()
        with pytest.raises(BasestampError):
            client.submit_sha256("invalid_hash")


class TestBasestampClientGetStamp:
    """Tests for the get_stamp method."""

    @patch("basestamp.client.urllib.request.urlopen")
    def test_get_stamp_with_nonce_and_proof(self, mock_urlopen):
        """Test getting a stamp with nonce and proof."""
        original_hash = "test_original_hash"
        nonce = "test_nonce_456"
        leaf_hash = calculate_sha256(nonce + original_hash)
        
        response_data = {
            "stamp_id": "test_stamp_456",
            "hash": original_hash,
            "timestamp": 1234567890,
            "status": "confirmed",
            "nonce": nonce,
            "merkle_proof": {
                "leaf_hash": leaf_hash,
                "leaf_index": 0,
                "siblings": ["sibling1"],
                "directions": [True],
                "root_hash": "root_hash"
            }
        }
        mock_urlopen.return_value = create_mock_response(response_data)

        client = BasestampClient()
        stamp = client.get_stamp("test_stamp_456")
        
        # Verify returned stamp object
        assert isinstance(stamp, Stamp)
        assert stamp.stamp_id == "test_stamp_456"
        assert stamp.hash == original_hash
        assert stamp.nonce == nonce
        assert stamp.merkle_proof is not None
        assert stamp.merkle_proof.leaf_hash == leaf_hash
        assert stamp.merkle_proof.siblings == ["sibling1"]

    @patch("basestamp.client.urllib.request.urlopen")
    def test_get_stamp_with_iso8601_timestamp(self, mock_urlopen):
        """Test getting a stamp with ISO 8601 timestamp format (real API format)."""
        original_hash = "test_original_hash"
        nonce = "test_nonce_456"
        leaf_hash = calculate_sha256(nonce + original_hash)
        
        response_data = {
            "stamp_id": "test_stamp_iso",
            "hash": original_hash,
            "timestamp": "2025-07-28T02:21:45.496978965Z",  # ISO 8601 format with nanoseconds
            "status": "confirmed",
            "nonce": nonce,
            "merkle_proof": {
                "leaf_hash": leaf_hash,
                "leaf_index": 0,
                "siblings": ["sibling1"],
                "directions": [True],
                "root_hash": "root_hash"
            }
        }
        mock_urlopen.return_value = create_mock_response(response_data)

        client = BasestampClient()
        stamp = client.get_stamp("test_stamp_iso")
        
        # Verify returned stamp object
        assert isinstance(stamp, Stamp)
        assert stamp.stamp_id == "test_stamp_iso"
        assert stamp.hash == original_hash
        assert stamp.nonce == nonce
        assert isinstance(stamp.timestamp, int)  # Should be converted to int
        assert stamp.timestamp > 0  # Should be a valid Unix timestamp
        assert stamp.merkle_proof is not None
        
        # Verify __repr__ works without TypeError
        repr_str = repr(stamp)
        assert "Stamp(CONFIRMED)" in repr_str
        assert "test_stamp_iso" in repr_str

    @patch("basestamp.client.urllib.request.urlopen")
    def test_get_stamp_without_proof_raises_exception(self, mock_urlopen):
        """Test getting a stamp without proof raises exception when wait=False."""
        response_data = {
            "stamp_id": "test_stamp_789",
            "hash": "test_hash",
            "timestamp": 1234567890,
            "status": "pending",
            # No merkle_proof - stamp not ready
        }
        mock_urlopen.return_value = create_mock_response(response_data)

        client = BasestampClient()
        # Without wait=True, should raise exception when proof is not available
        with pytest.raises(BasestampError, match="Stamp test_stamp_789 is not yet available.*Use wait=True"):
            client.get_stamp("test_stamp_789")

    @patch("basestamp.client.urllib.request.urlopen")
    def test_get_stamp_with_batch_info_nonce(self, mock_urlopen):
        """Test extracting nonce from batch_info when direct nonce not available."""
        response_data = {
            "stamp_id": "test_stamp_batch",
            "hash": "test_hash",
            "timestamp": 1234567890,
            "status": "confirmed",
            "batch_info": {
                "nonce": "batch_nonce_123"
            },
            "merkle_proof": {
                "leaf_hash": "leaf_hash",
                "leaf_index": 0,
                "siblings": [],
                "directions": [],
                "root_hash": "root_hash"
            }
        }
        mock_urlopen.return_value = create_mock_response(response_data)

        client = BasestampClient()
        stamp = client.get_stamp("test_stamp_batch")
        
        assert stamp.nonce == "batch_nonce_123"

    @patch("basestamp.client.urllib.request.urlopen")
    def test_get_stamp_not_ready_without_wait(self, mock_urlopen):
        """Test getting a stamp that's not ready without wait parameter."""
        response_data = {
            "stamp_id": "test_stamp_pending",
            "hash": "test_hash",
            "timestamp": 1234567890,
            "status": "pending",
            # No merkle_proof - stamp not ready
        }
        mock_urlopen.return_value = create_mock_response(response_data)

        client = BasestampClient()
        with pytest.raises(BasestampError, match="Stamp test_stamp_pending is not yet available.*Use wait=True"):
            client.get_stamp("test_stamp_pending")

    @patch("basestamp.client.urllib.request.urlopen")
    @patch("basestamp.client.time.sleep")
    def test_get_stamp_wait_success_immediate(self, mock_sleep, mock_urlopen):
        """Test waiting for stamp that's immediately available."""
        response_data = {
            "stamp_id": "test_stamp_ready",
            "hash": "test_hash",
            "timestamp": 1234567890,
            "status": "confirmed",
            "merkle_proof": {
                "leaf_hash": "leaf_hash",
                "leaf_index": 0,
                "siblings": [],
                "directions": [],
                "root_hash": "root_hash"
            }
        }
        mock_urlopen.return_value = create_mock_response(response_data)

        client = BasestampClient()
        stamp = client.get_stamp("test_stamp_ready", wait=True)
        
        assert isinstance(stamp, Stamp)
        assert stamp.stamp_id == "test_stamp_ready"
        assert stamp.merkle_proof is not None
        # Should not have slept since stamp was immediately ready
        mock_sleep.assert_not_called()

    @patch("basestamp.client.urllib.request.urlopen")
    @patch("basestamp.client.time.sleep")
    @patch("basestamp.client.time.time")
    def test_get_stamp_wait_success_after_polling(self, mock_time, mock_sleep, mock_urlopen):
        """Test waiting for stamp that becomes available after polling."""
        # Mock time progression: start at 0, then 1, then 2 seconds
        mock_time.side_effect = [0, 1, 2]
        
        # First call - not ready, second call - ready
        not_ready_data = {
            "stamp_id": "test_stamp_polling",
            "hash": "test_hash",
            "timestamp": 1234567890,
            "status": "pending",
        }
        
        ready_data = {
            "stamp_id": "test_stamp_polling",
            "hash": "test_hash",
            "timestamp": 1234567890,
            "status": "confirmed",
            "merkle_proof": {
                "leaf_hash": "leaf_hash",
                "leaf_index": 0,
                "siblings": [],
                "directions": [],
                "root_hash": "root_hash"
            }
        }
        
        mock_urlopen.side_effect = [create_mock_response(not_ready_data), create_mock_response(ready_data)]

        client = BasestampClient()
        stamp = client.get_stamp("test_stamp_polling", wait=True)
        
        assert isinstance(stamp, Stamp)
        assert stamp.stamp_id == "test_stamp_polling"
        assert stamp.merkle_proof is not None
        # Should have made 2 requests
        assert mock_urlopen.call_count == 2
        # Should have slept once between requests
        mock_sleep.assert_called_once_with(1)

    @patch("basestamp.client.urllib.request.urlopen")
    @patch("basestamp.client.time.sleep")
    @patch("basestamp.client.time.time")
    def test_get_stamp_wait_timeout(self, mock_time, mock_sleep, mock_urlopen):
        """Test timeout when waiting for stamp."""
        # Mock time progression: start at 0, then simulate 31 seconds elapsed
        mock_time.side_effect = [0, 31]
        
        # Always return not ready
        response_data = {
            "stamp_id": "test_stamp_timeout",
            "hash": "test_hash",
            "timestamp": 1234567890,
            "status": "pending",
        }
        mock_urlopen.return_value = create_mock_response(response_data)

        client = BasestampClient()
        with pytest.raises(BasestampError, match="Timeout waiting for stamp test_stamp_timeout after 30 seconds"):
            client.get_stamp("test_stamp_timeout", wait=True, timeout=30)

    @patch("basestamp.client.urllib.request.urlopen")
    def test_get_stamp_custom_timeout(self, mock_urlopen):
        """Test get_stamp with custom timeout parameter."""
        response_data = {
            "stamp_id": "test_stamp_custom",
            "hash": "test_hash",
            "timestamp": 1234567890,
            "status": "confirmed",
            "merkle_proof": {
                "leaf_hash": "leaf_hash",
                "leaf_index": 0,
                "siblings": [],
                "directions": [],
                "root_hash": "root_hash"
            }
        }
        mock_urlopen.return_value = create_mock_response(response_data)

        client = BasestampClient()
        stamp = client.get_stamp("test_stamp_custom", wait=True, timeout=60)
        
        assert isinstance(stamp, Stamp)
        assert stamp.stamp_id == "test_stamp_custom"





class TestStampVerification:
    """Tests for stamp verification functionality."""

    def test_verify_with_nonce_success(self):
        """Test successful verification with nonce."""
        original_hash = "verify_test_hash"
        nonce = "verify_nonce_123"
        leaf_hash = calculate_sha256(nonce + original_hash)
        
        merkle_proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=[],
            directions=[],
            root_hash=leaf_hash
        )
        
        stamp = Stamp(
            stamp_id="verify_test",
            hash=original_hash,
            timestamp=1640995200,
            status="confirmed",
            merkle_proof=merkle_proof,
            nonce=nonce
        )
        
        result = stamp.verify(original_hash)
        assert result is True

    def test_verify_with_wrong_hash_fails(self):
        """Test verification fails with wrong hash."""
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
            stamp_id="fail_test",
            hash=original_hash,
            timestamp=1640995200,
            status="confirmed",
            merkle_proof=merkle_proof,
            nonce=nonce
        )
        
        with pytest.raises(BasestampError, match="Calculated leaf hash .* doesn't match proof leaf hash"):
            stamp.verify(wrong_hash)

    def test_verify_without_nonce_raises_error(self):
        """Test verification raises error when no nonce is available."""
        original_hash = "test_hash"
        
        merkle_proof = MerkleProof(
            leaf_hash=original_hash,
            leaf_index=0,
            siblings=[],
            directions=[],
            root_hash=original_hash
        )
        
        stamp = Stamp(
            stamp_id="no_nonce_test",
            hash=original_hash,
            timestamp=1640995200,
            status="confirmed",
            merkle_proof=merkle_proof,
            nonce=None  # No nonce should raise error
        )
        
        with pytest.raises(BasestampError, match="No nonce available for verification - nonce is required"):
            stamp.verify(original_hash)

    def test_verify_no_proof_raises_error(self):
        """Test verification raises error when no proof available."""
        stamp = Stamp(
            stamp_id="no_proof_test",
            hash="test_hash",
            timestamp=1640995200,
            status="pending",
            merkle_proof=None,
            nonce=None
        )
        
        with pytest.raises(BasestampError, match="No Merkle proof available for verification"):
            stamp.verify("test_hash")

    def test_stamp_repr_with_proof(self):
        """Test Stamp __repr__ method with proof and nonce."""
        # Use a long hash that will be truncated (64 char SHA256)
        original_hash = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
        nonce = "test_nonce_123456789"  # Long nonce that will be truncated
        leaf_hash = calculate_sha256(nonce + original_hash)
        
        merkle_proof = MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=0,
            siblings=["sibling1", "sibling2"],
            directions=[True, False],
            root_hash="root_hash"
        )
        
        stamp = Stamp(
            stamp_id="test_stamp_repr",
            hash=original_hash,
            timestamp=1640995200,  # Fixed timestamp for consistent testing
            status="confirmed",
            merkle_proof=merkle_proof,
            nonce=nonce
        )
        
        repr_str = repr(stamp)
        
        # Check that all important information is present
        assert "Stamp(CONFIRMED)" in repr_str
        assert "test_stamp_repr" in repr_str
        assert original_hash in repr_str  # Original hash
        assert "2022-01-01 00:00:00 UTC" in repr_str  # Formatted timestamp
        assert "Merkle Proof: (2 siblings)" in repr_str
        assert f"Leaf Hash: {leaf_hash}" in repr_str  # Leaf hash
        assert "Root Hash: root_hash" in repr_str  # Root hash
        assert nonce in repr_str  # Full nonce

    def test_stamp_repr_without_proof(self):
        """Test Stamp __repr__ method without proof."""
        stamp = Stamp(
            stamp_id="pending_stamp",
            hash="short_hash",
            timestamp=1640995200,
            status="pending",
            merkle_proof=None,
            nonce=None
        )
        
        repr_str = repr(stamp)
        
        # Check pending stamp representation
        assert "Stamp(PENDING)" in repr_str
        assert "pending_stamp" in repr_str
        assert "short_hash" in repr_str  # Short hash should not be truncated
        assert "2022-01-01 00:00:00 UTC" in repr_str
        assert "No proof available" in repr_str
        # Should not contain proof information
        assert "Merkle Proof" not in repr_str
        assert "Nonce" not in repr_str



class TestBasestampClientMakeRequest:
    """Tests for the internal _make_request method."""

    @patch("basestamp.client.urllib.request.urlopen")
    def test_make_request_timeout(self, mock_urlopen):
        """Test request timeout handling."""
        mock_urlopen.side_effect = create_mock_timeout_error()

        client = BasestampClient()
        with pytest.raises(BasestampError, match="Request timeout after"):
            client._make_request("GET", "/test")

    @patch("basestamp.client.urllib.request.urlopen")
    def test_make_request_connection_error(self, mock_urlopen):
        """Test connection error handling."""
        mock_urlopen.side_effect = create_mock_connection_error("Connection failed")

        client = BasestampClient()
        with pytest.raises(BasestampError, match="Connection failed"):
            client._make_request("GET", "/test")

    @patch("basestamp.client.urllib.request.urlopen")
    def test_make_request_http_error_with_json_error_field(self, mock_urlopen):
        """Test HTTP error handling when response has JSON error field."""
        mock_urlopen.side_effect = create_mock_http_error(404, {"error": "Stamp not found"})

        client = BasestampClient()
        with pytest.raises(BasestampError, match="Stamp not found"):
            client._make_request("GET", "/test")

    @patch("basestamp.client.urllib.request.urlopen")
    def test_make_request_http_error_with_message_field(self, mock_urlopen):
        """Test HTTP error handling when response has JSON message field."""
        mock_urlopen.side_effect = create_mock_http_error(400, {"message": "Invalid request"})

        client = BasestampClient()
        with pytest.raises(BasestampError, match="Invalid request"):
            client._make_request("GET", "/test")

    @patch("basestamp.client.urllib.request.urlopen")
    def test_make_request_http_error_with_invalid_json(self, mock_urlopen):
        """Test HTTP error handling when response has invalid JSON."""
        # Create HTTP error with invalid JSON response
        error = create_mock_http_error(500)
        error.read = Mock(return_value=b"Internal Server Error")  # Invalid JSON
        mock_urlopen.side_effect = error

        client = BasestampClient()
        with pytest.raises(BasestampError, match="Internal Server Error"):
            client._make_request("GET", "/test")

    @patch("basestamp.client.urllib.request.urlopen")
    def test_make_request_invalid_json_response(self, mock_urlopen):
        """Test handling of invalid JSON in successful response."""
        # Create successful response with invalid JSON
        mock_response = Mock()
        mock_response.read.return_value = b"Invalid JSON content"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=None)
        mock_urlopen.return_value = mock_response

        client = BasestampClient()
        with pytest.raises(BasestampError, match="Invalid JSON response"):
            client._make_request("GET", "/test")

    @patch("basestamp.client.urllib.request.urlopen")
    def test_make_request_general_request_exception(self, mock_urlopen):
        """Test handling of general request exceptions."""
        mock_urlopen.side_effect = OSError("General error")

        client = BasestampClient()
        with pytest.raises(BasestampError, match="Request failed: General error"):
            client._make_request("GET", "/test")



class TestBasestampClientContextManager:
    """Tests for context manager functionality."""

    def test_context_manager_usage(self):
        """Test client as context manager."""
        with BasestampClient() as client:
            assert isinstance(client, BasestampClient)

    def test_context_manager_cleanup(self):
        """Test context manager cleanup."""
        client = BasestampClient()
        
        with client:
            pass
            
        # Client should still exist after context exit (no cleanup needed for urllib)
        assert isinstance(client, BasestampClient)

    def test_context_manager_exit_with_exception(self):
        """Test context manager __exit__ method is called even with exceptions."""
        client = BasestampClient()
        
        # The __exit__ method should be called even if an exception occurs
        try:
            with client:
                raise ValueError("Test exception")
        except ValueError:
            pass  # Expected exception
        
        # Client should still exist after exception
        assert isinstance(client, BasestampClient)


class TestTimestampParsing:
    """Tests for timestamp parsing functionality."""

    def test_parse_unix_timestamp_int(self):
        """Test parsing Unix timestamp as integer."""
        result = _parse_timestamp(1640995200)
        assert result == 1640995200

    def test_parse_unix_timestamp_string(self):
        """Test parsing Unix timestamp as string."""
        result = _parse_timestamp("1640995200")
        assert result == 1640995200

    def test_parse_iso8601_with_z_suffix(self):
        """Test parsing ISO 8601 timestamp with Z suffix."""
        # This is the format that was causing the original error
        iso_timestamp = "2025-07-28T02:21:45.496978965Z"
        result = _parse_timestamp(iso_timestamp)
        # Should be a valid Unix timestamp (positive integer)
        assert isinstance(result, int)
        assert result > 0

    def test_parse_iso8601_with_timezone(self):
        """Test parsing ISO 8601 timestamp with timezone offset."""
        iso_timestamp = "2022-01-01T00:00:00+00:00"
        result = _parse_timestamp(iso_timestamp)
        assert result == 1640995200

    def test_parse_iso8601_without_timezone(self):
        """Test parsing ISO 8601 timestamp without timezone."""
        iso_timestamp = "2022-01-01T00:00:00"
        result = _parse_timestamp(iso_timestamp)
        # Should be a valid Unix timestamp
        assert isinstance(result, int)
        assert result > 0

    def test_parse_iso8601_with_microseconds(self):
        """Test parsing ISO 8601 timestamp with microseconds."""
        iso_timestamp = "2022-01-01T00:00:00.123456Z"
        result = _parse_timestamp(iso_timestamp)
        assert isinstance(result, int)
        assert result > 0

    def test_parse_float_timestamp(self):
        """Test parsing float timestamp."""
        result = _parse_timestamp(1640995200.5)
        assert result == 1640995200

    def test_parse_invalid_timestamp_raises_error(self):
        """Test that invalid timestamp format raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported timestamp format"):
            _parse_timestamp("invalid_timestamp_format")

    def test_parse_empty_string_raises_error(self):
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported timestamp format"):
            _parse_timestamp("")

    def test_parse_none_raises_error(self):
        """Test that None raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported timestamp format"):
            _parse_timestamp(None)

    def test_parse_invalid_iso_format_raises_error(self):
        """Test that malformed ISO string raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported timestamp format"):
            _parse_timestamp("not-a-valid-iso-string")
"""Basestamp client implementation."""

import json
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Dict, Optional, Union

from .types import (
    BasestampError,
    ClientOptions,
    MerkleProof,
    ServerRequest,
    Stamp,
)


def _parse_timestamp(timestamp_value: Union[str, int, float]) -> int:
    """Parse timestamp from various formats to Unix timestamp integer.
    
    Args:
        timestamp_value: Timestamp in various formats (Unix int, ISO string, etc.)
        
    Returns:
        Unix timestamp as integer
        
    Raises:
        ValueError: If timestamp format is not supported
    """
    if isinstance(timestamp_value, (int, float)):
        return int(timestamp_value)
    
    if isinstance(timestamp_value, str):
        # Try parsing as integer first (Unix timestamp as string)
        try:
            return int(timestamp_value)
        except ValueError:
            pass
        
        # Try parsing as ISO 8601 datetime string
        try:
            # Handle various ISO 8601 formats
            timestamp_str = timestamp_value
            
            if timestamp_str.endswith('Z'):
                # UTC timezone indicator
                timestamp_str = timestamp_str.replace('Z', '+00:00')
            
            # Handle nanoseconds - Python's fromisoformat only supports up to microseconds
            if '.' in timestamp_str and '+' in timestamp_str:
                # Split at timezone
                date_part, tz_part = timestamp_str.rsplit('+', 1)
                if '.' in date_part:
                    # Truncate fractional seconds to microseconds (6 digits)
                    base_part, frac_part = date_part.split('.')
                    frac_part = frac_part[:6].ljust(6, '0')  # Keep only first 6 digits, pad if needed
                    timestamp_str = f"{base_part}.{frac_part}+{tz_part}"
            elif '.' in timestamp_str:
                # No timezone, just truncate fractional seconds
                base_part, frac_part = timestamp_str.split('.')
                frac_part = frac_part[:6].ljust(6, '0')
                timestamp_str = f"{base_part}.{frac_part}"
            
            dt = datetime.fromisoformat(timestamp_str)
            return int(dt.timestamp())
        except ValueError:
            pass
    
    raise ValueError(f"Unsupported timestamp format: {timestamp_value}")


class BasestampClient:
    """Client for interacting with the Basestamp timestamping service."""

    def __init__(self, options: Optional[ClientOptions] = None) -> None:
        """Initialize the Basestamp client.

        Args:
            options: Client configuration options
        """
        self.options = options or ClientOptions()

        # Set timeout in seconds (convert from milliseconds)
        self.timeout = self.options.timeout / 1000.0

    def submit_sha256(self, hash_value: str) -> str:
        """Submit a SHA256 hash for timestamping.

        Args:
            hash_value: SHA256 hash to timestamp

        Returns:
            stamp_id: Unique identifier for the created stamp

        Raises:
            BasestampError: If the request fails

        Example:
            >>> client = BasestampClient()
            >>> stamp_id = client.submit_sha256("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3")
            >>> print(stamp_id)
        """
        request_data = ServerRequest(hash=hash_value)
        response_data = self._make_request(
            "POST", "/stamp", data=request_data
        )

        return str(response_data["stamp_id"])

    def get_stamp(self, stamp_id: str, wait: bool = False, timeout: int = 30) -> Stamp:
        """Retrieve detailed information about a stamp.

        Args:
            stamp_id: The ID of the stamp to retrieve
            wait: Whether to poll for stamp availability (default: False)
            timeout: Maximum time to wait in seconds (default: 30)

        Returns:
            Stamp object with verification capability

        Raises:
            BasestampError: If the request fails or stamp is not ready when wait=False

        Example:
            >>> client = BasestampClient()
            >>> stamp = client.get_stamp("stamp_12345", wait=True, timeout=60)
            >>> print(stamp.status)
            >>> is_valid = stamp.verify(original_hash)
        """
        start_time = time.time()
        
        while True:
            response_data = self._make_request("GET", f"/stamp/{stamp_id}")
            
            # Check if stamp has proof (is ready)
            has_proof = "merkle_proof" in response_data and response_data["merkle_proof"]
            status = response_data.get("status", "")
            
            # If stamp is ready, return it
            if has_proof:
                proof_data = response_data["merkle_proof"]
                merkle_proof = MerkleProof(
                    leaf_hash=proof_data["leaf_hash"],
                    leaf_index=proof_data["leaf_index"],
                    siblings=proof_data["siblings"],
                    directions=proof_data["directions"],
                    root_hash=proof_data["root_hash"],
                )

                # Extract nonce from response or batch_info
                nonce = response_data.get("nonce")
                if not nonce and "batch_info" in response_data and response_data["batch_info"]:
                    nonce = response_data["batch_info"]["nonce"]

                return Stamp(
                    stamp_id=response_data["stamp_id"],
                    hash=response_data["hash"],
                    timestamp=_parse_timestamp(response_data["timestamp"]),
                    status=status,
                    merkle_proof=merkle_proof,
                    nonce=nonce
                )
            
            # If stamp is not ready and we're not waiting, raise exception
            if not wait:
                raise BasestampError(f"Stamp {stamp_id} is not yet available (status: {status}). Use wait=True to poll for availability.")
            
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                raise BasestampError(f"Timeout waiting for stamp {stamp_id} after {timeout} seconds")
            
            # Wait before next poll
            time.sleep(1)

    def _make_request(
        self, method: str, endpoint: str, data: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Make an HTTP request to the Basestamp API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            data: Optional request data

        Returns:
            Parsed JSON response

        Raises:
            BasestampError: If the request fails
        """
        url = f"{self.options.base_url}{endpoint}"
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "basestamp-python/1.0.0",
        }

        # Prepare request data
        request_data = None
        if data:
            if hasattr(data, "__dict__"):
                # Convert dataclass to dict
                request_data = json.dumps(data.__dict__).encode('utf-8')
            else:
                request_data = json.dumps(data).encode('utf-8')

        try:
            # Create request object
            req = urllib.request.Request(url, data=request_data, headers=headers, method=method)
            
            # Make the request with timeout
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                response_data = response.read().decode('utf-8')
                
                # Parse JSON response
                try:
                    json_data: Dict[str, Any] = json.loads(response_data)
                    return json_data
                except (json.JSONDecodeError, ValueError) as e:
                    raise BasestampError(f"Invalid JSON response: {str(e)}")

        except urllib.error.HTTPError as e:
            # Handle HTTP error responses
            error_message = f"HTTP {e.code}"
            try:
                error_response = e.read().decode('utf-8')
                error_data = json.loads(error_response)
                if "error" in error_data:
                    error_message = error_data["error"]
                elif "message" in error_data:
                    error_message = error_data["message"]
            except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
                error_message = error_response if 'error_response' in locals() else error_message

            raise BasestampError(error_message, e.code)

        except urllib.error.URLError as e:
            if hasattr(e, 'reason') and 'timeout' in str(e.reason).lower():
                raise BasestampError(f"Request timeout after {self.timeout} seconds")
            else:
                raise BasestampError(f"Connection error: {str(e.reason)}")
        
        except OSError as e:
            # This covers socket.timeout and other network-related errors
            if 'timed out' in str(e):
                raise BasestampError(f"Request timeout after {self.timeout} seconds")
            else:
                raise BasestampError(f"Request failed: {str(e)}")

    def __enter__(self) -> "BasestampClient":
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[Exception],
        exc_tb: Optional[object],
    ) -> None:
        """Context manager exit."""
        # No cleanup needed for urllib-based implementation
        pass

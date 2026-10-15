"""Basestamp client implementation."""

import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Dict, Optional, Union
from urllib.parse import quote, urlparse

from .merkle import normalize_hash
from .types import (
    BasestampError,
    ClientOptions,
    MerkleProof,
    ServerRequest,
    Stamp,
)


def _sdk_version() -> str:
    try:
        from importlib.metadata import version

        return version("basestamp")
    except Exception:  # pragma: no cover - not installed as a distribution
        return "0.0.1"


SDK_VERSION = _sdk_version()
# Distinctive User-Agent so the service can count usage per SDK/version.
# No other telemetry is collected.
USER_AGENT = (
    f"basestamp-python/{SDK_VERSION} "
    f"(python {sys.version_info.major}.{sys.version_info.minor})"
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

            if timestamp_str.endswith("Z"):
                # UTC timezone indicator
                timestamp_str = timestamp_str.replace("Z", "+00:00")

            # fromisoformat only supports microseconds; truncate nanoseconds
            if "." in timestamp_str and "+" in timestamp_str:
                # Split at timezone
                date_part, tz_part = timestamp_str.rsplit("+", 1)
                if "." in date_part:
                    # Truncate fractional seconds to microseconds (6 digits)
                    base_part, frac_part = date_part.split(".")
                    frac_part = frac_part[:6].ljust(
                        6, "0"
                    )  # Keep only first 6 digits, pad if needed
                    timestamp_str = f"{base_part}.{frac_part}+{tz_part}"
            elif "." in timestamp_str:
                # No timezone, just truncate fractional seconds
                base_part, frac_part = timestamp_str.split(".")
                frac_part = frac_part[:6].ljust(6, "0")
                timestamp_str = f"{base_part}.{frac_part}"

            dt = datetime.fromisoformat(timestamp_str)
            return int(dt.timestamp())
        except ValueError:
            pass

    raise ValueError(f"Unsupported timestamp format: {timestamp_value}")


_STAMP_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1")


def _validate_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"Invalid base_url: {base_url!r}")
    if parsed.scheme == "http" and parsed.hostname not in _LOCAL_HOSTS:
        raise ValueError(
            f"Refusing insecure base_url {base_url!r}: use https "
            "(plain http is only allowed for localhost)"
        )
    return base_url.rstrip("/")


class BasestampClient:
    """Client for interacting with the Basestamp timestamping service."""

    def __init__(self, options: Optional[ClientOptions] = None) -> None:
        """Initialize the Basestamp client.

        Args:
            options: Client configuration options
        """
        self.options = options or ClientOptions()
        self._base_url = _validate_base_url(self.options.base_url)
        if not self.options.timeout or self.options.timeout <= 0:
            raise ValueError("timeout must be a positive number of milliseconds")

        # Set timeout in seconds (convert from milliseconds)
        self.timeout = self.options.timeout / 1000.0
        self._ssl_context = ssl.create_default_context()

    def submit_sha256(self, hash_value: str) -> str:
        """Submit a SHA256 hash for timestamping.

        Args:
            hash_value: SHA256 hash to timestamp (64 hex chars; an optional
                ``0x`` prefix and uppercase are accepted and normalized)

        Returns:
            stamp_id: Unique identifier for the created stamp

        Raises:
            BasestampError: If the hash is malformed or the request fails

        Example:
            >>> client = BasestampClient()
            >>> stamp_id = client.submit_sha256(calculate_sha256(b"my document"))
            >>> print(stamp_id)
        """
        try:
            normalized = normalize_hash(hash_value)
        except ValueError as e:
            raise BasestampError(str(e))
        request_data = ServerRequest(hash=normalized)
        response_data = self._make_request("POST", "/stamp", data=request_data)

        stamp_id = response_data.get("stamp_id")
        if not isinstance(stamp_id, str) or not _STAMP_ID_RE.match(stamp_id):
            raise BasestampError(f"Server returned an invalid stamp_id: {stamp_id!r}")
        return stamp_id

    def wait_for_confirmation(
        self, stamp_id: str, timeout: float = 600, poll_interval: float = 10
    ) -> Stamp:
        """Poll until the stamp is confirmed on chain and return it.

        Raises:
            BasestampError: on timeout, a failed stamp, or request errors.
        """
        return self.get_stamp(
            stamp_id,
            wait=True,
            timeout=timeout,
            poll_interval=poll_interval,
            require_confirmed=True,
        )

    def health(self) -> Dict[str, Any]:
        """Return the service health document (``GET /health``)."""
        return self._make_request("GET", "/health")

    def get_info(self) -> Dict[str, Any]:
        """Return network/contract/signer info (``GET /info``)."""
        return self._make_request("GET", "/info")

    def get_stamp(
        self,
        stamp_id: str,
        wait: bool = False,
        timeout: float = 30,
        poll_interval: float = 1.0,
        require_confirmed: bool = False,
    ) -> Stamp:
        """Retrieve detailed information about a stamp.

        Args:
            stamp_id: The ID of the stamp to retrieve
            wait: Whether to poll for stamp availability (default: False)
            timeout: Maximum time to wait in seconds (default: 30)
            poll_interval: Seconds between polls when waiting (default: 1)
            require_confirmed: Only return once ``status == "confirmed"``
                (proofs appear earlier, at ``batched``, before the root is
                on chain)

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
        if not isinstance(stamp_id, str) or not _STAMP_ID_RE.match(stamp_id):
            raise BasestampError(f"Invalid stamp_id: {stamp_id!r}")
        start_time = time.time()

        while True:
            response_data = self._make_request(
                "GET", f"/stamp/{quote(stamp_id, safe='')}"
            )

            # Check if stamp has proof (is ready)
            has_proof = bool(response_data.get("merkle_proof"))
            status = response_data.get("status", "")

            if status == "failed":
                raise BasestampError(
                    f"Stamp {stamp_id} failed: {response_data.get('message', '')}"
                )

            ready = has_proof and (not require_confirmed or status == "confirmed")
            if ready:
                return self._parse_stamp(response_data)

            # If stamp is not ready and we're not waiting, raise exception
            if not wait:
                raise BasestampError(
                    f"Stamp {stamp_id} is not yet available (status: {status}). "
                    "Use wait=True to poll for availability."
                )

            # Check timeout
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                raise BasestampError(
                    f"Timeout waiting for stamp {stamp_id} after {timeout} seconds "
                    f"(last status: {status})"
                )

            # Wait before next poll
            time.sleep(max(0.0, min(poll_interval, timeout - elapsed)))

    @staticmethod
    def _parse_stamp(response_data: Dict[str, Any]) -> Stamp:
        try:
            proof_data = response_data["merkle_proof"]
            merkle_proof = MerkleProof(
                leaf_hash=proof_data["leaf_hash"],
                leaf_index=proof_data["leaf_index"],
                siblings=list(proof_data["siblings"]),
                directions=list(proof_data["directions"]),
                root_hash=proof_data["root_hash"],
            )

            # Extract nonce from response or batch_info
            nonce = response_data.get("nonce")
            if not nonce and response_data.get("batch_info"):
                nonce = response_data["batch_info"].get("nonce")
            if nonce is not None and not isinstance(nonce, str):
                nonce = str(nonce)
            merkle_proof.nonce = nonce

            return Stamp(
                stamp_id=response_data["stamp_id"],
                hash=response_data["hash"],
                timestamp=_parse_timestamp(response_data["timestamp"]),
                status=response_data.get("status", ""),
                merkle_proof=merkle_proof,
                nonce=nonce,
                tx_id=response_data.get("tx_id") or None,
                block_hash=response_data.get("block_hash") or None,
                merkle_root=response_data.get("merkle_root") or None,
                network=response_data.get("network"),
                message=response_data.get("message"),
                raw=response_data,
            )
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            raise BasestampError(f"Malformed stamp response: {e!r}")

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
        url = f"{self._base_url}{endpoint}"
        headers = {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }

        # Prepare request data
        request_data = None
        if data is not None:
            if hasattr(data, "__dict__"):
                # Convert dataclass to dict
                request_data = json.dumps(data.__dict__).encode("utf-8")
            else:
                request_data = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"

        try:
            # Create request object
            req = urllib.request.Request(
                url, data=request_data, headers=headers, method=method
            )

            # Make the request with timeout
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=self._ssl_context
            ) as response:
                # Refuse https -> http downgrades via redirects.
                final_url = response.geturl() if hasattr(response, "geturl") else None
                if (
                    isinstance(final_url, str)
                    and url.startswith("https://")
                    and not final_url.startswith("https://")
                ):
                    raise BasestampError(f"Insecure redirect to {final_url}")
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_RESPONSE_BYTES:
                    raise BasestampError("Response too large")

                # Parse JSON response
                try:
                    json_data = json.loads(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as e:
                    raise BasestampError(f"Invalid JSON response: {str(e)}")
                if not isinstance(json_data, dict):
                    raise BasestampError("Invalid JSON response: expected an object")
                return json_data

        except urllib.error.HTTPError as e:
            # Handle HTTP error responses
            error_message = f"HTTP {e.code}"
            error_response = ""
            try:
                error_response = (e.read(64 * 1024) or b"").decode("utf-8", "replace")
                error_data = json.loads(error_response)
                if isinstance(error_data, dict) and "error" in error_data:
                    error_message = str(error_data["error"])
                elif isinstance(error_data, dict) and "message" in error_data:
                    error_message = str(error_data["message"])
            except (ValueError, TypeError, AttributeError, OSError):
                if error_response:
                    error_message = error_response[:500]

            raise BasestampError(error_message, e.code)

        except urllib.error.URLError as e:
            if hasattr(e, "reason") and "timeout" in str(e.reason).lower():
                raise BasestampError(f"Request timeout after {self.timeout} seconds")
            else:
                raise BasestampError(f"Connection error: {str(e.reason)}")

        except OSError as e:
            # This covers socket.timeout and other network-related errors
            if "timed out" in str(e):
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

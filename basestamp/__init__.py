"""Basestamp Python Client Library.

A Python client library for the Basestamp cryptographic timestamping service.
Provides trustless Merkle proof verification for digital data.
"""

from .client import BasestampClient
from .merkle import calculate_sha256, verify_merkle_proof
from .types import (
    BasestampError,
    ClientOptions,
    MerkleProof,
    ServerRequest,
    Stamp,
)

__version__ = "1.0.0"
__author__ = "Basestamp"
__email__ = "support@basestamp.com"

__all__ = [
    "BasestampClient",
    "calculate_sha256",
    "verify_merkle_proof",
    "BasestampError",
    "ClientOptions",
    "MerkleProof",
    "ServerRequest",
    "Stamp",
]

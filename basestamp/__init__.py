"""Basestamp Python Client Library.

A Python client library for the Basestamp cryptographic timestamping service.
Provides trustless Merkle proof verification for digital data.
"""

from .chain import (
    STAMPED_TOPIC,
    JsonRpcClient,
    OnChainVerification,
    verify_root_on_chain,
)
from .client import BasestampClient
from .merkle import (
    calculate_sha256,
    compute_leaf_hash,
    compute_merkle_root,
    is_valid_hash,
    normalize_hash,
    verify_merkle_proof,
    verify_proof,
)
from .types import (
    DEFAULT_BASE_URL,
    MAINNET_BASE_URL,
    MAINNET_CHAIN_ID,
    MAINNET_CONTRACT_ADDRESS,
    MAINNET_RPC_URL,
    MAINNET_SIGNER_ADDRESS,
    SEPOLIA_BASE_URL,
    SEPOLIA_CHAIN_ID,
    SEPOLIA_CONTRACT_ADDRESS,
    SEPOLIA_RPC_URL,
    BasestampError,
    ClientOptions,
    MerkleProof,
    ServerRequest,
    Stamp,
)

__version__ = "0.1.0"
__author__ = "Basestamp"
__email__ = "support@basestamp.io"

__all__ = [
    "BasestampClient",
    "calculate_sha256",
    "verify_merkle_proof",
    "compute_leaf_hash",
    "compute_merkle_root",
    "verify_proof",
    "is_valid_hash",
    "normalize_hash",
    "verify_root_on_chain",
    "JsonRpcClient",
    "OnChainVerification",
    "STAMPED_TOPIC",
    "MAINNET_SIGNER_ADDRESS",
    "BasestampError",
    "ClientOptions",
    "MerkleProof",
    "ServerRequest",
    "Stamp",
    "DEFAULT_BASE_URL",
    "MAINNET_BASE_URL",
    "MAINNET_CHAIN_ID",
    "MAINNET_CONTRACT_ADDRESS",
    "MAINNET_RPC_URL",
    "SEPOLIA_BASE_URL",
    "SEPOLIA_CHAIN_ID",
    "SEPOLIA_CONTRACT_ADDRESS",
    "SEPOLIA_RPC_URL",
]

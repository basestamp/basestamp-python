"""Shared cross-SDK test vectors (testdata/vectors.json).

The same file is used by basestamp-python, basestamp-ts and basestamp-go.
Each vector is ``{name, hash, nonce, proof, expected_root, valid}`` where
``proof`` is the ``merkle_proof`` object exactly as returned by the API.
"""

import json
from pathlib import Path

import pytest

from basestamp import BasestampError, verify_proof
from basestamp.client import BasestampClient

VECTORS = json.loads(
    (Path(__file__).parent.parent / "testdata" / "vectors.json").read_text()
)


def test_vectors_present():
    assert any(v["valid"] for v in VECTORS)
    assert any(not v["valid"] for v in VECTORS)
    assert any(v["name"].startswith("mainnet-") for v in VECTORS)


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector(vector):
    result = verify_proof(
        vector["hash"], vector["nonce"], vector["proof"], vector["expected_root"]
    )
    assert result is vector["valid"]


@pytest.mark.parametrize(
    "vector",
    [v for v in VECTORS if "stamp_id" in v],
    ids=[v["name"] for v in VECTORS if "stamp_id" in v],
)
def test_real_vectors_through_stamp_api(vector):
    """Real mainnet responses parse and verify through the high-level API."""
    stamp = BasestampClient._parse_stamp(
        {
            "stamp_id": vector["stamp_id"],
            "hash": vector["hash"],
            "nonce": vector["nonce"],
            "status": "confirmed",
            "timestamp": "2026-10-15T17:07:04.081979442Z",
            "merkle_root": vector["expected_root"],
            "merkle_proof": vector["proof"],
            "tx_id": vector.get("tx_id"),
        }
    )
    assert stamp.verify(vector["hash"]) is True
    assert stamp.merkle_proof.verify(vector["hash"]) is True
    with pytest.raises(BasestampError):
        stamp.verify("00" * 32)

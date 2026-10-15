"""End-to-end test against the production Basestamp API on Base mainnet.

Skipped unless ``BASESTAMP_E2E=1``. Each run stamps a random hash, which costs
the service real ETH - never run this in a loop.

Optional environment variables:

* ``BASESTAMP_E2E_STAMP_ID`` + ``BASESTAMP_E2E_HASH``: re-verify an existing
  stamp instead of submitting a new one (no cost).
* ``BASESTAMP_E2E_RECORD``: path to write a JSON record (stamp id, hash, tx,
  root and the raw API response) as soon as the stamp is confirmed.
* ``BASESTAMP_BASE_URL`` / ``BASESTAMP_RPC_URL``: override endpoints.
"""

import json
import os
import secrets

import pytest

from basestamp import (
    MAINNET_BASE_URL,
    MAINNET_RPC_URL,
    BasestampClient,
    BasestampError,
    ClientOptions,
    verify_root_on_chain,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("BASESTAMP_E2E") != "1",
    reason="set BASESTAMP_E2E=1 to run the mainnet end-to-end test",
)


def test_e2e_stamp_confirm_and_verify_on_mainnet():
    base_url = os.environ.get("BASESTAMP_BASE_URL", MAINNET_BASE_URL)
    rpc_url = os.environ.get("BASESTAMP_RPC_URL", MAINNET_RPC_URL)
    client = BasestampClient(ClientOptions(base_url=base_url, timeout=30000))

    stamp_id = os.environ.get("BASESTAMP_E2E_STAMP_ID")
    hash_value = os.environ.get("BASESTAMP_E2E_HASH")
    if stamp_id and hash_value:
        print(f"\nRe-verifying existing stamp {stamp_id}")
    else:
        hash_value = secrets.token_bytes(32).hex()
        stamp_id = client.submit_sha256(hash_value)
        print(f"\nSubmitted hash {hash_value} -> stamp {stamp_id}")

    stamp = client.wait_for_confirmation(stamp_id, timeout=600, poll_interval=12)
    assert stamp.merkle_proof is not None
    print(f"Confirmed: tx {stamp.tx_id} root {stamp.merkle_proof.root_hash}")
    if stamp.tx_id:
        print(f"https://basescan.org/tx/{stamp.tx_id}")

    record_path = os.environ.get("BASESTAMP_E2E_RECORD")
    if record_path:
        with open(record_path, "w") as f:
            json.dump(
                {
                    "stamp_id": stamp_id,
                    "hash": hash_value,
                    "tx_id": stamp.tx_id,
                    "root": stamp.merkle_proof.root_hash,
                    "response": stamp.raw,
                },
                f,
                indent=2,
            )

    # Local verification: leaf binding + merkle path.
    assert stamp.verify(hash_value) is True
    assert stamp.merkle_proof.verify(hash_value) is True
    with pytest.raises(BasestampError):
        stamp.verify(secrets.token_bytes(32).hex())

    # On-chain verification: the root was emitted by the contract in tx_id.
    assert stamp.tx_id, "confirmed stamp has no tx_id"
    result = stamp.verify_on_chain(rpc_url=rpc_url)
    assert result.root_hash == stamp.merkle_proof.root_hash.lower()
    assert result.tx_hash == stamp.tx_id.lower()
    print(
        f"On-chain OK: block {result.block_number} ({result.confirmations} conf), "
        f"stamper {result.stamper}"
    )

    # A different root must not verify against the same transaction.
    tampered = format(int(stamp.merkle_proof.root_hash, 16) ^ 1, "064x")
    with pytest.raises(BasestampError):
        verify_root_on_chain(tampered, stamp.tx_id, rpc_url=rpc_url)

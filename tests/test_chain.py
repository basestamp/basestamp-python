"""Tests for on-chain verification (JSON-RPC mocked; data from mainnet E2E)."""

import io
import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from basestamp import BasestampError, MerkleProof, Stamp
from basestamp.chain import (
    OWNER_SELECTOR,
    STAMPED_TOPIC,
    JsonRpcClient,
    _topic_address,
    verify_root_on_chain,
)
from basestamp.types import MAINNET_CONTRACT_ADDRESS, MAINNET_SIGNER_ADDRESS

ROOT = "2c40530e143439d1544458803f311477d5853d6488b6ed8ff66d59fb9f510ee2"
TX = "0xe6b893740c88652ada17540223e20f68c160787329776404ff54f615937e6261"
BLOCK_HASH = "0xeb4fe8cf93d548e8d46fc8b30b5ce40fbb3ec3f5f9f19bfcc4a5404f4a1316a7"
BLOCK = 52647348
CONTRACT = MAINNET_CONTRACT_ADDRESS.lower()
SIGNER = MAINNET_SIGNER_ADDRESS.lower()


def make_log(root=ROOT, address=CONTRACT, stamper=SIGNER, removed=False):
    return {
        "address": address,
        "topics": [STAMPED_TOPIC, "0x" + root, _topic_address(stamper)],
        "data": "0x" + format(1792084044, "064x") + format(BLOCK, "064x"),
        "blockNumber": hex(BLOCK),
        "blockHash": BLOCK_HASH,
        "transactionHash": TX,
        "removed": removed,
    }


class FakeRpc(JsonRpcClient):
    """In-memory JSON-RPC stub."""

    def __init__(self, **overrides):
        super().__init__("https://rpc.example")
        self.state = {
            "eth_chainId": "0x2105",
            "eth_blockNumber": hex(BLOCK + 9),
            "owner": "0x" + "0" * 24 + SIGNER[2:],
            "receipt": {
                "status": "0x1",
                "to": CONTRACT,
                "logs": [make_log(root="11" * 32), make_log()],
            },
            "logs": [make_log()],
            "block": {"hash": BLOCK_HASH},
        }
        self.state.update(overrides)
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "eth_chainId":
            return self.state["eth_chainId"]
        if method == "eth_blockNumber":
            return self.state["eth_blockNumber"]
        if method == "eth_call":
            assert params[0]["data"] == OWNER_SELECTOR
            return self.state["owner"]
        if method == "eth_getTransactionReceipt":
            return self.state["receipt"]
        if method == "eth_getLogs":
            f = params[0]
            return [
                log
                for log in self.state["logs"]
                if int(f["fromBlock"], 16)
                <= int(log["blockNumber"], 16)
                <= int(f["toBlock"], 16)
            ]
        if method == "eth_getBlockByNumber":
            return self.state["block"]
        raise AssertionError(method)


class TestVerifyRootOnChain:
    def test_receipt_success(self):
        result = verify_root_on_chain(ROOT, TX, rpc=FakeRpc())
        assert result.root_hash == ROOT
        assert result.tx_hash == TX
        assert result.block_number == BLOCK
        assert result.block_hash == BLOCK_HASH
        assert result.block_timestamp == 1792084044
        assert result.stamper == SIGNER
        assert result.chain_id == 8453
        assert result.confirmations == 10

    def test_accepts_prefixed_uppercase_root_and_bare_tx(self):
        result = verify_root_on_chain("0x" + ROOT.upper(), TX[2:], rpc=FakeRpc())
        assert result.root_hash == ROOT

    def test_tampered_root_fails(self):
        bad = ROOT[:-1] + ("0" if ROOT[-1] != "0" else "1")
        with pytest.raises(BasestampError, match="did not emit a stamp event"):
            verify_root_on_chain(bad, TX, rpc=FakeRpc())

    def test_wrong_chain(self):
        with pytest.raises(BasestampError, match="chain 84532"):
            verify_root_on_chain(ROOT, TX, rpc=FakeRpc(eth_chainId=hex(84532)))

    def test_chain_check_can_be_skipped(self):
        rpc = FakeRpc(eth_chainId=hex(1))
        assert verify_root_on_chain(ROOT, TX, rpc=rpc, chain_id=None).chain_id == 1

    def test_owner_mismatch(self):
        with pytest.raises(BasestampError, match="does not match expected signer"):
            verify_root_on_chain(ROOT, TX, rpc=FakeRpc(owner="0x" + "0" * 63 + "1"))

    def test_no_contract(self):
        with pytest.raises(BasestampError, match="did not return an owner"):
            verify_root_on_chain(ROOT, TX, rpc=FakeRpc(owner="0x"))

    def test_log_from_other_stamper_rejected(self):
        receipt = {
            "status": "0x1",
            "to": CONTRACT,
            "logs": [make_log(stamper="0x" + "ab" * 20)],
        }
        with pytest.raises(BasestampError, match="did not emit"):
            verify_root_on_chain(ROOT, TX, rpc=FakeRpc(receipt=receipt))

    def test_signer_check_can_be_skipped(self):
        other = "0x" + "ab" * 20
        receipt = {"status": "0x1", "to": CONTRACT, "logs": [make_log(stamper=other)]}
        result = verify_root_on_chain(
            ROOT, TX, rpc=FakeRpc(receipt=receipt), signer_address=None
        )
        assert result.stamper == other

    @pytest.mark.parametrize(
        "log",
        [
            make_log(address="0x" + "cd" * 20),
            make_log(removed=True),
            dict(make_log(), topics=[STAMPED_TOPIC, "0x" + ROOT]),
            dict(
                make_log(),
                topics=["0x" + "00" * 32, "0x" + ROOT, _topic_address(SIGNER)],
            ),
            "not-a-log",
        ],
    )
    def test_non_matching_logs_rejected(self, log):
        receipt = {"status": "0x1", "to": CONTRACT, "logs": [log]}
        with pytest.raises(BasestampError, match="did not emit"):
            verify_root_on_chain(ROOT, TX, rpc=FakeRpc(receipt=receipt))

    def test_receipt_missing(self):
        with pytest.raises(BasestampError, match="not found"):
            verify_root_on_chain(ROOT, TX, rpc=FakeRpc(receipt=None))

    def test_receipt_reverted(self):
        receipt = {"status": "0x0", "to": CONTRACT, "logs": [make_log()]}
        with pytest.raises(BasestampError, match="reverted"):
            verify_root_on_chain(ROOT, TX, rpc=FakeRpc(receipt=receipt))

    def test_receipt_wrong_destination(self):
        receipt = {"status": "0x1", "to": "0x" + "cd" * 20, "logs": [make_log()]}
        with pytest.raises(BasestampError, match="not sent to the Basestamp contract"):
            verify_root_on_chain(ROOT, TX, rpc=FakeRpc(receipt=receipt))

    def test_malformed_status(self):
        receipt = {"status": None, "to": CONTRACT, "logs": []}
        with pytest.raises(BasestampError, match="Malformed receipt status"):
            verify_root_on_chain(ROOT, TX, rpc=FakeRpc(receipt=receipt))
        receipt = {"status": "0xzz", "to": CONTRACT, "logs": []}
        with pytest.raises(BasestampError, match="Malformed receipt status"):
            verify_root_on_chain(ROOT, TX, rpc=FakeRpc(receipt=receipt))

    def test_min_confirmations(self):
        with pytest.raises(BasestampError, match="confirmations"):
            verify_root_on_chain(ROOT, TX, rpc=FakeRpc(), min_confirmations=11)

    def test_malformed_event_data_tolerated(self):
        log = dict(make_log(), data="0x" + "zz" * 64)
        receipt = {"status": "0x1", "to": CONTRACT, "logs": [log]}
        assert (
            verify_root_on_chain(ROOT, TX, rpc=FakeRpc(receipt=receipt)).block_timestamp
            == 0
        )

    def test_reorged_block(self):
        with pytest.raises(BasestampError, match="no longer canonical"):
            verify_root_on_chain(
                ROOT, TX, rpc=FakeRpc(block={"hash": "0x" + "00" * 32})
            )

    def test_expected_block_hash(self):
        assert verify_root_on_chain(
            ROOT, TX, rpc=FakeRpc(), expected_block_hash=BLOCK_HASH[2:].upper()
        )
        with pytest.raises(BasestampError, match="expected"):
            verify_root_on_chain(
                ROOT, TX, rpc=FakeRpc(), expected_block_hash="0x" + "00" * 32
            )

    def test_log_search_without_tx(self):
        rpc = FakeRpc()
        result = verify_root_on_chain(
            ROOT, rpc=rpc, log_chunk_size=4, max_log_blocks=20
        )
        assert result.tx_hash == TX
        searches = [c for c in rpc.calls if c[0] == "eth_getLogs"]
        assert len(searches) == 3  # newest windows first, stops once found
        assert searches[0][1][0]["topics"] == [
            STAMPED_TOPIC,
            "0x" + ROOT,
            _topic_address(SIGNER),
        ]

    def test_log_search_explicit_range_not_found(self):
        rpc = FakeRpc()
        with pytest.raises(BasestampError, match="No stamp event"):
            verify_root_on_chain(
                ROOT,
                rpc=rpc,
                from_block=BLOCK + 1,
                to_block=BLOCK + 100,
                signer_address=None,
            )

    def test_invalid_inputs(self):
        with pytest.raises(ValueError):
            verify_root_on_chain("nothex", TX, rpc=FakeRpc())
        with pytest.raises(BasestampError, match="transaction hash"):
            verify_root_on_chain(ROOT, "0x1234", rpc=FakeRpc())
        with pytest.raises(BasestampError, match="transaction hash"):
            verify_root_on_chain(ROOT, 1234, rpc=FakeRpc())
        with pytest.raises(BasestampError, match="contract address"):
            verify_root_on_chain(ROOT, TX, rpc=FakeRpc(), contract_address="0x12")

    def test_default_client_constructed(self):
        with patch("basestamp.chain.JsonRpcClient") as cls:
            cls.return_value = FakeRpc()
            verify_root_on_chain(ROOT, TX, rpc_url="https://rpc.example", timeout=5)
            cls.assert_called_once_with("https://rpc.example", timeout=5)


class TestStampVerifyOnChain:
    def test_uses_tx_and_block_hash(self):
        proof = MerkleProof(ROOT, 0, [], [], ROOT)
        stamp = Stamp(
            "id", "ab" * 32, 0, "confirmed", proof, "1", tx_id=TX, block_hash=BLOCK_HASH
        )
        assert stamp.verify_on_chain(rpc=FakeRpc()).tx_hash == TX

    def test_requires_proof(self):
        with pytest.raises(BasestampError, match="No Merkle proof"):
            Stamp("id", "ab" * 32, 0, "pending").verify_on_chain(rpc=FakeRpc())


def _resp(payload):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    m = MagicMock()
    m.__enter__.return_value.read.return_value = body
    return m


def _http_error(code):
    return urllib.error.HTTPError(
        "https://rpc.example", code, "err", {}, io.BytesIO(b"")
    )


class TestJsonRpcClient:
    def test_rejects_insecure_url(self):
        with pytest.raises(BasestampError, match="https"):
            JsonRpcClient("http://rpc.example")
        JsonRpcClient("http://localhost:8545")

    def test_rejects_bad_timeout(self):
        with pytest.raises(BasestampError, match="timeout"):
            JsonRpcClient("https://rpc.example", timeout=0)

    @patch("basestamp.chain.urllib.request.urlopen")
    def test_success_sets_user_agent(self, urlopen):
        urlopen.return_value = _resp({"jsonrpc": "2.0", "id": 1, "result": "0x2105"})
        rpc = JsonRpcClient("https://rpc.example")
        assert rpc.call("eth_chainId", []) == "0x2105"
        req = urlopen.call_args[0][0]
        assert req.get_header("User-agent").startswith("basestamp-python/")
        assert "context" in urlopen.call_args[1]

    @patch("basestamp.chain.time.sleep")
    @patch("basestamp.chain.urllib.request.urlopen")
    def test_retries_transient_errors(self, urlopen, sleep):
        urlopen.side_effect = [
            _http_error(429),
            urllib.error.URLError("timed out"),
            _resp({"error": {"code": -32005, "message": "limit exceeded"}}),
            _resp({"result": "0x1"}),
        ]
        rpc = JsonRpcClient("https://rpc.example", backoff=0.01)
        assert rpc.call("eth_blockNumber", []) == "0x1"
        assert sleep.call_count == 3

    @patch("basestamp.chain.time.sleep")
    @patch("basestamp.chain.urllib.request.urlopen")
    def test_gives_up_after_retries(self, urlopen, sleep):
        urlopen.side_effect = _http_error(503)
        rpc = JsonRpcClient("https://rpc.example", max_retries=2)
        with pytest.raises(BasestampError, match="after 3 attempts"):
            rpc.call("eth_blockNumber", [])
        assert urlopen.call_count == 3

    @patch("basestamp.chain.urllib.request.urlopen")
    def test_non_retryable_http_error(self, urlopen):
        urlopen.side_effect = _http_error(403)
        with pytest.raises(BasestampError, match="HTTP 403"):
            JsonRpcClient("https://rpc.example").call("eth_chainId", [])

    @pytest.mark.parametrize(
        "body,match",
        [
            (b"not json", "invalid JSON"),
            (b"[1]", "unexpected payload"),
            (
                json.dumps(
                    {"error": {"code": 3, "message": "execution reverted"}}
                ).encode(),
                "execution reverted",
            ),
            (json.dumps({"error": "boom"}).encode(), "boom"),
        ],
    )
    @patch("basestamp.chain.urllib.request.urlopen")
    def test_bad_responses(self, urlopen, body, match):
        urlopen.return_value = _resp(body)
        with pytest.raises(BasestampError, match=match):
            JsonRpcClient("https://rpc.example").call("eth_call", [])

    @patch("basestamp.chain._MAX_RESPONSE_BYTES", 8)
    @patch("basestamp.chain.urllib.request.urlopen")
    def test_response_too_large(self, urlopen):
        urlopen.return_value = _resp({"result": "0x" + "0" * 64})
        with pytest.raises(BasestampError, match="too large"):
            JsonRpcClient("https://rpc.example").call("eth_call", [])

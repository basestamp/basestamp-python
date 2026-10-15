"""Tests for input validation and transport hardening."""

import json
from unittest.mock import MagicMock, patch

import pytest

from basestamp import BasestampClient, BasestampError, ClientOptions, MerkleProof, Stamp
from basestamp.merkle import _hash_pair, calculate_sha256

HASH = calculate_sha256("doc")
NONCE = "1792084040825303971"
LEAF = calculate_sha256(NONCE + HASH)
SIB = calculate_sha256("sibling")
ROOT = _hash_pair(LEAF, SIB)


def stamp_response(status="confirmed", **extra):
    data = {
        "stamp_id": "abc123",
        "hash": HASH,
        "status": status,
        "timestamp": "2026-10-15T17:07:24.066953318Z",
        "nonce": NONCE,
        "merkle_root": ROOT,
        "merkle_proof": {
            "leaf_hash": LEAF,
            "leaf_index": 0,
            "siblings": [SIB],
            "directions": [True],
            "root_hash": ROOT,
        },
        "tx_id": "0x" + "ab" * 32,
        "block_hash": "0x" + "cd" * 32,
        "network": "BASE Mainnet",
    }
    data.update(extra)
    return data


def mock_response(payload, url=None):
    m = MagicMock()
    inner = m.__enter__.return_value
    inner.read.return_value = (
        payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    )
    inner.geturl.return_value = url
    return m


class TestClientOptionsValidation:
    @pytest.mark.parametrize(
        "url", ["http://api.example.com", "ftp://x", "api-mainnet.basestamp.io", ""]
    )
    def test_rejects_insecure_or_invalid_base_url(self, url):
        with pytest.raises(ValueError):
            BasestampClient(ClientOptions(base_url=url))

    def test_allows_localhost_http_and_strips_slash(self):
        client = BasestampClient(ClientOptions(base_url="http://localhost:8080/"))
        assert client._base_url == "http://localhost:8080"

    @pytest.mark.parametrize("timeout", [0, -1])
    def test_rejects_bad_timeout(self, timeout):
        with pytest.raises(ValueError):
            BasestampClient(ClientOptions(timeout=timeout))


class TestSubmitValidation:
    @pytest.mark.parametrize("bad", ["", "abc", "zz" * 32, None, "ab" * 33])
    def test_rejects_malformed_hash(self, bad):
        with patch("basestamp.client.urllib.request.urlopen") as urlopen:
            with pytest.raises(BasestampError, match="Invalid hash"):
                BasestampClient().submit_sha256(bad)
            urlopen.assert_not_called()

    @patch("basestamp.client.urllib.request.urlopen")
    def test_normalizes_hash(self, urlopen):
        urlopen.return_value = mock_response({"stamp_id": "abc"})
        BasestampClient().submit_sha256("0x" + HASH.upper())
        body = json.loads(urlopen.call_args[0][0].data)
        assert body == {"hash": HASH}

    @pytest.mark.parametrize("sid", [None, "", "../x", 5])
    @patch("basestamp.client.urllib.request.urlopen")
    def test_rejects_bad_stamp_id_from_server(self, urlopen, sid):
        urlopen.return_value = mock_response({"stamp_id": sid})
        with pytest.raises(BasestampError, match="invalid stamp_id"):
            BasestampClient().submit_sha256(HASH)


class TestGetStampHardening:
    @pytest.mark.parametrize("sid", ["../../health", "a/b", "", "x" * 200, None])
    def test_rejects_bad_stamp_id(self, sid):
        with pytest.raises(BasestampError, match="Invalid stamp_id"):
            BasestampClient().get_stamp(sid)

    @patch("basestamp.client.urllib.request.urlopen")
    def test_parses_chain_fields(self, urlopen):
        urlopen.return_value = mock_response(stamp_response())
        stamp = BasestampClient().get_stamp("abc123")
        assert stamp.tx_id == "0x" + "ab" * 32
        assert stamp.block_hash == "0x" + "cd" * 32
        assert stamp.merkle_root == ROOT
        assert stamp.network == "BASE Mainnet"
        assert stamp.is_confirmed
        assert stamp.raw["stamp_id"] == "abc123"
        assert stamp.merkle_proof.nonce == NONCE
        assert stamp.verify(HASH)

    @patch("basestamp.client.urllib.request.urlopen")
    def test_numeric_nonce_coerced(self, urlopen):
        urlopen.return_value = mock_response(stamp_response(nonce=int(NONCE)))
        assert BasestampClient().get_stamp("abc123").verify(HASH)

    @patch("basestamp.client.urllib.request.urlopen")
    def test_failed_status_raises(self, urlopen):
        urlopen.return_value = mock_response({"status": "failed", "message": "boom"})
        with pytest.raises(BasestampError, match="failed: boom"):
            BasestampClient().get_stamp("abc123", wait=True)

    @patch("basestamp.client.urllib.request.urlopen")
    def test_malformed_proof_raises(self, urlopen):
        urlopen.return_value = mock_response(
            stamp_response(merkle_proof={"leaf_hash": LEAF})
        )
        with pytest.raises(BasestampError, match="Malformed stamp response"):
            BasestampClient().get_stamp("abc123")

    @patch("basestamp.client.time.sleep")
    @patch("basestamp.client.urllib.request.urlopen")
    def test_wait_for_confirmation_skips_batched(self, urlopen, sleep):
        urlopen.side_effect = [
            mock_response({"status": "pending"}),
            mock_response(stamp_response(status="batched", tx_id="")),
            mock_response(stamp_response()),
        ]
        stamp = BasestampClient().wait_for_confirmation("abc123", poll_interval=5)
        assert stamp.status == "confirmed"
        assert sleep.call_count == 2
        assert sleep.call_args[0][0] == 5

    @patch("basestamp.client.urllib.request.urlopen")
    def test_health_and_info(self, urlopen):
        urlopen.return_value = mock_response({"status": "healthy"})
        client = BasestampClient()
        assert client.health() == {"status": "healthy"}
        assert client.get_info() == {"status": "healthy"}
        assert urlopen.call_args[0][0].get_full_url().endswith("/info")


class TestTransportHardening:
    @patch("basestamp.client.urllib.request.urlopen")
    def test_rejects_https_downgrade_redirect(self, urlopen):
        urlopen.return_value = mock_response({}, url="http://evil.example/stamp")
        with pytest.raises(BasestampError, match="Insecure redirect"):
            BasestampClient().health()

    @patch("basestamp.client._MAX_RESPONSE_BYTES", 4)
    @patch("basestamp.client.urllib.request.urlopen")
    def test_response_too_large(self, urlopen):
        urlopen.return_value = mock_response({"status": "healthy"})
        with pytest.raises(BasestampError, match="too large"):
            BasestampClient().health()

    @patch("basestamp.client.urllib.request.urlopen")
    def test_non_object_json(self, urlopen):
        urlopen.return_value = mock_response([1, 2])
        with pytest.raises(BasestampError, match="expected an object"):
            BasestampClient().health()

    @patch("basestamp.client.urllib.request.urlopen")
    def test_uses_verified_tls_context(self, urlopen):
        urlopen.return_value = mock_response({})
        client = BasestampClient()
        client.health()
        ctx = urlopen.call_args[1]["context"]
        assert ctx.verify_mode.name == "CERT_REQUIRED"
        assert ctx.check_hostname is True


class TestVerificationHardening:
    def make_stamp(self, **kw):
        proof = MerkleProof(LEAF, 0, [SIB], [True], ROOT, nonce=NONCE)
        args = dict(
            stamp_id="abc",
            hash=HASH,
            timestamp=0,
            status="confirmed",
            merkle_proof=proof,
            nonce=NONCE,
            merkle_root=ROOT,
        )
        args.update(kw)
        return Stamp(**args)

    def test_valid(self):
        assert self.make_stamp().verify("0x" + HASH.upper())

    def test_malformed_hash(self):
        with pytest.raises(BasestampError, match="Invalid original hash"):
            self.make_stamp().verify("nope")

    def test_merkle_root_mismatch(self):
        with pytest.raises(BasestampError, match="does not match merkle_root"):
            self.make_stamp(merkle_root=SIB).verify(HASH)

    def test_tampered_sibling(self):
        proof = MerkleProof(LEAF, 0, [calculate_sha256("x")], [True], ROOT)
        with pytest.raises(BasestampError, match="proof structure is invalid"):
            self.make_stamp(merkle_proof=proof).verify(HASH)

    def test_tampered_root_both(self):
        proof = MerkleProof(LEAF, 0, [SIB], [True], SIB)
        with pytest.raises(BasestampError, match="proof structure is invalid"):
            self.make_stamp(merkle_proof=proof, merkle_root=SIB).verify(HASH)

    def test_wrong_nonce(self):
        with pytest.raises(BasestampError, match="Calculated leaf hash"):
            self.make_stamp(nonce="1").verify(HASH)

    def test_merkle_proof_verify_malformed(self):
        proof = MerkleProof("bad", 0, [], [], "bad", nonce=NONCE)
        assert proof.verify(HASH) is False
        proof = MerkleProof(LEAF, 0, [SIB], [True], ROOT, nonce=NONCE)
        assert proof.verify("bad") is False
        assert proof.verify(HASH.upper()) is True

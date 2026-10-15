"""On-chain verification of Basestamp merkle roots via Ethereum JSON-RPC.

The Basestamp contract on Base is deliberately minimal. Its deployed bytecode
exposes exactly two functions::

    owner() -> address                  (selector 0x8da5cb5b, immutable signer)
    stamp(bytes32 root)                 (selector 0xdd89581f, owner only;
                                         reverts with NotOwner() otherwise)

``stamp`` does not write storage; it only emits one event::

    topic0 = 0x88ad9da3...6b600         (event signature hash, see STAMPED_TOPIC)
    topic1 = merkle root                (bytes32, indexed)
    topic2 = stamper                    (address, indexed, always msg.sender == owner)
    data   = abi.encode(uint256 block.timestamp, uint256 block.number)

There is no storage slot to read with ``eth_call``, so a root is proven to be
anchored by finding a matching event log emitted by the contract, either in
the receipt of the stamping transaction (preferred, uses ``tx_id`` from the
API) or by searching ``eth_getLogs`` filtered by the root topic.
"""

import json
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from .merkle import normalize_hash
from .types import (
    MAINNET_CHAIN_ID,
    MAINNET_CONTRACT_ADDRESS,
    MAINNET_RPC_URL,
    MAINNET_SIGNER_ADDRESS,
    BasestampError,
)

#: topic0 of the event emitted by ``stamp(bytes32)`` (read from deployed bytecode).
STAMPED_TOPIC = "0x88ad9da3b29de3590ad9ee465751a6e2a86d8174c41c6a8fabe9360b13deb600"
#: ``stamp(bytes32)`` function selector.
STAMP_SELECTOR = "0xdd89581f"
#: ``owner()`` function selector.
OWNER_SELECTOR = "0x8da5cb5b"

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_RETRY_STATUS = {429, 500, 502, 503, 504}


@dataclass
class OnChainVerification:
    """Result of a successful on-chain verification."""

    root_hash: str
    tx_hash: str
    block_number: int
    block_hash: str
    block_timestamp: int
    stamper: str
    contract_address: str
    chain_id: int
    confirmations: int


def _normalize_address(address: str, what: str) -> str:
    if not isinstance(address, str) or not _ADDRESS_RE.match(address.strip()):
        raise BasestampError(f"Invalid {what} address: {address!r}")
    return address.strip().lower()


def _normalize_tx_hash(tx_hash: str) -> str:
    if not isinstance(tx_hash, str):
        raise BasestampError(f"Invalid transaction hash: {tx_hash!r}")
    value = tx_hash.strip()
    if not value.startswith("0x"):
        value = "0x" + value
    if not _TX_HASH_RE.match(value):
        raise BasestampError(f"Invalid transaction hash: {tx_hash!r}")
    return value.lower()


def _topic_address(address: str) -> str:
    return "0x" + "0" * 24 + address[2:]


def _hex_int(value: Any, what: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise BasestampError(f"Malformed {what} in RPC response: {value!r}")
    try:
        return int(value, 16)
    except ValueError:
        raise BasestampError(f"Malformed {what} in RPC response: {value!r}")


class JsonRpcClient:
    """Minimal, dependency-free JSON-RPC client with timeouts and retries."""

    def __init__(
        self,
        rpc_url: str = MAINNET_RPC_URL,
        timeout: float = 30.0,
        max_retries: int = 5,
        backoff: float = 1.0,
        user_agent: Optional[str] = None,
    ) -> None:
        parsed = urlparse(rpc_url)
        if parsed.scheme != "https" and not (
            parsed.scheme == "http"
            and parsed.hostname in ("localhost", "127.0.0.1", "::1")
        ):
            raise BasestampError(f"RPC URL must use https: {rpc_url!r}")
        if timeout <= 0:
            raise BasestampError("RPC timeout must be positive")
        self.rpc_url = rpc_url
        self.timeout = timeout
        self.max_retries = max(0, max_retries)
        self.backoff = backoff
        if user_agent is None:
            from .client import USER_AGENT

            user_agent = USER_AGENT
        # Some public RPC endpoints (incl. mainnet.base.org) reject the default
        # "Python-urllib" User-Agent with HTTP 403.
        self.user_agent = user_agent
        self._ssl_context = ssl.create_default_context()
        self._id = 0

    def call(self, method: str, params: List[Any]) -> Any:
        """Perform a JSON-RPC call and return ``result``."""
        self._id += 1
        body = json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        ).encode("utf-8")
        last_error = ""
        for attempt in range(self.max_retries + 1):
            if attempt:
                time.sleep(self.backoff * (2 ** (attempt - 1)))
            req = urllib.request.Request(
                self.rpc_url,
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": self.user_agent,
                },
            )
            try:
                with urllib.request.urlopen(
                    req, timeout=self.timeout, context=self._ssl_context
                ) as resp:
                    raw = resp.read(_MAX_RESPONSE_BYTES + 1)
            except urllib.error.HTTPError as e:
                last_error = f"HTTP {e.code}"
                if e.code in _RETRY_STATUS:
                    continue
                raise BasestampError(f"RPC {method} failed: {last_error}", e.code)
            except (urllib.error.URLError, OSError) as e:
                last_error = str(getattr(e, "reason", e))
                continue
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise BasestampError(f"RPC {method} response too large")
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as e:
                raise BasestampError(f"RPC {method} returned invalid JSON: {e}")
            if not isinstance(payload, dict):
                raise BasestampError(f"RPC {method} returned unexpected payload")
            if payload.get("error"):
                err = payload["error"]
                msg = err.get("message") if isinstance(err, dict) else str(err)
                code = err.get("code") if isinstance(err, dict) else None
                # -32005 / "limit exceeded" style errors are transient on public RPCs
                if code in (-32005, -32016) or "rate" in str(msg).lower():
                    last_error = str(msg)
                    continue
                raise BasestampError(f"RPC {method} error: {msg}")
            return payload.get("result")
        raise BasestampError(
            f"RPC {method} failed after {self.max_retries + 1} attempts: {last_error}"
        )


def _match_stamp_log(
    log: Dict[str, Any], root_topic: str, contract: str, signer: Optional[str]
) -> bool:
    if not isinstance(log, dict) or log.get("removed"):
        return False
    if str(log.get("address", "")).lower() != contract:
        return False
    topics = [str(t).lower() for t in (log.get("topics") or [])]
    if len(topics) < 3 or topics[0] != STAMPED_TOPIC or topics[1] != root_topic:
        return False
    if signer is not None and topics[2] != _topic_address(signer):
        return False
    return True


def verify_root_on_chain(
    root_hash: str,
    tx_hash: Optional[str] = None,
    *,
    rpc_url: str = MAINNET_RPC_URL,
    contract_address: str = MAINNET_CONTRACT_ADDRESS,
    signer_address: Optional[str] = MAINNET_SIGNER_ADDRESS,
    chain_id: Optional[int] = MAINNET_CHAIN_ID,
    min_confirmations: int = 1,
    expected_block_hash: Optional[str] = None,
    from_block: Optional[int] = None,
    to_block: Optional[int] = None,
    log_chunk_size: int = 10_000,
    max_log_blocks: int = 200_000,
    timeout: float = 30.0,
    rpc: Optional[JsonRpcClient] = None,
) -> OnChainVerification:
    """Prove that ``root_hash`` was stamped by the Basestamp contract.

    Args:
        root_hash: Merkle root (64 hex chars, optional 0x prefix).
        tx_hash: Stamping transaction (the API's ``tx_id``). When given, the
            receipt is fetched and must contain a matching event. When omitted,
            ``eth_getLogs`` is searched (``from_block``..``to_block``, or the most
            recent ``max_log_blocks`` blocks) in ``log_chunk_size`` windows.
        rpc_url: JSON-RPC endpoint (https).
        contract_address: Basestamp contract address.
        signer_address: Expected stamper (contract owner). ``None`` skips the
            check (the contract itself only allows its owner to stamp).
        chain_id: Expected chain id (``eth_chainId``); ``None`` skips the check.
        min_confirmations: Minimum confirmations (``latest - block + 1``).
        expected_block_hash: If given, the event's block hash must match
            (e.g. the API's ``block_hash``).

    Returns:
        OnChainVerification describing the anchoring event.

    Raises:
        BasestampError: if the root is not proven to be on chain, or RPC fails.
    """
    root = "0x" + normalize_hash(root_hash, "merkle root")
    contract = _normalize_address(contract_address, "contract")
    signer = (
        _normalize_address(signer_address, "signer")
        if signer_address is not None
        else None
    )
    client = rpc or JsonRpcClient(rpc_url, timeout=timeout)

    actual_chain_id = _hex_int(client.call("eth_chainId", []), "chain id")
    if chain_id is not None and actual_chain_id != chain_id:
        raise BasestampError(
            f"RPC endpoint is on chain {actual_chain_id}, expected {chain_id}"
        )

    if signer is not None:
        owner_word = client.call(
            "eth_call", [{"to": contract, "data": OWNER_SELECTOR}, "latest"]
        )
        if not isinstance(owner_word, str) or len(owner_word) != 66:
            raise BasestampError(
                f"Contract {contract} did not return an owner; wrong address or chain?"
            )
        owner = "0x" + owner_word[-40:].lower()
        if owner != signer:
            raise BasestampError(
                f"Contract owner {owner} does not match expected signer {signer}"
            )

    log: Optional[Dict[str, Any]] = None
    if tx_hash is not None:
        txh = _normalize_tx_hash(tx_hash)
        receipt = client.call("eth_getTransactionReceipt", [txh])
        if not receipt:
            raise BasestampError(f"Transaction {txh} not found (not mined yet?)")
        if _hex_int(receipt.get("status"), "receipt status") != 1:
            raise BasestampError(f"Transaction {txh} reverted")
        if str(receipt.get("to", "")).lower() != contract:
            raise BasestampError(
                f"Transaction {txh} was not sent to the Basestamp contract {contract}"
            )
        for candidate in receipt.get("logs") or []:
            if _match_stamp_log(candidate, root, contract, signer):
                log = candidate
                break
        if log is None:
            raise BasestampError(
                f"Transaction {txh} did not emit a stamp event for root {root}"
            )
    else:
        latest = _hex_int(client.call("eth_blockNumber", []), "block number")
        end = latest if to_block is None else min(to_block, latest)
        start = max(0, end - max_log_blocks + 1) if from_block is None else from_block
        topics: List[Optional[str]] = [STAMPED_TOPIC, root]
        if signer is not None:
            topics.append(_topic_address(signer))
        hi = end
        chunk = max(1, log_chunk_size)
        while hi >= start and log is None:
            lo = max(start, hi - chunk + 1)
            logs = client.call(
                "eth_getLogs",
                [
                    {
                        "address": contract,
                        "fromBlock": hex(lo),
                        "toBlock": hex(hi),
                        "topics": topics,
                    }
                ],
            )
            for candidate in logs or []:
                if _match_stamp_log(candidate, root, contract, signer):
                    log = candidate
                    break
            hi = lo - 1
        if log is None:
            raise BasestampError(
                f"No stamp event for root {root} found in blocks {start}..{end}"
            )

    block_number = _hex_int(log.get("blockNumber"), "log block number")
    block_hash = str(log.get("blockHash", "")).lower()
    if expected_block_hash is not None:
        exp = expected_block_hash.strip().lower()
        if not exp.startswith("0x"):
            exp = "0x" + exp
        if exp != block_hash:
            raise BasestampError(
                f"Stamp event is in block {block_hash}, expected {exp}"
            )
    data = str(log.get("data", ""))
    try:
        block_timestamp = int(data[2:66], 16) if len(data) >= 130 else 0
    except ValueError:
        block_timestamp = 0

    latest = _hex_int(client.call("eth_blockNumber", []), "block number")
    confirmations = latest - block_number + 1
    if confirmations < min_confirmations:
        raise BasestampError(
            f"Stamp has {confirmations} confirmations, need {min_confirmations}"
        )
    # Guard against reorgs: the block must still be canonical.
    block = client.call("eth_getBlockByNumber", [hex(block_number), False])
    if not block or str(block.get("hash", "")).lower() != block_hash:
        raise BasestampError(
            f"Block {block_number} containing the stamp is no longer canonical"
        )

    topics_out = [str(t).lower() for t in log["topics"]]
    return OnChainVerification(
        root_hash=root[2:],
        tx_hash=str(log.get("transactionHash", tx_hash or "")).lower(),
        block_number=block_number,
        block_hash=block_hash,
        block_timestamp=block_timestamp,
        stamper="0x" + topics_out[2][-40:],
        contract_address=contract,
        chain_id=actual_chain_id,
        confirmations=confirmations,
    )

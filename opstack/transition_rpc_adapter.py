#!/usr/bin/env python3
"""Bounded loopback Kona RPC compatibility: authenticated headers and receipts.

Only standard read-only upstream RPC is used. State/code is sourced from
authenticated account/storage proofs and verified bytecode hashes; unknown
preimages and execution-witness methods fail explicitly. This adapter
is capture tooling, not an OP acceptance receiver or a consensus/finality oracle.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path

import transition_capture as C

MAX_RECEIPTS = 16384
MAX_RESPONSE = 16 << 20
MAX_RECORD_BYTES = 64 << 20


class UnsupportedMethod(ValueError):
    pass


def integer(value, bits=64):
    raw = C.quantity(value)
    if len(raw) * 8 > bits:
        raise ValueError("RPC integer width exceeded")
    return raw


def receipt_rlp(receipt):
    """Canonical EIP-2718 receipt including OP deposit's optional tail."""
    kind = int.from_bytes(integer(receipt.get("type", "0x0"), 8), "big")
    if kind not in (0, 1, 2, 3, 4, 0x7e):
        raise ValueError("unsupported receipt type")
    if receipt.get("status") is not None:
        if receipt.get("root") is not None:
            raise ValueError("ambiguous receipt status/root")
        status = integer(receipt["status"], 8)
        if status not in (b"", b"\x01"):
            raise ValueError("invalid receipt status")
    else:
        status = C.unhex(receipt["root"], 32)
    logs = receipt["logs"]
    if not isinstance(logs, list) or len(logs) > 65536:
        raise ValueError("receipt log count cap exceeded")
    encoded_logs = []
    for log in logs:
        topics = log["topics"]
        if not isinstance(topics, list) or len(topics) > 4:
            raise ValueError("invalid receipt topics")
        data = C.unhex(log["data"])
        if len(data) > 1 << 20:
            raise ValueError("receipt log data cap exceeded")
        encoded_logs.append([C.unhex(log["address"], 20), [C.unhex(t, 32) for t in topics], data])
    fields = [status, integer(receipt["cumulativeGasUsed"]), C.unhex(receipt["logsBloom"], 256), encoded_logs]
    nonce, version = receipt.get("depositNonce"), receipt.get("depositReceiptVersion")
    if kind != 0x7e and (nonce is not None or version is not None):
        raise ValueError("deposit fields on ordinary receipt")
    if version is not None and nonce is None:
        raise ValueError("deposit version without nonce")
    if nonce is not None:
        fields.append(integer(nonce))
    if version is not None:
        fields.append(integer(version))
    raw = C.rlp(fields)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("receipt byte cap exceeded")
    return (bytes([kind]) if kind else b"") + raw


def compact(path, leaf):
    prefix = [2 if leaf else 0, 0] if len(path) % 2 == 0 else [3 if leaf else 1]
    nibbles = prefix + list(path)
    return bytes((nibbles[i] << 4) | nibbles[i + 1] for i in range(0, len(nibbles), 2))


def trie_root(items):
    """Immutable hexary Patricia construction; returns root and all preimages."""
    if len(items) > MAX_RECEIPTS:
        raise ValueError("trie item count cap exceeded")
    rows = []
    for key, value in items:
        if not isinstance(key, bytes) or not isinstance(value, bytes) or len(key) > 64:
            raise ValueError("invalid bounded trie item")
        rows.append((tuple(n for b in key for n in (b >> 4, b & 15)), value))
    rows.sort()
    if any(a[0] == b[0] for a, b in zip(rows, rows[1:])):
        raise ValueError("duplicate trie key")
    if sum(len(k) + len(v) for k, v in items) > MAX_RESPONSE:
        raise ValueError("trie input byte cap exceeded")
    records = {}
    def remember(node):
        encoded = C.rlp(node)
        records[C.keccak(encoded)] = encoded
        return node if len(encoded) < 32 else C.keccak(encoded)
    def build(entries, offset):
        if len(entries) == 1:
            key, value = entries[0]
            return [compact(key[offset:], True), value]
        common = offset
        while all(len(k) > common and k[common] == entries[0][0][common] for k, _ in entries):
            common += 1
        if common > offset:
            return [compact(entries[0][0][offset:common], False), remember(build(entries, common))]
        node = [b""] * 17
        for digit in range(16):
            group = [(k, v) for k, v in entries if len(k) > offset and k[offset] == digit]
            if group:
                node[digit] = remember(build(group, offset + 1))
        values = [v for k, v in entries if len(k) == offset]
        if values:
            node[16] = values[0]
        return node
    root = C.rlp(build(rows, 0)) if rows else C.rlp(b"")
    records[C.keccak(root)] = root
    if sum(len(v) for v in records.values()) > MAX_RECORD_BYTES:
        raise ValueError("trie record byte cap exceeded")
    return C.keccak(root), records


def ordered_receipts(block, receipts):
    C.header_rlp(block)
    txs = block["transactions"]
    if not isinstance(receipts, list) or not isinstance(txs, list) or len(receipts) != len(txs) or len(receipts) > MAX_RECEIPTS:
        raise ValueError("receipt/transaction count mismatch")
    raw = []
    for i, receipt in enumerate(receipts):
        if (integer(receipt["transactionIndex"]) != i.to_bytes((i.bit_length() + 7) // 8, "big") or
            C.unhex(receipt["blockHash"], 32) != C.unhex(block["hash"], 32) or
            integer(receipt["blockNumber"]) != integer(block["number"]) or
            C.unhex(receipt["transactionHash"], 32) != C.unhex(txs[i], 32)):
            raise ValueError("receipt identity or order mismatch")
        raw.append(receipt_rlp(receipt))
    items = [(C.rlp(i.to_bytes((i.bit_length() + 7) // 8, "big")), value) for i, value in enumerate(raw)]
    root, records = trie_root(items)
    if root != C.unhex(block["receiptsRoot"], 32):
        raise ValueError("receipt trie root mismatch")
    return raw, records


def storage_slot(value):
    if isinstance(value, str) and len(value) == 66:
        return C.unhex(value, 32)
    raw = integer(value, 256)
    return raw.rjust(32, b"\x00")


def verified_proof(block, address, slots, proof):
    """Authenticate every account/storage node before caching any preimage."""
    C.header_rlp(block)
    address = C.unhex(address, 20)
    if C.unhex(proof["address"], 20) != address:
        raise ValueError("proof address mismatch")
    raw = C.verify_trie_value(C.unhex(block["stateRoot"], 32), C.keccak(address), proof["accountProof"], allow_absence=True)
    empty_root = C.keccak(C.rlp(b""))
    empty_code = C.keccak(b"")
    if raw is None:
        account = [b"", b"", empty_root, empty_code]
    else:
        account = C.decode_rlp(raw)
        if not isinstance(account, list) or len(account) != 4 or any(not isinstance(v, bytes) for v in account):
            raise ValueError("invalid account encoding")
    nonce, balance, storage, code = account
    if (nonce and nonce[0] == 0) or (balance and balance[0] == 0) or len(nonce) > 8 or len(balance) > 32:
        raise ValueError("invalid account integer")
    if nonce != integer(proof["nonce"]) or balance != integer(proof["balance"], 256) or storage != C.unhex(proof["storageHash"], 32) or code != C.unhex(proof["codeHash"], 32):
        raise ValueError("proof fields differ from authenticated account")
    proofs = proof["storageProof"]
    if not isinstance(proofs, list) or len(proofs) != len(slots):
        raise ValueError("storage proof count mismatch")
    records = {C.keccak(C.unhex(v)): C.unhex(v) for v in proof["accountProof"]}
    for expected, item in zip(slots, proofs):
        if storage_slot(item["key"]) != expected:
            raise ValueError("storage proof slot mismatch")
        encoded = C.verify_trie_value(storage, C.keccak(expected), item["proof"], allow_absence=True)
        value = b"" if encoded is None else C.decode_rlp(encoded)
        if not isinstance(value, bytes) or len(value) > 32 or (value and value[0] == 0) or value != integer(item["value"], 256):
            raise ValueError("storage value differs from authenticated trie")
        records.update({C.keccak(C.unhex(v)): C.unhex(v) for v in item["proof"]})
    return records, code if raw is not None else None


class Adapter:
    def __init__(self, upstream, record_limit=MAX_RECORD_BYTES, header_window=1, transport_cache=None, cache_claim=None):
        C.endpoint_label(upstream)
        if not 1 <= record_limit <= MAX_RECORD_BYTES:
            raise ValueError("invalid record budget")
        if not 1 <= header_window <= 32:
            raise ValueError("header window invalid")
        self.upstream, self.record_limit = upstream, record_limit
        self.header_window = header_window
        self.prefetched_headers = 0
        self.transport_cache = None
        if transport_cache is not None:
            from transition_transport_cache import Cache
            self.transport_cache = Cache(transport_cache, cache_claim)
        self.records, self.record_bytes = {}, 0
        self.headers = OrderedDict()
        self.header_bytes = 0
        self.code_accounts = {}
        self.missing_preimages = {}
        self.method_counts = {}

    def retain(self, records):
        added = 0
        for digest, value in records.items():
            if C.keccak(value) != digest or (digest in self.records and self.records[digest] != value):
                raise ValueError("conflicting or unauthenticated preimage")
            if digest not in self.records:
                added += len(value)
        if len(set(self.records) | set(records)) > C.MAX_RECORDS:
            raise ValueError("retained preimage count exceeded")
        if self.record_bytes + added > self.record_limit:
            raise ValueError("retained preimage budget exceeded")
        self.records.update(records)
        self.record_bytes += added

    def cache_header(self, block):
        encoded = C.header_rlp(block)
        self.retain({C.keccak(encoded): encoded})
        size = len(json.dumps(block))
        if size > 8 << 20:
            raise ValueError("header cache entry byte cap exceeded")
        old = self.headers.get(block["hash"])
        if old is not None:
            self.header_bytes -= len(json.dumps(old))
        self.headers[block["hash"]] = block
        self.header_bytes += size
        while len(self.headers) > 128 or self.header_bytes > 8 << 20:
            _, removed = self.headers.popitem(last=False)
            self.header_bytes -= len(json.dumps(removed))

    def prefetch_parents(self, head):
        # Readahead is optional transport scheduling. Every cached parent must
        # form an exact authenticated chain from the independently requested
        # head; a failed fetch cannot authorize a fork or fake cache entry.
        from concurrent.futures import ThreadPoolExecutor
        number = int(head["number"], 16)
        numbers = list(range(number - 1, max(-1, number - self.header_window), -1))
        if not numbers:
            return
        def fetch(n):
            try:
                block = C.rpc(self.upstream, "eth_getBlockByNumber", [hex(n), False], cap=MAX_RESPONSE, timeout=4)
                C.header_rlp(block)
                return block if int(block["number"], 16) == n else None
            except (C.RpcFailure, ValueError, KeyError, TypeError):
                return None
        with ThreadPoolExecutor(max_workers=min(8, len(numbers))) as pool:
            parents = list(pool.map(fetch, numbers))
        expected = head["parentHash"]
        for parent in parents:
            if parent is None or C.unhex(parent["hash"], 32) != C.unhex(expected, 32):
                break
            self.cache_header(parent)
            self.prefetched_headers += 1
            expected = parent["parentHash"]

    def block(self, identifier):
        if not isinstance(identifier, str):
            raise ValueError("invalid block identifier")
        if identifier in self.headers:
            self.headers.move_to_end(identifier)
            return self.headers[identifier]
        is_hash = len(identifier) == 66
        if is_hash:
            C.unhex(identifier, 32)
        elif identifier not in ("latest", "finalized", "safe", "earliest"):
            integer(identifier)
        method = "eth_getBlockByHash" if is_hash else "eth_getBlockByNumber"
        cached = self.transport_cache.load(identifier) if self.transport_cache is not None and is_hash else None
        if cached is not None:
            block = dict(cached["block"])
            block["transactions"] = [tx["hash"] for tx in block["transactions"]]
        else:
            block = C.rpc(self.upstream, method, [identifier, False], cap=MAX_RESPONSE)
        encoded = C.header_rlp(block)
        if is_hash and C.unhex(block["hash"], 32) != C.unhex(identifier, 32):
            raise ValueError("requested header hash mismatch")
        if not is_hash and identifier.startswith("0x") and integer(block["number"]) != integer(identifier):
            raise ValueError("requested header number mismatch")
        # Cache immutable hash aliases only; never retain a moving safe/latest tag.
        self.cache_header(block)
        if self.header_window > 1 and cached is None:
            self.prefetch_parents(block)
        return block

    def dispatch(self, method, params):
        if method in {"debug_getRawHeader", "debug_getRawReceipts", "eth_getProof", "debug_dbGet", "eth_chainId", "eth_getBlockByHash", "eth_getBlockByNumber", "debug_executePayload"}:
            self.method_counts[method] = self.method_counts.get(method, 0) + 1
        if not isinstance(params, list):
            raise ValueError("invalid RPC params")
        if method in ("debug_getRawHeader", "debug_getRawReceipts"):
            if len(params) != 1:
                raise ValueError("invalid debug compatibility params")
            block = self.block(params[0])
            if method == "debug_getRawHeader":
                return "0x" + C.header_rlp(block).hex()
            cached = self.transport_cache.load(block["hash"]) if self.transport_cache is not None else None
            receipts = cached["receipts"] if cached is not None else C.rpc(self.upstream, "eth_getBlockReceipts", [block["number"]], cap=MAX_RESPONSE)
            raw, records = ordered_receipts(block, receipts)
            self.retain(records)
            return ["0x" + r.hex() for r in raw]
        if method == "eth_getProof":
            if len(params) != 3 or not isinstance(params[1], list) or len(params[1]) > 64:
                raise ValueError("bounded proof params invalid")
            address = "0x" + C.unhex(params[0], 20).hex()
            slots = [storage_slot(s) for s in params[1]]
            if len(set(slots)) != len(slots):
                raise ValueError("duplicate proof slots")
            identifier = params[2]
            if isinstance(identifier, dict):
                if set(identifier) - {"blockHash", "requireCanonical"} or identifier.get("requireCanonical", True) is not True:
                    raise ValueError("invalid canonical proof block")
                identifier = identifier["blockHash"]
            block = self.block(identifier)
            result = C.rpc(self.upstream, method, [address, ["0x" + s.hex() for s in slots],
                           {"blockHash": block["hash"], "requireCanonical": True}], cap=MAX_RESPONSE)
            records, code = verified_proof(block, address, slots, result)
            if code is not None and code not in self.code_accounts and len(self.code_accounts) >= 8192:
                raise ValueError("code provenance count budget exceeded")
            self.retain(records)
            if code is not None:
                self.code_accounts[code] = (address, block["hash"])
            return result
        if method == "debug_dbGet":
            if len(params) != 1:
                raise ValueError("invalid database params")
            key = C.unhex(params[0])
            if len(key) == 33 and key[0] == ord("c"):
                key = key[1:]
            if len(key) != 32:
                raise ValueError("invalid database key")
            if key in self.records:
                return "0x" + self.records[key].hex()
            if key not in self.code_accounts:
                if key.hex() in self.missing_preimages or len(self.missing_preimages) < 256:
                    self.missing_preimages[key.hex()] = self.missing_preimages.get(key.hex(), 0) + 1
                raise UnsupportedMethod("unknown authenticated preimage; no guessed sibling/code")
            address, block = self.code_accounts[key]
            raw = C.unhex(C.rpc(self.upstream, "eth_getCode", [address, {"blockHash": block, "requireCanonical": True}], cap=2 << 20))
            if len(raw) > 1 << 20 or C.keccak(raw) != key:
                raise ValueError("code hash mismatch")
            self.retain({key: raw})
            return "0x" + raw.hex()
        if method == "eth_getBlockByHash" and len(params) == 2 and params[1] is True and self.transport_cache is not None:
            cached = self.transport_cache.load(params[0])
            if cached is not None:
                return cached["block"]
        # These ordinary calls are only transport passthrough, not proof caches.
        # The host/receiver must still authenticate their contents. No generic
        # debug_dbGet or execution-witness passthrough exists.
        if method in ("eth_chainId", "eth_getBlockByHash", "eth_getBlockByNumber"):
            return C.rpc(self.upstream, method, params, cap=MAX_RESPONSE)
        raise UnsupportedMethod("unsupported capture method; no fabricated preimage/witness")

    def export(self, directory):
        directory.mkdir(parents=True, exist_ok=False)
        C.write_new(directory / "records.json", (json.dumps([(k.hex(), v.hex()) for k, v in sorted(self.records.items())]) + "\n").encode())
        C.write_new(directory / "capture.json", (json.dumps({"records": len(self.records), "bytes": self.record_bytes, "preimage_hashes_verified": True, "complete_witness": False, "derivation_accepted": False, "proof_verified": False, "missing_preimages": self.missing_preimages, "method_counts": self.method_counts, "prefetched_headers": self.prefetched_headers}, indent=2) + "\n").encode())


def serve(adapter, port, max_requests, seconds):
    # Single-threaded, loopback-only and lifetime/request bounded; no public proxy.
    import time
    deadline = time.monotonic() + seconds
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_POST(self):
            self.connection.settimeout(5)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1 << 20:
                    raise ValueError("request byte cap")
                req = json.loads(self.rfile.read(length))
                if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or not isinstance(req.get("method"), str):
                    raise ValueError("invalid RPC request")
                value = {"jsonrpc": "2.0", "id": req.get("id"), "result": adapter.dispatch(req["method"], req.get("params", []))}
            except UnsupportedMethod:
                value = {"jsonrpc": "2.0", "id": req.get("id"),
                         "error": {"code": -32601, "message": "capture method not supported"}}
            except (ValueError, KeyError, TypeError, C.RpcFailure):
                value = {"jsonrpc": "2.0", "id": req.get("id") if isinstance(locals().get("req"), dict) else None,
                         "error": {"code": -32000, "message": "capture method failed or unsupported"}}
            raw = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    class Server(HTTPServer):
        def get_request(self):
            sock, address = super().get_request()
            sock.settimeout(5)
            return sock, address
    with Server(("127.0.0.1", port), Handler) as server:
        server.timeout = 0.5
        while max_requests and time.monotonic() < deadline:
            server.handle_request()
            max_requests -= 1


def main():
    import signal
    def stop(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rpc", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--block", help="fetch/authenticate raw header+receipts once instead of serving")
    p.add_argument("--port", type=int, default=18545)
    p.add_argument("--seconds", type=int, default=180)
    p.add_argument("--max-requests", type=int, default=10000)
    p.add_argument("--header-window", type=int, default=1)
    p.add_argument("--transport-cache", type=Path)
    p.add_argument("--cache-claim")
    a = p.parse_args()
    if not 1 <= a.seconds <= 180 or not 1 <= a.max_requests <= 10000 or not 1024 <= a.port <= 65535:
        raise ValueError("adapter limits invalid")
    adapter = Adapter(a.rpc, header_window=a.header_window, transport_cache=a.transport_cache, cache_claim=a.cache_claim)
    try:
        if a.block:
            adapter.dispatch("debug_getRawHeader", [a.block])
            receipts = adapter.dispatch("debug_getRawReceipts", [a.block])
            print(json.dumps({"raw_receipts": len(receipts), "authenticated": True}))
        else:
            serve(adapter, a.port, a.max_requests, a.seconds)
    finally:
        adapter.export(a.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(json.dumps({'status': 'adapter_stopped', 'complete_witness': False}))
    except (ValueError, OSError, KeyError, TypeError, C.RpcFailure) as error:
        print(json.dumps({"status": "adapter_failed", "error_type": type(error).__name__}))
        raise SystemExit(1) from None

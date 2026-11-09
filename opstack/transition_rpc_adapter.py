#!/usr/bin/env python3
"""Bounded loopback Kona RPC compatibility: authenticated headers and receipts.

Only standard read-only upstream RPC is used. Unsupported state/code/witness
methods fail explicitly; there is no fake empty execution witness. This adapter
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


class Adapter:
    def __init__(self, upstream, record_limit=MAX_RECORD_BYTES):
        C.endpoint_label(upstream)
        if not 1 <= record_limit <= MAX_RECORD_BYTES:
            raise ValueError("invalid record budget")
        self.upstream, self.record_limit = upstream, record_limit
        self.records, self.record_bytes = {}, 0
        self.headers = OrderedDict()
        self.header_bytes = 0

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
        block = C.rpc(self.upstream, method, [identifier, False], cap=MAX_RESPONSE)
        encoded = C.header_rlp(block)
        if is_hash and C.unhex(block["hash"], 32) != C.unhex(identifier, 32):
            raise ValueError("requested header hash mismatch")
        if not is_hash and identifier.startswith("0x") and integer(block["number"]) != integer(identifier):
            raise ValueError("requested header number mismatch")
        self.retain({C.keccak(encoded): encoded})
        # Cache immutable hash aliases only; never retain a moving safe/latest tag.
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
        return block

    def dispatch(self, method, params):
        if not isinstance(params, list):
            raise ValueError("invalid RPC params")
        if method in ("debug_getRawHeader", "debug_getRawReceipts"):
            if len(params) != 1:
                raise ValueError("invalid debug compatibility params")
            block = self.block(params[0])
            if method == "debug_getRawHeader":
                return "0x" + C.header_rlp(block).hex()
            receipts = C.rpc(self.upstream, "eth_getBlockReceipts", [block["number"]], cap=MAX_RESPONSE)
            raw, records = ordered_receipts(block, receipts)
            self.retain(records)
            return ["0x" + r.hex() for r in raw]
        # These ordinary calls are only transport passthrough, not proof caches.
        # The host/receiver must still authenticate their contents. No generic
        # debug_dbGet or execution-witness passthrough exists.
        if method in ("eth_chainId", "eth_getBlockByHash", "eth_getBlockByNumber", "eth_getProof"):
            return C.rpc(self.upstream, method, params, cap=MAX_RESPONSE)
        raise UnsupportedMethod("unsupported capture method; no fabricated preimage/witness")

    def export(self, directory):
        directory.mkdir(parents=True, exist_ok=False)
        C.write_new(directory / "records.json", (json.dumps([(k.hex(), v.hex()) for k, v in sorted(self.records.items())]) + "\n").encode())
        C.write_new(directory / "capture.json", (json.dumps({"records": len(self.records), "bytes": self.record_bytes, "preimage_hashes_verified": True, "complete_witness": False, "derivation_accepted": False, "proof_verified": False}, indent=2) + "\n").encode())


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
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rpc", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--block", help="fetch/authenticate raw header+receipts once instead of serving")
    p.add_argument("--port", type=int, default=18545)
    p.add_argument("--seconds", type=int, default=180)
    p.add_argument("--max-requests", type=int, default=10000)
    a = p.parse_args()
    if not 1 <= a.seconds <= 180 or not 1 <= a.max_requests <= 10000 or not 1024 <= a.port <= 65535:
        raise ValueError("adapter limits invalid")
    adapter = Adapter(a.rpc)
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
    except (ValueError, OSError, KeyError, TypeError, C.RpcFailure) as error:
        print(json.dumps({"status": "adapter_failed", "error_type": type(error).__name__}))
        raise SystemExit(1) from None

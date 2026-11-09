#!/usr/bin/env python3
"""Recover or capture anchored-transition material without running a guest/prover.

Recovery accepts only pinned bytes. New RPC/KV material remains an incomplete
witness until the independent Kona verifier admits it. No endpoint credential or
process environment is included in reports; dependencies are never installed.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib

MAX_INPUT = (32 << 20) - 4
MAX_BODY = 64 << 20
MAX_RECORDS = 131072
HEADER = 176
BLOB_BYTES = 131072
SIDECAR_BYTES = BLOB_BYTES + 96
PINS = {
    21530433: "bae3a618357459a8a136b16c300e395841aa7c4f1c061886f71be8812eca4b25",
    18871913: "21f704b7bf79467487ee4e0a1811034ce414cc5b4e62b13d88dca75528b759c9",
    33312954: "c6a7eaf7e8c052f8a227d739ddbb84b5d3e2907002f83879a76f9d37740fc698",
}
SKIP = {".git", ".zig-cache", "node_modules", "target", ".ssh", ".aws", ".config", ".cargo", "venv", ".venv"}
RECEIPT = Path(__file__).with_name("transition-159257842-receipt.json")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def keccak(data):
    try:
        from Crypto.Hash import keccak as implementation
    except ImportError as exc:
        raise ValueError("use the existing host requirements environment for Keccak; nothing is installed automatically") from exc
    return implementation.new(digest_bits=256, data=data).digest()


def unhex(value, size=None):
    if not isinstance(value, str) or not re.fullmatch(r"(?:0x)?(?:[0-9a-fA-F]{2})*", value):
        raise ValueError("noncanonical hex bytes")
    result = bytes.fromhex(value.removeprefix("0x"))
    if size is not None and len(result) != size:
        raise ValueError("hex byte width mismatch")
    return result


def read_json(path, maximum=MAX_BODY * 3):
    if path.stat().st_size > maximum:
        raise ValueError("JSON input byte cap exceeded")
    return json.loads(path.read_bytes())


def write_new(path, data):
    # No archive pathname or producer filename is ever used as an output path.
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".op-capture-", delete=False) as output:
        temporary = Path(output.name)
        try:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
            os.link(temporary, path)  # Atomic publication, never replace a destination.
        finally:
            temporary.unlink(missing_ok=True)


def claim_from_receipt(receipt):
    s = receipt["statement"]
    return {"anchor": {"number": s["anchor_number"], "hash": "0x" + s["anchor_hash"]},
            "previous_number": s["previous_number"], "previous_root": "0x" + s["previous_root"],
            "next_number": s["next_number"], "next_root": "0x" + s["next_root"],
            "next_origin": {"number": s["next_origin_number"], "hash": "0x" + s["next_origin_hash"]}}


def claim_header(claim):
    if set(claim) != {"anchor", "previous_number", "previous_root", "next_number", "next_root", "next_origin"}:
        raise ValueError("invalid claim fields")
    if any(not isinstance(claim[name], dict) or set(claim[name]) != {"number", "hash"} for name in ("anchor", "next_origin")):
        raise ValueError("invalid checkpoint fields")
    out = bytearray()
    for number, digest in [(claim["anchor"]["number"], claim["anchor"]["hash"]),
                           (claim["previous_number"], claim["previous_root"]),
                           (claim["next_number"], claim["next_root"]),
                           (claim["next_origin"]["number"], claim["next_origin"]["hash"])]:
        if not isinstance(number, int) or isinstance(number, bool) or not 0 <= number < 1 << 64:
            raise ValueError("invalid checkpoint number")
        out += struct.pack("<Q", number) + unhex(digest, 32)
    return bytes(out)


def inspect_container(data, claim):
    if not HEADER <= len(data) <= MAX_INPUT or data[:8] not in (b"STWOPD01", b"STWOPDZ1"):
        raise ValueError("invalid bounded OPD envelope")
    if data[8:168] != claim_header(claim):
        raise ValueError("transition checkpoint identity mismatch")
    witness_len, count = struct.unpack_from("<II", data, 168)
    expected = witness_len + count * SIDECAR_BYTES
    if witness_len < 24 or count > 256 or expected > MAX_BODY:
        raise ValueError("transition body cap exceeded")
    if data[:8] == b"STWOPDZ1":
        decoder = zlib.decompressobj()
        body = decoder.decompress(data[HEADER:], expected + 1)
        if len(body) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError("non-exact bounded OPD decompression")
    else:
        body = data[HEADER:]
        if len(body) != expected:
            raise ValueError("transition body length mismatch")
    witness = body[:witness_len]
    if witness[:8] != b"STWOPX01" or len(witness) < 24:
        raise ValueError("invalid transition preimage envelope")
    metadata, records, total, reserved = struct.unpack_from("<IIII", witness, 8)
    table_end = 24 + records * 40
    if metadata != 0 or records > MAX_RECORDS or total != witness_len or reserved != 0 or table_end > total:
        raise ValueError("invalid transition preimage header")
    previous, end = None, 0
    for index in range(records):
        offset = 24 + 40 * index
        key = witness[offset:offset + 32]
        start, length = struct.unpack_from("<II", witness, offset + 32)
        if (previous is not None and key <= previous) or start != end or length > total - table_end - start:
            raise ValueError("noncanonical transition preimage table")
        previous, end = key, end + length
    if table_end + end != total:
        raise ValueError("trailing transition preimage bytes")
    previous = None
    for index in range(count):
        start = witness_len + index * SIDECAR_BYTES
        commitment = body[start:start + 48]
        if previous is not None and commitment <= previous:
            raise ValueError("sidecar commitments not strictly sorted")
        previous = commitment
    return {"bytes": len(data), "sha256": sha(data), "records": records, "sidecars": count,
            "container_validated": True, "preimage_hashes_verified": False,
            "kzg_verified": False, "derivation_accepted": False, "proof_verified": False}


def recover(roots, output=None, max_files=1000000):
    checked, candidates, found, stores = 0, 0, [], []
    for root in roots:
        for directory, dirs, names in os.walk(root, followlinks=False):
            dirs[:] = [name for name in sorted(dirs) if name not in SKIP and not Path(directory, name).is_symlink()]
            for name in sorted(names):
                path = Path(directory, name)
                try:
                    info = path.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                checked += 1
                if checked > max_files:
                    raise ValueError("recovery file-count cap exceeded")
                if name == "kvformat" and info.st_size <= 16:
                    try:
                        kind = path.read_text().strip()
                        if kind in ("directory", "rocksdb"):
                            stores.append({"path": str(path.parent), "format": kind})
                    except OSError:
                        pass
                if info.st_size in PINS:
                    with path.open("rb") as stream:
                        if stream.read(8) not in (b"STWOPD01", b"STWOPDZ1"):
                            continue
                        stream.seek(0)
                        data = stream.read(MAX_INPUT + 1)
                    candidates += 1
                    if sha(data) == PINS[info.st_size]:
                        found.append({"path": str(path), "bytes": len(data), "sha256": sha(data)})
                        if output is not None:
                            write_new(output, data)
                            return {"files_statted": checked, "candidates_hashed": candidates, "matches": found, "kv_stores": stores}
                elif path.suffix.lower() == ".zip" and info.st_size <= 512 << 20:
                    try:
                        with zipfile.ZipFile(path) as archive:
                            entries = archive.infolist()
                            if len(entries) > 100000:
                                raise ValueError("archive entry-count cap exceeded")
                            for entry in entries:
                                if entry.file_size not in PINS or not entry.filename.endswith("input.opd"):
                                    continue
                                with archive.open(entry) as stream:
                                    data = stream.read(MAX_INPUT + 1)
                                candidates += 1
                                if len(data) == entry.file_size and sha(data) == PINS[entry.file_size]:
                                    found.append({"archive": str(path), "entry": entry.filename, "bytes": len(data), "sha256": sha(data)})
                                    if output is not None:
                                        write_new(output, data)
                                        return {"files_statted": checked, "candidates_hashed": candidates, "matches": found, "kv_stores": stores}
                    except zipfile.BadZipFile:
                        continue
    return {"files_statted": checked, "candidates_hashed": candidates, "matches": found, "kv_stores": stores}


def endpoint_label(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("invalid RPC endpoint")
    return f"{parsed.scheme}://{parsed.hostname}" + (f":{parsed.port}" if parsed.port else "")


class RpcFailure(Exception):
    def __init__(self, kind, http=None, code=None):
        self.report = {"status": kind, "http_status": http, "rpc_code": code}


def classify_error(error):
    message = str(error.get("message", "")).lower()
    if "10,000" in message and "proof" in message:
        return "historical_proof_window_10000"
    if "not whitelisted" in message or "not found" in message or "not supported" in message:
        return "method_unavailable"
    if "missing trie" in message or "historical state" in message:
        return "historical_state_unavailable"
    return "rpc_error"


def rpc(url, method, params, *, cap=2 << 20, timeout=12):
    endpoint_label(url)
    # Read-only metadata/proof fetches. The payload-method capability probe has
    # deliberately invalid empty parameters and cannot execute a payload.
    # No debug trace, transaction submission, eth_call or proving method enters.
    metadata = {"eth_chainId", "eth_getBlockByHash", "eth_getBlockByNumber", "eth_getProof", "eth_getBlockReceipts", "debug_getRawHeader", "debug_getRawReceipts", "debug_dbGet", "eth_getCode"}
    if method not in metadata and not (method == "debug_executePayload" and params == []):
        raise ValueError("RPC method outside capture scope")
    request = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(), {"Content-Type": "application/json"})
    http = None
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read(cap + 1)
    except urllib.error.HTTPError as error:
        http = error.code
        with error:
            data = error.read(min(cap + 1, 4096))
    except (OSError, TimeoutError, urllib.error.URLError) as error:
        raise RpcFailure("transport_unavailable") from error
    if len(data) > cap:
        raise RpcFailure("response_byte_cap", http)
    try:
        result = json.loads(data)
    except (ValueError, UnicodeDecodeError) as error:
        raise RpcFailure("non_json_response", http) from error
    if not isinstance(result, dict):
        raise RpcFailure("invalid_rpc_response", http)
    if "error" in result:
        error = result["error"]
        if not isinstance(error, dict):
            raise RpcFailure("invalid_rpc_response", http)
        code = error.get("code")
        code = code if isinstance(code, int) and not isinstance(code, bool) else None
        raise RpcFailure(classify_error(error), http, code)
    if http is not None or result.get("id") != 1 or "result" not in result:
        raise RpcFailure("invalid_rpc_response", http)
    if result["result"] is None:
        raise RpcFailure("missing_historical_data")
    return result["result"]


def probe(url, layer, receipt):
    statement = receipt["statement"]
    number = statement["anchor_number"] if layer == "l1" else statement["previous_number"]
    digest = statement["anchor_hash"] if layer == "l1" else None
    jobs = [("chain_id", "eth_chainId", []), ("historical_header", "eth_getBlockByNumber", [hex(number), False])]
    if layer == "l2":
        jobs += [("historical_account_proof", "eth_getProof", ["0x4200000000000000000000000000000000000016", [], hex(number)]),
                 ("raw_header", "debug_getRawHeader", [hex(number)])]
    rows = []
    for name, method, params in jobs:
        try:
            result = rpc(url, method, params)
            if name == "chain_id" and result != ("0x1" if layer == "l1" else "0xa"):
                raise RpcFailure("wrong_chain")
            if name == "historical_header" and (int(result["number"], 16) != number or (digest and unhex(result["hash"], 32).hex() != digest)):
                raise RpcFailure("pinned_header_mismatch")
            rows.append({"capability": name, "status": "available"})
        except RpcFailure as error:
            rows.append({"capability": name, **error.report})
    return {"endpoint": endpoint_label(url), "layer": layer, "capabilities": rows, "complete_witness": False}



def probe_host(url, layer, receipt):
    """Probe exact pinned Kona-host dependencies before compiling/running it.

    Payload capability uses empty params only. A returned invalid-params error
    means exposed, not that a real payload/capture has been checked.
    """
    statement = receipt["statement"]
    digest = statement["anchor_hash"] if layer == "l1" else statement["block_hash"]
    jobs = [("raw_header", "debug_getRawHeader", ["0x" + digest])]
    if layer == "l1":
        jobs += [("raw_receipts", "debug_getRawReceipts", ["0x" + digest])]
    else:
        jobs += [("state_by_hash", "debug_dbGet", ["0x" + "00" * 32]),
                 ("payload_method_exposure_only", "debug_executePayload", [])]
    rows = []
    for name, method, params in jobs:
        try:
            rpc(url, method, params)
            rows.append({"capability": name, "status": "returned"})
        except RpcFailure as error:
            result = dict(error.report)
            if name == "payload_method_exposure_only" and result["rpc_code"] == -32602:
                result["status"] = "method_exposed_invalid_params_only"
            rows.append({"capability": name, **result})
    return {"endpoint": endpoint_label(url), "layer": layer, "capabilities": rows,
            "host_executed": False, "payload_executed": False, "complete_witness": False}


def rlp(value):
    if isinstance(value, list):
        payload = b"".join(rlp(v) for v in value)
        base = 0xc0
    else:
        payload, base = value, 0x80
        if len(payload) == 1 and payload[0] < 0x80:
            return payload
    if len(payload) < 56:
        return bytes([base + len(payload)]) + payload
    width = (len(payload).bit_length() + 7) // 8
    return bytes([base + 55 + width]) + len(payload).to_bytes(width, "big") + payload


def quantity(value):
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)", value):
        raise ValueError("noncanonical RPC quantity")
    number = int(value, 16)
    return number.to_bytes((number.bit_length() + 7) // 8, "big")


def header_rlp(block):
    fixed = [("parentHash", 32), ("sha3Uncles", 32), ("miner", 20), ("stateRoot", 32), ("transactionsRoot", 32), ("receiptsRoot", 32), ("logsBloom", 256)]
    fields = [unhex(block[name], size) for name, size in fixed]
    fields += [quantity(block[name]) for name in ("difficulty", "number", "gasLimit", "gasUsed", "timestamp")]
    fields += [unhex(block["extraData"]), unhex(block.get("mixHash", block.get("prevRandao")), 32), unhex(block["nonce"], 8)]
    optional = [("baseFeePerGas", None), ("withdrawalsRoot", 32), ("blobGasUsed", None), ("excessBlobGas", None), ("parentBeaconBlockRoot", 32), ("requestsHash", 32)]
    absent = False
    for name, size in optional:
        if block.get(name) is None:
            absent = True
        elif absent:
            raise ValueError("RPC header optional fields contain a gap")
        else:
            fields.append(quantity(block[name]) if size is None else unhex(block[name], size))
    encoded = rlp(fields)
    if keccak(encoded) != unhex(block["hash"], 32):
        raise ValueError("RPC header RLP does not match published hash")
    return encoded



def decode_rlp(data):
    """Strict, bounded RLP for authenticated header/account-trie material."""
    if len(data) > 65536:
        raise ValueError("RLP node byte cap exceeded")
    def parse(at, limit, depth):
        if at >= limit or depth > 16:
            raise ValueError("truncated or overdeep RLP")
        tag = data[at]
        if tag < 0x80:
            return data[at:at + 1], at + 1
        is_list = tag >= 0xc0
        base = 0xc0 if is_list else 0x80
        width = tag - base
        start = at + 1
        if width > 55:
            size = width - 55
            if start + size > limit or data[start] == 0:
                raise ValueError("noncanonical RLP length")
            width = int.from_bytes(data[start:start + size], "big")
            start += size
            if width < 56:
                raise ValueError("noncanonical long RLP")
        end = start + width
        if end > limit:
            raise ValueError("truncated RLP payload")
        if not is_list:
            if width == 1 and data[start] < 0x80:
                raise ValueError("noncanonical single-byte RLP")
            return data[start:end], end
        values, cursor = [], start
        while cursor < end:
            value, cursor = parse(cursor, end, depth + 1)
            values.append(value)
        return values, end
    value, end = parse(0, len(data), 0)
    if end != len(data):
        raise ValueError("trailing RLP")
    return value


def verify_trie_value(root, key, proof, *, allow_absence=False):
    """Verify an inclusion proof under an independently authenticated root.

    Absence is opt-in and authenticated by an empty root/branch or compact-path
    mismatch. No RPC account field/node supplies the expected trie root.
    """
    if len(root) != 32 or len(key) != 32 or not isinstance(proof, list) or not 0 <= len(proof) <= 64:
        raise ValueError("invalid bounded trie proof")
    if allow_absence and not proof and root == keccak(rlp(b"")):
        return None
    nodes, used = {}, set()
    for encoded in proof:
        raw = unhex(encoded)
        if not raw or len(raw) > 4096:
            raise ValueError("trie node byte cap exceeded")
        digest = keccak(raw)
        if digest in nodes:
            raise ValueError("duplicate trie proof node")
        nodes[digest] = raw
    path = [n for byte in key for n in (byte >> 4, byte & 15)]
    cursor, reference = 0, root
    for _ in range(65):
        if isinstance(reference, list):
            if len(rlp(reference)) >= 32:
                raise ValueError("noncanonical inline trie reference")
            node = reference
        elif isinstance(reference, bytes) and len(reference) == 32:
            if reference not in nodes:
                raise ValueError("missing authenticated trie node")
            used.add(reference)
            node = decode_rlp(nodes[reference])
        else:
            raise ValueError("invalid trie child reference")
        if not isinstance(node, list):
            raise ValueError("invalid trie node")
        if len(node) == 17:
            if cursor == len(path):
                value = node[16] or None
                break
            reference = node[path[cursor]]
            cursor += 1
            if reference == b"":
                value = None
                break
        elif len(node) == 2 and isinstance(node[0], bytes) and node[0]:
            nibbles = [n for byte in node[0] for n in (byte >> 4, byte & 15)]
            flag = nibbles[0]
            if flag > 3 or (not flag & 1 and nibbles[1] != 0):
                raise ValueError("noncanonical trie compact path")
            part = nibbles[1 if flag & 1 else 2:]
            if path[cursor:cursor + len(part)] != part:
                if not allow_absence:
                    raise ValueError("trie inclusion path mismatch")
                value = None
                break
            cursor += len(part)
            if flag & 2:
                if cursor != len(path):
                    if not allow_absence:
                        raise ValueError("truncated trie leaf path")
                    value = None
                    break
                value = node[1]
                break
            if not part:
                raise ValueError("empty trie extension")
            reference = node[1]
        else:
            raise ValueError("invalid trie arity")
    else:
        raise ValueError("trie traversal cap exceeded")
    if used != set(nodes) or not ((isinstance(value, bytes) and value) or (value is None and allow_absence)):
        raise ValueError("invalid or extraneous trie proof")
    return value


def verify_account(block, address, proof):
    header_rlp(block)
    if unhex(proof["address"], 20) != unhex(address, 20):
        raise ValueError("account address mismatch")
    raw = verify_trie_value(unhex(block["stateRoot"], 32), keccak(unhex(address, 20)), proof["accountProof"])
    account = decode_rlp(raw)
    if not isinstance(account, list) or len(account) != 4 or any(not isinstance(v, bytes) for v in account):
        raise ValueError("invalid account RLP")
    nonce, balance, storage, code = account
    if (nonce and nonce[0] == 0) or (balance and balance[0] == 0) or len(nonce) > 8 or len(balance) > 32:
        raise ValueError("noncanonical account integers")
    if nonce != quantity(proof["nonce"]) or balance != quantity(proof["balance"]) or storage != unhex(proof["storageHash"], 32) or code != unhex(proof["codeHash"], 32):
        raise ValueError("RPC account fields differ from authenticated trie")
    return raw


def capture_recent(l1_url, l2_url, output):
    """Retain a recent candidate and authenticated prestate account, not a witness.

    RPC-finalized anchor selection is recorded, not claimed as consensus or
    derivation verification. The L1-origin transaction and full execution access
    set still require capture; this command never fabricates a claim.opd.
    """
    if rpc(l1_url, "eth_chainId", []) != "0x1" or rpc(l2_url, "eth_chainId", []) != "0xa":
        raise ValueError("unexpected chain IDs")
    anchor = rpc(l1_url, "eth_getBlockByNumber", ["finalized", False])
    nxt = rpc(l2_url, "eth_getBlockByNumber", ["finalized", False])
    previous = rpc(l2_url, "eth_getBlockByHash", [nxt["parentHash"], False])
    if int(previous["number"], 16) + 1 != int(nxt["number"], 16) or previous["hash"] != nxt["parentHash"]:
        raise ValueError("recent candidate adjacency mismatch")
    address = "0x4200000000000000000000000000000000000016"
    proof = rpc(l2_url, "eth_getProof", [address, [], {"blockHash": previous["hash"], "requireCanonical": True}])
    account = verify_account(previous, address, proof)
    if unhex(proof["storageHash"], 32) != unhex(previous["withdrawalsRoot"], 32):
        raise ValueError("message passer root differs from post-Isthmus header")
    output.mkdir(parents=True, exist_ok=False)
    artifacts = {}
    for name, block in (("l1-anchor", anchor), ("previous", previous), ("next", nxt)):
        raw = header_rlp(block)
        write_new(output / (name + ".rlp"), raw)
        artifacts[name] = {"number": int(block["number"], 16), "hash": block["hash"], "header_sha256": sha(raw)}
        if name != "l1-anchor":
            preimage = bytes(32) + unhex(block["stateRoot"], 32) + unhex(block["withdrawalsRoot"], 32) + unhex(block["hash"], 32)
            write_new(output / (name + "-root-preimage.bin"), preimage)
            artifacts[name]["output_root"] = "0x" + keccak(preimage).hex()
    write_new(output / "account-proof.json", (json.dumps(proof) + "\n").encode())
    write_new(output / "account.rlp", account)
    result = {"candidate": artifacts, "account_proof_verified_under_previous_state_root": True,
              "anchor_selection": "RPC finalized header pinned at capture; consensus proof not checked",
              "l1_endpoint": endpoint_label(l1_url), "l2_endpoint": endpoint_label(l2_url),
              "next_origin_bound": False, "kzg_verified": False, "complete_witness": False,
              "derivation_accepted": False, "proof_verified": False}
    write_new(output / "capture.json", (json.dumps(result, indent=2) + "\n").encode())
    return result


def capture_headers(url, receipt, count, cached=(), on_header=None):
    if not 2 <= count <= 512:
        raise ValueError("header capture count must be 2..512")
    if len(cached) > count:
        raise ValueError("cached header count exceeds requested range")
    statement = receipt["statement"]
    expected = "0x" + statement["block_hash"]
    records, roots = {}, []
    for index, number in enumerate(range(statement["next_number"], statement["next_number"] - count, -1)):
        block = cached[index] if index < len(cached) else rpc(url, "eth_getBlockByHash", [expected, False])
        if int(block["number"], 16) != number or unhex(block["hash"], 32) != unhex(expected, 32):
            raise ValueError("pinned L2 header ancestry mismatch")
        encoded = header_rlp(block)
        records[keccak(encoded).hex()] = encoded.hex()
        if number in (statement["previous_number"], statement["next_number"]):
            preimage = bytes(32) + unhex(block["stateRoot"], 32) + unhex(block["withdrawalsRoot"], 32) + unhex(block["hash"], 32)
            name = "previous_root" if number == statement["previous_number"] else "next_root"
            if keccak(preimage).hex() != statement[name]:
                raise ValueError("post-Isthmus output-root preimage mismatch")
            records[statement[name]] = preimage.hex()
            roots.append(name)
        if index >= len(cached) and on_header is not None:
            names = {"hash", "parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom", "difficulty", "number", "gasLimit", "gasUsed", "timestamp", "extraData", "mixHash", "prevRandao", "nonce", "baseFeePerGas", "withdrawalsRoot", "blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot", "requestsHash"}
            on_header({name: value for name, value in block.items() if name in names})
        expected = block["parentHash"]
    return sorted(records.items()), {"headers": count, "output_root_preimages": roots, "authenticated_from": statement["block_hash"], "complete_witness": False, "derivation_accepted": False, "proof_verified": False}


def pack(claim, records, sidecars, compress=True):
    if not isinstance(records, list) or not isinstance(sidecars, list) or len(records) > MAX_RECORDS or len(sidecars) > 256:
        raise ValueError("transition material count cap exceeded")
    checked = {}
    for key, value in records:
        digest, payload = unhex(key, 32), unhex(value)
        if digest in checked or keccak(payload) != digest:
            raise ValueError("duplicate or unauthenticated preimage")
        checked[digest] = payload
    payload_len = sum(map(len, checked.values()))
    total = 24 + 40 * len(checked) + payload_len
    if total + len(sidecars) * SIDECAR_BYTES > MAX_BODY:
        raise ValueError("transition material byte cap exceeded")
    witness = bytearray(b"STWOPX01" + struct.pack("<IIII", 0, len(checked), total, 0))
    payload = bytearray()
    for key, value in sorted(checked.items()):
        witness += key + struct.pack("<II", len(payload), len(value))
        payload += value
    body = witness + payload
    blobs = []
    for row in sidecars:
        if set(row) != {"blob", "kzg_commitment", "kzg_proof"}:
            raise ValueError("invalid sidecar fields")
        blobs.append((unhex(row["kzg_commitment"], 48), unhex(row["kzg_proof"], 48), unhex(row["blob"], BLOB_BYTES)))
    blobs.sort()
    if any(a[0] == b[0] for a, b in zip(blobs, blobs[1:])):
        raise ValueError("duplicate sidecar commitment")
    for commitment, proof, blob in blobs:
        body += commitment + proof + blob
    data = bytes(body)
    magic = b"STWOPD01"
    if compress and HEADER + len(data) > 16 << 20:
        compressed = zlib.compress(data, 6)
        if len(compressed) < len(data):
            data, magic = compressed, b"STWOPDZ1"
    out = magic + claim_header(claim) + struct.pack("<II", total, len(blobs)) + data
    if len(out) > MAX_INPUT:
        raise ValueError("packed input transport cap exceeded")
    return out


@contextmanager
def kv_reader(path, format):
    if format == "directory":
        def rows():
            for prefix in sorted(path.iterdir()):
                if prefix.is_symlink() or not prefix.is_dir() or not re.fullmatch(r"[0-9a-f]{4}", prefix.name):
                    continue
                for item in sorted(prefix.iterdir()):
                    if item.is_symlink() or not re.fullmatch(r"[0-9a-f]{60}\.txt", item.name) or item.stat().st_size > 2 << 20:
                        raise ValueError("invalid bounded directory-KV record")
                    value = unhex(item.read_text())
                    yield bytes.fromhex(prefix.name + item.stem), value
        yield rows()
    else:
        try:
            from rocksdict import AccessType, Options, Rdict
        except ImportError as exc:
            raise ValueError("read-only rocksdict unavailable in this environment") from exc
        options = Options(raw_mode=True)
        # Never instantiate upstream DiskKeyValueStore: its Drop destroys DB.
        db = Rdict(str(path), options=options, access_type=AccessType.read_only())
        try:
            yield db.items()
        finally:
            db.close()


def import_kv(path, format, *, max_files=1000000):
    records, ignored, count, total = {}, {}, 0, 0
    with kv_reader(path, format) as rows:
        for key, value in rows:
            count += 1
            total += len(value)
            if count > max_files or total > 512 << 20 or len(key) != 32 or len(value) > 1 << 20:
                raise ValueError("KV capture cap exceeded")
            if key[0] == 2:
                digest = keccak(value)
                if digest[1:] != key[1:]:
                    raise ValueError("Kona masked Keccak preimage key mismatch")
                if digest in records and records[digest] != value:
                    raise ValueError("conflicting recovered preimage")
                records[digest] = value
            else:
                ignored[str(key[0])] = ignored.get(str(key[0]), 0) + 1
    if len(records) > MAX_RECORDS:
        raise ValueError("too many Keccak records; blob-hint records need separately reviewed filtering")
    return [(key.hex(), value.hex()) for key, value in sorted(records.items())], {"records": len(records), "kv_rows": count, "ignored_key_types": ignored, "preimage_hashes_verified": True, "sidecars_recovered": False, "complete_witness": False, "derivation_accepted": False, "proof_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("recover")
    p.add_argument("roots", type=Path, nargs="+")
    p.add_argument("--output", type=Path)
    p = commands.add_parser("probe")
    p.add_argument("--rpc", required=True)
    p.add_argument("--layer", choices=["l1", "l2"], required=True)
    p = commands.add_parser("probe-host")
    p.add_argument("--rpc", required=True)
    p.add_argument("--layer", choices=["l1", "l2"], required=True)
    p = commands.add_parser("recent")
    p.add_argument("--l1-rpc", required=True)
    p.add_argument("--l2-rpc", required=True)
    p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("headers")
    p.add_argument("--rpc", required=True)
    p.add_argument("--count", type=int, default=292)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("pack")
    p.add_argument("--records", type=Path, required=True)
    p.add_argument("--sidecars", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--raw", action="store_true")
    p = commands.add_parser("import-kv")
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--format", choices=["directory", "rocksdb"], required=True)
    p.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = read_json(RECEIPT, 1 << 20)
    claim = claim_from_receipt(receipt)
    if args.command == "recover":
        result = recover(args.roots, args.output)
    elif args.command == "probe":
        result = probe(args.rpc, args.layer, receipt)
    elif args.command == "probe-host":
        result = probe_host(args.rpc, args.layer, receipt)
    elif args.command == "recent":
        result = capture_recent(args.l1_rpc, args.l2_rpc, args.output)
    elif args.command == "headers":
        args.output.mkdir(parents=True, exist_ok=args.resume)
        claim_bytes = (json.dumps(claim, indent=2) + "\n").encode()
        claim_path = args.output / "claim.json"
        if claim_path.exists():
            if not args.resume or claim_path.read_bytes() != claim_bytes:
                raise ValueError("capture claim identity changed")
        else:
            write_new(claim_path, claim_bytes)
        journal = args.output / "headers.jsonl"
        cached = []
        if args.resume and journal.exists():
            if journal.stat().st_size > 8 << 20:
                raise ValueError("header journal byte cap exceeded")
            cached = [json.loads(line) for line in journal.read_bytes().splitlines()]
        with journal.open("ab" if args.resume else "xb") as stream:
            def retain(block):
                encoded = (json.dumps(block) + "\n").encode()
                if len(encoded) > 16384:
                    raise ValueError("header journal row cap exceeded")
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            records, result = capture_headers(args.rpc, receipt, args.count, cached, retain)
        for name, value in (("records.json", records), ("capture.json", result)):
            encoded = (json.dumps(value, indent=2) + "\n").encode()
            target = args.output / name
            if target.exists():
                if target.read_bytes() != encoded:
                    raise ValueError("immutable capture output differs")
            else:
                write_new(target, encoded)
    elif args.command == "import-kv":
        records, result = import_kv(args.input, args.format)
        args.output.mkdir(parents=True, exist_ok=False)
        write_new(args.output / "records.json", (json.dumps(records) + "\n").encode())
        write_new(args.output / "capture.json", (json.dumps(result, indent=2) + "\n").encode())
    else:
        data = pack(claim, read_json(args.records), read_json(args.sidecars), not args.raw)
        result = inspect_container(data, claim)
        result["preimage_hashes_verified"] = True
        result["compression_note"] = "zlib encoding may differ from Rust miniz; semantic container identity only"
        write_new(args.output, data)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except RpcFailure as error:
        print(json.dumps(error.report))
        raise SystemExit(1) from None
    except (ValueError, OSError, KeyError, TypeError) as error:
        # Do not echo endpoint URLs, HTTP bodies or environment into errors.
        print(json.dumps({"status": "capture_failed", "error_type": type(error).__name__}))
        raise SystemExit(1) from None

"""Content-addressed store of Starknet JSON-RPC exchanges.

Layout under ``<root>/<network>/``:

    objects/<aa>/<sha256>.json.gz     response ``result`` (or ``error``) bodies
    index/<aa>/<request-key>          one line: object digest (request -> response)
    blocks/<n>/requests.jsonl         which requests the collector made for block n

A request key is sha256 over the method and canonical JSON params, so the same
query issued by a later run (a multi-block assembly, a replay) resolves to the
recorded response regardless of JSON-RPC ids or key ordering.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def request_key(method: str, params: Any) -> str:
    return hashlib.sha256(method.encode() + b"\n" + canonical(params)).hexdigest()


PROOF = "starknet_getStorageProof"


def _h(x: str) -> str:
    return hex(int(x, 16))


def normalize_proof_params(params: dict) -> dict:
    """Canonical getStorageProof params: normalised hex, sorted contracts/keys/classes."""
    keys: dict[str, set[str]] = {}
    for e in params.get("contracts_storage_keys", []):
        keys.setdefault(_h(e["contract_address"]), set()).update(_h(k) for k in e["storage_keys"])
    return {
        "block_id": params["block_id"],
        "class_hashes": sorted({_h(x) for x in params.get("class_hashes", [])}, key=lambda x: int(x, 16)),
        "contract_addresses": sorted({_h(x) for x in params.get("contract_addresses", [])}, key=lambda x: int(x, 16)),
        "contracts_storage_keys": [
            {"contract_address": c, "storage_keys": sorted(ks, key=lambda x: int(x, 16))}
            for c, ks in sorted(keys.items(), key=lambda kv: int(kv[0], 16))
        ],
    }


def permute_proof(src_params: dict, result: dict, dst_params: dict) -> dict:
    """Reorder a proof result's positional arrays from src_params' order to dst_params'.

    Node lists are unordered sets keyed by hash, so only the per-contract leaf
    data and per-contract storage node lists need re-aligning.
    """
    leaves = {_h(c): leaf for c, leaf in zip(src_params.get("contract_addresses", []),
                                             result["contracts_proof"]["contract_leaves_data"])}
    storage: dict[str, dict] = {}
    for e, nodes in zip(src_params.get("contracts_storage_keys", []), result["contracts_storage_proofs"]):
        storage.setdefault(_h(e["contract_address"]), {}).update({n["node_hash"]: n for n in nodes})
    return {
        "classes_proof": result.get("classes_proof", []),
        "contracts_proof": {
            "nodes": result["contracts_proof"]["nodes"],
            "contract_leaves_data": [leaves[_h(c)] for c in dst_params.get("contract_addresses", [])],
        },
        "contracts_storage_proofs": [list(storage[_h(e["contract_address"])].values())
                                     for e in dst_params.get("contracts_storage_keys", [])],
        "global_roots": result["global_roots"],
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


class RpcStore:
    def __init__(self, root: Path, network: str):
        self.base = root / network
        self.objects = self.base / "objects"
        self.index = self.base / "index"
        self.blocks = self.base / "blocks"
        for d in (self.objects, self.index, self.blocks):
            d.mkdir(parents=True, exist_ok=True)

    # -- objects -----------------------------------------------------------
    def put_object(self, body: dict) -> str:
        data = canonical(body)
        digest = hashlib.sha256(data).hexdigest()
        path = self.objects / digest[:2] / f"{digest}.json.gz"
        if not path.exists():
            _atomic_write(path, gzip.compress(data, compresslevel=6))
        return digest

    def get_object(self, digest: str) -> dict:
        path = self.objects / digest[:2] / f"{digest}.json.gz"
        return json.loads(gzip.decompress(path.read_bytes()))

    # -- request index -----------------------------------------------------
    def record(self, method: str, params: Any, body: dict) -> str:
        key = self._record_exact(method, params, body)
        if method == PROOF and "result" in body and isinstance(params, dict):
            norm = normalize_proof_params(params)
            if norm != params:
                self._record_exact(method, norm, {"result": permute_proof(params, body["result"], norm)})
        return key

    def _record_exact(self, method: str, params: Any, body: dict) -> str:
        key = request_key(method, params)
        digest = self.put_object(body)
        _atomic_write(self.index / key[:2] / key, digest.encode())
        return key

    def _lookup_exact(self, method: str, params: Any) -> dict | None:
        key = request_key(method, params)
        path = self.index / key[:2] / key
        if not path.exists():
            return None
        return self.get_object(path.read_text().strip())

    def lookup(self, method: str, params: Any) -> dict | None:
        body = self._lookup_exact(method, params)
        if body is None and method == PROOF and isinstance(params, dict):
            # SNOS builds key lists from hash sets, so the same proof request
            # arrives in varying orders; match on the canonical form.
            norm = normalize_proof_params(params)
            found = self._lookup_exact(method, norm)
            if found is not None and "result" in found:
                body = {"result": permute_proof(norm, found["result"], params)}
        return body

    # -- immutable class definitions ------------------------------------
    # Class bodies never change once declared, so a definition recorded for
    # block b answers the same class hash at any block >= b.
    def _class_alias(self, method: str, class_hash: str) -> Path:
        return self.index / "classes" / method / hex(int(class_hash, 16))

    def record_class(self, method: str, class_hash: str, block: int, body: dict) -> None:
        path = self._class_alias(method, class_hash)
        if path.exists() and int(path.read_text().split()[0]) <= block:
            return
        _atomic_write(path, f"{block} {self.put_object(body)}".encode())

    def lookup_class(self, method: str, class_hash: str, block: int) -> dict | None:
        path = self._class_alias(method, class_hash)
        if not path.exists():
            return None
        first, digest = path.read_text().split()
        return self.get_object(digest) if int(first) <= block else None

    # -- per-block bookkeeping -------------------------------------------
    def block_dir(self, block: int) -> Path:
        d = self.blocks / str(block)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def note_request(self, block: int, method: str, params: Any, key: str, source: str, ms: float) -> None:
        line = json.dumps({"method": method, "key": key, "source": source, "ms": round(ms, 1), "params": params})
        with open(self.block_dir(block) / "requests.jsonl", "a") as f:
            f.write(line + "\n")

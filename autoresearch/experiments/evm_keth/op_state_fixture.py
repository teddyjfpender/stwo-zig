#!/usr/bin/env python3
"""Reconstruct root-authenticated Keth state inputs for a real OP workload.

This emits an OP-specific fixture for developing its execution layer. The
Ethereum-only bridge continues to reject it. Host witness authentication is not
a constrained Cairo application statement or a proof of OP derivation.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path

import rlp
from eth_hash.auto import keccak

if __package__:
    from .bridge import PINS, digest, write_new
    from .check_fixture import header_hash
    from .op_encoding import hex_bytes, quantity
    from .state_proofs import EMPTY_CODE_HASH, integer, lookup_nodes
else:
    from bridge import PINS, digest, write_new
    from check_fixture import header_hash
    from op_encoding import hex_bytes, quantity
    from state_proofs import EMPTY_CODE_HASH, integer, lookup_nodes


def state_at(root: str, accesses: list, nodes: dict, codes: dict) -> dict:
    result = {}
    for entry in accesses:
        address = entry['address']
        if address in result:
            raise ValueError('duplicate access-list account')
        raw = lookup_nodes(hex_bytes(root, 32), keccak(hex_bytes(address, 20)), nodes)
        if raw is None:
            result[address] = None
            continue
        account = rlp.decode(raw, strict=True)
        if not isinstance(account, list) or len(account) != 4:
            raise ValueError('invalid account leaf')
        nonce, balance, storage_root, code_hash = account
        if len(storage_root) != 32 or len(code_hash) != 32:
            raise ValueError('invalid account roots')
        if code_hash not in codes:
            raise ValueError('code missing for authenticated account')
        if integer(nonce) >= 2**64:
            raise ValueError('account nonce exceeds uint64')
        storage = {}
        for key in entry['storageKeys']:
            key_bytes = quantity(key).to_bytes(32, 'big')
            canonical_key = '0x' + key_bytes.hex()
            if canonical_key in storage:
                raise ValueError('duplicate storage access')
            leaf = lookup_nodes(storage_root, keccak(key_bytes), nodes)
            value = 0 if leaf is None else integer(rlp.decode(leaf, strict=True))
            storage[canonical_key] = hex(value)
        result[address] = dict(nonce=hex(integer(nonce)), balance=hex(integer(balance)),
                               codeHash='0x' + code_hash.hex(), storageHash='0x' + storage_root.hex(),
                               code='0x' + codes[code_hash].hex(), storage=storage)
    return result


def convert(source: Path, accesses_path: Path, provenance_path: Path, qualification_path: Path, out: Path) -> dict:
    raw = source.read_bytes()
    if source.suffix == '.gz':
        raw = gzip.decompress(raw)
    source_hash = hashlib.sha256(raw).hexdigest()
    data = json.loads(raw)
    provenance = json.loads(provenance_path.read_text())
    qualification = json.loads(qualification_path.read_text())
    if (provenance['reference_revision'] != PINS['op_reference']['revision']
            or digest(accesses_path) != provenance['access_list_sha256']
            or provenance['archives']['optimism-input.json.gz']['uncompressed_sha256'] != source_hash
            or qualification['input_sha256'] != source_hash or qualification['status'] != 'qualified'
            or qualification['binary_sha256'] != provenance['reference_binary_sha256']):
        raise ValueError('native input/reference identity mismatch')
    trial = qualification['trials'][0]
    reference_path = qualification_path.parent / (trial['name'] + '.json')
    if digest(reference_path) != trial['result_sha256']:
        raise ValueError('reference result hash mismatch')
    reference = json.loads(reference_path.read_text())
    block = data['block']
    if (data['chain_id'] != 10 or not reference['offline_execution_checked']
            or reference['computed_state_root'] != block['stateRoot']
            or reference['computed_receipt_root'] != block['receiptsRoot']
            or reference['block_hash'] != header_hash(block) or block['hash'] != reference['block_hash']):
        raise ValueError('expected qualified OP Mainnet block execution')
    nodes = {keccak(hex_bytes(node)): hex_bytes(node) for node in data['witness']['state']}
    codes = {keccak(hex_bytes(code)): hex_bytes(code) for code in data['witness']['codes']}
    codes[EMPTY_CODE_HASH] = b''
    accesses = [dict(address='0x' + hex_bytes(a['address'], 20).hex(),
                     storageKeys=['0x' + quantity(key).to_bytes(32, 'big').hex() for key in a['storageKeys']])
                for a in json.loads(accesses_path.read_text())]
    parent = data['witness']['headers'][0]
    if header_hash(parent) != parent['hash'] or parent['hash'] != block['parentHash']:
        raise ValueError('parent header identity mismatch')
    pre = state_at(parent['stateRoot'], accesses, nodes, codes)
    post = state_at(block['stateRoot'], accesses, nodes, codes)
    diffs = []
    for access in accesses:
        address = access['address']
        before, after = pre[address], post[address]
        if before == after:
            continue
        diff = dict(address=address)
        for label, value in (('preAccount', before), ('postAccount', after)):
            if value is not None:
                diff[label] = {k: v for k, v in value.items() if k not in ('storage', 'code')}
        storage = []
        for key in access['storageKeys']:
            a, b = (before or {}).get('storage', {}).get(key, '0x0'), (after or {}).get('storage', {}).get(key, '0x0')
            if a != b:
                storage.append(dict(storageKey=key, preValue=a, postValue=b))
        diff['storage'] = storage
        diffs.append(diff)
    header = {k: v for k, v in block.items() if k not in ('transactions', 'withdrawals', 'uncles')}
    fixture = dict(version='1', chainConfig=reference['chain_config'],
                   blocks=[dict(header=header, transaction=block['transactions'], uncles=[], withdrawals=block['withdrawals'])],
                   witness=dict(state=data['witness']['state'], ancestors=data['witness']['headers'], codes=data['witness']['codes']),
                   extra=dict(accessList=accesses, preState=pre, postState=post, stateDiffs=diffs, committed=data['witness']['state']),
                   opStack=dict(scope='OP execution development fixture; rejected by Ethereum-only bridge',
                                cairo_execution_proved=False, derivation_proved=False, consensus_authenticated=False))
    write_new(out, fixture)
    receipt = dict(schema='keth-op-state-fixture-v1', source_sha256=source_hash, fixture_sha256=digest(out),
                   access_list_sha256=digest(accesses_path), provenance_sha256=digest(provenance_path),
                   qualification_sha256=digest(qualification_path), block_hash=block['hash'],
                   pre_root=parent['stateRoot'], post_root=block['stateRoot'], accounts=len(accesses),
                   storage_slots=sum(len(a['storageKeys']) for a in accesses), changed_accounts=len(diffs),
                   changed_storage_slots=sum(len(d['storage']) for d in diffs),
                   native_execution_reference_checked=True, point_reads_authenticated=True,
                   cairo_execution_proved=False, derivation_proved=False)
    write_new(out.with_suffix(out.suffix + '.receipt.json'), receipt)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('input', 'access-list', 'provenance', 'qualification', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(convert(args.input, args.access_list, args.provenance, args.qualification, args.out), indent=2))

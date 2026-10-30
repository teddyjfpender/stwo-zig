#!/usr/bin/env python3
"""Recheck a complete candidate-access collection and emit offline OP inputs.

Only a successful reference execution establishes that the collected witness
was sufficient for this block. This assembly step makes no proof claim.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

if __package__:
    from .bridge import digest, write_new
    from .collect_state_witness import candidate_accesses
    from .state_proofs import verify_account
    from .witness_nodes import recover_compressed_siblings
else:
    from bridge import digest, write_new
    from collect_state_witness import candidate_accesses
    from state_proofs import verify_account
    from witness_nodes import recover_compressed_siblings


def assemble(collection: Path, block_path: Path, parent_path: Path, trace_path: Path, out: Path) -> dict:
    receipt = json.loads((collection / 'collection.json').read_text())
    block = json.loads(block_path.read_text())['result']
    parent = json.loads(parent_path.read_text())['result']
    traces = json.loads(trace_path.read_text())['result']
    if receipt['status'] != 'verified_candidate_accesses' or receipt['failed_accounts']:
        raise ValueError('candidate access collection is incomplete')
    if receipt['block_hash'] != block['hash'] or receipt['parent_hash'] != parent['hash']:
        raise ValueError('collection/block identity mismatch')
    for path in (block_path, parent_path, trace_path):
        if receipt['sources'][str(path)] != digest(path):
            raise ValueError('collection source file changed')
    expected = candidate_accesses(block, traces)
    if set(expected) != {a['address'] for a in receipt['accounts']} or len(receipt['accounts']) != len(expected):
        raise ValueError('collected account set is not exact')
    nodes, codes = set(), set()
    message_passer = None
    for account in receipt['accounts']:
        address = account['address']
        directory = collection / address
        if account['status'] != 'verified':
            raise ValueError('unverified candidate account')
        for name, sha256 in account['files'].items():
            if Path(name).name != name or digest(directory / name) != sha256:
                raise ValueError('account file hash/path mismatch')
        for label, header in (('pre', parent), ('post', block)):
            merged = None
            for path in sorted(directory.glob(label + '-proof-*.json')):
                proof = json.loads(path.read_text())['result']
                verify_account(header['stateRoot'], address, proof)
                nodes.update(proof['accountProof'])
                for slot in proof['storageProof']:
                    nodes.update(slot['proof'])
                if merged is None:
                    merged = dict(proof, storageProof=list(proof['storageProof']))
                else:
                    merged['storageProof'].extend(proof['storageProof'])
            if merged is None or {int(p['key'], 16) for p in merged['storageProof']} != {int(k, 16) for k in expected[address]}:
                raise ValueError('storage proof coverage mismatch')
            code = json.loads((directory / (label + '-code.json')).read_text())['result']
            verify_account(header['stateRoot'], address, merged, code)
            codes.add(code)
            if address == '0x4200000000000000000000000000000000000016' and label == 'post':
                message_passer = dict(address=address, accountProof=merged['accountProof'])
    # Include executed transient code as content-addressed blobs too. The EVM
    # obtains code only by its state-root-bound code hash.
    for trace in traces:
        codes.update(state['code'] for state in trace['result'].values() if 'code' in state)
    expanded, recovery = recover_compressed_siblings(nodes)
    value = dict(chain_id=receipt['chain_id'], block=block,
                 witness=dict(headers=[parent], codes=sorted(codes - {'0x'}), state=expanded),
                 message_passer_proof=message_passer)
    write_new(out, value)
    result = dict(schema='keth-op-reference-input-v1', input_sha256=digest(out),
                  collection_sha256=digest(collection / 'collection.json'),
                  block_hash=block['hash'], candidate_accounts=len(expected),
                  candidate_storage_slots=sum(map(len, expected.values())),
                  trie_nodes=len(expanded), trie_node_bytes=sum((len(n) - 2) // 2 for n in expanded),
                  compressed_sibling_recovery=recovery,
                  codes=len(value['witness']['codes']),
                  code_bytes=sum((len(c) - 2) // 2 for c in value['witness']['codes']),
                  execution_witness_complete=False, offline_reference_execution_passed=False,
                  cairo_execution_proved=False)
    write_new(out.with_suffix(out.suffix + '.receipt.json'), result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--collection', type=Path, required=True)
    parser.add_argument('--block', type=Path, required=True)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--trace', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(assemble(args.collection, args.block, args.parent, args.trace, args.out), indent=2))

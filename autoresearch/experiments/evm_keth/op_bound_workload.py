"""Prepare minimal root-authenticated transaction witnesses from native checkpoints.

The access trace is a witness-size hint, not a correctness authority. Cairo
checks access coverage, starting-state membership and the complete root diff.
"""
from __future__ import annotations

import copy
from eth_hash.auto import keccak

from .op_encoding import op_transaction_bytes, receipt_bytes
from .op_state_fixture import state_at
from .state_proofs import EMPTY_CODE_HASH


class VisitedNodes(dict):
    def __init__(self, nodes):
        super().__init__(nodes)
        self.visited = set()

    def __getitem__(self, key):
        value = super().__getitem__(key)
        self.visited.add(key)
        return value


def prepare_system(native: dict, checkpoints: dict, all_accesses: list, environment: dict) -> dict:
    before = native['witness']['headers'][0]['stateRoot']
    after = checkpoints['checkpoints'][0]['root']
    contracts = {'0x000f3df6d732807ef1319fb7b8bb8522d0beac02',
                 '0x0000f90827f1c53a10cb7a02335b175320002935'}
    accesses = [copy.deepcopy(a) for a in all_accesses if a['address'].lower() in contracts]
    if len(accesses) != 2:
        raise ValueError('system contract access witnesses are missing')
    nodes = VisitedNodes({keccak(bytes.fromhex(raw[2:])): bytes.fromhex(raw[2:])
        for raw in native['witness']['state'] + checkpoints['checkpoints'][0]['proof_nodes']})
    codes = {keccak(bytes.fromhex(c[2:])): bytes.fromhex(c[2:]) for c in native['witness']['codes']}
    codes[EMPTY_CODE_HASH] = b''
    pre = state_at(before, accesses, nodes, codes)
    state_at(after, accesses, nodes, codes)
    for account in pre.values():
        if account is not None:
            account.pop('code', None)
    return dict(action=0, parent_hash=native['block']['parentHash'], before_root=before, after_root=after,
                header={k: v for k, v in native['block'].items() if k not in ('transactions', 'withdrawals', 'uncles')},
                headers=list(reversed(native['witness']['headers'])),
                transaction_index=0, previous_gas=0, transaction='0x', pre_state=pre, access_list=accesses,
                codes={'0x' + h.hex(): '0x' + c.hex() for h, c in codes.items()}, environment=environment,
                proof_nodes=['0x' + nodes[key].hex() for key in sorted(nodes.visited)],
                expected=dict(transaction_hash='0x' + '00'*32, gas_used=0,
                              receipt_hash='0x' + keccak(b'').hex(), encoded_receipt='0x'),
                scope=dict(cairo_execution_proved=False, cairo_state_roots_bound=False, derivation_proved=False))


def main():
    import argparse
    import json
    from pathlib import Path
    from .bridge import digest, write_new
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native-input', 'checkpoints', 'environment-input', 'access-list', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    sources = dict(native_input=args.native_input, checkpoints=args.checkpoints,
                   environment_input=args.environment_input, access_list=args.access_list)
    identities = {key: digest(path) for key, path in sources.items()}
    native = json.loads(args.native_input.read_text())
    checkpoints = json.loads(args.checkpoints.read_text())
    environment = json.loads(args.environment_input.read_text())['environment']
    accesses = json.loads(args.access_list.read_text())
    args.out.mkdir(parents=True, exist_ok=False)
    write_new(args.out / 'system.json', prepare_system(native, checkpoints, accesses, environment))
    for index in range(len(native['block']['transactions'])):
        write_new(args.out / f'{index}.json', prepare(native, checkpoints, index, environment))
    if identities != {key: digest(path) for key, path in sources.items()}:
        raise ValueError('workload sources changed')
    write_new(args.out / 'prepared.json', dict(schema='keth-op-root-bound-workloads-v1',
        source_sha256=identities, block_hash=native['block']['hash'],
        transactions=len(native['block']['transactions']), op_block_execution_proved=False))


def prepare(native: dict, checkpoints: dict, index: int, environment: dict) -> dict:
    rows = checkpoints['checkpoints']
    if not checkpoints['complete_reference_execution'] or len(rows) != len(native['block']['transactions']) * 2:
        raise ValueError('complete native checkpoints required')
    if not 0 <= index < len(native['block']['transactions']):
        raise ValueError('transaction index outside block')
    before, after = rows[index*2:index*2+2]
    tx = native['block']['transactions'][index]
    raw = op_transaction_bytes(tx)
    tx_hash = '0x' + keccak(raw).hex()
    if any(row['transaction_index'] != index or row['transaction_hash'] != tx_hash
           for row in (before, after)) or (before['phase'], after['phase']) != ('pre', 'post'):
        raise ValueError('checkpoint transaction identity mismatch')
    accesses = copy.deepcopy(after['transaction_access_list'])
    for entry in accesses:
        entry['storageKeys'] = sorted(entry['storageKeys'])
    accesses.sort(key=lambda entry: entry['address'])
    original_nodes = {keccak(bytes.fromhex(raw[2:])): bytes.fromhex(raw[2:])
                      for raw in native['witness']['state']}
    nodes = VisitedNodes({**original_nodes, **{
        keccak(bytes.fromhex(raw[2:])): bytes.fromhex(raw[2:])
        for row in (before, after) for raw in row['proof_nodes']}})
    codes = {keccak(bytes.fromhex(c[2:])): bytes.fromhex(c[2:]) for c in native['witness']['codes']}
    codes[EMPTY_CODE_HASH] = b''
    pre = state_at(before['root'], accesses, nodes, codes)
    state_at(after['root'], accesses, nodes, codes)
    for account in pre.values():
        if account is not None:
            account.pop('code', None)
    for address, account in pre.items():
        expected = before['state'][address]
        if (account is None) != (expected is None):
            raise ValueError('authenticated account presence differs from checkpoint')
        if account is not None:
            for field in ('nonce', 'balance', 'codeHash', 'storageHash'):
                if account[field] != expected[field]:
                    raise ValueError('authenticated account differs from checkpoint')
            if any(int(value, 16) != int(expected['storage'][key], 16) for key, value in account['storage'].items()):
                raise ValueError('authenticated storage differs from checkpoint')
    previous = sum(int(row['receipt']['gasUsed'], 16) for row in rows[1:index*2:2])
    receipt = after['receipt']
    if previous + int(receipt['gasUsed'], 16) != int(receipt['cumulativeGasUsed'], 16):
        raise ValueError('receipt cumulative gas mismatch')
    expected_receipt = receipt_bytes({**receipt, 'logs': receipt['logs'] or [], 'type': tx['type']})
    return dict(action=1 if raw[0] == 0x7e else 2, parent_hash=native['block']['parentHash'],
                header={k: v for k, v in native['block'].items() if k not in ('transactions', 'withdrawals', 'uncles')},
                headers=list(reversed(native['witness']['headers'])),
                before_root=before['root'], after_root=after['root'], transaction_index=index,
                previous_gas=previous, pre_state=pre, access_list=accesses, transaction='0x' + raw.hex(),
                codes={'0x' + h.hex(): '0x' + c.hex() for h, c in codes.items()}, environment=environment,
                # Root-diff traversal also needs deletion/collapse siblings
                # beyond point membership paths. Retain the original witness.
                proof_nodes=['0x' + nodes[key].hex() for key in sorted(nodes.visited | original_nodes.keys())],
                expected=dict(transaction_hash=tx_hash, gas_used=int(receipt['gasUsed'], 16),
                              receipt_hash='0x' + keccak(expected_receipt).hex(),
                              encoded_receipt='0x' + expected_receipt.hex()),
                scope=dict(cairo_execution_proved=False, cairo_state_roots_bound=False, derivation_proved=False))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Collect and verify pre/post account, storage and code witnesses for a trace.

The trace supplies candidate accesses only. Missing system accesses or execution
effects require a separate offline reference execution before completeness can
be claimed. Existing files are never overwritten; failures retain partial data.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import threading
import time

from eth_hash.auto import keccak

if __package__:
    from .bridge import digest, write_new
    from .check_fixture import header_hash
    from .collect_rpc import rpc
    from .state_proofs import verify_account
else:
    from bridge import digest, write_new
    from check_fixture import header_hash
    from collect_rpc import rpc
    from state_proofs import verify_account


def candidate_accesses(block: dict, traces: list) -> dict[str, set[str]]:
    if len(traces) != len(block['transactions']):
        raise ValueError('trace transaction count mismatch')
    accesses = {}
    for tx, trace in zip(block['transactions'], traces):
        if trace.get('txHash') != tx['hash'] or 'error' in trace:
            raise ValueError('ordered trace hash mismatch or trace error')
        for address, state in trace['result'].items():
            accesses.setdefault(address.lower(), set()).update(state.get('storage', {}))
    # System effects and fee distribution can occur outside a transaction tracer.
    # This explicit supplemental set is not a completeness certificate.
    for address in (block['miner'], '0x4200000000000000000000000000000000000015',
                    '0x4200000000000000000000000000000000000016',
                    '0x4200000000000000000000000000000000000019',
                    '0x420000000000000000000000000000000000001a',
                    '0x420000000000000000000000000000000000001b',
                    '0x000f3df6d732807ef1319fb7b8bb8522d0beac02',
                    '0x0000f90827f1c53a10cb7a02335b175320002935',
                    '0x4e59b44847b379578588920ca78fbf26c0b4956c'):
        accesses.setdefault(address.lower(), set())
    # Standard EIP-4788 and EIP-2935 system writes precede transaction tracing.
    # Root checks still apply if either account is absent on a selected fork.
    timestamp_slot = int(block['timestamp'], 16) % 8191
    accesses['0x000f3df6d732807ef1319fb7b8bb8522d0beac02'].update(
        '0x' + value.to_bytes(32, 'big').hex() for value in (timestamp_slot, timestamp_slot + 8191))
    accesses['0x0000f90827f1c53a10cb7a02335b175320002935'].add(
        '0x' + ((int(block['number'], 16) - 1) % 8191).to_bytes(32, 'big').hex())
    return accesses


def collect(endpoint: str, chain_id: int, block_path: Path, parent_path: Path,
            trace_path: Path, out: Path, workers: int = 2,
            requests_per_second: float = 2, reuse: Path | None = None) -> dict:
    block = json.loads(block_path.read_text())['result']
    parent = json.loads(parent_path.read_text())['result']
    traces = json.loads(trace_path.read_text())['result']
    for header in (block, parent):
        if header_hash(header) != header['hash']:
            raise ValueError('header hash mismatch')
    if block['parentHash'] != parent['hash'] or int(block['number'], 16) != int(parent['number'], 16) + 1:
        raise ValueError('parent link mismatch')
    accesses = candidate_accesses(block, traces)
    known_codes = {'0x' + keccak(b'').hex(): '0x'}
    for trace in traces:
        for state in trace['result'].values():
            if 'code' in state:
                code = state['code']
                known_codes['0x' + keccak(bytes.fromhex(code[2:])).hex()] = code
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    receipt = dict(schema='keth-state-witness-collection-v1', status='running',
                   endpoint=endpoint, chain_id=chain_id, block_number=int(block['number'], 16),
                   block_hash=block['hash'], parent_hash=parent['hash'],
                   started_at=datetime.now(timezone.utc).isoformat(),
                   sources={str(p): digest(p) for p in (block_path, parent_path, trace_path)},
                   candidate_accounts=len(accesses), candidate_storage_slots=sum(map(len, accesses.values())),
                   requests_per_second=requests_per_second, reuse_from=str(reuse) if reuse else None,
                   collector_sha256=digest(Path(__file__)),
                   accounts=[], execution_witness_complete=False,
                   offline_reference_execution_passed=False, cairo_execution_proved=False)
    write_new(out / 'access-list.json', [{'address': a, 'storageKeys': sorted(keys)} for a, keys in sorted(accesses.items())])

    pacing = threading.Lock()
    last_request = 0.0

    def request(method, params):
        nonlocal last_request
        # One small retry budget for public endpoint transients, not an unbounded
        # restart or substitution of missing data with defaults.
        for attempt in range(3):
            with pacing:
                time.sleep(max(0, last_request + 1 / requests_per_second - time.monotonic()))
                last_request = time.monotonic()
            try:
                return rpc(endpoint, method, params)
            except Exception:
                if attempt == 2:
                    raise
                time.sleep(0.5 * (attempt + 1))

    def account(item):
        address, keys = item
        directory = out / address
        if reuse is not None and (reuse / address / 'account.json').is_file():
            previous = json.loads((reuse / address / 'account.json').read_text())
            if previous['status'] == 'verified' and previous['storage_slots'] == len(keys):
                # Recheck bytes against roots and the complete requested slot
                # set; an old status string alone never authorizes reuse.
                for name, expected in previous['files'].items():
                    if Path(name).name != name or digest(reuse / address / name) != expected:
                        raise ValueError('reused account file hash/path mismatch')
                for label, header in (('pre', parent), ('post', block)):
                    merged = None
                    for path in sorted((reuse / address).glob(label + '-proof-*.json')):
                        proof = json.loads(path.read_text())['result']
                        verify_account(header['stateRoot'], address, proof)
                        if merged is None:
                            merged = dict(proof, storageProof=list(proof['storageProof']))
                        else:
                            merged['storageProof'].extend(proof['storageProof'])
                    if merged is None or {int(p['key'], 16) for p in merged['storageProof']} != {int(k, 16) for k in keys}:
                        raise ValueError('reused storage proof coverage mismatch')
                    code = json.loads((reuse / address / (label + '-code.json')).read_text())['result']
                    verify_account(header['stateRoot'], address, merged, code)
                shutil.copytree(reuse / address, directory)
                return dict(previous, reused=True)
        directory.mkdir()
        result = dict(address=address, status='running', storage_slots=len(keys), files={})

        def retain(name, value):
            path = directory / name
            write_new(path, value)
            result['files'][name] = digest(path)

        try:
            for label, header in (('pre', parent), ('post', block)):
                slots = sorted(keys)
                # Bound RPC request size; each chunk repeats a root-checked
                # account proof and must return exactly the requested slot set.
                merged = None
                for index in range(0, max(1, len(slots)), 64):
                    requested = slots[index:index + 64]
                    response = request('eth_getProof', [address, requested, header['number']])
                    retain(f'{label}-proof-{index // 64}.json', response)
                    proof = response['result']
                    if {int(p['key'], 16) for p in proof['storageProof']} != {int(k, 16) for k in requested}:
                        raise ValueError('RPC did not return exact requested storage keys')
                    verify_account(header['stateRoot'], address, proof)
                    if merged is None:
                        merged = dict(proof, storageProof=list(proof['storageProof']))
                    else:
                        if any(merged[k] != proof[k] for k in ('nonce', 'balance', 'codeHash', 'storageHash')):
                            raise ValueError('account changed between proof chunks')
                        merged['storageProof'].extend(proof['storageProof'])
                cached = known_codes.get(merged['codeHash'])
                code = (dict(jsonrpc='2.0', id=1, result=cached, source='verified_code_hash_cache')
                        if cached is not None else request('eth_getCode', [address, header['number']]))
                retain(label + '-code.json', code)
                result[label] = verify_account(header['stateRoot'], address, merged, code['result'])
            result['status'] = 'verified'
        except Exception as error:
            result.update(status='failed', error_type=type(error).__name__, error=str(error))
        write_new(directory / 'account.json', result)
        return result

    try:
        chain = request('eth_chainId', [])
        write_new(out / 'chain.json', chain)
        if int(chain['result'], 16) != chain_id:
            raise ValueError('RPC chain ID mismatch')
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for count, result in enumerate(pool.map(account, sorted(accesses.items())), 1):
                receipt['accounts'].append(result)
                print(json.dumps(dict(account=count, total=len(accesses), address=result['address'],
                                      status=result['status'], error=result.get('error'))), flush=True)
        receipt['verified_accounts'] = sum(a['status'] == 'verified' for a in receipt['accounts'])
        receipt['failed_accounts'] = len(accesses) - receipt['verified_accounts']
        receipt['status'] = 'verified_candidate_accesses' if not receipt['failed_accounts'] else 'partial_failure'
    except Exception as error:
        receipt.update(status='failed', error=str(error), error_type=type(error).__name__)
        raise
    finally:
        receipt.update(elapsed_seconds=time.monotonic() - started,
                       finished_at=datetime.now(timezone.utc).isoformat())
        write_new(out / 'collection.json', receipt)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--chain-id', type=int, required=True)
    parser.add_argument('--block', type=Path, required=True)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--trace', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--requests-per-second', type=float, default=2)
    parser.add_argument('--reuse-verified-from', type=Path)
    args = parser.parse_args()
    if not 1 <= args.workers <= 4 or args.chain_id < 1 or not 0.1 <= args.requests_per_second <= 4:
        parser.error('use 1-4 workers, 0.1-4 requests/second and a positive chain ID')
    value = collect(args.endpoint, args.chain_id, args.block, args.parent, args.trace, args.out, args.workers,
                    args.requests_per_second, args.reuse_verified_from)
    if value['status'] != 'verified_candidate_accesses':
        raise SystemExit(1)

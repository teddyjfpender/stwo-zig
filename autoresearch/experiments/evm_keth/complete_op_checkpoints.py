#!/usr/bin/env python3
"""Complete a reference checkpoint witness with root-verified sibling probes.

Each failed attempt is retained. Short secure-path prefixes identify public
storage-proof queries; no storage values or node hashes are invented.
"""
from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path
import re
import subprocess

from eth_hash.auto import keccak

if __package__:
    from .bridge import digest, write_new
    from .collect_rpc import rpc
    from .state_proofs import verify_account
else:
    from bridge import digest, write_new
    from collect_rpc import rpc
    from state_proofs import verify_account

MISSING = re.compile(r'missing trie node ([0-9a-f]{64}) \(owner ([0-9a-f]{64})\) \(path ([0-9a-f]*)\)')


def complete(binary: Path, probe_binary: Path | None, source: Path, accesses_path: Path,
             endpoint: str | None, out: Path, attempts: int, supplemental_nodes: Path | None = None):
    out.mkdir(parents=True, exist_ok=False)
    raw = source.read_bytes()
    value = json.loads(gzip.decompress(raw) if source.suffix == '.gz' else raw)
    if supplemental_nodes is not None:
        value['witness']['state'] = sorted(set(value['witness']['state']) | set(json.loads(supplemental_nodes.read_text())))
    accesses = json.loads(accesses_path.read_text())
    owners = {keccak(bytes.fromhex(a['address'][2:])).hex(): a['address'] for a in accesses}
    result = dict(schema='keth-reference-checkpoint-completion-v1', status='running',
                  source_sha256=digest(source), access_list_sha256=digest(accesses_path),
                  binary_sha256=digest(binary), probe_binary_sha256=digest(probe_binary) if probe_binary else None,
                  supplemental_nodes_sha256=digest(supplemental_nodes) if supplemental_nodes else None,
                  endpoint=endpoint, attempts=[], cairo_execution_proved=False)
    try:
        for index in range(attempts):
            directory = out / f'attempt-{index + 1}'
            directory.mkdir()
            input_path, output_path = directory / 'input.json', directory / 'result.json'
            write_new(input_path, value)
            run = subprocess.run([str(binary.resolve()), '--input', str(input_path), '--output', str(output_path),
                                  '--access-list', str(accesses_path.resolve()), '--checkpoints', str(directory / 'checkpoints.json')],
                                 capture_output=True, text=True)
            (directory / 'run.log').write_text(run.stdout + run.stderr)
            receipt = json.loads(output_path.read_text())
            entry = dict(attempt=index + 1, input_sha256=digest(input_path), result_sha256=digest(output_path),
                         error=receipt.get('error'), returncode=run.returncode)
            result['attempts'].append(entry)
            print(json.dumps(entry), flush=True)
            if run.returncode == 0:
                checkpoints = json.loads((directory / 'checkpoints.json').read_text())
                if not receipt['offline_execution_checked'] or not checkpoints['complete_reference_execution']:
                    raise ValueError('reference/checkpoints did not qualify')
                result.update(status='qualified', qualified_directory=str(directory),
                              final_input_sha256=digest(input_path), checkpoints_sha256=digest(directory / 'checkpoints.json'))
                break
            match = MISSING.search(receipt.get('error', ''))
            if match is None:
                raise ValueError('reference failed for a reason other than missing sibling nodes')
            if endpoint is None or probe_binary is None:
                raise ValueError('offline checkpoint witness still lacks a required sibling node')
            missing, owner, encoded_path = match.groups()
            if owner not in owners:
                raise ValueError('missing sibling owner is outside the authenticated candidate accounts')
            nibbles = bytes.fromhex(encoded_path)
            if not nibbles or any(n > 15 for n in nibbles) or len(nibbles) > 7:
                raise ValueError('missing path outside the bounded public prefix search')
            prefix = ''.join(format(n, 'x') for n in nibbles)
            probe_path = directory / 'prefix-probe.json'
            subprocess.run([str(probe_binary.resolve()), '--prefix', prefix, '--output', str(probe_path)], check=True)
            probe = json.loads(probe_path.read_text())
            key = probe['storage_key']
            if not keccak(bytes.fromhex(key[2:])).hex().startswith(prefix):
                raise ValueError('prefix probe did not match its claimed secure path')
            address = owners[owner]
            parent = value['witness']['headers'][0]
            nodes = set(value['witness']['state'])
            target_found = False
            for label, header in (('pre', parent), ('post', value['block'])):
                response = rpc(endpoint, 'eth_getProof', [address, [key], header['number']])
                write_new(directory / (label + '-sibling-proof.json'), response)
                verify_account(header['stateRoot'], address, response['result'])
                if [int(p['key'], 16) for p in response['result']['storageProof']] != [int(key, 16)]:
                    raise ValueError('sibling query returned a different storage key')
                incoming = response['result']['accountProof'] + [n for s in response['result']['storageProof'] for n in s['proof']]
                target_found |= any(keccak(bytes.fromhex(n[2:])).hex() == missing for n in incoming)
                nodes.update(incoming)
            if not target_found:
                raise ValueError('authenticated sibling queries did not expose the required exact node hash')
            value['witness']['state'] = sorted(nodes)
        else:
            raise ValueError('bounded checkpoint completion attempt budget exhausted')
    except Exception as error:
        result.update(status='failed', error=str(error))
        raise
    finally:
        write_new(out / 'completion.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'input', 'access-list', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--probe-binary', type=Path)
    parser.add_argument('--endpoint')
    parser.add_argument('--supplemental-nodes', type=Path)
    parser.add_argument('--attempts', type=int, default=32)
    args = parser.parse_args()
    if not 1 <= args.attempts <= 64:
        parser.error('use 1-64 completion attempts')
    if bool(args.endpoint) != bool(args.probe_binary) or (not args.endpoint and not args.supplemental_nodes):
        parser.error('supply endpoint and probe-binary together, or use supplemental-nodes for offline replay')
    print(json.dumps(complete(args.binary, args.probe_binary, args.input, args.access_list, args.endpoint,
                              args.out, args.attempts, args.supplemental_nodes), indent=2))

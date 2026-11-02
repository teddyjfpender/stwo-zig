#!/usr/bin/env python3
"""Reverify retained bundle proofs against a trusted benchmark manifest.

The manifest is the expected statement registry, not an Ethereum light client.
This command never promotes the workload to an on-chain block certificate.
"""
from __future__ import annotations

import argparse
import bz2
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

if __package__:
    from .bridge import digest, write_new
else:
    from bridge import digest, write_new

CANONICAL_SECURITY = {'pow_bits': 26, 'fri_config': {'n_queries': 70, 'log_blowup_factor': 1,
    'log_last_layer_degree_bound': 0, 'fold_step': 1}, 'min_lifting_log_size': 0}


def expected_specs(transactions: int, chunk_size: int):
    if type(transactions) is not int or transactions < 1:
        raise ValueError('the pinned consistency program requires at least one transaction')
    if type(chunk_size) is not int or chunk_size < 1:
        raise ValueError('invalid transaction chunk size')
    return [('init', [])] + [
        ('body', [i, min(chunk_size, transactions-i)]) for i in range(0, transactions, chunk_size)
    ] + [('teardown', [])] + [('mpt_diff', [i]) for i in range(16)] + [('aggregator', [])]


def state_root_commitment_limbs(root: str) -> list[int]:
    """Keth publishes Blake2s(root bytes), as little-endian Uint256 limbs."""
    if not isinstance(root, str) or not root.startswith('0x') or len(root) != 66:
        raise ValueError('invalid state root')
    raw = bytes.fromhex(root[2:])
    if len(raw) != 32:
        raise ValueError('invalid state root')
    commitment = hashlib.blake2s(raw).digest()
    return [int.from_bytes(commitment[:16], 'little'), int.from_bytes(commitment[16:], 'little')]


def check_manifest(manifest: dict, *, prefix: bool = False) -> None:
    if not prefix and manifest['status'] != 'qualified-segmented-keth-block-workload':
        raise ValueError('bundle has not qualified')
    segments = manifest['segments']
    expected = expected_specs(manifest['workload']['transactions'], manifest['body_chunk_size'])
    if prefix:
        expected = expected[:len(segments)]
    if (not segments and not prefix) or [(s['role'], s['indices']) for s in segments] != expected:
        raise ValueError('missing, reordered or duplicated block segments')
    joined = []
    init_output = None
    body_commitment = None
    state_diff = None
    previous_trie_diff = None
    for segment in segments:
        if any(type(index) is not int for index in segment['indices']):
            raise ValueError('noncanonical segment indices')
        name = segment['role'] + ''.join('_' + str(i) for i in segment['indices'])
        if segment['name'] != name:
            raise ValueError('unexpected segment name')
        if segment['status'] != 'qualified' or segment['public_output_matches'] is not True:
            raise ValueError('unqualified segment')
        statement = segment['public_statement']
        if statement['program_len'] != segment['conversion']['compiled_program_cells_checked']:
            raise ValueError('compiled program length mismatch')
        if statement['output_len'] != len(segment['expected_public_output']):
            raise ValueError('output length mismatch')
        if statement['program_root_blake2s'] != manifest['program_roots_blake2s'][segment['role']]:
            raise ValueError('unexpected program identity')
        public = segment['expected_public_output']
        if any(type(value) is not int or not 0 <= value < 2**251 + 17 * 2**192 + 1 for value in public):
            raise ValueError('noncanonical public output field element')
        if segment['role'] == 'init':
            if len(public) != 4:
                raise ValueError('invalid init output')
            init_output = public
            body_commitment = public[:2]
        elif segment['role'] == 'body':
            if len(public) != 4 or public[:2] != body_commitment:
                raise ValueError('transaction commitment chain mismatch')
            body_commitment = public[2:]
        elif segment['role'] == 'teardown':
            if len(public) != 6 or public[:2] != init_output[2:] or public[2:4] != body_commitment:
                raise ValueError('teardown commitment chain mismatch')
            state_diff = public[4:]
        if segment['role'] == 'mpt_diff':
            roots = state_root_commitment_limbs(manifest['workload']['pre_state_root']) + state_root_commitment_limbs(manifest['workload']['post_state_root'])
            if len(public) != 9 or public[2] != segment['indices'][0] or public[3:7] != roots:
                raise ValueError('verified trie outputs do not bind expected pre/post state roots')
            if previous_trie_diff is not None and public[:2] != previous_trie_diff:
                raise ValueError('trie diff commitment chain mismatch')
            previous_trie_diff = public[-2:]
            if segment['indices'] == [15] and previous_trie_diff != state_diff:
                raise ValueError('trie diff does not match execution state diff')
        if segment['role'] == 'aggregator':
            if public != joined:
                raise ValueError('consistency proof does not bind all verified outputs')
        else:
            joined.extend([len(public)+2, manifest['program_poseidon_hashes'][segment['role']+'_compiled.json'], *public])


def verify(bundle: Path, oracle: Path, *, prefix: bool = False) -> dict:
    manifest_file = bundle / 'bundle-results.json'
    manifest = json.loads(manifest_file.read_text())
    if prefix:
        # Internal resume path. This receipt explicitly qualifies only a prefix.
        kept = []
        for segment in manifest['segments']:
            if segment['status'] != 'qualified':
                break
            kept.append(segment)
        if any(s['status'] == 'qualified' for s in manifest['segments'][len(kept):]):
            raise ValueError('qualified segments are not a contiguous prefix')
        roots = {}
        for segment in kept:
            roots.setdefault(segment['role'], segment['public_statement']['program_root_blake2s'])
        manifest = dict(manifest, segments=kept, program_roots_blake2s=roots)
    check_manifest(manifest, prefix=prefix)
    checked = []
    with tempfile.TemporaryDirectory(prefix='keth-bundle-verify-') as temporary:
        work = Path(temporary)
        proof = work / 'proof.json'
        for segment in manifest['segments']:
            compressed = bundle / segment['name'] / 'proofs/trial-1.proof.json.bz2'
            if digest(compressed) != segment['compressed_proof_sha256']:
                raise ValueError('retained proof hash mismatch')
            with bz2.open(compressed, 'rb') as inp, proof.open('wb') as out:
                shutil.copyfileobj(inp, out)
            if digest(proof) != segment['trial']['proof_sha256']:
                raise ValueError('decompressed proof hash mismatch')
            if json.loads(proof.read_text())['stark_proof']['config'] != CANONICAL_SECURITY:
                raise ValueError('proof does not use canonical security parameters')
            for command, extra, target in (
                ('verify', ['--channel', 'blake2s'], work / 'verdict.json'),
                ('inspect-blake2s-proof-public-output', [], work / 'output.json'),
                ('inspect-blake2s-proof-public-statement', [], work / 'statement.json'),
            ):
                target.unlink(missing_ok=True)
                subprocess.run([str(oracle.resolve()), command, '--proof', str(proof),
                                '--proof-format', 'json', *extra, '--result', str(target)], check=True)
            verdict = json.loads((work / 'verdict.json').read_text())
            if verdict['verified'] is not True or verdict['proof_sha256'] != segment['trial']['proof_sha256']:
                raise ValueError('official verifier did not accept exact proof bytes')
            output = [int(v, 16) for v in json.loads((work / 'output.json').read_text())]
            if output != segment['expected_public_output']:
                raise ValueError('verified public output mismatch')
            if json.loads((work / 'statement.json').read_text()) != segment['public_statement']:
                raise ValueError('verified public statement mismatch')
            checked.append({'segment': segment['name'], 'proof_sha256': verdict['proof_sha256']})
    return {'schema': 'keth-block-bundle-reverification-v1', 'verified': True,
            'scope': 'verified-prefix-only' if prefix else 'complete-bundle',
            'manifest_sha256': digest(manifest_file), 'oracle_sha256': digest(oracle),
            'proof_count': len(checked), 'proofs': checked,
            'claims': manifest['claims']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    receipt = verify(args.bundle, args.oracle)
    write_new(args.out, receipt)
    print(json.dumps({'verified': receipt['verified'], 'proof_count': receipt['proof_count']}))

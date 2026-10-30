"""Verify every STARK and the public block commitments of an OP execution bundle.

Trusted inputs are compiled bytecode, the official verifier binary, the expected
block hash and parent state root. Merkle checks on the public body and final
MessagePasser account run in this verifier. There is no recursive or L1 proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

import rlp
from eth_hash.auto import keccak

from .bridge import digest, write_new
from .check_fixture import header_hash
from .op_encoding import op_transaction_bytes, receipt_bytes, ordered_trie_root
from .proof_statement import DOMAIN, PRIME, assert_parameters, assert_program, limbs, program_claim
from .state_proofs import lookup_nodes

MESSAGE_PASSER = '0x4200000000000000000000000000000000000016'


def root_from_limbs(values):
    if len(values) != 2 or any(not 0 <= v < 2**128 for v in values):
        raise ValueError('noncanonical root limbs')
    return '0x' + b''.join(v.to_bytes(16, 'little') for v in values).hex()



PARTITION_DOMAIN = 0x6f705f657865637574696f6e5f706172746974696f6e5f7631


def join_partitioned(outputs):
    if len(outputs) != 3:
        raise ValueError('three phases required')
    auth, body, update = outputs
    for phase, output in enumerate(outputs):
        if (len(output) != 22 or any(not 0 <= v < PRIME for v in output)
                or output[:2] != [PARTITION_DOMAIN, phase] or output[2:14] != body[2:14]):
            raise ValueError('phase identity mismatch')
    empty = limbs('0x' + keccak(b'').hex())
    if (auth[14:18] != [0, *empty, 0] or update[14:18] != [0, *empty, 0]
            or auth[20:22] != [0, 0] or update[18:20] != [0, 0]
            or auth[18:20] != body[18:20] or body[20:22] != update[20:22]):
        raise ValueError('state authentication, execution or root-diff commitment mismatch')
    result = [DOMAIN, *body[2:18]]
    if result[1] == 0:
        if result[6:8] != empty:
            raise ValueError('system input must be empty')
        result[6:8] = [0, 0]
    return result


def verify(manifest_path: Path, compiled_path: Path, oracle: Path, block_hash: str, parent_root: str):
    manifest = json.loads(manifest_path.read_text())
    compiled_bytes = compiled_path.read_bytes()
    compiled = json.loads(compiled_bytes)
    compiled_digest, oracle_digest = hashlib.sha256(compiled_bytes).hexdigest(), digest(oracle)
    block, parent = manifest['block'], manifest['parent_header']
    if (header_hash(block) != block_hash or block['hash'] != block_hash
            or header_hash(parent) != block['parentHash'] or parent['stateRoot'] != parent_root):
        raise ValueError('block or trusted parent identity mismatch')
    transactions, receipts = block['transactions'], manifest['receipts']
    children = manifest['proofs']
    if (len(receipts) != len(transactions) or len(children) != len(transactions) + 1
            or not transactions or block.get('withdrawals') != [] or block.get('uncles') != []):
        raise ValueError('incomplete proof/body coverage or unsupported block body')
    raw_transactions = [op_transaction_bytes(tx) for tx in transactions]
    raw_receipts = [receipt_bytes({**receipt, 'type': tx['type'], 'logs': receipt['logs'] or []})
                    for tx, receipt in zip(transactions, receipts)]
    if (ordered_trie_root(raw_transactions) != block['transactionsRoot']
            or ordered_trie_root(raw_receipts) != block['receiptsRoot']):
        raise ValueError('public transaction/receipt trie root mismatch')
    bloom = 0
    for receipt in receipts:
        bloom |= int(receipt['logsBloom'], 16)
    if bloom != int(block['logsBloom'], 16):
        raise ValueError('block logs bloom mismatch')
    base = manifest_path.resolve().parent
    current, cumulative, footprint = parent_root, 0, 0
    gas_limit = int(block['gasLimit'], 16)
    verified = []
    with tempfile.TemporaryDirectory(prefix='keth-op-verify-') as temporary:
        temporary = Path(temporary)
        for number, child in enumerate(children):
            partitioned = 'phases' in child
            parts = child['phases'] if partitioned else [child]
            if len(parts) != (3 if partitioned else 1):
                raise ValueError('incomplete execution proof phases')
            outputs, hashes = [], []
            for phase, part in enumerate(parts):
                source = (base / part['proof']).resolve()
                source.relative_to(base)
                if not source.is_file() or source.stat().st_size > 512 * 1024**2:
                    raise ValueError('proof missing or exceeds verifier admission bound')
                proof = temporary / 'proof.json'
                shutil.copyfile(source, proof)
                proof_hash = digest(proof)
                if proof_hash != part['proof_sha256']:
                    raise ValueError('proof byte identity mismatch')
                assert_parameters(json.loads(proof.read_text()))
                verdict_path = temporary / f'{number}-{phase}-verdict.json'
                subprocess.run([str(oracle.resolve()), 'verify', '--proof', str(proof), '--channel', 'blake2s',
                                '--proof-format', 'json', '--result', str(verdict_path)], check=True, timeout=300,
                               stdout=subprocess.DEVNULL)
                verdict = json.loads(verdict_path.read_text())
                if (not verdict['verified'] or verdict['proof_sha256'] != proof_hash
                        or verdict['stwo_cairo_revision'] != '82f21252a68ec006d73e299f5bf1ce6d4db0ee78'
                        or verdict['stwo_revision'] != '7b211edde786775016ef3eecb837a6240d8fe792'):
                    raise ValueError('independent verifier did not accept the exact pinned proof')
                for kind in ('statement', 'output'):
                    destination = temporary / f'{number}-{phase}-{kind}.json'
                    subprocess.run([str(oracle.resolve()), f'inspect-blake2s-proof-public-{kind}', '--proof', str(proof),
                                    '--proof-format', 'json', '--result', str(destination)], check=True, timeout=300,
                                   stdout=subprocess.DEVNULL)
                statement = json.loads((temporary / f'{number}-{phase}-statement.json').read_text())
                assert_program(statement, compiled)
                output = [int(v, 16) for v in json.loads((temporary / f'{number}-{phase}-output.json').read_text())]
                if statement['output_len'] != len(output) or any(not 0 <= v < PRIME for v in output):
                    raise ValueError('invalid public output width or field')
                if digest(proof) != proof_hash:
                    raise ValueError('private verifier proof changed')
                outputs.append(output)
                hashes.append(proof_hash)
            output = join_partitioned(outputs) if partitioned else outputs[0]
            if (len(output) != 17
                    or any(not 0 <= v < PRIME for v in output) or output[0] != DOMAIN
                    or output[2] != 10 or output[3:5] != limbs(block_hash)
                    or root_from_limbs(output[8:10]) != current):
                raise ValueError('execution statement identity or root continuity mismatch')
            if number == 0:
                if (output[1] != 0 or output[5:8] != [0, 0, 0] or output[12:14] != [0, 0]
                        or output[14:16] != limbs('0x' + keccak(b'').hex()) or output[16] != 0):
                    raise ValueError('invalid system-call statement')
            else:
                index = number - 1
                raw, receipt = raw_transactions[index], receipts[index]
                action = 1 if raw[0] == 0x7e else 2
                if (output[1] != action or output[5] != index
                        or output[6:8] != limbs('0x' + keccak(raw).hex())
                        or output[14:16] != limbs('0x' + keccak(raw_receipts[index]).hex())
                        or output[12] != cumulative or output[13] > gas_limit - cumulative):
                    raise ValueError('transaction, receipt or gas statement mismatch')
                cumulative += output[13]
                footprint += output[16]
                if (cumulative != int(receipt['cumulativeGasUsed'], 16) or footprint > gas_limit
                        or (action == 1 and output[16] != 0)):
                    raise ValueError('cumulative gas or DA footprint mismatch')
            current = root_from_limbs(output[10:12])
            verified.append(dict(proof_sha256=hashes, public_output=output, phase_outputs=outputs))
    if (current != block['stateRoot'] or cumulative != int(block['gasUsed'], 16)
            or footprint != int(block['blobGasUsed'], 16)):
        raise ValueError('final state, gas or DA commitment mismatch')
    nodes = {keccak(bytes.fromhex(raw[2:])): bytes.fromhex(raw[2:]) for raw in manifest['final_state_nodes']}
    leaf = lookup_nodes(bytes.fromhex(current[2:]), keccak(bytes.fromhex(MESSAGE_PASSER[2:])), nodes)
    account = rlp.decode(leaf, strict=True) if leaf else None
    if (not isinstance(account, list) or len(account) != 4 or len(account[2]) != 32
            or '0x' + account[2].hex() != block['withdrawalsRoot']):
        raise ValueError('final MessagePasser storage root mismatch')
    if digest(compiled_path) != compiled_digest or digest(oracle) != oracle_digest:
        raise ValueError('trusted verification dependencies changed')
    return dict(schema='keth-op-execution-bundle-verification-v1', status='qualified-op-execution-bundle',
                block_hash=block_hash, parent_state_root=parent_root, final_state_root=current,
                verified_proofs=verified, program_claim_words=program_claim(compiled),
                compiled_sha256=compiled_digest, official_verifier_sha256=oracle_digest,
                transactions=len(transactions), gas_used=cumulative, da_footprint=footprint,
                op_block_execution_proved=True, cairo_state_roots_bound=True,
                public_body_and_message_passer_checked_on_host=True,
                recursive_aggregation_proved=False, derivation_proved=False, l1_verifier_compatible=False)


if __name__ == '__main__':
    import keth_types.patches
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'compiled', 'oracle', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--block-hash', required=True)
    parser.add_argument('--parent-state-root', required=True)
    args = parser.parse_args()
    result = verify(args.manifest, args.compiled, args.oracle, args.block_hash, args.parent_state_root)
    write_new(args.out, result)
    print(json.dumps(result, indent=2))

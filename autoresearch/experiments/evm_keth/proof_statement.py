"""Bind verified Cairo public program memory to trusted compiled bytecode."""
from __future__ import annotations

import hashlib
import struct

PRIME = 2**251 + 17 * 2**192 + 1
DOMAIN = int('6f705f657865637574696f6e5f7472616e736974696f6e5f7631', 16)
CANONICAL_CONFIG = dict(pow_bits=26,
    fri_config=dict(log_blowup_factor=1, log_last_layer_degree_bound=0, n_queries=70, fold_step=1),
    min_lifting_log_size=0)


def program_claim(compiled: dict) -> dict:
    digest = hashlib.sha256()
    if not isinstance(compiled.get('data'), list) or not compiled['data']:
        raise ValueError('compiled program contains no bytecode')
    for cell in compiled['data']:
        value = int(cell, 0) if isinstance(cell, str) else cell
        if type(value) is not int or not 0 <= value < PRIME:
            raise ValueError('noncanonical program cell')
        digest.update(struct.pack('<28I', *((value >> (9 * i)) & 511 for i in range(28))))
    return dict(count=len(compiled['data']) * 28, sha256_le=digest.hexdigest())


def assert_program(statement: dict, compiled: dict):
    if (statement['program_len'] != len(compiled['data'])
            or statement['program_claim_words'] != program_claim(compiled)):
        raise ValueError('proof program differs from trusted compiled bytecode')


def assert_parameters(proof: dict):
    if (proof['stark_proof']['config'] != CANONICAL_CONFIG or proof['channel_salt'] != 0
            or proof['preprocessed_trace_variant'] not in ('canonical_small', 'canonical')):
        raise ValueError('proof does not use the qualified canonical protocol')


def limbs(value: str) -> list[int]:
    raw = bytes.fromhex(value.removeprefix('0x'))
    if len(raw) != 32:
        raise ValueError('expected 32-byte commitment')
    return [int.from_bytes(raw[i:i+16], 'little') for i in (0, 16)]

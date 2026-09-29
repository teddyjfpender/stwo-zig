#!/usr/bin/env python3
"""Compile old/new native writers; compare every channel and untouched row.

Deterministic stateless deduction/table providers test emission and tiling, not
cryptographic deduction semantics. Full official proofs qualify those separately.
"""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import random
import re
import struct
import subprocess
import tempfile

U32 = C.c_uint32
Words = C.POINTER(U32)
Limb = C.CFUNCTYPE(U32, C.c_void_p, U32, U32, U32)
Deduce = C.CFUNCTYPE(C.c_int, C.c_void_p, U32, Words, C.c_size_t, Words, C.c_size_t)
Batch = C.CFUNCTYPE(C.c_int, C.c_void_p, U32, Words, C.c_size_t, C.c_size_t,
                    Words, C.c_size_t, C.c_size_t, C.c_size_t)


class Column(C.Structure):
    _fields_ = [('ptr', Words), ('len', C.c_size_t)]


class Run(C.Structure):
    _fields_ = [('input_columns', C.POINTER(Column)), ('output_columns', C.POINTER(Column)),
                ('lookup_words', Words), ('sub_words', Words), ('registers', Words),
                ('deduce_args', Words), ('row_count', C.c_size_t), ('start', C.c_size_t),
                ('end', C.c_size_t), ('bridge_context', C.c_void_p), ('table_limb_fn', Limb),
                ('deduce_fn', Deduce), ('deduce_batch_fn', Batch)]


def programs(path):
    data = path.read_bytes()
    assert data[:8] == b'STWZWIT\0'
    version, count = struct.unpack_from('<II', data, 8)
    assert version == 1
    offset = 16
    for _ in range(count):
        length, padding, regs, inputs, outputs, mult, lookups, subs, inst_count, _ = struct.unpack_from('<HH7IQ', data, offset)
        assert padding == 0 and mult == 0
        offset += 40
        name = data[offset:offset + length].decode()
        offset += length
        insts = [struct.unpack_from('<BBHIII', data, offset + i * 16) for i in range(inst_count)]
        offset += inst_count * 16
        args = pending = 0
        for op, _, _, _, _, _ in insts:
            if op == 26:
                pending += 1
            if op == 27:
                args, pending = max(args, pending), 0
        yield name, regs, inputs, outputs, lookups, subs, max(1, args)
    assert offset == len(data)


def deduction(selector, arguments, output_count):
    seed = (selector * 65537 + sum((i + 1) * value for i, value in enumerate(arguments))) % 0x7fffffff
    return [(seed + 8191 * (index + 1)) % 0x7fffffff for index in range(output_count)]


@Limb
def limb(_, table, row, index):
    return (table * 13 + row * 19 + index * 23) & 511


@Deduce
def deduce(_, selector, arguments, n_args, outputs, n_outputs):
    values = deduction(selector, arguments[:n_args], n_outputs)
    for i, value in enumerate(values):
        outputs[i] = value
    return 0


@Batch
def batch(_, selector, arguments, n_args, argument_stride, outputs, n_outputs, output_stride, rows):
    for row in range(rows):
        values = deduction(selector, arguments[row * argument_stride:row * argument_stride + n_args], n_outputs)
        for i, value in enumerate(values):
            outputs[row * output_stride + i] = value
    return 0


def evaluate(fn, shape, rows, start, end, inputs):
    _, registers, n_inputs, n_outputs, n_lookups, n_subs, args = shape
    sentinel = 0xdeadbeef
    output = [(U32 * rows)(*([sentinel] * rows)) for _ in range(n_outputs)]
    lookup = (U32 * (rows * n_lookups))(*([sentinel] * (rows * n_lookups)))
    sub = (U32 * (rows * n_subs))(*([sentinel] * (rows * n_subs)))
    inp_view = (Column * n_inputs)(*[Column(v, rows) for v in inputs])
    out_view = (Column * n_outputs)(*[Column(v, rows) for v in output])
    scratch, arguments = (U32 * registers)(), (U32 * args)()
    run = Run(inp_view, out_view, lookup, sub, scratch, arguments, rows, start, end, None, limb, deduce, batch)
    fn.argtypes, fn.restype = [C.POINTER(Run)], C.c_int
    assert fn(C.byref(run)) == 0
    return [list(v) for v in output], list(lookup), list(sub)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', type=Path, required=True)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    shapes = list(programs(root / 'vectors/cairo/official/witness_programs_v1.bin'))
    random_source = random.Random(20260928)
    with tempfile.TemporaryDirectory(prefix='cairo-native-tiles-') as directory:
        libraries = []
        source_hashes = []
        for variant, source_dir in enumerate([args.before, args.after]):
            sources = [source_dir / (shape[0] + '.c') for shape in shapes]
            digest = hashlib.sha256()
            for source in sources:
                digest.update(source.name.encode() + b'\0' + source.read_bytes())
            source_hashes.append(digest.hexdigest())
            library = Path(directory) / f'variant-{variant}.dylib'
            subprocess.run([str(args.zig), 'cc', '-O3', '-shared', '-fPIC',
                            *map(str, sources), '-o', str(library)], check=True)
            libraries.append(C.CDLL(str(library)))
        cases = 0
        for shape in shapes:
            name = shape[0]
            symbol = re.search(r'int (cairo_witness_[0-9a-f]+)\(', (args.before / (name + '.c')).read_text())[1]
            functions = [getattr(library, symbol) for library in libraries]
            # Full and partial ranges cover empty execution, a short tail, and
            # multiple tile boundaries; sentinels detect out-of-range stores.
            for rows, start, end in [(1, 0, 1), (39, 3, 38), (67, 0, 67), (39, 7, 7)]:
                inputs = [(U32 * rows)(*[random_source.randrange(0x7fffffff) for _ in range(rows)]) for _ in range(shape[2])]
                results = [evaluate(fn, shape, rows, start, end, inputs) for fn in functions]
                if results[0] != results[1]:
                    raise AssertionError(f'{name}: parity failed for {(rows, start, end)}')
                cases += 1
        receipt = {'schema': 'stwo-zig-cairo-native-row-tile-parity-v1', 'status': 'qualified',
                   'programs': len(shapes), 'cases': cases, 'source_sha256': source_hashes,
                   'coverage': 'all output/lookup/sub channels, untouched sentinels, empty/full/partial ranges with tile tails',
                   'providers': 'deterministic stateless synthetic providers; official proof verification required separately'}
        args.out.write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(receipt))


if __name__ == '__main__':
    main()

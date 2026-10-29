#!/usr/bin/env python3
"""Compile or trace owned OP Cairo modules using the pinned Keth runtime.

Run with Keth's Python. The OP overlay does not change its clean source pin or
admit OP fixtures through the Ethereum-only benchmark driver.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time

if __package__:
    from .bridge import PINS, authenticate, digest, write_new
else:
    from bridge import PINS, authenticate, digest, write_new


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keth-checkout', type=Path, required=True)
    sub = parser.add_subparsers(dest='action', required=True)
    compiler = sub.add_parser('compile')
    compiler.add_argument('--source', type=Path, required=True)
    compiler.add_argument('--out', type=Path, required=True)
    runner = sub.add_parser('trace')
    runner.add_argument('--compiled', type=Path, required=True)
    runner.add_argument('--input', type=Path, required=True)
    runner.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    identity = authenticate(args.keth_checkout.resolve(), PINS['keth'])
    if args.out.exists():
        parser.error('destination must be new')
    import keth_types.patches  # Required before importing EELS/Keth state types.
    started = time.monotonic()
    if args.action == 'compile':
        from dotenv import load_dotenv
        from cairo_addons.compiler import cairo_compile, implement_hints
        load_dotenv(args.keth_checkout / '.env')
        overlay = Path(__file__).resolve().parent / 'cairo'
        args.source.resolve().relative_to(overlay)
        os.environ['CAIRO_PATH'] = str(overlay) + ':' + os.environ.get('CAIRO_PATH', '')
        hashes = {str(p.relative_to(overlay)): digest(p) for p in overlay.rglob('*.cairo')}
        program = cairo_compile(args.source.resolve(), proof_mode=True)
        program.hints = implement_hints(program)
        write_new(args.out, program.Schema().dump(program))
        if hashes != {str(p.relative_to(overlay)): digest(p) for p in overlay.rglob('*.cairo')}:
            raise ValueError('overlay source changed during compilation')
        result = dict(source_files_sha256=hashes, compiled_cells=len(program.data), compiled_sha256=digest(args.out))
    else:
        from cairo_addons.rust_bindings.vm import generate_trace
        compiled_hash, input_hash = digest(args.compiled), digest(args.input)
        generate_trace(entrypoint='main', program_input=json.loads(args.input.read_text()),
                       compiled_program_path=str(args.compiled.resolve()), output_path=args.out,
                       output_trace_components=False, cairo_pie=False)
        if digest(args.compiled) != compiled_hash or digest(args.input) != input_hash:
            raise ValueError('compiled program or input changed during tracing')
        result = dict(compiled_sha256=compiled_hash, input_sha256=input_hash, trace_sha256=digest(args.out),
                      public_output=[int(x) for x in args.out.with_name(args.out.name + '.run_output.txt').read_text().split()])
    if authenticate(args.keth_checkout, PINS['keth']) != identity:
        raise ValueError('pinned Keth source changed')
    result.update(schema='keth-op-cairo-' + args.action + '-v1', keth_source=identity,
                  elapsed_seconds=time.monotonic() - started, op_block_execution_proved=False,
                  op_derivation_proved=False)
    write_new(args.out.with_name(args.out.name + '.receipt.json'), result)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Export Keth's actual Fibonacci sample as a Cairo PIE (transport test only).

Run with Python 3.10 and cairo-lang==0.13.5. No Keth Rust hints or EVM state
transition are exercised by this smoke program.
"""
from __future__ import annotations

import argparse
from importlib.metadata import version
from pathlib import Path
import platform

from bridge import PINS, authenticate, digest, write_new


def export(keth: Path, out: Path) -> dict:
    if platform.python_version_tuple()[:2] != ("3", "10") or version("cairo-lang") != "0.13.5":
        raise ValueError("use Python 3.10 with cairo-lang==0.13.5 for this fixture")
    from starkware.cairo.lang.cairo_constants import DEFAULT_PRIME
    from starkware.cairo.lang.compiler.cairo_compile import compile_cairo_files
    from starkware.cairo.lang.vm.cairo_runner import CairoRunner

    identity = authenticate(keth, PINS["keth"])
    source = keth / "cairo/tests/programs/fibonacci.cairo"
    source_hash = digest(source)
    program = compile_cairo_files([str(source)], prime=DEFAULT_PRIME)
    runner = CairoRunner(program=program, layout="small", proof_mode=False)
    runner.initialize_segments()
    end = runner.initialize_main_entrypoint()
    runner.initialize_vm(hint_locals={"program_input": [1, 1, 10]})
    runner.run_until_pc(end)
    runner.end_run()
    runner.read_return_values()
    # The independently expected sample output is 144.
    output = runner.builtin_runners["output_builtin"].base
    if runner.vm_memory[output] != 144:
        raise ValueError("Keth Fibonacci sample returned an unexpected result")
    out.mkdir(parents=True, exist_ok=False)
    pie = out / "keth_fibonacci.pie.zip"
    runner.get_cairo_pie().to_file(pie)
    if digest(source) != source_hash or authenticate(keth, PINS["keth"]) != identity:
        raise ValueError("Keth sample source changed during export")
    result = {"schema": "stwo-zig-keth-smoke-pie-v1", "source": identity,
              "source_path": "cairo/tests/programs/fibonacci.cairo",
              "source_sha256": source_hash, "python": platform.python_version(),
              "cairo_lang": version("cairo-lang"), "arguments": [1, 1, 10],
              "expected_output": [144], "pie_sha256": digest(pie),
              "scope": "keth-fibonacci-pie-transport-only"}
    write_new(out / "provenance.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keth-checkout", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    export(args.keth_checkout, args.out)

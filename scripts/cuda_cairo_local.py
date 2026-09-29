#!/usr/bin/env python3
"""Local CUDA-source compile/parity checks on CuMetal; never NVIDIA evidence."""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import random
import signal
from pathlib import Path
import subprocess
import sys
import time

from cuda_build_lib.product_selection import validate_aot_manifest

ROOT = Path(__file__).resolve().parents[1]
PIN = "e74b377942f9d2db0f2dde14c5a1b51a9c678692"
PATCH = ROOT / "conformance/cuda-cumetal-cairo-v0.6-pointer-select.patch"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args: list[str], timeout: int, env: dict[str, str] | None = None) -> tuple[int, str]:
    process = subprocess.Popen(args, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout)
        return process.returncode, output
    except subprocess.TimeoutExpired as error:
        # Stop the compiler's complete child tree, including xcrun/metal. Killing
        # only cumetalc otherwise leaves long optimizer jobs running unobserved.
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate()
        return 124, output + "\nLocal compile/execute deadline exceeded\n"


def compile_entry(entry: dict, directory: Path, args: argparse.Namespace) -> dict:
    label = f"{entry['kind']}-{entry['cache_key']}"
    destination = args.out / label
    destination.mkdir(parents=True, exist_ok=True)
    source = (directory / entry["file"]).resolve()
    # Source-first executable compilation uses CuMetal's NVVM importer. This
    # main does not launch anything: translation and execution are distinct gates.
    harness = destination / "compile.cu"
    harness.write_text(f'#include "{source.as_posix()}"\nint main() {{ return 0; }}\n')
    started = time.monotonic()
    command = [str(args.compiler), "--cuda-clang", str(args.clang), str(harness),
               "-DSTWO_CUMETAL=1", "-o", str(destination / "compile")]
    if args.inline_threshold is not None:
        command += ["--cuda-inline-threshold", str(args.inline_threshold)]
    code, output = run(command, args.timeout)
    (destination / "compile.log").write_text(output)
    passed = code == 0 and (destination / "compile").is_file()
    result = {"label": entry["label"], "kernel": entry["kernel_name"], "kind": entry["kind"],
              "source_sha256": digest(source), "cache_key": entry["cache_key"], "exit_code": code,
              "compiled": passed, "device_executed": False, "elapsed_s": time.monotonic() - started,
              "diagnostic_sha256": hashlib.sha256(output.encode()).hexdigest()}
    (destination / "receipt.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{'PASS' if passed else 'FAIL'} compile {entry['label']}", flush=True)
    return result


def felt_fixtures(path: Path, inverse: bool = False) -> None:
    prime = (1 << 251) + 17 * (1 << 192) + 1
    rng = random.Random(0x5354574F)
    values = [0, 1, 2, prime - 1, prime - 2, prime // 2]
    values += [1 << bit for bit in (26, 27, 31, 32, 63, 64, 127, 128, 191, 192, 250)]
    values += [rng.randrange(prime) for _ in range(32)]
    def words(value: int) -> list[int]:
        return [(value >> (27 * limb)) & ((1 << 27) - 1) for limb in range(10)]
    if inverse:
        values = [value for value in values if value != 0]
    inputs = [word for value in values for word in words(value)]
    expected = [word for value in values for word in words(pow(value, prime-2 if inverse else 3, prime))]
    path.write_text(f"constexpr unsigned kFeltCount = {len(values)}u;\n" +
                    "constexpr unsigned kFeltInputs[] = {" + ",".join(f"{v}u" for v in inputs) + "};\n" +
                    "constexpr unsigned kFeltExpected[] = {" + ",".join(f"{v}u" for v in expected) + "};\n")


def air_fixtures(path: Path) -> None:
    prime = (1 << 31) - 1
    rng = random.Random(0x414952)
    def cmul(a, b):
        return ((a[0]*b[0]-a[1]*b[1]) % prime, (a[0]*b[1]+a[1]*b[0]) % prime)
    def qmul(a, b):
        low, high = cmul(a[:2], b[:2]), cmul(a[2:], b[2:])
        cross0, cross1 = cmul(a[:2], b[2:]), cmul(a[2:], b[:2])
        return [(low[0]+2*high[0]-high[1]) % prime, (low[1]+high[0]+2*high[1]) % prime,
                (cross0[0]+cross1[0]) % prime, (cross0[1]+cross1[1]) % prime]
    cases, expected = [], []
    for case, address in enumerate([0, 1, prime-1, prime-2] + [rng.randrange(prime) for _ in range(28)]):
        trace = [0, 1, prime-1, prime-2, 2, 1 << 30, rng.randrange(prime), rng.randrange(prime)]
        parameter = [rng.randrange(prime) for _ in range(4)]
        coefficients = [[rng.randrange(prime) for _ in range(4)] for _ in range(6)]
        denominator = [0, 1, prime-1, 7][case % 4]
        initial = [rng.randrange(prime) for _ in range(32)]
        arena = trace + [0,0,0,1,address] + parameter + [x for c in coefficients for x in c] + [denominator] + initial
        assert len(arena) == 74
        output = []
        for row, value in enumerate(trace):
            scalar = (value+address) % prime
            secure = [(scalar*x) % prime for x in parameter]
            roots = [secure, [(scalar+1)*x % prime for x in parameter], [scalar*scalar % prime,0,0,0],
                     [0]*4, [0]*4, [(x+y) % prime for x,y in zip(secure,[11,13,17,19])]]
            products = [qmul(root, coefficient) for root, coefficient in zip(roots, coefficients)]
            output.append([(initial[coord*8+row]+denominator*sum(x[coord] for x in products)) % prime for coord in range(4)])
        cases.append(arena)
        expected.append([output[row][coord] for coord in range(4) for row in range(8)])
    def array(name, values):
        return f"constexpr unsigned {name}[{len(values)}][{len(values[0])}] = {{\n" + ",\n".join("{"+",".join(f"{v}u" for v in row)+"}" for row in values) + "\n};\n"
    path.write_text(f"constexpr unsigned kAirCaseCount = {len(cases)}u;\n"+array("kAirCases",cases)+array("kAirExpected",expected))


def row_fixtures(path: Path) -> None:
    rng = random.Random(0x524F5753)
    mask = (1 << 32) - 1
    cases = [[0]*6, [1]*6, [mask]*6, [mask,0,1<<31,1,mask-1,7]]
    cases += [[rng.getrandbits(32) for _ in range(6)] for _ in range(28)]
    outputs, lookups, subs, counts = [], [], [], [0]*32
    def rotate(value, bits):
        return ((value >> bits) | (value << (32-bits))) & mask
    for a,b,c,d,m0,m1 in cases:
        columns, lookup, sub = [], [], []
        for round in range(70):
            a = (a+b+m0) & mask; d = rotate(d^a,16)
            c = (c+d) & mask; b = rotate(b^c,12)
            a = (a+b+m1) & mask; d = rotate(d^a,8)
            c = (c+d) & mask; b = rotate(b^c,7)
            if round == 0:
                first = a
            columns.extend((a,b,c,d));lookup.append(a);sub.append(d)
            counts[a & 31] += 1
        columns.append(a^first)
        outputs.append(columns);lookups.append(lookup);subs.append(sub)
    def array(name, values):
        return f'constexpr unsigned {name}[] = {{'+','.join(f'{v}u' for v in values)+'};\n'
    def transpose(values):
        return [values[row][col] for col in range(len(values[0])) for row in range(len(values))]
    path.write_text(f'constexpr unsigned kRowCount = {len(cases)}u;\n'+
        array('kRowInputs',transpose(cases))+array('kRowExpected',transpose(outputs))+
        array('kRowLookup',transpose(lookups))+array('kRowSub',transpose(subs))+array('kRowCounts',counts))


def execute(harness: str, kernel: str, marker: str, args: argparse.Namespace, inverse: bool = False, materialized: bool = False) -> dict:
    source = ROOT / "tests/cuda/cumetal" / harness
    target = args.out / (source.stem + ("_inverse" if inverse else "_materialized" if materialized else ""))
    extra = []
    dependencies = {
        "powers_execution.cu": [ROOT / "src/backends/cuda/native/constraints/powers.cu"],
        "active_feeds_execution.cu": [ROOT / "src/backends/cuda/native/witness/active_feeds.cu"],
    }.get(harness, [])
    if harness == "felt252_execution.cu":
        entries = json.loads((args.witness_dir / "aot_manifest.json").read_text())
        entry = next(entry for entry in entries if entry["label"] == ("partial_ec_mul_generic" if inverse else "cube_252"))
        fixtures = args.out / ("felt252_inverse_fixtures.cuh" if inverse else "felt252_fixtures.cuh")
        felt_fixtures(fixtures, inverse)
        dependencies = [args.witness_dir / entry["file"], fixtures]
        extra = [f'-DSTWO_CANONICAL_FELT_SOURCE="{args.witness_dir / entry["file"]}"',
                 f'-DSTWO_CANONICAL_FELT_FIXTURES="{fixtures}"']
        if inverse:
            extra += ["-DSTWO_FELT_INVERSE=1"]
    if harness == "parametric_air_execution.cu":
        directory = args.air_parity_dir / "materialized" if materialized else args.air_parity_dir
        generated = json.loads((directory / "receipt.json").read_text())
        kernel_source = directory / "kernel.cu"
        if generated["schema"] != "stwo-cairo-cuda-parametric-parity-fixture-v1" or generated["source_sha256"] != digest(kernel_source):
            raise ValueError("invalid generated AIR differential identity")
        kernel = generated["kernel"]
        fixtures = args.out / "air_fixtures.cuh"
        air_fixtures(fixtures)
        dependencies = [kernel_source, fixtures, ROOT / "src/integrations/cairo_cuda/eval_codegen_parity.zig"]
        extra = [f'-DSTWO_AIR_PARITY_SOURCE="{kernel_source}"', f'-DSTWO_AIR_PARITY_FIXTURES="{fixtures}"',
                 f'-DSTWO_AIR_PARITY_KERNEL={kernel}']
    if harness == 'row_chunks_execution.cu':
        generated = json.loads((args.row_parity_dir/'receipt.json').read_text())
        kernel_source = args.row_parity_dir/'kernel.cu'
        if generated['schema'] != 'stwo-cairo-cuda-row-parity-v1' or generated['source_sha256'] != digest(kernel_source):
            raise ValueError('invalid generated row differential identity')
        kernel = generated['kernel']
        fixtures = args.out/'row_fixtures.cuh'
        row_fixtures(fixtures)
        dependencies = [kernel_source,fixtures,ROOT/'src/tools/cairo_cuda_witness_aot/row_parity.zig',ROOT/'src/tools/cairo_cuda_witness_aot/row_chunks.zig']
        extra = [f'-DSTWO_ROW_PARITY_SOURCE="{kernel_source}"',f'-DSTWO_ROW_PARITY_FIXTURES="{fixtures}"',f'-DSTWO_ROW_PARITY_KERNEL={kernel}']
    code, output = run([str(args.compiler), "--cuda-clang", str(args.clang), "-DSTWO_CUMETAL=1", *extra,
                        str(source), "-o", str(target)], args.timeout)
    compile_output = output
    gpu = False
    accepted = False
    if code == 0 and target.is_file():
        env = dict(os.environ, CUMETAL_TRACE_GPU="1", CUMETAL_MSL_MATH_MODE="safe")
        code, output = run([str(target)], 60, env)
        lines = [line for line in output.splitlines() if line.startswith("CUMETAL_PROVENANCE")]
        gpu = any(kernel in line and "device=apple_gpu" in line and "launch_success=true" in line for line in lines)
        forbidden = any("source=cpu_fallback" in line or "source=stub" in line for line in lines)
        accepted = code == 0 and gpu and not forbidden and marker in output
    (args.out / f"{target.name}.log").write_text(compile_output + output)
    print(f"{'PASS' if accepted else 'FAIL'} numerical {source.stem}", flush=True)
    return {"harness": harness, "operation": "inverse" if inverse else "materialized" if materialized else "default", "source_sha256": digest(source), "passed": accepted,
            "source_dependencies": [{"name": path.name, "sha256": digest(path)} for path in dependencies],
            "apple_gpu_launch": gpu, "exit_code": code}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--clang", type=Path, required=True)
    parser.add_argument("--witness-dir", type=Path, required=True)
    parser.add_argument("--eval-dir", type=Path, required=True)
    parser.add_argument("--air-parity-dir", type=Path, required=True)
    parser.add_argument("--row-parity-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--only", help="Compile labels containing this text; receipt marks partial coverage")
    parser.add_argument("--retry-from", type=Path, help="Retry only failed entries in a previous receipt")
    parser.add_argument("--inline-threshold", type=int, help="CuMetal importer optimization, recorded in the receipt")
    args = parser.parse_args()
    if args.jobs < 1 or args.jobs > 8 or args.timeout < 1:
        parser.error("jobs must be 1..8 and timeout positive")
    for name in ("checkout", "compiler", "witness_dir", "eval_dir", "air_parity_dir", "row_parity_dir", "out"):
        setattr(args, name, getattr(args, name).resolve())
    # clang++ is a driver-mode symlink; resolving it to clang drops C++ linkage.
    args.clang = args.clang.absolute()
    code, head = run(["git", "-C", str(args.checkout), "rev-parse", "HEAD"], 10)
    code_dirty, dirty = run(["git", "-C", str(args.checkout), "diff", "HEAD", "--"], 10)
    if code or head.strip() != PIN or code_dirty or dirty != PATCH.read_text():
        parser.error(f"requires CuMetal {PIN} with exactly the checked Cairo pointer-select patch")
    retry_labels = None
    if args.retry_from:
        prior = json.loads(args.retry_from.read_text())
        if prior.get("checkout_commit") != PIN or prior.get("checkout_patch_sha256") != digest(PATCH):
            parser.error("retry receipt has a different CuMetal authority")
        retry_labels = {entry["label"] for entry in prior["compilations"] if not entry["compiled"]}
    inventory = []
    contract = json.loads((ROOT / "conformance/cuda-cumetal-cairo-local-v1.json").read_text())
    for directory, pinned in (
        (args.witness_dir, "cairo_witness"), (args.eval_dir, "cairo_canonical_eval")
    ):
        count = contract["required_generated_entries"][pinned]
        path = directory / "aot_manifest.json"
        pinned_path = ROOT / "src/backends/cuda/aot/native" / pinned / "aot_manifest.json"
        if path.read_bytes() != pinned_path.read_bytes():
            parser.error(f"generated {pinned} manifest differs from its checked identity")
        entries = json.loads(path.read_text())
        validate_aot_manifest(directory, entries)
        if len(entries) != count:
            parser.error(f"expected {count} canonical {pinned} entries")
        inventory.extend((entry, directory) for entry in entries
                         if (not args.only or args.only in entry["label"]) and
                         (retry_labels is None or entry["label"] in retry_labels))
    if not inventory:
        parser.error("empty selected inventory")
    args.out.mkdir(parents=True, exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        results = list(executor.map(lambda pair: compile_entry(*pair, args), inventory))
    numerical = [execute("powers_execution.cu", "expand_powers_kernel", "PASS: QM31 powers", args),
                 execute("active_feeds_execution.cu", "count_active", "PASS: active feeds", args),
                 execute("felt252_execution.cu", "canonical_felt_cube", "PASS: felt252 cubes", args),
                 execute("parametric_air_execution.cu", "", "PASS: parametric AIR", args),
                 execute("felt252_execution.cu", "canonical_felt_inverse", "PASS: felt252 inverses", args, inverse=True),
                 execute("row_chunks_execution.cu", "", "PASS: row chunks", args),
                 execute("parametric_air_execution.cu", "", "PASS: parametric AIR", args, materialized=True)]
    receipt = {"schema": "stwo-zig-cairo-cuda-local-v1", "provider": "cumetal",
               "evidence_class": "apple_gpu_translation", "nvidia_qualified": False,
               "full_proof_verified": False, "checkout_commit": PIN,
               "checkout_patch_sha256": digest(PATCH),
               "compiler_sha256": digest(args.compiler), "clang_sha256": digest(args.clang),
               "complete_inventory": args.only is None and args.retry_from is None,
               "inline_threshold": args.inline_threshold,
               "retry_receipt_sha256": digest(args.retry_from) if args.retry_from else None,
               "runtime_sha256": digest(args.checkout / "build/libcumetal.dylib"),
               "selected_entries": len(inventory),
               "compile_passed": sum(result["compiled"] for result in results),
               "compilations": results, "numerical": numerical}
    (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return 0 if all(result["compiled"] for result in results) and all(result["passed"] for result in numerical) else 1


if __name__ == "__main__":
    sys.exit(main())

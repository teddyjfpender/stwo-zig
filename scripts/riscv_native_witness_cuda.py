#!/usr/bin/env python3
"""Lower the canonical typed Zig row writers to CUDA without copying recipes.

The pinned Zig C backend is the semantic translator. This script adds device
qualifiers, retains only referenced compiler-emitted static data, mechanically
extracts Zig's exact integer helper macros, and adds bounded launch wrappers.
It does not translate or simplify arithmetic expressions. Generated artifacts
belong in a build directory, never in the prover source tree.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from zig_protocol_lib.command import protocol_module_args

FAMILIES = (
    "base_alu_reg", "base_alu_imm", "shifts_reg", "shifts_imm", "lt_reg",
    "lt_imm", "branch_eq", "branch_lt", "lui", "auipc", "jalr", "jal",
    "load_store", "mul", "mulh", "div", "fence",
)
FUNCTION = re.compile(r"^static[^\n]*\([^\n]*\)(?:;| \{)$")
IDENTIFIER = re.compile(r"\b[A-Za-z_]\w*\b")
GLOBAL_NAME = re.compile(r"\b([A-Za-z_]\w*)\)?(?:\[[^]]*\])?(?: zig_nonstring)?\s*(?:=|;)")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def reachable_globals(lines: list[str]) -> tuple[dict[int, str], set[str]]:
    """Conservative symbol reachability; any runtime reference retains a global."""
    at: dict[int, str] = {}
    definitions: dict[str, str] = {}
    for index, line in enumerate(lines):
        if line.startswith("static ") and line.endswith(";") and (" = " in line or not FUNCTION.match(line)):
            match = GLOBAL_NAME.search(line)
            if match is None:
                raise ValueError(f"unrecognized compiler static declaration: {line[:160]}")
            at[index] = match[1]
            if " = " in line:
                definitions[match[1]] = line
    names = set(at.values())
    used = set(IDENTIFIER.findall("\n".join(
        line for index, line in enumerate(lines) if index not in at
    ))) & names
    pending = list(used)
    while pending:
        name = pending.pop()
        for dependency in set(IDENTIFIER.findall(definitions.get(name, ""))) & names - used:
            used.add(dependency)
            pending.append(dependency)
    return at, used


def integer_runtime(zig_header: str) -> str:
    """Use compiler helper bodies verbatim; qualify their functions for CUDA."""
    start = zig_header.index("#define zig_minInt_i8 ")
    end = zig_header.index("static inline bool zig_addo_u32", start)
    body = zig_header[start:end]
    if "zig_int_helpers(64, uint64_t)" not in body:
        raise ValueError("unsupported Zig integer runtime")
    return body.replace("static inline", "static __device__ inline")


def byte_string_initializer(line: str) -> str:
    """Preserve C's exact byte-array string semantics in CUDA C++.

    C permits an N-byte string in an N-byte uint8_t array with its trailing
    NUL omitted; C++ does not. Decode only ordinary C byte escapes and retain
    the declared length exactly. Unknown forms fail instead of being guessed.
    """
    match = re.fullmatch(r'(\s*static uint8_t const \w+\[([0-9]+)\](?: zig_nonstring)? = )"((?:[^"\\]|\\.)*)";', line)
    if match is None:
        return line
    raw = match[3]
    values: list[int] = []
    escapes = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, "'": 39, '"': 34, "?": 63}
    i = 0
    while i < len(raw):
        char = raw[i]
        i += 1
        if char != "\\":
            value = ord(char)
        else:
            if i == len(raw):
                raise ValueError("truncated compiler byte escape")
            char = raw[i]
            i += 1
            if char in "01234567":
                start = i - 1
                while i < min(len(raw), start + 3) and raw[i] in "01234567":
                    i += 1
                value = int(raw[start:i], 8)
            elif char in escapes:
                value = escapes[char]
            else:
                raise ValueError(f"unsupported compiler byte escape: {char}")
        if value > 255:
            raise ValueError("compiler byte initializer exceeds uint8_t")
        values.append(value)
    length = int(match[2])
    if len(values) > length:
        raise ValueError("compiler byte initializer exceeds array length")
    values.extend([0] * (length - len(values)))
    return match[1] + "{" + ",".join(map(str, values)) + "};"


def decorate(source: str, zig_header: str, *, export_prefix: str = "stwo_riscv_native_row_",
             families: tuple[str, ...] = FAMILIES,
             constant_symbols: frozenset[str] = frozenset()) -> tuple[str, dict[str, int]]:
    lines = source.splitlines()
    at, used = reachable_globals(lines)
    if used - constant_symbols:
        # Avoid silently relying on C-only tentative constants or changing any
        # string initializer's byte representation to make it valid C++.
        raise ValueError(f"writer acquired static runtime data: {sorted(used - constant_symbols)}")
    # Opt-in immutable numeric tables are compiler-emitted constants, never
    # caller data. Require a single exact definition with only integer literals
    # and braces. No strings, relocations, or function pointers can be retained.
    for name in used:
        definitions = [line for i, line in enumerate(lines) if at.get(i) == name and " = " in line]
        if len(definitions) != 1 or " const " not in definitions[0]:
            raise ValueError(f"invalid immutable device constant: {name}")
        initializer = definitions[0].split(" = ", 1)[1]
        if re.fullmatch(r"[{};,\s0-9()UINTC_]+", initializer) is None:
            raise ValueError(f"non-numeric immutable device constant: {name}")
    result: list[str] = ["#include <cuda_runtime.h>"]
    includes = 0
    void_pointers: set[str] = set()
    for index, line in enumerate(lines):
        if index in at:
            name = at[index]
            if name in used:
                qualifier = "__device__ __constant__ " if " = " in line else "extern __device__ __constant__ "
                result.append(line.replace("static ", qualifier, 1))
            continue
        if line == '#include "zig.h"':
            includes += 1
            result.extend((
                "#include <stdint.h>\n#include <stddef.h>\n#include <limits.h>\n#include <string.h>",
                '#define zig_extern extern "C" __device__',
                "#define zig_nonstring\n#define zig_unreachable() __builtin_unreachable()",
                integer_runtime(zig_header),
            ))
            continue
        if line.startswith("static "):
            if not FUNCTION.match(line):
                raise ValueError(f"unrecognized compiler declaration: {line[:160]}")
            line = line.replace("static ", "static __device__ ", 1)
            if line.endswith(" {"):
                void_pointers.clear()
        elif re.match(r"^uint32_t integrations_[^\n]*\) \{$", line):
            line = "__device__ " + line
            void_pointers.clear()
        line = byte_string_initializer(line)
        pointer = re.fullmatch(r"\s*void(?: const)? \*(\w+);", line)
        if pointer:
            void_pointers.add(pointer[1])
        assignment = re.fullmatch(r"(\s*)(\w+\.ptr) = (\w+);", line)
        if assignment and assignment[3] in void_pointers:
            # C permits implicit conversion from void*, C++ requires a cast.
            # This changes only the pointer type, never address or arithmetic.
            line = f"{assignment[1]}{assignment[2]} = static_cast<decltype({assignment[2]})>({assignment[3]});"
        # Zig permits a member named `class`. Rename only member declarations
        # and member accesses; string bytes and all expressions stay intact.
        line = re.sub(r"(?<=\.)class\b", "zig_cxx_class", line)
        line = re.sub(r"(?<= )class(?=;)", "zig_cxx_class", line)
        result.append(line)
    if includes != 1:
        raise ValueError("expected exactly one pinned compiler runtime include")
    for family in families:
        if len(re.findall(r"zig_extern uint32_t " + re.escape(export_prefix + family) + r"_v1\(", source)) != 1:
            raise ValueError(f"missing or duplicate writer export: {family}")
    return "\n".join(result) + "\n", {
        "discarded_static_symbols": len(set(at.values()) - used),
        "retained_static_symbols": len(used),
        "typed_families": len(families),
    }


def wrappers(local_zero: bool = False, pruned: bool = False) -> str:
    row_prefix = "stwo_riscv_localzero_row_" if local_zero else "stwo_riscv_native_row_"
    width_prefix = "stwo_riscv_localzero_width_" if local_zero else "stwo_riscv_native_width_"
    kernel_prefix = "stwo_cuda_native_localzero_" if local_zero else "stwo_cuda_native_witness_"
    predecessor_parameter = "const uint32_t *predecessors, " if local_zero else ""
    predecessor_argument = "predecessors, " if local_zero else ""
    row_predecessors = "predecessors, " if pruned else ("reinterpret_cast<const uint32_t (*)[3]>(predecessors), " if local_zero else "")
    placement = "uint32_t physical = __brev((i & 1u) ? (2*padded_rows-i)/2 : i/2) >> (32-(31u-__clz(padded_rows)));" if local_zero else "uint32_t physical = i;"
    if pruned:
        row_prefix="stwo_riscv_localzero_pruned_row_"
        width_prefix="stwo_riscv_localzero_pruned_width_"
        kernel_prefix="stwo_cuda_native_localzero_pruned_"
    parts = ["\n// Device-resident raw retirement rows -> canonical typed SoA columns.\n"]
    for family in FAMILIES:
        parts.append(f'''
__global__ void {kernel_prefix}{family}_v1(
    const uint32_t *rows, const uint32_t *indices, uint32_t source_count,
    uint32_t active_count, uint32_t padded_rows, {predecessor_parameter}uint32_t *output, uint32_t *status) {{
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= padded_rows) return;
    {placement}
    if (i >= active_count) {{
        for (uint32_t c = 0; c < {width_prefix}{family}_v1(); ++c)
            output[(size_t)c * padded_rows + physical] = 0;
        return;
    }}
    uint32_t source = indices ? indices[i] : i;
    if (source >= source_count || (indices && i && indices[i-1] >= source)) {{
        atomicCAS(status, 0u, 4u); return;
    }}
    uint32_t result = {row_prefix}{family}_v1(
        reinterpret_cast<const uint32_t (*)[24]>(rows + (size_t)source * 24),
        {row_predecessors}output, padded_rows, physical);
    if (result) atomicCAS(status, 0u, result);
}}
''')
    launcher = '''
extern "C" cudaError_t @KERNEL@v1_launch(
    uint32_t family, const uint32_t *rows, const uint32_t *indices,
    uint32_t source_count, uint32_t active_count, uint32_t padded_rows,
    @PRED@uint32_t *output, uint32_t *status, cudaStream_t stream) {
    if (family >= 17 || !rows || !output || !status || !padded_rows ||
        (padded_rows & (padded_rows - 1)) || padded_rows > (1u << 27) ||
        active_count > padded_rows || active_count > source_count@GUARD@)
        return cudaErrorInvalidValue;
    dim3 grid((padded_rows + 127u)/128u), block(128);
    switch (family) {
'''
    parts.append(launcher.replace("@KERNEL@", kernel_prefix).replace("@PRED@", predecessor_parameter).replace("@GUARD@", " || !predecessors || padded_rows < 2" if local_zero else ""))
    for index, family in enumerate(FAMILIES):
        parts.append(f"    case {index}: {kernel_prefix}{family}_v1<<<grid, block, 0, stream>>>(rows, indices, source_count, active_count, padded_rows, {predecessor_argument}output, status); break;\n")
    parts.append("    }\n    return cudaGetLastError();\n}\n")
    return "".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--zig", default="zig")
    parser.add_argument("--local-zero-pruned", action="store_true", help="use bounded original-lookup scalar witness DAG")
    parser.add_argument("--local-zero", action="store_true", help="emit the canonical V7 local-zero custody envelope")
    options = parser.parse_args()
    destination = options.out_dir.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    version = subprocess.check_output([options.zig, "version"], text=True).strip()
    if version != "0.15.2":
        raise ValueError(f"unsupported semantic translator: Zig {version}")
    environment = subprocess.check_output([options.zig, "env"], text=True)
    # Zig 0.15 emits ZON. Extract only its quoted library path; never publish
    # the environment object as provenance or rely on shell interpolation.
    match = re.search(r'^\s*\.lib_dir = ("(?:[^"\\]|\\.)*"),$', environment, re.M)
    if match is None:
        raise ValueError("Zig did not report its canonical library directory")
    header_path = Path(json.loads(match[1])) / "zig.h"
    header = header_path.read_bytes()
    generated = destination / "canonical-writers.c"
    if options.local_zero_pruned:
        options.local_zero=True
    entry = "src/riscv_cuda_native_localzero_export_v1.zig" if options.local_zero else "src/riscv_cuda_native_witness_export_v1.zig"
    if options.local_zero_pruned:
        entry="src/riscv_cuda_native_localzero_pruned_export_v1.zig"
    command = [options.zig, "build-obj", "-ofmt=c", f"-femit-bin={generated}",
               *protocol_module_args(entry,
                                     optimize="ReleaseFast", target="x86_64-linux-gnu.2.39", cpu_only=True,
                                     extra_packages=("stwo_riscv_frontend",))]
    subprocess.run(command, cwd=ROOT, check=True)
    raw = generated.read_bytes()
    code, counts = decorate(raw.decode(), header.decode(), export_prefix="stwo_riscv_localzero_pruned_row_" if options.local_zero_pruned else ("stwo_riscv_localzero_row_" if options.local_zero else "stwo_riscv_native_row_"))
    code = re.sub(r"\blinux\b", "zig_target_linux", code)
    code += wrappers(options.local_zero, options.local_zero_pruned)
    final = code.encode()
    (destination / "native-witness.cu").write_bytes(final)
    manifest = {
        "schema": "stwo-riscv-native-witness-cuda-v1", "zig_version": version,
        "semantic_source": "canonical_typed_zig_writers", "fully_resident_prover": False,
        "scope": "device_witness_primitive", "input_words_per_retirement": 24,
        "families": list(FAMILIES), "counts": counts,
        "generated_c_sha256": sha(raw), "compiler_integer_header_sha256": sha(header),
        "cuda_source_sha256": sha(final),
        "local_zero_custody": options.local_zero,
        "local_zero_pruned": options.local_zero_pruned,
        "pruned_recipe_sha256": sha((ROOT / "src/frontends/riscv/air/x0_native_witness_plan_v1.zig").read_bytes()) if options.local_zero_pruned else None,
        "export_source_sha256": sha((ROOT / "src/integrations/riscv_cuda" / ("native_local_zero_witness_exports_v1.zig" if options.local_zero else "native_witness_exports_v1.zig")).read_bytes()),
        "exporter_sha256": sha(Path(__file__).read_bytes()),
        "command": command,
    }
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"out_dir": str(destination), "cuda_source_sha256": sha(final), **counts}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

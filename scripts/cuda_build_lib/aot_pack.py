"""Deterministic packing and lookup carriers for offline CUDA cubins."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Sequence


class AotPackError(RuntimeError):
    pass


ABI_SCHEMAS = {
    "ordinary_constraint_v1": 1,
    "recorded_witness_v1": 2,
    "composition_wave_v2": 3,
    "native_constraint_slab_v1": 4,
    "native_constant_qm31_v1": 5,
}


def write_aot_pack(entries: Sequence[dict[str, object]], destination: Path) -> None:
    staging = destination.with_suffix(".staged")
    with staging.open("wb") as pack:
        offset = 0
        for entry in entries:
            payload = Path(entry["cubin"]).read_bytes()
            if not payload:
                raise AotPackError(f"empty generated cubin: {entry['cubin']}")
            entry["offset"] = offset
            entry["bytes"] = len(payload)
            entry["sha256"] = hashlib.sha256(payload).hexdigest()
            pack.write(payload)
            offset += len(payload)
    _publish(staging, destination)


def write_aot_carriers(
    entries: Sequence[dict[str, object]],
    pack: Path,
    output: Path,
) -> tuple[Path, Path]:
    assembly = output / "cuda_aot_pack.S"
    lookup = output / "cuda_aot_lookup.cc"
    pack_path = str(pack.resolve()).replace("\\", "\\\\").replace('"', '\\"')
    assembly_text = f""".section .rodata
.balign 16
.global stwo_cuda_aot_pack_start
.global stwo_cuda_aot_pack_end
.type stwo_cuda_aot_pack_start, @object
stwo_cuda_aot_pack_start:
.incbin "{pack_path}"
stwo_cuda_aot_pack_end:
.size stwo_cuda_aot_pack_start, stwo_cuda_aot_pack_end-stwo_cuda_aot_pack_start
.section .note.GNU-stack,"",@progbits
"""
    rows = "\n".join(
        "    {0x%016xULL, %dU, %dULL, %dULL, %dU, %s},"
        % (
            int(entry["cache_key"]),
            int(entry["sm"]),
            int(entry["offset"]),
            int(entry["bytes"]),
            int(entry["abi_schema"]),
            json.dumps(str(entry["kernel_name"])),
        )
        for entry in entries
    )
    if not rows:
        rows = '    {0ULL, 0U, 0ULL, 0ULL, 0U, ""},'
    lookup_text = f"""#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" const unsigned char stwo_cuda_aot_pack_start[];
extern "C" const unsigned char stwo_cuda_aot_pack_end[];

namespace {{
struct Entry {{
    std::uint64_t cache_key;
    std::uint32_t sm;
    std::uint64_t offset;
    std::uint64_t size;
    std::uint32_t abi_schema;
    const char *kernel_name;
}};

constexpr Entry kEntries[] = {{
{rows}
}};
constexpr std::size_t kEntryCount = {len(entries)};
}}  // namespace

extern "C" bool stwo_aot_lookup(
    std::uint64_t cache_key,
    std::uint32_t sm_major,
    std::uint32_t sm_minor,
    std::uint32_t abi_schema,
    const char *kernel_name,
    const unsigned char **out_data,
    std::size_t *out_len) {{
    if (out_data == nullptr || out_len == nullptr || abi_schema == 0 ||
        kernel_name == nullptr || kernel_name[0] == '\\0' || sm_minor > 9) return false;
    const std::uint32_t sm = sm_major * 10U + sm_minor;
    std::size_t low = 0;
    std::size_t high = kEntryCount;
    while (low < high) {{
        const std::size_t mid = low + (high - low) / 2;
        const Entry &entry = kEntries[mid];
        if (entry.cache_key < cache_key ||
            (entry.cache_key == cache_key && entry.sm < sm)) {{
            low = mid + 1;
        }} else {{
            high = mid;
        }}
    }}
    if (low == kEntryCount) return false;
    const Entry &entry = kEntries[low];
    if (entry.cache_key != cache_key || entry.sm != sm || entry.size == 0 ||
        entry.abi_schema != abi_schema ||
        std::strcmp(entry.kernel_name, kernel_name) != 0) return false;
    const std::size_t pack_size =
        static_cast<std::size_t>(stwo_cuda_aot_pack_end - stwo_cuda_aot_pack_start);
    if (entry.offset > pack_size || entry.size > pack_size - entry.offset) return false;
    *out_data = stwo_cuda_aot_pack_start + entry.offset;
    *out_len = static_cast<std::size_t>(entry.size);
    return true;
}}

extern "C" std::size_t stwo_zig_cuda_aot_entry_count() {{
    return kEntryCount;
}}
"""
    _atomic_write(assembly, assembly_text.encode("utf-8"))
    _atomic_write(lookup, lookup_text.encode("utf-8"))
    return assembly, lookup


def _publish(staging: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.replace(staging, destination)


def _atomic_write(destination: Path, payload: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        delete=False,
    ) as stream:
        stream.write(payload)
        staging = Path(stream.name)
    os.replace(staging, destination)

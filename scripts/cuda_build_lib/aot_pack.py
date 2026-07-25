"""Deterministic packing and lookup carriers for offline CUDA cubins."""

from __future__ import annotations

import hashlib
import json
import os
import re
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
    "native_seeded_xorshift_trace_v1": 6,
    "native_m31_permutation_trace_v1": 7,
    "native_indexed_recurrence_trace_v1": 8,
    "native_circle_affine_state_trace_v1": 9,
    "native_state_machine_statement_v1": 10,
    "native_state_machine_constraint_v1": 11,
    "native_plonk_logup_constraint_v1": 12,
    "native_m31_permutation_trace_v2": 13,
    "native_poseidon_constraint_v1": 14,
    "native_xor_logup_constraint_v1": 15,
    "native_xor_logup_trace_v1": 16,
    "native_blake_constraint_v1": 17,
    "native_m31_permutation_trace_v3": 18,
    "native_blake_exact_trace_v1": 19,
    "native_blake_exact_interaction_v1": 20,
    "native_blake_exact_trace_v2": 21,
}
DIGEST_RE = re.compile(r"[0-9a-f]{64}")


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
    _validate_carrier_entries(entries, pack)
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
    rows = "\n".join(_entry_row(entry) for entry in entries)
    if not rows:
        rows = '    {0ULL, 0U, 0ULL, 0ULL, 0U, {}, ""},'
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
    std::uint8_t sha256[32];
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
    std::size_t *out_len,
    unsigned char out_sha256[32]) {{
    if (out_data == nullptr || out_len == nullptr || out_sha256 == nullptr) return false;
    *out_data = nullptr;
    *out_len = 0;
    std::memset(out_sha256, 0, 32);
    if (abi_schema == 0 ||
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
    std::memcpy(out_sha256, entry.sha256, 32);
    return true;
}}

extern "C" std::size_t stwo_zig_cuda_aot_entry_count() {{
    return kEntryCount;
}}
"""
    _atomic_write(assembly, assembly_text.encode("utf-8"))
    _atomic_write(lookup, lookup_text.encode("utf-8"))
    return assembly, lookup


def _validate_carrier_entries(
    entries: Sequence[dict[str, object]],
    pack: Path,
) -> None:
    try:
        payload = pack.read_bytes()
    except OSError as error:
        raise AotPackError(f"cannot read generated AOT pack: {error}") from error
    for index, entry in enumerate(entries):
        digest = entry.get("sha256")
        if not isinstance(digest, str) or DIGEST_RE.fullmatch(digest) is None:
            raise AotPackError(
                f"AOT carrier entry {index} has a malformed cubin SHA-256"
            )
        try:
            offset = int(entry["offset"])
            size = int(entry["bytes"])
        except (KeyError, TypeError, ValueError) as error:
            raise AotPackError(
                f"AOT carrier entry {index} has invalid pack bounds"
            ) from error
        if (
            offset < 0
            or size <= 0
            or offset > len(payload)
            or size > len(payload) - offset
        ):
            raise AotPackError(
                f"AOT carrier entry {index} is outside the generated pack"
            )
        observed = hashlib.sha256(payload[offset : offset + size]).hexdigest()
        if observed != digest:
            raise AotPackError(
                f"AOT carrier entry {index} cubin digest disagrees with the pack"
            )


def _entry_row(entry: dict[str, object]) -> str:
    digest = bytes.fromhex(str(entry["sha256"]))
    digest_values = ", ".join(f"0x{value:02x}" for value in digest)
    return (
        "    {0x%016xULL, %dU, %dULL, %dULL, %dU, {%s}, %s},"
        % (
            int(entry["cache_key"]),
            int(entry["sm"]),
            int(entry["offset"]),
            int(entry["bytes"]),
            int(entry["abi_schema"]),
            digest_values,
            json.dumps(str(entry["kernel_name"])),
        )
    )


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

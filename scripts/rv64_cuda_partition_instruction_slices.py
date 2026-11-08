"""Bound CUDA optimizer modules while preserving ordered SSA slice calls."""
import hashlib
from pathlib import Path
import re


def partition(source: Path, destination: Path, steps_per_module: int = 8, max_module_bytes: int = 65536):
    if steps_per_module < 1 or max_module_bytes < 1:
        raise ValueError("positive instruction-slice module bound required")
    text = source.read_text()
    tag = "rv64_aot_" + hashlib.sha256(text.encode()).hexdigest()[:16]
    names = re.findall(r"__device__ __noinline__ OM31 ([A-Za-z0-9_]+_bounded_step_(\d+))\(", text)
    for original, index in names:
        text = re.sub(r"\b" + re.escape(original) + r"\b", tag + "_step_" + index, text)
    parts = list(re.finditer(r"__device__ __noinline__ OM31 " + tag + r"_step_\d+\(", text))
    mode = "instruction_slices"
    if parts:
        tail = text.index("__device__ __noinline__ void ", parts[-1].end())
    else:
        mode = "original_root_groups"
        parts = list(re.finditer(r"__device__ __noinline__ void [A-Za-z0-9_]+_part_\d+\(", text))
        if not parts:
            raise ValueError("bounded instruction functions required")
        tail = text.index('extern "C" __global__ void', parts[-1].end())
    prefix = text[:parts[0].start()]
    functions = [text[p.start():parts[i + 1].start() if i + 1 < len(parts) else tail]
                 for i, p in enumerate(parts)]
    declarations = "".join(f[:f.index("{")] + ";\n" for f in functions)
    destination.mkdir(parents=True, exist_ok=True)
    sources = []
    first = 0
    while first < len(functions):
        count, size = 1, len(functions[first])
        while count < steps_per_module and first + count < len(functions) and size + len(functions[first + count]) <= max_module_bytes:
            size += len(functions[first + count])
            count += 1
        path = destination / f"{tag}-steps-{first}.cu"
        path.write_text(prefix + "".join(functions[first:first + count]))
        sources.append(path)
        first += count
    entry = destination / f"{tag}-entry.cu"
    entry.write_text(prefix + declarations + text[tail:])
    return {"source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "instruction_slices": len(functions), "mode": mode, "steps_per_module": steps_per_module,
            "sources": sources + [entry]}

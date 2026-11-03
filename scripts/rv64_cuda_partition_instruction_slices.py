"""Bound CUDA optimizer modules while preserving ordered SSA slice calls."""
import hashlib
from pathlib import Path
import re


def partition(source: Path, destination: Path, steps_per_module: int = 8):
    if steps_per_module < 1:
        raise ValueError("positive instruction-slice module bound required")
    text = source.read_text()
    tag = "rv64_aot_" + hashlib.sha256(text.encode()).hexdigest()[:16]
    text = re.sub(r"\brv64_truth_bounded_step_(\d+)\b", lambda m: tag + "_step_" + m[1], text)
    parts = list(re.finditer(r"__device__ __noinline__ OM31 " + tag + r"_step_\d+\(", text))
    if not parts:
        raise ValueError("bounded instruction functions required")
    tail = text.index("__device__ __noinline__ void ", parts[-1].end())
    prefix = text[:parts[0].start()]
    functions = [text[p.start():parts[i + 1].start() if i + 1 < len(parts) else tail]
                 for i, p in enumerate(parts)]
    declarations = "".join(f[:f.index("{")] + ";\n" for f in functions)
    destination.mkdir(parents=True, exist_ok=True)
    sources = []
    for first in range(0, len(functions), steps_per_module):
        path = destination / f"{tag}-steps-{first}.cu"
        path.write_text(prefix + "".join(functions[first:first + steps_per_module]))
        sources.append(path)
    entry = destination / f"{tag}-entry.cu"
    entry.write_text(prefix + declarations + text[tail:])
    return {"source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "instruction_slices": len(functions), "steps_per_module": steps_per_module,
            "sources": sources + [entry]}

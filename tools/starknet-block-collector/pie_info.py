"""Read the Starknet OS output header and execution resources from a Cairo PIE zip."""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

HEADER = ("initial_root", "final_root", "prev_block_number", "new_block_number",
          "prev_block_hash", "new_block_hash", "os_program_hash", "os_config_hash",
          "use_kzg_da", "full_output")


def pie_summary(path: Path) -> dict:
    """OS output header fields plus n_steps / builtins; hashes as 0x-hex."""
    with zipfile.ZipFile(path) as z:
        meta = json.loads(z.read("metadata.json"))
        seg = meta["builtin_segments"]["output"]["index"]
        want = len(HEADER)
        out: dict[int, int] = {}
        # memory.bin: 40-byte cells = u64 LE address (segment << 47 | offset) + 32-byte LE felt.
        with z.open("memory.bin") as f:
            while len(out) < want:
                cell = f.read(40 * 65536)
                if not cell:
                    break
                for i in range(0, len(cell) - 39, 40):
                    a = int.from_bytes(cell[i:i + 8], "little")
                    if (a >> 47) & 0xFFFF == seg and (a & ((1 << 47) - 1)) < want:
                        out[a & ((1 << 47) - 1)] = int.from_bytes(cell[i + 8:i + 40], "little")
        res = json.loads(z.read("execution_resources.json"))
    info = {name: out.get(i) for i, name in enumerate(HEADER)}
    for k in ("initial_root", "final_root", "prev_block_hash", "new_block_hash", "os_config_hash"):
        if info[k] is not None:
            info[k] = hex(info[k])
    info["n_blocks"] = (info["new_block_number"] or 0) - (info["prev_block_number"] or 0)
    info["n_steps"] = res["n_steps"]
    info["n_memory_holes"] = res.get("n_memory_holes")
    info["builtins"] = {k: v for k, v in res["builtin_instance_counter"].items() if v}
    info["pie_bytes"] = path.stat().st_size
    return info


if __name__ == "__main__":
    for p in sys.argv[1:]:
        print(json.dumps({"pie": p, **pie_summary(Path(p))}, indent=1))

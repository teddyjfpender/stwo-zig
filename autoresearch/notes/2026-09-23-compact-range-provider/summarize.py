"""Publish only complete, independently verified CPU/Metal local CSP results."""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
rows = {}
negative = {}
for backend in ("cpu", "metal"):
    records = json.loads((HERE / f"suite-{backend}/results.json").read_text())
    assert len(records) == 17 and all(r.get("independent_verified") for r in records)
    rows[backend] = {r["case"].removeprefix(f"{backend}-"): r for r in records if not r["negative"]}
    negative[backend] = next(r for r in records if r["negative"])
assert rows["cpu"].keys() == rows["metal"].keys()
lines = [
    "## Compact-provider CSP results (2026-09-23)", "",
    "Apple M5 Max / 64 GiB, ReleaseFast, 16 workers. Three samples per positive",
    "workload, zero explicit warmups; the table reports full end-to-end medians.",
    "All use canonical inputs and 70 queries / 26 PoW bits. Timings include execution,",
    "witness generation, key admission, proving, artifact encoding and fresh verification.",
    "All 32 retained positive proofs and both software rejection proofs independently",
    "verify in separate processes. These are source-pinned local dirty-tree results.", "",
    "The compact range providers are selected by the shared product request path for",
    "base RISC-V and both extension profiles. ECDSA uses the pinned precompile guest",
    "(1,828 RISC-V steps); its result is not an isolated precompile timing.", "",
    "| Workload | CPU seconds | Metal seconds |",
    "| --- | ---: | ---: |",
]
for name in rows["cpu"]:
    lines.append(f"| {name} | {rows['cpu'][name]['total_seconds']:.6f} | {rows['metal'][name]['total_seconds']:.6f} |")
device = rows["metal"]["ecdsa_secp256k1-32"]["device"][0]
lines += [
    "",
    f"Metal ECDSA records {device['dispatches']:,} GPU dispatches and",
    f"{device['cpu_fallbacks']:,} CPU fallbacks per proof. This is the Metal backend's",
    "mixed execution path, not an exclusively GPU proof; raw reports retain",
    "the device counts for every workload and sample.",
    "",
    f"The bad-signature software fallback also proves rejection: CPU **{negative['cpu']['total_seconds']:.6f} s**,",
    f"Metal **{negative['metal']['total_seconds']:.6f} s** (one sample each). These are",
    "separate rejection proofs, not accelerated ECDSA performance rows.", "",
    "The historical 0.881876-second CPU ECDSA result also used precompiles.",
    "The current CPU result has not recovered that historical latency.",
    "Compact-child recursion is separately qualified at 70 queries / 26 PoW bits",
    "for base RISC-V, Ethereum and guest Poseidon; those tests are not CSP timings.", "",
    "[Source, qualification and all raw reports/proofs](../../autoresearch/notes/2026-09-23-compact-range-provider/README.md).",
    "",
]
section = "\n".join(lines)
readme = ROOT / "vectors/riscv_csp/README.md"
content = readme.read_text()
marker = "## Compact-provider CSP results (2026-09-23)"
if marker in content:
    content = content[:content.index(marker)].rstrip() + "\n\n"
else:
    content = content.rstrip() + "\n\n"
readme.write_text(content + section)
(HERE / "RESULTS.md").write_text(section.replace(
    "../../autoresearch/notes/2026-09-23-compact-range-provider/README.md", "README.md"))
print(section)

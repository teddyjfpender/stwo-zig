#!/usr/bin/env python3
"""Build a pinned native Bend runner; generated C stays outside the source tree."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bend-root", type=Path, required=True)
    p.add_argument("--output", type=Path, default=ROOT / ".zig-cache/bend/stwo-bend")
    p.add_argument("--target", choices=["cpu", "gpu"], default="cpu")
    args = p.parse_args()
    pin = json.loads((ROOT / "bend/toolchain.json").read_text())
    toolchain = args.bend_root.resolve()
    revision = subprocess.check_output(["git", "-C", str(toolchain), "rev-parse", "HEAD"], text=True).strip()
    if revision != pin["commit"]:
        p.error(f"Bend revision must be {pin['commit']}; got {revision}")
    if subprocess.check_output(["git", "-C", str(toolchain), "status", "--porcelain"], text=True).strip():
        p.error("Bend toolchain checkout must be clean")
    if args.target == "gpu" and platform.system() != "Darwin" and not (Path(os.environ.get("CUDA_HOME", "/usr/local/cuda")) / "include/nvrtc.h").exists():
        p.error("GPU target requires Metal on macOS or CUDA; refusing CPU fallback")
    compiler = ["node", str(toolchain / "bend2/main.ts")]
    subprocess.run(compiler + [str(ROOT / "bend/stwo/PROOF.bend")], check=True)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="stwo-bend-build-") as tmp:
        source = Path(tmp) / "stwo"
        shutil.copytree(ROOT / "bend/stwo", source)
        if args.target == "gpu":
            runner = source / "runner.bend"
            runner.write_text(runner.read_text().replace("write(run(req))", "write(run!(req))"))
            transport = source / "transport.c"
            transport.write_text("#define REQUIRE_GPU 1\n" + transport.read_text())
        subprocess.run(compiler + [str(source / "runner.bend"), "-o", str(output)], check=True)
        subprocess.run(compiler + [str(source / "runner.bend"), "-o", str(output) + ".c"], check=True)
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()
    metadata = {"schema": "stwo-bend-build-v1", "pin": pin, "target": args.target,
                "binary_sha256": sha(output), "generated_c_sha256": sha(Path(str(output) + ".c")),
                "sources": {str(f.relative_to(ROOT)): sha(f) for f in sorted((ROOT / "bend/stwo").iterdir()) if f.is_file()}}
    Path(str(output) + ".json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(output)


if __name__ == "__main__":
    main()

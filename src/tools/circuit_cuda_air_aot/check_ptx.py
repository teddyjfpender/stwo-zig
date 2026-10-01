"""Authenticate generated circuit AIR sources and lower every body to PTX."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


def check(clang: Path, generated: Path, stub: Path) -> None:
    manifest = json.loads((generated / "manifest.json").read_text())
    if manifest.get("schema") != "stwo-circuit-cuda-air-aot-v1":
        raise ValueError("unexpected circuit CUDA AOT manifest")
    bodies = manifest["bodies"]
    occurrences = manifest["occurrences"]
    if len(bodies) != 11 or len(occurrences) != 11:
        raise ValueError("incomplete pinned circuit AIR inventory")
    if {entry["body_index"] for entry in occurrences} != set(range(len(bodies))):
        raise ValueError("circuit AIR placement does not cover every body")
    seen_names: set[str] = set()
    seen_keys: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="stwo-circuit-air-ptx-") as temporary:
        for index, entry in enumerate(bodies):
            filename = entry["filename"]
            if Path(filename).name != filename or not filename.endswith(".cu"):
                raise ValueError("invalid circuit AIR filename")
            if filename in seen_names or entry["cache_key"] in seen_keys:
                raise ValueError("duplicate circuit AIR identity")
            seen_names.add(filename)
            seen_keys.add(entry["cache_key"])
            source = generated / filename
            if hashlib.sha256(source.read_bytes()).hexdigest() != entry["source_identity"]:
                raise ValueError(f"source identity mismatch: {filename}")
            for architecture in ("sm_80", "sm_90"):
                output = Path(temporary) / f"{index}_{architecture}.ptx"
                subprocess.run(
                    [
                        str(clang), "-x", "cuda", "--cuda-device-only",
                        f"--cuda-gpu-arch={architecture}",
                        "-Xclang", "-target-feature", "-Xclang", "+ptx78",
                        "-nocudainc", "-nocudalib", "-std=c++17", "-O3", "-S",
                        "-include", "cuda_runtime_api.h", "-I", str(stub),
                        str(source), "-o", str(output),
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                if not output.read_bytes().startswith(b"//"):
                    raise ValueError(f"empty PTX: {filename} {architecture}")
    print(f"CIRCUIT_CUDA_AIR_PTX=qualified bodies={len(bodies)} arches=sm_80,sm_90")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", required=True, type=Path)
    parser.add_argument("--generated", required=True, type=Path)
    parser.add_argument("--stub", required=True, type=Path)
    options = parser.parse_args()
    check(options.clang, options.generated, options.stub)


if __name__ == "__main__":
    main()

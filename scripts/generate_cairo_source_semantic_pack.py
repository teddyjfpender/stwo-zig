#!/usr/bin/env python3
"""Generate a proof-independent Cairo source semantic-pack fixture.

The component artifact is emitted by stwo-cairo's witness_genericize tool. This
script only packages authenticated source/toolchain identities and the tool's
reported geometry; it does not translate or invent Cairo AIR semantics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path


FORMAT = "stwo-zig-cairo-source-semantic-pack"
VERSION = 3
REGISTRY_FORMAT = "stwo-zig-cairo-source-component-registry"
REGISTRY_VERSION = 1
IDENTITY_DOMAIN = b"stwo-zig/cairo/source-semantic-pack/v3\0"
SOURCE_REPOSITORY = "https://github.com/starkware-libs/stwo-cairo"


def run(*args: str, cwd: Path) -> str:
    return subprocess.run(
        args,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(256 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )


def identity(
    source: dict[str, str],
    toolchain: dict[str, str],
    registry_sha256: str,
) -> str:
    digest = hashlib.sha256()
    digest.update(IDENTITY_DOMAIN)
    digest.update(struct.pack("<I", VERSION))

    def string(value: str) -> None:
        encoded = value.encode("ascii")
        digest.update(struct.pack("<Q", len(encoded)))
        digest.update(encoded)

    string(source["repository"])
    string(source["revision"])
    string(source["tree"])
    string(source["stwo_revision"])
    string(toolchain["rustc"])
    string(toolchain["cargo"])
    string(toolchain["rustfmt"])
    digest.update(bytes.fromhex(toolchain["source_cargo_lock_sha256"]))
    digest.update(bytes.fromhex(toolchain["generator_cargo_lock_sha256"]))
    digest.update(bytes.fromhex(toolchain["generator_sha256"]))
    digest.update(bytes.fromhex(registry_sha256))
    return digest.hexdigest()


def workspace_root(rust_root: Path) -> tuple[Path, Path]:
    rust_root = rust_root.resolve()
    cargo_root = rust_root / "stwo_cairo_prover"
    if not (cargo_root / "Cargo.toml").is_file():
        cargo_root = rust_root
    if not (cargo_root / "Cargo.toml").is_file():
        raise SystemExit(f"no stwo-cairo Cargo workspace under {rust_root}")
    repository_root = Path(
        run("git", "rev-parse", "--show-toplevel", cwd=cargo_root)
    )
    return repository_root, cargo_root


def parse_stwo_revision(cargo_toml: Path) -> str:
    match = re.search(
        r'^stwo\s*=\s*\{[^\n]*\brev\s*=\s*"([0-9a-f]{40})"',
        cargo_toml.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if match is None:
        raise SystemExit("workspace stwo revision was not found")
    return match.group(1)


def parse_geometry(census: str, component: str) -> dict[str, int]:
    match = re.search(
        rf"^\s*{re.escape(component)}\s+cols=(\d+)\s+"
        r"lookup_words=(\d+)\s+sub_words=(\d+)\s*$",
        census,
        re.MULTILINE,
    )
    if match is None:
        raise SystemExit(f"{component} was not an immediately rewritable component")
    return {
        "trace_columns": int(match.group(1)),
        "lookup_words": int(match.group(2)),
        "sub_input_words": int(match.group(3)),
    }


def relation_outputs(source: str) -> list[str]:
    match = re.search(
        r"pub\(crate\) const SUB_FEED_LAYOUT:.*?=\s*&\[(.*?)\];",
        source,
        re.DOTALL,
    )
    if match is None:
        raise SystemExit("emitted source has no SUB_FEED_LAYOUT")
    outputs: list[str] = []
    for name in re.findall(r'\(\s*"([^"]+)"', match.group(1)):
        if name not in outputs:
            outputs.append(name)
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--component", default="add_opcode_small")
    args = parser.parse_args()

    repository_root, cargo_root = workspace_root(args.rust_root)
    if run(
        "git",
        "status",
        "--porcelain",
        "--untracked-files=no",
        cwd=repository_root,
    ):
        raise SystemExit("stwo-cairo source repository has tracked modifications")
    component_source = (
        cargo_root
        / "crates"
        / "prover"
        / "src"
        / "witness"
        / "components"
        / f"{args.component}.rs"
    )
    tool_manifest = cargo_root / "tools" / "witness_genericize" / "Cargo.toml"
    tool_source = cargo_root / "tools" / "witness_genericize" / "src" / "main.rs"
    source_cargo_lock = cargo_root / "Cargo.lock"
    generator_cargo_lock = tool_manifest.parent / "Cargo.lock"
    for required in (
        component_source,
        tool_manifest,
        tool_source,
        source_cargo_lock,
        generator_cargo_lock,
    ):
        if not required.is_file():
            raise SystemExit(f"required source file is missing: {required}")

    cargo = shutil.which("cargo")
    rustc = shutil.which("rustc")
    rustfmt = shutil.which("rustfmt")
    if cargo is None or rustc is None or rustfmt is None:
        raise SystemExit("cargo, rustc, and rustfmt are required")

    run(
        cargo,
        "run",
        "--quiet",
        "--manifest-path",
        str(tool_manifest),
        "--",
        "--check",
        str(component_source),
        cwd=cargo_root,
    )
    census = run(
        cargo,
        "run",
        "--quiet",
        "--manifest-path",
        str(tool_manifest),
        "--",
        "--census",
        str(component_source),
        cwd=cargo_root,
    )

    output = args.output_dir.resolve()
    components_dir = output / "components"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cairo-source-pack-") as temporary:
        run(
            cargo,
            "run",
            "--quiet",
            "--manifest-path",
            str(tool_manifest),
            "--",
            "--emit-dir",
            temporary,
            str(component_source),
            cwd=cargo_root,
        )
        emitted = Path(temporary) / component_source.name
        if not emitted.is_file():
            raise SystemExit("witness_genericize did not emit the requested component")
        components_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(emitted, components_dir / emitted.name)

    artifact = components_dir / component_source.name
    emitted_source = artifact.read_text(encoding="utf-8")
    registry = {
        "components": [
            {
                "artifact_sha256": sha256(artifact),
                "canonical_ordinal": 0,
                "capacity_feeds": [],
                "name": args.component,
                "oracle": parse_geometry(census, args.component),
                "producer_edges": [],
                "relation_outputs": relation_outputs(emitted_source),
                "trace_parts": [{"kind": "main"}],
                "writer": "recorded_aot",
            }
        ],
        "format": REGISTRY_FORMAT,
        "version": REGISTRY_VERSION,
    }
    registry_path = output / "registry.json"
    canonical_json(registry_path, registry)
    registry_digest = sha256(registry_path)

    source = {
        "repository": SOURCE_REPOSITORY,
        "revision": run("git", "rev-parse", "HEAD", cwd=repository_root),
        "tree": run("git", "rev-parse", "HEAD^{tree}", cwd=repository_root),
        "stwo_revision": parse_stwo_revision(cargo_root / "Cargo.toml"),
    }
    toolchain = {
        "cargo": run(cargo, "--version", cwd=cargo_root),
        "generator_cargo_lock_sha256": sha256(generator_cargo_lock),
        "generator_sha256": sha256(tool_source),
        "rustc": run(rustc, "--version", cwd=cargo_root),
        "rustfmt": run(rustfmt, "--version", cwd=cargo_root),
        "source_cargo_lock_sha256": sha256(source_cargo_lock),
    }
    manifest = {
        "authority_sha256": identity(source, toolchain, registry_digest),
        "format": FORMAT,
        "provenance": "source-derived",
        "registry_sha256": registry_digest,
        "source": source,
        "toolchain": toolchain,
        "version": VERSION,
    }
    canonical_json(output / "manifest.json", manifest)


if __name__ == "__main__":
    main()

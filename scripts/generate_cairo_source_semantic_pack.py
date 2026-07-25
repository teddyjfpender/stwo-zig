#!/usr/bin/env python3
"""Generate a proof-independent Cairo source semantic pack.

Every artifact is copied byte-for-byte from an authenticated stwo-cairo checkout
after its checked-in generic program passes the pinned ``witness_genericize``
``--check`` oracle. PIEs and proof-selected artifacts are deliberately not accepted.
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
from dataclasses import dataclass
from pathlib import Path


FORMAT = "stwo-zig-cairo-source-semantic-pack"
VERSION = 3
REGISTRY_FORMAT = "stwo-zig-cairo-source-component-registry"
REGISTRY_VERSION = 1
IDENTITY_DOMAIN = b"stwo-zig/cairo/source-semantic-pack/v3\0"
SOURCE_REPOSITORY = "https://github.com/starkware-libs/stwo-cairo"
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
CLAIM_FIELD_RE = re.compile(
    r"^\s*pub ([a-z][a-z0-9_]*):\s*Option<[a-z][a-z0-9_]*::ClaimGenerator>",
    re.MULTILINE,
)
CENSUS_ROW_RE = re.compile(
    r"^\s*([a-z][a-z0-9_]*)\s+cols=(\d+)\s+"
    r"lookup_words=(\d+)\s+sub_words=(\d+)\s*$",
    re.MULTILINE,
)
SUB_FEED_RE = re.compile(
    r"\(\s*"
    r'"(?P<field>[a-z][a-z0-9_]*)"\s*,\s*'
    r"(?P<instance>\d+)\s*,\s*"
    r'"(?P<state>[a-z][a-z0-9_]*)_state"\s*,\s*'
    r"(?P<relation>\d+)\s*,\s*"
    r"(?P<base>\d+)\s*,\s*"
    r"(?P<width>\d+)\s*,?\s*"
    r"\)",
    re.MULTILINE,
)
SUB_FEED_BLOCK_RE = re.compile(
    r"pub\(crate\) const SUB_FEED_LAYOUT:.*?=\s*&\[(?P<body>.*?)\];",
    re.DOTALL,
)
GENERATED_MARKER = "// === BEGIN witness_genericize (generated; re-runnable) ==="


@dataclass(frozen=True)
class Feed:
    field: str
    instance: int
    target: str
    relation: int
    word_base: int
    words_per_instance: int


@dataclass(frozen=True)
class StwoBinding:
    declared_revision: str
    resolved_revision: str
    resolved_tree: str | None
    kind: str


def run(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostics"
        raise SystemExit(f"{Path(args[0]).name} failed: {detail}")
    return result.stdout.strip()


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


def resolve_stwo_binding(cargo_root: Path) -> StwoBinding:
    cargo_toml = cargo_root / "Cargo.toml"
    declared = parse_stwo_revision(cargo_toml)
    source = cargo_toml.read_text(encoding="utf-8")
    patch = re.search(
        r'(?ms)^\[patch\."https://github\.com/teddyjfpender/stwo"\]\s*'
        r'.*?^stwo\s*=\s*\{\s*path\s*=\s*"([^"]+)"\s*\}',
        source,
    )
    if patch is None:
        return StwoBinding(
            declared_revision=declared,
            resolved_revision=declared,
            resolved_tree=None,
            kind="declared_git_revision",
        )

    crate_root = (cargo_root / patch.group(1)).resolve()
    if not (crate_root / "Cargo.toml").is_file():
        raise SystemExit(f"patched Stwo crate is missing: {crate_root}")
    repository_root = Path(run("git", "rev-parse", "--show-toplevel", cwd=crate_root))
    if run("git", "status", "--porcelain", cwd=repository_root):
        raise SystemExit(f"patched Stwo source repository is dirty: {repository_root}")
    return StwoBinding(
        declared_revision=declared,
        resolved_revision=run("git", "rev-parse", "HEAD", cwd=repository_root),
        resolved_tree=run("git", "rev-parse", "HEAD^{tree}", cwd=repository_root),
        kind="clean_local_patch",
    )


def validate_stwo_binding(
    binding: StwoBinding,
    expected_revision: str | None,
) -> None:
    if expected_revision is not None and not re.fullmatch(
        r"[0-9a-f]{40}", expected_revision
    ):
        raise SystemExit("expected Stwo oracle revision must be 40 lowercase hex")
    if (
        binding.resolved_revision != binding.declared_revision
        and expected_revision is None
    ):
        raise SystemExit(
            "Cargo's local Stwo patch overrides the declared revision "
            f"{binding.declared_revision} with {binding.resolved_revision}; "
            "pass --expected-oracle-stwo-revision to acknowledge the exact "
            "diagnostic source pair"
        )
    if (
        expected_revision is not None
        and binding.resolved_revision != expected_revision
    ):
        raise SystemExit(
            "resolved Stwo oracle revision mismatch: "
            f"expected {expected_revision}, got {binding.resolved_revision}"
        )


def parse_rewritable_census(census: str) -> dict[str, dict[str, int]]:
    start = "--- MATCHED files (rewritable now) ---"
    end = "--- MATCHED files (needs trait extension:"
    if start not in census or end not in census:
        raise SystemExit("witness_genericize census has an unsupported format")
    body = census.split(start, 1)[1].split(end, 1)[0]
    entries: dict[str, dict[str, int]] = {}
    for match in CENSUS_ROW_RE.finditer(body):
        name, columns, lookup_words, sub_words = match.groups()
        if name in entries:
            raise SystemExit(f"witness census repeats {name}")
        entries[name] = {
            "trace_columns": int(columns),
            "lookup_words": int(lookup_words),
            "sub_input_words": int(sub_words),
        }
    if not entries:
        raise SystemExit("witness census contains no immediately rewritable components")
    return entries


def parse_claim_order(claims_source: str) -> list[str]:
    order = CLAIM_FIELD_RE.findall(claims_source)
    if not order or len(order) != len(set(order)):
        raise SystemExit("CairoClaimGenerator has missing or duplicate component fields")
    return order


def parse_feeds(source: str, component: str) -> list[Feed]:
    block = SUB_FEED_BLOCK_RE.search(source)
    if block is None:
        raise SystemExit(f"{component} emitted source has no SUB_FEED_LAYOUT")
    feeds = [
        Feed(
            field=match["field"],
            instance=int(match["instance"]),
            target=match["state"],
            relation=int(match["relation"]),
            word_base=int(match["base"]),
            words_per_instance=int(match["width"]),
        )
        for match in SUB_FEED_RE.finditer(block["body"])
    ]
    compact = re.sub(r"\s+", "", block["body"])
    if not feeds and compact:
        raise SystemExit(f"{component} SUB_FEED_LAYOUT could not be parsed")
    return feeds


def relation_outputs(feeds: list[Feed]) -> list[str]:
    outputs: list[str] = []
    for feed in feeds:
        if feed.target not in outputs:
            outputs.append(feed.target)
    return outputs


def derive_closed_topology(
    order: list[str],
    feeds_by_component: dict[str, list[Feed]],
) -> tuple[dict[str, list[dict[str, int | str]]], dict[str, list[dict[str, int | str]]]]:
    selected = set(order)
    edges: dict[str, list[dict[str, int | str]]] = {name: [] for name in order}
    capacities: dict[str, list[dict[str, int | str]]] = {
        name: [] for name in order
    }
    for producer in order:
        grouped: dict[str, list[Feed]] = {}
        for feed in feeds_by_component[producer]:
            if feed.target in selected:
                grouped.setdefault(feed.target, []).append(feed)
        for target, feeds in grouped.items():
            feeds.sort(key=lambda feed: feed.word_base)
            width = feeds[0].words_per_instance
            first = feeds[0].word_base
            for index, feed in enumerate(feeds):
                if (
                    feed.words_per_instance != width
                    or feed.word_base != first + index * width
                ):
                    raise SystemExit(
                        f"{producer}->{target} is not one contiguous uniform feed"
                    )
            edges[target].append(
                {
                    "producer": producer,
                    "word_base": first,
                    "words_per_instance": width,
                    "instances": len(feeds),
                }
            )
            capacities[target].append(
                {"producer": producer, "instances": len(feeds)}
            )
    return edges, capacities


def select_components(
    claim_order: list[str],
    census: dict[str, dict[str, int]],
    requested: list[str] | None,
    all_checked_rewritable: bool,
    component_root: Path,
) -> list[str]:
    source_names = set(claim_order)
    census_names = set(census)
    if not census_names.issubset(source_names):
        raise SystemExit(
            "rewritable census is not a subset of CairoClaimGenerator: "
            f"{sorted(census_names - source_names)}"
        )
    if all_checked_rewritable:
        selected = {
            name
            for name in census_names
            if GENERATED_MARKER
            in (component_root / f"{name}.rs").read_text(encoding="utf-8")
        }
        if not selected:
            raise SystemExit("source contains no checked rewritable semantic programs")
    else:
        names = requested or ["add_opcode_small"]
        if len(names) != len(set(names)):
            raise SystemExit("component selection contains duplicates")
        for name in names:
            if not NAME_RE.fullmatch(name):
                raise SystemExit(f"invalid component name: {name!r}")
            if name not in census:
                raise SystemExit(
                    f"{name} is not an immediately rewritable source component"
                )
        selected = set(names)
    return [name for name in claim_order if name in selected]


def emit_pack(
    output: Path,
    order: list[str],
    geometry: dict[str, dict[str, int]],
    component_root: Path,
    source: dict[str, str],
    toolchain: dict[str, str],
) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".cairo-source-pack-", dir=output.parent
    ) as temporary:
        staged = Path(temporary)
        components_dir = staged / "components"
        components_dir.mkdir()
        feeds_by_component: dict[str, list[Feed]] = {}
        for name in order:
            artifact = component_root / f"{name}.rs"
            if not artifact.is_file():
                raise SystemExit(f"checked source component disappeared: {name}")
            copied = components_dir / artifact.name
            shutil.copyfile(artifact, copied)
            feeds_by_component[name] = parse_feeds(
                copied.read_text(encoding="utf-8"), name
            )

        edges, capacities = derive_closed_topology(order, feeds_by_component)
        registry = {
            "components": [
                {
                    "artifact_sha256": sha256(components_dir / f"{name}.rs"),
                    "canonical_ordinal": ordinal,
                    "capacity_feeds": capacities[name],
                    "name": name,
                    "oracle": geometry[name],
                    "producer_edges": edges[name],
                    "relation_outputs": relation_outputs(feeds_by_component[name]),
                    "trace_parts": [{"kind": "main"}],
                    "writer": "recorded_aot",
                }
                for ordinal, name in enumerate(order)
            ],
            "format": REGISTRY_FORMAT,
            "version": REGISTRY_VERSION,
        }
        registry_path = staged / "registry.json"
        canonical_json(registry_path, registry)
        registry_digest = sha256(registry_path)
        manifest = {
            "authority_sha256": identity(source, toolchain, registry_digest),
            "format": FORMAT,
            "provenance": "source-derived",
            "registry_sha256": registry_digest,
            "source": source,
            "toolchain": toolchain,
            "version": VERSION,
        }
        canonical_json(staged / "manifest.json", manifest)

        if output.exists():
            shutil.rmtree(output)
        shutil.copytree(staged, output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rust-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--expected-oracle-stwo-revision")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--component", action="append")
    selection.add_argument("--all-checked-rewritable", action="store_true")
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

    component_root = cargo_root / "crates/prover/src/witness/components"
    claims_source = cargo_root / "crates/prover/src/witness/cairo_claim_generator.rs"
    tool_manifest = cargo_root / "tools/witness_genericize/Cargo.toml"
    tool_source = cargo_root / "tools/witness_genericize/src/main.rs"
    source_cargo_lock = cargo_root / "Cargo.lock"
    generator_cargo_lock = tool_manifest.parent / "Cargo.lock"
    for required in (
        component_root,
        claims_source,
        tool_manifest,
        tool_source,
        source_cargo_lock,
        generator_cargo_lock,
    ):
        if not required.exists():
            raise SystemExit(f"required source input is missing: {required}")

    cargo = shutil.which("cargo")
    rustc = shutil.which("rustc")
    rustfmt = shutil.which("rustfmt")
    if cargo is None or rustc is None or rustfmt is None:
        raise SystemExit("cargo, rustc, and rustfmt are required")
    stwo_binding = resolve_stwo_binding(cargo_root)
    validate_stwo_binding(stwo_binding, args.expected_oracle_stwo_revision)

    census_text = run(
        cargo,
        "run",
        "--quiet",
        "--manifest-path",
        str(tool_manifest),
        "--",
        "--census",
        str(component_root),
        cwd=cargo_root,
    )
    geometry = parse_rewritable_census(census_text)
    order = select_components(
        parse_claim_order(claims_source.read_text(encoding="utf-8")),
        geometry,
        args.component,
        args.all_checked_rewritable,
        component_root,
    )
    sources = [component_root / f"{name}.rs" for name in order]
    run(
        cargo,
        "run",
        "--quiet",
        "--manifest-path",
        str(tool_manifest),
        "--",
        "--check",
        *(str(path) for path in sources),
        cwd=cargo_root,
    )

    source = {
        "repository": SOURCE_REPOSITORY,
        "revision": run("git", "rev-parse", "HEAD", cwd=repository_root),
        "tree": run("git", "rev-parse", "HEAD^{tree}", cwd=repository_root),
        "stwo_revision": stwo_binding.resolved_revision,
    }
    toolchain = {
        "cargo": run(cargo, "--version", cwd=cargo_root),
        "generator_cargo_lock_sha256": sha256(generator_cargo_lock),
        "generator_sha256": sha256(tool_source),
        "rustc": run(rustc, "--version", cwd=cargo_root),
        "rustfmt": run(rustfmt, "--version", cwd=cargo_root),
        "source_cargo_lock_sha256": sha256(source_cargo_lock),
    }
    output = args.output_dir.resolve()
    emit_pack(output, order, geometry, component_root, source, toolchain)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""S31 v0.1 package builder and command-line frontend."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

S31_DIR = Path(__file__).resolve().parent
ROOT = S31_DIR.parents[2]
BUILD_FILE = S31_DIR / "build.zig"
PROJECTION_SHA256 = "ceea3c293a4fcd3ca8a20ba62f4845732f8725bdf610fe6367c83adcb8be7e09"
AIR_BUNDLE_SHA256 = "7b8022b09d84db371cc433aa0fcf132f7687f2720e05e4dc9a7650c575dc02c2"
PINNED_ASSETS = (
    ROOT / "vectors/circuit/official/compiled_air_constraints_v1.bin",
    ROOT / "vectors/circuit/official/circuit_air.air_programs_v1.bin",
)
TEXT_FRONTEND_SOURCES = (
    S31_DIR / "text_frontend.py",
    S31_DIR / "s31_stdlib.py",
    S31_DIR / "s31_mathlib.py",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hash(path: Path) -> str:
    return sha256(path.read_bytes())


def compiler_fingerprint() -> str:
    """Invalidate local packages when compiler, verifier, AIR, or Zig changes."""
    digest = hashlib.sha256()
    excluded = {".zig-cache", "zig-out", "target"}
    sources = sorted(
        path for path in (ROOT / "src").rglob("*")
        if path.is_file() and path.suffix in {".zig", ".zon"}
        and not excluded.intersection(path.parts)
    )
    for path in [*sources, Path(__file__), *TEXT_FRONTEND_SOURCES, *PINNED_ASSETS]:
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(b"\0")
        digest.update(bytes.fromhex(file_hash(path)))
    digest.update(invoke("zig", "version").strip().encode())
    return digest.hexdigest()


def invoke(*args: str) -> str:
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)} failed ({result.returncode})\n{result.stdout}{result.stderr}")
    return result.stdout + result.stderr


def load_source(path: Path) -> tuple[dict, bytes]:
    data = path.read_bytes()
    source = json.loads(data)
    if source.get("version") != 1 or not isinstance(source.get("name"), str):
        raise ValueError("S31 v0.1 requires a version 1 relation source")
    return source, data


def abi(source: dict, lowering: str) -> dict:
    shapes = {item["name"]: {"kind": item["kind"], "length": item["length"]} for item in source["inputs"]}
    for node in source["nodes"]:
        op = node["op"]
        if op == "constant":
            length = node["length"]
        elif op == "sum_lanes":
            length = 1
        elif op in {"hash_blake2s", "hash_blake2s_leaf", "hash_blake2s_pair",
                    "hash_poseidon2_leaf", "hash_poseidon2_pair"}:
            length = 8
        else:
            length = shapes[node["lhs"]]["length"]
        shapes[node["name"]] = {"kind": "m31", "length": length}
    return {
        "schema": "s31-public-abi-v1",
        "encoding": "eight canonical M31 words, encoded little-endian u32; unused words are zero" if lowering.startswith("direct-") else "eight little-endian u32 words; unused words are zero",
        "public_inputs": [
            {"name": item["name"], "kind": item["kind"], "length": item["length"]}
            for item in source["inputs"] if item["visibility"] == "public"
        ],
        "public_outputs": [{"name": name, **shapes[name]} for name in source["public_outputs"]],
    }


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def standard_library_lock(explicit_import: bool) -> dict:
    from s31_stdlib import STDLIB_ABI_VERSION

    return {
        "schema": "s31-stdlib-lock-v1",
        "package": "std",
        "version": STDLIB_ABI_VERSION,
        "explicit_import": explicit_import,
        "sources": {
            name: file_hash(S31_DIR / name)
            for name in ("s31_stdlib.py", "s31_mathlib.py")
        },
    }


def build_json(source_path: Path, output: Path, lowering: str = "gate",
               library_lock: dict | None = None) -> Path:
    if lowering not in {"gate", "chip", "sparse-gate", "sparse-chip", "direct-gate", "direct-chip"}:
        raise ValueError("lowering must be gate, chip, sparse-gate, sparse-chip, direct-gate, or direct-chip")
    source_path = source_path.resolve()
    source, data = load_source(source_path)
    lock_bytes = ((json.dumps(library_lock, indent=2, sort_keys=True) + "\n").encode()
                  if library_lock is not None else None)
    lock_digest = sha256(lock_bytes) if lock_bytes is not None else None
    lock_option = (f"-Ds31-stdlib-sha256={lock_digest}",) if lock_digest is not None else ()
    compiler_sha256 = compiler_fingerprint()
    output = output.resolve()
    if output.exists():
        manifest = verify_package(output)
        if manifest["program_sha256"] != sha256(data):
            raise FileExistsError(f"package already exists for a different source: {output}")
        if manifest.get("compiler_sha256") != compiler_sha256:
            raise FileExistsError(f"package was built with different compiler inputs: {output}")
        if manifest.get("lowering", "gate") != lowering:
            raise FileExistsError(f"package was built with different lowering: {output}")
        if manifest.get("stdlib_lock_sha256") != lock_digest:
            raise FileExistsError(f"package was built with a different standard library lock: {output}")
        return output

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.build-", dir=output.parent))
    try:
        name = source["name"]
        invoke(
            "zig", "build", "--build-file", str(BUILD_FILE), "install",
            "-Doptimize=ReleaseFast", "-Ds31-version=1",
            f"-Ds31-lowering={lowering}",
            f"-Ds31-source={source_path}", f"-Ds31-name={name}",
            *lock_option,
            "--prefix", str(staging),
        )
        prover = staging / "bin" / f"s31-{name}-prover"
        verifier = staging / "bin" / f"s31-{name}-native-verifier"
        invoke(str(prover), "check")
        inspection = json.loads(invoke(str(prover), "inspect"))
        if inspection["program_sha256"] != sha256(data):
            raise RuntimeError("compiled program does not match source")
        key = {
            "schema": "s31-verification-key-v4" if lowering.startswith("direct-") else "s31-verification-key-v3" if lowering.startswith("sparse-") else "s31-verification-key-v2" if lowering == "chip" else "s31-verification-key-v1",
            "profile": inspection["profile"],
            "chip": inspection["chip"],
            "name": name,
            "program_sha256": inspection["program_sha256"],
            "canonical_ir_sha256": inspection["canonical_ir_sha256"],
            "preprocessed_root": inspection["preprocessed_root"],
            "circuit_hash": inspection["circuit_hash"],
            "padded": inspection["padded"],
            "trace_log_size": inspection["trace_log_size"],
            "projection_sha256": PROJECTION_SHA256,
            "air_bundle_sha256": AIR_BUNDLE_SHA256,
            "fri": inspection["fri"],
        }
        if lock_digest is not None:
            key["stdlib_lock_sha256"] = lock_digest
        (staging / "source.s31.json").write_bytes(data)
        write_json(staging / "verification-key.json", key)
        if lock_bytes is not None:
            (staging / "stdlib-lock.json").write_bytes(lock_bytes)
        invoke(
            "zig", "build", "--build-file", str(BUILD_FILE), "install",
            "-Doptimize=ReleaseFast", "-Ds31-version=1",
            f"-Ds31-lowering={lowering}",
            f"-Ds31-source={source_path}", f"-Ds31-name={name}",
            f"-Ds31-key={staging / 'verification-key.json'}",
            *lock_option,
            "--prefix", str(staging),
        )
        write_json(staging / "public-abi.json", abi(source, lowering))
        write_json(staging / "cost-report.json", inspection)
        artifacts = [
            "source.s31.json", "verification-key.json", "public-abi.json",
            "cost-report.json", f"bin/{prover.name}", f"bin/{verifier.name}",
        ]
        if lock_bytes is not None:
            artifacts.append("stdlib-lock.json")
        manifest = {
            "schema": "s31-package-v1",
            "name": name,
            "lowering": lowering,
            "program_sha256": sha256(data),
            "compiler_sha256": compiler_sha256,
            "canonical_ir_sha256": inspection["canonical_ir_sha256"],
            "zig_version": invoke("zig", "version").strip(),
            "optimize": "ReleaseFast",
            "artifacts": {item: file_hash(staging / item) for item in artifacts},
        }
        if lock_digest is not None:
            manifest["stdlib_lock_sha256"] = lock_digest
        write_json(staging / "manifest.json", manifest)
        os.rename(staging, output)
        return output
    except Exception:
        shutil.rmtree(staging)
        raise


def lower_text(source_path: Path) -> tuple[dict, bytes, dict]:
    from text_frontend import compile_file

    relation, source_map = compile_file(source_path)
    encoded = (json.dumps(relation, indent=2, sort_keys=True) + "\n").encode()
    return relation, encoded, source_map


def build_text(source_path: Path, output: Path, lowering: str = "gate") -> Path:
    from text_frontend import Parser

    source_path = source_path.resolve()
    output = output.resolve()
    text_data = source_path.read_bytes()
    _, normalized, source_map = lower_text(source_path)
    parser = Parser(text_data.decode(), str(source_path))
    _, circuit = parser.parse()
    library_lock = standard_library_lock(parser.stdlib_explicit)
    def type_entry(typ: object) -> dict:
        return {"kind": typ.kind, "length": typ.length, **({"family": typ.family} if typ.family else {})}
    typed_interface = {
        "schema": "s31-text-interface-v1",
        "inputs": [{"name": name, "visibility": visibility, "type": type_entry(typ)}
                   for name, typ, visibility in circuit.params],
        "output": type_entry(circuit.result),
        "stdlib": {"package": "std", "version": library_lock["version"],
                   "explicit_import": parser.stdlib_explicit},
    }
    if output.exists():
        manifest = verify_package(output)
        if manifest.get("source_text_sha256") != sha256(text_data) or manifest["program_sha256"] != sha256(normalized):
            raise FileExistsError(f"package already exists for a different source: {output}")
        if manifest["compiler_sha256"] != compiler_fingerprint() or manifest["lowering"] != lowering:
            raise FileExistsError(f"package was built with different compiler inputs or lowering: {output}")
        return output
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{output.name}.text-", dir=output.parent) as directory:
        staging_root = Path(directory)
        normalized_path = staging_root / "normalized.s31.json"
        normalized_path.write_bytes(normalized)
        package = build_json(normalized_path, staging_root / "package", lowering, library_lock)
        (package / "source.s31").write_bytes(text_data)
        write_json(package / "source-map.json", {
            "schema": "s31-text-source-map-v1", "source_sha256": sha256(text_data),
            "nodes": source_map,
        })
        write_json(package / "typed-interface.json", typed_interface)
        manifest_path = package / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["source_text_sha256"] = sha256(text_data)
        manifest["text_frontend_version"] = 1
        for name in ("source.s31", "source-map.json", "typed-interface.json"):
            manifest["artifacts"][name] = file_hash(package / name)
        write_json(manifest_path, manifest)
        os.rename(package, output)
    return output


def build(source_path: Path, output: Path, lowering: str = "gate") -> Path:
    if source_path.suffix == ".s31":
        return build_text(source_path, output, lowering)
    return build_json(source_path, output, lowering)


def verify_package(package: Path) -> dict:
    manifest = json.loads((package / "manifest.json").read_text())
    if manifest.get("schema") != "s31-package-v1":
        raise ValueError("invalid S31 package manifest")
    for name, expected in manifest["artifacts"].items():
        path = (package / name).resolve()
        if not path.is_relative_to(package.resolve()) or file_hash(path) != expected:
            raise ValueError(f"S31 package artifact changed: {name}")
    if file_hash(package / "source.s31.json") != manifest["program_sha256"]:
        raise ValueError("S31 package source changed")
    if "stdlib_lock_sha256" in manifest:
        if "stdlib-lock.json" not in manifest["artifacts"] or file_hash(package / "stdlib-lock.json") != manifest["stdlib_lock_sha256"]:
            raise ValueError("S31 package standard library lock changed")
        key = json.loads((package / "verification-key.json").read_text())
        if key.get("stdlib_lock_sha256") != manifest["stdlib_lock_sha256"]:
            raise ValueError("S31 verification key has the wrong standard library lock")
    if "source_text_sha256" in manifest:
        required = {"source.s31", "source-map.json"}
        if manifest.get("text_frontend_version") == 1:
            required.add("typed-interface.json")
        if not required.issubset(manifest["artifacts"]):
            raise ValueError("S31 text package is missing source artifacts")
        if file_hash(package / "source.s31") != manifest["source_text_sha256"]:
            raise ValueError("S31 package text source changed")
        source_map = json.loads((package / "source-map.json").read_text())
        if source_map.get("source_sha256") != manifest["source_text_sha256"]:
            raise ValueError("S31 package source map does not match text source")
    return manifest


def package_for(source_or_package: Path) -> Path:
    if source_or_package.is_dir():
        verify_package(source_or_package)
        return source_or_package.resolve()
    if source_or_package.suffix == ".s31":
        data = source_or_package.read_bytes()
    else:
        _, data = load_source(source_or_package)
    digest = sha256(data)
    return build(source_or_package, ROOT / "zig-out/s31/mvp-cache" / f"{digest}-{compiler_fingerprint()}")


def explain(package: Path) -> dict:
    verify_package(package)
    report = json.loads((package / "cost-report.json").read_text())
    relation = json.loads((package / "source.s31.json").read_text())
    locations = (json.loads((package / "source-map.json").read_text())["nodes"]
                 if (package / "source-map.json").exists() else {})
    operations = {item["name"]: item["op"] for item in relation["nodes"]}
    components = ("qm31", "m31_to_u32", "eq", "triple_xor", "blake_g")
    nodes = []
    groups = {}
    for item in report["source_map"]:
        name = item["name"]
        entry = {
            "name": name,
            "op": operations.get(name, "input"),
            "source": locations.get(name),
            "gate_rows": {component: item[f"{component}_end"] - item[f"{component}_start"]
                          for component in components},
            "canonical_id": item["canonical_id"],
        }
        nodes.append(entry)
        if entry["source"] is not None:
            key = (entry["source"]["line"], entry["source"]["column"])
            if key not in groups:
                groups[key] = {"source": entry["source"], "nodes": [],
                               "gate_rows": {component: 0 for component in components},
                               "chip_rows": 0, "_ids": set()}
            group = groups[key]
            group["nodes"].append(name)
            if entry["canonical_id"] not in group["_ids"]:
                group["_ids"].add(entry["canonical_id"])
                for component in components:
                    group["gate_rows"][component] += entry["gate_rows"][component]
                if entry["op"] == "repeat" and report["chip"] is not None:
                    group["chip_rows"] += report["chip"]["rounds"]
    source_expressions = []
    for group in groups.values():
        del group["_ids"]
        source_expressions.append(group)
    return {
        "name": report["name"], "profile": report["profile"],
        "chip": report["chip"], "raw": report["raw"], "padded": report["padded"],
        "preprocessed_cells": report["preprocessed_cells"],
        "preprocessed_columns": report["preprocessed_columns"],
        "canonical_ir_sha256": report["canonical_ir_sha256"], "nodes": nodes,
        "source_expressions": source_expressions,
        "typed_interface": (json.loads((package / "typed-interface.json").read_text())
                            if (package / "typed-interface.json").exists() else None),
    }


def equations(package: Path) -> dict:
    """Explain node semantics; this is not a dump of the pinned circuit AIR."""
    report = explain(package)
    relation = json.loads((package / "source.s31.json").read_text())
    cost_nodes = {node["name"]: node for node in report["nodes"]}
    shapes = {item["name"]: (item["kind"], item["length"]) for item in relation["inputs"]}
    nodes = []
    hashes = {
        "hash_blake2s", "hash_blake2s_leaf", "hash_blake2s_pair",
        "hash_poseidon2_leaf", "hash_poseidon2_pair",
    }
    for node in relation["nodes"]:
        name, op = node["name"], node["op"]
        field_equations: list[str] = []
        functional_spec: str | None = None
        notes: list[str] = []
        if op == "constant":
            shape = ("m31", node["length"])
            field_equations.append(f"{name}[j] - {node['constant']} = 0")
        elif op == "sum_lanes":
            shape = ("m31", 1)
            length = shapes[node["lhs"]][1]
            field_equations.append(f"{name}[0] - sum({node['lhs']}[j] for j=0..{length - 1}) = 0")
        elif op in hashes:
            shape = ("m31", 8)
            arguments = ", ".join(node[key] for key in ("lhs", "rhs") if key in node)
            functional_spec = f"{name} = {op}({arguments})"
            notes.append("The hash's internal circuit equations are not expanded here.")
        else:
            shape = ("m31", shapes[node["lhs"]][1])
            lhs = f"{node['lhs']}[j]"
            rhs = f"{node['rhs']}[j]" if "rhs" in node else ""
            constant = node.get("constant")
            if op == "cast_m31":
                field_equations.append(f"{name}[j] - {lhs} = 0")
                notes.append("The u16 input has a separate range obligation.")
            elif op == "add":
                field_equations.append(f"{name}[j] - {lhs} - {rhs} = 0")
            elif op == "mul":
                field_equations.append(f"{name}[j] - {lhs} * {rhs} = 0")
            elif op == "add_const":
                field_equations.append(f"{name}[j] - {lhs} - {constant} = 0")
            elif op == "mul_const":
                field_equations.append(f"{name}[j] - {lhs} * {constant} = 0")
            elif op == "select":
                selector = f"{node['selector']}[0]"
                field_equations.extend((
                    f"{selector} * ({selector} - 1) = 0",
                    f"{name}[j] - (1 - {selector}) * {lhs} - {selector} * {rhs} = 0",
                ))
            elif op == "repeat":
                functional_spec = f"{name}[j] = F^{node['rounds']}({lhs})"
                for index, step in enumerate(node["body"], start=1):
                    previous = f"v{index - 1}"
                    if step["op"] == "square":
                        expression = f"{previous} * {previous}"
                    elif step["op"] == "add_const":
                        expression = f"{previous} + {step['constant']}"
                    else:
                        expression = f"{previous} * {step['constant']}"
                    notes.append(f"F step {index}: v{index} = {expression} (v0 is the current state)")
                notes.append("The selected profile either unrolls this body or uses the pinned step AIR chip.")
            else:
                functional_spec = f"{name} = {op}({lhs})"
                notes.append("No source-level equation is available for this operation.")
        shapes[name] = shape
        cost = cost_nodes.get(name, {})
        nodes.append({
            "name": name, "op": op,
            "output": {"kind": shape[0], "length": shape[1]},
            "field_equations": field_equations,
            "functional_spec": functional_spec,
            "notes": notes,
            "index": "j ranges over the output array" if shape[1] > 1 else "j=0",
            "source": cost.get("source"),
            "canonical_id": cost.get("canonical_id"),
            "builder_gate_rows": cost.get("gate_rows"),
            "expanded_air_terms": False,
        })
    assertions = [f"{item['lhs']}[j] - {item['rhs']}[j] = 0"
                  for item in relation["assertions"]]
    return {
        "schema": "s31-semantic-equations-v1",
        "program": relation["name"],
        "field_modulus": 2147483647,
        "scope": ("Source-level field equations. The pinned circuit AIR also constrains "
                  "wire lookup closure, public binding, range/bit rules, and profile-specific rows. "
                  "Builder gate counts are not physical AIR row ownership."),
        "profile": report["profile"],
        "nodes": nodes,
        "assertions": assertions,
        "public_inputs": [item["name"] for item in relation["inputs"]
                          if item["visibility"] == "public"],
        "public_outputs": relation["public_outputs"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(prog="s31", description="S31 circuit relation compiler")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("check", "inspect", "explain", "equations", "run"):
        help_text = {
            "explain": "show canonical nodes, source positions, and builder gate counts",
            "equations": "show source-level field equations (not expanded AIR terms)",
        }.get(command)
        sub = commands.add_parser(command, help=help_text)
        sub.add_argument("source_or_package", type=Path)
        if command == "run":
            sub.add_argument("assignment", type=Path)
    sub = commands.add_parser("build")
    sub.add_argument("source", type=Path)
    sub.add_argument("--out", type=Path, required=True)
    sub.add_argument("--lowering", choices=("gate", "chip", "sparse-gate", "sparse-chip", "direct-gate", "direct-chip"), default="gate")
    sub = commands.add_parser("lower", help="lower .s31 text to normalized relation JSON")
    sub.add_argument("source", type=Path)
    sub.add_argument("--out", type=Path)
    sub = commands.add_parser("prove")
    sub.add_argument("package", type=Path)
    sub.add_argument("assignment", type=Path)
    sub.add_argument("proof", type=Path)
    sub = commands.add_parser("verify")
    sub.add_argument("package", type=Path)
    sub.add_argument("proof", type=Path)
    sub.add_argument("--statement", type=Path)
    args = parser.parse_args()

    if args.command == "lower":
        if args.source.suffix != ".s31":
            raise ValueError("lower expects a .s31 text file")
        _, normalized, _ = lower_text(args.source)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_bytes(normalized)
            print(args.out)
        else:
            sys.stdout.buffer.write(normalized)
        return
    if args.command == "build":
        print(build(args.source, args.out, args.lowering))
        return
    if args.command == "explain":
        print(json.dumps(explain(package_for(args.source_or_package)), indent=2, sort_keys=True))
        return
    if args.command == "equations":
        print(json.dumps(equations(package_for(args.source_or_package)), indent=2, sort_keys=True))
        return
    if args.command in ("check", "inspect", "run"):
        package = package_for(args.source_or_package)
        manifest = verify_package(package)
        executable = package / "bin" / f"s31-{manifest['name']}-prover"
        extra = (str(args.assignment.resolve()),) if args.command == "run" else ()
        print(invoke(str(executable), args.command, *extra), end="")
        return

    package = args.package.resolve()
    manifest = verify_package(package)
    if args.command == "prove":
        assignment = json.loads(args.assignment.read_text())
        statement = {
            "public_inputs": assignment["public_inputs"],
            "public_outputs": assignment["public_outputs"],
        }
        proof = args.proof.resolve()
        proof.parent.mkdir(parents=True, exist_ok=True)
        executable = package / "bin" / f"s31-{manifest['name']}-prover"
        print(invoke(str(executable), "prove", str(args.assignment.resolve()), str(proof)), end="")
        statement_path = Path(str(proof) + ".statement.json")
        write_json(statement_path, statement)
        print(f"public statement: {statement_path}")
    elif args.command == "verify":
        proof = args.proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(proof) + ".statement.json")
        executable = package / "bin" / f"s31-{manifest['name']}-native-verifier"
        print(invoke(str(executable), str(proof), str(statement), str(package / "verification-key.json")), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
        print(f"s31: {exc}", file=sys.stderr)
        raise SystemExit(1)

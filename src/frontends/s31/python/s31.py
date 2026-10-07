#!/usr/bin/env python3
"""S31 v0.1 package builder and command-line frontend."""

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import argparse
import copy
import hashlib
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

S31_DIR = S31_SOURCE_ROOT
ROOT = S31_DIR.parents[2]
BUILD_FILE = S31_DIR / "build.zig"
PROJECTION_SHA256 = "ceea3c293a4fcd3ca8a20ba62f4845732f8725bdf610fe6367c83adcb8be7e09"
AIR_BUNDLE_SHA256 = "7b8022b09d84db371cc433aa0fcf132f7687f2720e05e4dc9a7650c575dc02c2"
PINNED_ASSETS = (
    ROOT / "vectors/circuit/official/compiled_air_constraints_v1.bin",
    ROOT / "vectors/circuit/official/circuit_air.air_programs_v1.bin",
)
TEXT_FRONTEND_SOURCES = (
    S31_DIR / "python/text_frontend.py",
    S31_DIR / "python/s31_stdlib.py",
    S31_DIR / "python/s31_mathlib.py",
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
        if op in {"constant", "array_slice"}:
            length = node["length"]
        elif op in {"sum_lanes", "u256_le", "u32_lt", "array_get"}:
            length = 1
        elif op == "array_concat":
            length = shapes[node["lhs"]]["length"] + shapes[node["rhs"]]["length"]
        elif op in {"hash_sha256d_header", "bitcoin_target_mainnet", "bitcoin_block_work", "bitcoin_prev_hash", "bitcoin_genesis_hash_mainnet"}:
            length = 16
        elif op in {"bitcoin_header_bits", "bitcoin_header_time"}:
            length = 2
        elif op in {"hash_blake2s", "hash_blake2s_leaf", "hash_blake2s_pair",
                    "hash_poseidon2_leaf", "hash_poseidon2_pair"}:
            length = 8
        else:
            length = shapes[node["lhs"]]["length"]
        shapes[node["name"]] = {"kind": (shapes[node["lhs"]]["kind"] if op in {"array_get", "array_concat", "array_slice", "select"} else
                                         "u16" if op in {"u256_add", "u256_add_checked", "u256_sub", "u256_sub_checked", "hash_sha256d_header", "bitcoin_target_mainnet", "bitcoin_block_work", "bitcoin_prev_hash", "bitcoin_header_bits", "bitcoin_header_time", "bitcoin_genesis_hash_mainnet"} else "m31"), "length": length}
    return {
        "schema": "s31-public-abi-v1",
        "encoding": "eight canonical M31 words, encoded little-endian u32; unused words are zero" if lowering.startswith("direct-") or lowering in {"sha-shift", "sha-fused"} else "eight little-endian u32 words; unused words are zero",
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
            name: file_hash(S31_DIR / "python" / name)
            for name in ("s31_stdlib.py", "s31_mathlib.py")
        },
    }


def build_json(source_path: Path, output: Path, lowering: str = "gate",
               library_lock: dict | None = None, fri_fold_step: int = 1) -> Path:
    if lowering not in {"gate", "chip", "sparse-gate", "sparse-chip", "sparse-wide-gate", "direct-gate", "direct-chip", "sha-joint", "sha-shift", "sha-fused"}:
        raise ValueError("invalid S31 lowering")
    if type(fri_fold_step) is not int or fri_fold_step not in (1, 4) or (fri_fold_step == 4 and lowering not in {"gate", "sparse-wide-gate"}):
        raise ValueError("FRI fold step 4 requires gate or sparse-wide-gate lowering; supported steps are 1 and 4")
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
        if manifest.get("fri_fold_step", 1) != fri_fold_step:
            raise FileExistsError(f"package was built with a different FRI fold step: {output}")
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
            f"-Ds31-lowering={lowering}", f"-Ds31-fri-fold-step={fri_fold_step}",
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
            "schema": "s31-verification-key-sha-fused-v4" if lowering == "sha-fused" else "s31-verification-key-sha-shift-v3" if lowering == "sha-shift" else "s31-verification-key-sha-joint-v1" if lowering == "sha-joint" else "s31-verification-key-v4" if lowering.startswith("direct-") else "s31-verification-key-v5" if lowering == "sparse-wide-gate" else "s31-verification-key-v3" if lowering.startswith("sparse-") else "s31-verification-key-v2" if lowering == "chip" else "s31-verification-key-v1",
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
        if lowering == "sha-joint":
            key["sha_joint"] = inspection["sha_joint"]
        if lowering == "sha-shift":
            key["sha_shift"] = inspection["sha_shift"]
        if lowering == "sha-fused":
            key["sha_fused"] = inspection["sha_fused"]
        (staging / "source.s31.json").write_bytes(data)
        write_json(staging / "verification-key.json", key)
        if lock_bytes is not None:
            (staging / "stdlib-lock.json").write_bytes(lock_bytes)
        recursive_option: tuple[str, ...] = ()
        recursive_next_option: tuple[str, ...] = ()
        fold_option: tuple[str, ...] = ()
        state_fold_option: tuple[str, ...] = ()
        if lowering in {"gate", "sparse-wide-gate"}:
            recursive_key = staging / "recursive-verification-key.json"
            invoke(str(prover), "recurse-keygen", str(staging / "verification-key.json"),
                   str(recursive_key))
            recursive_option = (f"-Ds31-recursive-key={recursive_key}",)
            recursive_next_key = staging / "recursive-verification-key-level2.json"
            invoke(str(prover), "recurse-keygen-next", str(staging / "verification-key.json"),
                   str(recursive_key), str(recursive_next_key))
            recursive_next_option = (f"-Ds31-recursive-next-key={recursive_next_key}",)
            if lowering == "sparse-wide-gate":
                fold_key = staging / "fixed-fold-verification-key.json"
                invoke(str(prover), "wide-fold-keygen", str(staging / "verification-key.json"),
                       str(recursive_key), str(recursive_next_key), str(fold_key))
                fold_option = (f"-Ds31-fold-key={fold_key}",)
        if lowering == "gate":
            fold_key = staging / "fixed-fold-verification-key.json"
            invoke(str(prover), "fold-keygen", str(staging / "verification-key.json"),
                   str(recursive_key), str(fold_key))
            fold_option = (f"-Ds31-fold-key={fold_key}",)
            if inspection.get("state_fold_step") is not None:
                state_fold_key = staging / "state-fold-verification-key.json"
                invoke(str(prover), "state-fold-keygen", str(staging / "verification-key.json"),
                       str(recursive_key), str(state_fold_key))
                state_fold_option = (f"-Ds31-state-fold-key={state_fold_key}",)
        invoke(
            "zig", "build", "--build-file", str(BUILD_FILE), "install",
            "-Doptimize=ReleaseFast", "-Ds31-version=1",
            f"-Ds31-lowering={lowering}", f"-Ds31-fri-fold-step={fri_fold_step}",
            f"-Ds31-source={source_path}", f"-Ds31-name={name}",
            f"-Ds31-key={staging / 'verification-key.json'}",
            *recursive_option,
            *recursive_next_option,
            *fold_option,
            *state_fold_option,
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
        if recursive_option:
            artifacts.append("recursive-verification-key.json")
        if recursive_next_option:
            artifacts.append("recursive-verification-key-level2.json")
        if fold_option:
            artifacts.append("fixed-fold-verification-key.json")
            if state_fold_option:
                artifacts.append("state-fold-verification-key.json")
        manifest = {
            "schema": "s31-package-v1",
            "name": name,
            "lowering": lowering,
            "fri_fold_step": fri_fold_step,
            "program_sha256": sha256(data),
            "compiler_sha256": compiler_sha256,
            "canonical_ir_sha256": inspection["canonical_ir_sha256"],
            "zig_version": invoke("zig", "version").strip(),
            "optimize": "ReleaseFast",
            "artifacts": {item: file_hash(staging / item) for item in artifacts},
        }
        if recursive_option:
            manifest["recursive_fri_fold_step"] = 4 if lowering == "sparse-wide-gate" else fri_fold_step
        if fold_option:
            manifest["capabilities"] = ["s31-fixed-fold-batch-v1"]
        if state_fold_option:
            manifest.setdefault("capabilities", []).append("s31-state-fold-batch-v2")
        if lock_digest is not None:
            manifest["stdlib_lock_sha256"] = lock_digest
        if source_path.read_bytes() != data or compiler_fingerprint() != compiler_sha256:
            raise RuntimeError("S31 source or compiler inputs changed during package build")
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


def text_interface(circuit: object, explicit_import: bool) -> dict:
    def type_entry(typ: object) -> dict:
        return {"kind": typ.kind, "length": typ.length,
                **({"family": typ.family} if typ.family else {})}

    return {
        "schema": "s31-text-interface-v1",
        "inputs": [{"name": name, "visibility": visibility, "type": type_entry(typ)}
                   for name, typ, visibility in circuit.params],
        "output": type_entry(circuit.result),
        "stdlib": {"package": "std", "version": standard_library_lock(explicit_import)["version"],
                   "explicit_import": explicit_import},
    }


def build_text(source_path: Path, output: Path, lowering: str = "gate", fri_fold_step: int = 1) -> Path:
    from text_frontend import Parser

    source_path = source_path.resolve()
    output = output.resolve()
    text_data = source_path.read_bytes()
    _, normalized, source_map = lower_text(source_path)
    parser = Parser(text_data.decode(), str(source_path))
    _, circuit = parser.parse()
    library_lock = standard_library_lock(parser.stdlib_explicit)
    typed_interface = text_interface(circuit, parser.stdlib_explicit)
    if output.exists():
        manifest = verify_package(output)
        if manifest.get("source_text_sha256") != sha256(text_data) or manifest["program_sha256"] != sha256(normalized):
            raise FileExistsError(f"package already exists for a different source: {output}")
        if manifest["compiler_sha256"] != compiler_fingerprint() or manifest["lowering"] != lowering:
            raise FileExistsError(f"package was built with different compiler inputs or lowering: {output}")
        if manifest.get("fri_fold_step", 1) != fri_fold_step:
            raise FileExistsError(f"package was built with a different FRI fold step: {output}")
        return output
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{output.name}.text-", dir=output.parent) as directory:
        staging_root = Path(directory)
        normalized_path = staging_root / "normalized.s31.json"
        normalized_path.write_bytes(normalized)
        package = build_json(normalized_path, staging_root / "package", lowering, library_lock, fri_fold_step)
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
        if source_path.read_bytes() != text_data or manifest["compiler_sha256"] != compiler_fingerprint():
            raise RuntimeError("S31 text source or compiler inputs changed during package build")
        write_json(manifest_path, manifest)
        os.rename(package, output)
    return output


def build(source_path: Path, output: Path, lowering: str = "gate", fri_fold_step: int = 1) -> Path:
    if source_path.suffix == ".s31":
        return build_text(source_path, output, lowering, fri_fold_step)
    return build_json(source_path, output, lowering, fri_fold_step=fri_fold_step)


def verify_package(package: Path) -> dict:
    manifest = json.loads((package / "manifest.json").read_text())
    if manifest.get("schema") != "s31-package-v1":
        raise ValueError("invalid S31 package manifest")
    name = manifest.get("name")
    artifacts = manifest.get("artifacts")
    if not isinstance(name, str) or not name or not isinstance(artifacts, dict):
        raise ValueError("incomplete S31 package manifest")
    capabilities = manifest.get("capabilities", [])
    if (not isinstance(capabilities, list) or any(not isinstance(item, str) for item in capabilities) or
            (any(item in capabilities for item in ("s31-state-fold-batch-v1", "s31-state-fold-batch-v2")) and
             "state-fold-verification-key.json" not in artifacts) or
            ("s31-fixed-fold-batch-v1" in capabilities and
             (manifest.get("lowering") not in {"gate", "sparse-wide-gate"} or
              "fixed-fold-verification-key.json" not in artifacts))):
        raise ValueError("invalid S31 package capabilities")
    required_artifacts = {
        "source.s31.json", "verification-key.json", "public-abi.json",
        "cost-report.json", f"bin/s31-{name}-prover",
        f"bin/s31-{name}-native-verifier",
    }
    if not required_artifacts.issubset(artifacts):
        raise ValueError("S31 package is missing required artifacts")
    fri_fold_step = manifest.get("fri_fold_step", 1)
    if (type(fri_fold_step) is not int or fri_fold_step not in (1, 4) or
            (fri_fold_step == 4 and manifest.get("lowering") not in {"gate", "sparse-wide-gate"})):
        raise ValueError("invalid S31 package FRI fold step")
    if manifest.get("lowering") in {"gate", "sparse-wide-gate"}:
        if not {"recursive-verification-key.json", "recursive-verification-key-level2.json"}.issubset(artifacts):
            raise ValueError("recursive package is missing its verification keys")
        recursive_key = json.loads((package / "recursive-verification-key.json").read_text())
        recursive_next_key = json.loads((package / "recursive-verification-key-level2.json").read_text())
        wide = manifest["lowering"] == "sparse-wide-gate"
        expected_schema = "s31-recursive-verification-key-v3" if wide else "s31-recursive-verification-key-v2"
        expected_recursive_step = 4 if wide else fri_fold_step
        actual_recursive_step = manifest.get("recursive_fri_fold_step")
        if (wide and (type(actual_recursive_step) is not int or actual_recursive_step != 4)) or (
                not wide and actual_recursive_step is not None and
                (type(actual_recursive_step) is not int or actual_recursive_step != expected_recursive_step)):
            raise ValueError("S31 recursive FRI schedule does not match the package profile")
        first_outer_step = recursive_key.get("outer_fri_fold_step")
        second_outer_step = recursive_next_key.get("outer_fri_fold_step")
        if (wide and (type(first_outer_step) is not int or first_outer_step != 4 or
                      type(second_outer_step) is not int or second_outer_step != 4)) or (
                not wide and (first_outer_step is not None or second_outer_step is not None)):
            raise ValueError("S31 recursive keys have an invalid FRI schedule")
        if (recursive_key.get("schema") != expected_schema or
                recursive_key.get("child_key_sha256") != file_hash(package / "verification-key.json") or
                recursive_key.get("projection_sha256") != PROJECTION_SHA256 or
                recursive_key.get("air_bundle_sha256") != AIR_BUNDLE_SHA256):
            raise ValueError("S31 recursive key does not match the child key and pinned AIR")
        if (recursive_next_key.get("schema") != expected_schema or
                recursive_next_key.get("child_key_sha256") != file_hash(package / "recursive-verification-key.json") or
                recursive_next_key.get("projection_sha256") != PROJECTION_SHA256 or
                recursive_next_key.get("air_bundle_sha256") != AIR_BUNDLE_SHA256):
            raise ValueError("S31 level-2 recursive key does not match its child key and pinned AIR")
        if wide:
            if "fixed-fold-verification-key.json" not in artifacts:
                raise ValueError("sparse-wide package is missing its fixed-fold key")
            fold_key = json.loads((package / "fixed-fold-verification-key.json").read_text())
            if (fold_key.get("schema") != "s31-fixed-fold-verification-key-v4" or
                    type(fold_key.get("outer_fri_fold_step")) is not int or
                    fold_key["outer_fri_fold_step"] != 4 or
                    fold_key.get("base_recursive_key_sha256") != file_hash(package / "recursive-verification-key-level2.json") or
                    fold_key.get("projection_sha256") != PROJECTION_SHA256 or
                    fold_key.get("air_bundle_sha256") != AIR_BUNDLE_SHA256):
                raise ValueError("S31 wide fixed-fold key does not match its base key and pinned AIR")
    if manifest.get("lowering") == "gate":
        if not {"recursive-verification-key.json", "recursive-verification-key-level2.json", "fixed-fold-verification-key.json"}.issubset(artifacts):
            raise ValueError("gate package is missing its recursive verification keys")
        fold_key = json.loads((package / "fixed-fold-verification-key.json").read_text())
        if (fold_key.get("schema") != "s31-fixed-fold-verification-key-v3" or
                fold_key.get("base_recursive_key_sha256") != file_hash(package / "recursive-verification-key.json") or
                fold_key.get("projection_sha256") != PROJECTION_SHA256 or
                fold_key.get("air_bundle_sha256") != AIR_BUNDLE_SHA256):
            raise ValueError("S31 fold key does not match its base key and pinned AIR")
        report = json.loads((package / "cost-report.json").read_text())
        if "state-fold-verification-key.json" in artifacts:
            state_fold_key = json.loads((package / "state-fold-verification-key.json").read_text())
            fold_step = report.get("state_fold_step")
            common_valid = (state_fold_key.get("base_recursive_key_sha256") == file_hash(package / "recursive-verification-key.json") and
                            state_fold_key.get("projection_sha256") == PROJECTION_SHA256 and
                            state_fold_key.get("air_bundle_sha256") == AIR_BUNDLE_SHA256)
            # The v1 shape remains readable for packages built before the
            # general step compiler; its installed verifier is sealed to v1.
            if state_fold_key.get("schema") == "s31-state-fold-verification-key-v1":
                old_step = report.get("repeated_step")
                valid_step = (isinstance(old_step, dict) and
                              state_fold_key.get("source_rounds") == old_step.get("rounds") and
                              state_fold_key.get("step_constant") == old_step.get("constant"))
            else:
                valid_step = (state_fold_key.get("schema") in
                              ("s31-state-fold-verification-key-v2", "s31-state-fold-verification-key-v3") and
                              isinstance(fold_step, dict) and
                              state_fold_key.get("source_rounds") == fold_step.get("rounds") and
                              state_fold_key.get("step_body") == fold_step.get("body") and
                              (state_fold_key.get("schema") != "s31-state-fold-verification-key-v3" or
                               state_fold_key.get("counter_bits") == 32))
            if not common_valid or not valid_step:
                raise ValueError("S31 state-fold key does not match its base key and pinned AIR")
        elif any(report.get(name) is not None for name in ("state_fold_step", "repeated_step")):
            raise ValueError("supported recurrence package is missing its state-fold key")
    for name, expected in artifacts.items():
        if not isinstance(name, str) or not isinstance(expected, str):
            raise ValueError("invalid S31 package artifact entry")
        path = (package / name).resolve()
        if not path.is_relative_to(package.resolve()) or file_hash(path) != expected:
            raise ValueError(f"S31 package artifact changed: {name}")
    if file_hash(package / "source.s31.json") != manifest["program_sha256"]:
        raise ValueError("S31 package source changed")
    key = json.loads((package / "verification-key.json").read_text())
    fri_config = key.get("fri")
    if (not isinstance(fri_config, dict) or
            key.get("name") != manifest["name"] or
            key.get("program_sha256") != manifest["program_sha256"] or
            key.get("canonical_ir_sha256") != manifest.get("canonical_ir_sha256") or
            fri_config.get("fold_step") != fri_fold_step):
        raise ValueError("S31 package key does not match manifest")
    report = json.loads((package / "cost-report.json").read_text())
    inspected_key_fields = (
        "program_sha256", "canonical_ir_sha256", "profile", "chip",
        "preprocessed_root", "circuit_hash", "padded", "trace_log_size", "fri",
    )
    if any(report.get(field) != key.get(field) for field in inspected_key_fields):
        raise ValueError("S31 package cost report does not match key")
    if manifest.get("lowering") == "sha-joint":
        joint = key.get("sha_joint")
        if (key.get("schema") != "s31-verification-key-sha-joint-v1" or
                key.get("profile") != "sha-joint-v1" or key.get("chip") is not None or
                not isinstance(joint, dict) or report.get("sha_joint") != joint or
                joint.get("proof_envelope") != "S31NAT6S" or
                joint.get("sha_calls") != 3 or joint.get("claimed_sums") != 12 or
                len(joint.get("gate_addresses", [])) != 56):
            raise ValueError("invalid SHA joint package key")
    if manifest.get("lowering") == "sha-shift":
        shift = key.get("sha_shift")
        if (key.get("schema") != "s31-verification-key-sha-shift-v3" or
                key.get("profile") != "sha-shift-v3" or key.get("chip") is not None or
                not isinstance(shift, dict) or report.get("sha_shift") != shift or
                shift.get("proof_envelope") != "S31SCJ03" or
                shift.get("sha_calls") != 3 or shift.get("component_count") != 24 or
                shift.get("claimed_sums") != 15 or
                len(shift.get("gate_addresses", [])) != 56):
            raise ValueError("invalid SHA shift package key")
    if manifest.get("lowering") == "sha-fused":
        fused = key.get("sha_fused")
        if (key.get("schema") != "s31-verification-key-sha-fused-v4" or
                key.get("profile") != "sha-fused-v4" or key.get("chip") is not None or
                not isinstance(fused, dict) or report.get("sha_fused") != fused or
                fused.get("proof_envelope") != "S31FCJ04" or
                fused.get("sha_calls") != 3 or fused.get("component_count") != 14 or
                fused.get("claimed_sums") != 10 or
                len(fused.get("gate_addresses", [])) != 56):
            raise ValueError("invalid SHA fused package key")
    manifest_lock = manifest.get("stdlib_lock_sha256")
    key_lock = key.get("stdlib_lock_sha256")
    has_lock_artifact = "stdlib-lock.json" in manifest["artifacts"]
    if manifest_lock is not None or key_lock is not None or has_lock_artifact:
        if manifest_lock is None or key_lock != manifest_lock or not has_lock_artifact:
            raise ValueError("S31 package standard library lock is incomplete")
        if file_hash(package / "stdlib-lock.json") != manifest_lock:
            raise ValueError("S31 package standard library lock changed")
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
        _, encoded, expected_locations = lower_text(package / "source.s31")
        if encoded != (package / "source.s31.json").read_bytes():
            raise ValueError("S31 text source does not lower to the sealed relation")
        if source_map != {"schema": "s31-text-source-map-v1",
                          "source_sha256": manifest["source_text_sha256"],
                          "nodes": expected_locations}:
            raise ValueError("S31 text source map does not match compiler output")
        if manifest.get("text_frontend_version") == 1:
            from text_frontend import Parser

            parser = Parser((package / "source.s31").read_text(), str(package / "source.s31"))
            _, circuit = parser.parse()
            expected_interface = text_interface(circuit, parser.stdlib_explicit)
            actual_interface = json.loads((package / "typed-interface.json").read_text())
            if manifest_lock is None:
                expected_interface.pop("stdlib")
            if actual_interface != expected_interface:
                raise ValueError("S31 typed interface does not match text source")
            if manifest_lock is not None:
                lock = json.loads((package / "stdlib-lock.json").read_text())
                sources = lock.get("sources", {})
                if (lock.get("schema") != "s31-stdlib-lock-v1" or
                        lock.get("package") != "std" or
                        lock.get("version") != expected_interface["stdlib"]["version"] or
                        lock.get("explicit_import") != parser.stdlib_explicit or
                        not isinstance(sources, dict) or
                        set(sources) != {"s31_stdlib.py", "s31_mathlib.py"} or
                        any(not isinstance(value, str) or len(value) != 64 or
                                any(char not in "0123456789abcdef" for char in value)
                                for value in sources.values())):
                    raise ValueError("S31 standard library lock does not match text source")
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
        elif op == "array_get":
            shape = (shapes[node["lhs"]][0], 1)
            field_equations.append(f"{name}[0] - {node['lhs']}[{node['index']}] = 0")
            notes.append("This is a view of an already constrained array position; it introduces no independent witness value.")
        elif op == "array_slice":
            shape = (shapes[node["lhs"]][0], node["length"])
            field_equations.append(
                f"{name}[j] - {node['lhs']}[{node['index']}+j] = 0, 0 <= j < {node['length']}")
            notes.append("Aligned packed words can alias source wires; shifted views use constrained coordinate unpacking and repacking.")
        elif op == "array_concat":
            left = shapes[node["lhs"]]
            right = shapes[node["rhs"]]
            shape = (left[0], left[1] + right[1])
            field_equations.extend((
                f"{name}[j] - {node['lhs']}[j] = 0, 0 <= j < {left[1]}",
                f"{name}[{left[1]}+j] - {node['rhs']}[j] = 0, 0 <= j < {right[1]}",
            ))
            notes.append("This is a concatenated view of constrained positions; it introduces no independent witness values.")
        elif op in {"u256_add", "u256_le", "u256_add_checked", "u256_sub", "u256_sub_checked"}:
            shape = ("u16", 16) if op in {"u256_add", "u256_add_checked", "u256_sub", "u256_sub_checked"} else ("m31", 1)
            functional_spec = f"{name} = {op}({node['lhs']}, {node['rhs']})"
            if op in {"u256_add", "u256_add_checked"}:
                field_equations.extend((
                    f"c[0] = 0; c[i] in {{0,1}}; {name}[i] in [0,65535]",
                    f"{node['lhs']}[i] + {node['rhs']}[i] + c[i] - {name}[i] - 65536*c[i+1] = 0",
                    ("the final carry is zero (checked addition)" if op == "u256_add_checked"
                     else "the final carry is discarded (addition modulo 2^256)"),
                ))
            elif op in {"u256_sub", "u256_sub_checked"}:
                field_equations.extend((
                    f"b[0] = 0; b[i] in {{0,1}}; {name}[i] in [0,65535]",
                    f"{node['lhs']}[i] + 65536*b[i+1] - {node['rhs']}[i] - b[i] - {name}[i] = 0",
                    ("the final borrow is zero (checked subtraction)" if op == "u256_sub_checked"
                     else "the final borrow is discarded (subtraction modulo 2^256)"),
                ))
            else:
                field_equations.extend((
                    "b[0] = 0; b[i] in {0,1}; d[i] in [0,65535]",
                    f"{node['rhs']}[i] + 65536*b[i+1] - {node['lhs']}[i] - b[i] - d[i] = 0",
                    f"{name}[0] = 1 - b[16]",
                ))
            notes.append("These are limb equations; the circuit also range checks each digit and constrains each carry/borrow Boolean.")
        elif op == "u32_lt":
            shape = ("m31", 1)
            functional_spec = f"{name} = unsigned32({node['lhs']}) < unsigned32({node['rhs']})"
            field_equations.extend((
                "b[0] = 1; b[i] in {0,1}; d[i] in [0,65535]",
                f"{node['rhs']}[i] + 65536*b[i+1] - {node['lhs']}[i] - b[i] - d[i] = 0, i=0..1",
                f"{name}[0] = 1 - b[2]",
            ))
            notes.append("The initial borrow of one makes equality false; both limbs are range checked.")
        elif op == "hash_sha256d_header":
            shape = ("u16", 16)
            functional_spec = f"{name} = SHA256(SHA256(LE16_bytes({node['lhs']}[0..39])))"
            field_equations.extend((
                "input and output limbs each lie in [0,65535]",
                "each decomposed bit b satisfies b * (b - 1) = 0",
                "low16 + 65536*carry_low = low16_a + low16_b",
                "high16 + 65536*carry_high = high16_a + high16_b + carry_low",
            ))
            notes.append("SHA-256 uses three fixed 64-byte compression blocks: two for the header and one for the second hash. Padding and bit lengths 640 and 256 are constants.")
            notes.append("Rotations and shifts permute constrained bits; choose, majority, and XOR use field multiplication. The output is raw digest bytes in little-endian u16 limbs.")
        elif op == "bitcoin_target_mainnet":
            shape = ("u16", 16)
            functional_spec = f"{name} = DecodeCompactMainnet(LE16_bytes({node['lhs']})[72..75])"
            field_equations.extend((
                "header nBits limbs decompose into Boolean bits and four little-endian bytes",
                "s[e] in {0,1}; sum(s[e], e=1..32)=1; sum(e*s[e])=exponent",
                "target byte[j] = sum(s[e] * mantissa byte[j-e+3]) over valid e and byte positions",
                "mantissa sign bit = 0; target bytes[28..31] = 0; target != 0",
            ))
            notes.append("The high-byte zero rule is equivalent to target <= Bitcoin mainnet powLimit, whose highest nonzero byte is 27 and equals 255.")
        elif op == "bitcoin_block_work":
            shape = ("u16", 16)
            functional_spec = f"{name} = floor(2^256 / ({node['lhs']} + 1))"
            field_equations.extend((
                "target + 1 and quotient + 1 are checked 256-bit additions",
                "q*d + r = (2^256-1)-target across 64 base-256 columns, with c[0]=c[64]=0",
                "0 <= r < d via sixteen base-65536 subtract-and-borrow equations",
            ))
            notes.append("Each byte convolution column and carry equation stays below M31, so field equality is integer equality. Zero target and maximum target are rejected.")
        elif op in {"bitcoin_prev_hash", "bitcoin_header_bits", "bitcoin_header_time"}:
            start, length = (2, 16) if op == "bitcoin_prev_hash" else (34, 2) if op == "bitcoin_header_time" else (36, 2)
            shape = ("u16", length)
            field_equations.append(f"{name}[j] = {node['lhs']}[{start}+j], 0 <= j < {length}")
            notes.append("This is a fixed view of already range-checked header limbs; assertions against the view reuse those same circuit wires.")
        elif op == "bitcoin_genesis_hash_mainnet":
            shape = ("u16", 16)
            field_equations.append(f"{name}[j] = little_endian_u16(mainnet_genesis_raw_bytes[2j:2j+2]), 0 <= j < 16")
            notes.append("The raw mainnet genesis digest is a compiler-owned constant, not a prover input.")
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
            elif op == "inv":
                field_equations.append(f"{lhs} * {name}[j] - 1 = 0")
                notes.append("A zero active lane has no satisfying inverse. Each packed group uses a pointwise product, difference, and arithmetic zero assertion; the assertion preserves one producer per lookup address.")
            elif op == "is_zero":
                field_equations.extend((
                    f"{lhs} * inverse - (1 - {name}[0]) = 0",
                    f"{lhs} * {name}[0] = 0",
                ))
                notes.append("These two equations force the output to be one exactly when the input is zero; the Boolean rule follows algebraically. Inverse is a private witness.")
            elif op in {"bool_not", "bool_and", "bool_or", "bool_xor", "bool_select"}:
                operands = [f"{node['lhs']}[0]"]
                if op != "bool_not":
                    operands.append(f"{node['rhs']}[0]")
                if op == "bool_select":
                    operands.append(f"{node['selector']}[0]")
                for operand in operands:
                    field_equations.append(f"{operand} * ({operand} - 1) = 0")
                a = operands[0]
                b = operands[1] if len(operands) > 1 else ""
                formula = {
                    "bool_not": f"1 - {a}",
                    "bool_and": f"{a} * {b}",
                    "bool_or": f"{a} + {b} - {a} * {b}",
                    "bool_xor": f"{a} + {b} - 2 * {a} * {b}",
                    "bool_select": f"(1 - {operands[-1]}) * {a} + {operands[-1]} * {b}",
                }[op]
                field_equations.append(f"{name}[0] - ({formula}) = 0")
                notes.append("Boolean operands are constrained to 0 or 1; the output is Boolean by the formula, with no output hint.")
            elif op == "add_const":
                field_equations.append(f"{name}[j] - {lhs} - {constant} = 0")
            elif op == "mul_const":
                field_equations.append(f"{name}[j] - {lhs} * {constant} = 0")
            elif op == "select":
                shape = shapes[node["lhs"]]
                selector = f"{node['selector']}[0]"
                field_equations.extend((
                    f"{selector} * ({selector} - 1) = 0",
                    f"{name}[j] - (1 - {selector}) * {lhs} - {selector} * {rhs} = 0",
                ))
                if shape[0] == "u16":
                    notes.append("Every selected limb equals one of two range-checked u16 limbs because the selector is Boolean; no new range witness is needed.")
            elif op == "repeat":
                mixes_lanes = any(step["op"] == "mix4" for step in node["body"])
                functional_spec = (f"{name} = F^{node['rounds']}({lhs})" if mixes_lanes else
                                   f"{name}[j] = F^{node['rounds']}({lhs})")
                for index, step in enumerate(node["body"], start=1):
                    previous = f"v{index - 1}"
                    if step["op"] == "square":
                        expression = f"{previous} * {previous}"
                    elif step["op"] == "add_const":
                        expression = f"{previous} + {step['constant']}"
                    elif step["op"] == "mix4":
                        expression = f"{previous} + splat<4>(sum({previous}))"
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


def independent_value_check(relation: dict, assignment: dict) -> dict:
    """Check supported relation values without calling the Zig runtime or circuit."""
    from oracle import UnsupportedOperation, evaluate_relation

    try:
        computed = evaluate_relation(relation, assignment)
    except UnsupportedOperation as exc:
        return {"status": "unsupported", "reason": str(exc)}
    return {"status": "passed", "computed_public_outputs": computed}


def prover_stages(log: str) -> dict | None:
    """Parse the runtime's stage timers without inventing unavailable PoW data."""
    stages = re.search(r"witness=([\d.]+)s, setup=([\d.]+)s, prove=([\d.]+)s", log)
    if stages is None:
        return None
    result = {
        "witness_seconds": float(stages.group(1)),
        "setup_seconds": float(stages.group(2)),
        "prove_seconds": float(stages.group(3)),
    }
    pow_stages = re.search(r"interaction_pow=([\d.]+)s fri_pow=([\d.]+)s", log)
    if pow_stages is not None:
        interaction, fri = float(pow_stages.group(1)), float(pow_stages.group(2))
        result["interaction_pow_seconds"] = interaction
        result["fri_pow_seconds"] = fri
        result["prove_excluding_pow_seconds"] = max(0.0, result["prove_seconds"] - interaction - fri)
    return result


def assignment_digest(path: Path) -> str:
    """Hash assignment values, independent of JSON whitespace and key order."""
    canonical = json.dumps(json.loads(path.read_text()), sort_keys=True,
                           separators=(",", ":"), ensure_ascii=True).encode()
    return sha256(canonical)


def oracle_provenance() -> dict:
    """Pin the independent oracle code and constants used by this run."""
    sources = (
        S31_DIR / "python/oracle.py",
        S31_DIR / "python/poseidon2_oracle.py",
        ROOT / "src/frontends/riscv/air/memory_commitment/poseidon2_constants.zig",
    )
    return {
        "python_version": platform.python_version(),
        "source_sha256": {str(path.relative_to(ROOT)): file_hash(path) for path in sources},
    }


def trial(source_or_package: Path, assignment_path: Path, output: Path,
          lowering: str | None = None, fri_fold_step: int | None = None) -> dict:
    """Build, prove, verify, and record one reproducible agent-facing trial."""
    source_or_package = source_or_package.resolve()
    assignment_path = assignment_path.resolve()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "trial-report.json").unlink(missing_ok=True)
    started = time.perf_counter()
    if source_or_package.is_dir():
        package = source_or_package
        manifest = verify_package(package)
        if lowering is not None and lowering != manifest["lowering"]:
            raise ValueError("requested lowering differs from the supplied package")
        if fri_fold_step is not None and fri_fold_step != manifest.get("fri_fold_step", 1):
            raise ValueError("requested FRI fold step differs from the supplied package")
    else:
        package = build(source_or_package, output / "package", lowering or "gate",
                        1 if fri_fold_step is None else fri_fold_step)
        manifest = verify_package(package)
    build_seconds = time.perf_counter() - started
    assignment = json.loads(assignment_path.read_text())
    relation = json.loads((package / "source.s31.json").read_text())
    value_check = independent_value_check(relation, assignment)
    statement = {
        "public_inputs": assignment["public_inputs"],
        "public_outputs": assignment["public_outputs"],
    }
    abi_data = json.loads((package / "public-abi.json").read_text())
    prover = package / "bin" / f"s31-{manifest['name']}-prover"
    verifier = package / "bin" / f"s31-{manifest['name']}-native-verifier"
    key = package / "verification-key.json"
    with tempfile.TemporaryDirectory(prefix=".trial-", dir=output) as directory:
        staging = Path(directory)
        proof = staging / "proof.bin"
        statement_path = staging / "statement.json"
        wrong_path = staging / "changed-statement.json"
        write_json(statement_path, statement)
        started = time.perf_counter()
        prover_log = invoke(str(prover), "prove", str(assignment_path), str(proof))
        prove_seconds = time.perf_counter() - started
        started = time.perf_counter()
        invoke(str(verifier), str(proof), str(statement_path), str(key))
        verify_seconds = time.perf_counter() - started
        changed = copy.deepcopy(statement)
        changed_field = None
        for category in ("public_outputs", "public_inputs"):
            for field in abi_data[category]:
                values = changed[category][field["name"]]
                if values:
                    bound = 65536 if field["kind"] == "u16" else (1 << 31) - 1
                    values[0] = (values[0] + 1) % bound
                    changed_field = f"{category}.{field['name']}[0]"
                    break
            if changed_field is not None:
                break
        if changed_field is None:
            raise ValueError("trial needs at least one public word to test statement binding")
        write_json(wrong_path, changed)
        try:
            invoke(str(verifier), str(proof), str(wrong_path), str(key))
        except RuntimeError:
            pass
        else:
            raise RuntimeError(f"native verifier accepted changed {changed_field}")
        proof_data = proof.read_bytes()
        (output / "proof.bin").write_bytes(proof_data)
        write_json(output / "statement.json", statement)
        write_json(output / "changed-statement.json", changed)
    source_equations = equations(package)
    write_json(output / "equations.json", source_equations)
    write_json(output / "explain.json", explain(package))
    cost = json.loads((package / "cost-report.json").read_text())
    result = {
        "schema": "s31-trial-v1",
        "program": manifest["name"],
        "package": str(package),
        "assignment": str(assignment_path),
        "lowering": manifest["lowering"],
        "fri_fold_step": manifest.get("fri_fold_step", 1),
        "profile": cost["profile"],
        "visible_fri": visible_fri(cost, manifest["lowering"]),
        "canonical_ir_sha256": cost["canonical_ir_sha256"],
        "program_sha256": manifest["program_sha256"],
        "raw": cost["raw"],
        "padded": cost["padded"],
        "preprocessed_cells": cost["preprocessed_cells"],
        "proof_sha256": sha256(proof_data),
        "proof_bytes": len(proof_data),
        "native_verifier_accepted": True,
        "changed_public_statement_rejected": changed_field,
        "text_source_relowered": "source_text_sha256" in manifest,
        "independent_value_oracle": value_check,
        "independent_value_oracle_provenance": oracle_provenance(),
        "build_or_load_seconds": build_seconds,
        "prove_seconds": prove_seconds,
        "prover_stages": prover_stages(prover_log),
        "verify_seconds": verify_seconds,
        "timing_note": "Single local observations; proof-of-work and cache state affect timings.",
        "artifacts": {
            "proof": "proof.bin", "statement": "statement.json",
            "changed_statement": "changed-statement.json",
            "equations": "equations.json", "explain": "explain.json",
        },
    }
    write_json(output / "trial-report.json", result)
    return result


def visible_fri(cost: dict, lowering: str) -> dict:
    """Give every lowering the same units for the visible FRI settings.

    The SHA shift/fused cost reports store log2(last-layer degree bound),
    whereas the older package reports store the degree bound itself.
    """
    raw = cost["fri"]
    last_layer = raw["last_layer_degree_bound"]
    if lowering in {"sha-shift", "sha-fused"}:
        last_layer = 1 << last_layer
    return {
        "pow_bits": raw["pow_bits"],
        "blowup_factor": 1 << raw["log_blowup_factor"],
        "last_layer_degree_bound": last_layer,
        "queries": raw["queries"],
        "fold_step": raw["fold_step"],
    }


def tune(source: Path, assignments: list[Path], output: Path,
         lowerings: list[str], warmup: Path | None = None) -> dict:
    """Compare proof profiles on the same source and assignment corpus."""
    if source.is_dir():
        raise ValueError("tune expects a source file so every profile compiles the same relation")
    if len(lowerings) < 2 or len(set(lowerings)) != len(lowerings):
        raise ValueError("tune requires at least two distinct --lowering values")
    if not assignments:
        raise ValueError("tune requires at least one assignment")
    source = source.resolve()
    assignments = [path.resolve() for path in assignments]
    warmup = warmup.resolve() if warmup is not None else None
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "tune-report.json").unlink(missing_ok=True)
    assignment_hashes = [assignment_digest(path) for path in assignments]
    packages = {}
    build_seconds = {}
    for lowering in lowerings:
        started = time.perf_counter()
        packages[lowering] = build(source, output / "packages" / lowering, lowering)
        build_seconds[lowering] = time.perf_counter() - started
    per_profile = {}
    canonical_digests = set()
    program_digests = set()
    for lowering, package in packages.items():
        manifest = verify_package(package)
        canonical_digests.add(manifest["canonical_ir_sha256"])
        program_digests.add(manifest["program_sha256"])
        if warmup is not None:
            trial(package, warmup, output / "warmup" / lowering)
        trials = [trial(package, assignment, output / "runs" / lowering / f"{index:03d}")
                  for index, assignment in enumerate(assignments)]
        proof_sizes = [item["proof_bytes"] for item in trials]
        wall_times = [item["prove_seconds"] for item in trials]
        verify_times = [item["verify_seconds"] for item in trials]
        non_pow_times = [item["prover_stages"]["prove_excluding_pow_seconds"]
                         for item in trials if item["prover_stages"] is not None and
                         "prove_excluding_pow_seconds" in item["prover_stages"]]
        cost = json.loads((package / "cost-report.json").read_text())
        per_profile[lowering] = {
            "package": str(package),
            "build_or_load_seconds": build_seconds[lowering],
            "profile": cost["profile"],
            "visible_fri": visible_fri(cost, lowering),
            "public_abi": json.loads((package / "public-abi.json").read_text()),
            "raw": cost["raw"],
            "padded": cost["padded"],
            "preprocessed_cells": cost["preprocessed_cells"],
            "proof_bytes_per_assignment": proof_sizes,
            "median_proof_bytes": statistics.median(proof_sizes),
            "wall_prove_seconds_per_assignment": wall_times,
            "median_wall_prove_seconds": statistics.median(wall_times),
            "native_verify_seconds_per_assignment": verify_times,
            "median_native_verify_seconds": statistics.median(verify_times),
            "prove_excluding_pow_seconds_per_assignment": non_pow_times,
            "median_prove_excluding_pow_seconds": (
                statistics.median(non_pow_times) if len(non_pow_times) == len(trials) else None),
            "native_verifier_accepted_all": all(item["native_verifier_accepted"] for item in trials),
            "changed_public_statement_rejected_all": all(
                item["changed_public_statement_rejected"] for item in trials),
            "independent_value_oracle_statuses": [
                item["independent_value_oracle"]["status"] for item in trials],
        }
    if len(program_digests) != 1 or len(canonical_digests) != 1:
        raise ValueError("tune profiles compiled different source or canonical relations")
    fri_settings = {json.dumps(item["visible_fri"], sort_keys=True)
                    for item in per_profile.values()}
    report = {
        "schema": "s31-tune-v1",
        "source": str(source),
        "program_sha256": next(iter(program_digests)),
        "canonical_ir_sha256": next(iter(canonical_digests)),
        "host": {"platform": platform.platform(), "machine": platform.machine(),
                 "python": platform.python_version(), "zig": invoke("zig", "version").strip()},
        "assignment_sha256": assignment_hashes,
        "independent_value_oracle_provenance": oracle_provenance(),
        "warmup_assignment_sha256": assignment_digest(warmup) if warmup is not None else None,
        "distinct_assignments": len(set(assignment_hashes)) == len(assignment_hashes),
        "same_visible_fri_settings": len(fri_settings) == 1,
        "profiles": per_profile,
        "timing_note": ("Use --warmup for one unmeasured proof per profile. Transcript-dependent "
                        "proof-of-work varies with the assignment; compare repeated distinct witnesses. "
                        "Visible FRI settings alone do not establish equal soundness across AIRs. "
                        "No profile is selected automatically."),
    }
    write_json(output / "tune-report.json", report)
    return report


def replay_state_step(previous: list[int], body: list[dict]) -> list[int]:
    """Independent scalar M31 replay of a sealed four-lane fold transition."""
    p = (1 << 31) - 1
    if len(previous) != 4 or any(type(word) is not int or not 0 <= word < p for word in previous):
        raise ValueError("invalid state-fold checkpoint state")
    values = previous.copy()
    for operation in body:
        op = operation.get("op")
        constant = operation.get("constant")
        if op == "square" and constant is None:
            values = [(value * value) % p for value in values]
        elif op in {"add_const", "mul_const"} and type(constant) is int and 0 <= constant < p:
            values = [((value + constant) if op == "add_const" else (value * constant)) % p
                      for value in values]
        elif op == "mix4" and constant is None:
            total = sum(values) % p
            values = [(value + total) % p for value in values]
        else:
            raise ValueError("unsupported sealed state-fold step operation")
    return values


def audit_fold_chain(package: Path, manifest: dict, proofs: list[Path], state: bool,
                     max_step: int | None) -> dict:
    """Verify every checkpoint and replay its public claim continuity."""
    if not proofs:
        raise ValueError("a fold chain needs at least one proof")
    if max_step is not None and not (0 <= max_step <= 0xffffffff):
        raise ValueError("--max-step must fit u32")
    if len(proofs) - 1 > 0xffffffff or (max_step is not None and len(proofs) - 1 > max_step):
        raise ValueError("fold chain exceeds the locally trusted depth")
    wide = manifest["lowering"] == "sparse-wide-gate"
    if state and (manifest["lowering"] != "gate" or
                  "state-fold-verification-key.json" not in manifest["artifacts"]):
        raise ValueError("state-fold chain requires a supported gate recurrence package")
    if not state and manifest["lowering"] not in {"gate", "sparse-wide-gate"}:
        raise ValueError("fixed-fold chain requires a gate or sparse-wide package")
    expected_schema = ("s31-state-fold-statement-v2" if state else
                       "s31-fixed-fold-statement-v4" if wide else "s31-fixed-fold-statement-v3")
    key_field = "state_fold_key_sha256" if state else "fold_key_sha256"
    native_command = "state-fold-verify" if state else "fold-verify"
    verifier = package / "bin" / f"s31-{manifest['name']}-native-verifier"
    body = None
    if state:
        key = json.loads((package / "state-fold-verification-key.json").read_text())
        body = key["step_body"]
    previous = None
    for index, raw_proof in enumerate(proofs):
        proof = raw_proof.resolve()
        statement_path = Path(str(proof) + ".statement.json")
        item = json.loads(statement_path.read_text())
        if item.get("schema") != expected_schema or type(item.get("step")) is not int or item["step"] != index:
            raise ValueError(f"fold checkpoint must have contiguous step {index}: {proof}")
        if previous is not None:
            for field in (key_field, "fold_preprocessed_root", "fold_circuit_hash",
                          "leaf_public_words", "base_public_words"):
                if item[field] != previous[field]:
                    raise ValueError(f"fold checkpoint changed {field} at step {index}")
        if state:
            if item["initial_state"] != item["leaf_public_words"][4:8]:
                raise ValueError("state-fold initial state differs from leaf output")
            if index == 0:
                if item["current_state"] != item["initial_state"]:
                    raise ValueError("state-fold base current state differs from initial state")
            elif (item["initial_state"] != previous["initial_state"] or
                  item["current_state"] != replay_state_step(previous["current_state"], body)):
                raise ValueError(f"state-fold transition mismatch at step {index}")
        invoke(str(verifier), native_command, str(proof), str(statement_path),
               *(("--max-step", str(max_step)) if max_step is not None else ()))
        previous = item
    result = {
        "schema": "s31-fold-chain-audit-v1",
        "kind": "state" if state else "fixed",
        "proofs_verified": len(proofs),
        "top_step": len(proofs) - 1,
        "leaf_public_words": previous["leaf_public_words"],
        "base_public_words": previous["base_public_words"],
        "fold_preprocessed_root": previous["fold_preprocessed_root"],
    }
    if state:
        result["initial_state"] = previous["initial_state"]
        result["current_state"] = previous["current_state"]
    return result


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
    sub.add_argument("--lowering", choices=("gate", "chip", "sparse-gate", "sparse-chip", "sparse-wide-gate", "direct-gate", "direct-chip", "sha-joint", "sha-shift", "sha-fused"), default="gate")
    sub.add_argument("--fri-fold-step", type=int, choices=(1, 4), default=1,
                     help="FRI folds per commitment for gate or sparse-wide-gate proofs; 4 can shrink recursive verifier circuits")
    sub = commands.add_parser("trial", help="build, prove, verify, and record one trial")
    sub.add_argument("source_or_package", type=Path)
    sub.add_argument("assignment", type=Path)
    sub.add_argument("--out", type=Path, required=True)
    sub.add_argument("--lowering", choices=("gate", "chip", "sparse-gate", "sparse-chip", "sparse-wide-gate", "direct-gate", "direct-chip", "sha-joint", "sha-shift", "sha-fused"))
    sub.add_argument("--fri-fold-step", type=int, choices=(1, 4),
                     help="select a gate or sparse-wide-gate package's FRI schedule, or check a supplied package")
    sub = commands.add_parser("tune", help="compare verified proof profiles on one source and assignment corpus")
    sub.add_argument("source", type=Path)
    sub.add_argument("assignments", type=Path, nargs="+")
    sub.add_argument("--warmup", type=Path, help="valid assignment proved once per profile before measurement")
    sub.add_argument("--out", type=Path, required=True)
    sub.add_argument("--lowering", action="append", required=True,
                     choices=("gate", "chip", "sparse-gate", "sparse-chip", "sparse-wide-gate", "direct-gate", "direct-chip", "sha-joint", "sha-shift", "sha-fused"))
    sub = commands.add_parser("oracle", help="check normalized relation values without building a proof")
    sub.add_argument("source_or_package", type=Path)
    sub.add_argument("assignment", type=Path)
    sub = commands.add_parser("lower", help="lower .s31 text to normalized relation JSON")
    sub.add_argument("source", type=Path)
    sub.add_argument("--out", type=Path)
    sub = commands.add_parser("prove")
    sub.add_argument("package", type=Path)
    sub.add_argument("assignment", type=Path)
    sub.add_argument("proof", type=Path)
    sub = commands.add_parser("wrap", help="prove verification of a saved gate or sparse-wide S31 proof")
    sub.add_argument("package", type=Path)
    sub.add_argument("child_proof", type=Path)
    sub.add_argument("outer_proof", type=Path)
    sub.add_argument("--statement", type=Path)
    sub.add_argument("--low-memory", action="store_true",
                     help="retain committed evaluations only; lower peak RAM with some extra proving time")
    sub = commands.add_parser("wrap-next", help="prove verification of an already recursive S31 proof")
    sub.add_argument("package", type=Path)
    sub.add_argument("child_proof", type=Path)
    sub.add_argument("outer_proof", type=Path)
    sub.add_argument("--statement", type=Path)
    sub.add_argument("--low-memory", action="store_true")
    for command, description in (
        ("fold-base", "start a fixed-key fold from a first-level recursive proof"),
        ("fold-next", "extend a fixed-key fold under the same verification key"),
        ("state-fold-base", "start a state-transition fold from a first-level recursive proof"),
        ("state-fold-next", "prove one more source recurrence step under the same key"),
    ):
        sub = commands.add_parser(command, help=description)
        sub.add_argument("package", type=Path)
        sub.add_argument("child_proof", type=Path)
        sub.add_argument("outer_proof", type=Path)
        sub.add_argument("--statement", type=Path)
        sub.add_argument("--low-memory", action="store_true")
    sub = commands.add_parser("fold-advance", help="prove several fixed-key folds while reusing the sealed AIR")
    sub.add_argument("package", type=Path)
    sub.add_argument("child_proof", type=Path)
    sub.add_argument("outer_proof", type=Path)
    sub.add_argument("--steps", type=int, required=True)
    sub.add_argument("--statement", type=Path)
    sub.add_argument("--checkpoint-dir", type=Path, help="keep intermediate proofs for resume")
    sub.add_argument("--low-memory", action="store_true")
    sub = commands.add_parser("state-fold-advance", help="prove several source steps, with optional resumable checkpoints")
    sub.add_argument("package", type=Path)
    sub.add_argument("child_proof", type=Path)
    sub.add_argument("outer_proof", type=Path)
    sub.add_argument("--steps", type=int, required=True,
                     help="number of new fold proofs; the first starts at step zero for a recursive base proof")
    sub.add_argument("--statement", type=Path)
    sub.add_argument("--checkpoint-dir", type=Path,
                     help="keep each intermediate proof and statement for resume")
    sub.add_argument("--low-memory", action="store_true")
    sub = commands.add_parser("audit-recursive", help="audit a saved child proof's in-circuit verifier inputs")
    sub.add_argument("package", type=Path)
    sub.add_argument("child_proof", type=Path)
    sub.add_argument("--statement", type=Path)
    sub = commands.add_parser("audit-recursive-next", help="audit the in-circuit verifier for a recursive child proof")
    sub.add_argument("package", type=Path)
    sub.add_argument("child_proof", type=Path)
    sub.add_argument("--statement", type=Path)
    for command, description in (
        ("audit-fold-base", "challenge a fixed-key fold's base circuit inputs"),
        ("audit-fold-next", "challenge a fixed-key fold's recursive circuit inputs"),
        ("audit-state-fold-base", "challenge a state fold's base circuit and counter"),
        ("audit-state-fold-next", "challenge a state fold's transition and recursive verifier"),
    ):
        sub = commands.add_parser(command, help=description)
        sub.add_argument("package", type=Path)
        sub.add_argument("child_proof", type=Path)
        sub.add_argument("--statement", type=Path)
    sub = commands.add_parser("verify")
    sub.add_argument("package", type=Path)
    sub.add_argument("proof", type=Path)
    sub.add_argument("--statement", type=Path)
    sub = commands.add_parser("verify-recursive", help="verify an outer proof against its embedded child key")
    sub.add_argument("package", type=Path)
    sub.add_argument("proof", type=Path)
    sub.add_argument("--statement", type=Path)
    sub = commands.add_parser("verify-recursive-next", help="verify a two-level recursive chain")
    sub.add_argument("package", type=Path)
    sub.add_argument("proof", type=Path)
    sub.add_argument("--statement", type=Path)
    sub = commands.add_parser("verify-fold", help="verify a fixed-key fold using only its top proof and statement")
    sub.add_argument("package", type=Path)
    sub.add_argument("proof", type=Path)
    sub.add_argument("--statement", type=Path)
    sub.add_argument("--max-step", type=int, help="reject a top fold statement above this locally trusted recursion depth")
    sub = commands.add_parser("verify-state-fold", help="verify a recursive state-transition proof from its top proof")
    sub.add_argument("package", type=Path)
    sub.add_argument("proof", type=Path)
    sub.add_argument("--statement", type=Path)
    sub.add_argument("--max-step", type=int, help="reject a top fold statement above this locally trusted recursion depth")
    for command, description in (
        ("audit-fold-chain", "verify every fixed-fold checkpoint and its public claim continuity"),
        ("audit-state-fold-chain", "verify every state-fold checkpoint and replay its source transition"),
    ):
        sub = commands.add_parser(command, help=description)
        sub.add_argument("package", type=Path)
        sub.add_argument("proofs", type=Path, nargs="+", help="fold proofs from step zero through the top step")
        sub.add_argument("--max-step", type=int)
    sub = commands.add_parser("inspect-fold", help="rebuild and report a sealed fold AIR's raw rows and padding headroom")
    sub.add_argument("package", type=Path)
    sub.add_argument("--step", type=int, default=0, help="rebuild the witness-free AIR at this u32 counter value")
    sub = commands.add_parser("inspect-state-fold", help="rebuild and report a state-fold AIR's raw rows and padding headroom")
    sub.add_argument("package", type=Path)
    sub.add_argument("--step", type=int, default=0, help="rebuild the witness-free AIR at this u32 counter value")
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
        print(build(args.source, args.out, args.lowering, args.fri_fold_step))
        return
    if args.command == "trial":
        print(json.dumps(trial(args.source_or_package, args.assignment, args.out,
                               args.lowering, args.fri_fold_step),
                         indent=2, sort_keys=True))
        return
    if args.command == "tune":
        print(json.dumps(tune(args.source, args.assignments, args.out, args.lowering,
                              args.warmup),
                         indent=2, sort_keys=True))
        return
    if args.command == "oracle":
        if args.source_or_package.is_dir():
            package = args.source_or_package.resolve()
            verify_package(package)
            relation = json.loads((package / "source.s31.json").read_text())
        elif args.source_or_package.suffix == ".s31":
            relation, _, _ = lower_text(args.source_or_package.resolve())
        else:
            relation, _ = load_source(args.source_or_package.resolve())
        result = independent_value_check(relation, json.loads(args.assignment.read_text()))
        if result["status"] != "passed":
            raise ValueError(result["reason"])
        print(json.dumps({"schema": "s31-oracle-v1", "program": relation["name"], **result},
                         indent=2, sort_keys=True))
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
    elif args.command == "wrap":
        if manifest["lowering"] not in {"gate", "sparse-wide-gate"}:
            raise ValueError("wrap requires a gate or sparse-wide package")
        child = args.child_proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(child) + ".statement.json")
        outer = args.outer_proof.resolve()
        outer.parent.mkdir(parents=True, exist_ok=True)
        executable = package / "bin" / f"s31-{manifest['name']}-prover"
        command = "recurse-wide-wrap" if manifest["lowering"] == "sparse-wide-gate" else "recurse-wrap"
        print(invoke(str(executable), command, str(child), str(statement),
                     str(outer), str(package / "verification-key.json"),
                     *(("--low-memory",) if args.low_memory else ())), end="")
        print(f"recursive statement: {outer}.statement.json")
    elif args.command == "wrap-next":
        if manifest["lowering"] not in {"gate", "sparse-wide-gate"}:
            raise ValueError("wrap-next requires a gate or sparse-wide package")
        child = args.child_proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(child) + ".statement.json")
        outer = args.outer_proof.resolve()
        outer.parent.mkdir(parents=True, exist_ok=True)
        executable = package / "bin" / f"s31-{manifest['name']}-prover"
        print(invoke(str(executable), "recurse-wrap-next", str(child), str(statement),
                     str(outer), str(package / "verification-key.json"),
                     str(package / "recursive-verification-key.json"),
                     str(package / "recursive-verification-key-level2.json"),
                     *(("--low-memory",) if args.low_memory else ())), end="")
        print(f"recursive chain statement: {outer}.statement.json")
    elif args.command in ("fold-base", "fold-next", "state-fold-base", "state-fold-next"):
        wide_fold = manifest["lowering"] == "sparse-wide-gate" and args.command in ("fold-base", "fold-next")
        if manifest["lowering"] != "gate" and not wide_fold:
            raise ValueError(f"{args.command} requires a gate or supported sparse-wide package")
        if args.command.startswith("state-fold-") and "state-fold-verification-key.json" not in manifest["artifacts"]:
            raise ValueError("source does not expose a supported typed recurrence step")
        child = args.child_proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(child) + ".statement.json")
        outer = args.outer_proof.resolve()
        outer.parent.mkdir(parents=True, exist_ok=True)
        executable = package / "bin" / f"s31-{manifest['name']}-prover"
        command = {
            "fold-base": "fold-wrap-base",
            "fold-next": "fold-wrap-next",
            "state-fold-base": "state-fold-wrap-base",
            "state-fold-next": "state-fold-wrap-next",
        }[args.command]
        if wide_fold:
            command = "wide-" + command
        key_name = ("state-fold-verification-key.json" if args.command.startswith("state-fold-")
                    else "fixed-fold-verification-key.json")
        print(invoke(str(executable), command, str(child), str(statement), str(outer),
                     str(package / "verification-key.json"),
                     str(package / "recursive-verification-key.json"),
                     *((str(package / "recursive-verification-key-level2.json"),) if wide_fold else ()),
                     str(package / key_name),
                     *(("--low-memory",) if args.low_memory else ())), end="")
        print(f"fold statement: {outer}.statement.json")
    elif args.command == "fold-advance":
        if manifest["lowering"] not in {"gate", "sparse-wide-gate"} or "s31-fixed-fold-batch-v1" not in manifest.get("capabilities", []):
            raise ValueError("fold-advance requires a package with the fixed-fold batch capability")
        child = args.child_proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(child) + ".statement.json")
        outer = args.outer_proof.resolve()
        if child == outer or args.steps < 1 or args.steps > 65536:
            raise ValueError("fold-advance needs a distinct output and 1..65536 steps")
        wide_fold = manifest["lowering"] == "sparse-wide-gate"
        initial = json.loads(statement.read_text())
        base_schema = "s31-recursive-chain-statement-v1" if wide_fold else "s31-recursive-gate-statement-v2"
        fold_schema = "s31-fixed-fold-statement-v4" if wide_fold else "s31-fixed-fold-statement-v3"
        if initial.get("schema") == base_schema:
            first_step = 0
            base_case = True
        elif initial.get("schema") == fold_schema:
            prior_step = initial.get("step")
            if type(prior_step) is not int or prior_step < 0 or prior_step > 0xffffffff:
                raise ValueError("input fixed-fold statement has an invalid step counter")
            first_step = prior_step + 1
            base_case = False
        else:
            raise ValueError("input must be a recursive base or fixed-fold proof")
        if first_step + args.steps - 1 > 0xffffffff:
            raise ValueError("fixed-fold step counter would overflow")
        executable = package / "bin" / f"s31-{manifest['name']}-prover"
        outer.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="s31-fixed-fold-advance-") as temporary:
            checkpoints = args.checkpoint_dir.resolve() if args.checkpoint_dir else Path(temporary)
            checkpoints.mkdir(parents=True, exist_ok=True)
            planned_paths: set[Path] = set()
            for index in range(args.steps):
                step = first_step + index
                target = outer if index == args.steps - 1 else checkpoints / f"fold-{step:05d}.proof"
                target_statement = Path(str(target) + ".statement.json")
                if target in planned_paths or target_statement in planned_paths or target in {child, statement} or target_statement in {child, statement}:
                    raise ValueError(f"fold batch paths collide: {target}")
                planned_paths.update((target, target_statement))
                if target.exists() or target_statement.exists():
                    raise ValueError(f"refusing to overwrite fold proof or statement: {target}")
            print(invoke(str(executable), "wide-fold-wrap-batch" if wide_fold else "fold-wrap-batch",
                         str(child), str(statement), str(outer),
                         str(package / "verification-key.json"),
                         str(package / "recursive-verification-key.json"),
                         *((str(package / "recursive-verification-key-level2.json"),) if wide_fold else ()),
                         str(package / "fixed-fold-verification-key.json"),
                         str(args.steps), str(checkpoints), str(first_step),
                         "base" if base_case else "next",
                         *(("--low-memory",) if args.low_memory else ())), end="")
        print(f"fold statement: {outer}.statement.json")
    elif args.command == "state-fold-advance":
        if manifest["lowering"] != "gate" or "state-fold-verification-key.json" not in manifest["artifacts"]:
            raise ValueError("state-fold-advance requires a supported gate-profile recurrence package")
        child = args.child_proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(child) + ".statement.json")
        outer = args.outer_proof.resolve()
        if child == outer or args.steps < 1:
            raise ValueError("state-fold-advance needs a distinct output and at least one step")
        if args.steps > 65536:
            raise ValueError("state-fold-advance accepts at most 65536 proofs per batch; resume from a checkpoint")
        state_key = json.loads((package / "state-fold-verification-key.json").read_text())
        new_counter = state_key["schema"] == "s31-state-fold-verification-key-v3"
        expected_statement = "s31-state-fold-statement-v2" if new_counter else "s31-state-fold-statement-v1"
        counter_max = (1 << 32) - 1 if new_counter else 65535
        initial = json.loads(statement.read_text())
        if initial.get("schema") == "s31-recursive-gate-statement-v2":
            first_step = 0
            base_case = True
        elif initial.get("schema") == expected_statement:
            prior_step = initial.get("step")
            if type(prior_step) is not int or prior_step < 0 or prior_step > counter_max:
                raise ValueError("input state-fold statement has an invalid step counter")
            first_step = initial["step"] + 1
            base_case = False
        else:
            raise ValueError("input must be a first-level recursive or state-fold proof")
        if first_step + args.steps - 1 > counter_max:
            raise ValueError("state-fold step counter would overflow")
        executable = package / "bin" / f"s31-{manifest['name']}-prover"
        verifier = package / "bin" / f"s31-{manifest['name']}-native-verifier"
        outer.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="s31-state-fold-advance-") as temporary:
            checkpoints = args.checkpoint_dir.resolve() if args.checkpoint_dir else Path(temporary)
            checkpoints.mkdir(parents=True, exist_ok=True)
            planned_paths = set()
            for index in range(args.steps):
                step = first_step + index
                target = (outer if index == args.steps - 1 else
                          checkpoints / f"state-{step:05d}.proof")
                target_statement = Path(str(target) + ".statement.json")
                if target in planned_paths or target_statement in planned_paths:
                    raise ValueError(f"state-fold batch outputs collide: {target}")
                planned_paths.update((target, target_statement))
                if target.exists() or target_statement.exists():
                    raise ValueError(f"refusing to overwrite fold proof or statement: {target}")
            batch_capability = ("s31-state-fold-batch-v2" if new_counter else "s31-state-fold-batch-v1")
            if batch_capability in manifest.get("capabilities", []):
                print(invoke(str(executable), "state-fold-wrap-batch", str(child), str(statement),
                             str(outer), str(package / "verification-key.json"),
                             str(package / "recursive-verification-key.json"),
                             str(package / "state-fold-verification-key.json"),
                             str(args.steps), str(checkpoints), str(first_step),
                             "base" if base_case else "next",
                             *(("--low-memory",) if args.low_memory else ())), end="")
                statement = Path(str(outer) + ".statement.json")
            else:
                # Old packages carry their own v1 binary, which only has the
                # one-step command. Preserve their installed proof format.
                for index in range(args.steps):
                    step = first_step + index
                    target = (outer if index == args.steps - 1 else
                              checkpoints / f"state-{step:05d}.proof")
                    target_statement = Path(str(target) + ".statement.json")
                    command = "state-fold-wrap-base" if base_case and index == 0 else "state-fold-wrap-next"
                    print(invoke(str(executable), command, str(child), str(statement), str(target),
                                 str(package / "verification-key.json"),
                                 str(package / "recursive-verification-key.json"),
                                 str(package / "state-fold-verification-key.json"),
                                 *(("--low-memory",) if args.low_memory else ())), end="")
                    child, statement = target, target_statement
            print(invoke(str(verifier), "state-fold-verify", str(outer), str(statement)), end="")
        print(f"state-fold top proof: {outer}")
    elif args.command == "audit-recursive":
        if manifest["lowering"] not in {"gate", "sparse-wide-gate"}:
            raise ValueError("audit-recursive requires a gate or sparse-wide package")
        child = args.child_proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(child) + ".statement.json")
        executable = package / "bin" / f"s31-{manifest['name']}-prover"
        command = "recurse-wide-audit" if manifest["lowering"] == "sparse-wide-gate" else "recurse-audit"
        print(invoke(str(executable), command, str(child), str(statement),
                     str(package / "verification-key.json")), end="")
    elif args.command == "audit-recursive-next":
        if manifest["lowering"] not in {"gate", "sparse-wide-gate"}:
            raise ValueError("audit-recursive-next requires a gate or sparse-wide package")
        child = args.child_proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(child) + ".statement.json")
        executable = package / "bin" / f"s31-{manifest['name']}-prover"
        print(invoke(str(executable), "recurse-audit-next", str(child), str(statement),
                     str(package / "verification-key.json"),
                     str(package / "recursive-verification-key.json")), end="")
    elif args.command in ("audit-fold-base", "audit-fold-next", "audit-state-fold-base", "audit-state-fold-next"):
        wide_fold = manifest["lowering"] == "sparse-wide-gate" and args.command in ("audit-fold-base", "audit-fold-next")
        if manifest["lowering"] != "gate" and not wide_fold:
            raise ValueError(f"{args.command} requires a gate or supported sparse-wide package")
        if args.command.startswith("audit-state-fold-") and "state-fold-verification-key.json" not in manifest["artifacts"]:
            raise ValueError("source does not expose a supported typed recurrence step")
        child = args.child_proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(child) + ".statement.json")
        executable = package / "bin" / f"s31-{manifest['name']}-prover"
        command = {
            "audit-fold-base": "fold-audit",
            "audit-fold-next": "fold-audit-next",
            "audit-state-fold-base": "state-fold-audit-base",
            "audit-state-fold-next": "state-fold-audit-next",
        }[args.command]
        if wide_fold:
            command = "wide-fold-audit-base" if args.command == "audit-fold-base" else "wide-fold-audit-next"
        key_name = ("state-fold-verification-key.json" if args.command.startswith("audit-state-fold-")
                    else "fixed-fold-verification-key.json")
        print(invoke(str(executable), command, str(child), str(statement),
                     str(package / "verification-key.json"),
                     str(package / "recursive-verification-key.json"),
                     *((str(package / "recursive-verification-key-level2.json"),) if wide_fold else ()),
                     str(package / key_name)), end="")
    elif args.command == "verify":
        proof = args.proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(proof) + ".statement.json")
        executable = package / "bin" / f"s31-{manifest['name']}-native-verifier"
        print(invoke(str(executable), str(proof), str(statement), str(package / "verification-key.json")), end="")
    elif args.command == "verify-recursive":
        if manifest["lowering"] not in {"gate", "sparse-wide-gate"}:
            raise ValueError("verify-recursive requires a gate or sparse-wide package")
        proof = args.proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(proof) + ".statement.json")
        executable = package / "bin" / f"s31-{manifest['name']}-native-verifier"
        print(invoke(str(executable), "recurse-verify", str(proof), str(statement)), end="")
    elif args.command == "verify-recursive-next":
        if manifest["lowering"] not in {"gate", "sparse-wide-gate"}:
            raise ValueError("verify-recursive-next requires a gate or sparse-wide package")
        proof = args.proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(proof) + ".statement.json")
        executable = package / "bin" / f"s31-{manifest['name']}-native-verifier"
        print(invoke(str(executable), "recurse-verify-next", str(proof), str(statement)), end="")
    elif args.command == "verify-fold":
        if manifest["lowering"] not in {"gate", "sparse-wide-gate"}:
            raise ValueError("verify-fold requires a gate or sparse-wide package")
        proof = args.proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(proof) + ".statement.json")
        executable = package / "bin" / f"s31-{manifest['name']}-native-verifier"
        if args.max_step is not None and not (0 <= args.max_step <= 0xffffffff):
            raise ValueError("--max-step must fit u32")
        max_step = ("--max-step", str(args.max_step)) if args.max_step is not None else ()
        print(invoke(str(executable), "fold-verify", str(proof), str(statement), *max_step), end="")
    elif args.command == "verify-state-fold":
        if manifest["lowering"] != "gate" or "state-fold-verification-key.json" not in manifest["artifacts"]:
            raise ValueError("verify-state-fold requires a supported gate-profile recurrence package")
        proof = args.proof.resolve()
        statement = args.statement.resolve() if args.statement else Path(str(proof) + ".statement.json")
        executable = package / "bin" / f"s31-{manifest['name']}-native-verifier"
        if args.max_step is not None and not (0 <= args.max_step <= 0xffffffff):
            raise ValueError("--max-step must fit u32")
        max_step = ("--max-step", str(args.max_step)) if args.max_step is not None else ()
        print(invoke(str(executable), "state-fold-verify", str(proof), str(statement), *max_step), end="")
    elif args.command in {"audit-fold-chain", "audit-state-fold-chain"}:
        result = audit_fold_chain(package, manifest, args.proofs,
                                  args.command == "audit-state-fold-chain", args.max_step)
        print(json.dumps(result, sort_keys=True))
    elif args.command == "inspect-fold":
        wide_fold = manifest["lowering"] == "sparse-wide-gate"
        if manifest["lowering"] != "gate" and not wide_fold:
            raise ValueError("inspect-fold requires a gate or sparse-wide package")
        if not 0 <= args.step <= 0xffffffff:
            raise ValueError("--step must fit u32")
        executable = package / "bin" / f"s31-{manifest['name']}-prover"
        print(invoke(str(executable), "wide-fold-inspect" if wide_fold else "fold-inspect",
                     str(package / "verification-key.json"),
                     str(package / "recursive-verification-key.json"),
                     *((str(package / "recursive-verification-key-level2.json"),) if wide_fold else ()),
                     str(package / "fixed-fold-verification-key.json"), "--step", str(args.step)), end="")
    elif args.command == "inspect-state-fold":
        if manifest["lowering"] != "gate" or "state-fold-verification-key.json" not in manifest["artifacts"]:
            raise ValueError("inspect-state-fold requires a supported gate-profile recurrence package")
        if not 0 <= args.step <= 0xffffffff:
            raise ValueError("--step must fit u32")
        executable = package / "bin" / f"s31-{manifest['name']}-prover"
        print(invoke(str(executable), "state-fold-inspect",
                     str(package / "verification-key.json"),
                     str(package / "recursive-verification-key.json"),
                     str(package / "state-fold-verification-key.json"), "--step", str(args.step)), end="")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, UnicodeError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
        print(f"s31: {exc}", file=sys.stderr)
        raise SystemExit(1)

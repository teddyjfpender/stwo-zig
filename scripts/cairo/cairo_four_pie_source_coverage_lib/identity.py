from __future__ import annotations

import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "vectors/cairo/source_semantics/v3/manifest.json"
SEMANTIC_REGISTRY_PATH = ROOT / "vectors/cairo/source_semantics/v3/registry.json"
DEFAULT_REPORT = ROOT / "vectors/cairo/source_semantics/four_pie_coverage_v1.json"
REPORT_FORMAT = "stwo-zig-cairo-four-pie-source-coverage"
SHAPE_SCHEMA = "stwo.kernel-emit.shape-report.v1"
CANONICAL_PIES = ("SN_PIE_1", "SN_PIE_2", "SN_PIE_3", "SN_PIE_4")
PIE_IDENTITIES = {
    "SN_PIE_1": {
        "bytes": 81_919_642,
        "sha256": "dbdda06ffb2cee7ee7c499b7805e9b9a20eba20518b301998edfb195ea2da0ee",
        "adapted_bytes": 297_469_956,
        "adapted_sha256": "6506b4f1a871c9f2f83d4a63c5bd288a44b60199d9e124cfcf55bf8154da9fb9",
    },
    "SN_PIE_2": {
        "bytes": 44_039_431,
        "sha256": "f10b70ca8af790a934ac36b3835136bbdc0cc47f62d6bc63169856dec3f0dc41",
        "adapted_bytes": 162_102_412,
        "adapted_sha256": "78b0995483a76e850c61cf7cb51861850f746ddf927344088014492b6752844c",
    },
    "SN_PIE_3": {
        "bytes": 81_333_170,
        "sha256": "673212f6fcc64b2c4fe3817a041756ddaa2386712fc971e3bd2dd7fca7b4aea4",
        "adapted_bytes": 285_299_888,
        "adapted_sha256": "348dbbc4673dc9d040df3bc29805d50f583d000d6df19bd6647c11c5711c9ce5",
    },
    "SN_PIE_4": {
        "bytes": 76_790_282,
        "sha256": "991eff7c3323e1b6b6cb2bb2d7df1704b1e31f4854c00c60d7413603fe455603",
        "adapted_bytes": 284_530_524,
        "adapted_sha256": "c6c134c098f2f80cb2b99629922caf52e5917b71f1f813d23d20bb8109c5543f",
    },
}
SHAPE_IDENTITIES = {
    "SN_PIE_1": "fc74589c654cb8285037dc3f9ca9cc93f38f21af50eb898cff334f614e8be71b",
    "SN_PIE_2": "c16205b04e38d5281b7fc3b9530efbedd4f27f748e593ca1698e09e74f6ee752",
    "SN_PIE_3": "00c8d6ad4dac379b270cd165082e6d9c1e01a596f25b76683d890175fdd5ab17",
    "SN_PIE_4": "80856e083f2b4f7092d20dd61afab5378d0e2389a8c288a17a7a1c9441ca49a4",
}
RESOURCE_IDENTITIES = {
    "SN_PIE_1": "5321e085cca0fe4c2f92a668387ef3d0ae1b7cc27989b6d8052975cc351616df",
    "SN_PIE_2": "3c262260ae076731ca78ca91822c86c03ae73a807c2e7fd8f8610e7e364a8f86",
    "SN_PIE_3": "eb021106c76bb5896ef35abe219bca3059e2f714c3a194d1fd6b3e329b1f6ab6",
    "SN_PIE_4": "c8c03abeb88a54fe4f7deff665c3df32ceaac41f25d650f6d51608461568ccab",
}
BUILTIN_NAMES = {
    "add_mod_builtin",
    "bitwise_builtin",
    "ec_op_builtin",
    "ecdsa_builtin",
    "keccak_builtin",
    "mul_mod_builtin",
    "output_builtin",
    "pedersen_builtin",
    "poseidon_builtin",
    "range_check96_builtin",
    "range_check_builtin",
}
# Evidence-producer identity only. These binaries cannot supply semantics, and
# their dirty/mismatched source closure remains an independent blocker.
DECODER_BINARY_IDENTITIES = {
    "gpu_bench": {
        "bytes": 338_734_688,
        "sha256": "c89fdf26865355473ae128b9a5b189d0a12ca6355b8de4b82c83ad90ab38412e",
    },
    "kernel_emit": {
        "bytes": 255_105_888,
        "sha256": "b3b7d72a59240ccd7abc0706a6bf0f7a052492f1c40623eaba6b641bfb657e16",
    },
}
ZIP_MEMBERS = {
    "version.json",
    "metadata.json",
    "memory.bin",
    "additional_data.json",
    "execution_resources.json",
}
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


class CoverageError(RuntimeError):
    pass


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoverageError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_pairs_no_duplicates,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise CoverageError(f"decode {path}: {error}") from error


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha256_path(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def identity(path: Path) -> dict[str, Any]:
    return {"bytes": path.stat().st_size, "sha256": sha256_path(path)}


def exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        raise CoverageError(
            f"{context} keys differ: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def named_paths(values: list[str], option: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        name, separator, raw_path = value.partition("=")
        if not separator or name not in CANONICAL_PIES or not raw_path:
            raise CoverageError(
                f"{option} requires one of {CANONICAL_PIES} as NAME=PATH: {value}"
            )
        if name in result:
            raise CoverageError(f"duplicate {option} entry: {name}")
        result[name] = Path(raw_path).expanduser().resolve()
    if set(result) != set(CANONICAL_PIES):
        raise CoverageError(
            f"{option} requires exactly {list(CANONICAL_PIES)}, got {sorted(result)}"
        )
    return result


def decode_pie(name: str, path: Path) -> dict[str, Any]:
    expected = PIE_IDENTITIES[name]
    actual = identity(path)
    sealed = {"bytes": expected["bytes"], "sha256": expected["sha256"]}
    if actual != sealed:
        raise CoverageError(
            f"{name} identity mismatch: expected "
            f"{sealed['bytes']}:{sealed['sha256']}, "
            f"got {actual['bytes']}:{actual['sha256']}"
        )
    try:
        with zipfile.ZipFile(path) as archive:
            members = set(archive.namelist())
            if members != ZIP_MEMBERS:
                raise CoverageError(
                    f"{name} ZIP members differ: missing={sorted(ZIP_MEMBERS - members)}, "
                    f"unexpected={sorted(members - ZIP_MEMBERS)}"
                )
            version = json.loads(
                archive.read("version.json"), object_pairs_hook=_pairs_no_duplicates
            )
            resources = json.loads(
                archive.read("execution_resources.json"),
                object_pairs_hook=_pairs_no_duplicates,
            )
    except (OSError, zipfile.BadZipFile, KeyError, json.JSONDecodeError) as error:
        raise CoverageError(f"decode {name}: {error}") from error
    if version != {"cairo_pie": "1.1"}:
        raise CoverageError(f"{name} has unsupported version: {version!r}")
    if not isinstance(resources, dict):
        raise CoverageError(f"{name} execution_resources.json is not an object")
    validate_execution_resources(name, resources)
    return {
        "name": name,
        **actual,
        "cairo_pie_version": version["cairo_pie"],
        "execution_resources": resources,
        "role": "runtime_coverage_only",
    }


def decode_adapted(name: str, path: Path) -> dict[str, Any]:
    expected = PIE_IDENTITIES[name]
    actual = identity(path)
    sealed = {
        "bytes": expected["adapted_bytes"],
        "sha256": expected["adapted_sha256"],
    }
    if actual != sealed:
        raise CoverageError(
            f"{name} adapted identity mismatch: expected "
            f"{sealed['bytes']}:{sealed['sha256']}, "
            f"got {actual['bytes']}:{actual['sha256']}"
        )
    return actual


def validate_execution_resources(name: str, resources: Any) -> None:
    if not isinstance(resources, dict):
        raise CoverageError(f"{name} execution resources are not an object")
    exact_keys(
        resources,
        {"builtin_instance_counter", "n_memory_holes", "n_steps"},
        f"{name} execution resources",
    )
    builtins = resources["builtin_instance_counter"]
    if not isinstance(builtins, dict):
        raise CoverageError(f"{name} builtin counters are not an object")
    exact_keys(builtins, BUILTIN_NAMES, f"{name} builtin counters")
    values = [resources["n_memory_holes"], resources["n_steps"], *builtins.values()]
    if any(type(value) is not int or value < 0 for value in values):
        raise CoverageError(f"{name} execution resources contain invalid counts")
    digest = hashlib.sha256(json_bytes(resources)).hexdigest()
    if digest != RESOURCE_IDENTITIES[name]:
        raise CoverageError(f"{name} execution-resource identity is stale")


def git_output(source_root: Path, *args: str) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(source_root), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.strip()
    except subprocess.CalledProcessError as error:
        raise CoverageError(f"git {' '.join(args)}: {error.stderr.strip()}") from error


def checkout_identity(source_root: Path) -> dict[str, Any]:
    status = git_output(source_root, "status", "--porcelain").splitlines()
    dirty_paths = [
        line.strip().split(maxsplit=1)[1]
        for line in status
        if len(line.strip().split(maxsplit=1)) == 2
    ]
    return {
        "revision": git_output(source_root, "rev-parse", "HEAD"),
        "tree": git_output(source_root, "rev-parse", "HEAD^{tree}"),
        "clean": not status,
        "dirty_paths": sorted(dirty_paths),
    }


def decoder_identity(
    cairo_root: Path,
    stwo_root: Path,
    gpu_bench: Path,
    kernel_emit: Path,
    *,
    gate_captured: bool,
) -> dict[str, Any]:
    return {
        "cairo_source": checkout_identity(cairo_root),
        "stwo_source": checkout_identity(stwo_root),
        "gpu_bench": identity(gpu_bench.resolve()),
        "kernel_emit": identity(kernel_emit.resolve()),
        "shape_schema": SHAPE_SCHEMA,
        "shape_capture": (
            "gate_invoked_kernel_emit_on_sealed_adapted_inputs"
            if gate_captured
            else "caller_supplied_shape_reports"
        ),
    }

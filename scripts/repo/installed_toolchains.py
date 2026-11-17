"""Bounded installed-tool admission; never install or fall back implicitly."""
from __future__ import annotations

import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path


def host() -> str:
    machine = {"arm64": "aarch64", "AMD64": "x86_64"}.get(platform.machine(), platform.machine())
    system = {"Darwin": "macos", "Linux": "linux"}.get(platform.system(), platform.system().lower())
    return machine + "-" + system


def specifications(root: Path, pins: dict, profile: str) -> list[dict]:
    specs = [
        {"tool": "zig", "command": ["zig", "version"], "version": pins["zig"]["version"]},
        {"tool": "python", "command": [sys.executable, "--version"], "version": pins["python"]["version"]},
    ]
    if profile == "oracles":
        requirements = {}
        for group in ("crates", "guests"):
            for directory, channel in pins["rust"][group].items():
                required = requirements.setdefault(channel, {"components": set(), "targets": set()})
                toolchain = tomllib.loads((root / directory / "rust-toolchain.toml").read_text())["toolchain"]
                if toolchain["channel"] != channel:
                    raise ValueError(f"Rust channel declaration drift: {directory}")
                for kind in required:
                    required[kind].update(toolchain.get(kind, []))
        for channel, required in sorted(requirements.items()):
            specs.append({"tool": "rust:" + channel, "command": ["rustup", "run", channel, "rustc", "--version"],
                          "version": "nightly" if channel.startswith("nightly-") else channel})
            for kind, values in required.items():
                if values:
                    specs.append({"tool": kind + ":" + channel,
                                  "command": ["rustup", kind[:-1], "list", "--installed", "--toolchain", channel],
                                  "required": sorted(values)})
    if profile == "formal":
        channel = pins["lean"]["formal/riscv-refinement"]
        specs += [
            {"tool": "lean", "command": ["elan", "run", channel, "lean", "--version"], "version": channel.split(":v")[-1]},
            {"tool": "sail", "command": ["sail", "--version"], "version": pins["sail"]["compiler"]},
        ]
    return specs


def executable_identity(command: list[str]) -> dict:
    selected = shutil.which(command[0])
    if selected is None:
        return {"path": None}
    path = Path(selected).resolve()
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return {"path": str(path), "sha256": digest.hexdigest()}


def inspect(root: Path, profile: str) -> dict:
    pins = json.loads((root / "toolchain.json").read_text())
    selected_host = host()
    report = {"schema": "installed-toolchain-admission-v1", "host": selected_host,
              "profile": profile, "tools": [], "status": "FAIL",
              "scope": "Version/component admission and invoked executable fingerprints; not dynamic-library closure, compilation, formal/proof or GPU qualification."}
    if profile not in pins["profiles"] or selected_host not in pins["profiles"][profile]["hosts"]:
        return {**report, "error": "unsupported host/profile; no command was executed"}
    distribution = pins["zig"]["distributions"][selected_host]
    report["setup"] = [
        {"tool": "zig", **distribution, "action": "Verify the archive SHA256 before extracting; prepend its directory to PATH, without replacing system tools."},
        {"tool": "python", "version": pins["python"]["version"], "action": "Invoke this entrypoint with that exact CPython; isolated installation may use uv python install --no-bin."},
    ]
    for spec in specifications(root, pins, profile):
        row = {**spec, "status": "FAIL"}
        try:
            result = subprocess.run(spec["command"], capture_output=True, text=True, timeout=20, check=False)
            text = result.stdout + result.stderr
            row.update(exit_code=result.returncode, stdout_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(),
                       stderr_sha256=hashlib.sha256(result.stderr.encode()).hexdigest(),
                       output=text[:4096], executable=executable_identity(spec["command"]))
            if "required" in spec:
                lines = text.splitlines()
                matched = all(any(line == value or line.startswith(value + "-") for line in lines) for value in spec["required"])
            else:
                versions = re.findall(r"\b\d+\.\d+\.\d+\b", text)
                matched = (text.startswith("rustc ") and "-nightly" in text.splitlines()[0]) if spec["version"] == "nightly" else bool(versions) and spec["version"] == versions[0]
            if result.returncode == 0 and matched:
                row["status"] = "PASS"
        except (OSError, subprocess.TimeoutExpired) as error:
            row["error"] = str(error)
        report["tools"].append(row)
        if row["status"] != "PASS" and spec["tool"].startswith("rust:"):
            report["setup"].append({"tool": spec["tool"], "command": ["rustup", "toolchain", "install", spec["command"][2], "--profile", "minimal"]})
        elif row["status"] != "PASS" and "required" in spec:
            report["setup"].append({"tool": spec["tool"], "command": ["rustup", spec["command"][1], "add", *spec["required"], "--toolchain", spec["command"][-1]]})
        elif row["status"] != "PASS" and spec["tool"] == "lean":
            report["setup"].append({"tool": "lean", "command": ["elan", "toolchain", "install", spec["command"][2]]})
        elif row["status"] != "PASS" and spec["tool"] == "sail":
            report["setup"].append({"tool": "sail", **pins["sail"]["distributions"][selected_host],
                                    "action": "Verify before extracting; add sail/bin to PATH. The existing riscv_sail_gate.py preflight remains mandatory."})
    if all(row["status"] == "PASS" for row in report["tools"]):
        report["status"] = "PASS"
    return report

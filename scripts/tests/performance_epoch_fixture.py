"""Small synthetic epoch-2 receipt; no prover, compiler, or Metal execution."""

from __future__ import annotations

import copy
from pathlib import Path

from scripts.bench.performance_epoch_gate_lib.codec import atomic_write, canonical_bytes, content_digest, sha256_bytes
from scripts.bench.performance_epoch_gate_lib.plan import build_plan
from scripts.bench.performance_epoch_gate_lib.session import attempt_chain_seed
from scripts.repo.product_identity_lib import canonical_identity_sha256


class Fixture:
    def __init__(self, root: Path, protocol: dict, protocol_sha256: str):
        self.root = root
        self.raw = root / "raw"
        self.raw.mkdir()
        self.protocol = copy.deepcopy(protocol)
        self.protocol["statistics"]["minimum_excluded_verified_warmups"] = 1
        self.protocol["statistics"]["minimum_measured_verified_proofs_per_arm_per_round"] = 1
        self.protocol["statistics"]["bootstrap_iterations"] = 20
        self.protocol_sha256 = protocol_sha256
        self.candidate_commit = "a" * 40
        self.candidate_tree = "b" * 40
        self.plans = {}
        self.plan_digests = {}
        for role in ("linux", "macos"):
            base = root / role
            paths = {
                "baseline_root": str(base / "baseline"),
                "candidate_root": str(base / "candidate"),
                "bundle_root": str(base / "bundle"),
                "baseline_local_cache": str(base / "cache-a-local"),
                "baseline_global_cache": str(base / "cache-a-global"),
                "candidate_local_cache": str(base / "cache-b-local"),
                "candidate_global_cache": str(base / "cache-b-global"),
            }
            plan = build_plan(
                protocol=self.protocol, protocol_sha256=protocol_sha256,
                host_role=role, session_nonce=("1" if role == "linux" else "2") * 64,
                candidate_commit=self.candidate_commit, candidate_tree=self.candidate_tree,
                paths=paths,
            )
            self.plans[role] = plan
            self.plan_digests[role] = sha256_bytes(canonical_bytes(plan))
        self.sources = copy.deepcopy(self.plans["linux"]["sources"])
        self.artifacts: list[dict] = []
        self.attempts = {"linux": [], "macos": []}
        self.previous = {
            role: attempt_chain_seed(role, self.plans[role], self.plan_digests[role])
            for role in self.plans
        }
        self.builds: list[dict] = []
        self.rows: list[dict] = []
        self.trusted: dict[str, str] = {}

    def artifact(self, kind: str, content: bytes, label: str) -> str:
        identifier = f"{label}-{len(self.artifacts) + 1}"
        relative = f"artifacts/{len(self.artifacts) + 1}-{kind}"
        path = self.raw / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        self.artifacts.append({
            "id": identifier, "path": relative, "kind": kind,
            "sha256": sha256_bytes(content), "bytes": len(content),
        })
        return identifier

    def artifact_info(self, identifier: str) -> dict:
        return next(item for item in self.artifacts if item["id"] == identifier)

    def attempt(
        self, role: str, command_id: str, stage: str, *,
        workload_id=None, round_index=None, order_position=None,
        proof: bytes | None = None, verifier: dict | None = None,
        timing: dict | None = None, resource: dict | None = None,
        status: str = "success",
    ) -> int:
        sequence = len(self.attempts[role]) + 1
        prefix = f"{role}-{sequence}"
        refs = {
            "stdout": self.artifact("stdout", b"", f"{prefix}-stdout"),
            "stderr": self.artifact("stderr", b"", f"{prefix}-stderr"),
            "proof": None,
            "verifier": None,
            "timing": self.artifact("timing", canonical_bytes(timing or {"schema": "process-timing-v1", "wall_seconds": 1.0}), f"{prefix}-timing"),
            "resource": self.artifact("resource", canonical_bytes(resource or {"schema": "process-resource-v1", "peak_rss_bytes": 100}), f"{prefix}-resource"),
        }
        if proof is not None:
            refs["proof"] = self.artifact("proof", proof, f"{prefix}-proof")
        if verifier is not None:
            refs["verifier"] = self.artifact("verifier", canonical_bytes(verifier), f"{prefix}-verifier")
        command = next(item for item in self.plans[role]["commands"] if item["id"] == command_id)
        attempt = {
            "sequence": sequence, "host_role": role, "command_id": command_id,
            "stage": stage, "arm": command["arm"], "workload_id": workload_id,
            "round_index": round_index, "order_position": order_position,
            "status": status, "failure_class": None if status == "success" else "network",
            "started_at_unix_ns": sequence * 10 + 1,
            "ended_at_unix_ns": sequence * 10 + 2,
            "exit_code": 0 if status == "success" else 255,
            "artifacts": refs, "previous_attempt_sha256": self.previous[role],
        }
        attempt["attempt_sha256"] = sha256_bytes(canonical_bytes(attempt))
        self.previous[role] = attempt["attempt_sha256"]
        self.attempts[role].append(attempt)
        return sequence

    def identity(self, role: str, backend: str, name: str) -> dict:
        features = f"test-{role}-{backend}"
        value = {
            "schema_version": 2, "name": name,
            "frontend": "riscv" if "riscv" in name else "native",
            "backend": "metal_hybrid" if backend == "metal" else "cpu_native", "role": "cli",
            "protocol_features": features, "protocol_manifest_sha256": sha256_bytes(features.encode()),
            "identity_sha256": "0" * 64,
            "implementation_repository": self.protocol["repository"],
            "implementation_commit": self.candidate_commit,
            "implementation_tree": self.candidate_tree, "implementation_dirty": False,
            "dirty_content_sha256": None, "zig_version": "0.15.2",
            "target_arch": "aarch64" if role == "macos" else "x86_64",
            "target_os": "macos" if role == "macos" else "linux", "target_abi": "none",
            "cpu_model": "test", "cpu_features_sha256": "3" * 64,
            "optimize": "ReleaseFast", "runtime_manifest": "test",
            "sdk_manifest": "test", "aot_manifest": "test",
        }
        value["identity_sha256"] = canonical_identity_sha256(value)
        return value

    def product(self, spec: dict, arm: str, cold: float, warm: float) -> dict:
        role = spec["host_role"]
        executable = self.artifact("executable", f"{spec['id']}-{arm}".encode(), f"{spec['id']}-{arm}-exe")
        installed = self.artifact("installed-manifest", canonical_bytes({
            "schema": "build-installed-manifest-v1",
            "installed_files": [{"path": "bin/product", "sha256": self.artifact_info(executable)["sha256"], "bytes": self.artifact_info(executable)["bytes"]}],
            "warm_rebuilt_files": [],
        }), f"{spec['id']}-{arm}-installed")
        links = ["Metal.framework"] if spec["id"] == "macos-native-metal" else ["libSystem"]
        link = self.artifact("link-surface", canonical_bytes({"schema": "build-link-surface-v1", "entries": links}), f"{spec['id']}-{arm}-links")
        unrelated = ["src/frontends/cairo/legacy.zig"] if arm == "baseline" else []
        closure = self.artifact("source-closure", canonical_bytes({
            "schema": "build-source-closure-v1", "compiled_sources": ["src/core.zig"],
            "unrelated_sources": unrelated,
        }), f"{spec['id']}-{arm}-closure")
        cold_seq = self.attempt(role, f"build:{spec['id']}:{arm}:cold", "build-cold", timing={"schema": "process-timing-v1", "wall_seconds": cold})
        warm_seq = self.attempt(role, f"build:{spec['id']}:{arm}:warm", "build-warm", timing={"schema": "process-timing-v1", "wall_seconds": warm})
        return {
            "arm": arm, "product": spec[f"{arm}_step"], "source": copy.deepcopy(self.sources[arm]),
            "product_identity": self.identity(role, "metal" if "metal" in spec["id"] else "cpu", spec["candidate_step"]) if arm == "candidate" else None,
            "executable_artifact": executable, "installed_manifest_artifact": installed,
            "link_surface_artifact": link, "source_closure_artifact": closure,
            "cold_attempt_sequence": cold_seq, "warm_attempt_sequence": warm_seq,
            "cold_seconds": cold, "warm_seconds": warm,
        }

    def add_builds(self) -> None:
        for spec in self.protocol["build_comparisons"]:
            baseline = self.product(spec, "baseline", 1.0, 0.1)
            candidate = self.product(spec, "candidate", 0.9, 0.1)
            self.builds.append({
                "id": spec["id"], "host_role": spec["host_role"],
                "baseline": baseline, "candidate": candidate, "verdict": "PASS",
            })

    def sample(self, row: dict, arm: str, stage: str, round_index, position) -> dict:
        proof = b"canonical-proof"
        proof_sha = sha256_bytes(proof)
        dispatches = 1 if row["backend"] == "metal-hybrid" else 0
        fallbacks = 1 if row["backend"] == "metal-hybrid" and arm == "baseline" else 0
        verifier = {
            "schema": "proof-verifier-v1", "local_verified": True,
            "rust_oracle_verified": True, "canonical_proof_sha256": proof_sha,
            "metal_device_dispatches": dispatches, "metal_fallback_count": fallbacks,
        }
        timing = {"schema": "proof-timing-v1", "prove_seconds": 1.0, "request_seconds": 1.1}
        sequence = self.attempt(
            row["host_role"], f"prove:{row['backend']}:{row['workload']['id']}:{arm}", stage,
            workload_id=row["workload"]["id"], round_index=round_index,
            order_position=position, proof=proof, verifier=verifier, timing=timing,
        )
        return {
            "attempt_sequence": sequence, "prove_seconds": 1.0, "request_seconds": 1.1,
            "peak_rss_bytes": 100, "numerator_units": row["numerator"]["units"],
            "locally_verified": True, "pinned_rust_stwo_verified": True,
            "canonical_proof_sha256": proof_sha, "metal_device_dispatches": dispatches,
            "metal_fallback_count": fallbacks,
        }

    def add_rows(self) -> None:
        build_map = {
            ("macos", "cpu"): "macos-native-cpu", ("macos", "metal-hybrid"): "macos-native-metal",
            ("linux", "cpu"): "linux-native-cpu",
        }
        from scripts.bench.performance_epoch_gate_lib.statistics import first_order
        for lane in self.protocol["performance_lanes"]:
            build = next(item for item in self.builds if item["id"] == build_map[(lane["host_role"], lane["backend"])])
            for workload in self.protocol["workloads"]:
                row = {
                    "host_role": lane["host_role"], "backend": lane["backend"],
                    "runtime_mode": lane["runtime_mode"],
                    "workload": {key: copy.deepcopy(workload[key]) for key in ("id", "name", "parameters")},
                    "numerator": copy.deepcopy(workload["numerator"]),
                    "baseline_executable_artifact": build["baseline"]["executable_artifact"],
                    "candidate_executable_artifact": build["candidate"]["executable_artifact"],
                    "warmups": {}, "rounds": [],
                }
                row["warmups"] = {
                    arm: [self.sample(row, arm, "warmup", None, None)]
                    for arm in ("baseline", "candidate")
                }
                initial = first_order(workload["id"])
                for index in range(1, 4):
                    order = initial if index % 2 else initial[::-1]
                    samples = {}
                    for letter in order:
                        arm = "baseline" if letter == "A" else "candidate"
                        samples[arm] = [self.sample(row, arm, "sample", index, order.index(letter))]
                    row["rounds"].append({
                        "index": index, "order": order, "cooldown_seconds": 1.0,
                        **samples,
                    })
                row["summary"] = {
                    "paired_throughput_ratios": [1.0, 1.0, 1.0],
                    "hodges_lehmann": 1.0, "ci_lower": 1.0, "ci_upper": 1.0,
                    "baseline_peak_rss_bytes": 100, "candidate_peak_rss_bytes": 100,
                    "peak_rss_ratio": 1.0,
                }
                row["verdict"] = "PASS"
                self.rows.append(row)

    def add_specials(self) -> tuple[list[dict], dict]:
        proof = b"canonical-proof"
        proof_sha = sha256_bytes(proof)
        verifier = {"schema": "proof-verifier-v1", "local_verified": True, "rust_oracle_verified": True, "canonical_proof_sha256": proof_sha}
        aot_seq = self.attempt("macos", "aot:candidate:metal-hybrid", "aot-check", proof=proof, verifier=verifier)
        aot_attempt = self.attempts["macos"][aot_seq - 1]
        identity = self.artifact("aot-identity", canonical_bytes({
            "schema": "metal-aot-identity-v1", "source_sha256": "4" * 64,
            "manifest_sha256": "5" * 64, "metallib_sha256": "6" * 64,
            "sdk": "test", "metal_runtime": "test",
        }), "aot-identity")
        metal_build = next(item for item in self.builds if item["id"] == "macos-native-metal")
        aot = [{
            "host_role": "macos", "backend": "metal-hybrid", "runtime_mode": "authenticated-aot",
            "attempt_sequence": aot_seq, "executable_artifact": metal_build["candidate"]["executable_artifact"],
            "aot_identity_artifact": identity, "proof_artifact": aot_attempt["artifacts"]["proof"],
            "verifier_artifact": aot_attempt["artifacts"]["verifier"], "no_runtime_compilation": True,
            "metal_device_dispatches": 1, "metal_fallback_count": 0,
            "cold_initialization_seconds": 0.1, "verdict": "PASS",
        }]
        challenge_verifier = {"schema": "riscv-challenge-verifier-v1", "local_verified": True, "stark_v_verified": True, "proof_sha256": proof_sha}
        challenge_seq = self.attempt(
            "linux", "challenge:candidate:riscv", "riscv-challenge", proof=proof,
            verifier=challenge_verifier, timing={"schema": "process-timing-v1", "wall_seconds": 2.0},
        )
        challenge_attempt = self.attempts["linux"][challenge_seq - 1]
        bundle_identity = {
            "repository": self.protocol["trusted_stark_v"]["repository"],
            "commit": self.protocol["trusted_stark_v"]["commit"], "tree": "7" * 40,
            "rust_toolchain": "nightly", "executable_sha256": "8" * 64,
            "manifest_sha256": "9" * 64,
        }
        bundle = self.artifact("trusted-bundle", canonical_bytes({"schema": "trusted-stark-v-bundle-v1", "identity": bundle_identity}), "trusted-bundle")
        challenge = {
            "host_role": "linux", "attempt_sequence": challenge_seq,
            "trusted_bundle_identity": bundle_identity, "trusted_bundle_artifact": bundle,
            "proof_artifact": challenge_attempt["artifacts"]["proof"],
            "verifier_artifact": challenge_attempt["artifacts"]["verifier"],
            "total_seconds": 2.0, "allocated_at_unix_ns": 1_000_000_000,
            "verified_at_unix_ns": 3_000_000_000, "complete_clock_scope": True,
            "locally_verified": True, "pinned_stark_v_verified": True, "verdict": "PASS",
        }
        self.attempt(
            "linux", "challenge:candidate:riscv", "riscv-challenge",
            status="infrastructure_failure",
        )
        return aot, challenge

    def seal_sessions(self) -> dict:
        sessions = {}
        for role in ("linux", "macos"):
            plan_paths = self.plans[role]["paths"]
            role_attempts = self.attempts[role]
            ledger = self.artifact("attempt-ledger", canonical_bytes({
                "schema": "build-monorepo-performance-attempt-ledger-v1", "attempts": role_attempts,
            }), f"{role}-ledger")
            journal = self.artifact("attempt-journal", b"".join(canonical_bytes(item) for item in role_attempts), f"{role}-journal")
            host = {
                "runner_id": f"runner-{role}", "os": "Linux" if role == "linux" else "macOS",
                "os_version": "test", "kernel": "test", "cpu": "test", "logical_cpu_count": 8,
                "gpu": "none" if role == "linux" else "Apple test", "memory_bytes": 1024,
                "filesystem": "ssd", "power_source": "ac", "thermal_state": "nominal",
                "sdk": "test", "metal_runtime": "not_applicable" if role == "linux" else "Metal test",
            }
            toolchains = {"zig": "0.15.2", "python": "3", "rust_toolchain": "nightly", "rustc": "test"}
            conditions = {"profiler_attached": False, "unrelated_sustained_work": False, "power_source_changed": False, "thermal_throttling": False}
            caches = {
                arm: {
                    scope: {"path": plan_paths[f"{arm}_{scope}_cache"], "initially_empty": True}
                    for scope in ("local", "global")
                } for arm in ("baseline", "candidate")
            }
            attestation = {
                "schema": "build-performance-producer-attestation-v1", "provider": "github-actions",
                "repository": self.protocol["repository"], "workflow_sha": "c" * 40,
                "run_id": 1, "run_attempt": 1, "job": f"performance-{role}",
                "artifact_name": f"performance-{role}-1", "plan_sha256": self.plan_digests[role],
                "session_nonce": self.plans[role]["session_nonce"], "attempt_count": len(role_attempts),
                "terminal_attempt_sha256": self.previous[role],
                "host_sha256": sha256_bytes(canonical_bytes(host)),
                "toolchains_sha256": sha256_bytes(canonical_bytes(toolchains)),
                "conditions_sha256": sha256_bytes(canonical_bytes(conditions)),
                "caches_sha256": sha256_bytes(canonical_bytes(caches)),
                "raw_bundle_sha256": "0" * 64,
            }
            attestation["attestation_sha256"] = sha256_bytes(canonical_bytes(attestation))
            self.trusted[role] = attestation["attestation_sha256"]
            sessions[role] = {
                "host_role": role, "plan_sha256": self.plan_digests[role],
                "session_nonce": self.plans[role]["session_nonce"],
                "started_at_unix_ns": 1, "ended_at_unix_ns": 10_000_000,
                "host": host, "toolchains": toolchains, "conditions": conditions,
                "caches": caches,
                "attempt_ledger_artifact": ledger, "attempt_journal_artifact": journal,
                "producer_attestation": attestation,
            }
        return sessions

    def build(self) -> tuple[dict, Path]:
        self.add_builds()
        self.add_rows()
        aot, challenge = self.add_specials()
        sessions = self.seal_sessions()
        bundle = {"schema": "build-monorepo-performance-raw-bundle-v1", "schema_version": 1, "artifacts": self.artifacts}
        bundle["content_sha256"] = content_digest(bundle)
        for role, session in sessions.items():
            attestation = session["producer_attestation"]
            attestation["raw_bundle_sha256"] = bundle["content_sha256"]
            attestation["attestation_sha256"] = sha256_bytes(canonical_bytes({
                key: item for key, item in attestation.items() if key != "attestation_sha256"
            }))
            self.trusted[role] = attestation["attestation_sha256"]
        receipt = {
            "schema": "build-monorepo-performance-baseline-v2", "schema_version": 2,
            "created_at_unix": 1_800_000_000, "protocol_sha256": self.protocol_sha256,
            "authority": copy.deepcopy(self.protocol["authority"]),
            "plan_sha256": copy.deepcopy(self.plan_digests), "sources": copy.deepcopy(self.sources),
            "sessions": sessions, "raw_bundle": bundle, "attempts": self.attempts,
            "build_comparisons": self.builds, "performance_rows": self.rows,
            "aot_checks": aot, "riscv_challenge": challenge, "verdict": "PASS",
        }
        receipt["content_sha256"] = content_digest(receipt)
        path = self.root / "receipt.json"
        atomic_write(path, receipt)
        return receipt, path

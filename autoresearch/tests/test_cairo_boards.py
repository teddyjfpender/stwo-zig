"""Wave-1 Cairo tracks: manifest groups, cairo_proof_v1 parser, ledger boards.

Contract: autoresearch/TRACKS.md §2 (track taxonomy), §3.1-3.3 (dual boundary,
named phase cutpoints, workload baskets), §3.4 (objective boards must be
registered in ledger.BOARDS), §7 (calibration gates promotion), §8 (wave 1).
"""

import copy
import hashlib
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))
from stwo_perf import ledger, manifest as manifest_mod, runner
from stwo_perf.manifest import Manifest, ManifestError

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cairo"

PINNED_STWO_CAIRO = "82f21252a68ec006d73e299f5bf1ce6d4db0ee78"
PINNED_STWO = "7b211edde786775016ef3eecb837a6240d8fe792"

CAIRO_ARGS = (
    "prove --prover-input vectors/cairo/official/all_opcodes.prover_input.json "
    "--params vectors/cairo/official/all_opcodes.params.json "
    "--proof-format json --verify"
)

FAKE_PRODUCT = '''#!/usr/bin/env python3
import hashlib
import json
import sys

REPORT = json.loads(REPORT_JSON)
PROFILE = json.loads(PROFILE_JSON)

args = sys.argv[1:]
proof_path = args[args.index("--proof") + 1]
payload = PROOF_PAYLOAD
with open(proof_path, "wb") as handle:
    handle.write(payload)
REPORT["proof"]["bytes"] = len(payload)
REPORT["proof"]["sha256"] = hashlib.sha256(payload).hexdigest()
if "--stage-profile-out" in args:
    with open(args[args.index("--stage-profile-out") + 1], "w") as handle:
        json.dump(PROFILE, handle)
MUTATE
print(json.dumps(REPORT))
'''


def load_report() -> dict:
    return json.loads((FIXTURES / "cairo_product_report_v2.json").read_text())


def load_profile() -> dict:
    return json.loads((FIXTURES / "cairo_stage_profile_v1.json").read_text())


def cairo_group_spec(**overrides) -> dict:
    spec = {
        "enabled": True,
        "promotion_eligible": False,
        "promotion_blocked_reason": "no judge-host calibration yet",
        "board": "cairo_cpu",
        "build_step": "true",
        "binary": "bin/stwo-cairo-cpu",
        "report_schema": "cairo_proof_v1",
        "correctness_oracle": {
            "authority": "official-stwo-cairo-verifier",
            "repository": "https://github.com/starkware-libs/stwo-cairo",
            "commit": PINNED_STWO_CAIRO,
            "stwo_repository": "https://github.com/starkware-libs/stwo",
            "stwo_commit": PINNED_STWO,
            "adapter": "tools/stwo-cairo-official-verifier-rs",
            "build_command": "cargo build --locked --release",
            "final_validator": True,
        },
        "gates_policy": {
            "warmups": 1,
            "samples_per_round": 1,
            "min_rounds": 3,
            "max_rounds": 3,
        },
        "mechanism_telemetry": {
            "fail_closed": True,
            "required_fields": [
                "product_identity_sha256", "protocol_manifest_sha256", "profile",
                "input_sha256", "proof_format", "proof_bytes", "proof_sha256",
                "stwo_cairo_revision", "stwo_revision", "mean_execute_seconds",
                "mean_prove_seconds", "mean_verify_seconds",
                "mean_cold_process_seconds", "phase_seconds",
            ],
        },
        "workloads": {
            "cairo_all_opcodes": {
                "class": "small",
                "args": CAIRO_ARGS,
                "native_unit": "committed cells",
            },
        },
    }
    spec.update(overrides)
    return spec


def raw_manifest(**overrides) -> dict:
    return {
        "manifest_version": 2,
        "harness": {"anchor_commit": None},
        "editable_paths": [],
        "locked_paths": [],
        "gates_policy": {
            "ci_level": 0.95,
            "theta_floor": 0.01,
            "dispersion_multiplier": 2.0,
            "warmups": 1,
            "samples_per_round": 1,
            "min_rounds": 3,
            "max_rounds": 3,
            "search_health": {
                "trailing_window": 4,
                "gradient_snr_threshold": 2.0,
                "auto_boost_rounds": 2,
                "maximum_rounds": 8,
            },
            "wall_clock_cap_seconds": {"small": 120},
        },
        "qualification_policy": {
            "required_checks": ["allowed_diff"],
            "max_active_per_user": 1,
        },
        "workload_registry": {
            "classes": {
                "small": {
                    "scored": True,
                    "resource": {
                        "profile": "standard",
                        "command_timeout_seconds": 120,
                        "wall_clock_cap_seconds": 120,
                    },
                    "sampling": {
                        "warmups": 1,
                        "samples_per_round": 1,
                        "min_rounds": 3,
                        "max_rounds": 3,
                    },
                },
            },
            "groups": {"cairo_cpu": cairo_group_spec(**overrides)},
        },
    }


class CairoManifestGroupTest(unittest.TestCase):
    """The committed MANIFEST.json actually declares the wave-1 Cairo tracks."""

    @classmethod
    def setUpClass(cls):
        cls.m = manifest_mod.load(REPO_ROOT)

    def test_cairo_cpu_is_live_and_never_promotion_eligible(self):
        group = self.m.group_for_board("cairo_cpu")
        self.assertEqual(group.group_id, "cairo_cpu")
        self.assertTrue(group.enabled)
        self.assertFalse(group.promotion_eligible)
        self.assertIn("calibration", (group.promotion_blocked_reason or "").lower())
        self.assertEqual(
            group.build_step, "zig build stwo-cairo-cpu -Doptimize=ReleaseFast",
        )
        self.assertEqual(group.binary, "zig-out/bin/stwo-cairo-cpu")
        self.assertEqual(group.report_schema, "cairo_proof_v1")

    def test_cairo_metal_is_staged_dark_like_the_cuda_group(self):
        group = self.m.group_for_board("cairo_metal")
        self.assertFalse(group.enabled)
        self.assertFalse(group.promotion_eligible)
        self.assertIn("parity_gated", group.disabled_reason)
        self.assertEqual(
            group.build_step, "zig build stwo-cairo-metal -Doptimize=ReleaseFast",
        )
        self.assertEqual(group.binary, "zig-out/bin/stwo-cairo-metal")
        self.assertEqual(group.report_schema, "cairo_proof_v1")

    def test_both_cairo_groups_pin_the_official_verifier_as_final_validator(self):
        cargo = (
            REPO_ROOT / "tools" / "stwo-cairo-official-verifier-rs" / "Cargo.toml"
        ).read_text()
        self.assertIn(f'stwo-cairo-revision = "{PINNED_STWO_CAIRO}"', cargo)
        self.assertIn(f'stwo-revision = "{PINNED_STWO}"', cargo)
        for board in ("cairo_cpu", "cairo_metal"):
            oracle = self.m.group_for_board(board).correctness_oracle
            self.assertEqual(oracle["authority"], "official-stwo-cairo-verifier")
            self.assertEqual(oracle["commit"], PINNED_STWO_CAIRO)
            self.assertEqual(oracle["stwo_commit"], PINNED_STWO)
            self.assertEqual(
                oracle["adapter"], "tools/stwo-cairo-official-verifier-rs",
            )
            self.assertIs(oracle["final_validator"], True)

    def test_cairo_workloads_use_committed_fixtures_and_standard_classes(self):
        for board in ("cairo_cpu", "cairo_metal"):
            group = self.m.group_for_board(board)
            self.assertTrue(group.workloads)
            for workload in group.workloads:
                self.assertIn(workload.workload_class, ("small", "wide"))
                command, proof_format, verify = runner._cairo_command(workload)
                self.assertEqual(command, "prove")
                self.assertEqual(proof_format, "json")
                self.assertTrue(verify)
                fixture = workload.args.split("--prover-input ")[1].split(" ")[0]
                params = workload.args.split("--params ")[1].split(" ")[0]
                self.assertTrue((REPO_ROOT / fixture).is_file(), fixture)
                self.assertTrue((REPO_ROOT / params).is_file(), params)

    def test_acceptance_corpus_is_wired_and_digest_bound(self):
        corpus = self.m.group_for_board("cairo_cpu").acceptance_corpus
        self.assertEqual(corpus["path"], "vectors/cairo/cairo_program_matrix.json")
        payload = (REPO_ROOT / corpus["path"]).read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), corpus["sha256"])
        matrix = json.loads(payload)
        self.assertEqual(matrix["kind"], "cairo_acceptance_corpus")
        self.assertEqual(
            matrix["source_repository"]["url"],
            "https://github.com/zksecurity/zkvm-benchmarks.git",
        )

    def test_uncommitted_portfolio_entries_are_declared_not_hidden(self):
        provisioning = self.m.group_for_board("cairo_cpu").workload_provisioning
        pending = provisioning["pending"]
        self.assertIn("cairo_memory_7m", pending)
        self.assertEqual(pending["cairo_memory_7m"]["committed_cells"], 604162096)
        runnable = {
            w.workload_id for w in self.m.group_for_board("cairo_cpu").workloads
        }
        self.assertEqual(runnable & set(pending), set())
        self.assertEqual(
            provisioning["documentation"], "autoresearch/schema/cairo-proof-v1.md",
        )
        self.assertTrue(
            (REPO_ROOT / provisioning["documentation"]).is_file(),
        )

    def test_cairo_report_schema_is_registered(self):
        self.assertIn("cairo_proof_v1", manifest_mod.REPORT_SCHEMA_VERSIONS)
        self.assertEqual(manifest_mod.REPORT_SCHEMA_VERSIONS["cairo_proof_v1"], 1)


class CairoManifestValidationTest(unittest.TestCase):
    """Every Cairo-specific manifest rule fails closed."""

    def _load(self, **overrides) -> Manifest:
        raw = raw_manifest(**overrides)
        manifest_mod._validate(raw)
        return Manifest(root=REPO_ROOT, raw=raw)

    def test_valid_fixture_group_loads(self):
        manifest = self._load()
        self.assertEqual(manifest.group("cairo_cpu").board, "cairo_cpu")

    def test_promotion_eligible_cairo_group_is_rejected(self):
        raw = raw_manifest()
        raw["workload_registry"]["groups"]["cairo_cpu"]["promotion_eligible"] = True
        with self.assertRaisesRegex(ManifestError, "promotion eligible"):
            manifest_mod._validate(raw)

    def test_live_unpromotable_group_must_say_why(self):
        raw = raw_manifest()
        del raw["workload_registry"]["groups"]["cairo_cpu"]["promotion_blocked_reason"]
        with self.assertRaisesRegex(ManifestError, "promotion_blocked_reason"):
            manifest_mod._validate(raw)

    def test_missing_oracle_is_rejected(self):
        raw = raw_manifest()
        del raw["workload_registry"]["groups"]["cairo_cpu"]["correctness_oracle"]
        with self.assertRaisesRegex(ManifestError, "correctness_oracle must pin"):
            manifest_mod._validate(raw)

    def test_unpinned_oracle_commit_is_rejected(self):
        raw = raw_manifest()
        oracle = raw["workload_registry"]["groups"]["cairo_cpu"]["correctness_oracle"]
        oracle["commit"] = "82f21252"
        with self.assertRaisesRegex(ManifestError, "full lowercase Git commit"):
            manifest_mod._validate(raw)

    def test_non_final_validator_oracle_is_rejected(self):
        raw = raw_manifest()
        oracle = raw["workload_registry"]["groups"]["cairo_cpu"]["correctness_oracle"]
        oracle["final_validator"] = False
        with self.assertRaisesRegex(ManifestError, "final validator"):
            manifest_mod._validate(raw)

    def test_foreign_oracle_authority_is_rejected(self):
        raw = raw_manifest()
        oracle = raw["workload_registry"]["groups"]["cairo_cpu"]["correctness_oracle"]
        oracle["authority"] = "pinned-rust-stwo"
        with self.assertRaisesRegex(ManifestError, "official stwo-cairo verifier"):
            manifest_mod._validate(raw)

    def test_unknown_mechanism_field_is_rejected(self):
        raw = raw_manifest()
        group = raw["workload_registry"]["groups"]["cairo_cpu"]
        group["mechanism_telemetry"]["required_fields"].append("prove_ms")
        with self.assertRaisesRegex(ManifestError, "unsupported mechanism field"):
            manifest_mod._validate(raw)

    def test_missing_stable_mechanism_field_is_rejected(self):
        raw = raw_manifest()
        group = raw["workload_registry"]["groups"]["cairo_cpu"]
        group["mechanism_telemetry"]["required_fields"].remove("proof_sha256")
        with self.assertRaisesRegex(ManifestError, "omits stable field"):
            manifest_mod._validate(raw)

    def test_missing_phase_telemetry_is_rejected(self):
        raw = raw_manifest()
        group = raw["workload_registry"]["groups"]["cairo_cpu"]
        group["mechanism_telemetry"]["required_fields"].remove("phase_seconds")
        with self.assertRaisesRegex(ManifestError, "phase_seconds"):
            manifest_mod._validate(raw)

    def test_lax_mechanism_telemetry_is_rejected(self):
        raw = raw_manifest()
        group = raw["workload_registry"]["groups"]["cairo_cpu"]
        group["mechanism_telemetry"]["fail_closed"] = False
        with self.assertRaisesRegex(ManifestError, "must fail closed"):
            manifest_mod._validate(raw)

    def test_resource_telemetry_is_refused_for_cairo(self):
        raw = raw_manifest()
        group = raw["workload_registry"]["groups"]["cairo_cpu"]
        group["resource_telemetry"] = {"fail_closed": True}
        with self.assertRaisesRegex(ManifestError, "only valid for"):
            manifest_mod._validate(raw)

    def test_acceptance_corpus_shape_fails_closed(self):
        raw = raw_manifest()
        group = raw["workload_registry"]["groups"]["cairo_cpu"]
        group["acceptance_corpus"] = {"path": "vectors/x.json"}
        with self.assertRaisesRegex(ManifestError, "requires path and sha256"):
            manifest_mod._validate(raw)
        group["acceptance_corpus"] = {"path": "/etc/passwd", "sha256": "a" * 64}
        with self.assertRaisesRegex(ManifestError, "repository vectors path"):
            manifest_mod._validate(raw)
        group["acceptance_corpus"] = {"path": "vectors/x.json", "sha256": "nope"}
        with self.assertRaisesRegex(ManifestError, "canonical lowercase SHA-256"):
            manifest_mod._validate(raw)

    def test_drifted_acceptance_corpus_digest_fails_the_load(self):
        raw = json.loads((REPO_ROOT / "autoresearch" / "MANIFEST.json").read_text())
        group = raw["workload_registry"]["groups"]["cairo_cpu"]
        group["acceptance_corpus"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ManifestError, "digest drifted"):
            manifest_mod._validate_acceptance_corpora(REPO_ROOT, raw)

    def test_missing_acceptance_corpus_fails_a_complete_checkout(self):
        raw = json.loads((REPO_ROOT / "autoresearch" / "MANIFEST.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "vectors" / "cairo").mkdir(parents=True)
            with self.assertRaisesRegex(ManifestError, "not readable"):
                manifest_mod._validate_acceptance_corpora(repo, raw)

    def test_harness_only_tree_has_no_corpus_to_bind(self):
        raw = json.loads((REPO_ROOT / "autoresearch" / "MANIFEST.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            manifest_mod._validate_acceptance_corpora(Path(tmp), raw)

    def test_pending_provisioning_entries_are_shape_checked(self):
        raw = raw_manifest()
        group = raw["workload_registry"]["groups"]["cairo_cpu"]
        group["workload_provisioning"] = {
            "note": "n", "documentation": "d",
            "pending": {"x": {"vm_steps": 1, "committed_cells": 2, "reason": "r"}},
        }
        manifest_mod._validate(raw)
        group["workload_provisioning"]["pending"]["x"]["vm_steps"] = 0
        with self.assertRaisesRegex(ManifestError, "positive integer"):
            manifest_mod._validate(raw)

    def test_pending_entry_cannot_shadow_a_runnable_workload(self):
        raw = raw_manifest()
        group = raw["workload_registry"]["groups"]["cairo_cpu"]
        group["workload_provisioning"] = {
            "note": "n", "documentation": "d",
            "pending": {
                "cairo_all_opcodes": {
                    "vm_steps": 1, "committed_cells": 2, "reason": "r",
                },
            },
        }
        with self.assertRaisesRegex(ManifestError, "both a runnable workload"):
            manifest_mod._validate(raw)


class CairoLedgerBoardsTest(unittest.TestCase):
    def test_wave_one_boards_are_registered(self):
        for board in ("cairo_cpu", "cairo_metal", "pr6_supremacy"):
            self.assertIn(board, ledger.BOARDS)

    def test_boards_are_append_only(self):
        historical = (
            "core_cpu", "core_hybrid", "core_metal", "core_cuda",
            "heavy_native", "heavy_cairo", "stream", "riscv",
        )
        self.assertEqual(ledger.BOARDS[:len(historical)], historical)
        self.assertEqual(len(set(ledger.BOARDS)), len(ledger.BOARDS))

    def test_every_manifest_board_is_a_registered_board(self):
        manifest = manifest_mod.load(REPO_ROOT)
        for group in manifest.groups():
            self.assertIn(group.board, ledger.BOARDS, group.group_id)


class CairoReportParserTest(unittest.TestCase):
    """cairo_proof_v1 parsing is fail-closed on a real product report."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        raw = raw_manifest()
        manifest_mod._validate(raw)
        self.manifest = Manifest(root=self.root, raw=raw)
        self.group = self.manifest.group("cairo_cpu")
        self.workload = self.manifest.workloads(board="cairo_cpu")[0]
        self.report = load_report()
        self.proof = self.root / "proof.json"
        payload = b"cairo-proof-artifact"
        self.proof.write_bytes(payload)
        self.report["proof"]["bytes"] = len(payload)
        self.report["proof"]["sha256"] = hashlib.sha256(payload).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def _parse(self, report=None):
        return runner._parse_cairo_report(
            report if report is not None else self.report,
            self.group, self.workload, self.proof,
        )

    def test_valid_report_is_accepted_and_normalized(self):
        parsed = self._parse()
        self.assertEqual(parsed["stwo_cairo_revision"], PINNED_STWO_CAIRO)
        self.assertEqual(parsed["stwo_revision"], PINNED_STWO)
        self.assertEqual(parsed["proof_format"], "json")
        self.assertEqual(parsed["profile"], "official-live-cairo-canonical-small")
        self.assertEqual(len(parsed["product_identity_sha256"]), 64)
        self.assertGreater(parsed["prove_seconds"], 0.0)
        self.assertGreater(parsed["verify_seconds"], 0.0)
        self.assertEqual(parsed["execute_seconds"], 0.0)
        self.assertEqual(parsed["cpu_fallbacks"], 0)

    def test_wrong_product_schema_version_is_rejected(self):
        self.report["schema_version"] = 3
        with self.assertRaisesRegex(runner.RunError, "expected cairo_proof_v1"):
            self._parse()

    def test_unknown_top_level_field_is_rejected(self):
        self.report["extra"] = 1
        with self.assertRaisesRegex(ValueError, r"unknown=\['extra'\]"):
            self._parse()

    def test_unpinned_upstream_revision_is_rejected(self):
        self.report["product"]["upstream"]["stwo_cairo_revision"] = "a" * 40
        with self.assertRaisesRegex(ValueError, "manifest-pinned"):
            self._parse()
        self.report["product"]["upstream"]["stwo_cairo_revision"] = PINNED_STWO_CAIRO
        self.report["product"]["upstream"]["stwo_revision"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "manifest-pinned"):
            self._parse()

    def test_foreign_product_binary_is_rejected(self):
        self.report["product"]["name"] = "stwo-cairo-metal"
        with self.assertRaisesRegex(ValueError, "declared binary"):
            self._parse()

    def test_debug_build_is_rejected(self):
        self.report["product"]["optimize"] = "Debug"
        with self.assertRaisesRegex(ValueError, "ReleaseFast"):
            self._parse()

    def test_backend_fallback_is_rejected(self):
        self.report["backend_evidence"]["cpu_fallbacks"] = 1
        with self.assertRaisesRegex(ValueError, "cpu_fallbacks must be zero"):
            self._parse()

    def test_unverified_sample_is_rejected(self):
        self.report["verification"]["zig"] = False
        with self.assertRaisesRegex(ValueError, "completed in-process"):
            self._parse()

    def test_report_must_bind_the_retained_proof(self):
        self.report["proof"]["sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "does not match the retained proof"):
            self._parse()
        self.report["proof"]["sha256"] = "not-hex"
        with self.assertRaisesRegex(ValueError, "canonical lowercase SHA-256"):
            self._parse()

    def test_missing_proof_artifact_is_rejected(self):
        self.proof.unlink()
        with self.assertRaisesRegex(ValueError, "did not retain the requested proof"):
            self._parse()

    def test_prove_report_may_not_claim_execution(self):
        self.report["execution"] = {
            "program_type": "json", "program_sha256": "d" * 64,
            "arguments_sha256": None, "adapter_sha256": "e" * 64, "wall_ns": 5,
        }
        with self.assertRaisesRegex(ValueError, "null execution"):
            self._parse()

    def test_workload_without_verify_is_refused(self):
        raw = raw_manifest()
        args = CAIRO_ARGS.replace(" --verify", "")
        raw["workload_registry"]["groups"]["cairo_cpu"]["workloads"][
            "cairo_all_opcodes"]["args"] = args
        manifest_mod._validate(raw)
        workload = Manifest(self.root, raw).workloads(board="cairo_cpu")[0]
        with self.assertRaisesRegex(ValueError, "must request --verify"):
            runner._parse_cairo_report(
                self.report, self.group, workload, self.proof,
            )

    def test_workload_may_not_own_the_runner_output_paths(self):
        raw = raw_manifest()
        raw["workload_registry"]["groups"]["cairo_cpu"]["workloads"][
            "cairo_all_opcodes"]["args"] = CAIRO_ARGS + " --proof /tmp/x.json"
        manifest_mod._validate(raw)
        workload = Manifest(self.root, raw).workloads(board="cairo_cpu")[0]
        with self.assertRaisesRegex(ValueError, "runner owns"):
            runner._parse_cairo_report(
                self.report, self.group, workload, self.proof,
            )

    def test_declared_proof_format_must_match(self):
        self.report["proof"]["format"] = "binary"
        with self.assertRaisesRegex(ValueError, "is not the requested"):
            self._parse()


class CairoStageProfileTest(unittest.TestCase):
    """TRACKS §3.2 named cutpoints: complete, classified, or fail closed."""

    def setUp(self):
        raw = raw_manifest()
        manifest_mod._validate(raw)
        self.workload = Manifest(REPO_ROOT, raw).workloads(board="cairo_cpu")[0]
        self.profile = load_profile()

    def test_every_named_cutpoint_is_derived(self):
        phases = runner._parse_cairo_stage_profile(self.profile, self.workload)
        self.assertEqual(
            set(phases),
            {"witness", "commit", "interaction", "composition", "fri"},
        )
        for phase, seconds in phases.items():
            self.assertGreater(seconds, 0.0, phase)

    def test_phase_partition_covers_every_root_exactly_once(self):
        owners = {}
        for phase, (required, optional) in runner.CAIRO_PHASE_STAGES.items():
            for stage_id in required + optional:
                self.assertNotIn(stage_id, owners)
                owners[stage_id] = phase
        roots = [node["id"] for node in self.profile["stages"]]
        self.assertTrue(set(roots) <= set(owners))
        total = sum(node["seconds"] for node in self.profile["stages"])
        phases = runner._parse_cairo_stage_profile(self.profile, self.workload)
        self.assertAlmostEqual(total, sum(phases.values()), places=9)

    def test_unclassified_stage_root_fails_closed(self):
        profile = copy.deepcopy(self.profile)
        profile["stages"].append(
            {"id": "brand_new_stage", "label": "New", "seconds": 1.0},
        )
        with self.assertRaisesRegex(ValueError, "unclassified Cairo stage root"):
            runner._parse_cairo_stage_profile(profile, self.workload)

    def test_missing_mandatory_cutpoint_fails_closed(self):
        profile = copy.deepcopy(self.profile)
        profile["stages"] = [
            node for node in profile["stages"]
            if node["id"] != "fri_quotient_build_and_commit"
        ]
        with self.assertRaisesRegex(ValueError, "missing mandatory cutpoint"):
            runner._parse_cairo_stage_profile(profile, self.workload)

    def test_wrong_stage_schema_version_fails_closed(self):
        profile = copy.deepcopy(self.profile)
        profile["schema_version"] = 2
        with self.assertRaisesRegex(ValueError, "schema_version is not"):
            runner._parse_cairo_stage_profile(profile, self.workload)

    def test_non_cairo_profile_fails_closed(self):
        profile = copy.deepcopy(self.profile)
        profile["example"] = "wide_fibonacci"
        with self.assertRaisesRegex(ValueError, "not a Cairo profile"):
            runner._parse_cairo_stage_profile(profile, self.workload)

    def test_manifest_declares_the_full_named_cutpoint_set(self):
        derived = set(runner.CAIRO_PHASE_STAGES) | {"execute", "verify"}
        derived |= set(runner.CAIRO_UNINSTRUMENTED_PHASES)
        self.assertEqual(derived, set(manifest_mod.CAIRO_PHASE_NAMES))


class CairoBenchOnceTest(unittest.TestCase):
    """bench_once dispatches Cairo to the cold-process warmup/sample loop."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.out_dir = self.root / "runs"
        raw = raw_manifest()
        manifest_mod._validate(raw)
        self.manifest = Manifest(root=self.root, raw=raw)
        self.workload = self.manifest.workloads(board="cairo_cpu")[0]
        self._install_product()

    def tearDown(self):
        self.tmp.cleanup()

    def _install_product(self, mutate: str = "pass", payload: bytes = b"proof-bytes"):
        binary = self.root / "bin" / "stwo-cairo-cpu"
        binary.parent.mkdir(parents=True, exist_ok=True)
        source = (
            FAKE_PRODUCT
            .replace("REPORT_JSON", repr(json.dumps(load_report())))
            .replace("PROFILE_JSON", repr(json.dumps(load_profile())))
            .replace("PROOF_PAYLOAD", repr(payload))
            .replace("MUTATE", mutate)
        )
        binary.write_text(source)
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)

    def test_cold_process_loop_produces_dual_boundary_and_phases(self):
        result = runner.bench_once(
            self.root, self.manifest, self.workload, 1, 2, self.out_dir, "a1",
        )
        self.assertEqual(result.proof_verified, 2)
        self.assertTrue(result.byte_identical)
        self.assertGreater(result.prove_ms, 0.0)
        self.assertGreater(result.request_ms, 0.0)
        self.assertEqual(result.peak_rss_mib, None)
        self.assertIs(result.resources_complete, False)
        phases = result.mechanism["phase_seconds"]
        self.assertEqual(set(phases), set(manifest_mod.CAIRO_PHASE_NAMES))
        self.assertIsNone(phases["serialize"])
        self.assertGreater(phases["fri"], 0.0)
        envelope = json.loads(Path(result.report_path).read_text())
        self.assertEqual(envelope["schema"], "cairo_proof_v1")
        self.assertEqual(envelope["measurement_boundary"], "cold_process")
        self.assertEqual(len(envelope["measured_samples"]), 2)
        self.assertEqual(len(envelope["product_reports"]), 2)
        self.assertFalse(envelope["phase_profile_source"]["scored"])

    def test_mechanism_covers_exactly_the_declared_required_fields(self):
        result = runner.bench_once(
            self.root, self.manifest, self.workload, 1, 1, self.out_dir, "a1",
        )
        declared = self.manifest.group("cairo_cpu").mechanism_telemetry[
            "required_fields"]
        self.assertEqual(sorted(result.mechanism), sorted(declared))
        self.assertTrue(
            set(declared) <= manifest_mod.CAIRO_MECHANISM_FIELDS,
        )

    def test_phase_profile_is_recorded_on_the_last_discarded_warmup(self):
        runner.bench_once(
            self.root, self.manifest, self.workload, 2, 1, self.out_dir, "a1",
        )
        stages = list(self.out_dir.glob("cairo_all_opcodes.a1.stages.json"))
        self.assertEqual(len(stages), 1)
        # Warmup proofs are removed; exactly the measured samples are retained.
        proofs = sorted(p.name for p in self.out_dir.glob("*.proof"))
        self.assertEqual(proofs, ["cairo_all_opcodes.a1.i2.proof"])

    def test_zero_warmups_is_refused_because_phase_telemetry_is_mandatory(self):
        with self.assertRaisesRegex(runner.RunError, "at least one warmup"):
            runner.bench_once(
                self.root, self.manifest, self.workload, 0, 1, self.out_dir, "a1",
            )

    def test_drifting_statement_between_samples_fails_closed(self):
        self._install_product(
            mutate='\nif proof_path.endswith("i2.proof"):\n'
                   '    REPORT["input"]["sha256"] = "f" * 64\n',
        )
        with self.assertRaisesRegex(runner.RunError, "input_sha256 changed"):
            runner.bench_once(
                self.root, self.manifest, self.workload, 1, 2, self.out_dir, "a1",
            )

    def test_missing_binary_refuses_to_fabricate(self):
        (self.root / "bin" / "stwo-cairo-cpu").unlink()
        with self.assertRaisesRegex(runner.RunError, "refusing to fabricate"):
            runner.bench_once(
                self.root, self.manifest, self.workload, 1, 1, self.out_dir, "a1",
            )


if __name__ == "__main__":
    unittest.main()

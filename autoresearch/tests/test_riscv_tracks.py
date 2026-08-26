"""Wave-2 RISC-V tracks: riscv_metal registration and the era-3 staged basket.

Contract: autoresearch/TRACKS.md §2 (track taxonomy — riscv_metal is a wave-2
track), §3.1 (the scored boundary), §3.3 (workload baskets and the killer
set), §7 (per-board eras; a class-universe change is a new era), §8 (wave 2),
plus the user directive to accelerate the wave-2 RISC-V items.

The load-bearing property in this file is negative: nothing landed here may
change what the riscv board scores in era 2. That is enforced structurally
(staged rows live outside `workloads`), by validation (`manifest.py` refuses
overlap), and by the pinned era-2 universe digest below.
"""

import copy
import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))
from stwo_perf import ledger, manifest as manifest_mod
from stwo_perf.manifest import Manifest, ManifestError

REPO_ROOT = Path(__file__).resolve().parents[2]

CSP_MANIFEST = "vectors/riscv_csp/manifest-v2.json"
RISCV_CORPUS = "vectors/riscv_guests/riscv_program_matrix.json"

# TRACKS §7: the riscv board's era-2 scoring universe, frozen. This is the
# canonical digest of `workload_registry.groups.riscv.workloads` — the exact
# set of rows era 2 scores. Changing a scored board's basket is a new era, so
# moving this pin is only legitimate in the same change that opens era 3 (the
# operator sequence is in autoresearch/schema/scoring.md). A staged basket
# addition must NEVER move it.
ERA_2_RISCV_UNIVERSE_SHA256 = (
    "b4704d69d1bdb15e941dd0f91207323e0ac2bc940b88e8bdbe000113035adfbf"
)
ERA_2_RISCV_WORKLOAD_COUNT = 20


def universe_digest(workloads: dict) -> str:
    payload = json.dumps(workloads, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def raw_manifest() -> dict:
    return json.loads((REPO_ROOT / "autoresearch" / "MANIFEST.json").read_text())


class RiscvMetalRegistrationTest(unittest.TestCase):
    """The wave-2 RISC-V Metal track is registered, staged, and unrunnable."""

    @classmethod
    def setUpClass(cls):
        cls.m = manifest_mod.load(REPO_ROOT)

    def test_board_is_registered_in_the_append_only_board_list(self):
        self.assertIn("riscv_metal", ledger.BOARDS)
        # TRACKS §6: BOARDS is append-only. Every board that existed before
        # wave 2 must still be there, in order.
        self.assertEqual(
            ledger.BOARDS[:-1],
            (
                "core_cpu", "core_hybrid", "core_metal", "core_cuda",
                "heavy_native", "heavy_cairo", "stream", "riscv",
                "cairo_cpu", "cairo_metal", "pr6_supremacy",
            ),
        )
        self.assertEqual(ledger.BOARDS[-1], "riscv_metal")
        self.assertEqual(len(set(ledger.BOARDS)), len(ledger.BOARDS))

    def test_group_is_staged_dark_exactly_like_cairo_metal(self):
        group = self.m.group_for_board("riscv_metal")
        cairo_metal = self.m.group_for_board("cairo_metal")
        for staged in (group, cairo_metal):
            self.assertFalse(staged.enabled)
            self.assertFalse(staged.promotion_eligible)
            self.assertIn("parity_gated", staged.disabled_reason)
        self.assertIn("M5", group.promotion_blocked_reason)
        self.assertIn("calibration", group.promotion_blocked_reason.lower())

    def test_group_pins_the_verified_build_step_binary_and_protocol(self):
        group = self.m.group_for_board("riscv_metal")
        self.assertEqual(
            group.build_step, "zig build riscv-metal-bench -Doptimize=ReleaseFast",
        )
        self.assertEqual(group.binary, "zig-out/bin/riscv-metal-bench")
        product = (
            REPO_ROOT / "build_support" / "products" / "riscv_metal.zig"
        ).read_text()
        # The declared step and binary must be the ones the product actually
        # installs, and the protocol string must be the product's own.
        self.assertIn('.benchmark_step = "riscv-metal-bench"', product)
        self.assertIn('"riscv-metal-bench",', product)
        self.assertIn(".state = .parity_gated", product)
        self.assertIn(
            '.protocol_features = "rv32im-zkvm-v1+lifted-pcs-v1" ++',
            product,
        )
        self.assertIn(
            '"+metal-runtime-v2+authenticated-core-aot-v2"',
            product,
        )

    def test_report_adapter_is_declared_absent_because_the_product_emits_none(self):
        group = self.m.group_for_board("riscv_metal")
        self.assertEqual(group.report_adapter["status"], "absent")
        self.assertEqual(group.report_schema, "riscv_proof_v3")
        # The claim is checkable: the installed benchmark is the shared RISC-V
        # bench runner, which has no bench subcommand and no report output.
        runner_src = (
            REPO_ROOT / "src" / "tools" / "riscv" / "bench" / "runner.zig"
        ).read_text()
        for absent in ("--report-out", "--proof-out", "--protocol"):
            self.assertNotIn(absent, runner_src)
        self.assertNotIn("riscv_proof_v3", runner_src)

    def test_absent_adapter_makes_the_group_structurally_unpromotable(self):
        raw = raw_manifest()
        group = raw["workload_registry"]["groups"]["riscv_metal"]
        group["enabled"] = True
        with self.assertRaisesRegex(ManifestError, "report_adapter.status is 'absent'"):
            manifest_mod._validate(raw)
        # And a group that tries to go live AND promotable in one step is
        # refused by the adapter rule, not merely by the disabled-group rule.
        group["promotion_eligible"] = True
        with self.assertRaisesRegex(ManifestError, "report_adapter.status is 'absent'"):
            manifest_mod._validate(raw)

    def test_oracle_mirrors_the_backend_independent_sail_authority(self):
        metal = self.m.group_for_board("riscv_metal").correctness_oracle
        cpu = self.m.group_for_board("riscv").correctness_oracle
        self.assertEqual(metal["authority"], "sail-riscv")
        self.assertEqual(metal["commit"], cpu["commit"])
        self.assertEqual(metal["repository"], cpu["repository"])
        self.assertIs(metal["final_validator"], True)
        evidence = REPO_ROOT / metal["evidence"]["path"]
        self.assertEqual(
            hashlib.sha256(evidence.read_bytes()).hexdigest(),
            metal["evidence"]["sha256"],
        )
        # The stark-v benchmark reference is CPU-only and must not be mirrored.
        self.assertNotIn("benchmark_reference", metal)

    def test_workloads_use_committed_elfs_and_official_secure_parameters(self):
        group = self.m.group_for_board("riscv_metal")
        self.assertTrue(group.workloads)
        seen = set()
        for workload in group.workloads:
            self.assertIn(workload.workload_class, ("small", "wide", "deep"))
            seen.add(workload.workload_class)
            elf = workload.args.split("--elf ")[1].split(" ")[0]
            self.assertTrue((REPO_ROOT / elf).is_file(), elf)
            # TRACKS §3.1: a new track never ships a laxer boundary. The
            # RISC-V secure protocol is pow 26 / 70 queries.
            self.assertIn("--pow-bits 26", workload.args)
            self.assertIn("--n-queries 70", workload.args)
        self.assertEqual(seen, {"small", "wide", "deep"})

    def test_board_has_no_scored_classes_while_it_is_dark(self):
        self.assertEqual(self.m.class_names(board="riscv_metal"), [])


class RiscvCspStagedBasketTest(unittest.TestCase):
    """The EthProofs CSP matrix is wired, admitted, and era-gated."""

    @classmethod
    def setUpClass(cls):
        cls.m = manifest_mod.load(REPO_ROOT)
        cls.group = cls.m.group_for_board("riscv")
        cls.basket = cls.group.era_staged_basket
        cls.csp = json.loads((REPO_ROOT / CSP_MANIFEST).read_text())

    def test_basket_is_staged_for_era_three_and_digest_bound(self):
        self.assertEqual(self.basket["activates_in_era"], 3)
        admission = self.basket["admission"]
        self.assertEqual(admission["path"], CSP_MANIFEST)
        self.assertEqual(
            hashlib.sha256((REPO_ROOT / CSP_MANIFEST).read_bytes()).hexdigest(),
            admission["sha256"],
        )
        self.assertEqual(self.csp["schema"], "stwo_riscv_csp_suite_v2")
        self.assertEqual(admission["authority"], self.csp["suite"])

    def test_every_csp_matrix_row_is_wired_exactly_once(self):
        expected = {
            (target, case["input_size"])
            for target, spec in self.csp["targets"].items()
            for case in spec["cases"]
        }
        wired = {
            (row["admission"]["target"], row["admission"]["input_size"])
            for row in self.basket["rows"].values()
        }
        self.assertEqual(wired, expected)
        self.assertEqual(len(self.basket["rows"]), len(expected))
        self.assertEqual(len(expected), 16)

    def test_admission_binds_committed_guest_bytes_inputs_and_exact_cycles(self):
        for rid, row in self.basket["rows"].items():
            target = row["admission"]["target"]
            spec = self.csp["targets"][target]
            guest = REPO_ROOT / spec["guest"]["path"]
            self.assertEqual(
                hashlib.sha256(guest.read_bytes()).hexdigest(),
                spec["guest"]["sha256"],
                f"{rid}: committed guest ELF drifted",
            )
            case = next(
                c for c in spec["cases"]
                if c["input_size"] == row["admission"]["input_size"]
            )
            payload = (REPO_ROOT / case["input_path"]).read_bytes()
            self.assertEqual(
                hashlib.sha256(payload).hexdigest(), case["input_sha256"],
                f"{rid}: committed input drifted",
            )
            # No scored workload without oracle admission: the row's cycle
            # count IS the corpus's pinned exact retirement count.
            self.assertEqual(
                row["admission"]["expected_cycles"], case["expected_cycles"],
                f"{rid}: expected_cycles is not the corpus retirement count",
            )

    def test_args_name_the_committed_guest_and_the_secure_protocol(self):
        for rid, row in self.basket["rows"].items():
            args = row["args"]
            spec = self.csp["targets"][row["admission"]["target"]]
            self.assertIn(f"--elf {spec['guest']['path']}", args, rid)
            self.assertIn("--protocol secure", args, rid)
            self.assertNotIn("--protocol functional", args, rid)
            self.assertIn("--backend cpu", args, rid)
            # riscv_proof_v3 groups must carry the admission token or the
            # runner refuses the command outright.
            self.assertIn("{admission}", args, rid)
            self.assertIn("{warmups}", args, rid)
            self.assertIn("{samples}", args, rid)
            for referenced in re.findall(r"--(?:elf|input) (\S+)", args):
                self.assertTrue((REPO_ROOT / referenced).is_file(), referenced)

    def test_class_mapping_follows_measured_retirement_counts(self):
        """Classes are assigned by measured steps against the era-2 bands."""
        era2 = {"small": [], "wide": [], "deep": []}
        # The era-2 bands, taken from the committed trace corpus rather than
        # asserted: every base-corpus row's exact step count.
        vectors = json.loads(
            (REPO_ROOT / "vectors" / "riscv_elfs" / "trace_vectors.json").read_text()
        )
        steps_by_name = {v["name"]: v["total_steps"] for v in vectors["vectors"]}
        for workload in self.group.workloads:
            name = workload.workload_id.removeprefix("riscv_")
            if name in steps_by_name:
                era2[workload.workload_class].append(steps_by_name[name])
        wide_floor = min(era2["wide"])
        deep_floor = min(era2["deep"])
        self.assertLess(wide_floor, deep_floor)
        for rid, row in self.basket["rows"].items():
            cycles = row["admission"]["expected_cycles"]
            self.assertGreaterEqual(cycles, wide_floor, rid)
            if row["class"] == "wide":
                self.assertLess(cycles, deep_floor, rid)
            else:
                self.assertEqual(row["class"], "deep", rid)
                self.assertGreaterEqual(cycles, deep_floor, rid)
        # The CSP matrix has nothing in the era-2 small band, and the basket
        # must not pretend otherwise.
        self.assertNotIn(
            "small", {row["class"] for row in self.basket["rows"].values()},
        )

    def test_killer_set_covers_the_tracks_named_riscv_families(self):
        roles = {rid: row["role"] for rid, row in self.basket["rows"].items()}
        families = {
            row["killer_family"]
            for row in self.basket["rows"].values()
            if row["role"] == "killer"
        }
        self.assertEqual(set(roles.values()), {"scored_candidate", "killer"})
        # TRACKS §3.3 names paging-hostile and Keccak-heavy for RISC-V.
        self.assertIn("keccak_heavy", families)
        self.assertIn("paging_hostile", families)
        self.assertGreaterEqual(
            sum(1 for role in roles.values() if role == "killer"), 2,
        )
        self.assertTrue(any(role == "scored_candidate" for role in roles.values()))
        # The paging-hostile killer is the ECDSA row: an order of magnitude
        # past the deepest era-2 workload.
        ecdsa = self.basket["rows"]["riscv_csp_ecdsa_secp256k1"]
        self.assertEqual(ecdsa["killer_family"], "paging_hostile")
        self.assertGreater(ecdsa["admission"]["expected_cycles"], 5_000_000)

    def test_acceptance_corpus_pins_the_upstream_riscv_guest_matrix(self):
        corpus = self.group.acceptance_corpus
        self.assertEqual(corpus["path"], RISCV_CORPUS)
        payload = (REPO_ROOT / RISCV_CORPUS).read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), corpus["sha256"])
        matrix = json.loads(payload)
        self.assertEqual(matrix["kind"], "riscv_acceptance_corpus")
        cairo = json.loads(
            (REPO_ROOT / "vectors" / "cairo" / "cairo_program_matrix.json").read_text()
        )
        # Same upstream, same pin as the Cairo acceptance corpus.
        self.assertEqual(
            matrix["source_repository"]["url"], cairo["source_repository"]["url"],
        )
        self.assertEqual(
            matrix["source_repository"]["commit"],
            cairo["source_repository"]["commit"],
        )
        # Honest about what upstream ships: source only, so nothing here can
        # masquerade as a committed fixture.
        self.assertEqual(matrix["source_repository"]["prebuilt_artifacts"], "none")
        self.assertEqual(matrix["provisioning"]["status"], "pending")
        self.assertTrue(matrix["programs"])
        blockers = {b["id"] for b in matrix["provisioning"]["blockers"]}
        self.assertIn("guest_abi_port", blockers)
        self.assertIn("sail_differential_admission", blockers)
        for program in matrix["programs"]:
            self.assertIs(
                program["in_rv32im_zkvm_v1_profile"],
                not program["uses_precompile"],
                program["slug"],
            )
            for source in program["source_files"]:
                self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")

    def test_general_workloads_beyond_crypto_are_named_not_implied(self):
        matrix = json.loads((REPO_ROOT / RISCV_CORPUS).read_text())
        general = {
            program["slug"] for program in matrix["programs"]
            if program["workload_kind"] == "general"
        }
        self.assertIn("mat-mul", general)
        self.assertIn("fib", general)


class RiscvEraTwoImmutabilityTest(unittest.TestCase):
    """TRACKS §7: nothing staged may change what era 2 scores."""

    @classmethod
    def setUpClass(cls):
        cls.m = manifest_mod.load(REPO_ROOT)
        cls.group = cls.m.group_for_board("riscv")

    def test_era_two_scoring_universe_is_byte_identical(self):
        raw = raw_manifest()
        workloads = raw["workload_registry"]["groups"]["riscv"]["workloads"]
        self.assertEqual(len(workloads), ERA_2_RISCV_WORKLOAD_COUNT)
        self.assertEqual(
            universe_digest(workloads),
            ERA_2_RISCV_UNIVERSE_SHA256,
            "the riscv era-2 scoring universe changed; TRACKS §7 makes a "
            "basket or class-universe change a NEW ERA — open era 3 (see "
            "autoresearch/schema/scoring.md) rather than editing era 2",
        )

    def test_riscv_board_still_exposes_exactly_its_era_two_rows(self):
        selected = self.m.workloads(board="riscv")
        self.assertEqual(len(selected), ERA_2_RISCV_WORKLOAD_COUNT)
        staged = set(self.group.era_staged_basket["rows"])
        self.assertEqual({w.workload_id for w in selected} & staged, set())
        for workload in selected:
            # Era 2 scores the functional protocol; no staged secure row leaked in.
            self.assertIn("--protocol functional", workload.args)

    def test_staged_rows_are_unreachable_from_every_selection_path(self):
        staged = set(self.group.era_staged_basket["rows"])
        for name in self.m.class_names(board="riscv", include_disabled=True):
            selected = {
                w.workload_id
                for w in self.m.workloads(workload_class=name, board="riscv")
            }
            self.assertEqual(selected & staged, set(), name)
        pools = self.group.holdout_generator["pools"]
        for name, ids in pools.items():
            self.assertEqual(set(ids) & staged, set(), name)

    def test_riscv_board_era_two_is_open_and_still_scores_prove_ms(self):
        era = ledger.current_era(REPO_ROOT, "riscv")
        self.assertEqual(era["era"], 2)
        self.assertEqual(era["status"], "open")
        self.assertEqual(
            self.group.scored_dimension, manifest_mod.DEFAULT_SCORED_DIMENSION,
        )
        self.assertEqual(self.group.scored_dimension, "prove_ms")

    def test_no_era_three_record_was_opened(self):
        eras = ledger.board_eras(REPO_ROOT, "riscv")
        self.assertEqual([era["era"] for era in eras], [1, 2])

    def test_riscv_metal_has_no_era_of_its_own_yet(self):
        self.assertEqual(ledger.board_eras(REPO_ROOT, "riscv_metal"), ())


class EraStagedBasketValidationTest(unittest.TestCase):
    """Every staging rule fails closed."""

    def _raw(self) -> dict:
        return raw_manifest()

    def _basket(self, raw: dict) -> dict:
        return raw["workload_registry"]["groups"]["riscv"]["era_staged_basket"]

    def test_committed_manifest_validates(self):
        manifest_mod._validate(self._raw())

    def test_staged_row_colliding_with_a_scored_workload_is_refused(self):
        raw = self._raw()
        group = raw["workload_registry"]["groups"]["riscv"]
        row = copy.deepcopy(group["era_staged_basket"]["rows"]["riscv_csp_sha256_128b"])
        group["era_staged_basket"]["rows"]["riscv_alu_test"] = row
        with self.assertRaisesRegex(ManifestError, "both a runnable workload"):
            manifest_mod._validate(raw)

    def test_unknown_role_is_refused(self):
        raw = self._raw()
        self._basket(raw)["rows"]["riscv_csp_sha256_128b"]["role"] = "guard"
        with self.assertRaisesRegex(ManifestError, "unsupported role"):
            manifest_mod._validate(raw)

    def test_killer_without_a_named_family_is_refused(self):
        raw = self._raw()
        del self._basket(raw)["rows"]["riscv_csp_ecdsa_secp256k1"]["killer_family"]
        with self.assertRaisesRegex(ManifestError, "must name its"):
            manifest_mod._validate(raw)

    def test_non_killer_claiming_a_killer_family_is_refused(self):
        raw = self._raw()
        row = self._basket(raw)["rows"]["riscv_csp_sha256_128b"]
        row["killer_family"] = "keccak_heavy"
        with self.assertRaisesRegex(ManifestError, "declares a killer_family"):
            manifest_mod._validate(raw)

    def test_basket_without_the_required_killers_is_refused(self):
        raw = self._raw()
        rows = self._basket(raw)["rows"]
        for rid, row in list(rows.items()):
            if row["role"] == "killer":
                row["role"] = "scored_candidate"
                row.pop("killer_family", None)
        with self.assertRaisesRegex(ManifestError, "requires at least 2"):
            manifest_mod._validate(raw)

    def test_unknown_class_is_refused(self):
        raw = self._raw()
        self._basket(raw)["rows"]["riscv_csp_sha256_128b"]["class"] = "gigantic"
        with self.assertRaisesRegex(ManifestError, "unknown class"):
            manifest_mod._validate(raw)

    def test_non_positive_cycle_count_is_refused(self):
        raw = self._raw()
        admission = self._basket(raw)["rows"]["riscv_csp_sha256_128b"]["admission"]
        admission["expected_cycles"] = 0
        with self.assertRaisesRegex(ManifestError, "must be a positive integer"):
            manifest_mod._validate(raw)

    def test_staging_into_a_historical_era_is_refused(self):
        raw = self._raw()
        self._basket(raw)["activates_in_era"] = 1
        with self.assertRaisesRegex(ManifestError, "era 1 is history"):
            manifest_mod._validate(raw)

    def test_admission_corpus_digest_drift_is_refused(self):
        raw = self._raw()
        self._basket(raw)["admission"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ManifestError, "digest drifted"):
            manifest_mod._validate_acceptance_corpora(REPO_ROOT, raw)

    def test_report_adapter_shape_is_enforced(self):
        raw = self._raw()
        adapter = raw["workload_registry"]["groups"]["riscv_metal"]["report_adapter"]
        adapter["status"] = "maybe"
        with self.assertRaisesRegex(ManifestError, "report_adapter.status must be"):
            manifest_mod._validate(raw)
        adapter["status"] = "absent"
        adapter["emits"] = "  "
        with self.assertRaisesRegex(ManifestError, "report_adapter.emits"):
            manifest_mod._validate(raw)


class TracksDocumentConsistencyTest(unittest.TestCase):
    """TRACKS.md and schema/scoring.md describe what actually landed."""

    @classmethod
    def setUpClass(cls):
        cls.m = manifest_mod.load(REPO_ROOT)
        cls.tracks = (REPO_ROOT / "autoresearch" / "TRACKS.md").read_text()
        cls.scoring = (
            REPO_ROOT / "autoresearch" / "schema" / "scoring.md"
        ).read_text()

    def test_every_manifest_board_is_a_registered_ledger_board(self):
        for group in self.m.groups():
            self.assertIn(group.board, ledger.BOARDS, group.group_id)

    def test_tracks_table_records_riscv_metal_as_registered_staged(self):
        row = next(
            line for line in self.tracks.splitlines()
            if line.startswith("| `riscv_metal`")
        )
        self.assertIn("parity_gated", row)
        self.assertIn("registered-staged", row)

    def test_tracks_basket_section_describes_the_staged_riscv_extension(self):
        self.assertIn("era_staged_basket", self.tracks)
        for family in ("keccak_heavy", "paging_hostile", "field_native_saturating"):
            self.assertIn(family, self.tracks)

    def test_scoring_doc_carries_the_era_three_handoff(self):
        self.assertIn("zig build riscv-csp-bench", self.scoring)
        self.assertIn("--aa --board riscv", self.scoring)
        self.assertIn("activates_in_era: 3", self.scoring)
        # The handoff must not contain a fabricated measurement.
        era_three = self.scoring.split("### Era 3 also carries")[1]
        self.assertNotRegex(era_three, r"aa_dispersion.*0\.\d+")


if __name__ == "__main__":
    unittest.main()

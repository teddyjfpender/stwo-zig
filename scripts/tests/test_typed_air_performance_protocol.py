from __future__ import annotations

import contextlib
import copy
import io
import unittest

from scripts import typed_air_performance_protocol as protocol_validator


class TypedAirPerformanceProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = protocol_validator.REPOSITORY_ROOT
        cls.path = protocol_validator.DEFAULT_PROTOCOL
        cls.raw = cls.path.read_bytes()
        cls.protocol = protocol_validator.decode_strict_json(cls.raw)

    def changed(self) -> dict[str, object]:
        return copy.deepcopy(self.protocol)

    @staticmethod
    def milestone(value: dict[str, object], milestone_id: str) -> dict[str, object]:
        return next(
            item
            for item in value["milestones"]
            if item["id"] == milestone_id
        )

    def assert_invalid(self, value: dict[str, object], pattern: str) -> None:
        with self.assertRaisesRegex(protocol_validator.ProtocolError, pattern):
            protocol_validator.validate_protocol_value(self.root, value)

    def test_repository_contract_and_default_cli_validate(self) -> None:
        summary = protocol_validator.validate_protocol(self.root, self.path)
        self.assertEqual(("M5", "M6", "M7", "M8", "M9"), summary.milestones)
        self.assertEqual(("cpu-native", "metal-hybrid"), summary.lanes)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = protocol_validator.main([])
        self.assertEqual(0, status)
        self.assertEqual(summary.render() + "\n", stdout.getvalue())
        self.assertEqual("", stderr.getvalue())

    def test_duplicate_json_and_unknown_root_field_fail_closed(self) -> None:
        duplicate = self.raw.replace(
            b'{\n  "schema": ',
            b'{\n  "schema": "forged",\n  "schema": ',
            1,
        )
        with self.assertRaisesRegex(protocol_validator.ProtocolError, "duplicate JSON key: schema"):
            protocol_validator.decode_strict_json(duplicate)

        changed = self.changed()
        changed["unreviewed_extension"] = True
        self.assert_invalid(changed, "protocol field set mismatch")

    def test_schema_version_and_predeclaration_are_frozen(self) -> None:
        changed = self.changed()
        changed["schema_version"] = 2
        self.assert_invalid(changed, "schema version drifted")

        changed = self.changed()
        changed["optimization_claim_contract"]["predeclaration"] = "optional"
        self.assert_invalid(changed, "optimization claim contract drifted")

    def test_authority_and_corpus_hash_drift_fail(self) -> None:
        for section, field in (
            ("statistical_authority", "statistics_sha256"),
            ("statistical_authority", "amendment_sha256"),
            ("corpus_authority", "canonical_trace_manifest_sha256"),
            ("corpus_authority", "crypto_provenance_sha256"),
        ):
            with self.subTest(section=section, field=field):
                changed = self.changed()
                changed[section][field] = "0" * 64
                self.assert_invalid(changed, "drifted")

    def test_sampling_arithmetic_and_exact_lanes_fail_on_drift(self) -> None:
        changed = self.changed()
        changed["sampling_protocol"]["measured_verified_proofs_per_arm"] = 29
        self.assert_invalid(changed, "sampling_protocol.measured_verified_proofs_per_arm drifted")

        changed = self.changed()
        changed["lanes"].reverse()
        self.assert_invalid(changed, "performance lanes drifted")

    def test_universal_threshold_and_primary_target_drift_fail(self) -> None:
        changed = self.changed()
        changed["universal_hard_budgets"]["verified_request_speed_lower_ci"] = 0.969
        self.assert_invalid(changed, "universal budgets drifted")

        changed = self.changed()
        self.milestone(changed, "M6")["primary_target"]["threshold"] = 1.05
        self.assert_invalid(changed, "M6 primary target drifted")

        changed = self.changed()
        del self.milestone(changed, "M7")["primary_target"]
        self.assert_invalid(changed, r"milestones\[2\] field set mismatch")

    def test_m5_authored_case_matrix_is_exact(self) -> None:
        changed = self.changed()
        cases = self.milestone(changed, "M5")["family_microbenchmarks"]["cases"]
        cases[0], cases[1] = cases[1], cases[0]
        self.assert_invalid(changed, "M5 family cases drifted")

        changed = self.changed()
        self.milestone(changed, "M5")["family_microbenchmarks"]["log_rows"] = [10, 14]
        self.assert_invalid(changed, "M5 row matrix drifted")

    def test_m8_requires_exact_seventeen_families_and_nine_workloads(self) -> None:
        changed = self.changed()
        self.milestone(changed, "M8")["family_microbenchmarks"]["families"].pop()
        self.assert_invalid(changed, "M8 17-family corpus drifted")

        changed = self.changed()
        self.milestone(changed, "M8")["full_proof_workloads"].pop()
        self.assert_invalid(changed, "M8 workloads drifted")

        changed = self.changed()
        families = self.milestone(changed, "M8")["family_microbenchmarks"]["families"]
        families[-1] = families[0]
        self.assert_invalid(changed, "M8 17-family corpus drifted")

    def test_m6_call_matrix_and_zero_call_profiles_are_independent(self) -> None:
        changed = self.changed()
        self.milestone(changed, "M6")["corpus"]["call_counts"] = [1, 8, 64, 512, 4096]
        self.assert_invalid(changed, "M6 corpus call_counts drifted")

        changed = self.changed()
        gates = self.milestone(changed, "M6")["exact_gates"]
        gates["extension_profile_zero_calls"] = gates["base_profile_zero_calls"]
        self.assert_invalid(changed, "M6 extension-profile zero-call gate drifted")

        changed = self.changed()
        gates = self.milestone(changed, "M6")["exact_gates"]
        gates["zero_calls"] = gates.pop("base_profile_zero_calls")
        self.assert_invalid(changed, "M6.exact_gates field set mismatch")

    def test_m7_worker_matrix_and_resource_overrides_are_frozen(self) -> None:
        changed = self.changed()
        self.milestone(changed, "M7")["worker_counts"] = [1, 2, 4]
        self.assert_invalid(changed, "M7 worker matrix drifted")

        changed = self.changed()
        gates = self.milestone(changed, "M7")["statistical_gates"]
        gates["largest_worker_count_total_resource_work_over_one_worker_upper_ci"] = 1.20
        self.assert_invalid(changed, "M7 total-work override drifted")

        changed = self.changed()
        self.milestone(changed, "M7")["universal_budget_overrides"].pop()
        self.assert_invalid(changed, "M7 resource overrides drifted")

    def test_m9_matrix_targets_and_overrides_are_frozen(self) -> None:
        changed = self.changed()
        self.milestone(changed, "M9")["corpus"]["leaf_counts"] = [2, 4, 8, 16]
        self.assert_invalid(changed, "M9 corpus leaf_counts drifted")

        changed = self.changed()
        gates = self.milestone(changed, "M9")["statistical_gates"]
        gates["eight_leaf_four_worker_speed_lower_ci"] = 1.20
        self.assert_invalid(changed, "M9 statistical gate.*drifted")

        changed = self.changed()
        self.milestone(changed, "M9")["universal_budget_overrides"].reverse()
        self.assert_invalid(changed, "M9 resource overrides drifted")

    def test_local_paths_cannot_be_relabelled_or_escape_repository(self) -> None:
        changed = self.changed()
        changed["documentation"] = "../PERFORMANCE.md"
        self.assert_invalid(changed, "documentation drifted")

        changed = self.changed()
        changed["statistical_authority"]["statistics_path"] = (
            "conformance/performance-authority/epoch-3/../stats.py"
        )
        self.assert_invalid(changed, "statistical_authority.statistics_path drifted")


if __name__ == "__main__":
    unittest.main()

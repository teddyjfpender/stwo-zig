import tempfile
import unittest
from pathlib import Path

from scripts.source_conformance_lib import typed_air_proposals


class TypedAirProposalIsolationTests(unittest.TestCase):
    def test_only_exact_authoring_tools_and_tests_may_reference_proposals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            sources = {
                "src/frontends/riscv/air/lang/materialization_cost.zig": (
                    "pub const marker = true;\n"
                ),
                "src/frontends/riscv/air/lang/materialization_cost_test.zig": (
                    'const cost = @import("materialization_cost.zig");\n'
                ),
                "src/frontends/riscv/air/lang/mod.zig": (
                    'pub const materialization_cost = @import("materialization_cost.zig");\n'
                ),
                "src/frontends/riscv/materialization_frontier_tool.zig": (
                    'const command = @import("air/lang/materialization_frontier_command.zig");\n'
                ),
                "src/frontends/riscv/build.zig": (
                    'const artifact_name = "typed_air_h009_artifacts";\n'
                ),
                "src/tests/riscv/proposal_test.zig": (
                    "const policy = frontend.air.lang.cost_aware_materializer;\n"
                ),
                "src/frontends/riscv/air/lang/typed_poseidon2_frontier_artifact_test.zig": (
                    'const reviewed = @import("typed_air_h009_artifacts");\n'
                    "const bytes = reviewed.h009_poseidon2_frontier;\n"
                ),
                "src/frontends/riscv/prover/production.zig": (
                    "const policy = frontend.air.lang.cost_aware_materializer;\n"
                    "// materialization_frontier_manifest in a comment is inert.\n"
                ),
            }
            for relative, text in sources.items():
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")

            findings = typed_air_proposals.scan(repo)
            self.assertEqual(
                {
                    "typed-air-proposal-consumer:frontends/riscv/air/lang/mod.zig",
                    "typed-air-proposal-consumer:frontends/riscv/prover/production.zig",
                    "typed-air-proposal-consumer:tests/riscv/proposal_test.zig",
                },
                {finding.key for finding in findings},
            )
            for finding in findings:
                self.assertTrue(
                    "cost_aware_materializer" in finding.message
                    or "materialization_cost" in finding.message
                )

    def test_reviewed_artifact_fields_are_confined_to_the_exact_artifact_test(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            source = repo / "src/frontends/riscv/air/lang/materialization_cost_test.zig"
            source.parent.mkdir(parents=True)
            source.write_text(
                'const reviewed = @import("typed_air_h009_artifacts");\n'
                "const bytes = reviewed.h009_poseidon2_frontier;\n",
                encoding="utf-8",
            )

            findings = typed_air_proposals.scan(repo)
            self.assertEqual(1, len(findings))
            self.assertIn("typed_air_h009_artifacts", findings[0].message)
            self.assertIn("h009_poseidon2_frontier", findings[0].message)

    def test_reflective_string_reference_is_also_a_consumer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            source = repo / "src/frontends/riscv/prover/reflection.zig"
            source.parent.mkdir(parents=True)
            source.write_text(
                'const policy = @field(lang, "materialization_frontier_manifest");\n',
                encoding="utf-8",
            )

            findings = typed_air_proposals.scan(repo)
            self.assertEqual(1, len(findings))
            self.assertIn("materialization_frontier_manifest", findings[0].message)


if __name__ == "__main__":
    unittest.main()

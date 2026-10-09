"""Privacy requests must survive source lowering and package validation."""

import copy
import sys
import unittest
from pathlib import Path

S31 = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(S31 / "python"))

import proof_privacy
import s31
from oracle import OracleError, evaluate_relation
from text_frontend import Parser, SourceError, compile_text

TEXT = """use std@1;
fn square(x: [m31; 1]) -> [m31; 1] { x .* x }
blinded circuit hidden(private x: [m31; 1], public claim: [m31; 1]) -> public [m31; 1] {
    let y = square(x);
    assert_eq(y, claim);
    claim
}
"""


class PrivacyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source, _ = compile_text(TEXT)
        self.manifest = {"proof_mode": "blinded", "proof_privacy": proof_privacy.POLICY.copy(),
                         "lowering": "gate", "fri_fold_step": 1, "artifacts": {}}
        self.key = {"schema": proof_privacy.KEY_SCHEMA, "profile": proof_privacy.PROFILE,
                    "proof_privacy": proof_privacy.POLICY.copy()}
        self.report = {"proof_privacy": proof_privacy.POLICY.copy()}

    def test_mode_is_independent_of_visibility_and_values(self) -> None:
        transparent, _ = compile_text(TEXT.replace("blinded circuit", "circuit"))
        self.assertNotIn("proof_mode", transparent)  # Legacy normalized bytes stay stable.
        self.assertEqual(self.source["proof_mode"], "blinded")
        self.assertEqual({k: v for k, v in self.source.items() if k != "proof_mode"}, transparent)
        assignment = {"public_inputs": {"claim": [81]}, "private_inputs": {"x": [9]},
                      "public_outputs": {"claim": [81]}}
        self.assertEqual(evaluate_relation(self.source, assignment), evaluate_relation(transparent, assignment))
        self.assertEqual(s31.abi(self.source, "gate"), s31.abi(transparent, "gate"))
        parser = Parser(TEXT, "privacy.s31")
        _, circuit = parser.parse()
        self.assertEqual(s31.text_interface(circuit, parser.stdlib_explicit)["proof_mode"], "blinded")
        self.assertEqual(proof_privacy.policy_for(transparent, "sparse-wide-gate", 4), None)
        proof_privacy.validate_package(transparent, {"artifacts": {}, "lowering": "gate"}, {}, {})

    def test_bad_modes_and_declarations_rejected(self) -> None:
        for mode in (None, True, 1, "zk", "unknown", {}):
            source = {**self.source, "proof_mode": mode}
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                proof_privacy.policy_for(source, "gate", 1)
            with self.assertRaises(OracleError):
                evaluate_relation(source, {"public_inputs": {}, "public_outputs": {}})
        for text in (TEXT.replace("blinded circuit", "blinded fn"),
                     TEXT.replace("blinded circuit", "blinded blinded circuit"),
                     TEXT.replace("blinded circuit", "zk circuit")):
            with self.subTest(text=text), self.assertRaises(SourceError):
                compile_text(text)

    def test_unsupported_profiles_rejected_before_compilation(self) -> None:
        for lowering in ("chip", "sparse-gate", "sparse-chip", "sparse-wide-gate",
                         "direct-gate", "direct-chip", "sha-joint", "sha-shift", "sha-fused"):
            with self.subTest(lowering=lowering), self.assertRaisesRegex(ValueError, "require gate"):
                proof_privacy.policy_for(self.source, lowering, 1)
        for step in (0, 4, True, 1.0):
            with self.subTest(step=step), self.assertRaises(ValueError):
                proof_privacy.policy_for(self.source, "gate", step)

    def test_package_policy_cannot_be_stripped_changed_or_mislabelled(self) -> None:
        proof_privacy.validate_package(self.source, self.manifest, self.key, self.report)
        for object_name in ("manifest", "key", "report"):
            for field, value in (("rounds", 0), ("rounds", 79), ("queries", 69),
                                 ("extra_openings", 0), ("rounds", 80.0),
                                 ("scheme", "unknown"), ("extra", 0)):
                objects = {name: copy.deepcopy(getattr(self, name)) for name in ("manifest", "key", "report")}
                objects[object_name]["proof_privacy"][field] = value
                with self.subTest(object=object_name, field=field, value=value), self.assertRaises(ValueError):
                    proof_privacy.validate_package(self.source, **objects)
            objects = {name: copy.deepcopy(getattr(self, name)) for name in ("manifest", "key", "report")}
            objects[object_name].pop("proof_privacy")
            with self.subTest(stripped=object_name), self.assertRaises(ValueError):
                proof_privacy.validate_package(self.source, **objects)
        for field, value in (("schema", "s31-verification-key-v1"), ("profile", "circuit-v1")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                proof_privacy.validate_package(self.source, self.manifest, {**self.key, field: value}, self.report)
        transparent = {**self.source, "proof_mode": "transparent"}
        with self.assertRaises(ValueError):
            proof_privacy.validate_package(transparent, self.manifest, self.key, self.report)

    def test_recursive_metadata_is_rejected(self) -> None:
        for artifact in proof_privacy.RECURSIVE_ARTIFACTS:
            manifest = {**self.manifest, "artifacts": {artifact: "dummy"}}
            with self.subTest(artifact=artifact), self.assertRaisesRegex(ValueError, "recursion"):
                proof_privacy.validate_package(self.source, manifest, self.key, self.report)
        for field, value in (("capabilities", ["s31-fixed-fold-batch-v1"]), ("recursive_fri_fold_step", 1)):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "recursion"):
                proof_privacy.validate_package(self.source, {**self.manifest, field: value}, self.key, self.report)


if __name__ == "__main__":
    unittest.main()

"""Adversarial controls for the S31 formal evidence gate."""
from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import s31_formal
from scripts.s31_formal_lib import checks

ROOT = Path(__file__).resolve().parents[2]
FORMAL = ROOT / "formal/s31"


class FormalGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.coverage = json.loads((FORMAL / "coverage.json").read_text())
        self.bindings = json.loads((FORMAL / "source-bindings.json").read_text())
        self.inventory = checks.inventory(ROOT, s31_formal.lean_code)
        self.theorems = set(self.inventory["theorems"])

    def test_comments_and_literals_do_not_create_false_escapes(self) -> None:
        checks.scan_source('/- axiom /- sorry -/ unsafe -/\n-- admit\n'
                           'def s := "native_decide -- /- axiom"\n', "control", s31_formal.lean_code)

    def test_escapes_in_code_are_rejected(self) -> None:
        for token in ("sorry", "admit", "axiom", "unsafe", "native_decide"):
            with self.subTest(token=token), self.assertRaises(checks.FormalError):
                checks.scan_source(f"theorem cheat : True := by {token}\n", "control", s31_formal.lean_code)

    def test_string_comment_markers_cannot_hide_following_escape(self) -> None:
        for literal in ('"--"', '"/-"', '"a\\\"/-b"'):
            with self.subTest(literal=literal), self.assertRaises(checks.FormalError):
                checks.scan_source(f"def s := {literal}; axiom cheat : False\n", "control", s31_formal.lean_code)

    def test_unterminated_comment_is_rejected(self) -> None:
        with self.assertRaises(checks.FormalError):
            checks.scan_source("/- unterminated", "control", s31_formal.lean_code)

    def test_inventory_preserves_question_mark_names_and_excludes_private(self) -> None:
        names = checks.theorem_names("namespace X\nprivate theorem hidden : True := by trivial\n"
                                     "@[simp] theorem ofNat?_toNat : True := by trivial\nend X\n", s31_formal.lean_code)
        self.assertEqual(names, ["X.ofNat?_toNat"])

    def test_unsupported_declaration_style_is_rejected(self) -> None:
        with self.assertRaises(checks.FormalError):
            checks.theorem_names("namespace X\ntheorem «hidden name» : True := by trivial\nend X\n", s31_formal.lean_code)

    def test_full_coverage_is_valid(self) -> None:
        checks.check_coverage(ROOT, self.bindings["ops"], self.coverage, self.theorems)

    def test_missing_added_duplicate_and_reordered_operations_are_rejected(self) -> None:
        for kind in ("missing", "added", "duplicate", "reordered"):
            value = copy.deepcopy(self.coverage)
            entries = value["operations"]
            if kind == "missing":
                entries.pop()
            elif kind == "added":
                extra = copy.deepcopy(entries[-1]); extra["op"] = "new_operation"; entries.append(extra)
            elif kind == "duplicate":
                entries.append(copy.deepcopy(entries[-1]))
            else:
                entries.reverse()
            with self.subTest(kind=kind), self.assertRaises(checks.FormalError):
                checks.check_coverage(ROOT, self.bindings["ops"], value, self.theorems)

    def test_missing_and_unknown_proofs_are_rejected(self) -> None:
        for proofs in ([], ["S31.Gadgets.unproved"]):
            value = copy.deepcopy(self.coverage)
            value["operations"][0]["gadget_theorems"] = proofs
            with self.subTest(proofs=proofs), self.assertRaises(checks.FormalError):
                checks.check_coverage(ROOT, self.bindings["ops"], value, self.theorems)

    def test_missing_source_function_is_rejected(self) -> None:
        value = copy.deepcopy(self.coverage)
        value["operations"][0]["source"]["function"] = "not_a_compiler_function"
        with self.assertRaises(checks.FormalError):
            checks.check_coverage(ROOT, self.bindings["ops"], value, self.theorems)

    def test_unproved_compiler_claim_is_rejected(self) -> None:
        value = copy.deepcopy(self.coverage)
        value["production_compiler_correctness_proved"] = True
        with self.assertRaises(checks.FormalError):
            checks.check_coverage(ROOT, self.bindings["ops"], value, self.theorems)

    def test_empty_audit_is_rejected(self) -> None:
        for expected in (set(), self.theorems):
            with self.subTest(empty=not expected), self.assertRaises(checks.FormalError):
                checks.check_audit("", expected)

    def test_audit_rejects_missing_extra_duplicate_and_unknown_axiom(self) -> None:
        good = "S31_THEOREM S31.example\nS31_AXIOM S31.example propext\n"
        checks.check_audit(good, {"S31.example"})
        for bad in ("", good + "S31_THEOREM S31.extra\n", good + "S31_THEOREM S31.example\n",
                    good + "S31_AXIOM S31.example sorryAx\n", good + "error: failed\n",
                    good + "S31_AXIOM S31.example propext\n"):
            with self.subTest(bad=bad), self.assertRaises(checks.FormalError):
                checks.check_audit(bad, {"S31.example"})

    def test_kernel_log_rejects_missing_duplicate_and_failed_module(self) -> None:
        files = {"formal/s31/S31.lean": "digest", "formal/s31/S31/Gadgets/Field.lean": "digest"}
        good = "replaying S31\nreplaying S31.Gadgets.Field\n"
        checks.check_kernel_log(good, files)
        for bad in ("", "replaying S31\n", good + "replaying S31\n",
                    good + "leanchecker found a problem in S31\n"):
            with self.subTest(bad=bad), self.assertRaises(checks.FormalError):
                checks.check_kernel_log(bad, files)

    def test_deleted_or_symlinked_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in self.inventory["files"]:
                path = root / relative; path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, path)
            path = root / "formal/s31/S31/Evidence/NonVacuity.lean"
            path.unlink()
            with self.assertRaises(checks.FormalError):
                checks.inventory(root, s31_formal.lean_code)
            path.symlink_to(ROOT / "formal/s31/S31/Evidence/NonVacuity.lean")
            with self.assertRaises(checks.FormalError):
                checks.inventory(root, s31_formal.lean_code)

    def test_unimported_new_theorem_cannot_disappear_from_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in self.inventory["files"]:
                path = root / relative; path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, path)
            (root / "formal/s31/S31/Orphan.lean").write_text(
                "namespace S31.Orphan\ntheorem ignored : True := by trivial\nend S31.Orphan\n")
            expected = set(checks.inventory(root, s31_formal.lean_code)["theorems"])
            log = "".join("S31_THEOREM " + name + "\n" for name in self.theorems)
            with self.assertRaises(checks.FormalError):
                checks.check_audit(log, expected)

    def test_source_drift_changes_generated_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in s31_formal.BINDINGS + ["formal/s31/coverage.json"]:
                path = root / relative; path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, path)
            with patch.object(s31_formal, "ROOT", root), patch.object(s31_formal, "FORMAL", root / "formal/s31"):
                before = s31_formal.generated()[root / "formal/s31/source-bindings.json"]
                source = root / s31_formal.RELATION
                source.write_text(source.read_text() + "\n// changed source identity\n")
                after = s31_formal.generated()[root / "formal/s31/source-bindings.json"]
                self.assertNotEqual(before, after)


if __name__ == "__main__":
    unittest.main()

"""Behavioral negative coverage for source-owned package complexity accounting."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.repo import package_budget as budget


REVIEW_ERRORS = budget.review_errors
HOT_ERRORS = budget.hot_path_errors


class PackageBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        review = patch.object(budget, "review_errors", return_value=[])
        review.start()
        self.addCleanup(review.stop)
        hot = patch.object(budget, "hot_path_errors", return_value=[])
        hot.start()
        self.addCleanup(hot.stop)
        baseline = patch.object(budget, "baseline", return_value="base")
        baseline.start()
        self.addCleanup(baseline.stop)
        self.root = Path(self.temp.name).resolve()

    def contract(self, path, name="owner", excluded=()):
        directory = self.root / path
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "package.contract.json").write_text("{}")
        return SimpleNamespace(directory=directory, package=name, consumer_subdirs=excluded,
                               api_surface=("A",), dependencies={"dependency": "../dep"}, metadata=None)

    def write(self, path, text):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)
        return path

    def test_nested_owner_and_excluded_source_never_credited_to_parent(self):
        parent = self.contract("src/a", excluded=("consumer",))
        child = self.contract("src/a/child", "child")
        paths = [self.write(p, "line\n") for p in
                 ("src/a/a.zig", "src/a/child/a.zig", "src/a/consumer/a.zig", "build.zig")]
        measured = budget.measure(self.root, [parent, child], paths)
        self.assertEqual(measured["packages"]["owner"]["code_lines"], 1)
        self.assertEqual(measured["packages"]["child"]["code_lines"], 1)
        self.assertEqual(measured["unowned"]["code_lines"], 2)

    def test_generated_scripts_count_as_scripts_and_generated_not_manual(self):
        owner = self.contract("src/a")
        path = self.write("src/a/generated/tool.py", "# generated\n# generator: tool\n# regenerate: command\n")
        row = budget.measure(self.root, [owner], [path])["packages"]["owner"]
        self.assertEqual((row["script_files"], row["generated_code_files"], row["generated_code_lines"]), (1, 1, 3))
        self.assertEqual(row["code_lines"], 0)

    def test_moving_file_transfers_count_without_subtraction_credit(self):
        a, b = self.contract("src/a", "a"), self.contract("src/b", "b")
        path = self.write("src/a/a.zig", "one\ntwo\n")
        before = budget.measure(self.root, [a, b], [path])
        (self.root / path).rename(self.root / "src/b/a.zig")
        after = budget.measure(self.root, [a, b], ["src/b/a.zig"])
        self.assertEqual(before["packages"]["a"]["code_lines"], after["packages"]["b"]["code_lines"])
        self.assertEqual(after["packages"]["a"]["code_lines"], 0)

    def test_stale_api_dependency_and_flag_counts_are_measured(self):
        owner = self.contract("src/a")
        self.write("conformance/rv64-flags.json", json.dumps({"flags": {
            "live": {"status": "runtime", "owner": "src/a/a.zig"},
            "constant": {"status": "constant", "owner": "src/a/a.zig"},
            "outside": {"status": "qualification", "owner": "scripts/tool.py"}}}))
        result = budget.measure(self.root, [owner], [])
        row = result["packages"]["owner"]
        self.assertEqual((row["api_entries"], row["dependencies"], row["rv64_registry_flags"]), (1, 1, 1))
        self.assertEqual(result["unowned"]["rv64_registry_flags"], 1)

    def test_tracked_symlink_refused_instead_of_counting_external_source(self):
        owner = self.contract("src/a")
        self.write("external.zig", "secret\n")
        (self.root / "src/a/link.zig").symlink_to(self.root / "external.zig")
        with self.assertRaisesRegex(ValueError, "symlink"):
            budget.measure(self.root, [owner], ["src/a/link.zig"])

    def test_missing_and_exceeded_budget_fail_closed(self):
        owner = self.contract("src/a")
        owner.budget = None
        with patch.object(budget, "measure", return_value={"packages": {"owner": budget.empty()}}):
            self.assertIn("missing measured budget", budget.check(self.root, [owner])[0])
        owner.budget = budget.empty()
        for counter in budget.COUNTERS:
            measured = budget.empty() | {counter: 1}
            with self.subTest(counter=counter), patch.object(budget, "measure", return_value={"packages": {"owner": measured}}):
                self.assertEqual([f"owner: {counter} 1 exceeds budget 0"], budget.check(self.root, [owner]))

    def test_v2_budget_extension_is_strict_without_activating_cdc(self):
        from scripts.repo import ci_package_graph
        from scripts.repo.check_package_workspace import load_contract
        original = json.loads((Path(__file__).resolve().parents[2] / "src/waist/core/package.contract.json").read_text())
        original["schema"] = "stwo-zig-package-contract-v2"
        original.pop("consumers", None)
        original["budget"] = budget.empty()
        path = self.root / "package.contract.json"
        path.write_text(json.dumps(original))
        self.assertIsNone(load_contract(path).metadata)
        self.assertEqual(budget.empty(), load_contract(path).budget)
        for invalid in ({}, budget.empty() | {"extra": 0}, budget.empty() | {"code_lines": -1},
                        budget.empty() | {"code_lines": True}, budget.empty() | {"code_lines": 1.5}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                ci_package_graph.parse_contract_metadata(original | {"budget": invalid}, "test")

    def test_budget_increase_requires_exact_base_before_after_and_review(self):
        owner = self.contract("src/a")
        before = budget.empty()
        owner.budget = before | {"code_lines": 1}
        path = "conformance/rv64-productionisation-budget.json"
        self.write(path, json.dumps({}))
        old = SimpleNamespace(returncode=0, stdout=json.dumps({"budget": before}))
        transaction = {"package": "owner", "base_commit": "base", "before": before,
                       "after": owner.budget, "decision": "https://github.com/teddyjfpender/stwo-zig/issues/370#issuecomment-123"}
        with patch.object(budget.subprocess, "run", return_value=old):
            self.assertIn("exact reviewed CB-2", REVIEW_ERRORS(self.root, [owner], "base")[0])
            for row in (transaction, transaction | {"base_commit": "stale"},
                        transaction | {"decision": "approved"}, transaction | {"after": before}):
                self.write(path, json.dumps({"package_budget_changes": [row]}))
                errors = REVIEW_ERRORS(self.root, [owner], "base")
                self.assertEqual(row != transaction, bool(errors))
            owner.budget = before
            self.assertEqual([], REVIEW_ERRORS(self.root, [owner], "base"))

    def test_hot_branch_proxy_ignores_comments_literals_and_other_functions(self):
        source = 'fn hot() void { if (a) {} while (b) {} const s = "if => }"; // for {\n } fn other() void { if (c) {} }'
        self.assertEqual(2, budget.branch_count(source, "hot"))
        with self.assertRaisesRegex(ValueError, "exactly once"):
            budget.branch_count(source + ' fn hot() void {}', "hot")
        with self.assertRaisesRegex(ValueError, "unterminated"):
            budget.branch_count('fn hot() void { if (a) {}', "hot")

    def test_hot_budget_rejects_wrong_owner_ambiguity_overage_and_malformed_rows(self):
        owner = self.contract("src/a")
        self.write("src/a/hot.zig", "fn hot() void { if (true) {} }")
        row = {"package": "owner", "source": "src/a/hot.zig", "function": "hot", "max_branches": 1, "decision": "issue370"}
        for entries, fails in (([row], False), ([row | {"package": "other"}], True),
                               ([row | {"max_branches": 0}], True), ([row, row], True),
                               ([row | {"function": "missing"}], True), ([row | {"max_branches": True}], True),
                               ([row | {"max_branches": 16}], True), ([row | {"source": 1}], True)):
            self.write("conformance/rv64-productionisation-budget.json", json.dumps({"hot_path_budgets": entries}))
            with self.subTest(entries=entries):
                self.assertEqual(fails, bool(HOT_ERRORS(self.root, [owner])))


class FailedBudgetReceiptTests(unittest.TestCase):
    def test_failure_still_publishes_measurement_and_preserves_failed_status(self):
        from scripts.repo import check_package_workspace as workspace
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "failed-budget.json"
            report = {"schema": "package-complexity-census/v1", "measurement": {"packages": {}}}
            with patch("sys.argv", ["workspace", "--repo", str(root), "--budget-report", str(output)]), patch.object(
                workspace, "check_repository", return_value=["owner: code_lines exceeds budget"],
            ), patch.object(budget, "report", return_value=report), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(1, workspace.main())
            receipt = json.loads(output.read_text())
            self.assertEqual("FAIL", receipt["status"])
            self.assertEqual(["owner: code_lines exceeds budget"], receipt["failures"])
            self.assertEqual(report["measurement"], receipt["measurement"])

    def test_malformed_contract_cannot_erase_original_refusal_or_fabricate_census(self):
        from scripts.repo import check_package_workspace as workspace
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = root / "src/owner/package.contract.json"
            contract.parent.mkdir(parents=True)
            contract.write_text("invalid-json")
            output = root / "failed-budget.json"
            budget.write_failure_report(root, output, ["invalid contract"])
            receipt = json.loads(output.read_text())
            self.assertEqual("FAIL", receipt["status"])
            self.assertEqual(["invalid contract"], receipt["failures"])
            self.assertIn("measurement_error", receipt)
            self.assertNotIn("measurement", receipt)

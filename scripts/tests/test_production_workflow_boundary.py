from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLED = ROOT / ".github/workflows"
TEMPLATES = ROOT / "autoresearch/workflows"
RESEARCH_WORKFLOWS = {
    "audit.yml",
    "automerge.yml",
    "benchmark-pages.yml",
    "judge.yml",
    "metal-calibration.yml",
    "pr6-supremacy.yml",
    "promote.yml",
    "qualify-fork.yml",
    "record.yml",
    "validate.yml",
}


class ProductionWorkflowBoundaryTests(unittest.TestCase):
    def test_autoresearch_workflows_are_templates_not_installed_ci(self) -> None:
        installed = {path.name for path in INSTALLED.glob("*.yml")}
        templates = {path.name for path in TEMPLATES.glob("*.yml")}
        self.assertTrue(RESEARCH_WORKFLOWS.isdisjoint(installed))
        self.assertTrue(RESEARCH_WORKFLOWS <= templates)

    def test_production_workflows_do_not_import_autoresearch(self) -> None:
        for path in sorted(INSTALLED.glob("*.yml")):
            with self.subTest(workflow=path.name):
                self.assertNotIn("autoresearch", path.read_text(encoding="utf-8").lower())

    def test_package_release_is_manual_or_tag_only(self) -> None:
        source = (INSTALLED / "package-release.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", source)
        self.assertIn('tags:\n      - "v*"', source)
        self.assertNotIn("pull_request:", source)
        self.assertNotIn("schedule:", source)


if __name__ == "__main__":
    unittest.main()

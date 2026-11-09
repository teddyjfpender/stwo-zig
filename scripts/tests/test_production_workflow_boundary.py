from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INSTALLED = ROOT / ".github/workflows"


class ProductionWorkflowBoundaryTests(unittest.TestCase):
    def test_production_workflows_do_not_reference_the_retired_research_tree(self) -> None:
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

"""The RISC-V frontend README must describe every result class it can report.

The CSP benchmark README documented only `host-qualified-non-comparable` for a
release after `power-condition-non-publishable` was added, so a reader could not
tell a throttled run from a foreign-host run. Nothing went red, because no check
tied the prose to the classifier. This is that check: the reachable classes are
derived from `classify_result` itself rather than restated here, so adding a
class fails until the README explains it.
"""

from __future__ import annotations

import itertools
import unittest
from pathlib import Path

from scripts.riscv_csp_benchmark_lib.host import classify_result


ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "src/frontends/riscv/README.md"


def reachable_result_classes() -> set[str]:
    return {
        classify_result(
            host_matches=host_matches,
            power_admissible=power_admissible,
            complete_matrix=complete_matrix,
            memory_available=memory_available,
        )
        for host_matches, power_admissible, complete_matrix, memory_available in (
            itertools.product((True, False), repeat=4)
        )
    }


class ResultClassDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = README.read_text(encoding="utf-8")

    def test_every_reachable_result_class_is_documented(self) -> None:
        for result_class in sorted(reachable_result_classes()):
            with self.subTest(result_class=result_class):
                self.assertIn(f"`{result_class}`", self.readme)

    def test_the_power_class_documents_its_precedence(self) -> None:
        # `classify_result` returns the power class before consulting the host,
        # so a throttled run on the publication host is non-publishable rather
        # than comparable. The README has to say so, or the class reads as a
        # milder variant of the host mismatch.
        self.assertEqual(
            "power-condition-non-publishable",
            classify_result(
                host_matches=True,
                power_admissible=False,
                complete_matrix=True,
                memory_available=True,
            ),
        )
        power_section = self.readme.split("`power-condition-non-publishable`", 1)
        self.assertEqual(2, len(power_section))
        self.assertRegex(power_section[1], r"(?s)^.{0,600}?outranks")

    def test_the_readme_names_no_result_class_the_classifier_cannot_return(self) -> None:
        # Guards the other direction: a class removed from the classifier must
        # not linger in the prose as a value readers could expect to see.
        documented = {
            candidate
            for candidate in (
                "official-host-comparable",
                "host-qualified-non-comparable",
                "power-condition-non-publishable",
            )
            if f"`{candidate}`" in self.readme
        }
        self.assertEqual(reachable_result_classes(), documented)


if __name__ == "__main__":
    unittest.main()

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "check_build_configure_closure.py"
SPEC = importlib.util.spec_from_file_location("configure_closure", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ConfigureClosureTests(unittest.TestCase):
    def test_parse_steps_ignores_options(self) -> None:
        help_text = """Usage: zig build\n\nSteps:\n  install (default) Copy\n  focused  Build it\n\nGeneral Options:\n  -h Help\n"""
        self.assertEqual({"install", "focused"}, MODULE.parse_steps(help_text))

    def test_python_checker_has_no_parallel_scope_authority(self) -> None:
        self.assertFalse(hasattr(MODULE, "SCOPES"))
        self.assertFalse(hasattr(MODULE, "MANIFESTS"))

    def test_selected_metal_is_native_only(self) -> None:
        registry = {
            "backend_availability": {"metal-hybrid": True},
            "applications": [
                {"air": "wide_fibonacci", "backends": ["cpu", "metal-hybrid"]},
                {
                    "adapter": "stark-v-rv32im-elf",
                    "air": "stark_v_rv32im",
                    "backends": ["cpu"],
                },
            ],
        }
        MODULE.validate_application_backends(registry, metal=True)

    def test_application_backend_mutations_fail_closed(self) -> None:
        cases = [
            {
                "backend_availability": {"metal-hybrid": True},
                "applications": [
                    {"air": "wide_fibonacci", "backends": ["cpu"]},
                ],
            },
            {
                "backend_availability": {"metal-hybrid": True},
                "applications": [
                    {
                        "adapter": "stark-v-rv32im-elf",
                        "air": "stark_v_rv32im",
                        "backends": ["cpu", "metal-hybrid"],
                    },
                ],
            },
        ]
        for registry in cases:
            with self.subTest(registry=registry):
                with self.assertRaisesRegex(
                    SystemExit,
                    "does not match selected products",
                ):
                    MODULE.validate_application_backends(registry, metal=True)


if __name__ == "__main__":
    unittest.main()

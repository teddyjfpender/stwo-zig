import importlib.util
import json
import tempfile
import unittest
from contextlib import ExitStack
from itertools import product
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).parents[1] / "check_build_configure_closure.py"
SPEC = importlib.util.spec_from_file_location("configure_closure", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ConfigureClosureTests(unittest.TestCase):
    def test_configure_only_skips_install_exercise_and_default_retains_it(self) -> None:
        for configure_only in (True, False):
            for platform, explicit_receipt in product(("linux", "darwin"), (True, False)):
                with self.subTest(configure_only=configure_only, platform=platform, explicit_receipt=explicit_receipt):
                    with tempfile.TemporaryDirectory() as raw, ExitStack() as stack:
                        repo = Path(raw).resolve()
                        default_name = "configure-only-closure.json" if configure_only else "configure-closure.json"
                        receipt = repo / ("receipt.json" if explicit_receipt else f"zig-out/build-graph/{default_name}")
                        arguments = [str(SCRIPT), "--repo", str(repo)]
                        if explicit_receipt:
                            arguments.extend(["--receipt", str(receipt)])
                        if configure_only:
                            arguments.append("--configure-only")
                        stack.enter_context(mock.patch.object(MODULE.sys, "argv", arguments))
                        stack.enter_context(mock.patch.object(MODULE.sys, "platform", platform))
                        stack.enter_context(mock.patch("builtins.print"))
                        catalog = stack.enter_context(mock.patch.object(
                            MODULE, "read_product_catalog", return_value=({}, {"core": {}}, "digest")
                        ))
                        scope = stack.enter_context(mock.patch.object(
                            MODULE, "check_scope", return_value={"scope": "core"}
                        ))
                        unknown = stack.enter_context(mock.patch.object(MODULE, "check_unknown_scope"))
                        ownership = stack.enter_context(mock.patch.object(MODULE, "check_install_ownership"))
                        install = stack.enter_context(mock.patch.object(
                            MODULE, "exercise_install", return_value={"files": ["bin/stwo-zig"]}
                        ))
                        self.assertEqual(0, MODULE.main())
                        catalog.assert_called_once_with(repo)
                        scope.assert_called_once_with(repo, "core", {}, {}, {"core": {}})
                        unknown.assert_called_once_with(repo)
                        ownership.assert_called_once_with(repo)
                        payload = json.loads(receipt.read_text())
                        self.assertEqual([receipt], list(repo.rglob("*.json")))
                        if configure_only:
                            install.assert_not_called()
                            self.assertEqual("stwo-build-configure-only-closure-v1", payload["schema"])
                            self.assertIs(False, payload["installs_exercised"])
                            self.assertEqual([], payload["install_manifests"])
                        else:
                            expected = [mock.call(repo, metal=False)]
                            if platform == "darwin":
                                expected.append(mock.call(repo, metal=True))
                            self.assertEqual(expected, install.call_args_list)
                            self.assertEqual("stwo-build-configure-closure-v2", payload["schema"])
                            self.assertEqual(len(expected), len(payload["install_manifests"]))

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

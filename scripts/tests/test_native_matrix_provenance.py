import json
import unittest
from unittest import mock

from scripts.native.native_proof_matrix_lib.provenance import (
    CommandResult,
    collect_load,
    collect_static,
    validate_environment,
    validate_load,
)


SYSTEM_PROFILE = json.dumps(
    {
        "SPHardwareDataType": [
            {
                "machine_model": "Mac17,7",
                "machine_name": "MacBook Pro",
                "chip_type": "Apple M5 Max",
                "physical_memory": "64 GB",
            }
        ],
        "SPDisplaysDataType": [
            {
                "sppci_model": "Apple M5 Max",
                "sppci_cores": "40",
                "spdisplays_mtlgpufamilysupport": "spdisplays_metal4",
            }
        ],
    }
)


class FakeRunner:
    def __init__(self, *, full_xcode: bool = True):
        self.full_xcode = full_xcode

    def __call__(self, command: tuple[str, ...]) -> CommandResult:
        values = {
            (
                "system_profiler",
                "SPHardwareDataType",
                "SPDisplaysDataType",
                "-json",
                "-detailLevel",
                "mini",
            ): SYSTEM_PROFILE,
            ("sw_vers", "-productVersion"): "26.5.2\n",
            ("sw_vers", "-buildVersion"): "25F84\n",
            ("xcode-select", "-p"): "/Applications/Xcode.app/Contents/Developer\n",
            ("xcodebuild", "-version"): "Xcode 18.0\nBuild version 18A1\n",
            ("xcrun", "--sdk", "macosx", "--show-sdk-version"): "26.5\n",
            ("xcrun", "--find", "metal"): "/toolchain/usr/bin/metal\n",
            ("xcrun", "--find", "metallib"): "/toolchain/usr/bin/metallib\n",
            ("zig", "version"): "0.15.2\n",
            ("rustc", "+nightly-2025-07-14", "--version"): "rustc 1.90.0-nightly\n",
            ("pmset", "-g", "therm"): "Note: No thermal warning level has been recorded\n",
            ("pmset", "-g", "batt"): "Now drawing from 'AC Power'\n",
        }
        if not self.full_xcode and command in {
            ("xcodebuild", "-version"),
            ("xcrun", "--find", "metal"),
            ("xcrun", "--find", "metallib"),
        }:
            return CommandResult(72, "", "not found")
        return CommandResult(0, values.get(command, ""))


class NativeMatrixProvenanceTest(unittest.TestCase):
    def test_source_jit_accepts_command_line_tools_and_binds_runtime_to_os(self):
        value = collect_static("source-jit", FakeRunner(full_xcode=False))
        self.assertTrue(value["complete"])
        self.assertIsNone(value["toolchain"]["metal_compiler_path"])
        self.assertEqual(
            value["toolchain"]["runtime_compiler"],
            "Metal.framework_source_jit_bound_to_os_build",
        )
        validate_environment(value, "source-jit")

    def test_authenticated_aot_requires_full_offline_metal_toolchain(self):
        incomplete = collect_static("authenticated-aot", FakeRunner(full_xcode=False))
        self.assertFalse(incomplete["complete"])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            validate_environment(incomplete, "authenticated-aot")

        complete = collect_static("authenticated-aot", FakeRunner())
        self.assertTrue(complete["complete"])
        validate_environment(complete, "authenticated-aot")

    def test_load_snapshot_records_thermal_power_and_normalized_load(self):
        with mock.patch("os.cpu_count", return_value=10), mock.patch(
            "os.getloadavg", return_value=(2.0, 1.0, 0.5)
        ):
            value = collect_load(FakeRunner())
        self.assertEqual(value["power_source"], "AC Power")
        self.assertEqual(value["load_average"]["one_minute_per_logical_cpu"], 0.2)
        validate_load(value)

    def test_invalid_or_missing_thermal_evidence_fails_closed(self):
        value = collect_load(lambda _: CommandResult(1, "", "missing"))
        self.assertFalse(value["complete"])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            validate_load(value)


if __name__ == "__main__":
    unittest.main()

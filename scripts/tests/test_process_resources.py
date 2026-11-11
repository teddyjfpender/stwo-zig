from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.repo.process_resources_lib import (
    DARWIN_MEASUREMENT,
    GNU_LINUX_MEASUREMENT,
    WALL_CLOCK_MEASUREMENT,
    ResourceMeasurementError,
    collector_label,
    measurement_command,
    measurement_environment,
    parse_process_resources,
)


class ProcessResourceTests(unittest.TestCase):
    def test_commands_are_platform_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            time_binary = Path(directory) / "time"
            time_binary.touch()
            darwin, darwin_measurement = measurement_command(
                ["prove"], platform="darwin", time_binary=time_binary, required=True
            )
            linux, linux_measurement = measurement_command(
                ["prove"], platform="linux", time_binary=time_binary, required=True
            )
        self.assertEqual(darwin, [str(time_binary), "-l", "prove"])
        self.assertEqual(darwin_measurement, DARWIN_MEASUREMENT)
        self.assertEqual(linux, [str(time_binary), "-v", "prove"])
        self.assertEqual(linux_measurement, GNU_LINUX_MEASUREMENT)

    def test_optional_collector_falls_back_to_wall_clock(self) -> None:
        command, measurement = measurement_command(
            ["prove"],
            platform="freebsd",
            time_binary=Path("/missing/time"),
        )
        self.assertEqual(command, ["prove"])
        self.assertEqual(measurement, WALL_CLOCK_MEASUREMENT)
        self.assertEqual(collector_label(measurement), "wall-clock-only")
        with self.assertRaisesRegex(ResourceMeasurementError, "missing"):
            measurement_command(
                ["prove"],
                platform="linux",
                time_binary=Path("/missing/time"),
                required=True,
            )

    def test_darwin_metrics_are_normalized_to_kib(self) -> None:
        metrics = parse_process_resources(
            "1048577 maximum resident set size\n"
            "17 instructions retired\n"
            "19 cycles elapsed\n"
            "2097152 peak memory footprint\n",
            DARWIN_MEASUREMENT,
        )
        self.assertEqual(metrics["peak_rss_kib"], 1025)
        self.assertEqual(metrics["instructions_retired"], 17)
        self.assertEqual(metrics["cycles_elapsed"], 19)
        self.assertEqual(metrics["peak_memory_footprint_bytes"], 2097152)
        self.assertEqual(collector_label(DARWIN_MEASUREMENT, sample=True), "time -l + sample")

    def test_measurement_environment_forces_stable_locale(self) -> None:
        environment = measurement_environment({"LC_ALL": "pt_PT.UTF-8", "LANE": "metal"})
        self.assertEqual(environment["LC_ALL"], "C")
        self.assertEqual(environment["LANE"], "metal")

    def test_gnu_metrics_use_reported_kib(self) -> None:
        metrics = parse_process_resources(
            b"Maximum resident set size (kbytes): 2048\n",
            GNU_LINUX_MEASUREMENT,
        )
        self.assertEqual(metrics["peak_rss_kib"], 2048)
        self.assertIsNone(metrics["instructions_retired"])
        self.assertEqual(collector_label(GNU_LINUX_MEASUREMENT), "time -v")

    def test_missing_duplicate_and_unknown_metrics_fail_closed(self) -> None:
        with self.assertRaisesRegex(ResourceMeasurementError, "one positive"):
            parse_process_resources("", GNU_LINUX_MEASUREMENT)
        with self.assertRaisesRegex(ResourceMeasurementError, "more than once"):
            parse_process_resources(
                "1 maximum resident set size\n2 maximum resident set size\n",
                DARWIN_MEASUREMENT,
            )
        with self.assertRaisesRegex(ResourceMeasurementError, "unsupported"):
            parse_process_resources("", "unknown")


if __name__ == "__main__":
    unittest.main()

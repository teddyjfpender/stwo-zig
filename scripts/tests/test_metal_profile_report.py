import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scripts.metal.metal_profile_report import ProfileError, build_report, load_events, main


def metadata(*, requested=True, enabled=True):
    return {
        "schema": "stwo-metal-profile-v1",
        "type": "metadata",
        "sequence": 0,
        "device": "Test GPU",
        "stage_boundary_timestamps_supported": True,
        "encoder_timestamps_requested": requested,
        "encoder_timestamps_enabled": enabled,
    }


def command(operation, gpu_ms, kernel, encoder_ms, *, status="completed", overflow=False):
    return {
        "schema": "stwo-metal-profile-v1",
        "type": "command_buffer",
        "operation": operation,
        "status": status,
        "gpu_ms": gpu_ms,
        "encoder_gpu_ms": encoder_ms,
        "unattributed_gpu_ms": max(0.0, gpu_ms - encoder_ms),
        "encode_cpu_ms": 0.1,
        "commit_cpu_ms": 0.02,
        "wait_cpu_ms": gpu_ms + 0.2,
        "counter_overflow": overflow,
        "encoders": [
            {
                "kind": "compute",
                "pipelines": [kernel],
                "gpu_ms": encoder_ms,
                "dispatches": 1,
                "grid_threads": 1024,
                "max_threadgroup_threads": 256,
                "bound_buffer_capacity_bytes": 4096,
                "inline_bytes": 8,
                "blit_bytes": 0,
            }
        ],
    }


class MetalProfileReportTest(unittest.TestCase):
    def test_build_report_ranks_kernel_totals_and_aggregates_host_cost(self):
        report = build_report(
            [
                metadata(),
                command("commit", 5.0, "merkle", 4.0),
                command("commit", 3.0, "merkle", 2.0),
                command("witness", 7.0, "relation", 6.0),
            ]
        )
        self.assertEqual(report["summary"]["command_buffers"], 3)
        self.assertEqual(report["summary"]["command_gpu_ms"], 15.0)
        self.assertEqual(report["summary"]["encoder_gpu_ms"], 12.0)
        self.assertEqual(report["summary"]["unattributed_gpu_ms"], 3.0)
        self.assertEqual(report["summary"]["encode_cpu_ms"], 0.3)
        self.assertEqual(report["kernels"][0]["name"], "merkle")
        self.assertEqual(report["kernels"][0]["total_gpu_ms"], 6.0)
        self.assertEqual(report["kernels"][0]["count"], 2)
        self.assertEqual(report["commands"][0]["name"], "commit")
        self.assertEqual(report["commands"][0]["total_gpu_ms"], 8.0)

    def test_load_events_rejects_schema_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.ndjson"
            path.write_text('{"schema":"wrong","type":"metadata"}\n', encoding="utf-8")
            with self.assertRaises(ProfileError):
                load_events(path)

    def test_strict_exit_detects_counter_overflow(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.ndjson"
            events = [metadata(), command("commit", 1.0, "merkle", 0.8, overflow=True)]
            path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(path), "--strict"]), 2)

    def test_missing_encoder_timestamp_is_counted(self):
        event = command("commit", 1.0, "merkle", 0.8)
        del event["encoders"][0]["gpu_ms"]
        event["encoder_gpu_ms"] = 0.0
        event["unattributed_gpu_ms"] = 1.0
        report = build_report([metadata(), event])
        self.assertEqual(report["summary"]["untimed_encoders"], 1)
        self.assertEqual(report["kernels"][0]["timed_count"], 0)

    def test_encoder_total_drift_is_rejected(self):
        event = command("commit", 1.0, "merkle", 0.8)
        event["encoder_gpu_ms"] = 0.7
        with self.assertRaises(ProfileError):
            build_report([metadata(), event])

    def test_strict_exit_detects_encoder_time_exceeding_command(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.ndjson"
            event = command("commit", 0.2, "merkle", 0.4)
            events = [metadata(), event]
            path.write_text("".join(json.dumps(item) + "\n" for item in events), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(path), "--strict"]), 2)
            report = build_report(events)
            self.assertEqual(report["summary"]["timing_inconsistent_commands"], 1)

    def test_strict_exit_detects_counter_allocation_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.ndjson"
            event = command("commit", 1.0, "merkle", 0.0)
            del event["encoders"][0]["gpu_ms"]
            event["counter_allocation_error"] = "sample count exceeds device limit"
            events = [metadata(), event]
            path.write_text("".join(json.dumps(item) + "\n" for item in events), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(path), "--strict"]), 2)
            report = build_report(events)
            self.assertEqual(report["summary"]["counter_allocation_errors"], 1)

    def test_strict_accepts_intentionally_untimed_command_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.ndjson"
            event = command("commit", 1.0, "merkle", 0.0)
            del event["encoders"][0]["gpu_ms"]
            events = [metadata(requested=False, enabled=False), event]
            path.write_text("".join(json.dumps(item) + "\n" for item in events), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(path), "--strict"]), 0)
            report = build_report(events)
            self.assertEqual(report["summary"]["untimed_encoders"], 1)
            self.assertFalse(report["summary"]["encoder_timestamps_enabled"])

    def test_strict_rejects_requested_but_unsupported_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.ndjson"
            event = command("commit", 1.0, "merkle", 0.0)
            del event["encoders"][0]["gpu_ms"]
            events = [metadata(requested=True, enabled=False), event]
            path.write_text("".join(json.dumps(item) + "\n" for item in events), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(path), "--strict"]), 2)


if __name__ == "__main__":
    unittest.main()

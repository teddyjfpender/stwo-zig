import contextlib
import copy
import hashlib
import io
import json
import tempfile
import types
import unittest
from pathlib import Path


from scripts.metal_profile_report_lib import build_report
from scripts.native_profile_capture import parse_args
from scripts.native_profile_capture_lib.contract import (
    validate_metal_profile,
    validate_profile_report,
)
from scripts.native_profile_capture_lib.controller import _product_receipts
from scripts.native_profile_capture_lib.evidence import (
    publish_manifest,
    verify_manifest,
    write_bytes_exclusive,
)
from scripts.native_profile_capture_lib.model import (
    METAL_MAX_ENCODERS_PER_COMMAND_BUFFER,
    PROFILE_WORKLOADS,
    CaptureError,
)
from scripts.native_profile_capture_lib.sample_profile import build_sample_summary
from scripts.tests import native_proof_matrix_support as support


def node(stage_id, children=None):
    return {
        "id": stage_id,
        "label": stage_id.replace("_", " ").title(),
        "seconds": 0.01,
        "children": children,
    }


CORE_IDS = (
    "draw_random_coeff",
    "composition_trace_extract",
    "composition_evaluation",
    "composition_interpolate_and_split",
    "composition_commit",
    "oods_point_and_mask_points",
    "sampled_value_evaluation",
    "sampled_value_channel_mix",
    "fri_quotient_build_and_commit",
    "proof_of_work",
    "fri_decommit",
    "trace_decommit",
    "constraint_check_and_assembly",
)


def profile_report(lane, workload):
    report = support.make_report(
        lane,
        workload,
        samples=1,
        warmups=1,
        resource_profile="large",
    )
    report["profiled"] = True
    report["evidence_class"] = "profiled_diagnostic"
    report["timing"]["stage_profiles"] = [{
        "schema_version": 1,
        "runtime": "ReleaseFast",
        "example": workload.name,
        "stages": [
            node("channel_and_scheme_init"),
            node("preprocessed_commit", [node("merkle_commit")]),
            node("main_trace_commit", [node("merkle_commit")]),
            node("statement_mix"),
            node("core_prove", [node(stage_id) for stage_id in CORE_IDS]),
        ],
    }]
    sample = report["timing"]["samples"][0]
    for sample_field, report_field in (
        ("native_mhz", "diagnostic_native_mhz"),
        ("request_native_mhz", "diagnostic_request_native_mhz"),
        ("trace_row_mhz", "diagnostic_trace_row_mhz"),
        ("request_trace_row_mhz", "diagnostic_request_trace_row_mhz"),
        ("committed_mcells_per_second", "diagnostic_committed_mcells_per_second"),
    ):
        report["throughput"][report_field] = support.summary(sample[sample_field])
    return report


def metal_events(*, counters):
    encoder_ms = 0.8 if counters else None
    return [
        {
            "schema": "stwo-metal-profile-v1",
            "type": "metadata",
            "sequence": 0,
            "pid": 123,
            "device": "Test GPU",
            "stage_boundary_timestamps_supported": True,
            "encoder_timestamps_requested": counters,
            "encoder_timestamps_enabled": counters,
        },
        {
            "schema": "stwo-metal-profile-v1",
            "type": "command_buffer",
            "sequence": 1,
            "operation": "commit",
            "status": "completed",
            "gpu_ms": 1.0,
            "encoder_gpu_ms": encoder_ms or 0.0,
            "unattributed_gpu_ms": 0.2 if counters else 1.0,
            "encode_cpu_ms": 0.1,
            "commit_cpu_ms": 0.01,
            "wait_cpu_ms": 1.1,
            "counter_overflow": False,
            "encoders": [{
                "kind": "compute",
                "pipelines": ["merkle"],
                "gpu_ms": encoder_ms,
                "dispatches": 1,
                "grid_threads": 64,
                "bound_buffer_capacity_bytes": 1024,
                "inline_bytes": 8,
                "blit_bytes": 0,
            }],
        },
    ]


class NativeProfileCaptureTest(unittest.TestCase):
    def test_metal_counter_buffer_capacity_is_bounded(self):
        default_args = parse_args([])
        self.assertEqual(
            METAL_MAX_ENCODERS_PER_COMMAND_BUFFER,
            default_args.metal_max_encoders,
        )
        boundary_args = parse_args([
            "--metal-max-encoders",
            str(METAL_MAX_ENCODERS_PER_COMMAND_BUFFER),
        ])
        self.assertEqual(
            METAL_MAX_ENCODERS_PER_COMMAND_BUFFER,
            boundary_args.metal_max_encoders,
        )
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parse_args([
                "--metal-max-encoders",
                str(METAL_MAX_ENCODERS_PER_COMMAND_BUFFER + 1),
            ])

    def test_all_six_examples_satisfy_cpu_and_metal_stage_contract(self):
        args = support.args(samples=1, warmups=1, resource_profile="large")
        for workload in PROFILE_WORKLOADS:
            for lane in ("cpu", "metal"):
                fingerprint, coverage = validate_profile_report(
                    profile_report(lane, workload), lane, workload, args
                )
                self.assertEqual(support.PROOF_WIRE_SHA256, fingerprint[0])
                self.assertEqual("backend_init_seconds", coverage["host_timer_ids"][0])
                self.assertEqual(list(CORE_IDS), coverage["stage_tree"]["core_stage_ids"])
                if lane == "metal":
                    self.assertGreater(coverage["metal_backend"]["total_metal_dispatches"], 0)

    def test_stage_and_telemetry_drift_fail_closed(self):
        workload = PROFILE_WORKLOADS[0]
        args = support.args(samples=1, warmups=1, resource_profile="large")
        report = profile_report("cpu", workload)
        report["timing"]["stage_profiles"][0]["stages"].pop()
        with self.assertRaisesRegex(CaptureError, "stable root stage IDs changed"):
            validate_profile_report(report, "cpu", workload, args)

        report = profile_report("metal", workload)
        report["backend_telemetry"]["samples"][0]["classification"] = "host_only"
        with self.assertRaisesRegex(CaptureError, "classification disagrees"):
            validate_profile_report(report, "metal", workload, args)

    def test_metal_command_only_and_targeted_counter_modes_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for counters, mode in ((False, "command-only"), (True, "encoder-timestamps")):
                events = metal_events(counters=counters)
                ndjson = root / f"{mode}.ndjson"
                aggregate = root / f"{mode}.json"
                ndjson.write_text("".join(json.dumps(event) + "\n" for event in events))
                aggregate.write_text(json.dumps(build_report(events)))
                summary = validate_metal_profile(
                    ndjson,
                    aggregate,
                    mode=mode,
                    expected_pid=123,
                    backend_dispatches=4,
                )
                self.assertEqual(mode, summary["mode"])
                self.assertEqual(1, summary["kernel_dispatches"])

            events = metal_events(counters=False)
            ndjson.write_text("".join(json.dumps(event) + "\n" for event in events))
            aggregate.write_text(json.dumps(build_report(events)))
            with self.assertRaisesRegex(CaptureError, "counter request"):
                validate_metal_profile(
                    ndjson,
                    aggregate,
                    mode="encoder-timestamps",
                    expected_pid=123,
                    backend_dispatches=4,
                )

    def test_cpu_sample_summary_requires_real_hotspots(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary) / "cpu.sample.txt"
            sample.write_text(
                "header\nSort by top of stack, same collapsed\n"
                "  prove_main (in native-proof-bench-cpu) 17\n"
                "Binary Images:\n"
            )
            summary = build_sample_summary(sample)
            self.assertEqual(17, summary["top_hotspot_samples"])
            sample.write_text("no hotspot section\n")
            with self.assertRaisesRegex(CaptureError, "no parsed"):
                build_sample_summary(sample)

    def test_manifest_detects_exact_artifact_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_bytes_exclusive(root / "row/cpu.stdout.json", b"{}\n")
            result = publish_manifest(root, {"schema_version": 1, "rows": []})
            self.assertEqual(64, len(result["manifest_sha256"]))
            self.assertEqual(1, len(verify_manifest(root)["artifacts"]))
            (root / "row/cpu.stdout.json").write_bytes(b"mutated\n")
            with self.assertRaisesRegex(CaptureError, "differs"):
                verify_manifest(root)

    def test_profile_manifest_binds_focused_products_but_cannot_promote(self):
        workload = PROFILE_WORKLOADS[0]
        rows = [{
            "workload": workload.report_dict(),
            "descriptor_sha256": support.MODULE.workload_descriptor_sha256(
                workload, "functional"
            ),
            "lanes": {},
        }]
        for lane in ("cpu", "metal"):
            report = profile_report(lane, workload)
            rows[0]["lanes"][lane] = {
                "product_identity": report["product_identity"],
                "coverage": {
                    "host_timer_scope": {"request_seconds": "verified request"}
                },
                "proof": {"proof_sha256": support.PROOF_WIRE_SHA256},
            }
        settings = types.SimpleNamespace(
            protocol="functional",
            warmups=1,
            samples=1,
            resource_profile="large",
            metal_runtime="source-jit",
        )
        binary_hashes = {"cpu": "6" * 64, "metal": "7" * 64}
        host = {"schema": "native_matrix_host_environment_v1"}
        receipts = _product_receipts(
            settings=settings,
            rows=rows,
            binary_hashes=binary_hashes,
            host_environment=host,
        )
        self.assertFalse(receipts["cpu"]["promotion_eligible"])
        self.assertFalse(receipts["metal"]["promotion_eligible"])

        manifest = {
            "schema_version": 2,
            "protocol": "native_profiler_baseline_v2",
            "product_receipts": receipts,
            "host_environment": host,
            "binaries": {
                lane: {"path": lane, "sha256": digest}
                for lane, digest in binary_hashes.items()
            },
            "rows": rows,
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_bytes_exclusive(root / "row/cpu.stdout.json", b"{}\n")
            publish_manifest(root, manifest)
            verified = verify_manifest(root)
            self.assertEqual(
                verified["product_receipts"]["metal"]["product_identity"]["name"],
                "stwo-native-metal",
            )

        substituted = copy.deepcopy(manifest)
        receipt = substituted["product_receipts"]["metal"]
        receipt["host_device"] = {
            "schema": "native_matrix_host_environment_v1",
            "metal_device": {"runtime_identity": "substituted-metal-runtime"},
        }
        payload = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        receipt["receipt_sha256"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_bytes_exclusive(root / "row/cpu.stdout.json", b"{}\n")
            with self.assertRaisesRegex(CaptureError, "host/device identity"):
                publish_manifest(root, substituted)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import recursive_pipeline_protocol as protocol
from scripts import recursive_pipeline_cli as pipeline_cli
from scripts import recursive_pipeline_zig_stage101_frontier as frontier


def digest(value: int) -> str:
    return f"{value:064x}"


def blob(kind: int, schema: int, identity: int, byte_count: int = 32) -> dict:
    return {
        "byte_count": byte_count,
        "format_version": 1,
        "kind": kind,
        "schema_version": schema,
        "sha256": digest(identity),
    }


def description(count: int = 2) -> dict:
    namespace = digest(10)
    rows = []
    for index in range(count):
        inputs = []
        for ordinal, ((role, input_ordinal), (kind, schema)) in enumerate(
            zip(
                frontier.STAGE_INPUT_COORDINATES,
                frontier.STAGE_INPUT_CODECS,
                strict=True,
            )
        ):
            inputs.append({
                "blob": blob(kind, schema, 1000 + index * 16 + ordinal),
                "ordinal": input_ordinal,
                "role": role,
            })
        recipe = inputs[2]["blob"]
        rows.append({
            "campaign_namespace_sha256": namespace,
            "local_task_identity_sha256": digest(100 + index),
            "recipe_ref": copy.deepcopy(recipe),
            "segment_index": index,
            "semantic_authorities": {
                field: digest(200 + index * 16 + authority)
                for authority, field in enumerate(protocol.KEY_AUTHORITY_FIELDS)
            },
            "stage_inputs": inputs,
        })
    padded = 1 << (count - 1).bit_length()
    return {
        "authenticated_segment_count": count,
        "campaign_namespace_sha256": namespace,
        "custody_validation_receipt_identity_sha256": digest(2),
        "format": frontier.FORMAT,
        "import_receipt_identity_sha256": digest(3),
        "rows": rows,
        "schema_version": frontier.SCHEMA_VERSION,
        "table_ref": blob(
            frontier.TABLE_KIND,
            frontier.TABLE_SCHEMA_VERSION,
            4,
            256 + count * 512,
        ),
        "topology": {
            "empty_leaf_count": padded - count,
            "fold_count": padded - 1,
            "leaf_count": count,
            "padded_leaf_count": padded,
        },
        "validation_receipt_identity_sha256": digest(5),
    }


class ZigStage101FrontierTests(unittest.TestCase):
    def test_canonical_description_forwards_only_native_frontier(self) -> None:
        value = description(3)
        parsed = frontier.parse_description(protocol.canonical_bytes(value))
        nodes = frontier.stage101_frontier(parsed)
        self.assertEqual([node["node_id"] for node in nodes], [
            "native/0", "native/1", "native/2",
        ])
        self.assertTrue(all(node["dependencies"] == [] for node in nodes))
        self.assertTrue(all(node["semantic_options"] == {} for node in nodes))
        self.assertEqual(nodes[2]["external_inputs"], value["rows"][2]["stage_inputs"])
        self.assertEqual(
            nodes[1]["local_task_identity_sha256"],
            value["rows"][1]["local_task_identity_sha256"],
        )

    def test_description_rejects_order_role_codec_count_and_task_drift(self) -> None:
        source = description(3)
        mutations = []
        changed = copy.deepcopy(source)
        changed["rows"][0], changed["rows"][1] = changed["rows"][1], changed["rows"][0]
        mutations.append(changed)
        changed = copy.deepcopy(source)
        changed["rows"][0]["stage_inputs"][0]["role"] = 3
        mutations.append(changed)
        changed = copy.deepcopy(source)
        changed["rows"][0]["stage_inputs"][5]["blob"]["schema_version"] = 1
        mutations.append(changed)
        changed = copy.deepcopy(source)
        changed["authenticated_segment_count"] = 2
        mutations.append(changed)
        changed = copy.deepcopy(source)
        changed["rows"][0]["local_task_identity_sha256"] = "00" * 32
        mutations.append(changed)
        changed = copy.deepcopy(source)
        changed["rows"][0]["recipe_ref"] = blob(9, 1, 9999)
        mutations.append(changed)
        for value in mutations:
            with self.subTest(value=value):
                with self.assertRaises(protocol.PipelineError):
                    frontier.parse_description(protocol.canonical_bytes(value))

    def test_python_does_not_mint_recursive_topology_or_validation_identity(self) -> None:
        value = description(5)
        # The Zig validation identity is opaque controller metadata.  Any
        # nonzero canonical digest is forwarded; Python does not recompute it.
        value["validation_receipt_identity_sha256"] = digest(999)
        parsed = frontier.parse_description(protocol.canonical_bytes(value))
        self.assertEqual(parsed["topology"], value["topology"])
        self.assertEqual(
            parsed["validation_receipt_identity_sha256"], digest(999)
        )
        with self.assertRaisesRegex(
            protocol.PipelineError, "requires Zig wrapper, empty, and fold"
        ):
            frontier.require_complete_recursive_description(parsed)

    def test_controller_view_is_unsealed_and_explicitly_incomplete(self) -> None:
        source = description(5)
        view = frontier.controller_view(source)
        self.assertFalse(view["complete_recursive_campaign"])
        self.assertEqual(view["description"], source)
        self.assertEqual(len(view["nodes"]), 5)
        self.assertNotIn("content_sha256", view)
        frontier.validate_controller_view(view)

        changed = copy.deepcopy(view)
        changed["nodes"][0]["external_inputs"].reverse()
        with self.assertRaises(protocol.PipelineError):
            frontier.validate_controller_view(changed)

        changed = copy.deepcopy(view)
        changed["complete_recursive_campaign"] = True
        with self.assertRaises(protocol.PipelineError):
            frontier.validate_controller_view(changed)

    def test_cli_emits_only_the_incomplete_zig_frontier_view(self) -> None:
        source = description(3)
        arguments = [
            "stage101-frontier",
            "--cold-describe-worker", "/typed/zig-boundary",
            "--campaign-import-receipt", "/sealed/campaign.stwcir04",
            "--artifact-store-root", "/zig/cas",
            "--timeout-seconds", "17",
        ]
        with mock.patch.object(
            pipeline_cli.zig_frontier,
            "run_cold_describe",
            return_value=source,
        ) as describe, mock.patch.object(pipeline_cli, "_emit") as emit:
            self.assertEqual(pipeline_cli.main(arguments), 0)
        describe.assert_called_once_with(
            Path("/typed/zig-boundary"),
            Path("/sealed/campaign.stwcir04"),
            Path("/zig/cas"),
            timeout_seconds=17.0,
        )
        emitted = emit.call_args.args[0]
        frontier.validate_controller_view(emitted)
        self.assertEqual(len(emitted["nodes"]), 3)
        self.assertFalse(emitted["complete_recursive_campaign"])

    def test_noncanonical_framing_and_unknown_fields_fail_closed(self) -> None:
        value = description(2)
        raw = protocol.canonical_bytes(value)
        with self.assertRaises(protocol.PipelineError):
            frontier.parse_description(raw[:-1])
        changed = copy.deepcopy(value)
        changed["python_inferred_shape"] = True
        with self.assertRaises(protocol.PipelineError):
            frontier.parse_description(protocol.canonical_bytes(changed))

    def test_cold_describe_executes_only_the_typed_zig_boundary(self) -> None:
        raw = protocol.canonical_bytes(description(3))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "cold-describe"
            receipt = root / "campaign.stwcir04"
            store = root / "cas"
            executable.write_bytes(b"fixture")
            receipt.write_bytes(b"receipt")
            store.mkdir()

            def run(command: list[str], **options: object) -> subprocess.CompletedProcess:
                options["stdout"].write(raw)  # type: ignore[union-attr]
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(frontier.subprocess, "run", side_effect=run) as invoked:
                parsed, nodes = frontier.stage101_frontier_from_cold_receipt(
                    executable, receipt, store, timeout_seconds=17
                )
            self.assertEqual(parsed["authenticated_segment_count"], 3)
            self.assertEqual(len(nodes), 3)
            command = invoked.call_args.args[0]
            self.assertEqual(command, [
                str(executable.resolve()),
                "--campaign-import-receipt",
                str(receipt.resolve()),
                "--artifact-store-root",
                str(store.resolve()),
            ])
            self.assertEqual(invoked.call_args.kwargs["timeout"], 17)
            self.assertIs(invoked.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_cold_describe_rejects_failure_timeout_and_oversized_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "cold-describe"
            receipt = root / "campaign.stwcir04"
            store = root / "cas"
            executable.write_bytes(b"fixture")
            receipt.write_bytes(b"receipt")
            store.mkdir()

            def failed(command: list[str], **options: object) -> subprocess.CompletedProcess:
                options["stderr"].write(b"typed custody rejected\n")  # type: ignore[union-attr]
                return subprocess.CompletedProcess(command, 17)

            with mock.patch.object(frontier.subprocess, "run", side_effect=failed):
                with self.assertRaisesRegex(protocol.PipelineError, "exit 17"):
                    frontier.run_cold_describe(executable, receipt, store)
            with mock.patch.object(
                frontier.subprocess,
                "run",
                side_effect=subprocess.TimeoutExpired([str(executable)], 1),
            ):
                with self.assertRaisesRegex(protocol.PipelineError, "timed out"):
                    frontier.run_cold_describe(
                        executable, receipt, store, timeout_seconds=1
                    )

            def oversized(command: list[str], **options: object) -> subprocess.CompletedProcess:
                options["stdout"].seek(frontier.MAX_DESCRIPTION_BYTES)  # type: ignore[union-attr]
                options["stdout"].write(b"xx")  # type: ignore[union-attr]
                return subprocess.CompletedProcess(command, 0)

            with mock.patch.object(frontier.subprocess, "run", side_effect=oversized):
                with self.assertRaisesRegex(protocol.PipelineError, "size differs"):
                    frontier.run_cold_describe(executable, receipt, store)

    def test_cold_describe_rejects_missing_paths_and_invalid_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "cold-describe"
            receipt = root / "campaign.stwcir04"
            store = root / "cas"
            executable.write_bytes(b"fixture")
            receipt.write_bytes(b"receipt")
            store.mkdir()
            with self.assertRaisesRegex(protocol.PipelineError, "timeout differs"):
                frontier.run_cold_describe(
                    executable, receipt, store, timeout_seconds=float("nan")
                )
            with self.assertRaisesRegex(protocol.PipelineError, "unavailable"):
                frontier.run_cold_describe(
                    root / "missing", receipt, store
                )


if __name__ == "__main__":
    unittest.main()

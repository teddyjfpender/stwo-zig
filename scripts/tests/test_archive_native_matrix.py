import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.native.archive_native_matrix import ArchiveError, build_manifest, publish_bundle


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_matrix(path: Path) -> Path:
    row = path / "row"
    row.mkdir(parents=True)
    lanes = {}
    for lane in ("cpu", "metal"):
        stdout = row / f"{lane}.stdout.json"
        stderr = row / f"{lane}.stderr.txt"
        proof = row / f"{lane}.proof.json"
        stdout.write_text(json.dumps({"backend": lane}) + "\n", encoding="utf-8")
        stderr.write_bytes(b"stderr\n")
        proof.write_text(json.dumps({"proof_bytes_hex": "00"}) + "\n", encoding="utf-8")
        lanes[lane] = {
            "stdout_artifact": f"row/{lane}.stdout.json",
            "stdout_sha256": digest(stdout.read_bytes()),
            "stderr_artifact": f"row/{lane}.stderr.txt",
            "stderr_sha256": digest(stderr.read_bytes()),
            "proof_artifact": {
                "path": f"row/{lane}.proof.json",
                "sha256": digest(proof.read_bytes()),
            },
        }
    summary = {
        "protocol": "native_proof_cross_backend_matrix_v4",
        "schema_version": 4,
        "generated_at": "2026-07-18T06:43:34.232047+00:00",
        "configuration": {"provenance": {"git_commit": "a" * 40}},
        "rows": [{"lanes": lanes}],
    }
    report = path / "summary.json"
    report.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def seed_archive(archive: Path, report: Path) -> str:
    """Layout-v2 archives require the report to be archived under a run first."""
    raw = report.read_bytes()
    sha = digest(raw)
    run = "2026-07-18-064334-matrix-v4-aaaaaaaa"
    run_report = archive / "runs" / run / "report.json"
    run_report.parent.mkdir(parents=True, exist_ok=True)
    run_report.write_bytes(raw)
    index = {
        "schema_version": 2,
        "runs": {
            run: {
                "kind": "native_proof_cross_backend_matrix_v4",
                "report": {"path": f"runs/{run}/report.json", "bytes": len(raw), "sha256": sha},
                "deltas": [],
                "bundle": None,
            }
        },
        "artifacts": {sha: {"path": f"runs/{run}/report.json", "bytes": len(raw), "run": run}},
        "deltas": {},
        "bundles": {},
        "comparisons": [],
    }
    (archive / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
    return run


class ArchiveNativeMatrixTests(unittest.TestCase):
    def test_publishes_exact_tree_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = write_matrix(root / "matrix")
            run = seed_archive(root / "archive", report)
            first = publish_bundle(root / "matrix", root / "archive", report)
            second = publish_bundle(root / "matrix", root / "archive", report)
            self.assertEqual(first, second)
            self.assertEqual(6, first["artifact_files"])
            self.assertEqual(run, first["run"])
            self.assertEqual(f"runs/{run}/bundle", first["path"])
            bundle = root / "archive" / first["path"]
            # No duplicated report bytes: the run's report.json is the single copy.
            self.assertFalse((bundle / "summary.json").exists())
            self.assertTrue((bundle / "tree/row/metal.proof.json").is_file())
            manifest = json.loads((bundle / "manifest.json").read_text())
            self.assertEqual("a" * 40, manifest["execution_provenance"]["runner"]["git_commit"])
            self.assertIn("host fields absent", manifest["limitations"][0])
            index = json.loads((root / "archive" / "index.json").read_text())
            self.assertEqual(first, index["runs"][run]["bundle"])
            self.assertEqual(first, index["bundles"][first["bundle_sha256"]])

    def test_refuses_unarchived_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = write_matrix(root / "matrix")
            with self.assertRaisesRegex(ArchiveError, "index.json is missing"):
                publish_bundle(root / "matrix", root / "archive", report)

    def test_preserves_complete_host_provenance_without_a_missing_field_limitation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = write_matrix(root / "matrix")
            summary = json.loads(report.read_text())
            summary["configuration"]["host_environment"] = {"schema": "host-v1"}
            summary["configuration"]["host_load"] = {"start": {}, "end": {}}
            report.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

            manifest, _ = build_manifest(root / "matrix", report)
            self.assertEqual(
                {"schema": "host-v1"},
                manifest["execution_provenance"]["host_environment"],
            )
            self.assertEqual(1, len(manifest["limitations"]))

    def test_rejects_artifact_and_report_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = write_matrix(root / "matrix")
            (root / "matrix/row/cpu.stdout.json").write_text("mutated\n")
            with self.assertRaisesRegex(ArchiveError, "digest mismatch"):
                build_manifest(root / "matrix", report)

            report = write_matrix(root / "other")
            immutable = root / "immutable.json"
            immutable.write_text("{}\n")
            with self.assertRaisesRegex(ArchiveError, "differs"):
                build_manifest(root / "other", immutable)

    def test_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = write_matrix(root / "matrix")
            summary = json.loads(report.read_text())
            summary["rows"][0]["lanes"]["cpu"]["stdout_artifact"] = "../escape"
            report.write_text(json.dumps(summary) + "\n")
            with self.assertRaisesRegex(ArchiveError, "safe relative path"):
                build_manifest(root / "matrix", None)


if __name__ == "__main__":
    unittest.main()

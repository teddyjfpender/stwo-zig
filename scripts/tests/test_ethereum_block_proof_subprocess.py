from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import tempfile
import textwrap
import unittest

from scripts import ethereum_block_proof_controller as controller
from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_store as store
from scripts.tests.ethereum_block_proof_fixture import build_plan, file_identity


def install_tool(base: Path, fail_once: Path) -> Path:
    tool = base / "bin/proof-tool"
    source = f'''#!/usr/bin/env python3
import hashlib, json, os, pathlib, subprocess, sys

FAIL_ONCE = pathlib.Path({str(fail_once)!r})
OMIT_TERMINAL = pathlib.Path({str(base / "omit-terminal")!r})
SURVIVE_ONCE = pathlib.Path({str(base / "surviving-descendant")!r})
DESCENDANT_PID = pathlib.Path({str(base / "surviving-descendant.pid")!r})

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\\n").encode()

def seal(value):
    value = dict(value)
    value["content_sha256"] = hashlib.sha256(canonical(value)).hexdigest()
    return value

def identity(path):
    raw = path.read_bytes()
    return {{"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}

def load(path):
    return json.loads(pathlib.Path(path).read_text())

def publish(path, payload):
    path = pathlib.Path(path)
    with path.open("xb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    os.fsync(directory)
    os.close(directory)

def option(name):
    return sys.argv[sys.argv.index(name) + 1]

def root_for(statement):
    return hashlib.sha256(("root:" + statement).encode()).hexdigest()

def proof_bytes(statement):
    return canonical({{"statement_sha256": statement, "root_sha256": root_for(statement)}})

def leaf_stream():
    request = load(option("--request"))
    proof_root = pathlib.Path(option("--proof-root"))
    progress = pathlib.Path(request["durable_progress"]["path"])
    prefix = request["durable_progress"]["publication_prefix"]
    publications = []
    for segment in request["segments"][request["first_uncommitted_segment"]:]:
        index = segment["segment_index"]
        proof = proof_root / f"segment-{{index:06d}}.stw"
        result = proof_root / f"segment-{{index:06d}}.result.json"
        raw = proof_bytes(segment["expected_statement_sha256"])
        publish(proof, raw)
        leaf = seal({{
            "schema": "stwo.ethereum.block-proof-leaf-result.v1",
            "status": "proved",
            "request_sha256": request["content_sha256"],
            "segment_index": index,
            "expected_authority_sha256": segment["expected_authority"]["sha256"],
            "statement_sha256": segment["expected_statement_sha256"],
            "root_sha256": root_for(segment["expected_statement_sha256"]),
            "proof": {{"path": proof.name, **identity(proof)}},
            "prove_timing": {{"wall_ns": 10, "user_ns": 9, "system_ns": 1}},
        }})
        publish(result, canonical(leaf))
        record = seal({{
            "schema": request["durable_progress"]["schema"],
            "segment_index": index,
            "stream_session_sha256": request["stream_session_sha256"],
            "request_sha256": request["content_sha256"],
            "proof": {{"path": f"{{prefix}}/{{proof.name}}", **identity(proof)}},
            "result": {{"path": f"{{prefix}}/{{result.name}}", **identity(result)}},
        }})
        with progress.open("ab", buffering=0) as output:
            output.write(canonical(record))
            os.fsync(output.fileno())
        publications.append({{
            "segment_index": index,
            "progress_record_sha256": record["content_sha256"],
            "proof": record["proof"], "result": record["result"],
        }})
        if FAIL_ONCE.exists():
            FAIL_ONCE.unlink()
            raise SystemExit(7)
    if OMIT_TERMINAL.exists():
        OMIT_TERMINAL.unlink()
        return
    terminal = seal({{
        "schema": "stwo.ethereum.block-proof-leaf-stream-result.v1",
        "status": "complete", "request_sha256": request["content_sha256"],
        "producer_sha256": identity(pathlib.Path(sys.argv[0]))["sha256"],
        "stream_session_sha256": request["stream_session_sha256"],
        "first_segment_index": request["first_uncommitted_segment"],
        "publications": publications,
    }})
    publish(option("--result"), canonical(terminal))
    if SURVIVE_ONCE.exists():
        SURVIVE_ONCE.unlink()
        descendant = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True,
        )
        DESCENDANT_PID.write_text(str(descendant.pid))

def parent_producer():
    request = load(option("--request"))
    semantic = request["task_request"]
    raw = proof_bytes(semantic["expected_statement_sha256"])
    proof = pathlib.Path(option("--proof-out"))
    publish(proof, raw)
    result = seal({{
        "schema": "stwo.ethereum.block-proof-parent-result.v1", "status": "proved",
        "request_sha256": request["content_sha256"],
        "producer_sha256": identity(pathlib.Path(sys.argv[0]))["sha256"],
        "statement_sha256": semantic["expected_statement_sha256"],
        "root_sha256": root_for(semantic["expected_statement_sha256"]),
        "proof_bytes": len(raw), "proof_sha256": hashlib.sha256(raw).hexdigest(),
        "prove_timing": {{"wall_ns": 10, "user_ns": 9, "system_ns": 1}},
    }})
    publish(option("--result"), canonical(result))

def verifier():
    request = load(option("--request"))
    semantic = request.get("task_request", request)
    proof_path = pathlib.Path(option("--proof"))
    proof = identity(proof_path)
    decoded = json.loads(proof_path.read_text())
    verifier_sha = identity(pathlib.Path(sys.argv[0]))["sha256"]
    receipt = {{
        "schema": "stwo.ethereum.block-proof-verification-receipt.v2",
        "status": "verified", "scope": semantic["scope"],
        "level": semantic["level"], "node_index": semantic["node_index"],
        "statement_sha256": semantic["expected_statement_sha256"],
        "root_sha256": decoded["root_sha256"], "proof_bytes": proof["bytes"],
        "proof_sha256": proof["sha256"], "verifier_sha256": verifier_sha,
        "security": semantic["verification_security"],
        "proof_profile_authority": semantic["proof_profile_authority"],
        "fresh_verification": True,
    }}
    result = seal({{
        "schema": "stwo.ethereum.block-proof-verifier-result.v1",
        "status": "verified", "request_sha256": request["content_sha256"],
        "verifier_sha256": verifier_sha,
        "statement_sha256": semantic["expected_statement_sha256"],
        "root_sha256": decoded["root_sha256"], "proof_bytes": proof["bytes"],
        "proof_sha256": proof["sha256"], "verification_receipt": receipt,
    }})
    publish(option("--result"), canonical(result))

command = sys.argv[1]
if command == "ethereum-block-leaf-producer": leaf_stream()
elif command == "ethereum-block-parent-producer": parent_producer()
elif command in ("ethereum-leaf-verifier", "ethereum-parent-verifier"): verifier()
else: raise SystemExit(64)
'''
    tool.write_text(textwrap.dedent(source))
    tool.chmod(0o700)
    return tool


def production_plan(base: Path, *, fail: bool) -> tuple[dict, dict]:
    plan, paths = build_plan(base, segment_count=2)
    marker = base / "fail-once" if fail else base / "disabled-failure"
    if fail:
        marker.write_text("fail after one durable leaf")
    tool = install_tool(base, marker)
    updated = copy.deepcopy(plan)
    updated["prover"] = file_identity(tool)
    updated["verifier"] = file_identity(tool)
    updated = protocol.seal({
        key: value for key, value in updated.items() if key != "content_sha256"
    })
    paths["prover"] = tool
    paths["verifier"] = tool
    paths["omit_terminal"] = base / "omit-terminal"
    paths["surviving_descendant"] = base / "surviving-descendant"
    paths["descendant_pid"] = base / "surviving-descendant.pid"
    return updated, paths


def execute(plan: dict, paths: dict) -> dict:
    return controller.run_subprocess_for_test(
        plan, paths["run_root"], paths["segment_root"],
        prover_path=paths["prover"], verifier_path=paths["verifier"],
        timeout_seconds=5,
    )


class EthereumBlockProofSubprocessTests(unittest.TestCase):
    def test_prelaunch_partial_session_is_completed_without_discarding_the_root(self) -> None:
        for static_files in (False, True):
            with self.subTest(static_files=static_files), tempfile.TemporaryDirectory() as raw:
                plan, paths = production_plan(Path(raw), fail=False)
                run_root = paths["run_root"].absolute()
                staging = controller._prepare_root(run_root, plan)
                from scripts.ethereum_block_proof_child import SubprocessChildAdapter
                adapter = SubprocessChildAdapter(plan, run_root=run_root)
                adapter._ensure_spool({"scratch_root": staging})
                adapter.close()
                session = run_root / "leaf-stream/sessions/session-000000"
                session.mkdir()
                if static_files:
                    (session / "proofs").mkdir()
                    (session / "stdout.bin").write_bytes(b"")
                    (session / "stderr.bin").write_bytes(b"")
                result = execute(plan, paths)
                sessions = result["result"]["systems"]["stwo"]["proof_custody"][
                    "producer_sessions"
                ]
                self.assertEqual(len(sessions), 1)
                self.assertEqual(sessions[0]["receipt"]["classification"], "complete")

    def test_one_stream_incrementally_publishes_and_resume_is_process_free(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan, paths = production_plan(Path(raw), fail=False)
            first = execute(plan, paths)
            self.assertEqual(len(first["records"]), 3)
            sessions = first["result"]["systems"]["stwo"]["proof_custody"][
                "producer_sessions"
            ]
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0]["receipt"]["classification"], "complete")
            progress = paths["run_root"] / "leaf-stream/proofs/progress.ndjson"
            self.assertEqual(len(progress.read_text().splitlines()), 3)
            manifest = (paths["run_root"] / "topology-test.json").read_bytes()
            second = execute(plan, paths)
            self.assertEqual(second["manifest"], first["manifest"])
            self.assertEqual((paths["run_root"] / "topology-test.json").read_bytes(), manifest)
            self.assertEqual(len(list(
                (paths["run_root"] / "leaf-stream/sessions").iterdir()
            )), 1)
            replayed = controller.replay_subprocess_for_test(
                plan, paths["run_root"], paths["segment_root"],
                prover_path=paths["prover"], verifier_path=paths["verifier"],
            )
            self.assertEqual(replayed["manifest"], first["manifest"])

    def test_failed_stream_keeps_committed_prefix_and_resumes_in_new_session(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan, paths = production_plan(Path(raw), fail=True)
            with self.assertRaises(protocol.ProofProtocolError):
                execute(plan, paths)
            leaf0 = paths["run_root"] / "leaves/segment-000000"
            retained = {
                path: path.read_bytes() for path in leaf0.rglob("*") if path.is_file()
            }
            final = execute(plan, paths)
            self.assertTrue(all(path.read_bytes() == value for path, value in retained.items()))
            sessions = final["result"]["systems"]["stwo"]["proof_custody"][
                "producer_sessions"
            ]
            self.assertEqual([item["receipt"]["classification"] for item in sessions],
                             ["failed", "complete"])
            self.assertFalse(final["result"]["comparison_ready"])
            self.assertFalse(final["records"][1]["proof_artifact"]["attempts"][
                "performance_claim_eligible"
            ])

    def test_complete_session_requires_a_cross_bound_terminal_result(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan, paths = production_plan(Path(raw), fail=False)
            paths["omit_terminal"].write_text("omit the completion authority")
            with self.assertRaises(protocol.ProofProtocolError):
                execute(plan, paths)
            receipt = store.read_canonical_json(
                paths["run_root"].joinpath(
                    "leaf-stream/sessions/session-000000/session-receipt.json"
                ),
                "leaf stream receipt",
            )
            self.assertEqual(receipt["classification"], "failed")

    def test_surviving_lockless_descendant_rejects_the_stream_session(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan, paths = production_plan(Path(raw), fail=False)
            paths["surviving_descendant"].write_text("spawn one descendant")
            with self.assertRaises(protocol.ProofProtocolError):
                execute(plan, paths)
            self.assertTrue(paths["descendant_pid"].is_file())
            receipt = store.read_canonical_json(
                paths["run_root"].joinpath(
                    "leaf-stream/sessions/session-000000/session-receipt.json"
                ),
                "leaf stream receipt",
            )
            self.assertEqual(receipt["classification"], "failed")

    def test_replay_rejects_session_and_progress_symlinks_without_launching(self) -> None:
        for relative in (
            "leaf-stream/sessions/session-000000/session-receipt.json",
            "leaf-stream/proofs/progress.ndjson",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as raw:
                plan, paths = production_plan(Path(raw), fail=False)
                execute(plan, paths)
                path = paths["run_root"] / relative
                path.unlink()
                path.symlink_to(paths["run_root"] / "topology-test.json")
                with self.assertRaises(protocol.ProofProtocolError):
                    controller.replay_subprocess_for_test(
                        plan, paths["run_root"], paths["segment_root"],
                        prover_path=paths["prover"], verifier_path=paths["verifier"],
                    )
                self.assertEqual(len(list(
                    (paths["run_root"] / "leaf-stream/sessions").iterdir()
                )), 1)


if __name__ == "__main__":
    unittest.main()

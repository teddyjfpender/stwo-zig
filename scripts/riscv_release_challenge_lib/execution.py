"""Execute one fresh RISC-V release challenge under a bounded trust policy."""

from __future__ import annotations

import json
import os
import shutil
import stat
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    from riscv_release_oracle_lib.relations import compare_sum_dumps
    from riscv_release_oracle_lib import public_values as public_value_contract
    from riscv_staged_smoke_lib import contracts
except ModuleNotFoundError:
    from scripts.riscv_release_oracle_lib.relations import compare_sum_dumps
    from scripts.riscv_release_oracle_lib import public_values as public_value_contract
    from scripts.riscv_staged_smoke_lib import contracts

from . import model


def normalize_artifact_public_data(statement: dict[str, Any]) -> dict[str, Any]:
    flat = statement.get("public_data")
    if not isinstance(flat, dict):
        raise model.ChallengeError("candidate proof public data is malformed")
    public = {
        field: flat.get(field)
        for field in (
            "initial_pc", "final_pc", "clock", "initial_regs", "final_regs",
            "reg_last_clock", "program_root", "initial_rw_root", "final_rw_root",
        )
    }
    public["io_entries"] = {
        field: flat.get(field)
        for field in (
            "input_start", "input_len", "input_words", "output_len",
            "output_len_addr", "output_data_addr", "output_words",
        )
    }
    try:
        return public_value_contract.validate_public_data_shape(
            public, "candidate proof public_data",
        )
    except ValueError as error:
        raise model.ChallengeError(str(error)) from error


def require_static_elf(path: Path) -> None:
    if path.stat().st_size > 128 * 1024 * 1024:
        raise model.ChallengeError(f"candidate tool is oversized: {path.name}")
    raw = path.read_bytes()
    if len(raw) < 64 or raw[:4] != b"\x7fELF" or raw[5] != 1:
        raise model.ChallengeError(f"candidate tool is not little-endian ELF: {path.name}")
    if raw[4] == 2:
        program_offset = struct.unpack_from("<Q", raw, 32)[0]
        entry_size, count = struct.unpack_from("<HH", raw, 54)
    elif raw[4] == 1:
        program_offset = struct.unpack_from("<I", raw, 28)[0]
        entry_size, count = struct.unpack_from("<HH", raw, 42)
    else:
        raise model.ChallengeError(f"candidate ELF class is unsupported: {path.name}")
    if entry_size < 4 or count == 0 or program_offset + entry_size * count > len(raw):
        raise model.ChallengeError(f"candidate ELF program headers are malformed: {path.name}")
    for index in range(count):
        if struct.unpack_from("<I", raw, program_offset + entry_size * index)[0] == 3:
            raise model.ChallengeError(f"candidate tool has a dynamic interpreter: {path.name}")


class CommandRunner:
    def __init__(self, *, deadline_ns: int, prefix: list[str] | None = None) -> None:
        self.deadline_ns = deadline_ns
        self.prefix = prefix or []

    def run(self, name: str, command: list[str]) -> tuple[str, dict[str, object]]:
        remaining = (self.deadline_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            raise model.ChallengeError("challenge execution deadline expired")
        started = time.monotonic_ns()
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(
                [*self.prefix, *command], stdout=stdout, stderr=stderr,
                start_new_session=True,
            )
            try:
                returncode = process.wait(timeout=max(1, remaining))
            except subprocess.TimeoutExpired as error:
                os.killpg(process.pid, 9)
                process.wait()
                raise model.ChallengeError(f"{name} exceeded the challenge deadline") from error
            stdout.seek(0)
            stderr.seek(0)
            stdout_bytes = stdout.read(model.MAX_JSON_BYTES + 1)
            stderr_bytes = stderr.read(model.MAX_JSON_BYTES + 1)
        if len(stdout_bytes) > model.MAX_JSON_BYTES or len(stderr_bytes) > model.MAX_JSON_BYTES:
            raise model.ChallengeError(f"{name} produced oversized diagnostic output")
        try:
            stdout_text = stdout_bytes.decode()
            stderr_text = stderr_bytes.decode()
        except UnicodeDecodeError as error:
            raise model.ChallengeError(f"{name} produced non-UTF-8 diagnostics") from error
        elapsed = time.monotonic_ns() - started
        if returncode != 0:
            diagnostic = (stderr_text or stdout_text).strip()
            raise model.ChallengeError(f"{name} failed ({returncode}): {diagnostic}")
        return stdout_text, {
            "name": name,
            "duration_ns": elapsed,
            "returncode": returncode,
        }


class CandidateSandbox:
    """Chroot an unprivileged candidate away from trusted anchor material."""

    def __init__(
        self, root: Path, *, cli: Path, trace_cli: Path, elf: Path, input_path: Path,
        deadline_ns: int,
    ) -> None:
        self.root = root
        self.output = root / "out"
        if root.exists():
            raise model.ChallengeError("candidate sandbox already exists")
        for relative in ("bin", "work", "out", "proc"):
            (root / relative).mkdir(parents=True, exist_ok=False)
        for source, relative, mode in (
            (cli, "bin/prover", 0o555),
            (trace_cli, "bin/trace", 0o555),
            (elf, "work/challenge.elf", 0o444),
            (input_path, "work/challenge.input", 0o444),
        ):
            destination = root / relative
            shutil.copyfile(source, destination)
            destination.chmod(mode)
        (root / "bin").chmod(0o555)
        (root / "work").chmod(0o555)
        self.output.chmod(0o700)
        root.chmod(0o555)
        ownership = subprocess.run(
            ["sudo", "-n", "chown", "65534:65534", str(self.output)],
            check=False, capture_output=True, text=True, timeout=10,
        )
        if ownership.returncode != 0:
            raise model.ChallengeError(
                "cannot assign isolated candidate output ownership: "
                + (ownership.stderr or ownership.stdout).strip()
            )
        prefix = [
            "sudo", "-n", "unshare", "--net", "--mount", "--pid", "--fork",
            "--kill-child=SIGKILL", f"--mount-proc={root / 'proc'}", "--",
            "prlimit", "--cpu=160:160", "--as=3221225472:3221225472",
            "--fsize=134217728:134217728", "--nproc=256:256", "--",
            "setpriv", "--no-new-privs", "--",
            "chroot", "--userspec=65534:65534", str(root),
        ]
        self.runner = CommandRunner(deadline_ns=deadline_ns, prefix=prefix)

    def run(self, name: str, command: list[str]) -> tuple[str, dict[str, object]]:
        return self.runner.run(name, command)

    def collect_outputs(self, destinations: dict[str, Path]) -> None:
        ownership = subprocess.run(
            [
                "sudo", "-n", "chown", "-R", f"{os.getuid()}:{os.getgid()}",
                str(self.output),
            ],
            check=False, capture_output=True, text=True, timeout=10,
        )
        if ownership.returncode != 0:
            raise model.ChallengeError(
                "cannot recover isolated candidate outputs: "
                + (ownership.stderr or ownership.stdout).strip()
            )
        names = {entry.name for entry in self.output.iterdir()}
        if names != set(destinations):
            raise model.ChallengeError(f"candidate output set drifted: {sorted(names)}")
        for name, destination in destinations.items():
            source = self.output / name
            metadata = source.lstat()
            if not stat.S_ISREG(metadata.st_mode) or source.is_symlink():
                raise model.ChallengeError(f"candidate output is not regular: {name}")
            if metadata.st_size > model.MAX_JSON_BYTES:
                raise model.ChallengeError(f"candidate output is oversized: {name}")
            shutil.copyfile(source, destination)

    def close(self) -> None:
        subprocess.run(
            [
                "sudo", "-n", "chown", "-R", f"{os.getuid()}:{os.getgid()}",
                str(self.output),
            ],
            check=False, capture_output=True, timeout=10,
        )
        self.root.chmod(0o755)
        for directory in (
            self.root / "bin", self.root / "work", self.output, self.root / "proc",
        ):
            directory.chmod(0o755)
        shutil.rmtree(self.root)


def execute(
    *, challenge_path: Path, identity: dict[str, Any], cli: Path, trace_cli: Path,
    oracle_cli: Path, verifier_cli: Path, evidence_dir: Path, replay_ledger: Path,
) -> dict[str, Any]:
    started = time.monotonic_ns()
    challenge = model.strict_json(challenge_path)
    derived = model.validate_challenge(challenge, expected_identity=identity, now=int(time.time()))
    if evidence_dir.exists() and any(evidence_dir.iterdir()):
        raise model.ChallengeError("challenge evidence directory is not empty")
    remaining_lifetime_ns = max(
        0, challenge["expires_at_unix"] - int(time.time())
    ) * 1_000_000_000
    deadline = min(
        started + 180_000_000_000,
        time.monotonic_ns() + remaining_lifetime_ns,
    )
    for path in (cli, trace_cli):
        require_static_elf(path)
    for path, expected_digest in {
        cli: identity["candidate"]["executable_sha256"],
        trace_cli: identity["candidate"]["trace_executable_sha256"],
        oracle_cli: identity["anchor"]["oracle_executable_sha256"],
        verifier_cli: identity["anchor"]["verifier_executable_sha256"],
    }.items():
        if model.sha256_file(path) != expected_digest:
            raise model.ChallengeError(f"execution binary differs from challenge: {path.name}")
    model.claim_replay_slot(replay_ledger, challenge["challenge_id_sha256"])
    evidence_dir.mkdir(parents=True, exist_ok=True)
    local_challenge = evidence_dir / "challenge.json"
    local_challenge.write_bytes(challenge_path.read_bytes())
    elf_path = evidence_dir / "challenge.elf"
    input_path = evidence_dir / "challenge.input"
    elf_path.write_bytes(derived.elf_bytes)
    input_path.write_bytes(derived.input_bytes)
    proof_path = evidence_dir / "proof.json"
    report_path = evidence_dir / "prove-report.json"
    verify_path = evidence_dir / "verify-receipt.json"
    oracle_public_path = evidence_dir / "oracle-public.json"
    candidate_public_path = evidence_dir / "candidate-public.json"
    oracle_relations_path = evidence_dir / "oracle-relations.txt"
    candidate_relations_path = evidence_dir / "candidate-relations.txt"
    trusted_runner = CommandRunner(deadline_ns=deadline)
    records: list[dict[str, object]] = []
    phase_args = ["--experimental"] if identity["candidate"]["phase"] == "candidate" else []
    sandbox = CandidateSandbox(
        evidence_dir / ".candidate-sandbox",
        cli=cli,
        trace_cli=trace_cli,
        elf=elf_path,
        input_path=input_path,
        deadline_ns=deadline,
    )
    try:
        _, record = sandbox.run("candidate-prove", [
            "/bin/prover", "prove", "--elf", "/work/challenge.elf",
            "--input", "/work/challenge.input", "--backend", "cpu",
            "--protocol", "secure", "--output", "/out/proof.json",
            "--report-out", "/out/prove-report.json", *phase_args,
        ])
        records.append(record)
        sandbox.collect_outputs({
            "proof.json": proof_path,
            "prove-report.json": report_path,
        })
        candidate_public, record = sandbox.run("candidate-public", [
            "/bin/trace", "--public-values", "/work/challenge.elf",
            "--input", "/work/challenge.input", "--max-steps", "1000000",
        ])
        records.append(record)
        candidate_relations, record = sandbox.run("candidate-relations", [
            "/bin/trace", "--relation-sums", "/work/challenge.elf",
            "--input", "/work/challenge.input", "--max-steps", "1000000",
        ])
        records.append(record)
    finally:
        sandbox.close()
    candidate_public_path.write_text(candidate_public, encoding="utf-8")
    candidate_relations_path.write_text(candidate_relations, encoding="utf-8")
    report = model.strict_json(report_path)
    statement_digest = report.get("statement_sha256")
    if not isinstance(statement_digest, str) or model.SHA256_RE.fullmatch(statement_digest) is None:
        raise model.ChallengeError("prove report has no valid statement digest")
    verify_receipt, record = trusted_runner.run("anchor-independent-verify", [
        str(verifier_cli), "verify", "--artifact", str(proof_path),
        "--elf", str(elf_path), "--protocol", "secure",
        "--expect-statement-digest", statement_digest,
    ])
    records.append(record)
    verify_path.write_text(verify_receipt, encoding="utf-8")
    receipt = model.strict_json(verify_path)
    if receipt.get("status") != "verified" or receipt.get("statement_sha256") != statement_digest:
        raise model.ChallengeError("anchor verifier receipt differs from challenged proof")
    oracle_public, record = trusted_runner.run("pinned-oracle-public", [
        str(oracle_cli), "--elf", str(elf_path), "--input", str(input_path),
        "--max-steps", "1000000",
    ])
    records.append(record)
    oracle_public_path.write_text(oracle_public, encoding="utf-8")
    if len(candidate_public.encode()) > model.MAX_JSON_BYTES:
        raise model.ChallengeError("candidate public diagnostic is oversized")
    oracle_relations, record = trusted_runner.run("pinned-oracle-relations", [
        str(oracle_cli), "--relation-sums", "--elf", str(elf_path),
        "--input", str(input_path), "--max-steps", "1000000",
    ])
    records.append(record)
    oracle_relations_path.write_text(oracle_relations, encoding="utf-8")

    proof = model.strict_json(proof_path)
    oracle = model.strict_json(oracle_public_path)
    candidate_public_payload = model.strict_json(candidate_public_path)
    expected_status = (
        "not_release_gated" if identity["candidate"]["phase"] == "candidate"
        else "release_gated"
    )
    provenance = candidate_public_payload.get("provenance")
    if not isinstance(provenance, dict):
        raise model.ChallengeError("candidate public diagnostic provenance is malformed")
    witness_layout = provenance.get("witness_layout_sha256")
    if not isinstance(witness_layout, str) or model.SHA256_RE.fullmatch(witness_layout) is None:
        raise model.ChallengeError("candidate public diagnostic witness layout is malformed")
    candidate_public_data = public_value_contract.parse_public_values_diagnostic(
        candidate_public,
        candidate=identity["candidate"]["commit"],
        witness_layout_sha256=witness_layout,
        elf_sha256=derived.elf_sha256,
        input_sha256=derived.input_sha256,
    )
    contracts.validate_artifact(
        proof,
        expected_status=expected_status,
        expected_commit=identity["candidate"]["commit"],
        expected_dirty=False,
        elf_sha256=derived.elf_sha256,
        input_sha256=derived.input_sha256,
        witness_layout_sha256=witness_layout,
    )
    if proof.get("protocol") != "secure":
        raise model.ChallengeError("candidate proof does not use the secure protocol")
    contracts.validate_prove_report(
        report,
        expected_status=expected_status,
        experimental=identity["candidate"]["phase"] == "candidate",
        statement_sha256=statement_digest,
        proof_path="/out/proof.json",
        expected_commit=identity["candidate"]["commit"],
        expected_dirty=False,
        executable_sha256=identity["candidate"]["executable_sha256"],
    )
    contracts.validate_verify_receipt(
        receipt,
        expected_status=expected_status,
        policy="secure",
        statement_sha256=statement_digest,
        proof_bytes=bytes.fromhex(proof["proof_bytes_hex"]),
        transcript_state_blake2s=report["transcript_state_blake2s"],
        expected_commit=identity["anchor"]["candidate_commit"],
        expected_dirty=False,
        executable_sha256=identity["anchor"]["verifier_executable_sha256"],
    )
    statement = proof.get("statement")
    trace = oracle.get("trace")
    if not isinstance(statement, dict) or not isinstance(trace, dict):
        raise model.ChallengeError("candidate proof or oracle terminal trace is malformed")
    proof_public_data = normalize_artifact_public_data(statement)
    if proof_public_data != oracle.get("public_data"):
        raise model.ChallengeError("candidate proof public data differs from pinned Rust oracle")
    if candidate_public_data != oracle.get("public_data"):
        raise model.ChallengeError("candidate public diagnostic differs from pinned Rust oracle")
    if (statement.get("final_pc"), statement.get("total_steps")) != (
        trace.get("final_pc"), trace.get("total_steps"),
    ):
        raise model.ChallengeError("candidate statement terminal state differs from Rust execution")
    relation_comparison = compare_sum_dumps(oracle_relations, candidate_relations)
    if not relation_comparison["agree"]:
        raise model.ChallengeError(
            f"candidate relation sums differ from pinned Rust oracle: {relation_comparison['first_divergence']}"
        )
    binding = relation_comparison.get("binding")
    expected_binding = {
        "implementation_commit": identity["candidate"]["commit"],
        "implementation_dirty": False,
        "oracle_commit": identity["anchor"]["oracle_commit"],
        "elf_sha256": derived.elf_sha256,
        "input_sha256": derived.input_sha256,
    }
    if not isinstance(binding, dict) or any(binding.get(key) != value for key, value in expected_binding.items()):
        raise model.ChallengeError("candidate relation binding differs from challenged identities")
    expected_executables = {
        cli: identity["candidate"]["executable_sha256"],
        trace_cli: identity["candidate"]["trace_executable_sha256"],
        oracle_cli: identity["anchor"]["oracle_executable_sha256"],
        verifier_cli: identity["anchor"]["verifier_executable_sha256"],
    }
    for path, expected_digest in expected_executables.items():
        if model.sha256_file(path) != expected_digest:
            raise model.ChallengeError(f"execution binary changed during challenge: {path.name}")
    if model.sha256_file(elf_path) != derived.elf_sha256 or \
            model.sha256_file(input_path) != derived.input_sha256:
        raise model.ChallengeError("challenged ELF or input changed during execution")

    files = {
        path.name: model.sha256_file(path)
        for path in (
            local_challenge, elf_path, input_path, proof_path, report_path, verify_path,
            oracle_public_path, candidate_public_path, oracle_relations_path,
            candidate_relations_path,
        )
    }
    result = {
        "schema": model.RESULT_SCHEMA,
        "status": "PASS",
        "challenge_id_sha256": challenge["challenge_id_sha256"],
        "anchor": identity["anchor"],
        "candidate": identity["candidate"],
        "network_isolation": "linux-unshare-network-namespace-required",
        "comparisons": {
            "independent_verify": "PASS",
            "public_data_exact": "PASS",
            "trace_terminal_state_exact": "PASS",
            "relation_sums_exact": "PASS",
        },
        "files": files,
        "timing": {
            "wall_duration_ns": time.monotonic_ns() - started,
            "commands": records,
        },
        "trust_limits": [
            "The GitHub-hosted worker, trusted workflow, and repository owner remain trusted.",
            "The verifier is a separate process from the reusable exhaustive anchor, not the challenged source.",
            "Fresh randomized sampling complements rather than replaces exhaustive anchor evidence.",
            "The pinned Rust oracle independently checks execution public data and relation sums.",
        ],
    }
    model.validate_result(result, challenge, evidence_dir)
    return result

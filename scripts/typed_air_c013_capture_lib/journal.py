"""Append-only raw-attempt journal for crash-auditable C-013 capture."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .codec import canonical_bytes, content_digest, sha256_file, write_new
from .model import CaptureError, SCHEDULE_SHA256


class AttemptJournal:
    def __init__(self, bundle: Path, plan: dict[str, Any], plan_bytes: bytes):
        self.bundle = bundle.resolve()
        try:
            self.bundle.mkdir(mode=0o700, parents=False, exist_ok=False)
        except OSError as error:
            raise CaptureError(f"cannot create exclusive capture bundle: {self.bundle}") from error
        write_new(self.bundle / "plan.json", plan_bytes)
        (self.bundle / "attempts").mkdir(mode=0o700)
        self.path = self.bundle / "journal.ndjson"
        try:
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except OSError as error:
            raise CaptureError("cannot create attempt journal") from error
        self._output = os.fdopen(descriptor, "wb", buffering=0)
        self._closed = False
        self._records = 0
        self.append(
            {
                "schema": "stwo.typed-air.c013-attempt-journal-header.v1",
                "session_id": plan["session_id"],
                "plan_sha256": plan["content_sha256"],
                "schedule_sha256": SCHEDULE_SHA256,
                "planned_attempts": len(plan["attempts"]),
            }
        )

    @property
    def records(self) -> int:
        return self._records

    def append(self, value: dict[str, Any]) -> dict[str, Any]:
        if self._closed:
            raise CaptureError("attempt journal is already closed")
        record = dict(value)
        record["content_sha256"] = content_digest(record)
        payload = canonical_bytes(record)
        try:
            self._output.write(payload)
            os.fsync(self._output.fileno())
        except OSError as error:
            raise CaptureError("could not durably append attempt journal") from error
        self._records += 1
        return record

    def retain_attempt_streams(
        self,
        ordinal: int,
        stdout: bytes,
        stderr: bytes,
    ) -> dict[str, dict[str, Any]]:
        if ordinal < 0:
            raise CaptureError("attempt ordinal cannot be negative")
        relative_stdout = Path("attempts") / f"{ordinal:04d}.stdout.json"
        relative_stderr = Path("attempts") / f"{ordinal:04d}.stderr.bin"
        write_new(self.bundle / relative_stdout, stdout)
        write_new(self.bundle / relative_stderr, stderr)
        stdout_bytes, stdout_sha = sha256_file(self.bundle / relative_stdout)
        stderr_bytes, stderr_sha = sha256_file(self.bundle / relative_stderr)
        return {
            "stdout": {
                "path": relative_stdout.as_posix(),
                "bytes": stdout_bytes,
                "sha256": stdout_sha,
            },
            "stderr": {
                "path": relative_stderr.as_posix(),
                "bytes": stderr_bytes,
                "sha256": stderr_sha,
            },
        }

    def close(self) -> dict[str, Any]:
        if self._closed:
            raise CaptureError("attempt journal closed more than once")
        try:
            os.fsync(self._output.fileno())
            self._output.close()
        except OSError as error:
            raise CaptureError("could not close attempt journal") from error
        self._closed = True
        size, digest = sha256_file(self.path)
        return {
            "path": self.path.relative_to(self.bundle).as_posix(),
            "bytes": size,
            "sha256": digest,
            "records": self._records,
        }

    def abandon(self) -> None:
        if self._closed:
            return
        try:
            self._output.flush()
            os.fsync(self._output.fileno())
            self._output.close()
        finally:
            self._closed = True

    def __enter__(self) -> "AttemptJournal":
        return self

    def __exit__(self, *_: object) -> None:
        self.abandon()

#!/usr/bin/env python3
"""Archived pre-Sail challenge CLI; retained only for format forensics."""

def main(_argv: list[str] | None = None) -> int:
    raise SystemExit(
        "retired pre-Sail challenge command; use scripts/riscv_release_gate.py "
        "--strict with a pinned formal workspace"
    )


if __name__ == "__main__":
    raise SystemExit(main())

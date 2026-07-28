"""RVFI-DII v1 framing and connection mechanics for pinned Sail sessions."""

from __future__ import annotations

import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Any

from .contract import EquivalenceError

ROOT = Path(__file__).resolve().parents[2]
RVFI_DII_ENTRY = 0x0001_0000
RVFI_DII_V1_BYTES = 88
RVFI_TRANSPORT_PATCH = (
    ROOT / "conformance" / "riscv" / "sail-rvfi-zkvm-entry.patch"
)
SAIL_CONFIG_OVERRIDES = (
    ROOT / "conformance" / "riscv" / "sail-rv32im-override.json",
    ROOT / "conformance" / "riscv" / "sail-rv32im-tagged-options.json",
)


def decode_rvfi_dii_v1(packet: bytes) -> dict[str, Any]:
    """Decode the official 704-bit RVFI-DII v1 little-endian packet."""
    if len(packet) != RVFI_DII_V1_BYTES:
        raise EquivalenceError(
            f"RVFI-DII packet has {len(packet)} bytes, expected {RVFI_DII_V1_BYTES}"
        )
    words = struct.unpack("<11Q", packet)
    return {
        "order": words[0],
        "pc": words[1] & 0xFFFF_FFFF,
        "next_pc": words[2] & 0xFFFF_FFFF,
        "instruction": words[3] & 0xFFFF_FFFF,
        "rd_value": words[6] & 0xFFFF_FFFF,
        "memory": {
            "address": words[7] & 0xFFFF_FFFF,
            "read_value": words[8] & 0xFFFF_FFFF,
            "write_value": words[9] & 0xFFFF_FFFF,
            "read_mask": packet[80] & 0xF,
            "write_mask": packet[81] & 0xF,
        },
        "rd": packet[84] & 0x1F,
        "trap": packet[85] != 0,
        "halt": packet[86] != 0,
        "intr": packet[87] != 0,
    }


def reserve_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def connect_rvfi(
    process: subprocess.Popen[bytes],
    port: int,
    timeout_seconds: float,
) -> socket.socket:
    deadline = time.monotonic() + timeout_seconds
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _, stderr = process.communicate()
            raise EquivalenceError(
                f"Sail exited before RVFI connection: "
                f"{stderr.decode(errors='replace').strip()}"
            )
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except OSError as error:
            last_error = error
            time.sleep(0.01)
    raise EquivalenceError(f"timed out connecting to Sail RVFI-DII: {last_error}")


def recv_exact(connection: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise EquivalenceError(
                f"Sail RVFI-DII closed after {len(result)} of {size} bytes"
            )
        result.extend(chunk)
    return bytes(result)

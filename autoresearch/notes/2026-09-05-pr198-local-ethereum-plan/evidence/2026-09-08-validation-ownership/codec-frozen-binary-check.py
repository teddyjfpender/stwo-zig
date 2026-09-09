#!/usr/bin/env python3
"""Run exactly one already-compiled codec test via Zig 0.15 test protocol."""
import hashlib, json, os, select, struct, subprocess, sys, time
from pathlib import Path
root = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(root / "scripts"))
from zig_serial_build import build_lock, DEFAULT_LOCK
base = Path(__file__).resolve().parent
binary = root / ".git/local-ethereum/devex-validation-source-v3/source/src/integrations/riscv_cpu/.zig-cache/o/87cb08a32281a12657ac8658ac6b39d5/test"
name = "recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_test.test.Ethereum cohort replay publication preserves absent and present initial claims"
receipt = {"binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "test_name": name, "command": [str(binary), "--listen=-", "--seed=0xf7eb47ed"], "protocol": "query_test_metadata(4), run_test(5, selected exact index), exit(0)", "compilation": False, "real_replay": False}
with build_lock(DEFAULT_LOCK, label="frozen-codec-only"):
    with (base / "codec-frozen-binary-stderr.log").open("wb") as stderr:
        proc = subprocess.Popen(receipt["command"], cwd=binary.parents[3], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr)
        deadline = time.monotonic() + 30
        def read_exact(size):
            data = b""
            while len(data) < size:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([proc.stdout], [], [], remaining)[0]:
                    raise TimeoutError("bounded codec test protocol timed out")
                chunk = os.read(proc.stdout.fileno(), size - len(data))
                if not chunk: raise RuntimeError("unexpected test protocol EOF")
                data += chunk
            return data
        def receive():
            tag, size = struct.unpack("<II", read_exact(8))
            return tag, read_exact(size)
        def send(tag, body=b""):
            proc.stdin.write(struct.pack("<II", tag, len(body)) + body)
            proc.stdin.flush()
        try:
            tag, version = receive()
            assert tag == 0, tag
            receipt["zig_version"] = version.decode()
            send(4)
            tag, metadata = receive()
            assert tag == 3, tag
            string_len, count = struct.unpack_from("<II", metadata)
            offsets = struct.unpack_from("<" + "I" * count, metadata, 8)
            strings = metadata[8 + 8 * count:]
            assert len(strings) == string_len
            names = [strings[offset:].split(b"\0", 1)[0].decode() for offset in offsets]
            assert names.count(name) == 1, names
            index = names.index(name)
            receipt["metadata_test_names"] = names
            receipt["test_index"] = index
            send(5, struct.pack("<I", index))
            tag, result = receive()
            assert tag == 4, tag
            result_index, flags = struct.unpack("<II", result)
            assert result_index == index
            receipt["result_flags"] = flags
            receipt["passed"] = flags == 0
            send(0)
            receipt["exit_code"] = proc.wait(timeout=5)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
(base / "codec-frozen-binary-result.json").write_text(json.dumps(receipt, indent=2) + "\n")
print(json.dumps(receipt, indent=2))
sys.exit(0 if receipt.get("passed") and receipt.get("exit_code") == 0 else 1)

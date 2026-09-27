import json, struct, blake3, hashlib
protocol = b'stwo.blake3.experimental.v1'
digest = bytes([0xab]) * 32
prefix = b'stwo-zig/riscv/transcript-state/v2\0' + struct.pack('<I', len(protocol)) + protocol + digest
print(json.dumps({'implementation': 'python blake3 ' + blake3.__version__, 'legacy': hashlib.blake2s(b'stwo-zig/riscv/transcript-state/v1' + digest + struct.pack('<I', 0)).hexdigest(), 'blake3': {str(n): blake3.blake3(prefix + struct.pack('<Q', n)).hexdigest() for n in [0, 1, 2**32, 2**64-1]}}, indent=2))

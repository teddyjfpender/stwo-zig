"""Independent byte-encoding oracle; requires Python blake3, never imported by prover."""
import json, struct
from blake3 import blake3
P = b'stwo.blake3.experimental.v1'
def h(tag, *parts): return blake3(P + bytes([tag]) + b''.join(parts)).digest()
u32 = lambda x: struct.pack('<I', x)
u64 = lambda x: struct.pack('<Q', x)
state = h(0)
out = {'init': state.hex()}
state = h(1, state, u64(3), *(u32(x) for x in [0, 0x80000000, 0xffffffff]))
out['words'] = state.hex()
out['draw0'] = h(5, state, u64(0)).hex()
out['draw1'] = h(5, state, u64(1)).hex()
state = h(3, state, u64(0xfedcba9876543210)); out['integer'] = state.hex()
state = h(2, state, u64(1), *(u32(x) for x in [0,1,2147483646,7])); out['felts'] = state.hex()
leaf = h(7, *(u32(x) for x in [0,1,2147483646,7])); out['leaf'] = leaf.hex()
node = h(8, leaf, bytes(range(32))); out['node'] = node.hex()
state = h(4, state, node); out['root'] = state.hex()
nonce = 0
while int.from_bytes(h(6,state,u32(8),u64(nonce))[:4],'little') & 255: nonce += 1
out['nonce8'] = nonce
print(json.dumps(out, indent=2))

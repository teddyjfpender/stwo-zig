"""Geometry only: parse retained v2 plans, never admit proofs or claim timings."""
import json, struct
from pathlib import Path
HERE = Path(__file__).resolve().parent
BASELINE = HERE.parent / '2026-09-23-blake3-csp-regression' / 'suite'

def compressions(addresses, depth):
    leaves = set(addresses)
    parents = sum(len({address >> level for address in leaves}) for level in range(1, depth + 1))
    return len(leaves) + 2 * parents

def padded(rows):
    return 1 << max(1, (max(1, rows) - 1).bit_length())

def inspect(path):
    raw = path.read_bytes()
    assert raw.count(b'B3CPLAN1') == 1
    at = raw.index(b'B3CPLAN1')
    assert struct.unpack_from('<I', raw, at + 8)[0] == 2
    nm, np = struct.unpack_from('<II', raw, at + 140)
    groups = [[], [], []]
    for i in range(nm):
        address, _, direction, _, _ = struct.unpack_from('<IIIII', raw, at + 148 + 20 * i)
        assert direction in (0, 1) and address % 4 == 0
        groups[1 + direction].append(address)
    for i in range(np):
        _, address, _ = struct.unpack_from('<III', raw, at + 148 + 20 * nm + 12 * i)
        assert address % 4 == 0
        groups[0].append(address)
    byte = [compressions([a + limb for a in words for limb in range(4)], 30) for words in groups]
    old = sum(byte) * 56
    public_rom = sum(byte[1:]) * 56
    # Hypothesis only: change memory tree to u32 leaves / 28-bit word addresses.
    # Keep the current two-compression internal-node frame in this estimate.
    word_memory = sum(compressions([a >> 2 for a in words], 28) for words in groups[1:]) * 56
    return dict(case=path.stem, v2_g_rows=old, v2_padded=padded(old),
                public_rom_g_rows=public_rom, public_rom_padded=padded(public_rom),
                hypothetical_word_memory_g_rows=word_memory,
                hypothetical_word_memory_padded=padded(word_memory))

if __name__ == '__main__':
    rows = [inspect(p) for p in sorted(BASELINE.glob('cpu-*.b3proof'))]
    (HERE / 'geometry.json').write_text(json.dumps(rows, indent=2) + '\n')
    for row in rows:
        print(row['case'], row['v2_g_rows'], row['public_rom_g_rows'], row['hypothetical_word_memory_g_rows'])

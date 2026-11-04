#!/usr/bin/env python3
"""Reference implementation of the RV64 M5 canonical-native v1 encodings (stream canon-native).

This file is the executable spec of /workspace/m3/M5-INTERFACES.md section "canon-native" and of
design/riscv-proving-stack/rv64-m5-canon-native.md.  The Zig module
src/integrations/riscv_cpu/word16_global_execution/ethereum/canon_native.zig must agree with it byte for
byte; its tests pin the digests this script prints (`vectors`), and canon-vk's in-circuit rule pins the
same vectors (vectors/rv64-m5/canon-native-v1-vectors.json).

Encoding rule (binding note sec. 2): every hash input is a domain tag followed by a FIXED-LENGTH sequence
of canonical u32 words, serialised little-endian.  The tag is the 32-byte Blake2s-256 digest of its ASCII
name (8 constant words in-circuit).  u64 = (lo, hi) words; digest = 8 words (LE u32 of its 32 bytes);
optional log = 0 when absent (every admitted log is >= 5, so 0 is unambiguous).

  H(tag, words) = Blake2s-256( Blake2s-256(tag) || LE32(words) )

  python3 scripts/rv64_m5_canon_native_ref.py vectors [--out FILE]
"""
import argparse
import hashlib
import json
import struct

VERSION_NAME = "rv64-m5-native-chi-chain/v1"
LOCAL_RELATIONS = 10  # production gkr_local/fractions.zig Relation (byte_pair added); rv64-m7-profiles.md sec. 2.1
GLOBAL_RELATIONS = 3  # ram, kio, wire (separate bus sums, binding note F4)
RUNGS = 3             # class rungs per family (kill rule: 4 if the cells-weighted tax > 40 %)
FAMILIES_TRUTH = 12   # services/types.zig FAMILIES

# family ids (u32)
CPU_FIRST, CPU_MIDDLE, CPU_LAST, CPU_SINGLE = 0, 1, 2, 3
TRUTH_BASE = 16       # 16 + services/types.zig Family (keccak=0 ... bls12_381_g1_double=11)
MEMORY_BOUNDARY = 32  # the `mb` family (binding note sec. 5.1)
TRUTH_NAMES = ["keccak", "add", "double", "sha256", "arith256_mod", "bn254_g1_add", "bn254_g1_double", "bn254_fp2_mul",
               "bls12_381_fp2_mul", "arith384_mont", "bls12_381_g1_add", "bls12_381_g1_double"]
FAMILY_NAMES = {CPU_FIRST: "cpu_first", CPU_MIDDLE: "cpu_middle", CPU_LAST: "cpu_last", CPU_SINGLE: "cpu_single", MEMORY_BOUNDARY: "mb"}
FAMILY_NAMES.update({TRUTH_BASE + i: "truth_" + n for i, n in enumerate(TRUTH_NAMES)})

# component ids (index in these frozen lists) of a class rung vector
CPU_COMPONENTS = ["cpu_log", "alu_log", "alu_tail_log", "binary_log", "binary_tail_log", "shift_log", "shift_tail_log", "jalr_log",
                  "division_log", "multiplication_log", "ls_log", "ls_tail_log", "boundary_log", "initial_log", "terminal_log",
                  "bridge.keccak", "bridge.add", "bridge.double", "bridge.sha256", "bridge.arith256_mod", "bridge.bn254_g1_add",
                  "bridge.bn254_g1_double", "bridge.bn254_fp2_mul", "bridge.bls12_381_fp2_mul", "bridge.arith384_mont",
                  "bridge.bls12_381_g1_add", "bridge.bls12_381_g1_double", "bridge.bulk.desc", "bridge.bulk.copy", "bridge.bulk.set",
                  "bridge.bulk.ucopy", "bridge.bulk.cdesc", "bridge.bulk.cmp", "bridge.bulk.jdesc", "bridge.bulk.jscan", "bridge.bulk.jtab",
                  "bridge.sponge.call", "bridge.sponge.perm", "bridge.ls_dword", "bridge.ls_dword_tail", "bridge.zbb"]
TRUTH_COMPONENTS = ["main", "aux"]

# kinds of segment statements
KIND_CPU, KIND_TRUTH, KIND_MB = 1, 2, 3

TAGS = {
    "class_key": "rv64-m5-class-key/v1",
    "structure": "rv64-m5-native-structure/v1",
    "vk": "rv64-m5-native-vk/v1",
    "nat_leaf": "rv64-m5-tnat-leaf/v1",
    "nat_empty": "rv64-m5-tnat-empty/v1",
    "node": "rv64-m5-merkle-node/v1",
    "table": "rv64-m5-tnat-header/v1",
    "version": "rv64-m5-native-version/v1",
    "state": "rv64-m5-state/v1",
    "stmt": "rv64-m5-stmt/v1",
    "rho": "rv64-m5-rho/v1",
    "iv": "rv64-m5-chain-iv/v1",
    "seg": "rv64-m5-seg",
    "chi": "rv64-m5-chi",
}
MASK32 = 0xFFFFFFFF


def tag(name):
    return hashlib.blake2s(TAGS[name].encode()).digest()


def le(words):
    for w in words:
        if not (0 <= w <= MASK32):
            raise ValueError("word out of range: %r" % (w,))
    return struct.pack("<%dI" % len(words), *words)


def H(name, words):
    return hashlib.blake2s(tag(name) + le(words)).digest()


def u64(v):
    return [v & MASK32, (v >> 32) & MASK32]


def dw(d):
    assert len(d) == 32
    return list(struct.unpack("<8I", d))


def opt(log):
    return 0 if log is None else log


# ---------------------------------------------------------------- version, class key, structure, VK
def version_identity(rungs=RUNGS):
    return H("version", [1, LOCAL_RELATIONS, GLOBAL_RELATIONS, rungs, MEMORY_BOUNDARY])


def rung_table_id(table):
    """table: {family: [rung vector dict comp->log, ...]} -> digest of every class structure, canonical order."""
    words = [len(table)]
    for fam in sorted(table):
        vecs = table[fam]
        words += [fam, len(vecs)]
        for r, v in enumerate(vecs):
            words += dw(structure_digest(fam, r, v))
    return H("structure", [0xFFFFFFFF] + words)


def structure_digest(family, rung, vector):
    """S^nat summary of one class: the component -> log vector, components sorted by id (absent = 0)."""
    items = sorted(vector.items())
    words = [family, rung, len(items)]
    for comp, log in items:
        words += [comp, opt(log)]
    return H("structure", words)


def class_key(family, rung, profile_identity, image, rung_table):
    return H("class_key", [family, rung] + dw(profile_identity) + dw(image) + dw(rung_table))


def native_vk_hash(family, rung, suite, fixed_identity, fixed_root, profile_identity, structure):
    return H("vk", [family, rung] + dw(suite) + dw(fixed_identity) + dw(fixed_root) + dw(profile_identity) + dw(structure))


def nat_leaf(index, family, rung, vkhash):
    return H("nat_leaf", [index, family, rung] + dw(vkhash))


def nat_empty(index):
    return H("nat_empty", [index])


def node(left, right):
    return H("node", dw(left) + dw(right))


def table_depth(n):
    d = 1
    while (1 << d) < n:
        d += 1
    return d


def table_root(leaves):
    """leaves: list of leaf digests in canonical (family, rung) order. Fixed depth, empty-padded."""
    depth = table_depth(len(leaves))
    level = list(leaves) + [nat_empty(i) for i in range(len(leaves), 1 << depth)]
    for _ in range(depth):
        level = [node(level[2 * i], level[2 * i + 1]) for i in range(len(level) // 2)]
    return level[0], depth


def table_path(leaves, index):
    depth = table_depth(len(leaves))
    level = list(leaves) + [nat_empty(i) for i in range(len(leaves), 1 << depth)]
    path = []
    for _ in range(depth):
        path.append(level[index ^ 1])
        level = [node(level[2 * i], level[2 * i + 1]) for i in range(len(level) // 2)]
        index >>= 1
    return path


def verify_path(root, depth, index, leaf, path):
    if len(path) != depth or index >= (1 << depth):
        return False
    cur = leaf
    for sib in path:
        cur = node(cur, sib) if index & 1 == 0 else node(sib, cur)
        index >>= 1
    return cur == root


def table_header(image, profile_identity, rung_table, depth, count, root):
    return H("table", [1, depth, count] + dw(image) + dw(profile_identity) + dw(rung_table) + dw(root))


# ---------------------------------------------------------------- state, stmt_k, rho, chain, chi
def state_digest(pc, regs, halted=0):
    assert len(regs) == 32
    words = u64(pc)
    for r in regs:
        words += u64(r)
    return H("state", words + [halted])


def stmt_cpu(ordinal, cpu_ordinal, steps_in, steps, ls_count, ls_dword, calls, first_ids, sponge, bulk, mass, relations, legacy):
    """stmt_k of a CPU segment. calls/first_ids: 12 families; sponge (calls, perms, first_id); bulk 8 counts
    (calls, copy_words, set_words, ucopy_rows, cmp_calls, cmp_words, jump_calls, jump_rows); mass (ram, kio, wire)
    u64; relations bitmask ram|kio<<1|wire<<2; legacy = today's worker statement digest (cpuStatementWithAuthority)."""
    assert len(calls) == FAMILIES_TRUTH and len(first_ids) == FAMILIES_TRUTH and len(sponge) == 3 and len(bulk) == 8 and len(mass) == 3
    words = [KIND_CPU, ordinal, cpu_ordinal] + u64(steps_in) + [steps, ls_count, ls_dword] + list(calls) + list(first_ids)
    words += list(sponge) + list(bulk)
    for m in mass:
        words += u64(m)
    words += [relations] + dw(legacy)
    return H("stmt", words)


def stmt_truth(ordinal, family, first_id, calls, logs, mass, relations, legacy):
    words = [KIND_TRUTH, ordinal, family, first_id, calls, logs[0], logs[1]]
    for m in mass:
        words += u64(m)
    words += [relations] + dw(legacy)
    return H("stmt", words)


def stmt_mb(ordinal, chunk, cells, first_addr, last_addr, prev_last_addr, image_commit, initial_digest, terminal_digest, mass_ram):
    words = [KIND_MB, ordinal, chunk, cells] + u64(first_addr) + u64(last_addr) + u64(prev_last_addr)
    words += dw(image_commit) + dw(initial_digest) + dw(terminal_digest) + u64(mass_ram)
    return H("stmt", words)


def rho(main_root, local_digest=None, marginals=()):
    """rho_k: every stage-one commitment of segment k (today's manifest entry: MAIN root, local GKR receipt
    digest and its terminal marginals).  marginals: list of instances, each a list of OM31 values (8 words, each < p)."""
    words = dw(main_root) + [0 if local_digest is None else 1] + (dw(local_digest) if local_digest is not None else [0] * 8)
    words.append(len(marginals))
    for inst in marginals:
        words.append(len(inst))
        for v in inst:
            assert len(v) == 8 and all(c < 0x7FFFFFFF for c in v)
            words += list(v)
    return H("rho", words)


def chain_iv(version=None):
    return H("iv", dw(version or version_identity()))


def chain_step(m, k, family, rung, vkhash, stmt, s_in, s_out, rho_k):
    return H("seg", dw(m) + [k, family, rung] + dw(vkhash) + dw(stmt) + dw(s_in) + dw(s_out) + dw(rho_k))


def chi(statement, m_final):
    return H("chi", dw(statement) + dw(m_final))


# ---------------------------------------------------------------- vectors
def seq(n, start):
    return bytes((start + i) & 0xFF for i in range(n))


def vectors():
    v = {}
    v["tags"] = {k: tag(k).hex() for k in TAGS}
    ver = version_identity()
    v["version_identity"] = ver.hex()
    prof, img, suite = seq(32, 1), seq(32, 33), seq(32, 65)
    table = {CPU_MIDDLE: [{1: 22, 2: 18, 3: None}, {1: 22, 2: 19, 3: 16}, {1: 22, 2: 20, 3: 17}],
             TRUTH_BASE + 0: [{0: 16}, {0: 17}, {0: 18}]}
    rt = rung_table_id(table)
    v["rung_table_id"] = rt.hex()
    st = structure_digest(CPU_MIDDLE, 1, table[CPU_MIDDLE][1])
    v["structure_cpu_middle_r1"] = st.hex()
    v["class_key_cpu_middle_r1"] = class_key(CPU_MIDDLE, 1, prof, img, rt).hex()
    leaves, vks = [], []
    order = [(f, r) for f in sorted(table) for r in range(len(table[f]))]
    for idx, (f, r) in enumerate(order):
        vk = native_vk_hash(f, r, suite, seq(32, 100 + idx), seq(32, 150 + idx), prof, structure_digest(f, r, table[f][r]))
        vks.append(vk)
        leaves.append(nat_leaf(idx, f, r, vk))
    root, depth = table_root(leaves)
    v["tnat"] = {"order": order, "vkhash": [x.hex() for x in vks], "leaves": [x.hex() for x in leaves], "depth": depth, "root": root.hex(),
                 "path_index_4": [x.hex() for x in table_path(leaves, 4)],
                 "header": table_header(img, prof, rt, depth, len(leaves), root).hex()}
    assert verify_path(root, depth, 4, leaves[4], table_path(leaves, 4))
    assert not verify_path(root, depth, 3, leaves[4], table_path(leaves, 4))
    regs0 = [0] + [i * 0x0101010101 for i in range(1, 32)]
    regs1 = [0] + [(i * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF for i in range(1, 32)]
    s0 = state_digest(0x80000000, regs0)
    s1 = state_digest(0x80001234, regs1)
    s2 = state_digest(0x80004000, regs1, 1)
    v["state"] = [s0.hex(), s1.hex(), s2.hex()]
    legacy0, legacy1 = seq(32, 200), seq(32, 7)
    calls = [3, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]
    first = [1] * 12
    st0 = stmt_cpu(0, 1, 0, 4194303, 1000, 77, calls, first, (1, 4, 9), (2, 10, 20, 0, 1, 3, 0, 0), (9000, 75, 12), 7, legacy0)
    st1 = stmt_truth(1, TRUTH_BASE + 0, 1, 3, (16, 0x1b0415), (0, 75, 0), 2, legacy1)
    st2 = stmt_mb(2, 0, 513, 0x1000, 0x9ff8, 0, seq(32, 9), seq(32, 10), seq(32, 11), 1026)
    v["stmt"] = [st0.hex(), st1.hex(), st2.hex()]
    r0 = rho(seq(32, 50), seq(32, 51), [[[1, 2, 3, 4, 5, 6, 7, 8]], [[0x7FFFFFFE] * 8, [0] * 8]])
    r1 = rho(seq(32, 60))
    r2 = rho(seq(32, 70))
    v["rho"] = [r0.hex(), r1.hex(), r2.hex()]
    iv = chain_iv(ver)
    m1 = chain_step(iv, 0, CPU_MIDDLE, 1, vks[1], st0, s0, s1, r0)
    m2 = chain_step(m1, 1, TRUTH_BASE + 0, 0, vks[3], st1, s1, s1, r1)
    m3 = chain_step(m2, 2, MEMORY_BOUNDARY, 0, vks[5], st2, s1, s1, r2)
    v["chain"] = [iv.hex(), m1.hex(), m2.hex(), m3.hex()]
    v["chi"] = chi(seq(32, 240), m3).hex()
    return v


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cmd", choices=["vectors"])
    p.add_argument("--out")
    a = p.parse_args()
    out = {"schema": "rv64-m5-canon-native-vectors/v1", "version": VERSION_NAME, "vectors": vectors()}
    text = json.dumps(out, indent=1, sort_keys=True)
    if a.out:
        open(a.out, "w").write(text + "\n")
    print(text)


if __name__ == "__main__":
    main()

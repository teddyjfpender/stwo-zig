#!/usr/bin/env python3
"""RV64 M5/M7 negative corpus: spec + CPU harness against a fresh receiver.

Spec: design/riscv-proving-stack/rv64-m5-binding.md section 7 (case ids are stable).
Runs ON the pod. Each case copies an accepted proof directory, applies ONE
mutation, and runs a fresh, separate, cache-disabled, GPU-disabled receiver
process exactly as `rv64_m3_pod.py receive` does (same argv shape and env).

  python3 rv64_m5_negative_corpus.py spec                      # print the full spec (incl. pending M5/M7 cases)
  python3 rv64_m5_negative_corpus.py run --run RUN_DIR --donor DONOR_RUN_DIR --out OUT [--jobs 3] [--cases ID,..]

  v4 (M6): --format m6-root (root-only receiver, same expectations as m5-root);
            --alt-format-run ALT   accepted run of the SAME block under another named format/policy (NV03 DW07 RO10:
                                   the whole proof dir is replaced by ALT's, the receiver keeps this run's policy);
            --table-root HEX / --donor-table-root HEX   {table_root} placeholder for --receiver-argv (RO09);
            receiver policy env (STWO_RV64_NATIVE_VERSION, STWO_RV64_OUTER_PROFILE, STWO_RV64_FOLD_ARITY) is inherited
            from the caller's environment. Examples: /workspace/m3/runs/m6-profiles/corpus_{fv3,k3,nv2}.sh on the pod.

RUN_DIR is a harness run directory (plan.json + an accepted receiver-*/ dir)
of a dev block (26235156 or 24628607). DONOR_RUN_DIR is an accepted run of the
OTHER dev block (cross-block substitutions). Pending cases (format does not
exist yet) are listed in the receipt with status "pending" and never run.

Verdict rule: a case PASSES when the receiver's verdict equals the expectation.
  reject                 : a CLEAN rejection: exit code > 0 with no crash marker
                           (signal, panic, unreachable, segfault, timeout) and
                           stdout accepted/completed not both true. A crash is
                           never a pass: a receiver that dies on every mutated
                           input would otherwise pass the whole corpus.
                           Each rejection is classed (reject_class): semantic,
                           resource (size/memory caps) or missing (absent file);
                           non-semantic classes still pass but are listed in
                           the receipt so a reviewer sees what did the work.
  accept                 : exit 0 and accepted and completed_ethereum_block (controls).
  reject_or_same_statement: producer-advisory metadata the receiver re-derives.
                           Accepting is allowed only if the receiver's statement
                           (output, root digest, root authority, manifest) equals
                           the control's; otherwise it must reject.
Standard library only; no GPU; never holds the GPU lock.
"""
import argparse
import concurrent.futures as cf
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from rv64_validation import CRASH_MARKERS, RESOURCE_ERRORS, MISSING_ERRORS, reject_class

SCHEMA = "rv64-m5-negative-corpus/v5"
DEV_BLOCKS = {26235156, 24628607}
HOST_BYTES = 34359738368


def rec(*names):
    return [f"recursion-om31/{n}" for n in names]


def nth_fold(proof, i):
    """i-th fold proof of the tree in file order (binary trees: 0 -> fold-000002, 1 -> fold-000005, as before; k-ary trees
    name folds by their node index, diet-wire M6)."""
    return "recursion-om31/" + sorted(p.name for p in (proof / "recursion-om31").glob("fold-*.proof"))[i]


def flip(path, where):
    data = bytearray(path.read_bytes())
    offset = {"head": min(64, len(data) - 1), "mid": len(data) // 2, "tail": len(data) - 9}[where]
    data[offset] ^= 0x01
    path.write_bytes(bytes(data))
    return offset


def swap(a, b):
    tmp = a.with_suffix(a.suffix + ".swap")
    a.rename(tmp)
    b.rename(a)
    tmp.rename(b)


def json_edit(path, fn):
    value = json.loads(path.read_text())
    fn(value)
    path.write_text(json.dumps(value))


def root_node(tree):
    return max(tree["nodes"], key=lambda n: n.get("leaf_count", 0))


def digest_list(path):
    return list(hashlib.sha256(path.read_bytes()).digest())


def bundle(proof, fn):
    json_edit(proof / "bundle.json", fn)


def coherent_swap(proof, kind, a, b):
    """Swap two segment files AND their bundle entries (declaration, request, claims, proof hash) together."""
    files = {"cpus": "cpu", "truths": "truth"}[kind]
    swap(proof / f"{files}-{a}.bin", proof / f"{files}-{b}.bin")
    bundle(proof, lambda v: v[kind].__setitem__(slice(None), [v[kind][b] if i == a else v[kind][a] if i == b else e for i, e in enumerate(v[kind])]))


def coherent_drop_last_cpu(proof):
    last = None

    def edit(v):
        nonlocal last
        last = len(v["cpus"]) - 1
        v["cpus"].pop()
    bundle(proof, edit)
    (proof / f"cpu-{last}.bin").unlink()


def coherent_dup_cpu(proof, src, dst):
    shutil.copyfile(proof / f"cpu-{src}.bin", proof / f"cpu-{dst}.bin")
    bundle(proof, lambda v: v["cpus"].__setitem__(dst, json.loads(json.dumps(v["cpus"][src]))))


def coherent_terminal_value_flip(proof):
    """Flip the low value byte of the middle TERMINAL RAM cell in cells.bin
    (layout: cells_wire.zig, 16-byte header, n initial then n terminal 23-byte
    cells: address u64, value u64, epoch u16, tick u32, rights u8) and rewrite
    bundle.json cells_sha256. Rights, epoch and tick stay canonical, so only
    the RAM TEARDOWN closure (the global LogUp-GKR ram relation) can reject.
    This is the M3 analogue of the M5 teardown obligation (binding note 9.F2)."""
    path = proof / "cells.bin"
    data = bytearray(path.read_bytes())
    n = int.from_bytes(data[8:12], "little")
    if n == 0 or len(data) != 16 + 2 * n * 23:
        raise ValueError(f"unexpected cells.bin layout n={n} len={len(data)}")
    offset = 16 + n * 23 + (n // 2) * 23 + 8
    data[offset] ^= 0x01
    path.write_bytes(bytes(data))
    h = digest_list(path)
    bundle(proof, lambda v: v.__setitem__("cells_sha256", h))
    return offset


def coherent_flip(proof, name, setter):
    offset = flip(proof / name, "mid")
    h = digest_list(proof / name)
    bundle(proof, lambda v: setter(v, h))
    return offset


OUTER_GKR_MAGIC = (0x524B474F).to_bytes(4, "little")  # OGKR section header, legacy v1 or anchored-Eq v2
OUTER_GKR_VERSIONS = (1, 2)

def gkr_offset(data):
    offsets = [data.find(OUTER_GKR_MAGIC + v.to_bytes(4, "little")) for v in OUTER_GKR_VERSIONS]
    return min((offset for offset in offsets if offset >= 0), default=-1)


def gkr_section(path):
    data = path.read_bytes()
    at = gkr_offset(data)
    if at < 0:
        raise RuntimeError(f"no outer GKR section (magic OGKR v1/v2) in {path.name}: format not wired")
    return bytearray(data), at


def gkr_flip(path, delta=96):
    data, at = gkr_section(path)
    data[at + delta] ^= 0x01
    path.write_bytes(bytes(data))
    return at + delta


def gkr_zero(path, words=64):
    data, at = gkr_section(path)
    end = min(len(data), at + 8 + 4 * words)
    data[at + 8:end] = bytes(end - at - 8)
    path.write_bytes(bytes(data))
    return at


def cross_format(c):
    """Replace the whole proof directory by the ALT proof of the same block under another named format."""
    alt = c.get("alt_proof")
    if not alt:
        raise RuntimeError("needs --alt-format-run")
    shutil.rmtree(c["proof"])
    shutil.copytree(alt, c["proof"])


def no_store(c):
    """RO08: every producer cache / store the receiver could consult is absent."""
    for name in ("artifact-store", "store", "setup-cache", "vk-cache", "fold-class-cache"):
        shutil.rmtree(c["proof"] / name, ignore_errors=True)
    empty = c["proof"].parent / "empty-store"
    empty.mkdir(exist_ok=True)
    for key in ("STWO_RV64_ARTIFACT_STORE", "STWO_RV64_STORE", "STWO_ZIG_RV64_SETUP_CACHE", "STWO_RV64_VK_CACHE"):
        c["env"].pop(key, None)
    c["env"]["STWO_RV64_ARTIFACT_STORE"] = str(empty)
    c["env"]["STWO_RV64_FOLD_CLASS_CACHE"] = "0"


def other_table_root(c):
    if not c.get("donor_table_root"):
        raise RuntimeError("needs --table-root and --donor-table-root")
    c["argv"]["table_root"] = c["donor_table_root"]


def sidecar_edit(proof):
    """Edit every integer named like a statement field in producer JSON sidecars (report/tree/root statement)."""
    names = {"kappa", "leaf_count", "cpu_proofs", "seg_hi", "seg_lo", "depth", "chi", "bus", "mass"}

    def walk(v):
        if isinstance(v, dict):
            for k in list(v):
                if k in names and isinstance(v[k], int):
                    v[k] += 1
                else:
                    walk(v[k])
        elif isinstance(v, list):
            for x in v:
                walk(x)
    edited = 0
    for path in list(proof.rglob("*.json")):
        try:
            value = json.loads(path.read_text())
        except Exception:
            continue
        walk(value)
        path.write_text(json.dumps(value))
        edited += 1
    return edited


# Each case: id, family (spec section 7), expect, today ("m3" runnable now | "m5"/"m7" pending), what, mutate(ctx).
# ctx: proof (Path, mutable copy), donor (Path, read-only), request (dict, mutable), env (dict, mutable), argv (dict, mutable)
CASES = [
    dict(id="C00-control", family="control", expect="accept", today="m3", what="unmodified accepted proof directory",
         mutate=lambda c: None),
    # Segment chain: dropped / duplicated / permuted
    dict(id="S01-drop-native-segment", family="segment-chain", expect="reject", today="m3",
         what="delete the last CPU native segment proof (cpu-3.bin)", mutate=lambda c: (c["proof"] / "cpu-3.bin").unlink()),
    dict(id="S02-drop-leaf", family="segment-chain", expect="reject", today="m3",
         what="delete leaf-000003.proof", mutate=lambda c: (c["proof"] / rec("leaf-000003.proof")[0]).unlink()),
    dict(id="S03-dup-native-segment", family="segment-chain", expect="reject", today="m3",
         what="cpu-2.bin copied over cpu-3.bin (segment 2 claimed twice, segment 3 absent)",
         mutate=lambda c: shutil.copyfile(c["proof"] / "cpu-2.bin", c["proof"] / "cpu-3.bin")),
    dict(id="S04-dup-leaf", family="segment-chain", expect="reject", today="m3",
         what="leaf-000002.proof copied over leaf-000003.proof",
         mutate=lambda c: shutil.copyfile(c["proof"] / rec("leaf-000002.proof")[0], c["proof"] / rec("leaf-000003.proof")[0])),
    dict(id="S05-permute-native-segments", family="segment-chain", expect="reject", today="m3",
         what="swap cpu-1.bin and cpu-2.bin", mutate=lambda c: swap(c["proof"] / "cpu-1.bin", c["proof"] / "cpu-2.bin")),
    dict(id="S06-permute-leaves", family="segment-chain", expect="reject", today="m3",
         what="swap leaf-000000.proof and leaf-000001.proof",
         mutate=lambda c: swap(c["proof"] / rec("leaf-000000.proof")[0], c["proof"] / rec("leaf-000001.proof")[0])),
    dict(id="S07-permute-truth", family="segment-chain", expect="reject", today="m3",
         what="swap truth-0.bin and truth-1.bin (service/truth family order)",
         mutate=lambda c: swap(c["proof"] / "truth-0.bin", c["proof"] / "truth-1.bin")),
    # Coherent variants: the producer also rewrites bundle.json (file hashes, declarations, claims)
    # so the byte-level WideBundleFileChanged check cannot be what rejects.
    dict(id="S08-coherent-permute-native", family="segment-chain", expect="reject", today="m3",
         what="swap cpu-1/cpu-2 files AND their bundle.json entries (order permuted consistently)",
         mutate=lambda c: coherent_swap(c["proof"], "cpus", 1, 2)),
    dict(id="S09-coherent-drop-native", family="segment-chain", expect="reject", today="m3",
         what="drop cpu-3.bin AND its bundle.json entry (kappa 4 -> 3, consistent bundle)",
         mutate=lambda c: coherent_drop_last_cpu(c["proof"])),
    dict(id="S10-coherent-dup-native", family="segment-chain", expect="reject", today="m3",
         what="cpu-3 := cpu-2 in files AND bundle.json (segment 2 duplicated consistently)",
         mutate=lambda c: coherent_dup_cpu(c["proof"], 2, 3)),
    dict(id="S11-coherent-permute-truth", family="segment-chain", expect="reject", today="m3",
         what="swap truth-0/truth-1 files AND bundle.json entries",
         mutate=lambda c: coherent_swap(c["proof"], "truths", 0, 1)),
    # kappa (leaf count) / producer metadata the receiver must re-derive
    dict(id="K01-tree-leaf-count", family="kappa", expect="reject_or_same_statement", today="m3",
         what="tree.json: root node leaf_count - 1 (producer-claimed kappa)",
         mutate=lambda c: json_edit(c["proof"] / "recursion-om31/tree.json", lambda t: root_node(t).__setitem__("leaf_count", root_node(t)["leaf_count"] - 1))),
    dict(id="K02-report-cpu-proofs", family="kappa", expect="reject_or_same_statement", today="m3",
         what="report.json: cpu_proofs - 1 (producer-claimed segment count)",
         mutate=lambda c: json_edit(c["proof"] / "report.json", lambda r: r.__setitem__("cpu_proofs", r["cpu_proofs"] - 1))),
    dict(id="K03-tree-drop-node", family="kappa", expect="reject_or_same_statement", today="m3",
         what="tree.json: remove the first leaf node", mutate=lambda c: json_edit(c["proof"] / "recursion-om31/tree.json", lambda t: t["nodes"].pop(0))),
    # child VK / rung / class
    dict(id="V01-cross-class-fold", family="child-vk", expect="reject", today="m3",
         what="second fold proof copied over the first (binary: fold-000005 over fold-000002; different child classes)",
         mutate=lambda c: shutil.copyfile(c["proof"] / nth_fold(c["proof"], 1), c["proof"] / nth_fold(c["proof"], 0))),
    dict(id="V02-cross-block-fold", family="child-vk", expect="reject", today="m3",
         what="donor block's first fold proof in place of this block's first fold proof (binary: fold-000002)",
         mutate=lambda c: shutil.copyfile(c["donor"] / nth_fold(c["donor"], 0), c["proof"] / nth_fold(c["proof"], 0))),
    dict(id="V03-cross-block-leaf", family="child-vk", expect="reject", today="m3",
         what="donor block leaf-000000.proof (other native VK, same family/position)",
         mutate=lambda c: shutil.copyfile(c["donor"] / rec("leaf-000000.proof")[0], c["proof"] / rec("leaf-000000.proof")[0])),
    dict(id="V04-cross-block-root", family="child-vk", expect="reject", today="m3",
         what="donor block root.proof in place of root.proof",
         mutate=lambda c: shutil.copyfile(c["donor"] / rec("root.proof")[0], c["proof"] / rec("root.proof")[0])),
    dict(id="V05-cross-block-native", family="child-vk", expect="reject", today="m3",
         what="donor block cpu-0.bin in place of cpu-0.bin (wrong native segment, other block)",
         mutate=lambda c: shutil.copyfile(c["donor"] / "cpu-0.bin", c["proof"] / "cpu-0.bin")),
    # Review 2 (codex/rv64-m5-profiles): a cross-block ROOT that passes the size cap. V04's donor root is larger
    # than 24628607's own (748,536 > 706,424 B) and was stopped by FileTooBig, not cryptographically. The
    # shape donor (--root-donor) is an accepted proof of ANOTHER block whose root.proof is no larger than this
    # block's; it is only read, never proven or measured.
    dict(id="V06-coherent-cross-block-root", family="child-vk", expect="reject", today="m3-cap", requires=("root_donor_fits",),
         what="root.proof of a same-size-class accepted proof of another block (passes the size cap)",
         mutate=lambda c: shutil.copyfile(c["root_donor"] / rec("root.proof")[0], c["proof"] / rec("root.proof")[0])),
    dict(id="V07-coherent-cross-block-tree", family="child-vk", expect="reject", today="m3-cap", requires=("root_donor_same_tree",),
         what="the WHOLE recursion-om31 directory (tree.json, every leaf, fold and root) of a same-shape accepted proof of another block",
         mutate=lambda c: (shutil.rmtree(c["proof"] / "recursion-om31"), shutil.copytree(c["root_donor"] / "recursion-om31", c["proof"] / "recursion-om31"))),
    # tampered bytes (native roots, outer proofs)
    dict(id="R01-native-head-flip", family="native-root", expect="reject", today="m3",
         what="flip one bit at byte 64 of cpu-0.bin (commitment/header region)", mutate=lambda c: flip(c["proof"] / "cpu-0.bin", "head")),
    dict(id="R02-native-mid-flip", family="native-root", expect="reject", today="m3",
         what="flip one bit mid cpu-0.bin", mutate=lambda c: flip(c["proof"] / "cpu-0.bin", "mid")),
    dict(id="R03-truth-mid-flip", family="native-root", expect="reject", today="m3",
         what="flip one bit mid truth-0.bin", mutate=lambda c: flip(c["proof"] / "truth-0.bin", "mid")),
    dict(id="R04-root-proof-flip", family="outer-bytes", expect="reject", today="m3",
         what="flip one bit mid root.proof", mutate=lambda c: flip(c["proof"] / rec("root.proof")[0], "mid")),
    dict(id="R05-root-proof-truncate", family="outer-bytes", expect="reject", today="m3",
         what="truncate root.proof by 32 bytes",
         mutate=lambda c: (lambda p: p.write_bytes(p.read_bytes()[:-32]))(c["proof"] / rec("root.proof")[0])),
    dict(id="R06-leaf-proof-flip", family="outer-bytes", expect="reject", today="m3",
         what="flip one bit mid leaf-000004.proof", mutate=lambda c: flip(c["proof"] / rec("leaf-000004.proof")[0], "mid")),
    dict(id="R07-coherent-native-flip", family="native-root", expect="reject", today="m3",
         what="flip one bit mid cpu-0.bin AND rewrite its bundle.json sha256 (proof itself must fail)",
         mutate=lambda c: coherent_flip(c["proof"], "cpu-0.bin", lambda v, h: v["cpus"][0]["proof"].__setitem__("sha256", h))),
    dict(id="R08-coherent-native-head-flip", family="native-root", expect="reject", today="m3",
         what="flip one bit at byte 64 of cpu-0.bin AND rewrite its bundle.json sha256",
         mutate=lambda c: (lambda o: (bundle(c["proof"], lambda v: v["cpus"][0]["proof"].__setitem__("sha256", digest_list(c["proof"] / "cpu-0.bin"))), o)[1])(flip(c["proof"] / "cpu-0.bin", "head"))),
    dict(id="R09-coherent-truth-flip", family="native-root", expect="reject", today="m3",
         what="flip one bit mid truth-0.bin AND rewrite its bundle.json sha256",
         mutate=lambda c: coherent_flip(c["proof"], "truth-0.bin", lambda v, h: v["truths"][0]["proof"].__setitem__("sha256", h))),
    # chi / global stage
    dict(id="X01-stage-one-flip", family="chi", expect="reject", today="m3",
         what="flip one bit mid stage-one.bin (global stage: MAIN roots that chi is drawn from)",
         mutate=lambda c: flip(c["proof"] / "stage-one.bin", "mid")),
    dict(id="X02-cells-flip", family="chi", expect="reject", today="m3",
         what="flip one bit mid cells.bin (global GKR cells)", mutate=lambda c: flip(c["proof"] / "cells.bin", "mid")),
    dict(id="X03-coherent-stage-one-flip", family="chi", expect="reject", today="m3",
         what="flip one bit mid stage-one.bin AND rewrite bundle.json stage_one.sha256",
         mutate=lambda c: coherent_flip(c["proof"], "stage-one.bin", lambda v, h: v["stage_one"].__setitem__("sha256", h))),
    dict(id="X04-coherent-cells-flip", family="chi", expect="reject", today="m3",
         what="flip one bit mid cells.bin AND rewrite bundle.json cells_sha256",
         mutate=lambda c: coherent_flip(c["proof"], "cells.bin", lambda v, h: v.__setitem__("cells_sha256", h))),
    dict(id="X06-coherent-terminal-value", family="chi", expect="reject", today="m3",
         what="cells.bin: flip the value of the middle TERMINAL cell AND rewrite bundle.json cells_sha256 "
              "(canonical rights/epoch/tick; only the RAM teardown closure can reject)",
         mutate=lambda c: coherent_terminal_value_flip(c["proof"])),
    # statement / profile (receiver policy)
    dict(id="T01-wrong-output", family="statement", expect="reject", today="m3",
         what="receiver request expected_output: last byte changed (claimed block output differs)",
         mutate=lambda c: c["request"].__setitem__("expected_output", c["request"]["expected_output"][:-2] + ("00" if c["request"]["expected_output"][-2:] != "00" else "01"))),
    dict(id="P01-wrong-native-profile", family="profile", expect="reject", today="m3",
         what="receiver selects proven_beta2_q256_p0_fold4 for conjectured128 proofs",
         mutate=lambda c: c["argv"].__setitem__("profile", "proven_beta2_q256_p0_fold4")),
    # Outer profile selection (recsize): runnable once the receiver reads STWO_RV64_OUTER_PROFILE (capability
    # detected from the receiver binary); otherwise listed as unsupported, never counted as a pass.
    # today="m3-cap": runnable today but only when `capabilities()` grants every `requires` entry. Harnesses that
    # import CASES and filter on today == "m3" therefore keep their v2 behaviour.
    # STWO_RV64_FOLD_ARITY=2 keeps the receiver's tree plan equal to the proofs' binary tree, so only the outer
    # profile differs and a rejection cannot come from a missing node file (P02d shows that weaker path).
    dict(id="P02-wrong-outer-profile", family="profile", expect="reject", today="m3-cap", requires=("outer_profile_env",),
         what="receiver selects outer m3_b4_q51_p26_fold4 (STWO_RV64_OUTER_PROFILE) with binary folds for r1 binary-fold proofs",
         mutate=lambda c: c["env"].update(STWO_RV64_OUTER_PROFILE="m3_b4_q51_p26_fold4", STWO_RV64_FOLD_ARITY="2")),
    dict(id="P02b-wrong-outer-profile-b8", family="profile", expect="reject", today="m3-cap", requires=("outer_profile_env",),
         what="receiver selects outer m3_b8_q34_p26_fold4 with binary folds for r1 proofs",
         mutate=lambda c: c["env"].update(STWO_RV64_OUTER_PROFILE="m3_b8_q34_p26_fold4", STWO_RV64_FOLD_ARITY="2")),
    dict(id="P02d-wrong-outer-profile-default-arity", family="profile", expect="reject", today="m3-cap", requires=("outer_profile_env",),
         what="receiver selects outer m3 with its default arity 4 (tree plan differs too)",
         mutate=lambda c: c["env"].__setitem__("STWO_RV64_OUTER_PROFILE", "m3_b4_q51_p26_fold4")),
    dict(id="P04-wrong-fold-arity", family="profile", expect="reject", today="m3-cap", requires=("outer_profile_env",),
         what="receiver keeps r1 but plans 4-ary folds (STWO_RV64_FOLD_ARITY=4) for binary-fold proofs",
         mutate=lambda c: c["env"].update(STWO_RV64_OUTER_PROFILE="r1_b2_q108_p20_fold4", STWO_RV64_FOLD_ARITY="4")),
    dict(id="P03-unknown-outer-profile", family="profile", expect="reject", today="m3-cap", requires=("outer_profile_env",),
         what="receiver given an unknown outer profile name: must refuse CLEANLY (an error exit, not a panic)",
         mutate=lambda c: c["env"].__setitem__("STWO_RV64_OUTER_PROFILE", "m9_b2_q1_p0_fold4")),
    dict(id="C01-control-explicit-r1", family="control", expect="accept", today="m3-cap", requires=("outer_profile_env",),
         what="unmodified proof, receiver selects the proof's outer profile explicitly (r1 unless the caller's "
              "STWO_RV64_OUTER_PROFILE names another, e.g. an M5 canonical profile; M5 integrate)",
         mutate=lambda c: c["env"].__setitem__("STWO_RV64_OUTER_PROFILE",
                                               os.environ.get("STWO_RV64_OUTER_PROFILE") or "r1_b2_q108_p20_fold4")),
    # Pending: formats that do not exist until M5 / M7 (spec only; never run).
    dict(id="N01-forged-null-slot", family="null-slot", expect="reject", today="m5",
         what="k-ary fold: real child slot re-tagged null (child dropped while kappa kept)"),
    dict(id="N02-null-with-payload", family="null-slot", expect="reject", today="m5",
         what="null-tagged slot carrying a non-zero child digest"),
    dict(id="N03-null-not-trailing", family="null-slot", expect="reject", today="m5",
         what="null slot followed by a real slot (canonical null placement violated)"),
    dict(id="K04-root-kappa", family="kappa", expect="reject", today="m5",
         what="root statement kappa != receiver-derived segment count"),
    dict(id="G01-wrong-rung", family="child-vk", expect="reject", today="m5",
         what="leaf proof of rung r' presented at a chain position whose native segment has rung r"),
    dict(id="G02-vkfold-mismatch", family="child-vk", expect="reject", today="m5",
         what="root vk_fold public input != receiver-derived constant"),
    dict(id="G03-child-vk-not-in-table", family="child-vk", expect="reject", today="m5",
         what="fold child VK neither in the leaf VK table nor equal to vk_fold"),
    dict(id="G04-native-vk-not-in-table", family="child-vk", expect="reject", today="m5",
         what="leaf guesses a native VK with a valid-looking but non-member Merkle path"),
    dict(id="B01-bus-balance", family="bus", expect="reject", today="m5",
         what="root bus-balance sum != 0 (one segment's claimed sum shifted, chain re-hashed)"),
    dict(id="X05-chi-root-mismatch", family="chi", expect="reject", today="m5",
         what="root statement chi != H(statement || MAIN roots sorted by segment index)"),
    # Added by the 2026-11-04 adversarial review (rv64-m5-binding.md section 9). Pending formats.
    dict(id="Z01-truth-leaf-state-jump", family="segment-chain", expect="reject", today="m5",
         what="non-CPU (truth/service) leaf outputs s_out != s_in (machine state jumped by a segment without CPU rows)"),
    dict(id="Z02-free-segment-request", family="statement", expect="reject", today="m5",
         what="stmt_k (per-segment request: calls, first ids, steps, ls_count, first_step) altered, chain re-hashed"),
    dict(id="Z03-family-counter-gap", family="segment-chain", expect="reject", today="m5",
         what="per-family call/truth-id counters: a truth shard skips or repeats an id range (truth span), chain re-hashed"),
    dict(id="Z04-mass-wrap", family="bus", expect="reject", today="m5",
         what="an accumulated LogUp mass (ram/kio/wire/range/AND) >= p, or two child masses whose field sum wraps below p"),
    dict(id="Z05-segment-index-wrap", family="segment-chain", expect="reject", today="m5",
         what="leaf k >= MAX_PROOFS or k = p-1 so that seg_hi + 1 wraps to 0 in M31"),
    dict(id="Z06-depth-exceeded", family="segment-chain", expect="reject", today="m5",
         what="degenerate (comb-shaped) tree with fold depth > D_MAX"),
    dict(id="Z07-noncanonical-word", family="chi", expect="reject", today="m5",
         what="chi or bus coordinate presented as w + p (u32 alias of the same M31 value)"),
    dict(id="Z08-merkle-node-as-leaf", family="child-vk", expect="reject", today="m5",
         what="T_nat/T_rec membership with an internal node presented as a leaf (shorter path / missing leaf-node domain tags)"),
    dict(id="Z09-cross-relation-cancel", family="bus", expect="reject", today="m5",
         what="ram imbalance d and wire imbalance -d: single summed bus balances, per-relation closure must not"),
    dict(id="Z10-forged-teardown", family="bus", expect="reject", today="m5",
         what="terminal memory (teardown) chosen by the producer to balance a forged RAM trace / output (receiver lacks cells)"),
    dict(id="Z11-absent-relation-claim", family="bus", expect="reject", today="m5",
         what="segment of an (f,r) without relation R carries a non-zero R claim"),
    dict(id="Z12-boundary-not-in-air", family="segment-chain", expect="reject", today="m5",
         what="leaf s_in/s_out mixed into the transcript but differing from the native trace's first/last state"),
    dict(id="M01-gkr-sumcheck-tamper", family="outer-gkr", expect="reject", today="m7",
         what="outer LogUp-GKR: one sumcheck round polynomial coefficient changed"),
    dict(id="M02-gkr-claim-tamper", family="outer-gkr", expect="reject", today="m7",
         what="outer LogUp-GKR: final layer claim inconsistent with the committed columns"),
    dict(id="M03-compress-profile", family="compress", expect="reject", today="m7",
         what="C2 proof verified under C1 profile (or fold-step 3 vs 4)"),
    dict(id="M04-compress-inner-root", family="compress", expect="reject", today="m7",
         what="C1/C2 proof wrapping a different root statement digest"),
    # ---- Review 2 / M5 stream formats (rv64-m5-binding.md section 10). Pending; tiers and owners in CASE_META.
    # Canonical leaf R_leaf[f,r]
    dict(id="L01-transcript-seed-mismatch", family="canonical-leaf", expect="reject", today="m5",
         what="leaf: V^nat word used by membership differs from the word mixed into the in-circuit native transcript"),
    dict(id="L02-understated-mass", family="canonical-leaf", expect="reject", today="m5",
         what="leaf: NS.mass[R] below mass_authority(f, r, stmt_k)[R] for one relation"),
    dict(id="L03-local-gkr-not-chained", family="canonical-leaf", expect="reject", today="m5",
         what="chain step: local GKR receipt digest / terminal marginals changed, m_out unchanged (F13)"),
    dict(id="L04-relation-mask", family="canonical-leaf", expect="reject", today="m5",
         what="leaf: relation mask not the (f, r) constant (keccak shard claims ram, cpu shard drops ram)"),
    dict(id="L05-index-one-sided", family="canonical-leaf", expect="reject", today="m5",
         what="leaf k = p - 1: passes a one-sided MAX_PROOFS - 1 - k < 2^16 check (two-sided range required)"),
    # Memory-boundary family mb (binding section 5.1)
    dict(id="MB01-unsorted-chunk", family="memory-boundary", expect="reject", today="m5",
         what="mb leaf: chunk address not above the previous chunk's last address (overlap or repeat)"),
    dict(id="MB02-initial-not-image", family="memory-boundary", expect="reject", today="m5",
         what="mb leaf: initial value or rights of a touched word differ from the image commitment (incl. zero default)"),
    dict(id="MB03-terminal-epoch", family="memory-boundary", expect="reject", today="m5",
         what="mb leaf: terminal epoch above the CPU ordinal counter"),
    dict(id="MB04-output-word", family="memory-boundary", expect="reject", today="m5",
         what="halt flag / output_len / output words: missing, duplicated across chunks, or not from terminal cells (F14)"),
    dict(id="MB05-touched-count", family="memory-boundary", expect="reject", today="m5",
         what="mb: initial count != terminal count, or init/teardown mass omitted from mass[ram]"),
    # k-ary fold
    dict(id="G06-compress-vk-as-child", family="child-vk", expect="reject", today="m5",
         what="fold child admitted by a T_rec entry of kind compress1/compress2 (fold must constrain child kind in {leaf, fold})"),
    dict(id="KF01-child-order", family="kary-fold", expect="reject", today="m5",
         what="fold: two children swapped (adjacency seg/m/s/ctr/steps must fail)"),
    dict(id="KF02-agreement", family="kary-fold", expect="reject", today="m5",
         what="fold: one child with different T_nat/T_rec/img/stmt/chi/E than the fold's outputs"),
    dict(id="KF03-counter-in-field", family="kary-fold", expect="reject", today="m5",
         what="fold: ctr/steps/kappa summed in M31 (child values p-1 and 2 give 1)"),
    # Root-only receiver (format m5-root). Process tier: mutations of the M5 proof directory or receiver policy.
    dict(id="RR01-root-flip-fast", family="root-only", expect="reject", today="m5", formats=("m5-root",),
         what="root proof bit flip: rejected by the root-only receiver FIRST (wall recorded; gate <= 1.5 s)",
         mutate=lambda c: flip(c["proof"] / c["root_path"], "mid")),
    dict(id="RR02-root-truncate-extend", family="root-only", expect="reject", today="m5", formats=("m5-root",),
         what="root proof with 32 zero bytes appended (truncation is R05)",
         mutate=lambda c: (lambda p: p.write_bytes(p.read_bytes() + bytes(32)))(c["proof"] / c["root_path"])),
    dict(id="RR03-store-supplied-vk", family="root-only", expect="reject_or_same_statement", today="m5", formats=("m5-root",),
         what="a VK / vk-table file planted in the proof directory: never read (same statement) or refused",
         mutate=lambda c: [(c["proof"] / n).write_bytes(bytes(range(256)) * 4) for n in ("vk-tables.bin", "T_rec.bin", "T_nat.bin", "recursion-om31/vk-tables.bin")]),
    dict(id="RR04-tampered-vk-cache", family="root-only", expect="reject", today="m5",
         what="receiver-local derive-vk-tables cache edited (one T_rec leaf): refused, or re-derived and rejected"),
    dict(id="RR05-sidecar-ns", family="root-only", expect="reject_or_same_statement", today="m5", formats=("m5-root",),
         what="producer sidecar NS/statement JSON edited (kappa, chi, bus): the receiver reads NS from the proof only",
         mutate=lambda c: sidecar_edit(c["proof"])),
    dict(id="RR06-unknown-profile-id", family="root-only", expect="reject", today="m5",
         what="unknown profile id in the root header or receiver policy: clean refusal, no panic"),
    dict(id="RR07-audit-disagrees", family="root-only", expect="reject", today="m5",
         what="--audit on every reject case of this corpus also rejects; on C00 it agrees with root-only"),
    # Outer LogUp-GKR (outer-gkr stream) beyond M01/M02
    dict(id="M05-gkr-instance-order", family="outer-gkr", expect="reject", today="m7",
         what="outer GKR: two instances permuted in the mixed instance list"),
    dict(id="M06-gkr-instance-tag", family="outer-gkr", expect="reject", today="m7",
         what="outer GKR: an instance's (relation, component) tag relabelled"),
    dict(id="M07-gkr-late-mix", family="outer-gkr", expect="reject", today="m7",
         what="outer GKR: claims mixed after the challenge that consumes them (transcript order)"),
    dict(id="M08-gkr-round-count", family="outer-gkr", expect="reject", today="m7",
         what="outer GKR: one round polynomial dropped (shorter sumcheck than the class constant)"),
    dict(id="M09-gkr-qm31-challenge", family="outer-gkr", expect="reject", today="m7",
         what="outer GKR challenge drawn in QM31 (4 coords) instead of OM31 (8): arithmetic gate must refuse"),
    dict(id="M10-gkr-mass", family="outer-gkr", expect="reject", today="m7",
         what="outer relation multiplicity mass >= p for the real circuit facts"),
    # Fused Blake2s gadget (blake-gadget stream)
    dict(id="BG01-reference-vectors", family="blake-gadget", expect="accept", today="m7",
         what="completeness: gadget digest == reference Blake2s-256 (RFC 7693 vectors, 0/1/63/64/65/128-byte and random messages, keyed=0)"),
    dict(id="BG02-g-output", family="blake-gadget", expect="reject", today="m7",
         what="one G-function output word altered in the witness"),
    dict(id="BG03-xor-multiplicity", family="blake-gadget", expect="reject", today="m7",
         what="XOR lookup multiplicity shifted between two table rows"),
    dict(id="BG04-schedule", family="blake-gadget", expect="reject", today="m7",
         what="message schedule sigma or a rotation amount changed for one round row"),
    dict(id="BG05-limb-range", family="blake-gadget", expect="reject", today="m7",
         what="u32 word as non-canonical limbs (16-bit limb >= 2^16, or w + 2^32 split)"),
    dict(id="BG06-padding-rows", family="blake-gadget", expect="reject", today="m7",
         what="padding row with non-zero lookup multiplicity or non-zero output"),
    dict(id="BG07-final-flag-counter", family="blake-gadget", expect="reject", today="m7",
         what="finalization flag f0 or byte counter t of a compression changed"),
    dict(id="BG08-xor-mass", family="blake-gadget", expect="reject", today="m7",
         what="XOR/range table mass >= p at the gadget's max compressions per proof"),
    # ---- Corpus v4 (M6, M6-INTERFACES.md profiles P2). Owners in CASE_META. ----
    # native-format: native v2 (strict roster chi chain; optional native GKR)
    dict(id="NV01-vkhash-not-tnat-leaf", family="native-v2", expect="reject", today="m6",
         what="chain step vkhash differs from the vkhash in the T_nat leaf of (f,r) (canon-native review A1 regression)"),
    dict(id="NV02-declaration-not-rung", family="native-v2", expect="reject", today="m6",
         what="segment declaration vector != the rung vector of its (f,r): strict roster refuses (no per-segment shape)"),
    dict(id="NV03-cross-native-version", family="native-v2", expect="reject", today="m6", requires=("alt_format_proof",),
         what="proof of the other native version (v1 <-> v2) of the same block under this receiver's policy",
         mutate=cross_format),
    dict(id="NV04-lambda-not-chained", family="native-v2", expect="reject", today="m6",
         what="v2 chain: local GKR receipt digest / terminal marginals changed, m_out unchanged (L03 under v2)"),
    dict(id="NV05-stale-relation-count", family="native-v2", expect="reject", today="m6",
         what="native identity hashed with LOCAL_RELATIONS = 9 presented to a v2 receiver (v2 hashes 10)"),
    dict(id="NV06-native-gkr-tamper", family="native-v2", expect="reject", today="m6",
         what="native LogUp-GKR (if shipped): one layer claim or round coefficient changed"),
    dict(id="NV07-rung-padding-mult", family="native-v2", expect="reject", today="m6",
         what="rung padding row with a non-zero lookup multiplicity or non-zero yield"),
    dict(id="NV08-fixed-other-rung", family="native-v2", expect="reject", today="m6",
         what="native FIXED root / preprocessed root of another rung of the same family used for a segment"),
    # diet-wire: outer GKR + one fused Blake2s instance + set-v2 + k-ary (+ q51)
    dict(id="DW01-gkr-section-flip", family="diet-outer", expect="reject", today="m6", requires=("gkr_section",),
         what="root proof: one byte inside the outer GKR section (after the OGKR v1 header) flipped",
         mutate=lambda c: gkr_flip(c["proof"] / c["root_path"])),
    dict(id="DW02-gkr-section-zeroed", family="diet-outer", expect="reject", today="m6", requires=("gkr_section",),
         what="root proof: 64 words of the outer GKR section after the header zeroed (dropped rounds, same length)",
         mutate=lambda c: gkr_zero(c["proof"] / c["root_path"])),
    dict(id="DW03-double-count", family="diet-outer", expect="reject", today="m6",
         what="gkrBound component keeps a classic LogUp column AND is counted in the GKR closure (double count / omission)"),
    dict(id="DW04-binding-prefix", family="diet-outer", expect="reject", today="m6",
         what="binding column Pre final != sum_g rho_g (claim_n,g + gamma claim_d,g)"),
    dict(id="DW05-fused-instance-count", family="diet-outer", expect="reject", today="m6",
         what="fused Blake2s: instance count != 1 per node, or instance log size != the class constant"),
    dict(id="DW06-tape-order", family="diet-outer", expect="reject", today="m6",
         what="fused Blake2s hint tape not in builder creation order (rows permuted, multiplicities kept)"),
    dict(id="DW07-cross-outer-format", family="diet-outer", expect="reject", today="m6", requires=("alt_format_proof",),
         what="canonical/old-format proof of the same block under the diet receiver policy (or vice versa)",
         mutate=cross_format),
    dict(id="DW08-arity-relabel", family="diet-outer", expect="reject", today="m6",
         what="k-ary fold under set-v2: arity-3 fold presented at an arity-4 T_rec entry (G05 on diet)"),
    dict(id="DW10-eq-column-forged", family="diet-outer", expect="reject", today="m6",
         what="binding E(x) changed on one row and Pre recomputed so the boundary holds: the eq constraint (endpoints + "
              "carry recurrence) must fail, not the boundary (review DW-R1: E was unconstrained)"),
    dict(id="DW11-prefix-not-cyclic", family="diet-outer", expect="reject", today="m6",
         what="Pre with Pre[0] = 0 and the target carried by the wrap row (non-cyclic edge): the cyclic target_per_row form must fail"),
    dict(id="DW12-cap-slot-guessed", family="diet-outer", expect="reject", today="m6",
         what="k4-cap3 fold: a child path ends at a cap node chosen by a guessed index, not the query position's top 3 bits"),
    dict(id="DW13-cap-not-root", family="diet-outer", expect="reject", today="m6",
         what="k4-cap3 fold: the 8 guessed cap nodes are not hashed (same node hasher/tags) to the root that seeds the child transcript"),
    dict(id="DW09-q51-under-q108", family="diet-outer", expect="reject", today="m6",
         what="diet m3 (q51) proof verified under the diet r1 (q108) receiver policy, and vice versa"),
    # fold-v3: in-circuit T_rec membership, NS interval chain, PCD self-VK
    dict(id="F301-child-vk-not-in-trec", family="fold-v3", expect="reject", today="m6",
         what="fold v3 child VK not a T_rec leaf (membership path for a VK outside the table)"),
    dict(id="F302-trec-other-class", family="fold-v3", expect="reject", today="m6",
         what="child VK proven by the T_rec path/index of another class (kind/family/rung/arity relabel)"),
    dict(id="F303-interval-gap", family="fold-v3", expect="reject", today="m6",
         what="NS interval: child i+1 seg_lo != child i seg_hi + 1"),
    dict(id="F304-seg-wrap", family="fold-v3", expect="reject", today="m6",
         what="seg_lo/seg_hi range check missing so seg_hi + 1 wraps in M31 (Z05/L05 on v3)"),
    dict(id="F305-compress-child", family="fold-v3", expect="reject", today="m6",
         what="fold v3 admits a child of T_rec kind compress1/compress2 (G06 on v3)"),
    dict(id="F306-self-vk-hashed", family="fold-v3", expect="reject", today="m6",
         what="design check: no v3 circuit hashes its own VK; T_rec is a public input (PCD self-VK)"),
    dict(id="F307-chain-break", family="fold-v3", expect="reject", today="m6",
         what="m_in/m_out chain broken across two children (m_in of child i+1 != m_out of child i)"),
    dict(id="F308-depth", family="fold-v3", expect="reject", today="m6",
         what="fold depth above D_MAX (Z06 on v3)"),
    # standalone root-only receiver (M6). RO01-RO07 = RR01-RR07 re-run with this receiver (`run --format m6-root`).
    dict(id="RO08-no-store", family="root-only", expect="accept", today="m6", formats=("m5-root", "m6-root"),
         what="control with every producer store/cache absent and an empty ArtifactStore env: must still accept",
         mutate=no_store),
    dict(id="RO09-other-block-trec", family="root-only", expect="reject_or_same_statement", today="m6", formats=("m5-root", "m6-root"),
         requires=("donor_table_root",),
         what="receiver given the table pin derived for the OTHER dev block: per-block tables (M5) must refuse; a block-"
              "independent image table (native v2 strict roster) may accept, but only with the control's statement",
         mutate=other_table_root),
    dict(id="RO10-v3-without-audit", family="root-only", expect="reject", today="m6", requires=("alt_format_proof",),
         formats=("m6-root",),
         what="old-format (pre fold-v3) root accepted root-only only with --audit: under fold-v3 policy it is refused",
         mutate=cross_format),
    # compress (M7 prep; pending until C1/C2 exist)
    dict(id="CP01-multiproof-noncanonical", family="compress", expect="reject", today="m7",
         what="multiproof with an extra, reordered or duplicated sibling (wire must be exactly the canonical set)"),
    dict(id="CP02-cap-node", family="compress", expect="reject", today="m7",
         what="one Merkle cap node substituted (cap mixed into the transcript; path checked to the cap)"),
    dict(id="CP03-last-layer-degree", family="compress", expect="reject", today="m7",
         what="pruned last FRI layer with a coefficient at or above 2^log_last_layer"),
    dict(id="CP04-fold-step", family="compress", expect="reject", today="m7",
         what="C2 proven at fold_step 3 verified at fold_step 4 (M03 variant)"),
    # ---- Corpus v5 (M7-INTERFACES PR2). Missing mutators stay explicitly pending. ----
    dict(id="OG01-succinct-aux-differential", family="outer-gkr-v2", expect="reject", today="m7", what="succinct first/second/carry at a random OM31 circle point differ from public_aux interpolation or the circuit lane"),
    dict(id="OG02-degenerate-row-coordinate", family="outer-gkr-v2", expect="reject", today="m7", what="GKR row coordinate zero or one admitted by native or circuit verifier"),
    dict(id="OG03-same-class-section-splice", family="outer-gkr-v2", expect="reject", today="m7", what="outer GKR section from another node of the same class spliced into a production proof"),
    dict(id="OG04-instance-tag-relabel", family="outer-gkr-v2", expect="reject", today="m7", what="instance relation/component tag relabelled while keeping its claims"),
    dict(id="OG05-relation-mass", family="outer-gkr-v2", expect="reject", today="m7", what="per-relation source-bound mass at least p admitted"),
    dict(id="OG06-cross-outer-gkr-format", family="outer-gkr-v2", expect="reject", today="m7", requires=("alt_format_proof",), what="GKR v2 and M6 no-GKR proof policies crossed in either direction", mutate=cross_format),
    dict(id="OG07-legacy-binding-version", family="outer-gkr-v2", expect="reject", today="m7", what="unbound-Eq v1 section accepted by the anchored-Eq v2 receiver, including a rewritten version word"),
    dict(id="NG01-native-section-flip", family="native-gkr-v2", expect="reject", today="m7", what="one byte of the native GKR section flipped in a production v2-gkr proof"),
    dict(id="NG02-producer-claimed-mass", family="native-gkr-v2", expect="reject", today="m7", what="mass gate trusts producer-claimed mass instead of independently source-bound mass"),
    dict(id="NG03-rung-row-mismatch", family="native-gkr-v2", expect="reject", today="m7", what="segment rows differ from its strict rung, including cpu_single and terminal"),
    dict(id="NG04-cross-native-gkr-format", family="native-gkr-v2", expect="reject", today="m7", requires=("alt_format_proof",), what="v2-gkr and strict/default native proof policies crossed in either direction", mutate=cross_format),
    dict(id="NG05-other-roster", family="native-gkr-v2", expect="reject", today="m7", what="native GKR rung roster identity replaced by another roster"),
    dict(id="F309-v3-cap-slot", family="fold-v3", expect="reject", today="m7", what="v3 k4-cap3 path uses a guessed cap slot rather than query position"),
    dict(id="F310-null-chain-slot", family="fold-v3", expect="reject", today="m7", what="null child counted as a segment in the node-summary chain"),
    dict(id="F311-v3-root-no-audit", family="fold-v3", expect="accept", today="m7", what="v3 root accepted by fresh root-only receiver with stores deleted and without --audit"),
    dict(id="F312-cross-v3-compat", family="fold-v3", expect="reject", today="m7", requires=("alt_format_proof",), what="v3 and M6 compat proof policies crossed in either direction", mutate=cross_format),
    dict(id="CP05-compress-vk-in-trec", family="compress", expect="reject", today="m7", what="fold admits a C1 proof as a child or a C1 VK as a T_rec member"),
    dict(id="CP06-summary-passthrough", family="compress", expect="reject", today="m7", what="C1 output node summary differs from the child in any field"),
    dict(id="CP07-nonroot-child", family="compress", expect="reject", today="m7", what="C1 child has a consistent summary but does not cover every native segment"),
    dict(id="CP08-cross-compress-stage", family="compress", expect="reject", today="m7", what="C2 proof verified under C1 parameters"),
    dict(id="CP09-uncompressed-as-c2", family="compress", expect="reject", today="m7", what="uncompressed root bytes presented as the C2 artifact"),
    dict(id="CP10-compress-other-block", family="compress", expect="reject", today="m7", what="C2 proof of the other dev block under this block's statement"),
]

# Tier: R = fresh receiver process on a mutated proof directory / receiver policy (this harness runs it);
#       U = unit test of a receiver/root statement check on a mutated public statement (no proof);
#       W = circuit witness mutation: the named constraint must fail (constraint checker / mock prover).
# Owner: the M5 stream that writes the hook. A U/W hook is a zig test whose name starts with
# "corpus <ID>" (e.g. test "corpus Z01 truth leaf asserts s_out == s_in"); `coverage --src DIR` finds them.
CASE_META = {
    "P02": ("R", "rootverify"), "P02b": ("R", "rootverify"), "P02d": ("R", "rootverify"), "P04": ("R", "rootverify"), "P03": ("R", "rootverify"), "C01": ("R", "rootverify"),
    "N01": ("W", "canon-vk"), "N02": ("W", "canon-vk"), "N03": ("W", "canon-vk"),
    "K04": ("U", "rootverify"), "G01": ("W", "canon-vk"), "G02": ("U", "rootverify"), "G03": ("W", "canon-vk"),
    "G04": ("W", "canon-vk"), "G05": ("W", "canon-vk"), "G06": ("W", "canon-vk"), "B01": ("U", "rootverify"), "X05": ("U", "rootverify"),
    "Z01": ("W", "canon-vk"), "Z02": ("W", "canon-vk"), "Z03": ("W", "canon-vk"), "Z04": ("W", "canon-vk"),
    "Z05": ("W", "canon-vk"), "Z06": ("W", "canon-vk"), "Z07": ("U", "rootverify"), "Z08": ("W", "canon-vk"),
    "Z09": ("U", "rootverify"), "Z10": ("W", "canon-native"), "Z11": ("W", "canon-vk"), "Z12": ("W", "canon-native"),
    "M01": ("W", "outer-gkr"), "M02": ("W", "outer-gkr"), "M03": ("R", "compress"), "M04": ("W", "compress"),
    "L01": ("W", "canon-vk"), "L02": ("W", "canon-vk"), "L03": ("U", "canon-native"), "L04": ("W", "canon-vk"),
    "L05": ("W", "canon-vk"), "MB01": ("W", "canon-native"), "MB02": ("W", "canon-native"), "MB03": ("W", "canon-native"),
    "MB04": ("W", "canon-native"), "MB05": ("W", "canon-native"), "KF01": ("W", "canon-vk"), "KF02": ("W", "canon-vk"),
    "KF03": ("W", "canon-vk"), "RR01": ("R", "rootverify"), "RR02": ("R", "rootverify"), "RR03": ("R", "rootverify"),
    "RR04": ("R", "rootverify"), "RR05": ("R", "rootverify"), "RR06": ("R", "rootverify"), "RR07": ("R", "rootverify"),
    "M05": ("W", "outer-gkr"), "M06": ("W", "outer-gkr"), "M07": ("W", "outer-gkr"), "M08": ("W", "outer-gkr"),
    "M09": ("U", "profiles"), "M10": ("U", "outer-gkr"), "BG01": ("W", "blake-gadget"), "BG02": ("W", "blake-gadget"),
    "BG03": ("W", "blake-gadget"), "BG04": ("W", "blake-gadget"), "BG05": ("W", "blake-gadget"),
    "BG06": ("W", "blake-gadget"), "BG07": ("W", "blake-gadget"), "BG08": ("U", "blake-gadget"),
    # corpus v5 (M7)
    "OG01": ("U", "outer-gkr"), "OG02": ("U", "outer-gkr"), "OG03": ("R", "outer-gkr"), "OG04": ("W", "outer-gkr"),
    "OG05": ("U", "outer-gkr"), "OG06": ("R", "outer-gkr"), "OG07": ("U", "outer-gkr"),
    "NG01": ("R", "native-gkr"), "NG02": ("U", "native-gkr"), "NG03": ("W", "native-gkr"), "NG04": ("R", "native-gkr"), "NG05": ("U", "native-gkr"),
    "F309": ("W", "fold-circuit"), "F310": ("W", "fold-circuit"), "F311": ("R", "fold-circuit"), "F312": ("R", "fold-circuit"),
    "CP05": ("W", "compress"), "CP06": ("W", "compress"), "CP07": ("W", "compress"), "CP08": ("R", "compress"), "CP09": ("R", "compress"), "CP10": ("R", "compress"),
    # corpus v4 (M6)
    "NV01": ("U", "native-format"), "NV02": ("U", "native-format"), "NV03": ("R", "native-format"), "NV04": ("U", "native-format"),
    "NV05": ("U", "native-format"), "NV06": ("W", "native-format"), "NV07": ("W", "native-format"), "NV08": ("W", "native-format"),
    "DW01": ("R", "diet-wire"), "DW02": ("R", "diet-wire"), "DW03": ("W", "diet-wire"), "DW04": ("W", "diet-wire"),
    "DW05": ("W", "diet-wire"), "DW06": ("W", "diet-wire"), "DW07": ("R", "diet-wire"), "DW08": ("W", "diet-wire"),
    "DW09": ("R", "diet-wire"), "DW10": ("W", "outer-gkr"), "DW11": ("W", "outer-gkr"),
    "DW12": ("W", "diet-wire"), "DW13": ("W", "diet-wire"),
    "F301": ("W", "fold-v3"), "F302": ("W", "fold-v3"), "F303": ("W", "fold-v3"), "F304": ("W", "fold-v3"),
    "F305": ("W", "fold-v3"), "F306": ("U", "fold-v3"), "F307": ("W", "fold-v3"), "F308": ("W", "fold-v3"),
    "RO08": ("R", "fold-v3"), "RO09": ("R", "fold-v3"), "RO10": ("R", "fold-v3"),
    "CP01": ("R", "compress"), "CP02": ("R", "compress"), "CP03": ("R", "compress"), "CP04": ("R", "compress"),
}

# Under the M5 root-only receiver (format "m5-root") the receiver reads ONLY the root proof and its policy.
# A mutation of a file it never reads cannot change the statement, so those cases must be rejected or
# accepted with the control's statement; their protection moved into the circuits (W-tier cases above).
# `--format m5-audit` keeps today's expectations (the full-tree re-verify must still reject them).
ROOT_ONLY_UNREAD = {"S01", "S02", "S03", "S04", "S05", "S06", "S07", "S08", "S09", "S10", "S11", "V01", "V02", "V03", "V05",
                    "R01", "R02", "R03", "R06", "R07", "R08", "R09", "X01", "X02", "X03", "X04", "X06"}


def case_key(case_id):
    return case_id.split("-", 1)[0]


def tier_owner(case):
    if case["today"] in ("m3", "m3-cap") and case_key(case["id"]) not in CASE_META:
        return "R", "profiles"
    return CASE_META[case_key(case["id"])]


ROOT_FORMATS = ("m5-root", "m6-root")


def expectation(case, fmt):
    if fmt in ROOT_FORMATS and case["expect"] == "reject" and case_key(case["id"]) in ROOT_ONLY_UNREAD:
        return "reject_or_same_statement"
    return case["expect"]


def spec():
    out = []
    for case in CASES:
        tier, owner = tier_owner(case)
        row = {k: v for k, v in case.items() if k != "mutate"} | {"tier": tier, "owner": owner}
        if expectation(case, "m5-root") != case["expect"]:
            row["expect_m5_root"] = expectation(case, "m5-root")
        out.append(row)
    return out


def coverage(src):
    """U/W hooks: zig tests named 'corpus <ID> ...' anywhere under src. Returns {case_id: [file:line, ...]}."""
    import re
    found = {}
    pattern = re.compile(r'test\s+"corpus\s+([A-Z]+[0-9]+[a-z]?)\b')
    for path in Path(src).rglob("*.zig"):
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            m = pattern.search(line)
            if m:
                found.setdefault(m.group(1), []).append(f"{path.relative_to(src)}:{number}")
    rows = []
    for case in CASES:
        tier, owner = tier_owner(case)
        if tier == "R":
            continue
        rows.append({"id": case["id"], "tier": tier, "owner": owner, "today": case["today"],
                     "hooks": found.get(case_key(case["id"]), [])})
    return rows


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def proof_dir(run):
    plan = json.loads((run / "plan.json").read_text())
    job = plan["jobs"][0]
    # Resident services publish proof paths in their receipt, not case/batch.
    receipt_path = run / "receipt.json"
    if receipt_path.is_file():
        requests = json.loads(receipt_path.read_text()).get("requests", [])
        matches = [r for r in requests if r.get("block") == job["block"] and r.get("trial") == 0]
        if len(matches) == 1:
            proof = Path(matches[0]["proof"])
            if not (proof / "bundle.json").is_file():
                raise SystemExit(f"resident proof directory is missing: {proof}")
            return plan, job, proof
    hits = sorted((Path(job["target"]) / "batch").glob(f"trial-0/{job['block']}/proof"))
    if not hits:
        raise SystemExit(f"no proof dir under {run}")
    return plan, job, hits[0]


def accepted_receiver_dir(run):
    dirs = sorted(run.glob("receiver-*"))
    for d in reversed(dirs):
        out = d / "strict-receiver.stdout"
        try:
            value = json.loads(out.read_text())
            if value.get("accepted") is True and value.get("completed_ethereum_block") is True:
                return d, value
        except Exception:
            continue
    raise SystemExit(f"no accepted receiver-* under {run}; run the harness receive first")


def statement(stdout):
    r = stdout.get("recursive", {})
    return {"output": stdout.get("output"), "root_digest": r.get("root_digest"), "root_authority": r.get("root_authority"),
            "manifest": r.get("manifest"), "native_profile": stdout.get("native_profile"), "outer_profile": stdout.get("outer_profile")}


def environment():
    env = {k: v for k, v in os.environ.items() if not k.startswith("STWO_RV64_GPU_")}
    env.pop("STWO_ZIG_RV64_SETUP_CACHE", None)
    env.pop("STWO_RV64_OUTER_PLAN_CLASS_STORE", None)
    env.update(CUDA_VISIBLE_DEVICES="", STWO_RV64_GPU_PCS_HELPER="/bin/false", STWO_RV64_FOLD_CLASS_CACHE="0")
    return env


def capabilities(receiver, proof, root_donor, root_path, alt_proof=None, donor_table_root=None):
    """What the receiver binary and the donors allow. Detected, never assumed."""
    caps = {"outer_profile_env": False, "root_donor_fits": False, "root_donor_same_tree": False,
            "alt_format_proof": bool(alt_proof) and Path(alt_proof).is_dir(), "donor_table_root": bool(donor_table_root),
            "gkr_section": False}
    try:
        caps["gkr_section"] = gkr_offset((proof / root_path).read_bytes()) >= 0
    except OSError:
        pass
    try:
        caps["outer_profile_env"] = b"STWO_RV64_OUTER_PROFILE" in Path(receiver).read_bytes()
    except OSError:
        pass
    if root_donor:
        _, _, other = proof_dir(Path(root_donor))
        mine, theirs = proof / root_path, other / root_path
        caps["root_donor_fits"] = theirs.is_file() and theirs.stat().st_size <= mine.stat().st_size
        names = lambda d: sorted(p.name for p in (d / "recursion-om31").iterdir())
        caps["root_donor_same_tree"] = caps["root_donor_fits"] and names(proof) == names(other)
    return caps


def run_case(case, ctx):
    work = ctx["work"] / case["id"]
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    proof = work / "proof"
    shutil.copytree(ctx["proof"], proof)
    request = json.loads(ctx["request_path"].read_text())
    request["output_directory"] = str(work / "capture")
    argv = {"profile": ctx["profile"], "table_root": ctx.get("table_root") or ""}
    env = environment()
    (work / "gpu-disabled").mkdir()
    env["STWO_RV64_GPU_WORKDIR"] = str(work / "gpu-disabled")
    mctx = {"proof": proof, "donor": ctx["donor"], "root_donor": ctx.get("root_donor"), "root_path": ctx["root_path"],
            "request": request, "env": env, "argv": argv, "alt_proof": ctx.get("alt_proof"),
            "donor_table_root": ctx.get("donor_table_root")}
    expect = expectation(case, ctx["format"])
    tier, owner = tier_owner(case)
    result = {"id": case["id"], "family": case["family"], "expect": expect, "tier": tier, "owner": owner, "what": case["what"]}
    try:
        detail = case["mutate"](mctx)
        if isinstance(detail, int):
            result["mutation_detail"] = {"flipped_byte_offset": detail}
    except Exception as error:
        result.update(status="harness_error", error=f"mutation failed: {error!r}", passed=False)
        shutil.rmtree(work, ignore_errors=True)
        return result
    request_path = work / "receiver-request.json"
    request_path.write_text(json.dumps(request, indent=1))
    command = ["nice", "-n", "10", *[a.format(receiver=ctx["receiver"], profile=argv["profile"], request=request_path, proof=proof,
                                             fixed=ctx["fixed_setup_bytes"], host=HOST_BYTES, table_root=argv["table_root"])
                                    for a in ctx["argv_template"]]]
    started = time.monotonic()
    timed_out = False
    with open(work / "stdout", "wb") as out, open(work / "stderr", "wb") as err:
        try:
            proc = subprocess.run(command, stdout=out, stderr=err, env=env, cwd=ctx["cwd"], timeout=1800)
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out, returncode = True, None
    wall = time.monotonic() - started
    stderr = (work / "stderr").read_text(errors="replace").splitlines()
    first_error = next((line for line in stderr if line.startswith("error") or "error:" in line[:40]), None)
    accepted = False
    same = None
    try:
        stdout = json.loads((work / "stdout").read_text())
        accepted = returncode == 0 and stdout.get("accepted") is True and stdout.get("completed_ethereum_block") is True
        if accepted:
            same = statement(stdout) == ctx["control_statement"]
    except Exception:
        pass
    crashed = timed_out or returncode is None or returncode < 0 or any(m in line for line in stderr for m in CRASH_MARKERS)
    verdict = "accept" if accepted else ("crash" if crashed else "reject")
    if expect == "accept":
        passed = accepted and same is True
    elif expect == "reject":
        passed = verdict == "reject"
    else:  # reject_or_same_statement
        passed = verdict == "reject" or (accepted and same is True)
    result.update(status="timeout" if timed_out else "ran", verdict=verdict, exit_code=returncode, wall_s=round(wall, 2),
                  first_error=first_error, reject_class=reject_class(first_error) if verdict == "reject" else None,
                  last_stderr=stderr[-1] if stderr else None, same_statement_as_control=same, passed=passed)
    shutil.rmtree(work, ignore_errors=True)
    print(json.dumps({k: result.get(k) for k in ("id", "verdict", "passed", "exit_code", "wall_s", "first_error")}, default=str), flush=True)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("spec")
    cv = sub.add_parser("coverage", help="list U/W-tier cases and the zig 'corpus <ID>' tests that implement them")
    cv.add_argument("--src", required=True)
    cv.add_argument("--out")
    r = sub.add_parser("run")
    r.add_argument("--root-donor", help="accepted run of ANY other block whose root.proof is no larger than RUN's (read only; V06/V07)")
    r.add_argument("--format", choices=("m3", "m5-root", "m5-audit", "m6-root"), default="m3")
    r.add_argument("--receiver-argv", help="JSON list template; {receiver} {profile} {request} {proof} {fixed} {host} {table_root}")
    r.add_argument("--alt-format-run", help="accepted run of the SAME block under another named format (NV03 DW07 RO10)")
    r.add_argument("--table-root", help="receiver table pin for this block ({table_root} in --receiver-argv)")
    r.add_argument("--donor-table-root", help="table pin derived for the donor block (RO09)")
    r.add_argument("--root-path", default="recursion-om31/root.proof")
    r.add_argument("--run", required=True)
    r.add_argument("--donor", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--receiver")
    r.add_argument("--jobs", type=int, default=3)
    r.add_argument("--cases")
    r.add_argument("--work", default="/workspace/m3/scratch/m4-profiles/corpus")
    args = p.parse_args()
    if args.cmd == "spec":
        print(json.dumps({"schema": SCHEMA, "cases": spec()}, indent=1))
        return
    if args.cmd == "coverage":
        rows = coverage(args.src)
        value = {"schema": SCHEMA, "src": args.src, "implemented": sum(1 for r in rows if r["hooks"]), "total": len(rows), "cases": rows}
        if args.out:
            Path(args.out).write_text(json.dumps(value, indent=1))
        print(json.dumps({k: value[k] for k in ("implemented", "total")} | {"missing_by_owner": {o: [r["id"] for r in rows if r["owner"] == o and not r["hooks"]] for o in sorted({r["owner"] for r in rows})}}, indent=1))
        return
    run, donor_run = Path(args.run), Path(args.donor)
    plan, job, proof = proof_dir(run)
    _, djob, donor_proof = proof_dir(donor_run)
    if job["block"] not in DEV_BLOCKS or djob["block"] not in DEV_BLOCKS or job["block"] == djob["block"]:
        raise SystemExit("run and donor must be the two different dev blocks (26235156, 24628607)")
    recv_dir, control_stdout = accepted_receiver_dir(run)
    receiver = Path(args.receiver or plan["assets"]["recursive_receiver"])
    default_argv = ["{receiver}", "--security-profile", "{profile}", "verify-recursion-candidate", "{request}", "{proof}", "{fixed}", "{host}"]
    ctx = {"proof": proof, "donor": donor_proof, "request_path": recv_dir / "receiver-request.json", "profile": plan["profile"],
           "receiver": receiver, "fixed_setup_bytes": job["resources"]["fixed_setup_bytes"], "cwd": plan.get("producer_cwd") or "/",
           "control_statement": statement(control_stdout), "work": Path(args.work) / str(job["block"]), "format": args.format,
           "argv_template": json.loads(args.receiver_argv) if args.receiver_argv else default_argv, "root_path": args.root_path}
    ctx["work"].mkdir(parents=True, exist_ok=True)
    if args.alt_format_run:
        _, ajob, ctx["alt_proof"] = proof_dir(Path(args.alt_format_run))
        if ajob["block"] != job["block"]:
            raise SystemExit("--alt-format-run must be the SAME block")
    ctx["table_root"], ctx["donor_table_root"] = args.table_root, args.donor_table_root
    caps = capabilities(receiver, proof, args.root_donor, args.root_path, ctx.get("alt_proof"), args.donor_table_root)
    if args.root_donor:
        _, rjob, ctx["root_donor"] = proof_dir(Path(args.root_donor))
        if rjob["block"] == job["block"]:
            raise SystemExit("--root-donor must be another block")
    wanted = set(args.cases.split(",")) if args.cases else None
    fmt_ok = lambda c: args.format in c.get("formats", ("m3", "m5-root", "m5-audit", "m6-root"))
    candidates = [c for c in CASES if "mutate" in c and fmt_ok(c) and (c["today"] in ("m3", "m3-cap") or args.format != "m3") and (wanted is None or c["id"] in wanted)]
    unsupported = [{"id": c["id"], "missing": [r for r in c.get("requires", ()) if not caps.get(r)]} for c in candidates if not all(caps.get(r) for r in c.get("requires", ()))]
    skip = {u["id"] for u in unsupported}
    runnable = [c for c in candidates if c["id"] not in skip]
    pending = [{k: v for k, v in c.items() if k != "mutate"} | {"status": "pending", "tier": tier_owner(c)[0], "owner": tier_owner(c)[1]}
               for c in CASES if "mutate" not in c or (c["today"] not in ("m3", "m3-cap") and args.format == "m3")]
    load = os.getloadavg()[0]
    started = time.time()
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda c: run_case(c, ctx), runnable))
    receipt = {"schema": SCHEMA, "measured": True, "date": time.strftime("%Y-%m-%dT%H:%M:%S"), "block": job["block"],
               "donor_block": djob["block"], "run": str(run), "proof_dir": str(proof), "donor_proof_dir": str(donor_proof),
               "receiver": str(receiver), "receiver_sha256": sha(receiver), "native_profile": plan["profile"],
               "receiver_env": {"CUDA_VISIBLE_DEVICES": "", "STWO_RV64_GPU_PCS_HELPER": "/bin/false",
                                "STWO_ZIG_RV64_SETUP_CACHE": "unset", "STWO_RV64_FOLD_CLASS_CACHE": "0",
                                "STWO_RV64_OUTER_PLAN_CLASS_STORE": "unset"},
               "control_statement": ctx["control_statement"], "jobs": args.jobs, "loadavg_1m_start": load,
               "loadavg_1m_end": os.getloadavg()[0], "wall_s": round(time.time() - started, 1),
               "ran": len(results), "passed": sum(1 for x in results if x.get("passed")),
               "unexpected_accepts": [x["id"] for x in results if x.get("verdict") == "accept" and x["expect"] == "reject"],
               "crashes": [x["id"] for x in results if x.get("verdict") == "crash"],
               "nonsemantic_rejects": {x["id"]: x["reject_class"] for x in results if x.get("reject_class") not in (None, "semantic")},
               "format": args.format, "capabilities": caps, "root_donor": args.root_donor, "unsupported": unsupported,
               "walls_s": {x["id"]: x.get("wall_s") for x in results},
               "results": results, "pending": pending}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=1, default=str))
    print(json.dumps({k: receipt[k] for k in ("block", "ran", "passed", "unexpected_accepts", "crashes", "nonsemantic_rejects", "wall_s")}))
    sys.exit(0 if receipt["passed"] == receipt["ran"] else 1)


if __name__ == "__main__":
    main()

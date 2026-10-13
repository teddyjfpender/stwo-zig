#!/usr/bin/env python3
"""Source-bound CAS05 Fiat–Shamir/BCS theorem-input ledger.

This audits a deterministic schedule. It does not model BLAKE2s as a random
oracle, establish Merkle binding, or assign a soundness probability.
"""

from __future__ import annotations

import hashlib
import json
import re
import argparse
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "verifier": "src/core/pcs/paired_sparse_cascade_experimental.zig",
    "prover": "src/prover/pcs/paired_sparse_cascade_experimental.zig",
    "shared": "src/core/pcs/paired_cascade_experimental.zig",
    "wire": "src/core/pcs/paired_sparse_cascade_wire.zig",
    "relation": "src/core/pcs/paired_sparse_relation_experimental.zig",
    "channel": "src/core/channel/blake2s.zig",
    "queries": "src/core/queries.zig",
    "source": "src/core/pcs/transposed_merkle_sparse.zig",
    "merkle": "src/core/pcs/transposed_merkle_cascade.zig",
}
P = (1 << 31) - 1


class IndependentRawChannel:
    """A tiny byte model for one fixed transcript fixture, not a ROM model."""

    def __init__(self) -> None:
        self.digest = bytes(32)
        self.counter = 0

    def absorb(self, data: bytes) -> None:
        self.digest = hashlib.blake2s(self.digest + data).digest()
        self.counter = 0

    def mix_u64(self, value: int) -> None:
        self.absorb(struct.pack("<Q", value))

    def mix_felts(self, values: list[tuple[int, int, int, int]]) -> None:
        self.absorb(b"".join(struct.pack("<4I", *value) for value in values))

    def draw_words(self) -> tuple[int, ...]:
        if self.counter == (1 << 32) - 1:
            raise OverflowError("channel draw counter exhausted")
        block = hashlib.blake2s(self.digest + struct.pack("<I", self.counter) + b"\x00").digest()
        self.counter += 1
        return struct.unpack("<8I", block)

    def draw_secure(self) -> tuple[int, int, int, int]:
        while True:
            words = self.draw_words()
            if all(word < 2 * P for word in words):
                return tuple(word % P for word in words[:4])  # type: ignore[return-value]


def fixture() -> dict[str, object]:
    """Independent BLAKE2s/LE replay of a 3-height CAS05 event schedule."""
    c = IndependentRawChannel()
    c.mix_u64(0x5333_3143_4153_3035)  # S31CAS05
    c.mix_u64(5)
    c.mix_u64(4)  # XDM04
    c.mix_u64(0x5333_3143_4152_3033)  # root tag
    for value in (7, 3, 2, 13, 2, 2, 2):
        c.mix_u64(value)
    c.absorb(bytes([1]) * 32)  # source root
    ood_seed = c.draw_secure()
    c.mix_u64(0x5333_3143_4143_3033)  # claim tag
    for height in range(3):
        c.mix_felts([tuple(range(1 + 8 * height + 4 * j, 5 + 8 * height + 4 * j))
                     for j in range(2)])
    batch = c.draw_secure()
    alphas = []
    for height in range(3):
        alphas.append(c.draw_secure())
        if height < 2:
            c.absorb(bytes([height + 2]) * 32)
    c.mix_felts([tuple(range(25 + 4 * i, 29 + 4 * i)) for i in range(4)])
    raw = []
    while len(raw) < 13:
        raw.extend(word & 127 for word in c.draw_words())
    return {
        "ood_seed": ood_seed, "batch": batch, "alphas": alphas,
        "raw_queries": raw[:13], "final_digest_hex": c.digest.hex(),
        "final_counter": c.counter,
    }


def body(source: str, start: str, end: str) -> str:
    try:
        return source.split(start, 1)[1].split(end, 1)[0]
    except IndexError as exc:
        raise ValueError(f"missing function boundary: {start} / {end}") from exc


def ordered_once(source: str, label: str, *anchors: str) -> None:
    positions = []
    for anchor in anchors:
        if source.count(anchor) != 1:
            raise ValueError(f"{label}: expected one {anchor!r}")
        positions.append(source.index(anchor))
    if positions != sorted(positions):
        raise ValueError(f"{label}: transcript order changed")


def require(source: str, label: str, *anchors: str) -> None:
    for anchor in anchors:
        if anchor not in source:
            raise ValueError(f"{label}: missing {anchor!r}")


def audit_sources(s: dict[str, str]) -> dict[str, object]:
    """Fail closed when source changes invalidate the scoped schedule claim."""
    if set(s) != set(SOURCES):
        raise ValueError("source roster changed")
    verifier = body(s["verifier"], "pub fn verifyAgainstStatement(", "fn lineWord(")
    prover = body(s["prover"], "fn proveImpl(", "\n}")
    ood = body(s["shared"], "pub fn drawOodPoint(", "pub fn drawBatchAfterOod(")
    batch = body(s["shared"], "pub fn drawBatchAfterOod(", "fn matches(")
    ordered_once(verifier, "CAS05 verifier",
                 "try statement.profile.validate();",
                 "try validateProof(proof);",
                 "if (!matches(statement, proof)) return error.UnexpectedSparseStatement;",
                 "var staged = channel.*;",
                 "bindVersion(&staged);",
                 "const sampled = try old.drawOodPoint(&staged, proof.profile, proof.source_root);",
                 "const batch = old.drawBatchAfterOod(&staged, proof.claims);",
                 "alpha.* = staged.drawSecureFelt();",
                 "blake2_merkle.Blake2sMerkleChannel.mixRoot(&staged, proof.line_openings[i].root);",
                 "staged.mixFelts(proof.terminal_ordered_coeffs);",
                 "const raw = try queries.drawQueries(",
                 "var opened = try xdm.verifyAndCollect(",
                 "try verifyFolds(allocator, proof, raw, answers.values, alphas);",
                 "channel.* = staged;")
    require(verifier, "CAS05 line-round barrier",
            "for (alphas, 0..) |*alpha, i| {",
            "if (i < proof.line_openings.len)",
            "source.largest_log_size,\n        source.query_count,")
    if verifier.count("staged.drawSecureFelt()") != 1 or verifier.count("queries.drawQueries(") != 1:
        raise ValueError("CAS05 verifier challenge/query count changed")
    if re.findall(r"\bstaged\.(mix\w+|draw\w+|updateDigest|verifyPowNonce)\(", verifier) != [
        "drawSecureFelt", "mixFelts"]:
        raise ValueError("CAS05 verifier gained an unreviewed direct channel operation")
    ordered_once(prover, "CAS05 prover",
                 "cascade.bindVersion(&staged);",
                 "const point = try core.pcs.paired_cascade_experimental.drawOodPoint(&staged, profile, root);",
                 "core.pcs.paired_cascade_experimental.drawBatchAfterOod(&staged, claims);",
                 "const alpha = staged.drawSecureFelt();",
                 "core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(&staged, trees[step].root());",
                 "const last_alpha = staged.drawSecureFelt();",
                 "staged.mixFelts(terminal);",
                 "const raw = try core.queries.drawQueries(",
                 "channel.* = staged;")
    require(prover, "CAS05 prover line-round barrier", "for (0..line_count) |step| {",
            "const line_count = height_count - 1;")
    if re.findall(r"\bstaged\.(mix\w+|draw\w+|updateDigest|verifyPowNonce)\(", prover) != [
        "drawSecureFelt", "drawSecureFelt", "mixFelts"]:
        raise ValueError("CAS05 prover gained an unreviewed direct channel operation")
    ordered_once(ood, "CAS05 OOD source binding",
                 "staged.mixU64(ROOT_TAG);", "staged.mixU64(profile.source.largest_log_size);",
                 "staged.mixU64(profile.source.height_count);",
                 "staged.mixU64(profile.log_blowup);",
                 "staged.mixU64(profile.source.query_count);",
                 "staged.mixU64(count);",
                 "staged.updateDigest(blake2_hash.Blake2sHasher.concatAndHash(staged.digestBytes(), root));",
                 "staged.drawSecureFelt()",
                 "if (point.y.c1.isZero()) return error.DegenerateOodPoint;",
                 "channel.* = staged;")
    ordered_once(batch, "CAS05 claim binding", "channel.mixU64(CLAIM_TAG);",
                 "for (claims) |height| channel.mixFelts(height);",
                 "return channel.drawSecureFelt();")
    require(s["verifier"], "CAS05 version", "const TRANSCRIPT_TAG: u64 = 0x5333_3143_4153_3035;",
            "channel.mixU64(TRANSCRIPT_TAG);", "channel.mixU64(OUTER_VERSION);",
            "channel.mixU64(xdm.VERSION);")
    require(s["source"], "XDM04 version and bounds", 'pub const MAGIC = "S31XDM04";',
            "pub const VERSION: u16 = 4;", "pub const MAX_LOG_SIZE: u32 = 22;",
            "self.query_count > (1 << 14)")
    require(s["wire"], "CAS05 byte path",
            "var decoded = try decode(allocator, encoded);",
            "try cascade.verifyAgainstStatement(allocator, decoded.proof, channel, statement);")
    require(s["relation"], "CAS05 extractor channel",
            "channel: *blake2s_channel.Blake2sChannel,",
            "try cascade.verifyAgainstStatement(a, proof, &staged, statement);")
    channel = s["channel"]
    ordered_once(body(channel, "pub fn drawU32s(", "pub fn drawSecureFelt("),
                 "channel draw encoding", "const counter = u32ToBytesLe(self.n_draws);",
                 "hash_input[36] = 0;",
                 "self.n_draws = nextDrawCounter(self.n_draws) catch",
                 "const hash = hashBytes(hash_input[0..]);")
    require(channel, "counter exhaustion", "return std.math.add(u32, current, 1) catch error.DrawCounterExhausted;",
            '@panic("BLAKE2s draw counter exhausted")')
    require(channel, "raw versus reduced channel", "pub const Blake2sChannel = Blake2sChannelGeneric(false);",
            "pub const Blake2sM31Channel = Blake2sChannelGeneric(true);")
    require(s["queries"], "CAS05 raw query law",
            "const words = channel.drawU32s();",
            "out[produced] = @as(usize, word & query_mask);",
            "if (produced == n_queries) break;")
    require(s["merkle"], "source Merkle roles", 'h.update("S31XDL03");',
            'h.update("S31XDU03");', 'h.update("S31XDI03");')
    return {
        "schema": "cas05-bcs-rom-theorem-input-v1",
        "scope": "experimental CAS05/XDM04 raw Blake2s transcript",
        "status": "deterministic_source_schedule_only",
        "production_admitted": False,
        "native_proven_security_bits": None,
        "max_largest_log_size": 22,
        "max_raw_queries": 1 << 14,
        "max_query_hash_blocks": (1 << 14) // 8,
        "counter": "u32 checked before every raw/secure hash block; exhaustion traps before hashing",
        "round_schedule": [
            "CAS05, outer and XDM04 version words",
            "profile words then source root",
            "OOD secure draw with checked on-circle/nondegenerate mapping",
            "claim tag and profile-sized claim arrays then batch secure draw",
            "for each nonterminal height: alpha secure draw then line root",
            "last alpha secure draw",
            "terminal coefficients then raw query blocks",
            "authenticate exact sampled source and line rows; verify all folds; publish channel on success",
        ],
        "query_law_if_fresh_ideal_hash_outputs": {
            "word": "each 32-bit word is masked to its low k bits, 4 <= k <= 22",
            "per_draw": "eight independent uniform k-bit positions if each 256-bit hash block is fresh and ideal",
            "duplicates": "allowed; all raw query occurrences are checked",
            "freshness_and_adaptive_ROM_proven": False,
            "nonideal_hash_assumption": "BLAKE2s is not proven to instantiate a random oracle",
        },
        "BCS_theorem_inputs": {
            "published_expression": "(T+R)*max(epsilon_i) + 3*(T^2+1)/2^lambda",
            "T_total_adversary_hash_queries": None,
            "R_exact_interactive_rounds": None,
            "epsilon_i_for_CAS05_sparse_protocol": None,
            "lambda_justified_for_shared_BLAKE2s_and_Merkle": None,
            "adaptive_fiat_shamir_reduction": None,
            "Merkle_binding_and_cross_role_collision_bound": None,
            "CAS05_no_grinding": True,
        },
        "full_theorem_join_complete": False,
    }


def audit(root: Path = ROOT) -> dict[str, object]:
    sources = {key: (root / path).read_text() for key, path in SOURCES.items()}
    report = audit_sources(sources)
    report["source_sha256"] = {key: hashlib.sha256(value.encode()).hexdigest()
                               for key, value in sources.items()}
    expected_fixture = json.loads((root / "design/pcs/fixtures/cas05_bcs_transcript.json").read_text())
    if expected_fixture != json.loads(json.dumps(fixture())):
        raise ValueError("CAS05 independent byte fixture changed")
    report["independent_byte_fixture"] = expected_fixture
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-proven", action="store_true",
                        help="fail while any CAS05 BCS/ROM theorem input is undischarged")
    args = parser.parse_args()
    try:
        report = audit()
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2 if args.require_proven else 0


if __name__ == "__main__":
    raise SystemExit(main())

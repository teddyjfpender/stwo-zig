# Serialized execution receiver review

The reviewed chain receiver derives immutable ROM, permissions, initial PC/SP,
and initial value root from independently pinned ELF/input/configuration. Each
batch proof binds its complete admitted ROM opcode union, profile/policies,
provider rosters, private RAM root transition, and public CPU boundaries. The
receiver checks index/coverage/root/PC/register/service-ID adjacency before
accepting a proof and advancing its cursor. Producer summary timings/endpoints
and `completed` are not proof authority. Complete verification additionally
requires the independently expected absorbing terminal PC and a terminal root
certificate authenticating halt1, length43, and all expected output bytes.
The externally supplied expected configuration remains the caller's authority;
the producer's archived request is not used to choose an expected validator.

Ownership review found the expected ordering: touched openings freeze before
advancing the VM; moving openings empties the previous owner; CPU/crypto narrow
metadata survives clearing compact advice; source mains release after sealing;
proof and metadata sync before sparse cache publication and cursor advancement.
No execution replay or all-RAM snapshot occurs in this bridge. A failure aborts
without returning a verified chain result. Directory-entry crash durability and
process resumption are separate from the cryptographic acceptance conditions.

Concrete admission improvements were reported and applied by the driver owner:
worker budget validation before thread creation; preflight terminal alignment
and wholly writable terminal chunk; per-receipt steps bounded by receiver
`batch_steps`. `workers=0` now selects a bounded automatic count. `max_batches`
is a producer pilot stop, not a receiver semantic assertion.

The registered `test-riscv64-ethereum-chain` ReleaseSafe gate qualifies strict
malformed/unknown/duplicate/truncated JSON, schema/ROM/profile admission,
adjacency gaps, and a genuine physical serialized receipt accepted under the
expected authority but rejected under a changed immutable program. It also
checks budget validation and bounded automatic workers.

The frozen profiled real65k prefix passes 23 fresh-process serialized receiver
cases in `serialized-chain-adversarial-v1.json`. The valid prefix takes 0.874s
wall time including initial image/root derivation, versus the producer's local
receiver's reported 0.228s geometry setup +0.0187s verification. Other cases
reject schema, order, coverage, root/PC64/register/call-ID gaps, embedded ROM,
claim collusion, and malformed wire with a recomputed valid SHA. A fake
`completed:true` real prefix rejects at the terminal PC check. A separate
five-retirement synthetic ABI program—not an Ethereum validator—qualifies
complete certificate presence/corruption/output/pin checks. Original real
artifacts remain byte-identical. This report does not qualify a complete real
Ethereum block or recursive aggregation.

One measured cost repetition remains: the65k prover builds geometry setup
(0.234s), then rebuilds a second local receiver setup (0.228s) for a 3.574s proof.
The first setup is already independently derived from expected authority and
can also serve local verification. A fresh external receiver still reconstructs
its own setup. Any reuse should retain count-independent geometry keys and
explicit ownership, and be measured across the whole job before adoption.

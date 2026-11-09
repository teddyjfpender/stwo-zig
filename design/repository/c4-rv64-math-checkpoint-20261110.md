# C4 bounded RV64 mathematical ownership checkpoint — 2026-11-10

Status: **PARTIAL C4 FOUNDATION; FULL FRONTEND/CPU/PROOF ACCEPTANCE UNRUN**.
This backup is separate from the unmergeable full product ownership candidate.
It does not advance PR357 or claim that C4/P3 is complete.

Base: `fb9a8479068a7d9216780e4a4550dbc9fd7c1619` (accepted C2 main).
Material tree before this runbook: `e75c40d0ccb3ad7b8362fe9da8a41dccecb10e38`.
Backup ref: `backup/c4-rv64-math-20261110`.
Slice336; owner @teddyjfpender.
Approval: https://github.com/teddyjfpender/stwo-zig/issues/352#issuecomment-6753676480.

Three complete mathematical implementations now have canonical lower owners:

| Old source | Canonical source |
| --- | --- |
| `src/frontends/riscv/rv64/ethereum_services/arith256.zig` | `src/frontends/riscv/rv64/service_primitives/arith256.zig` |
| `src/frontends/riscv/rv64/ethereum_services/secp256k1.zig` | `src/frontends/riscv/rv64/service_primitives/secp256k1.zig` |
| `src/frontends/riscv/rv64/ethereum_services/sha256.zig` | `src/frontends/riscv/rv64/service_primitives/sha256.zig` |

The complete secp256k1/SHA sources are byte identical. Arithmetic source is
identical after moving its one whole independent-oracle comparison test to
ethereum_services/arith256_candidate_test.zig. That test keeps its original
Candidate.mulAddMod oracle and exact body; only std/limbs/mulAddModPacket aliases
provide its new lexical scope. Both original literal test roots (inventory and
fast_execution_test) collect that complete case. No candidate test was removed,
filtered away, replaced by a self-oracle or imported into the neutral subject.

Only three public provider paths are added: rv64.arith256_mod,
rv64.secp256k1_rcb and rv64.sha256_compression. Upper session aliases use those
same canonical source modules. All23 original declarations/signatures remain;
record/enum fields, defaults, numerical bodies and protocol tags are unchanged.
The new root contract test pins module identity; its execution remains part of
full hosted frontend acceptance, not the bounded source probe below.
The additive isolated package version is0.2.0 in contract/.zon/README; a later
combined major authority/product transaction must retain its approved major.

## Actual bounded evidence

A pinned source-only test fixture contains16 before-files/2741 lines and17
after-files/2746 lines, with std as its only named dependency. It is not a
worktree or component checkout. Actual unfiltered executions pass22 tests
BEFORE and AFTER in Debug and ReleaseFast, under memguard1GiB. Every run
completes; the actual declared test-name multiset matches across the ownership
move, including all four specified cases below. Raw diagnostic source-path
prefixes move with their owner, rather than being falsely called identical.
The source code compiled in these executions is byte identical to this
checkpoint; subsequent edits affect only README/configuration/documentation.

Actual Zig0.15.2 reflected layout/field-offset/tag outputs match before/after
for Kind, Ref, Operation, Program and Values. This includes Kind1/2, Ref0/1/2,
operation0/1/2/3, Program size471/alignment1 and Values size2560/alignment16.
Complete source identity and four direct record readers are unchanged outside
literal import targets. No serialized type reader, error normalization,
new public runtime ABI or product dispatch was introduced. Diagnostic type-name
strings can follow the new source location; no string-identity claim is made.

Four preserved named test bodies (SHA256):

- `arith256 long division equals the generic u512 remainder`: `b644c7bb20131d97012f8a790e0cfa7c518423e989cc2c91ac9b678dcc09a6fc`.
- `packet arith256_mod matches the candidate executor's semantics`: `ed5f2c9d1462491bff4f5e527d5702a5b0ccd9666acf98f1da574016c0528cad`.
- `secp256k1 fast reduction equals the generic u512 remainder`: `b6feb86a88e27df2f38ce93408e7c0881c4c1f94197a63a69696b970bdd6c85a`.
- `packet compression matches std.crypto on abc`: `8903baa6e1c89aedeea595e2c654485c39f4af49e6d91f35a668cd515af9e13c`.

The package-workspace checker at the material source (after README correction)
reports ZERO findings. This is the existing static package checker, not final
strict C4 P3: final P3 is not installed on this additive foundation tree.
Formatter/AST checks pass for changed Zig sources. Source-pinned formal manifest
bytes are unchanged; its three old-path bindings remain for the tracked formal
regeneration follow-up328, not hand-edited pins. Full frontend/native CPU,
actual repository-wide discovery union, semantic negatives and frozen Native
proof bytes are UNRUN here. No GPU or hardware/timing qualification is claimed.
Before backup push, invoke rv64_gate on the exact commit; laptop pod-only
refusal is UNRUN, never PASS.

## Budget and integration

Measured source is +44/-27/net+17 within the approved <=40 sub-budget of C4's
existing <=800 allowance. Three complete moves receive no subtraction credit.
Flags/scripts added/removed are0. A dedicated budget entry records the prior
RFC decision; it does not increase the overall C4 reserve. Documentation and
configuration are reported separately in the commit. C4 old-base cumulative
source is+414 including the original geometry+61; after that prerequisite lands
as C3 foundation, charge it once to C3 and adjust the actual base-relative C4
report (do not claim unlanded credit or double-count the source).

Replay this bounded source diff onto accepted main with exact path/source
checks; preserve incoming C1 accepted flag retirements. Do not apply the full
partial product tree or overwrite reserved authority/graph/geometry files.
Keep canonical checkout/default index/HEAD unchanged and use private Git objects.
The remaining Session/Event/packet/admission dependency closure is NOT approved
by this math cut, nor is publishing104 private runtime members. Those require
bounded real ownership contracts. Final C4 still requires the actual component
module DAG, legacy consumer update, strict workspace/P3 zero and hosted CPU/
proof-byte acceptance.

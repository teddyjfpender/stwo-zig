# OP Mainnet: guest and CPU proof continuation

Six pinned historical OP Mainnet blocks (chain 10, Ecotone era) now replay with
actual registry configuration. Every case reproduces its complete expected
block hash in native Kona and matches the production RV64 runner against
Unicorn: N-1 then one instruction, all registers, terminal PC, output and service
counts. These are historical mainnet inputs, not testnet or current-head claims.

The branch is rebased onto GPU `bf2b6c072d51341f1c733f05f870d70b4c15834b`.
Execution/proof measurements began on `2b7eceb8cf93c185637e91762742f91a3412ee82`;
the intervening GPU changes concern the CUDA job Stage2/device-claim seam. The
linked recursion route was type-checked after the final rebase. No physical GPU
measurement or recursive OP root is claimed.

## Mainnet execution measurements

`frontier` is the prior optimized Revm/MPT guest with full LTO. `full` adds SHA,
EVM ADDMOD/MULMOD and bulk memory. `bn254` additionally uses the explicit
Montgomery field adapter. Counts compare our own binaries on identical inputs;
they are not SP1 comparisons or proof-speed measurements.

| OP block | Gas used | Txs | Frontier instructions | Full services | BN254 trial | Fewer vs frontier |
|---|---:|---:|---:|---:|---:|---:|
| 120794432 | 43,851 | 1 | 1,106,822 | 821,721 | 823,363 | 25.61% |
| 121003241 | 1,243,355 | 10 | 19,331,400 | 16,499,533 | 16,510,963 | 14.59% |
| 121049889 | 329,122 | 3 | 6,761,716 | 5,706,703 | 5,707,677 | 15.59% |
| 121057303 | 423,281 | 4 | 7,661,045 | 6,394,106 | 6,395,123 | 16.52% |
| 121065789 | 27,255,387 | 13 | 2,520,725,903 | 2,500,418,167 | 1,376,966,523 | 45.37% |
| 121135704 | 1,885,913 | 18 | 24,329,539 | 20,767,823 | 20,770,017 | 14.63% |

The heavy block's profile attributes about 91% of retired instructions to BN254
pairing arithmetic. The trial lowers its count from 2.521B to 1.377B (45.37%),
but issues 6,432,694 admitted Montgomery calls. Its total service RAM word
transitions rise from 34,927,949 (`full`) to 162,809,929. It remains experimental:
a lower whole-proof time/cost for that block has not been established.

The first adapter zeroed every packet and then filled it. That generated a bulk
memset per multiplication: 6,476,548 memset calls / 1,036,361,048 bytes in the
heavy case. Direct construction returns that to 43,854 calls / 7,130,008 bytes.
The prior packet retired 1,795,292,415 instructions; the corrected packet retires
1,376,966,523. Those first-trial native counts were diagnostic, not an admitted
performance result; the corrected variant has complete independent-oracle data.

The CPU evaluator recognizes only the canonical shifted BN254 packet and uses
four-limb REDC. All other operands retain general Montgomery semantics. Boundary
and seeded wide-integer tests, existing AIR rows with forged-output rejection,
and 110 Ark property tests cover the adapter. No AIR/transcript change is made.

## Complete CPU proof and independent reception

OP Mainnet **120794432** (one deposit transaction, 43,851 gas) and
**121057303** (four transactions, 423,281 gas) have physical native
STARK proof bundles. These prove the supplied execution with all admitted service
and RAM relations; they are not merely execution traces or constraints checks.

| Guest | Retired instructions | CPU / service proofs | Producer wall | Fresh receiver wall | Producer peak RSS | Binary proof/sidecar bytes |
|---|---:|---:|---:|---:|---:|---:|
| 120794432 / SHA first checkpoint | 970,702 | 4 / 2 | 200.077 s | 31.799 s | 2.703 GiB | 15,538,334 |
| 120794432 / bulk + SHA + arithmetic | 821,721 | 4 / 2 | 286.521 s | 34.938 s | 2.704 GiB | 16,580,348 |
| 121057303 / 4 proof workers, 1 setup worker | 6,394,106 | 7 / 7 | 268.611 s | 34.897 s | 4.083 GiB | 41,101,146 |

These runs overlapped other development/build work. Their wall times are cold
operational receipts, not a controlled speedup comparison. Compilation is
outside measured stages. The first SHA checkpoint predates later diagnostic
code changes; its exact ELF identity is recorded separately.

All three fresh receiver runs accepted the complete 43-byte OP output. Both full-service runs also
rejects corrupted CPU proof bytes after recomputing the untrusted outer digest
(`RootMismatch`), in addition to the transport-digest rejection
(`WideBundleFileChanged`). Original byte identities are recorded; the corruption trials restore those bytes.
No prefix counts as success. Full proof binaries are not added to Git; their
sizes/SHA identities, reports and reproduction commands are retained.

The CPU-only `rv64-word16-ethereum-native` product uses the same native statement,
service roster, profile and durable receiver without requiring circuit-module
registration. Existing GPU/recursive entry points retain their policy checks.
Producer-only process-local setup sharing now matches the GPU path's
identity-only/source sharing mode. It restores/persists no files. Fresh receivers
have a separate clean environment and rebuild their own authority. The older
uncached control remains selectable. No binary-size/build-speed claim is made.

## Cell accounting and resource failures

For the small block at 262,143-step geometry, the source-derived MAIN+INTERACTION
payload changes from **8,159,530,336 bits** (`sha`) to **7,828,394,784 bits** (`full`),
about 4.1% fewer. Counts include padding and exclude FIXED, PCS blowup, composition,
openings, recursion and proof bytes. These are not proof-size estimates.

A first 256 MiB fixed-setup attempt failed with `OutOfMemory`; the successful
checkpoint explicitly uses 1 GiB. Failures remain under `cpu/`.

For user-transaction block **121057303** (4 transactions, 423,281 gas), a candidate
planner originally rejected an exactly full arithmetic table. Candidate producer
geometry now reserves a padding row rather than relaxing the receiver check.
CPU planning is extracted into `ethereum/cpu_plan.zig`; the old planner shrinks
from 973 to 811 lines. The bounded native plan covers the complete 6,394,106-step
execution. At 262,143-step geometry it needs 25 CPU + 7 service proofs and
47,641,668,992 MAIN+INTERACTION bits. At 1,048,575 steps it needs 7 + 7 proofs and
34,422,769,024 bits, about 28% fewer. Neither plan is itself a proof.

A materializing setup attempt was killed (signal 9); producer-local identity-only
sharing then reached an explicit retained-input admission failure: 3,505,687,308
bytes requested against a 2 GiB cap. The subsequent 1M-step trial admits 4 GiB
retained inputs and keeps unchanged security parameters. The serial trial lost its execution session without a final producer receipt;
it is recorded as incomplete, with no inferred exit status. The subsequent
four-worker trial completes, fresh-verifies and rejects rehashed corruption:
7 CPU + 7 service proofs, 268.611 s producer wall, 34.897 s fresh receiver wall,
4.083 GiB producer peak RSS. Native proving itself takes 236.947 s; setup is
25.763 s. Its 41,101,146 binary proof/sidecar bytes are recorded separately from
execution and trace-cell cost. All restored artifact hashes pass the final audit.

The final supervisor writes a heartbeat and periodic stage progress, records
bounded timeouts, and separates proof/setup worker counts. The tested resource
preset is `opstack/presets/cpu-4workers.json`. Only the successful trial is a
complete user-block proof; neither earlier planning nor missing receipts count.

## Reproduction and validation

Use [the runbook](../../../opstack/README.md) (from this report directory the
repository root is three levels up). Start with fresh artifact directories,
`--network mainnet` (the default), pinned source/cache identities, and the
reported security profile `conjectured128_b2_q108_p20_fold4`. The reproduced
BN254 guest and execution runner are byte-identical to the independently checked
pair: guest `142819a8380d5257feb938b630a417e5cb01c0e55073630872105ed583ba95ab`,
runner `96249a52a693b4ea6566f025ad986d1c7a14c62665deb82e44a493e88f2dc27c`.
`build-bn254.json` records compiler, source and lock identities and explicit
16/16/16/8 memory thresholds; ambient `STWO_ADMITTED_*` variables cannot leak in.
Source snapshots in older benchmark receipts describe their working-tree
checkpoint. ELF/input/tool SHA identities identify the actual measurements.

Passing checks: 14 Rust execution/witness/sponge tests; 103 OP Revm tests
(including Ecotone/Isthmus/Jovian operator-vault cases); 110 Ark field/curve
property tests; 23 Python checks; standalone REDC tests; shifted-packet AIR
accept/reject test; candidate cell-accounting overflow test; unfiltered Ethereum
chain and curve truth gates; post-rebase linked-recursion type-check; owned-file
formatting; vendored-source inventory/drift checks. Test filtering uses the
repository's nonempty-selection guard.

Repository-wide formatting, upstream pins and source conformance are not green.
Baseline logs show the existing circuit-provenance/formatting/size violations.
The residual oversized `gkr_main.zig` is explicit in `opstack/DESIGN.md`; its next
split is documented rather than hidden by a threshold increase. Tests and
receipts here do not claim those global gates passed.

`security_qualified=false` throughout: the current native conjectured-128 target
is unchanged and is not a whole-protocol security certificate. Authenticated L1
derivation/KZG, execution–derivation binding, anchored L1/reorg handling,
recursive/accumulator closure and a direct settlement verifier remain open.
This is not yet a complete SP1 replacement. There is no SNARK wrapper.

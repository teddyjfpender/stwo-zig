# Native Blake versus P2: bounded CPU source-cost gate

For the **measured selected CPU geometry and current circuit gadgets**, replacing
native P2 commitments/transcript with Blake is not a promising immediate CPU
optimization. The source cost moves much more hashing work into recursion.
This is a source-work comparison, not a new native proof or measured end-to-end
Blake benchmark. Keep the native P2 default and R7 production admission unchanged.

The tests are isolated and create no native crypto suite, ISA feature, source
key, accepted mixed circuit, proof or Runtime/Topology selector. They do not
modify protected R5 or `outer_gkr` sources. OM31 and the native B4/q72/P0/fold4
128-bit target under documented assumptions remain fixed. No 96-bit/QM31 control
is used to claim a speedup.

## Matched actual geometry

`actual_cost_test.zig` fresh-verifies the retained 796,406-step selected OP
bundle (one CPU, detached sponge, Keccak and SHA; native bundle 5,045,776 bytes).
It derives the CPU shape from the independently reconstructed source setup/key.
Only column counts, logs, masks and FRI layer dimensions cross into a **new**
32-byte Blake witness allocation. No P2 root, proof or field value is cast into
a Blake cryptographic type. The Blake proof values are zero dummy advice and
are never asserted valid. The original native receiver still completes full
RAM/KIO/Wire/terminal acceptance after the callback.

The existing OM31 native Blake verifier executes its real PCS/OODS sampling,
DEEP, FRI, full32-byte Merkle paths and raw-OM31 transcript gadgets trace-only.
R7 multiplication and DEEP-dot lowering scopes are enabled. An explicit audit
statement supplies public/claim framing and substitutes the reconstructed
composition expression for the missing AIR. It **does not** establish the
original source AIR, P2 local-GKR/frame obligations, mixed Input-origin/Var
closure or a proposed production transcript identity. No mixed R7 finalizer or
source-key constructor runs. A second trace uses the existing P2 verifier on
the exact same geometry and audit framing, also without an acceptance claim.

| Item | Actual source value |
|---|---:|
| Native field | OM31, eight M31 coordinates |
| FRI | B4, 72 queries, P0, fold4 |
| Columns FIXED / MAIN / INTER / composition | 177 / 1,357 / 880 / 16 |
| Tree heights | 22 / 22 / 22 / 22 |
| Global mask log / composition split | 20 / 1 |
| Physical claim count | 16 |
| Blake compression blocks | 26,518 |
| Blake G gates | 2,121,440 |
| Triple XOR rows | 212,144 |
| Blake M31-to-u32 rows | 246,128 |
| Matched P2 permutations | 43,257 |
| Native OM multiplication calls, both traces | 28,283 |
| Native DEEP dot calls, both traces | 1,656 |

The generic QM arithmetic counts are 769,350 for Blake and 963,913 for P2;
both pad to log20 in this partial graph. The proof, statement and source-input
lowering remain unqualified for a mixed roster; these are not final leaf totals.
The filtered ReleaseSafe test passes and the common budget returns to zero.

## Hash-role cost, table floors and padding

The existing BLAKE-G role has 52 MAIN, 104 OM31 interaction and 11 FIXED columns.
Triple XOR has 20/48/5. Five additional XOR table roles contribute 87,050,496
MAIN+INTER cells plus 4,178,688 FIXED cells at their source-fixed logs. XOR12
uses log20 through its existing expansion; it is not a log24 table. The P2
range16 provider is already present and is not double charged in these additions.

The primitive census independently verifies 80 G gates and eight triple XOR
rows per compression block. Even a one-block hash's full old roster uses about
91.9M cells, largely fixed lookup-table floors. This census is not a proof.

For the actual source trace, 2,121,440 G gates just exceed 2^21 and pad to log22.
Named hash-role costs, including their FIXED columns, are:

| Source hash work | Cells |
|---|---:|
| Matched P2 permutation role (log16, 741 columns) | 48,562,176 |
| Blake G + triple XOR + additional XOR tables, cap0 | 810,814,464 |
| Same Blake roles, static cap1 counterfactual | 460,590,080 |

These are **named role counts**, not complete R7 proof sizes or a speed ratio.
The Blake column additions also expand the next-level opening budget by 341
MAIN+INTER and 31 FIXED columns across seven roles. Existing P2 GKR/frame work
would remain and can change pooled padding. M31-to-u32 and Input/Var/range
closure costs are outside this table. Source preparation, cold FIXED keys and
proofs must also be counted in any actual comparison.

The 26,518 blocks divide into 11,016 trace-leaf blocks, 6,336 trace-path blocks,
7,560 FRI Merkle blocks and 1,606 residual FS blocks under the explicit audit
framing. The source-derived FRI and authentication path counts are recorded in
the receipt. This gives concrete work counts instead of a guessed 20k figure.

Existing Merkle caps offer a bounded counterfactual, not a new hash protocol.
For cap1, nine eligible trace/FRI trees save 639 compression blocks after
charging each cap root, crossing G padding to log21. The estimate excludes cap
selection arithmetic, source-class/witness reconstruction, keys and the actual
physical gate. Current factories require cap0; they have not been relaxed.
Cap3/cap5 counts in the receipt are static scenarios only. Even cap1's named
hash-role count remains much larger than the matched P2 role.

The observed native P2 commitment hotspot motivates this question; it does
not prove that the native hash saving can pay for these recursive costs. A
future log22 CPU/native-tree24 geometry may gain more native speed while the
outer G role stays on a padding plateau. That is an **unmeasured crossover
hypothesis**, not justification to implement the crypto switch now. No full
heavy replay was run. The next high-payoff direction remains reducing guest
and provider work, including complete pairing delegation.

## Exact reuse seams and necessary changes if reconsidered

- Native OM31 arithmetic/engine and B4/q72 configuration can remain. The old
  `gkr_local/worker_protocol.zig` already has a complete eight-coordinate raw
  OM31 channel and full32-byte **prefixed** Blake Merkle suite. The existing
  `om31_native/{common,mod,proof,shape}` circuit path is the corresponding reuse
  seam. A plain-Blake suite requires its own correct IV/framing identity;
  prefixed and plain modes cannot share keys/proofs by accident.
- Current native P2 workers, MAIN scope, local-GKR receipt and manifest use
  full36-byte nine-M31 roots. A native Blake suite needs a distinct typed root
  representation and domain. One possible bridge is a separately named P2
  commitment to a tagged full eight-u32 Blake root. Each u32 must be encoded
  injectively (e.g. two16-bit limbs), never reduced to a single M31. The circuit
  must bind that commitment to the actual32-byte PCS root. Zero-padding,
  truncating or casting roots is not such a bridge. Source geometry identities
  remain mandatory even for zero-column trees with identical root digests.
- Source manifests/expected statements and global relation draws stay P2 only
  through an explicitly source-owned mixed-suite policy. Every MAIN and source
  key must be fixed before the relevant challenges. Old P2 proof bytes, local
  receipts and scopes cannot simply be reused under new framing.
- R7's eight-role stream and source authorities intentionally reject BLAKE-G
  and triple-XOR work. The old mixed census mode is diagnostic only and does
  not admit a combined R7 AIR. A new source-owned roster must include every
  G/XOR relation, full OM31 lookup challenges, immutable use counts and all
  Var/range/byte source closure. Protected old authorities must remain intact.
- New source-owned identities, frame/wire version, source key normalization,
  native+circuit transcript parity, physical mutation proofs, global closure,
  source-only fresh reception and recursion/root/settlement compatibility all
  remain gates. Merely setting the native secure field to OM31 is insufficient
  if a reused outer XOR component accidentally retains QM31 challenges.

Blake's 256-bit output has the standard nominal128-bit birthday work factor.
That is compatible with a documented-assumptions target, but not a composed
2^-128 claim for arbitrary adversarial query budgets or a certification. The
native switch would add hash obligations throughout the tree, so terminal-only
Blake's existing bounded note does not automatically qualify it. Re-account
all query/union/mass/pole/FS terms, raw-mod OM31 challenge bias, XOR lookup
soundness and source binding before promotion. The existing profile remains
`security_qualified=false`.

## Reproduce the bounded gate

Add the two NEW module imports to `rv64_op_pure_p2_test_root.zig` and run:

```sh
zig build test-riscv64-op-pure-p2 -Doptimize=ReleaseSafe \
  -Driscv-test-filter='native Blake source census' -j1
STWO_OP_NATIVE_BLAKE_AUDIT_CONFIG=/path/to/pinned-small.config.json \
STWO_OP_NATIVE_BLAKE_AUDIT_NATIVE=/path/to/retained-native-bundle \
zig build test-riscv64-op-pure-p2 -Doptimize=ReleaseSafe \
  -Driscv-test-filter='native Blake actual CPU' -j1
python3 opstack/tools/native_blake_cost.py --primitive-log /tmp/primitive.log \
  --actual-log /tmp/actual.log --out /tmp/native-blake-source-cost.json
```

The temporary test-root imports used for qualification were restored. Default
runtime, native proof bytes and old R6/R7 authority identities are unchanged.

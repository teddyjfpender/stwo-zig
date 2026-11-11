# Direct native-verifier groups (closed)

The existing four-member detached fixture spends56% of measured node proving
on three recursive folds. This experiment appends the complete source-owned
native verifiers to one context, then hashes their full frame digests through
the existing canonical adjacent-pair tree. It does not create or verify
intermediate recursive child proofs. Complete execution admission remains a
separate receiver obligation.

`source.Stream` accepts aligned groups of1,2or4 consecutive native members.
Each append validates ordinal/profile/manifest, reconstructs the PCS shape from
the concrete independent source key and emits into a caller-owned context.
Borrowed captures, statement arenas and native proof buffers expire after the
callback. Only circuit graph/value metadata survives. Builder scopes are entered
and exited per callback; they never stay globally bound while other workers run.
A failed append poisons the stream. Finalization and source-wide Var fanout close
once per group. The source-only and witness paths use the same emitters.

The dedicated production `emitInto` APIs preserve standalone operation order.
The truth production view now lives in `truth_local_gkr/leaf.zig`; the historical
test module reexports its exact type. The retained660,292-byte CPU/frontier leaf
still accepts under its independently rebuilt original source identity, and the
group-of-one source graph exactly matches the standalone graph.

The1/2/4 source gate includes power-of-two padding and all six R6 roles:

| Direct group | FIXED cells | MAIN cells | INTER cells | Total cells |
| --- | ---: | ---: | ---: | ---: |
|1|19,896,320|42,541,056|42,254,336|104,691,712|
|2|39,727,104|85,016,576|83,984,384|208,728,064|
|4|79,388,672|169,967,616|167,444,480|416,800,768|

The four standalone wrappers alone cost520,104,448 cells, including native OM31.
The direct group saves19.86% against those wrappers and eliminates all three
additional fold proofs. Their cells are not counted in that lower-bound saving.
This counts committed source trace cells, not LDE/scratch/RSS or proving time;
FIXED setup may be reused by identity. Numerical/source parity, canonical frame
digests and child ninth-limb refusal pass under a12GiB budget, with664.2MB peak
requested allocation and zero teardown. No physical group proof or block speed
ratio is established by this source gate.

```sh
zig build check-riscv64-op-native-group -Doptimize=ReleaseSafe -j1
zig build test-riscv64-op-native-group -Doptimize=ReleaseSafe -j1
```

The bounded physical gate now proves all four native verifiers directly. Its
711,340-byte proof takes44.984seconds after12.920seconds of cold source/key
construction. A separately rebuilt source key verifies it and rejects changed
output, corrupted proof, and an independently verified old-topology root proof.
The public root is identical to the retained seven-node tree. The old tree
encodes1,274,831,872 cells versus416,800,768 here (3.059x fewer), including all
three eliminated folds. Requested peak is9,296,996,721 bytes under32GiB, with
zero final live allocation. This is a fixture qualification during concurrent
engineering, not a controlled OP block timing or a whole-block speedup.
See `vectors/reports/rv64-opstack-cpu-20261109/direct-native-group4-physical-v1.json`.

Before promotion: complete independent
execution/coverage/terminal/output admission, bounded group selection on actual
source classes, composed security accounting and full OP measurements. Admission
stays closed and the security label remains a128-bit target under documented
assumptions, with `security_qualified=false`.


## Complete actual execution (experimental)

The selected Kona guest for block120794432 now closes all796,406retirements,
124sponge calls/338permutations and34SHA calls through ONE physical grouped
root. Its four native members are CPU/frontier, detached sponge, local-GKR
Keccak and classic SHA. No wrapped child or intermediate fold proof is created.
The750,068-byte root accepts in a separate source-only process with the native
proof file physically absent. Eight physical proof/output/metadata/debt attacks
reject, followed by a restored positive control.

Prove/persist/native-root-check takes93.373seconds; total root producer121.133s
also includes native re-verification and cold source construction. Native proof
production is ADDITIONAL. A fresh CLI receiver takes22.609s rebuilding group
source/key authority, then30.151ms reading/verifying the root. Requested peak
18.885GB is below32GiB, with zero final heap/external retention. These runs
qualify correctness during concurrent engineering, not a quiet speed comparison.
The complete source model is830,730,240cells. Its QM31 role crosses the2^23
padding boundary; existing R7 dot lowering and a final-only b2/q144 PCS policy
are experiments to measure next, not established speedups.

```sh
zig build rv64-op-group-root -Doptimize=ReleaseFast -j1
rv64-op-group-root prove CONFIG DETACHED_NATIVE ROOT 4
rv64-op-group-root verify CONFIG SOURCE_ONLY ROOT 4
rv64-op-group-root qualify CONFIG SOURCE_ONLY ROOT 4
```

`SOURCE_ONLY` needs only `detached-op.json` and public `cells.bin`; ELF/input/
ABI/output remain independently pinned by CONFIG. Receiver-selected1/2/4 group
limit and profile must match. `model` generates source-only cost/key metadata
without claiming a root proof. `qualify` runs the retained adversarial corpus;
normal verification performs one root check. An optional resources.json bounds
host, worker and parked data ownership. Existing OP/Ethereum commands/defaults
and source-suite admission are unchanged.

Producer keys are built once per group and retired after its proof. Remaining
fold keys are derived lazily in canonical postorder and retired immediately;
no collection of wide parent keys is retained. Root metadata does not contain a
proposed VK. The receiver validates all native identities/ordinals/manifests,
all polynomial-shape advice against independently derived rosters, global claims
and terminal policy, then constructs its own group/fold keys. Root publication
requires the complete native callback and all closure plus physical acceptance.
Actual multi-group fold runtime qualification remains open; all768 numeric
planner cases already match the independent original tree implementation.

## Independently selected terminal PCS (experimental)

The native member profile stays `op_target_b4_q72_p0_fold4_v1`. An explicit
receiver policy can prove only the final group or final fold with the existing
`op_control_b2_q144_p0_fold4_v1` profile. All intermediate groups and folds retain
b4/q72. The native verifiers, full public frames, canonical ordered tree, global
RAM/KIO/Wire closure and pinned terminal output stay unchanged.

Use `--terminal-outer=b2-q144` on **both** producer and receiver; the optional
resources file can appear before or after the flag. `--terminal-outer=b4-q72`
is explicit default behavior. Old command arguments, B4 proof format/identity
and B4 metadata field order remain supported. A proof cannot choose this policy:
the receiver rejects metadata that differs from its selected terminal profile,
then derives the expected source key under that exact profile.

The b2 profile halves the commitment extension factor while doubling queries;
there is no recursive parent paying for the larger terminal opening proof.
Both profiles have nominal query-times-log-blowup product144 under the existing
FRI assumptions. This is **not** a composed security certificate. Native local
GKR/lookup bounds are unchanged; the outer source AIR, OM31 lookup mass and
characteristic bounds remain enforced. Hash-query unions, Fiat-Shamir, FRI and
recursive composition retain their documented assumptions. The label remains
“128-bit security target under documented assumptions”, `security_qualified=false`
and production admission closed. Reduced LDE work is a cost hypothesis until a
matched workload is measured; cold source setup and opening costs must be counted.

The matched selected four-member block gate now passes with this terminal policy:
1,341,688-byte proof,46.589s prove/persist/verify versus the retained B4
93.373s, and62.63s total producer including fresh native verification and cold
source setup. The original native proof production is additional. Requested
peak is13.313GB under32GiB, with zero final live ownership. A separate
native-bin-absent receiver reconstructs its key in11.413s and verifies in53.2ms;
eight retained physical attacks reject. The B4 default control still verifies
under its original identity, and both profiles authenticate the same canonical
public root. Both policy cross-selections reject; stripping the B2 metadata
policy to pretend B4 still rejects at physical key authority.

These are correctness qualifications during concurrent engineering, not a quiet
speed comparison or a heavy-block result. The first B2 attempt failed before
publishing any root because compact same-domain columns lacked host values;
the narrow OM31 shadow fix now has compact/full-storage byte parity and
allocation-failure coverage. The failure is retained in the receipt rather than
counted as a benchmark. See
`vectors/reports/rv64-opstack-cpu-20261109/grouped-terminal-b2-actual-small-v1.json`.

### Explicit R7 arithmetic policy

The experimental shared runtime also accepts receiver-pinned
`Options.arithmetization = .r7` (`--arithmetization=r7` on the grouped CLI).
The default remains R6, including its existing proof and metadata bytes. New R7
metadata records the arithmetic policy explicitly; a receiver checks that policy
before constructing wide source keys. Proof headers never select a fallback.

Both modes share native capture adapters, source admission, canonical planning,
public frames, tree ordering, bounded custody, and publication. Typed key owners
reuse the existing R6/R7 `Ref` and `Captured` dispatch. R7 source streams lower
whole DEEP numerators into native dot rows and finalize the complete eight-role
Var argument once. Subsequent R7 folds use the same verifier body as existing R7
recursion, with an explicit canonical R6 tree hash domain. Existing R7 fold
methods retain their original domain and source identity.

Native proofs retain their independent B4 profile. The optional final-only
B2/q144 outer policy remains separate from arithmetic selection. A fresh
receiver must select both policies explicitly, for example:

```sh
rv64-op-group-root verify config.json source-only root-directory 4 \
  --terminal-outer=b2-q144 --arithmetization=r7
```

The R7 source census of the selected 796,406-step block's four native fragments
has 643,035,136 committed trace cells, with QM31 rows at log23 instead of the
R6 census's log24. The actual one-group R7+B2 root qualified at 37.757 s for
node proving/persistence/verification, 51.743 s for the producer including native
reception and cold setup, and 8.965 GB peak requested allocation. Its fresh
source-only receiver accepts without the native proof file, rejects nine
physical/metadata controls including a valid opposite-format proof, and refuses
a stripped R7 policy under an independently reconstructed R6 key. These are
single qualification runs, not a controlled performance benchmark. See
`vectors/reports/rv64-opstack-cpu-20261109/grouped-r7-terminal-b2-actual-small-v1.json`.
Production source-suite admission remains closed; no heavy OP execution or proof
was repeated.

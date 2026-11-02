# Opaque streamed-bottom GKR storage

The qualified opt-in source route removes dense bottom numerator/denominator planes from tree construction and the last two GKR stages. Set `STWO_ZIG_GKR_STREAM_BOTTOM=1`. With `STWO_ZIG_GKR_TREE_CHECKPOINTS` unset it retains dense upper layers; setting that variable to `2` retains only alternating checkpoints. These choices are independent. The conservative non-streamed default remains available. This changes operational storage and replay work, never proof fields, transcript, relation classification, receiver, or security profile.

The numerical core accepts an opaque immutable `MultiplicitiesSource` with a variable count and joined raw-range callback. The callback writes at most 64 requested M31 numerator and secure denominator values from the caller's durable source. The frontend adapter maps these physical fact spans to the original NativeProvider and RowSink authority, using one 128-lane row scratch area and exact 0/1 padding. It never reconstructs expanded MAIN columns or stores a full raw plane. Metadata and challenges remain immutable until all joined work returns; no source pointer escapes in the resulting proof or artifact.

Both storage variants construct the first retained reduction from bounded raw tiles using the original adjacent fraction reductions. Dense-upper storage retains all subsequent layers. Checkpoint storage constructs the first even checkpoint and reconstructs missing odd levels using the qualified lazy checkpoint implementation. The final virtual and raw bottom stages replay bounded tiles for the original range sum evaluator and fold kernel. Raw numerator arithmetic stays in M31 until its first fold. That fold allocates only its half-sized secure outputs; subsequent rounds use the ordinary owned oracle. Constant masks read just their required values. No hidden pool, full-size replay buffer, expanded witness, or global cache is introduced.

All callback errors are collected per scheduler ordinal and inspected after the joined wave; output owners unwind before the borrowed source retires. The explicit `cloneOwned` interface materializes an independent owned raw layer because cloning an opaque borrower cannot otherwise preserve ownership semantics. The production source path uses owned sumcheck and never calls this clone path. Its full-raw-plane metric is zero; bounded raw tile scratch still exists and is not represented as a retained heap plane.

## Current resource contract

The frozen source-specific plan charges zero full raw-input bytes and retains a
conservative **80 bytes per padded fact** for dense-upper storage or **68 bytes
per padded fact** for checkpoint storage. These are payload terms, not complete
process-memory promises. Checked metadata, proof/artifact headers and the larger
of numerical versus terminal-binding construction phases are added separately.
Original backing capacity remains charged after logical shrink. Tight modes
execute under the exact admitted requested-byte cap; they do not fall back to a
less constrained allocator or a different storage choice on failure. Retained
MAIN/PCS, setup, recycler caches, stack scratch and allocator/kernel overhead
have separate accounting. The resource plan and actual numerical peak are
reported independently of RSS and footprint.

Before numerical execution, the environment is frozen once. Optional per-CPU
hybrid selection uses receiver-independent resource geometry to select80 or68;
its exact resolved policy is shared by admission and sealing and reported per
worker. A failed80 admission never silently retries68. See
`rv64-gkr-hybrid-tree-policy.md` for the explicit resource selector and its
negative full-block performance observation.

Qualification covers Q/OM exact proof/artifact/next-draw parity against frozen original source, fresh terminal MLE verification, mixed heights and tiny constant masks, signed/padded values, zero-pole propagation, callback shape and failure paths, owned clone independence, pooled and held-lease paths, and exhaustive allocation failure cleanup. The frontend range tests compare original dense inputs at row/padded-lane boundaries for widths through 128. Complete two-CPU plus Keccak, ADD and DOUBLE physical proofs freshly close all global obligations in Safe and Fast. Real CPU0 memory/time and source-bound gates are recorded separately; this prototype does not establish whole-protocol 128-bit security or GPU qualification.

## Earlier checkpoint-only experiment

The first source implementation deliberately retained the old104-byte admission
reserve until its smaller phase/capacity bound was qualified independently. The
following CPU0 experiment records that historical implementation, rather than
the current80/68 policy.

Real CPU0 used four same-binary alternating ABBA runs, toggling only the streamed-bottom flag with checkpoint2, q70/P26/fold4, sixteen workers, and the unchanged tight 104-byte admission. All sixteen authoritative artifact hashes match and all four independent fresh receivers accept. Numerical requested-owner peak falls from 7,233,043,898 to 2,691,389,018 bytes (62.79% lower). Full raw planes fall from 4,541,656,320 bytes to zero, while the old planned input reservation remains 4,541,656,320 bytes. Maximum RSS is 13,826,523,136 versus 11,047,092,224 bytes; it includes the rest of the prover.

Median proving time is 8.9322 to 9.2271 seconds, with total GKR time 2.6928 to 2.9150 seconds. Raw projection moves from the old input phase into the numerical phase, so numerical time alone is not an equivalent stage comparison. This is an observed modest CPU replay cost for a substantial owned-memory reduction, not a whole-block or GPU performance claim. The remaining requested peak closely matches the retained even-level bank (~64/3 bytes per fact); staggered sumcheck dimensions avoid materializing every instance's first folded half simultaneously. Those historical measurements preceded the separately qualified source-specific capacity and phase bounds now described above.

## Complete-block observations

The same pinned104,253,913-step Ethereum block, q70/P26 control and explicit
two-lane/eight-worker resource schedule produced these individual observations:

| Raw/tree storage | Keccak maximum log | Proving | Peak RSS |
| --- | ---: | ---: | ---: |
| Materialized / tight dense |18|242.44s|42.49GB|
| Streamed / dense upper |18|231.55s|38.07GB|
| Streamed / dense upper |16|224.75s|37.71GB|
| Streamed / alternating checkpoints |16|254.66s|30.17GB|

All complete receivers accept. Storage-only comparisons at the same geometry
match every durable proof/bundle/cell artifact. K16 changes the service roster,
so K16 versus K18 is execution/output/cell-accounting comparison, not whole-proof
byte parity. K16 increases the physical proof inventory from30 to36 proofs and
total proof bytes from27.07MB to43.44MB. It is not automatically a recursion win.
These observations combine memory, admission and concurrent scheduling effects;
no isolated same-security GKR-over-LogUp speedup follows from them.

Generated worker-phase accounting is in
`vectors/reports/rv64-gkr-tree-checkpoints-20261102/fullblock-phase-accounting.json`.
For streamed dense-upper K18, the measured sequential phase boundaries are95.32s
stage one and136.04s stage two. CPU numerical durations sum to103.50s and
CPU binding construction to15.97s; concurrent worker sums do not add to wall
time. The numerical GKR kernel is only part of the complete proof cost.

Receipts: `vectors/reports/rv64-om-ethereum-20261102/fullblock-stream80-k18-v1/`,
`fullblock-stream80-k16-v1/`, and `fullblock-stream68-k16-v1/`.

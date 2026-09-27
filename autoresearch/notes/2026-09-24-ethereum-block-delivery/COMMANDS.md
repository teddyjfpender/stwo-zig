# Canonical Ethereum block commands

The normal ReleaseFast stream and standalone receiver products build and have
freshly qualified the complete two-segment canonical joint-manifest fixture.
That qualification is recorded in `joint-two-segment-root-v1/qualification.json`.
The larger mainnet block and separate sorted-memory protocol are still pending.

```sh
python3 scripts/zig_serial_build.py \
  stwo-ethereum-block-stream stwo-ethereum-block-verify \
  -Doptimize=ReleaseFast -j1
```

`stwo-ethereum-block-stream` uses the same `ethereum_block_stream.zig` root as the
measurement executable. It executes, proves every segment, recursively folds
adjacent verified segments, and freshly verifies the completed root. Its arguments
are positional:

```text
stwo-ethereum-block-stream ELF INPUT EXPECTED_OUTPUT MAX_LEAF_CYCLES ROOT_PROOF REPORT canonical [paired] [joint] [schedule=PATH]
```

- ELF admission chooses the explicit Ethereum or Ethereum+SHA execution profile.
- `canonical` selects 70 queries and 26 PoW bits; `diagnostic` is a separate research
  option and is rejected by the canonical standalone receiver.
- `MAX_LEAF_CYCLES` is a ceiling, not a guaranteed admissible AIR geometry. The
  schedule balances the complete execution into a power-of-two leaf count and
  reserves final output publication inside the terminal leaf.
- `paired` is an explicit memory/time tradeoff. It proves adjacent executions
  into one parent; it does not omit either execution or their memory linkage.
- `joint` requires `paired`, canonical security, and exactly two scheduled
  execution segments. It commits both leaves first, derives a manifest from
  independently admitted span/key/geometry fields and exact cycle coverage,
  proves both under the shared challenges, and recursively proves their root.
  It retains the existing full-memory custody; it does not activate the separate
  sorted-memory AIR or a block-wide manifest for larger jobs.
- Proof and report paths must be fresh. The report's success flag is emitted only
  after the complete root has been freshly verified. The report is not itself a
  verification authority.

The measurement wrapper remains the preferred timing entry point. It accepts
an installed binary with `--binary zig-out/bin/stwo-ethereum-block-stream`, hashes
all workload inputs, and excludes the build from its timing. See README.md for
the running mainnet invocation and distinctions between partial and full results.

The receiver command is:

```text
stwo-ethereum-block-verify ROOT_PROOF REPORT TRUSTED_ROOT_KEY_HEX
```

The final argument must be the verifier's independently obtained 64-hex-character
root-key identity. **Do not obtain this pin from an untrusted received report.**
The report supplies bounded metadata; its claimed key is checked against the
external pin before proof I/O. The pin binds the key's canonical security,
component identities, preprocessing commitment and statement context. Verification
then checks the proof and complete Span root. Report timings, success flags and
workload file hashes are not accepted as cryptographic evidence.

The current root key is specialized to its admitted statement/context. This
command does not implement a public universal setup or manufacture independent
trust in a prover-selected key. A deployment must provide its own admission
configuration. The retained authentication artifact used by
`qualify_block_receiver.py` is trusted local test setup only.

`stwo-ethereum-block-proof` is the older research multiplexer for materialize and
replay commands. Its existing behavior is preserved; it is not the command for
the full BLAKE3 stream measured here.

## Larger-segment sizing

`build_segment_geometry.py` builds an admission-only census tool.
`run_segment_geometry.py` screens balanced 128/256/512-leaf schedules on the
SHA-profile mainnet fixture. Its entry, recovery-region and terminal records
report actual commitment row counts; `proof_verified` is always false. The
log-24 production trace limit is unchanged. A passing census does not establish
prover memory sufficiency, full-block coverage or recursive proof correctness.

The stream entry point additionally accepts `segment=N` in place of the optional
`paired` argument. This replays the normal balanced schedule, proves leaf N with
its full memory custody and verifies its recursive wrapper. It writes only the
report path: `segment_recursive_proof_verified=true` and
`complete_execution_proof_verified=false`. It does not write the requested root
proof path. This mode measures one real scheduled leaf without claiming a block
root or changing the canonical q70/PoW26 settings. Full block delivery continues
to require running without `segment=N` and independently verifying the root.

### Explicit work schedules (qualification in progress)

The stream accepts `schedule=PATH` alongside `segment=N` or `paired`. PATH holds
a JSON array of positive cycle budgets. The schedule is validated against full
execution preflight: the number of budgets must match the current power-of-two
span shape, all budgets must obey the command's maximum, their sum must equal the
full execution, and the last budget must cover terminal publication. Replay
checks every selected segment against that schedule; full root completion and
output checks are unchanged. The schedule file is a planning input, not proof
evidence.

The geometry tool accepts `all` instead of one target index and an optional final
schedule pathname. It emits one JSON line per segment, followed by a summary only
after exact coverage, completion and output checks. `plan_work_segments.py`
proposes schedules from a completed census using interpolated G-row density.
`qualify_work_schedules.py` independently replays the 256-leaf candidate, then a
512-leaf fallback if necessary. Passing all geometry checks still requires native
and full-custody recursive proof qualification before a long full-block run.

### Exact-count proof forest and memory census

The stream also accepts `exact`. With `schedule=PATH`, it admits a JSON array
of any positive segment count whose budgets sum to the complete execution and
cover terminal publication. Without an override it chooses an exact balanced
count. `paired` may be combined with `exact`; an odd final execution is proved
as a single leaf. No dummy execution leaf is proved. For example:

```text
stwo-ethereum-block-stream ELF INPUT EXPECTED_OUTPUT MAX_LEAF_CYCLES BUNDLE_JSON REPORT_JSON canonical paired exact memory-witness schedule=SCHEDULE_JSON
stwo-ethereum-block-exact-verify BUNDLE_JSON TRUSTED_ROSTER_DIGEST_HEX
```

The second command requires a 64-hex-character roster pin obtained independently
of the received bundle/report. It verifies each dyadic proof file with bounded
ownership and checks complete ordered segment/cycle coverage. The result is a
verified proof **forest**, not a single recursive root. `memory-witness` only
spools/sorts real accesses and reports the exact memory instance count;
`separate_memory_proof_verified` remains false. Every execution leaf retains its
existing full memory custody. The report's `memory_initial_sources` array is
ordered `[register, ordinary_RW, public_input_in_continuation_RW_root, program]`.
`exact-three-segment-v1/qualification.json` records the canonical three-segment
development fixture and its fresh receiver result.

For fast provider sizing, `qualify_memory_roster.py` runs the separate
`ethereum-block-memory-roster` host replay on that fixture without proving. It
checks its event/source census against the qualified proof report and writes
`exact-three-segment-v1/memory-first-touch.bin` as sorted 10-byte records:
`space u8`, `address LE u32`, `initial value LE u32`, `source u8`. This roster is
planning data; it cannot replace a PCS commitment or a proved initial-value bus.

`qualify_exact_schedule_geometry.py` rebuilds the admission-only geometry tool
and replays every segment of the 218-segment exact proposal. A passing geometry
scan is not a proof; the separate-memory component and complete-block root still
need cryptographic qualification.

`qualify_exact_memory_roster.py` replays that same proposed schedule and writes
the full sorted first-touch roster plus an 8-byte `(address,value)` roster of
all nonzero initial continuation RW leaves, including public input. The report
records its count and SHA256. The runner checks execution completion and output,
but these data remain host-only planning evidence until the execution and
memory AIRs prove their relation.

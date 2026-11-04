# recsize port onto the M4 base (stream diet, 2026-11-04)

Branch `codex/rv64-m4-recsize-port` takes the 4 commits of `codex/rv64-m3-recsize` (`5d68d0f01`) and rebases them onto
`bcd401ce4`, the M4 base. That base includes fold v2, the fold class cache and the M2a pipelined executor. A fix-up
commit on top generalises fold v2's `classKey` to N children.

This branch is **not for merging** now. M5/M7 own the merge; canon-vk owns `om31_outer.zig` and `execution_wrap.zig`, and
profiles owns the binding note.

## Conflict resolution

- **Message word.** `versionWord(2) = version` (2, the v2 binary message word), which keeps binary byte-identity with M3.
  k-ary folds use `(arity << 8) | version`, i.e. 0x302 and 0x402.
  - No two arities share a message.
  - The low byte still names the v2 semantics: guessed, digest-bound child keys.
- **`classKey`.** It now takes `[]const Child` and hashes the profile-aware domain (`domainName()`), then
  `versionWord(arity)`, then each child's geometry in order.
  - Binary keys under r1 are unchanged.
  - Different arities, or a different outer profile, never share a class.
- **`Authority.identityOf`.** The HEAD helper is kept, but it now hashes `P.domainName()`. That equals `P.domain` under the
  default r1 profile.
- **Pipelined route (M2a).** It stays binary and fails closed on arity ≠ 2 with `UnsupportedPipelinedFoldArity`. It uses
  the k-ary `Node` binary view (`left()`, `right()`, `isLeaf()`).
- **Sequential plan route.** The k-ary `runPreparedSequential` from recsize is kept. The serialize/write timings of HEAD's
  lane path are preserved, and receiver mode (`existing_only`) skips the writes.

## Tests (pod, CPU only, ReleaseFast)

See `cpu-tests.log` and `cpu-tests.summary.txt`. 6/6 build steps pass:
- **`check-rv64-ethereum-recursion`:** the whole recursion route type-checks.
- **`test-riscv64-om31-outer`:** the r1 binary fold root proves, and a fresh receiver accepts it. The output tamper is
  rejected. 702,968 bytes.
- **`test-riscv64-om31-m3-fold`:**
  - The m3 4-ary root proves on CPU (421.5 s) and a fresh receiver accepts it (6.8 s).
  - The output, the r1 receiver and the PoW tamper are all rejected. 389,180 bytes.
  - New assertions pass:
    - `versionWord` values for 2, 3, 4 and 5.
    - `classKey` differs across arities 2, 3 and 4.
    - `classKey` is equal for same-geometry children with different key values, and under child reordering.
    - `classKey` rejects arity 1.

The fold census matches the recsize receipt to within one compression (+80 G gates per binary fold), because v2 guesses
the child keys.

| profile / arity | fold vars | Blake G | vs r1 binary |
|---|---:|---:|---:|
| r1 q108, arity 2 | 19,127,713 | 3,769,520 | 1.00 |
| r1 q108, arity 4 | 38,253,638 | 7,538,960 | 2.00 |
| m3 b4 q51, arity 2 | 9,583,598 | 1,881,040 | 0.50 |
| m3 b4 q51, arity 4 | 19,165,401 | 3,762,000 | 1.00 |

## Not done

**No GPU byte-parity run.** `/workspace` on the pod was at 100% (79 MB free) when the driver build was due. That space is
held by other streams' build and run directories, not by this stream (about 0.7 GB). The r1 byte-identity of the port on
26235156 and 24628607 is therefore **unverified on GPU**. It is the first gate before M5 uses this branch.

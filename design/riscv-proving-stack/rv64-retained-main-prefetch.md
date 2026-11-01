# Bounded advice for the current worker's sealed MAIN

`--prefetch-retained-main-bytes=N` is a producer-only operational option, off
by default (`N=0`). Nonzero CLI/pipeline caps range from one actual host page
to 4GiB. Advice ranges round down to complete pages without exceeding the cap or
owned mapping. This is a per-worker bound on requested advice, not a global
cache, completed read count, reservation of resident pages or hard RAM limit.

After validating its sealed manifest entry, a worker optionally advises its own
stable MAIN before drawing/generating interactions. The kernel may overlap
paging with interaction generation/commitment and another lane's proving. No
next-job lookahead reads another worker tree. Current-worker exclusive access
continues through completion/deinit, and normal cancellation still joins lanes
before destroying their workers.

On supported Linux/macOS hosts, the advice is `madvise(MADV_WILLNEED)`. Unsupported
hosts use a counted no-op fallback. OS advice failure is nonfatal and counted;
the native coefficients remain valid for ordinary demand paging. Accepted advice
bytes mean the syscall accepted that requested range, not that all I/O completed
or that the range became resident. An error may itself have partial kernel
side effects; a zero successful-advice counter is not proof of zero I/O.

Mapped Store owners now have a Store-local intrusive registry. Numeric token
identity is checked under its mutex before interpreting any owner context, then
retained views are validated against the actual contiguous native arena. The
mapping remains leased throughout advice; release unlinks/unmaps under the same
mutex. Parked MAIN reuses the qualified parked-owner registry and restores only
this worker early. A successful early restore avoids the redundant later restore
after interaction commitment. No witness rebuild, recommitment, source ownership
change or process-global coefficient cache is introduced.

The `retained_main_prefetch` stage records call time and ordinary process/lane
usage. `retained_main` telemetry separately records calls, requested bytes,
successfully advised bytes, failed calls and unsupported calls. Counters describe
this optional operation; they do not enter any proof transcript. Immutable
setup/cache identities, per-lane budgets and owned truth transfers are preserved.

The four new runtime tests cover page-cap rounding, mapped/parked native value
and root parity, foreign contexts/retained-view rejection before advice, and
complete mixed CPU/Keccak/ADD/DOUBLE physical proof parity with fresh verification
in both storage modes. The existing allocation-failure, FD, restore and lifetime
suite remains a required regression gate. CLI cap/duplicate/producer-only tests
are part of the declared product root.

A current LS7 prefix control, 1GiB prefetch, and parked+1GiB prefetch each retain all
11 expected proof/public artifacts exactly and freshly verify. Each covers
16,777,212 instructions with four CPU and three truth proofs; none is a completed
block claim. Seven worker calls successfully advise 4,429,365,248 bytes total
while preserving the per-worker cap. Compilation was active during those runs,
so their wall observations do not qualify a speedup. Full combined queue/prefetch
measurements will use the receiver-qualified current source after integration.

Darwin `/usr/bin/time -l` page reclaims/minor faults and page faults/major faults
are whole-process OS counters across all mappings and input files. They do not
isolate retained MAIN, and minor faults must not be labeled exclusively anonymous
or major faults exclusively retained-file reads. Overlapping per-stage process
counters are not additive. Fault changes alone do not measure saved I/O traffic.

This changes no AIR, geometry, statement, public execution profile or proof
bytes. It does not qualify the requested whole-protocol 128-bit security target;
the existing nominal 96-bit control remains a control. No hard-memory or guaranteed
asynchronous-I/O claim is made.


Both complete retained-parking products pass in ReleaseSafe/ReleaseFast with a
27-test floor, retaining all original allocation-failure/lifetime gates. The
runtime-page followup also passes focused bounds tests in both modes. Exact
source, byte caps, hint counters, stage times and fresh-prefix results are pinned
in `vectors/reports/rv64-word16-execution-20261101/retained-main-prefetch-prefix-v1.json`.
The combined current-source full sweep belongs to the integration workstream;
this receipt does not claim that pending measurement already ran.

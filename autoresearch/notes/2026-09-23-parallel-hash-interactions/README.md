# Bounded parallel typed hash interactions

The canonical framework writer now divides independent tiles between worker-private
inversion workspaces, writes into the final committed columns, combines exact
field sums and performs the global shifted prefix after every helper has drained.
The serial and parallel routes share the same tile equations and prefix code.

The production adapter uses the existing proof pool with an explicit lease,
maximum eight workers and a 128 MiB inversion-scratch bound. Small domains,
unavailable worker reservations and the diagnostic
`STWO_RISCV_SERIAL_HASH_INTERACTIONS=1` switch use the serial route. No independent
thread pool is created. Extra helper workspaces are scoped to each component;
they are not yet retained between components or proofs.

Shared callers: full-width execution commitment columns (all profiles/backends),
BLAKE3 native recursion parent production, and compact range interaction providers.
No workload name or CSP-specific path chooses this optimization.

Focused tests cover exact column/claim parity, reversed completion order, zero
denominators, allocation cleanup and overlapping workspace rejection. Real-pool parity, unavailable-lease fallback and post-failure lease-drain tests
also passed. Proof and backend qualifications are recorded below.

`measure.py` runs three serial then three parallel samples per case in the same
binary, 16 workers, 70 queries / 26 PoW bits, without explicit warmups. It checks
all retained proof hashes against the preceding qualified compact-provider suite
and invokes fresh verification for each arm. All times include execution,
witness, admission, proving, encoding and fresh verification. Sampling order is
fixed, not randomized; these are local diagnostic comparisons.

## CPU qualification

ReleaseSafe focused suite: 5/5 passed, including the actual four-worker pool,
unavailable-lease fallback and reacquiring all workers after a zero-denominator
failure. CPU ReleaseFast product build passed.

| Case | Serial E2E s | Parallel E2E s | Serial hash interactions s | Parallel hash interactions s |
| --- | ---: | ---: | ---: | ---: |
| ECDSA precompile | 1.362768 | 1.178634 | 0.210719 | 0.034557 |
| SHA-256/128 | 4.146175 | 2.912084 | 1.513999 | 0.252607 |
| Keccak/128 | 9.083842 | 7.162147 | 2.496668 | 0.534828 |

All 18 measured CPU proofs verified in process. Every retained arm artifact also
verified in a fresh process and matches the previous compact-provider proof hash.
The ECDSA execution+witness+proving subtotal is 0.977914 s; its complete transaction
is 1.178634 s. This is still slower than the original 0.882 s proving-scope result.
SHA and Keccak remain substantially regressed against the original qualification.

Keccak sampled-value evaluation still takes 2.490914 s median. This change does
not address the coefficient-retention cutoff or barycentric scheduling cost.

## Metal qualification

ReleaseFast product build passed, with 177 exact Metal kernel exports and
AOT/JIT kernel parity. All 18 measured proofs verified in process; all six
retained arm artifacts independently verified and match preceding suite hashes.

| Case | Serial E2E s | Parallel E2E s | Serial hash interactions s | Parallel hash interactions s |
| --- | ---: | ---: | ---: | ---: |
| ecdsa_secp256k1-32 | 2.154700 | 1.947453 | 0.210462 | 0.036875 |
| sha256-128 | 4.306719 | 3.004454 | 1.547790 | 0.255541 |
| keccak-128 | 9.055408 | 7.178006 | 2.517520 | 0.534021 |

This is a targeted three-workload qualification, not a new full-suite benchmark.
No recursion-parent performance claim is made from the leaf measurements. The
native parent caller uses the shared adapter, but parent qualification after this
change remains to be run. The original CSP and broader recursion goals remain open.

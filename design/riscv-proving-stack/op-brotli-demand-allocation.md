# Demand-initialized Brotli allocation (opt-in)

The existing pinned protocol decoder initializes 32 MiB of u8, 4 MiB of u32 and
16 MiB of HuffmanCode storage for **each channel**, before it knows which cells
are needed. Its output/truncation and malformed-padding policies are retained.
The `lazy-brotli` feature replaces only these three allocation backends with safe
owned Vec-backed cells. Every requested cell is initialized; each live allocation
charges the original per-type capacity, and drop/free returns that exact charge.
No unsafe or read-before-write assumption is introduced. Original allocator
fragmentation behavior is intentionally not an acceptance requirement.

The genuine new mainnet transition contains three Brotli channels. Both native
variants accept the exact pinned output and produce byte-identical channel data.
Google's independent C Brotli decoder (Node 22.22.3/Brotli 1.1.0) agrees on all
three. Eager initialization is 54,525,952 bytes per channel; actual requested
initialized cells total 4,389,588 / 2,335,822 / 2,309,805 bytes respectively.
All three per-type live counters return to zero. This is allocation work, not a
measurement of RV64 retirements or physical proving improvement.

Focused tests cover capacity exhaustion, reuse/zeroing, owner lifetime, foreign
free, initialization-panic rollback, valid data, every short-input prefix,
output caps including zero, and three malformed-padding controls. The diagnostic
collector is native-only, bounded to 32 calls and 64 MiB of copied actual data.
`opstack/tools/brotli_census_compare.py` reproduces exact channel/reference checks.

Receipt: `vectors/reports/rv64-opstack-performance-20261109/brotli-lazy-native-v1.json`.
Selected/default guest/profile remain unchanged. Isolated RV64/Unicorn probes are
the next qualification gate. No complete transition replay or STARK was run.

## Bounded RV64 qualification

`brotli-probe` and `brotli-lazy` build variants execute the same BRP1-framed
isolated decoder. Their 43-byte BP diagnostic hashes the decoded output and binds
accept/reject plus length. BP cannot be admitted as an OP execution result.
`opstack/tools/brotli_probe_bench.py` enforces a maximum four-million-step cap.

The eager golden control did not finish within 4,000,000 instructions. The lazy
candidate completed the identical 10-byte plaintext in 48,493 instructions;
five-byte output truncation took 48,507; a malformed input took 46,982. Independent
Unicorn agreed on every completed output, all registers, PC and exact steps.
The setup-heavy golden probe therefore saves over 82× instructions relative to
the bounded control. This is **not** a whole-transition or proving multiplier.
The completed native real-transition channel checks remain the semantic control;
a full RV64 transition was intentionally not executed. Receipt:
`brotli-lazy-rv64-v1.json` in the same report directory.

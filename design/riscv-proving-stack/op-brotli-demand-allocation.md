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

# Concrete native batch bridge

`src/integrations/riscv_cpu/rv64_ethereum_batch.zig` joins one native execution
walk to the authenticated execution prover without retaining a retirement
journal. The caller owns and appends its compact tape and boundary capture;
`Batch.observe` reads immutable cached ROM decoding and records only counters,
register terminal clocks, and the adjacent PC. It does not execute instructions.

The batch snapshots initial PC/registers/global clock and first IDs for Keccak,
ADD and DOUBLE. It rejects changed source seeds, profile mismatch, instruction or
clock discontinuity. Provider counts cover all eight DIV/REM and five MUL
opcodes. Public admitted opcodes come from the complete independently derived
ProgramAuthority, never from the observed batch union.

`finish` runs against the current final native image, before the next batch
advances. It checks tape/capture/CPU steps and endpoints, derives independent
provider geometries and explicit empty rosters, sorts touched native words,
and creates private compatibility cells/clocks plus touched-chunk openings.
No touched words means null openings. No full memory snapshot, second execution,
or full retirement journal is created by this bridge. Compatibility arrays are
owned narrow copies; authority/tape/capture remain borrowed. Openings can be
transferred explicitly, and every allocation failure cleans up local ownership.

The focused ReleaseSafe gate includes actual mixed generator-point execution
with global clocks offset by 2^40, exact clock/cell/count comparison, exhaustive
finish allocation failures and retries, and the empty RAM/provider case. This
qualifies the native adapter; block-level proof completion and receiver endpoint
binding belong to the authenticated coordinator and block driver.

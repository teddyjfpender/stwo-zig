# OP Mainnet block 120794432: native proof and execution wrap

On 2026-11-08 a canonical GLV RV64 Kona guest replayed OP Mainnet
block `120794432` from the historical fixture pinned in
[`opstack/mainnet-fixtures.json`](../../../opstack/mainnet-fixtures.json).
The pinned upstream Kona host and independent Unicorn 2.1.4 execution agreed
with the RV64 run. Unicorn matched the terminal registers and output after
797,040 instructions; the guest made 124 sponge and 34 SHA-256 service calls.
The block has one transaction and used 43,851 gas.

The native runner produced one RV64 CPU STARK and two service STARKs. A fresh
`verify-candidate` process rebuilt authority, checked the complete bundle and
verified the same terminal output. It rejected a flipped midpoint bit in
`cpu-0.bin` (`WideBundleFileChanged`) and the same mutation with the manifest
checksum updated (`RootMismatch`). The test restored the exact bundle bytes.
The retained native bundle manifest has SHA-256
`968aacfe3a9c74f573a121e0f0ecdcd9c9f52df419903b4dba1b4cb8b19a8c84`.

| Stage | Wall time | Peak RSS | Outcome |
| --- | ---: | ---: | --- |
| Native production, Zig 0.15.2 LLVM `ReleaseSmall` | 58.902 s | 2.722 GiB | Complete bundle |
| Cold native receiver | 5.776 s | 1.923 GiB | Accepted; 0.183 s in proof verification |
| Initial native production, non-LLVM `ReleaseFast` | 900.160 s | 2.013 GiB | Timeout; no complete bundle |
| Execution recursion wrap, non-LLVM `ReleaseFast` | 289.969 s | Unmeasured | SIGKILL after admission of the first of three leaf graphs |

The LLVM `ReleaseFast` build of the linked recursion product ended with
`compiler command terminated unexpectedly`. The same compilation with the
non-LLVM backend built the executable used for the wrap. The wrap received a
1 GiB fixed-setup cap and a 5.5 GiB requested receiver budget, under a 600 s
wall limit. The process exited 137 before that limit with no saved leaf or
published root. The run did not reach `verify-recursion-candidate`. The source
of the kill was not independently established.

The ordered public fold fixture compiled with the non-LLVM backend. A separate
admission test rejected substituted child digests and transport roles. The
full synthetic child/parent proof test hit its 300 s cap before it reported a
parent graph, so there is no positive parent-proof measurement. This fixture
is separate from the Mainnet native replay; see [the receiver contract](../../../opstack/RECURSIVE.md).

[`receipt.json`](receipt.json) records program, input, source, fixture, runner,
and profile identities, exact command arguments and budgets, measurements,
and native bundle checksums. The absolute paths in its recorded invocations
identify run-local inputs and outputs. To replay on another machine, use the
historical fixture tooling and canonical GLV guest in [`opstack/`](../../../opstack/),
replace those paths with local paths, and check the pinned bytes and authority
before proving. The binary proof files are not included in this report.

This proves the native execution of the pinned historical OP input. It does
not establish L1 derivation, a verified recursive root, a joined checkpoint
proof, Solidity settlement, or certified whole-protocol 128-bit security. The
native profile is the repository's conjectured 128-bit FRI target.

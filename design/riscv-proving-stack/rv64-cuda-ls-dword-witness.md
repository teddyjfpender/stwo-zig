# Resident LS-D64 MAIN expansion

`rv64.dword_witness.packRouted(allocator, captured.advice.events[shard])`
stable-filters the same naturally aligned LD/SD events as the native services
pipeline. It writes fourteen words per event directly, avoiding an intermediate
native `Event` copy or the 39-column MAIN upload. The receiver-derived head/tail
geometry selects borrowed ranges of that compact buffer. CPU capture remains
outside this operation.

`resident.Commands.witnessDword` dispatches the context-owned kernel into the
existing native 39-column physical circle layout. Padding is written as zero.
GPU threads own consecutive physical output rows, deriving the logical compact
event index by the inverse circle/bit-reversal map. This keeps all MAIN stores
coalesced. The kernel derives after values, gap/carry limbs and addresses from
compact inputs; it does not introduce a second constraint authority. The native
source row oracle checks every output cell.

Compact ingress is 56 bytes/event, versus 156 bytes per MAIN row. Typed dispatch
checks geometry, capacity and ownership before enqueue, records one launch and
poisons failed jobs. Native dispatch checks allocation custody, disjointness and
the required inactive terminal row. Invalid event flags, clocks, epochs, rights
and alignment set a sticky verdict and emit a zero row. Verdict success alone
does not authenticate an event: MAIN constraints, OWNER and RAM closure remain
mandatory in the proving controller.

The focused RTX 5090 run matches native rows at logs 5, 13 and 20, including
empty/padded instances, signed-immediate wraparound, clock carries and epoch
transitions. Fourteen malformed-event variants and foreign-owner/alias/capacity
mutations reject. The current host suite passes 77 tests. The million-event
case generates 40,894,464 MAIN cells in a 0.224896 ms CUDA-event median over nine
warm samples (0.005499 ns/output cell). The kernel uses 56 registers and no stack
or spills.

This is trace-stage timing on valid randomized events at production-sized
geometry. It excludes capture, packing, PCIe traffic, proving and verification;
it is neither an Ethereum segment timing nor an end-to-end cost per committed
cell. Actual Ethereum-event and driver integration remain open. This focused
iteration does not rerun the four sanitizer tools or claim their qualification.
The compact receipt is in
`vectors/reports/rv64-cuda-ls-dword-witness-20261103/qualification.json`.

The native oracle is exported with `rv64-ls-dword-fixtures`. The normal GPU test
is `tests/cuda/rv64/ls_dword_witness_smoke.cu`, linked with the native context and
`ls_dword_witness.cu`. Large fixture files stay in scratch storage.

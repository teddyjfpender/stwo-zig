# M7 compact CPU witness ingress

Status: production GPU path implemented behind `STWO_RV64_CPU_COMPACT_INGRESS=1`;
both-block proof parity, independent receivers and numerical/memory-safety
gates pass. The flag remains off by default: serial host packing offsets the
metadata transfer reduction in these initial paired service measurements.

The transfer record is 16 bytes: result `u64`, authenticated ROM-row index
`u32`, and next PC `u32`. Each 256-row chunk also carries a 384-byte seed:
32 register values and 32 access clocks. Full chunks therefore transfer
17.5 bytes per retired instruction, replacing the previous 56-byte CPU
metadata transfer. This figure covers CPU metadata only; other native fact
and memory transfers remain separately charged.

The host capture already checked each register read and write. A chunk's seed
takes the value and clock preceding the first touch of each register from that
capture. One GPU warp reconstructs the chunk, one lane per register. It visits
rs1, rs2 and rd accesses in the original order (including register aliases),
then applies the rd write. Independent chunks can run in parallel; there is no
whole-segment serial register scan. x0 remains zero. The generated metadata is
the original 56-byte device ABI, so downstream consumers and the existing CPU
MAIN formatter are unchanged. MAIN, range histograms and ROM multiplicities
remain resident.

Packing happens before acquiring the per-device projection mutex and outside
the synchronous service callback, allowing other workers' GPU work to proceed.
The unpack kernel shares the witness stream. Ingress joins before unpacking;
the existing joined status readback refuses an invalid ROM row or metadata.
Scoped allocation, generation, range and read/write-alias checks apply before
every kernel launch. Borrowed compact uploads are joined before release.

This changes witness construction only. It introduces no protocol, transcript,
claim, topology or proof-format change. The full acceptance gate compares all
native bins, the bundle, every recursive node proof and the tree with explicit
M6 k4-cap3 receipts, then runs fresh CPU-only receivers with caches disabled.
A wrong chunk seed must fail the original CPU/register AIR and independent
native/recursive proof verification.

Measured [M] numerical gate: seven register-consistent cases cover counts
1, 255, 256, 257, 4097 and 100003, plus a non-power-of-two 17-row chunk. Every
reconstructed metadata word matches the independent CPU reference. Invalid
chunk geometry, reserved version word, output bounds and ROM row reject.
Compute-sanitizer memcheck reports zero errors. These are formatter/control
results; production latency and whole-native H2D improvements are measured by
the separate service receipts.

Measured [M] production gate, same binaries with ingress off/on, two dev blocks
and three requests each: all six compact requests preserve every M6 native bin,
bundle, recursive proof, tree and root byte. Fresh CPU-only, cache-disabled
receivers accept both blocks. The explicit M6 comparison is in
`compact-on-m6-parity.json`; `compact-source-and-transfer.json` binds the five
production source files by SHA256 because the build marker preceded a keyword
correction. Those hashes match the committed sources.

CPU metadata H2D per request falls from 857,118,024 to 267,849,456 bytes for
block 26235156 and 1,506,107,512 to 470,658,704 bytes for block 24628607. This is
a 68.75% metadata reduction. Whole-native H2D and the 80-byte target are not
qualified by this narrower counter. Serial host packing costs roughly 0.30 and
0.50 seconds across each request's segments. The warm native medians off/on
are 3.021/3.241 seconds (small) and 4.5605/4.549 seconds (headline); warm request
medians are 13.480/13.5885 and 18.662/18.4905 seconds respectively. Loaded-pod
measurements show no consistent native latency win, so this version is opt-in.
The next optimization parallelizes independent chunk packing.

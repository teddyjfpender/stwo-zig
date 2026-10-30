# Initial and terminal execution boundaries

`block_v8_full_boundary_policy_v1.zig` independently derives the initial state
from the pinned ELF and input bytes using the authoritative execution-session
initializer. The entry PC, x2 stack pointer, x3 global pointer, other zero
registers, all ELF-loaded words and the input overlay enter the initial snapshot
identity. Initial admission requires first cycle 1 and the exact snapshot/CPU;
there is no skipped-first-instruction permission.

The external full statement pins ELF/input hashes, total instruction count,
expected 43 output bytes and security configuration. Its initial and terminal
policy IDs are separate domains; a full-boundary digest binds both. These are
public admission operands, not successful verification receipts. The upper
root must authenticate the child keys/public supplies and bind the first and
last IDs, exact coverage and CPU/snapshot adjacency.

The terminal ABI is derived from the ELF's halt, output-length and output-data
symbols. The final halt word must equal 1, output length must equal 43 and the
43 output bytes must equal the independently pinned expected output. The
retained ABI's success byte at offset 32 must be 1. Completion must be the
halt-flag reason; a host ECALL exit is not silently treated as this statement.

A terminal `Window` forces the halt word, length word and eleven output words
into the independently reconstructed compact RAM boundary table, including
unchanged output words. Its fixed columns anchor the actual final RAM values,
not merely a host output hash. Global RAM's first/last endpoints close against
that table, and the narrow late bridge binds those transitions to the exact
endpoint-main roots authenticated by native or mixed original proofs. The
unused fourth byte of the last output word is not an output byte; its actual
memory value still remains fixed by the snapshot-derived RAM boundary.

Every native load/store row retains the per-access halt guard. It permits a
nonzero after-value only at the last instruction of the last cohort. Its
instruction clock is distinct from the completion access clock: the latter
must equal `4 * local_cycles - 1`, the third access of the final instruction.
Caller accesses retain the zero-halt policy at every instruction, so terminal
completion must arise from a native store. An earlier write-one/clear-zero
sequence cannot be hidden by matching the final snapshot. Native terminal
completion contributes zero unretired ROM fetches; intermediate cohorts still
contribute their authenticated unretired next instruction.

Default empty boundary options preserve the existing nonterminal policy and
transcript. Explicit initial/terminal ports add a separate Window transcript
frame before commitments. Fresh Directory receivers receive these ports from
the external full statement; producer JSON cannot authorize them. A terminal
artifact presented with the old nonterminal policy rejects.

The native benchmark's `--full-execution-boundaries` option reads independently
pinned `input.bin` and `expected-output.bin`. Common strict environment inputs
are `STWO_B8_FULL_INPUT`, `STWO_B8_EXPECTED_OUTPUT`,
`STWO_B8_TOTAL_CYCLES`, `STWO_B8_FULL_INPUT_SHA256` and
`STWO_B8_EXPECTED_OUTPUT_SHA256`. These options do not themselves assert a
complete Ethereum proof; that requires the initial-to-terminal folded root.

## Qualified complete fixtures

The native first-through-terminal original bundle passed all 11 tests. A
second gate wrapped its two native, bridge and compact-memory originals into
one genuine q70/26 recursive root and again passed all 11 tests. The fresh
receiver reloaded only encoded public metadata and root bytes after all
producer/capture/key/profile owners were destroyed, independently derived a
new full policy, and called `UpperReceiver.verifyFull`. Missing initial or
terminal ports, a skipped first instruction and a different expected output
all reject at the root receiver.

The retained native fixture root is 981,445 bytes, SHA-256
`864099a4a732d43732665d559f1e7d86c4c42835ac7ff3582a10edf79a8ad9de`.
Its proof, public metadata, policy IDs, log and receiving-source hashes are in
`campaign/qualification/new-full-boundary-root-q70-v1/`.

The terminal mixed fixture also qualified: nine actual retirements, one
Keccak call at cycle 3 and the final native halt store at cycle 9. Its mixed,
bridge and compact originals became one q70/26 root; fresh full receiving and
missing-port/wrong-output negatives passed (485 tests, one skipped in its
complete suite). The 1,021,354-byte root has SHA-256
`f204e46da61d61b2d38516da5b6ae0c3cc57284f18d3d751d491e7f7361acca9`;
proof and public metadata are retained in
`vectors/reports/riscv-cpu-architecture-20261029/terminal-mixed-root-qualification-v1/`.

These are complete small executed fixtures, not an assertion that the retained
139,214,856-instruction Ethereum block has already been proved. That result
requires the separately orchestrated full driver, all windows and final fold.

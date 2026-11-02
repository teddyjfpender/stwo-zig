# Portable prepared root-chain work, version 1

The collector executes once and writes a narrow job. A fresh process reads that
job, derives immutable program/policy authority from its own pinned request, and
constructs one wide witness without a VM, native RAM image, execution replay or
all-RAM snapshot. This format is the qualified root-chain control. Its content
SHA and native value roots are not distributed phase-one PCS commitments.

`rv64_prepared_work_packet.zig` exposes a borrowed `View` for the collector and
an owning decoded `Packet` for the worker. The borrowed view contains metadata,
`Native.Finished`, optional `NativeFrontier.Prepared`, and compact `Tape`.
Writing never consumes these owners. Reading returns independent narrow owners;
failure frees every partial allocation. The existing worker may subsequently
consume openings/graph and clear Tape; ordinary `Packet.deinit` remains safe.

The explicit little-endian frame is:

| Section | Representation |
|---|---|
| Header | 384 bytes: version, exact sizes/counts, index/first-step, identities, roots, content digest |
| Compact public boundary | 768 bytes, with no program, opcode mask or public RAM-cell ledger |
| Private touched cells | 32 bytes each: address/initial/final u64, clock u32, rights u8, three zero bytes |
| Openings | Sorted u64 chunk indices; flat before/after u64 words, u32 clocks and u8 rights |
| Native graph | Existing qualified frontier frame, including full permutation I/O |
| Tape | Existing qualified Tape frame, last, with exact EOF |

Private opening descriptors are rebuilt as views into owned flat arrays. Their
indices, shape, clocks, rights and first/last values must match the sorted private
cells. Geometry is restricted to 512-byte chunks. Supported execution profiles
are the two Ethereum service ABIs with either legacy-byte or packed control;
the broader inner Tape/graph wire qualifications do not broaden this worker ABI.
The worker hydrates program and opcode policy only from its expected Authority.

Request identity separately binds ELF/input pins, terminal contract, immutable
policy, immutable program/profile/control key, symbols and semantic budgets.
The selected state policy is independently expected, never accepted merely
because a packet repeated an opaque request digest. Future representation
policies need an explicit trusted-input/wire identity migration. The content
digest is a corruption/job identity, not execution authority.

Before payload allocation, the reader checks exact file size, header/identity,
streamed content digest, encoded and decoded allocation budgets, inner frame
counts and canonical provider geometry. A streamed PC walk through independently
decoded ROM verifies actual DIV/MUL, ordinary memory and service counts. It does
not execute instructions or construct arithmetic hints. This rejects a small
packet that lies about counts/logs to induce an enormous wide provider arena.
Both encoded bytes and conservatively admitted decoding allocation are capped
at 512 MiB. No whole encoded Tape copy is allocated by the writer or reader.

Atomic publication uses an exclusive random pending file in the destination
directory, mode0600. It streams the complete job, computes/records its digest,
syncs the file, then uses same-directory `linkat` for exclusive final publication.
It never renames over or removes an existing final target. Identical retries
verify length, recorded digest and recomputed content before syncing; conflicting
targets fail unchanged. The containing directory is synced before success.
The outer collector must also sync newly created directory entries in their
parents before its first cache publication.

The Native handoff callback returns only after that publication succeeds; only
then may the collector publish the sparse Cache patch and reuse capture/Tape.
A failed callback leaves the Cache and prepared phase unchanged. The qualified
native frontier's durable phase also permits publication retry without repeating
the callback. A visible pending filename never means the job is ready.

Eight focused ReleaseSafe and ReleaseFast tests passed. They cover both ABIs and
controls, high-u64 values/PC/addresses/global clocks, native Memory/Cache death,
no-RAM jobs, Tape crossing 64-KiB buffers, exhaustive decode OOM, truncation and
budget rejection, identity/state/policy mismatch, recomputed-digest count/log
inflation, opening aliases, unsupported geometry, failed handoff, corrupt stored
digest and concurrent same/conflicting publications. Gate logs are
`/tmp/rv64-work-packet-safe.log` and `/tmp/rv64-work-packet-fast.log`.

The separate process pilot collected two 65k jobs and proved job1 before job0
existed. Fresh finalization and a separate prefix receiver accepted 131,072
instructions. Job0 matched the previous serial proof exactly; this demonstrates
real out-of-order process work without execution replay. Final directory-sync
rerun evidence is recorded by the process coordinator's qualification receipt.
Each worker result remains a conditional root-chain fragment until the canonical
receiver checks the complete expected prefix/terminal contract.

The future distributed protocol is separate: workers first return actual PCS
roots for all tuple/multiplicity-bearing advice, the coordinator seals the
complete ordered manifest, and each worker/receiver independently derives the
shared challenges. No PacketV1 hash/native-root field or caller-supplied alpha
can substitute for those commitments. Global RAM activation additionally requires
the real aggregate receiver and initialization/teardown/terminal proof closure.

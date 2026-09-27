//! Canonical segment-to-recursive-child orchestration with caller-owned admission.
//! The verifier is reusable; the execution owner is single-use once proving starts.
const std = @import("std");
const execution = @import("blake3_execution_proof.zig");
const segment = @import("blake3_segment_execution.zig");
const parent = @import("../recursion/blake3_execution_parent_preparation.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const aggregate = @import("../recursion/blake3_execution_aggregate.zig");
const hash_columns = @import("../recursion/blake3_native_hash_columns.zig");
const custody_rows = @import("../recursion/air/blake3_parent_custody_rows.zig");
const Custody = @import("../recursion/air/blake3_memory_custody.zig").Prepared;
const binding = @import("../recursion/blake3_execution_span.zig");
const manifest_mod = @import("block_commitment_manifest.zig");
pub fn ForBackend(comptime Backend: type) type {
    return ForExecutionProfile(Backend, .rv32im_zkvm_v1);
}
pub fn ForEthereumBackend(comptime Backend: type) type {
    return ForExecutionProfile(Backend, .rv32im_zkvm_ethereum_v1);
}
pub fn ForEthereumShaBackend(comptime Backend: type) type {
    return ForExecutionProfile(Backend, .rv32im_zkvm_ethereum_sha_v1);
}
const Pool = @import("stwo_prover_engine").work_pool.WorkPool;
fn ForExecutionProfile(comptime Backend: type, comptime profile: @import("../isa/execution_profile.zig").ExecutionProfile) type {
    const sha = profile == .rv32im_zkvm_ethereum_sha_v1;
    const extended = profile != .rv32im_zkvm_v1;
    return struct {
        const Api = if (sha) @import("blake3_ethereum_sha_proof.zig").ForBackend(Backend) else if (extended) @import("blake3_ethereum_proof.zig").ForBackend(Backend) else execution.ForBackend(Backend);
        const FirstRound = if (extended) Api.FirstRound else void;
        const Verified = if (sha) @import("blake3_ethereum_sha_proof.zig").Verified else if (extended) @import("blake3_ethereum_proof.zig").Verified else execution.Verified;
        const Owner = if (sha) @import("blake3_ethereum_witness.zig").ShaOwner else if (extended) @import("blake3_ethereum_witness.zig").Owner else segment.Owner;
        /// Borrows all inputs. Checks admission and custody before generating
        /// interactions. The returned preparation owns its columns and retains
        /// no pointers into the execution owner, verifier or conversion witnesses.
        /// Failed proving may consume the execution owner's interaction phase;
        /// rebuild that owner before retrying. Admission failures leave it usable.
        pub fn prepare(a: std.mem.Allocator, owner: *Owner, verifier: *Api.PreparedVerifier, expected: [32]u8, statement: spans.SpanStatement, capacity: u32) !parent.Prepared {
            if (extended) @compileError("Extension segment preparation requires prepareWithPool");
            return prepareWithPool(a, owner, verifier, expected, statement, capacity, null);
        }
        /// The caller binds this pool for the complete preparation transaction.
        pub fn prepareWithPool(a: std.mem.Allocator, owner: *Owner, verifier: *Api.PreparedVerifier, expected: [32]u8, statement: spans.SpanStatement, capacity: u32, pool: ?*Pool) !parent.Prepared {
            if (extended and pool == null) return error.MissingExecutionPool;
            var admitted = try admit(a, owner, verifier, expected, statement);
            defer admitted.deinit();
            return proveAdmitted(a, owner, verifier, expected, statement, capacity, &admitted, pool);
        }
        /// Both children are independently pinned and fully admitted before
        /// either interaction phase is consumed. Owners/verifiers remain borrowed;
        /// after proving starts a failure may require rebuilding either owner.
        pub fn preparePair(a: std.mem.Allocator, owners: [2]*Owner, verifiers: [2]*Api.PreparedVerifier, expected: [2][32]u8, statements: [2]spans.SpanStatement, capacity: u32) !aggregate.Fold {
            if (extended) @compileError("Extension segment pairing requires preparePairWithPool");
            return preparePairWithPool(a, owners, verifiers, expected, statements, capacity, null);
        }
        /// The caller binds this pool for the complete preparation transaction.
        pub fn preparePairWithPool(a: std.mem.Allocator, owners: [2]*Owner, verifiers: [2]*Api.PreparedVerifier, expected: [2][32]u8, statements: [2]spans.SpanStatement, capacity: u32, pool: ?*Pool) !aggregate.Fold {
            return preparePairInternal(false, a, owners, verifiers, expected, statements, capacity, pool, null);
        }
        /// Consumes distinct execution owners on every path, including admission
        /// failure. An aliased owner is destroyed once. Verifiers stay borrowed.
        /// Each execution owner is released after capture and planning. Captures
        /// and custody remain alive until final-layout emission and attachment.
        pub fn preparePairOwnedWithPool(a: std.mem.Allocator, owners: [2]*Owner, verifiers: [2]*Api.PreparedVerifier, expected: [2][32]u8, statements: [2]spans.SpanStatement, capacity: u32, pool: ?*Pool) !aggregate.Fold {
            return preparePairInternal(true, a, owners, verifiers, expected, statements, capacity, pool, null);
        }
        const JointInputs = struct { context: manifest_mod.Context, admissions: [2]manifest_mod.Admission };
        const JointProof = struct { roots: [2][2][32]u8, manifest: manifest_mod.Sealed };
        /// Borrowed variant for admission checks and callers retaining owners.
        pub fn preparePairWithManifest(a: std.mem.Allocator, owners: [2]*Owner, verifiers: [2]*Api.PreparedVerifier, expected: [2][32]u8, statements: [2]spans.SpanStatement, context: manifest_mod.Context, admissions: [2]manifest_mod.Admission, capacity: u32, pool: *Pool) !aggregate.Fold {
            if (!extended) @compileError("Joint manifest requires an extension execution profile");
            return preparePairInternal(false, a, owners, verifiers, expected, statements, capacity, pool, .{ .context = context, .admissions = admissions });
        }
        /// Owns both admitted children. Every child is committed before the
        /// common roster is sealed; a mismatched replay root fails before its
        /// interaction phase. The caller independently supplies the component
        /// census and its exact work coverage.
        pub fn preparePairOwnedWithManifest(a: std.mem.Allocator, owners: [2]*Owner, verifiers: [2]*Api.PreparedVerifier, expected: [2][32]u8, statements: [2]spans.SpanStatement, context: manifest_mod.Context, admissions: [2]manifest_mod.Admission, capacity: u32, pool: *Pool) !aggregate.Fold {
            if (!extended) @compileError("Joint manifest requires an extension execution profile");
            return preparePairInternal(true, a, owners, verifiers, expected, statements, capacity, pool, .{ .context = context, .admissions = admissions });
        }
        fn preparePairInternal(comptime consume: bool, a: std.mem.Allocator, owners: [2]*Owner, verifiers: [2]*Api.PreparedVerifier, expected: [2][32]u8, statements: [2]spans.SpanStatement, capacity: u32, pool: ?*Pool, joint_inputs: ?JointInputs) !aggregate.Fold {
            var owned = [2]bool{ consume, consume and owners[0] != owners[1] };
            defer for (owners, owned) |owner, live| {
                if (live) owner.deinit();
            };
            if (extended and pool == null) return error.MissingExecutionPool;
            if (owners[0] == owners[1]) return error.AliasedAggregateChildren;
            _ = try spans.SpanStatement.fold(statements[0], statements[1]);
            var left_admission = try admit(a, owners[0], verifiers[0], expected[0], statements[0]);
            var left_admission_alive = true;
            defer if (left_admission_alive) left_admission.deinit();
            var right_admission = try admit(a, owners[1], verifiers[1], expected[1], statements[1]);
            var right_admission_alive = true;
            defer if (right_admission_alive) right_admission.deinit();
            var joint: ?JointProof = null;
            var first_rounds: [2]?FirstRound = .{ null, null };
            defer if (comptime extended) for (&first_rounds) |*round| if (round.*) |*ready| ready.deinit(a);
            if (joint_inputs) |inputs| {
                if (!extended) return error.UnsupportedExecutionProfile;
                const expected_context = try @import("block_execution_admission.zig").context(statements, verifiers[0].config);
                if (!std.meta.eql(inputs.context, expected_context)) return error.InvalidComponentCensus;
                for (verifiers, expected, statements, inputs.admissions, 0..) |verifier, id, child, admission, i| {
                    if (!std.meta.eql(verifier.config, inputs.context.config)) return error.InvalidComponentCensus;
                    const derived = try @import("block_execution_admission.zig").derive(verifier, id, child, profile, @intCast(i));
                    if (!std.meta.eql(admission, derived)) return error.InvalidComponentCensus;
                }
                var roots: [2][2][32]u8 = undefined;
                for (owners, verifiers, expected, &roots, &first_rounds) |owner, verifier, id, *slot, *round| {
                    round.* = try Api.commitFirstRound(a, owner, verifier, id);
                    slot.* = round.*.?.roots;
                }
                var builder = try manifest_mod.Builder.init(inputs.context, &inputs.admissions);
                for (roots, 0..) |pair, i| try builder.append(@intCast(i), pair);
                joint = .{ .roots = roots, .manifest = try builder.seal() };
            }
            // Captures remain at stable addresses until their plans are consumed.
            var left_capture = try proveCapture(a, owners[0], verifiers[0], expected[0], pool, if (joint) |j| .{ .first = &first_rounds[0].?, .roots = j.roots[0], .manifest = j.manifest } else null);
            defer left_capture.deinit();
            var left_plan = try parent.State.plan(a, verifiers[0], &left_capture, expected[0], capacity);
            defer left_plan.deinit();
            if (consume) {
                owners[0].deinit();
                owned[0] = false;
            }
            var right_capture = try proveCapture(a, owners[1], verifiers[1], expected[1], pool, if (joint) |j| .{ .first = &first_rounds[1].?, .roots = j.roots[1], .manifest = j.manifest } else null);
            defer right_capture.deinit();
            var right_plan = try parent.State.plan(a, verifiers[1], &right_capture, expected[1], capacity);
            defer right_plan.deinit();
            if (consume) {
                owners[1].deinit();
                owned[1] = false;
            }
            var shared = try hash_columns.Shared.initReserved(a, .{ left_plan.layout, right_plan.layout }, .{
                try custody_rows.hashCounts(.{ &left_admission.entry, &left_admission.exit }),
                try custody_rows.hashCounts(.{ &right_admission.entry, &right_admission.exit }),
            });
            defer shared.deinit();
            var left = try emitAttached(a, &left_plan, try shared.partition(0), verifiers[0], &left_capture, expected[0], statements[0], &left_admission);
            var left_alive = true;
            defer if (left_alive) left.deinit();
            left_admission.deinit();
            left_admission_alive = false;
            var right = try emitAttached(a, &right_plan, try shared.partition(1), verifiers[1], &right_capture, expected[1], statements[1], &right_admission);
            right_admission.deinit();
            right_admission_alive = false;
            // Aggregate preparation consumes both partitions on every path.
            left_alive = false;
            return aggregate.prepareShared(a, &left, &right, statements, &shared.owner);
        }
        const Admitted = struct {
            entry: Custody,
            exit: Custody,
            fn deinit(self: *@This()) void {
                self.entry.deinit();
                self.exit.deinit();
            }
        };
        fn admit(a: std.mem.Allocator, owner: *Owner, verifier: *Api.PreparedVerifier, expected: [32]u8, statement: spans.SpanStatement) !Admitted {
            try verifier.validate(expected);
            try statement.validate();
            if (statement.body != .executed or statement.slots.height != 0) return error.InvalidExecutionSpan;
            const pin = try owner.admission();
            if (extended) {
                try Api.validateForProving(owner, verifier, expected);
            } else {
                if (owner.native.compact_ranges) |ranges| {
                    if (verifier.ranges == null) return error.CompactRangeProtocolNotAdmitted;
                    try Api.validateCompactForProving(owner.native, owner.hashes, pin);
                    const actual = try verifier.key.identityCompact(&owner.native.statement, pin, verifier.config, ranges.plan);
                    if (!std.mem.eql(u8, &actual, &expected)) return error.UntrustedExecutionKey;
                } else {
                    if (verifier.ranges != null) return error.CompactRangeProtocolNotAdmitted;
                    try Api.validateForProving(owner.native, owner.hashes, pin);
                    try verifier.key.admit(&owner.native.statement, pin, verifier.config, expected);
                }
            }
            const shape = if (extended) &verifier.native else &verifier.shape;
            var entry = try owner.memory.prepareContinuation(a, .entry, &shape.public_data, verifier.admission(), statement.body.executed.entry.rw_memory, 1_000_000_000, 999_999_999);
            errdefer entry.deinit();
            var exit = try owner.memory.prepareContinuation(a, .exit, &shape.public_data, verifier.admission(), statement.body.executed.exit.rw_memory, 1_010_000_000, 1_009_999_999);
            errdefer exit.deinit();
            try binding.validate(a, statement, &shape.public_data, verifier.admission(), verifier.config, &entry.plan, &exit.plan);
            return .{ .entry = entry, .exit = exit };
        }
        fn emitAttached(a: std.mem.Allocator, plan: *parent.Planned, columns: hash_columns.Owner, verifier: *Api.PreparedVerifier, capture: *Verified, expected: [32]u8, statement: spans.SpanStatement, admitted: *Admitted) !parent.PartitionPrepared {
            const state = try plan.emitPartition(columns);
            defer state.deinit();
            var result = try state.finishPartitionReleasingRows();
            errdefer result.deinit();
            try parent.attachSpan(a, &result, verifier, capture, expected, statement, .{ &admitted.entry, &admitted.exit });
            return result;
        }
        const JointLeaf = struct { first: *FirstRound, roots: [2][32]u8, manifest: manifest_mod.Sealed };
        fn proveCapture(a: std.mem.Allocator, owner: *Owner, verifier: *Api.PreparedVerifier, expected: [32]u8, pool: ?*Pool, joint: ?JointLeaf) !Verified {
            // Opt-in stage telemetry for recursive end-to-end comparisons. It
            // observes actual leaf work without changing scheduling or proofs.
            const profiled = std.process.hasEnvVarConstant("STWO_RISCV_SEGMENT_PARENT_PROFILE");
            var timer: ?std.time.Timer = if (profiled) try std.time.Timer.start() else null;
            const proof = if (extended) if (joint) |j| try Api.proveCommittedWithManifest(a, owner, verifier, expected, j.first, j.roots, j.manifest, pool.?) else try Api.prove(a, owner, verifier, expected, pool.?) else if (verifier.ranges != null) try Api.proveCompact(a, owner.native, owner.hashes, try owner.admission(), verifier.config) else try Api.prove(a, owner.native, owner.hashes, try owner.admission(), verifier.config);
            @import("stwo_prover_engine").measurement.process_usage.reportStage("segment.leaf_proved");
            const proving_ns = if (timer) |*t| t.read() else 0;
            const capture = if (extended) if (joint) |j| try Api.verifyCaptureWithManifestOwned(a, proof.proof, verifier, expected, j.roots, j.manifest) else try Api.verifyCaptureOwned(a, proof.proof, verifier, expected) else try Api.verifyPreparedCaptureOwned(a, proof.proof, verifier, expected);
            @import("stwo_prover_engine").measurement.process_usage.reportStage("segment.leaf_capture");
            if (timer) |*t| std.debug.print("BLAKE3_SEGMENT_LEAF_TIMING proving_ns={d} capture_verification_ns={d}\n", .{ proving_ns, t.read() - proving_ns });
            return capture;
        }
        fn proveAdmitted(a: std.mem.Allocator, owner: *Owner, verifier: *Api.PreparedVerifier, expected: [32]u8, statement: spans.SpanStatement, capacity: u32, admitted: *Admitted, pool: ?*Pool) !parent.Prepared {
            var capture = try proveCapture(a, owner, verifier, expected, pool, null);
            defer capture.deinit();
            return parent.prepareSpan(a, verifier, &capture, expected, capacity, statement, .{ &admitted.entry, &admitted.exit });
        }
    };
}

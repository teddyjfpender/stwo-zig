//! Canonical segment-to-recursive-child orchestration with caller-owned admission.
//! The verifier is reusable; the execution owner is single-use once proving starts.
const std = @import("std");
const execution = @import("blake3_execution_proof.zig");
const segment = @import("blake3_segment_execution.zig");
const parent = @import("../recursion/blake3_execution_parent_preparation.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const aggregate = @import("../recursion/blake3_execution_aggregate.zig");
const Custody = @import("../recursion/air/blake3_memory_custody.zig").Prepared;
const binding = @import("../recursion/blake3_execution_span.zig");
pub fn ForBackend(comptime Backend: type) type {
    return ForProfile(Backend, false);
}
pub fn ForEthereumBackend(comptime Backend: type) type {
    return ForProfile(Backend, true);
}
const Pool = @import("stwo_prover_engine").work_pool.WorkPool;
fn ForProfile(comptime Backend: type, comptime ethereum: bool) type {
    return struct {
        const Api = if (ethereum) @import("blake3_ethereum_proof.zig").ForBackend(Backend) else execution.ForBackend(Backend);
        const Owner = if (ethereum) @import("blake3_ethereum_witness.zig").Owner else segment.Owner;
        /// Borrows all inputs. Checks admission and custody before generating
        /// interactions. The returned preparation owns its columns and retains
        /// no pointers into the execution owner, verifier or conversion witnesses.
        /// Failed proving may consume the execution owner's interaction phase;
        /// rebuild that owner before retrying. Admission failures leave it usable.
        pub fn prepare(a: std.mem.Allocator, owner: *Owner, verifier: *Api.PreparedVerifier, expected: [32]u8, statement: spans.SpanStatement, capacity: u32) !parent.Prepared {
            if (ethereum) @compileError("Ethereum segment preparation requires prepareWithPool");
            return prepareWithPool(a, owner, verifier, expected, statement, capacity, null);
        }
        /// The caller binds this pool for the complete preparation transaction.
        pub fn prepareWithPool(a: std.mem.Allocator, owner: *Owner, verifier: *Api.PreparedVerifier, expected: [32]u8, statement: spans.SpanStatement, capacity: u32, pool: ?*Pool) !parent.Prepared {
            if (ethereum and pool == null) return error.MissingExecutionPool;
            var admitted = try admit(a, owner, verifier, expected, statement);
            defer admitted.deinit();
            return proveAdmitted(a, owner, verifier, expected, statement, capacity, &admitted, pool);
        }
        /// Both children are independently pinned and fully admitted before
        /// either interaction phase is consumed. Owners/verifiers remain borrowed;
        /// after proving starts a failure may require rebuilding either owner.
        pub fn preparePair(a: std.mem.Allocator, owners: [2]*Owner, verifiers: [2]*Api.PreparedVerifier, expected: [2][32]u8, statements: [2]spans.SpanStatement, capacity: u32) !aggregate.Fold {
            if (ethereum) @compileError("Ethereum segment pairing requires preparePairWithPool");
            return preparePairWithPool(a, owners, verifiers, expected, statements, capacity, null);
        }
        /// The caller binds this pool for the complete preparation transaction.
        pub fn preparePairWithPool(a: std.mem.Allocator, owners: [2]*Owner, verifiers: [2]*Api.PreparedVerifier, expected: [2][32]u8, statements: [2]spans.SpanStatement, capacity: u32, pool: ?*Pool) !aggregate.Fold {
            return preparePairInternal(false, a, owners, verifiers, expected, statements, capacity, pool);
        }
        /// Consumes distinct execution owners on every path, including admission
        /// failure. An aliased owner is destroyed once. Verifiers stay borrowed.
        /// Each completed child's execution storage and custody are released
        /// before the next child is proved, bounding simultaneous residency.
        pub fn preparePairOwnedWithPool(a: std.mem.Allocator, owners: [2]*Owner, verifiers: [2]*Api.PreparedVerifier, expected: [2][32]u8, statements: [2]spans.SpanStatement, capacity: u32, pool: ?*Pool) !aggregate.Fold {
            return preparePairInternal(true, a, owners, verifiers, expected, statements, capacity, pool);
        }
        fn preparePairInternal(comptime consume: bool, a: std.mem.Allocator, owners: [2]*Owner, verifiers: [2]*Api.PreparedVerifier, expected: [2][32]u8, statements: [2]spans.SpanStatement, capacity: u32, pool: ?*Pool) !aggregate.Fold {
            var owned = [2]bool{ consume, consume and owners[0] != owners[1] };
            defer for (owners, owned) |owner, live| {
                if (live) owner.deinit();
            };
            if (ethereum and pool == null) return error.MissingExecutionPool;
            if (owners[0] == owners[1]) return error.AliasedAggregateChildren;
            _ = try spans.SpanStatement.fold(statements[0], statements[1]);
            var left_admission = try admit(a, owners[0], verifiers[0], expected[0], statements[0]);
            var left_admission_alive = true;
            defer if (left_admission_alive) left_admission.deinit();
            var right_admission = try admit(a, owners[1], verifiers[1], expected[1], statements[1]);
            var right_admission_alive = true;
            defer if (right_admission_alive) right_admission.deinit();
            var left = try proveAdmitted(a, owners[0], verifiers[0], expected[0], statements[0], capacity, &left_admission, pool);
            var left_alive = true;
            defer if (left_alive) left.deinit();
            left_admission.deinit();
            left_admission_alive = false;
            if (consume) {
                owners[0].deinit();
                owned[0] = false;
            }
            var right = try proveAdmitted(a, owners[1], verifiers[1], expected[1], statements[1], capacity, &right_admission, pool);
            right_admission.deinit();
            right_admission_alive = false;
            if (consume) {
                owners[1].deinit();
                owned[1] = false;
            }
            left_alive = false;
            return aggregate.prepareOwned(a, &left, &right, statements);
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
            if (ethereum) {
                try Api.validateForProving(owner, verifier, expected);
            } else {
                try Api.validateForProving(owner.native, owner.hashes, pin);
                try verifier.key.admit(&owner.native.statement, pin, verifier.config, expected);
            }
            const shape = if (ethereum) &verifier.native else &verifier.shape;
            var entry = try owner.memory.prepareContinuation(a, .entry, &shape.public_data, verifier.admission(), statement.body.executed.entry.rw_memory, 1_000_000_000, 999_999_999);
            errdefer entry.deinit();
            var exit = try owner.memory.prepareContinuation(a, .exit, &shape.public_data, verifier.admission(), statement.body.executed.exit.rw_memory, 1_010_000_000, 1_009_999_999);
            errdefer exit.deinit();
            try binding.validate(a, statement, &shape.public_data, verifier.admission(), verifier.config, &entry.plan, &exit.plan);
            return .{ .entry = entry, .exit = exit };
        }
        fn proveAdmitted(a: std.mem.Allocator, owner: *Owner, verifier: *Api.PreparedVerifier, expected: [32]u8, statement: spans.SpanStatement, capacity: u32, admitted: *Admitted, pool: ?*Pool) !parent.Prepared {
            const proof = if (ethereum) try Api.prove(a, owner, verifier, expected, pool.?) else try Api.prove(a, owner.native, owner.hashes, try owner.admission(), verifier.config);
            var capture = if (ethereum) try Api.verifyCaptureOwned(a, proof.proof, verifier, expected) else try Api.verifyPreparedCaptureOwned(a, proof.proof, verifier, expected);
            defer capture.deinit();
            return parent.prepareSpan(a, verifier, &capture, expected, capacity, statement, .{ &admitted.entry, &admitted.exit });
        }
    };
}

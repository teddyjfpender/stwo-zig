//! Canonical segment-to-recursive-child orchestration with caller-owned admission.
//! The verifier is reusable; the execution owner is single-use once proving starts.
const std = @import("std");
const execution = @import("blake3_execution_proof.zig");
const segment = @import("blake3_segment_execution.zig");
const parent = @import("../recursion/blake3_execution_parent_preparation.zig");
const spans = @import("../recursion/span_statement_blake3.zig");
const binding = @import("../recursion/blake3_execution_span.zig");
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Api = execution.ForBackend(Backend);
        /// Borrows all inputs. Checks admission and custody before generating
        /// interactions. The returned preparation owns its columns and retains
        /// no pointers into the execution owner, verifier or conversion witnesses.
        /// Failed proving may consume the execution owner's interaction phase;
        /// rebuild that owner before retrying. Admission failures leave it usable.
        pub fn prepare(a: std.mem.Allocator, owner: *segment.Owner, verifier: *Api.PreparedVerifier, expected: [32]u8, statement: spans.SpanStatement, capacity: u32) !parent.Prepared {
            try verifier.validate(expected);
            try statement.validate();
            if (statement.body != .executed or statement.slots.height != 0) return error.InvalidExecutionSpan;
            const pin = try owner.admission();
            // Authenticate this owner's complete statement against the caller's
            // key before proving; never select authority from the produced proof.
            try verifier.key.admit(&owner.native.statement, pin, verifier.config, expected);
            var entry = try owner.memory.prepareContinuation(a, .entry, &verifier.shape.public_data, verifier.admission(), statement.body.executed.entry.rw_memory, 1_000_000_000, 999_999_999);
            defer entry.deinit();
            var exit = try owner.memory.prepareContinuation(a, .exit, &verifier.shape.public_data, verifier.admission(), statement.body.executed.exit.rw_memory, 1_010_000_000, 1_009_999_999);
            defer exit.deinit();
            try binding.validate(a, statement, &verifier.shape.public_data, verifier.admission(), verifier.config, &entry.plan, &exit.plan);
            const proof = try Api.prove(a, owner.native, owner.hashes, pin, verifier.config);
            var capture = try Api.verifyPreparedCaptureOwned(a, proof.proof, verifier, expected);
            defer capture.deinit();
            return parent.prepareSpan(a, verifier, &capture, expected, capacity, statement, .{ &entry, &exit });
        }
    };
}

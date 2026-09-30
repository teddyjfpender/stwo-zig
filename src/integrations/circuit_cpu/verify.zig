//! `verify_circuit` on a `CircuitSerialize` proof: the Zig counterpart of the
//! oracle's `verify-circuit` (upstream `crates/circuit_verifier/src/verify.rs`
//! at https://github.com/starkware-libs/proving
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! The request (`wire.verify_request`) names the verified circuit's
//! `PcsConfig`, preprocessed layout, preprocessed root and claimed output
//! digest. The proof is decoded under `circuit_verifier_proof_config` of
//! those, converted to the in-circuit verifier's values and checked by
//! building the verification circuit (`statements.circuit_verifier`). As
//! upstream, a proof that fails to decode, is malformed for its config, or
//! does not satisfy the circuit is rejected; the verdict says which step
//! rejected it. Only allocation failure is an error.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const wire = @import("stwo_circuit_recursion_wire");
const verifier_proof = @import("verifier_proof.zig");

const QM31 = core.fields.qm31.QM31;
const preprocessed = circuit.common.preprocessed;
const circuit_statement = circuit.statements.circuit_statement;
const circuit_verifier = circuit.statements.circuit_verifier;
const component_table = circuit.air_eval.component_table;

pub const Request = wire.verify_request.VerifyRequest;

/// Where a rejected proof failed.
pub const Stage = enum {
    /// The request's layout is not a circuit-AIR preprocessed layout.
    layout,
    /// `circuit_verifier_proof_config` rejects the request's config.
    config,
    /// `deserialize_proof_with_config`.
    deserialize,
    /// Building the verification circuit (a malformed proof or statement).
    build,
    /// The verification circuit is not satisfied.
    circuit,
};

pub const Verdict = union(enum) {
    /// The verifier's output digest (its reserved output wires).
    accepted: [8]u32,
    rejected: struct { stage: Stage, reason: anyerror },

    pub fn isAccepted(self: Verdict) bool {
        return self == .accepted;
    }
};

/// `verify_circuit` of `proof_bytes` under `request`. `table` is the
/// circuit-AIR evaluator table (`air_eval.circuit_components`).
pub fn verifyProofBytes(
    gpa: std.mem.Allocator,
    table: *const component_table.Table,
    request: *const Request,
    proof_bytes: []const u8,
) std.mem.Allocator.Error!Verdict {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const layout = columnLayout(request.preprocessed_column_log_sizes) catch |err|
        return reject(.layout, err);
    const config: circuit_verifier.CircuitConfig = .{
        .config = request.pcs_config,
        .preprocessed_column_log_sizes = layout,
    };
    const shape = blk: {
        const proof_config = circuit_statement.circuitVerifierProofConfig(arena, &layout, request.pcs_config) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return reject(.config, err),
        };
        break :blk proof_config.shape();
    };
    var decoded = wire.circuit_serialize.deserializeProof(gpa, proof_bytes, shape) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return reject(.deserialize, err),
    };
    defer decoded.deinit();
    const values = verifier_proof.circuitVerifierValues(arena, &decoded.proof, shape) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return reject(.deserialize, err),
    };

    var ctx = circuit_verifier.verifyCircuit(
        gpa,
        table,
        &config,
        circuit.builder.blake.hashValue(QM31, request.preprocessed_root),
        &values,
        .{ .output_digest = circuit.builder.blake.hashValue(QM31, request.output_digest) },
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.VerificationFailed => return reject(.circuit, err),
        else => return reject(.build, err),
    };
    defer ctx.deinit();
    return .{ .accepted = try outputDigest(&ctx) };
}

fn reject(stage: Stage, reason: anyerror) Verdict {
    return .{ .rejected = .{ .stage = stage, .reason = reason } };
}

/// The request's layout, which must have the circuit AIR's column count.
/// The ids borrow the request.
fn columnLayout(columns: []const wire.verify_request.Column) error{LayoutColumnCount}!preprocessed.ColumnLayout {
    if (columns.len != preprocessed.N_PREPROCESSED_COLUMNS) return error.LayoutColumnCount;
    var layout: preprocessed.ColumnLayout = undefined;
    for (&layout.entries, columns) |*entry, column| entry.* = .{ .id = column.id, .log_size = column.log_size };
    return layout;
}

/// The unpacked `u32` words at the reserved output wires `3..3 + 8`.
fn outputDigest(ctx: anytype) std.mem.Allocator.Error![8]u32 {
    const values = ctx.values();
    var digest: [8]u32 = undefined;
    for (&digest, 0..) |*word, i| {
        const limbs = values[circuit.builder.context.u_var_idx + 1 + i].toM31Array();
        word.* = limbs[0].v | (limbs[1].v << 16);
    }
    return digest;
}

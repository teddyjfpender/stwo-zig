//! Program-fetch tuples of the three Ethereum-SHA precompile callers.
//! The caller's native fixed/main PCS columns must be opened by a v5 request
//! quotient before any result here can contribute to global ROM closure.
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const sha = @import("../air/guest_precompile/sha256_memory_caller.zig");
const keccak = @import("../air/guest_precompile/keccakf_caller.zig");
const signer = @import("../air/guest_precompile/secp256k1_recovery_caller.zig");

pub const Kind = enum { sha, keccak, signer };
pub const Request = struct { numerator: Q, tuple: [5]Q };

/// The same tuple and negative active selector emitted by the native caller
/// AIR. `fixed` and `main` are one caller row at the *same PCS point*; the
/// adapter that opens them is responsible for offset/row placement.
pub fn fromCommittedCaller(kind: Kind, fixed: []const Q, main: []const Q) !Request {
    return fromCommittedCallerFor(Q, kind, fixed, main);
}
pub fn RequestFor(comptime S: type) type {
    return if (S == Q) Request else struct { numerator: S, tuple: [5]S };
}
/// The original geometry and tuple equations, shared with symbolic recursion.
pub fn fromCommittedCallerFor(comptime S: type, kind: Kind, fixed: []const S, main: []const S) !RequestFor(S) {
    const zero = S.zero();
    return switch (kind) {
        .sha => blk: {
            if (fixed.len < sha.PREPROCESSED_COLUMN_COUNT or
                main.len < sha.PHYSICAL_MAIN_COLUMN_COUNT)
                return error.InvalidV5ProgramCallerGeometry;
            break :blk .{ .numerator = zero.sub(fixed[0]), .tuple = .{
                main[sha.Layout.pc],            scalar(S, @import("../isa/sha256_compression_v1.zig").proof_opcode_id),
                zero,                           main[sha.Layout.registers],
                main[sha.Layout.registers + 1],
            } };
        },
        .keccak => blk: {
            if (main.len < keccak.Layout.main_columns)
                return error.InvalidV5ProgramCallerGeometry;
            break :blk .{ .numerator = zero.sub(main[keccak.Layout.enabler]), .tuple = .{
                main[keccak.Layout.pc],               scalar(S, keccak.opcode_id), zero,
                main[keccak.Layout.pointer_register], zero,
            } };
        },
        .signer => blk: {
            if (main.len < signer.Layout.main_columns)
                return error.InvalidV5ProgramCallerGeometry;
            break :blk .{ .numerator = zero.sub(main[signer.Layout.is_active]), .tuple = .{
                main[signer.Layout.pc],               scalar(S, signer.opcode_id), zero,
                main[signer.Layout.pointer_register], zero,
            } };
        },
    };
}

fn scalar(comptime S: type, value: u32) S {
    return S.fromBase(M.fromCanonical(value));
}

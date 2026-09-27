//! Root/key and PoW nonce word producers for native transcript/path joins.
const std = @import("std");
const core = @import("stwo_core");
const verifier = @import("../../prover/verifier.zig");
const statement_mod = @import("../../air/statement_v2.zig");
const native = @import("blake3_native_transcript.zig");
const recorder = @import("blake3_native_recorder.zig");
const roots = @import("blake3_root_sources.zig");
const word = @import("blake3_private_word.zig");
const boundary = @import("blake3_boundary.zig");
const M = core.fields.m31.M31;
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    words: []word.Row,
    fixed_words: []word.Row,
    key: [8]boundary.Row,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(comptime Engine: type, a: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, interaction_nonce: u64, transcript: *const native.Prepared) !Prepared {
    comptime {
        if (Engine.Hasher != @import("../blake3_engine_protocol.zig").Hasher) @compileError("native root adapter requires BLAKE3 capture");
    }
    try capture.validate();
    try transcript.plan.validate();
    try @import("../../prover/verifier_protocol.zig").V2Protocol.validate(statement);
    if (!std.meta.eql(statement.public_data.wireId(), capture.public_data.data.wireId()) or !std.meta.eql(statement.authority_id, capture.receipt.authority_id) or capture.proof.commitments.len != 4) return error.InvalidNativeRootNonce;
    try @import("../../prover/statement_validation.zig").verifyPreprocessedRoot(Engine, a, config, statement.core, capture.proof.commitments[0]);
    const count = capture.proof.commitments.len + capture.proof.fri.layers.len;
    if (transcript.live.root_reads.len != count or transcript.plan.fixed.root_reads.len != count) return error.InvalidNativeRootNonce;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const words = try temp.alloc(word.Row, (count - 1) * 8 + 4);
    const fixed_words = try temp.alloc(word.Row, words.len);
    var key: [8]boundary.Row = undefined;
    for (transcript.live.root_reads, transcript.plan.fixed.root_reads, 0..) |receipt, fixed, index| {
        const source = try roots.caller(index);
        if (!std.meta.eql(receipt, fixed) or !std.meta.eql(receipt.source, source) or receipt.operation >= transcript.operations.len or transcript.operations[receipt.operation] != .routed_root) return error.InvalidNativeRootNonce;
        const digest = if (index < 4) capture.proof.commitments[index] else capture.proof.fri.layers[index - 4].commitment;
        const operation = transcript.operations[receipt.operation].routed_root;
        if (!std.meta.eql(operation.source, source) or !std.meta.eql(operation.value, digest)) return error.InvalidNativeRootNonce;
        for (receipt.uses, 0..) |reads, coordinate| {
            const uses = try std.math.add(u32, reads, std.math.cast(u32, capture.proof.queries.raw.len) orelse return error.InvalidNativeRootNonce);
            if (uses >= core.fields.m31.Modulus) return error.InvalidNativeRootNonce;
            const wire = try std.math.add(u32, source.first_wire, @intCast(coordinate));
            const value = std.mem.readInt(u32, digest[coordinate * 4 ..][0..4], .little);
            if (index == 0) {
                key[coordinate] = try boundary.logicalRow(source.circuit, wire, M.fromCanonical(uses), value);
            } else {
                const row = (index - 1) * 8 + coordinate;
                words[row] = try word.logicalRow(source.circuit, wire, uses, value);
                fixed_words[row] = try word.logicalRow(source.circuit, wire, uses, 0);
            }
        }
    }
    var nonce_reads: [2][2]u32 = @splat(@splat(0));
    var seen: [2][2]bool = @splat(@splat(false));
    const nonces = [2]u64{ interaction_nonce, capture.proof.proof_of_work };
    if (transcript.live.payload_reads.len != transcript.plan.fixed.payload_reads.len) return error.InvalidNativeRootNonce;
    for (transcript.live.payload_reads, transcript.plan.fixed.payload_reads) |receipt, fixed| {
        if (receipt.operation != fixed.operation or !std.meta.eql(receipt.source, fixed.source) or !std.mem.eql(u32, receipt.uses, fixed.uses)) return error.InvalidNativeRootNonce;
        if (receipt.source.circuit != recorder.Recorder.nonce_source.circuit) continue;
        if ((receipt.source.first_wire != 0 and receipt.source.first_wire != 2) or receipt.uses.len != 2 or receipt.operation >= transcript.operations.len) return error.InvalidNativeRootNonce;
        const slot = receipt.source.first_wire / 2;
        const phase: usize = switch (transcript.operations[receipt.operation]) {
            .pow => |operation| blk: {
                if (operation.nonce_source == null or !std.meta.eql(operation.nonce_source.?, receipt.source) or operation.nonce != nonces[slot]) return error.InvalidNativeRootNonce;
                break :blk 0;
            },
            .routed_integer => |operation| blk: {
                if (!std.meta.eql(operation.source, receipt.source) or operation.value != nonces[slot]) return error.InvalidNativeRootNonce;
                break :blk 1;
            },
            else => return error.InvalidNativeRootNonce,
        };
        if (seen[slot][phase]) return error.InvalidNativeRootNonce;
        seen[slot][phase] = true;
        for (&nonce_reads[slot], receipt.uses) |*total, reads| total.* = try std.math.add(u32, total.*, reads);
    }
    for (seen, nonce_reads, nonces, 0..) |phases, reads, nonce, index| {
        if (!phases[0] or !phases[1]) return error.InvalidNativeRootNonce;
        for (reads, 0..) |uses, coordinate| {
            const wire: u32 = @intCast(index * 2 + coordinate);
            const row = words.len - 4 + wire;
            const value: u32 = @truncate(nonce >> @as(u6, @intCast(coordinate * 32)));
            words[row] = try word.logicalRow(recorder.Recorder.nonce_source.circuit, wire, uses, value);
            fixed_words[row] = try word.logicalRow(recorder.Recorder.nonce_source.circuit, wire, uses, 0);
        }
    }
    return .{ .arena = arena, .words = words, .fixed_words = fixed_words, .key = key };
}

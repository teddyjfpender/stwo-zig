//! Execution-key preprocessing root, private proof roots and the single PCS
//! nonce. All root words are full-width; path reads share transcript producers.
const std = @import("std");
const core = @import("stwo_core");
const Verified = @import("../../prover/blake3_execution_capture.zig").Verified;
const transcript_mod = @import("blake3_native_transcript.zig");
const roots = @import("blake3_root_sources.zig");
const word = @import("blake3_private_word.zig");
const boundary = @import("blake3_boundary.zig");
const M = core.fields.m31.M31;
pub const Prepared = @import("blake3_native_root_nonce.zig").Prepared;
pub fn prepare(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8, transcript: *const transcript_mod.Planned) !Prepared {
    try capture.validate(admitted, expected);
    try transcript.plan.validate();
    return prepareCaptured(a, &capture.proof, if (@TypeOf(capture.*) == @import("../../prover/blake3_ethereum_capture.zig").Verified) admitted.root else admitted.key.preprocessed_root, admitted.config, transcript);
}
pub fn prepareParent(a: std.mem.Allocator, admission: anytype, capture: *const @import("../blake3_native_parent_verifier.zig").Verified, transcript: *const transcript_mod.Planned) !Prepared {
    try capture.validate(admission, admission.expected_id);
    try transcript.plan.validate();
    return prepareCaptured(a, &capture.capture, admission.key.preprocessed_root, try admission.config(), transcript);
}
fn prepareCaptured(a: std.mem.Allocator, proof: anytype, root: [32]u8, config: core.pcs.PcsConfig, transcript: *const transcript_mod.Planned) !Prepared {
    if (!std.mem.eql(u8, &proof.commitments[0], &root)) return error.InvalidExecutionRoots;
    const count = proof.commitments.len + proof.fri.layers.len;
    if (transcript.plan.fixed.root_reads.len != count) return error.InvalidExecutionRoots;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const words = try temp.alloc(word.Row, (count - 1) * 8 + 2);
    const fixed_words = try temp.alloc(word.Row, words.len);
    var key: [8]boundary.Row = undefined;
    const path_reads = std.math.cast(u32, proof.queries.raw.len) orelse return error.InvalidExecutionRoots;
    for (transcript.plan.fixed.root_reads, 0..) |receipt, index| {
        const source = try roots.caller(index);
        if (!std.meta.eql(receipt.source, source) or receipt.operation >= transcript.operations.len or transcript.operations[receipt.operation] != .routed_root) return error.InvalidExecutionRoots;
        const digest = if (index < 4) proof.commitments[index] else proof.fri.layers[index - 4].commitment;
        const operation = transcript.operations[receipt.operation].routed_root;
        if (!std.meta.eql(operation.source, source) or !std.meta.eql(operation.value, digest)) return error.InvalidExecutionRoots;
        for (receipt.uses, 0..) |reads, coordinate| {
            const uses = try std.math.add(u32, reads, path_reads);
            if (uses >= core.fields.m31.Modulus) return error.InvalidExecutionRoots;
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
    const nonce_source = @import("blake3_transcript_witness.zig").Caller{ .circuit = 4_100_001, .first_wire = 2 };
    var seen: [2]bool = @splat(false);
    var nonce_reads: [2]u32 = @splat(0);
    for (transcript.plan.fixed.payload_reads) |receipt| {
        if (receipt.source.circuit != nonce_source.circuit) continue;
        if (!std.meta.eql(receipt.source, nonce_source) or receipt.uses.len != 2 or receipt.operation >= transcript.operations.len) return error.InvalidExecutionRoots;
        const phase: usize = switch (transcript.operations[receipt.operation]) {
            .pow => |op| blk: {
                if (op.nonce_source == null or !std.meta.eql(op.nonce_source.?, nonce_source) or op.nonce != proof.proof_of_work or op.bits != config.pow_bits) return error.InvalidExecutionRoots;
                break :blk 0;
            },
            .routed_integer => |op| blk: {
                if (!std.meta.eql(op.source, nonce_source) or op.value != proof.proof_of_work) return error.InvalidExecutionRoots;
                break :blk 1;
            },
            else => return error.InvalidExecutionRoots,
        };
        if (seen[phase]) return error.InvalidExecutionRoots;
        seen[phase] = true;
        for (&nonce_reads, receipt.uses) |*uses, reads| uses.* = try std.math.add(u32, uses.*, reads);
    }
    if (!seen[0] or !seen[1]) return error.InvalidExecutionRoots;
    for (nonce_reads, 0..) |uses, coordinate| {
        const wire = nonce_source.first_wire + @as(u32, @intCast(coordinate));
        const value: u32 = @truncate(proof.proof_of_work >> @as(u6, @intCast(coordinate * 32)));
        words[words.len - 2 + coordinate] = try word.logicalRow(nonce_source.circuit, wire, uses, value);
        fixed_words[words.len - 2 + coordinate] = try word.logicalRow(nonce_source.circuit, wire, uses, 0);
    }
    return .{ .arena = arena, .words = words, .fixed_words = fixed_words, .key = key };
}

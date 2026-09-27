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
    const joint = if (comptime @import("blake3_execution_profile.zig").isExtension(@TypeOf(capture.*))) capture.joint_manifest != null else false;
    return prepareCaptured(a, &capture.proof, if (comptime @import("blake3_execution_profile.zig").isExtension(@TypeOf(capture.*))) admitted.root else admitted.key.preprocessed_root, admitted.config, transcript, joint);
}
pub fn prepareParent(a: std.mem.Allocator, admission: anytype, capture: *const @import("../blake3_native_parent_verifier.zig").Verified, transcript: *const transcript_mod.Planned) !Prepared {
    try capture.validate(admission, admission.expected_id);
    try transcript.plan.validate();
    return prepareCaptured(a, &capture.capture, admission.key.preprocessed_root, try admission.config(), transcript, false);
}
pub fn prepareCaptured(a: std.mem.Allocator, proof: anytype, root: [32]u8, config: core.pcs.PcsConfig, transcript: *const transcript_mod.Planned, joint: bool) !Prepared {
    return prepareMode(true, null, a, proof, root, config, transcript, if (joint) 2 else 0);
}
/// Explicit dense-source parity oracle after enclosing capture admission.
pub fn prepareCapturedRows(a: std.mem.Allocator, proof: anytype, root: [32]u8, config: core.pcs.PcsConfig, transcript: *const transcript_mod.Planned, joint: bool) !Prepared {
    return prepareMode(false, null, a, proof, root, config, transcript, if (joint) 2 else 0);
}
/// Admitted external first trees. Prefix3 is exact fused access: fixed/main/
/// witness roots are supplied publicly; no private row manufactures witness authority.
pub fn prepareCapturedExternal(a: std.mem.Allocator, proof: anytype, root: [32]u8, config: core.pcs.PcsConfig, transcript: *const transcript_mod.Planned, prefix: usize) !Prepared {
    if (prefix != 2 and prefix != 3) return error.InvalidExecutionRoots;
    return prepareMode(true, null, a, proof, root, config, transcript, prefix);
}
/// All eight original premix/semantic roots are independently public PAGE
/// inputs. The two remaining roots and FRI roots retain original word AIR.
pub fn prepareCapturedExternalFor(comptime count: usize, a: std.mem.Allocator, proof: anytype, root: [32]u8, config: core.pcs.PcsConfig, transcript: *const transcript_mod.Planned, prefix: usize) !Prepared {
    comptime if (count != 10) @compileError("explicit PAGE root route requires ten commitments");
    if (prefix != 8) return error.InvalidExecutionRoots;
    return prepareMode(true, count, a, proof, root, config, transcript, prefix);
}
fn prepareMode(comptime direct: bool, comptime exact_count: ?usize, a: std.mem.Allocator, proof: anytype, root: [32]u8, config: core.pcs.PcsConfig, transcript: *const transcript_mod.Planned, prefix: usize) !Prepared {
    const joint = prefix >= 2;
    if (comptime exact_count) |count| {
        if (proof.commitments.len != count) return error.InvalidExecutionRoots;
    } else if (proof.commitments.len != 4 and proof.commitments.len != 5) return error.InvalidExecutionRoots;
    if (prefix >= proof.commitments.len) return error.InvalidExecutionRoots;
    if (!std.mem.eql(u8, &proof.commitments[0], &root)) return error.InvalidExecutionRoots;
    const count = try std.math.add(usize, proof.commitments.len, proof.fri.layers.len);
    if (transcript.plan.fixed.root_reads.len != count - prefix) return error.InvalidExecutionRoots;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const word_count = try std.math.add(usize, try std.math.mul(usize, count - @max(@as(usize, 1), prefix), 8), 2);
    const Columns = @import("blake3_native_root_nonce.zig").Columns;
    var columns: ?Columns = null;
    errdefer if (columns) |*owned| owned.deinit();
    if (direct) columns = try Columns.init(a, .{ if (joint) 16 else 8, word_count });
    const words: []word.Row = if (direct) &.{} else try temp.alloc(word.Row, word_count);
    const fixed_words: []word.Row = if (direct) &.{} else try temp.alloc(word.Row, word_count);
    const key: []boundary.Row = if (direct) &.{} else try temp.alloc(boundary.Row, 8);
    var joint_main: ?[8]boundary.Row = if (joint and !direct) @as([8]boundary.Row, undefined) else null;
    const path_reads = std.math.cast(u32, proof.queries.raw.len) orelse return error.InvalidExecutionRoots;
    if (path_reads >= core.fields.m31.Modulus) return error.InvalidExecutionRoots;
    if (joint) {
        const first = try roots.caller(0);
        const second = try roots.caller(1);
        for (0..8) |coordinate| {
            const first_row = try boundary.logicalRow(first.circuit, first.first_wire + @as(u32, @intCast(coordinate)), M.fromCanonical(path_reads), std.mem.readInt(u32, proof.commitments[0][coordinate * 4 ..][0..4], .little));
            const second_row = try boundary.logicalRow(second.circuit, second.first_wire + @as(u32, @intCast(coordinate)), M.fromCanonical(path_reads), std.mem.readInt(u32, proof.commitments[1][coordinate * 4 ..][0..4], .little));
            if (direct) {
                try columns.?.putFixed(2, coordinate, first_row, first_row);
                try columns.?.putFixed(2, 8 + coordinate, second_row, second_row);
            } else {
                key[coordinate] = first_row;
                joint_main.?[coordinate] = second_row;
            }
        }
    }
    for (transcript.plan.fixed.root_reads, prefix..) |receipt, index| {
        const source = try roots.caller(index);
        if (!std.meta.eql(receipt.source, source) or receipt.operation >= transcript.operations.len or transcript.operations[receipt.operation] != .routed_root) return error.InvalidExecutionRoots;
        const digest = if (index < proof.commitments.len) proof.commitments[index] else proof.fri.layers[index - proof.commitments.len].commitment;
        const operation = transcript.operations[receipt.operation].routed_root;
        if (!std.meta.eql(operation.source, source) or !std.meta.eql(operation.value, digest)) return error.InvalidExecutionRoots;
        for (receipt.uses, 0..) |reads, coordinate| {
            const uses = try std.math.add(u32, reads, path_reads);
            if (uses >= core.fields.m31.Modulus) return error.InvalidExecutionRoots;
            const wire = try std.math.add(u32, source.first_wire, @intCast(coordinate));
            const value = std.mem.readInt(u32, digest[coordinate * 4 ..][0..4], .little);
            if (index == 0) {
                const row = try boundary.logicalRow(source.circuit, wire, M.fromCanonical(uses), value);
                if (direct) try columns.?.putFixed(2, coordinate, row, row) else key[coordinate] = row;
            } else {
                const row = (index - @max(@as(usize, 1), prefix)) * 8 + coordinate;
                const live = try word.logicalRow(source.circuit, wire, uses, value);
                const fixed = try word.logicalRow(source.circuit, wire, uses, 0);
                if (direct) try columns.?.putFixed(9, row, live, fixed) else {
                    words[row] = live;
                    fixed_words[row] = fixed;
                }
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
        const live = try word.logicalRow(nonce_source.circuit, wire, uses, value);
        const fixed = try word.logicalRow(nonce_source.circuit, wire, uses, 0);
        if (direct) try columns.?.putFixed(9, word_count - 2 + coordinate, live, fixed) else {
            words[word_count - 2 + coordinate] = live;
            fixed_words[word_count - 2 + coordinate] = fixed;
        }
    }
    if (columns) |*owned| try owned.finish();
    return .{ .columns = columns, .arena = arena, .words = words, .fixed_words = fixed_words, .key = key, .joint_main = joint_main };
}

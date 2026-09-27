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
pub const Columns = @import("blake3_upstream_source_columns_v1.zig").ForSlots(.{ 2, 9 });
pub const MainColumns = @import("blake3_upstream_source_columns_v1.zig").ForSlots(.{2});
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    words: []word.Row,
    fixed_words: []word.Row,
    key: []boundary.Row,
    columns: ?Columns = null,
    main_columns: ?MainColumns = null,
    word_skip: usize = 0,
    external_key: bool = false,
    /// Opt-in public bus supplies the independently pinned main root.
    external_main: bool = false,
    /// Joint leaf transcripts pin the main PCS root in the parent key even
    /// though that root is absent from the shared challenge prefix.
    joint_main: ?[8]boundary.Row = null,
    pub fn deinit(self: *Prepared) void {
        if (self.columns) |*columns| columns.deinit();
        if (self.main_columns) |*columns| columns.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn wordCount(self: *const Prepared) usize {
        return if (self.columns) |*columns| columns.count(9) -| self.word_skip else self.words.len;
    }
    pub fn skipFirstWords(self: *Prepared, count: usize) !void {
        if (count > self.wordCount()) return error.InvalidExecutionRoots;
        if (self.columns != null) self.word_skip = try std.math.add(usize, self.word_skip, count) else {
            self.words = self.words[count..];
            self.fixed_words = self.fixed_words[count..];
        }
    }
    pub fn attachMain(self: *Prepared, a: std.mem.Allocator, rows: [8]boundary.Row) !void {
        if (self.joint_main != null or self.main_columns != null) return error.InvalidExecutionRoots;
        if (self.columns) |*columns| {
            if (columns.count(2) != 8) return error.InvalidExecutionRoots;
            var main = try MainColumns.init(a, .{8});
            errdefer main.deinit();
            for (rows) |row| try main.appendFixed(2, row, row);
            try main.finish();
            self.main_columns = main;
        } else self.joint_main = rows;
    }
    pub fn appendKey(self: *const Prepared, b: anytype) !void {
        if (self.external_key) return;
        if (self.columns) |*columns| {
            if (self.key.len != 0) return error.InvalidNativeRootNonce;
            try b.appendBorrowed(2, try (try columns.view(2)).subview(0, 8));
        } else try b.append(2, self.key, self.key);
    }
    pub fn appendMain(self: *const Prepared, b: anytype) !void {
        if (self.external_main) return;
        if (self.main_columns) |*columns| {
            if (self.joint_main != null) return error.InvalidExecutionRoots;
            try columns.appendTo(2, b);
        } else if (self.columns) |*columns| {
            if (self.joint_main != null) return error.InvalidExecutionRoots;
            const view = try columns.view(2);
            if (view.rowCount() == 16) try b.appendBorrowed(2, try view.subview(8, 8)) else if (view.rowCount() != 8) return error.InvalidExecutionRoots;
        } else if (self.joint_main) |*main| try b.append(2, main, main);
    }
    pub fn appendWords(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (self.words.len != 0 or self.fixed_words.len != 0) return error.InvalidNativeRootNonce;
            const view = try columns.view(9);
            if (self.word_skip > view.rowCount()) return error.InvalidNativeRootNonce;
            try b.appendBorrowed(9, try view.subview(self.word_skip, view.rowCount() - self.word_skip));
        } else try b.append(9, self.words, self.fixed_words);
    }
};
pub fn prepare(comptime Engine: type, a: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, interaction_nonce: u64, transcript: *const native.Prepared) !Prepared {
    return prepareMode(true, Engine, a, statement, capture, config, interaction_nonce, transcript);
}
/// Explicit dense-source parity oracle with the same native admission gates.
pub fn prepareRows(comptime Engine: type, a: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, interaction_nonce: u64, transcript: *const native.Prepared) !Prepared {
    return prepareMode(false, Engine, a, statement, capture, config, interaction_nonce, transcript);
}
fn prepareMode(comptime direct: bool, comptime Engine: type, a: std.mem.Allocator, statement: *const statement_mod.RiscVStatementV2, capture: *const verifier.VerifiedSegmentV2CaptureForEngine(Engine), config: core.pcs.PcsConfig, interaction_nonce: u64, transcript: *const native.Prepared) !Prepared {
    comptime {
        if (Engine.Hasher != @import("../blake3_engine_protocol.zig").Hasher) @compileError("native root adapter requires BLAKE3 capture");
    }
    try capture.validate();
    try transcript.plan.validate();
    try @import("../../prover/verifier_protocol.zig").V2Protocol.validate(statement);
    if (!std.meta.eql(statement.public_data.wireId(), capture.public_data.data.wireId()) or !std.meta.eql(statement.authority_id, capture.receipt.authority_id) or capture.proof.commitments.len != 4) return error.InvalidNativeRootNonce;
    try @import("../../prover/statement_validation.zig").verifyPreprocessedRoot(Engine, a, config, statement.core, capture.proof.commitments[0]);
    const count = try std.math.add(usize, capture.proof.commitments.len, capture.proof.fri.layers.len);
    if (transcript.live.root_reads.len != count or transcript.plan.fixed.root_reads.len != count) return error.InvalidNativeRootNonce;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const word_count = try std.math.add(usize, try std.math.mul(usize, count - 1, 8), 4);
    var columns: ?Columns = null;
    errdefer if (columns) |*owned| owned.deinit();
    if (direct) columns = try Columns.init(a, .{ 8, word_count });
    const words: []word.Row = if (direct) &.{} else try temp.alloc(word.Row, word_count);
    const fixed_words: []word.Row = if (direct) &.{} else try temp.alloc(word.Row, word_count);
    const key: []boundary.Row = if (direct) &.{} else try temp.alloc(boundary.Row, 8);
    for (transcript.live.root_reads, transcript.plan.fixed.root_reads, 0..) |receipt, expected_receipt, index| {
        const source = try roots.caller(index);
        if (!std.meta.eql(receipt, expected_receipt) or !std.meta.eql(receipt.source, source) or receipt.operation >= transcript.operations.len or transcript.operations[receipt.operation] != .routed_root) return error.InvalidNativeRootNonce;
        const digest = if (index < 4) capture.proof.commitments[index] else capture.proof.fri.layers[index - 4].commitment;
        const operation = transcript.operations[receipt.operation].routed_root;
        if (!std.meta.eql(operation.source, source) or !std.meta.eql(operation.value, digest)) return error.InvalidNativeRootNonce;
        for (receipt.uses, 0..) |reads, coordinate| {
            const uses = try std.math.add(u32, reads, std.math.cast(u32, capture.proof.queries.raw.len) orelse return error.InvalidNativeRootNonce);
            if (uses >= core.fields.m31.Modulus) return error.InvalidNativeRootNonce;
            const wire = try std.math.add(u32, source.first_wire, @intCast(coordinate));
            const value = std.mem.readInt(u32, digest[coordinate * 4 ..][0..4], .little);
            if (index == 0) {
                const row = try boundary.logicalRow(source.circuit, wire, M.fromCanonical(uses), value);
                if (direct) try columns.?.putFixed(2, coordinate, row, row) else key[coordinate] = row;
            } else {
                const row = (index - 1) * 8 + coordinate;
                const live = try word.logicalRow(source.circuit, wire, uses, value);
                const fixed = try word.logicalRow(source.circuit, wire, uses, 0);
                if (direct) try columns.?.putFixed(9, row, live, fixed) else {
                    words[row] = live;
                    fixed_words[row] = fixed;
                }
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
            const row = word_count - 4 + wire;
            const value: u32 = @truncate(nonce >> @as(u6, @intCast(coordinate * 32)));
            const live = try word.logicalRow(recorder.Recorder.nonce_source.circuit, wire, uses, value);
            const fixed = try word.logicalRow(recorder.Recorder.nonce_source.circuit, wire, uses, 0);
            if (direct) try columns.?.putFixed(9, row, live, fixed) else {
                words[row] = live;
                fixed_words[row] = fixed;
            }
        }
    }
    if (columns) |*owned| try owned.finish();
    return .{ .columns = columns, .arena = arena, .words = words, .fixed_words = fixed_words, .key = key };
}

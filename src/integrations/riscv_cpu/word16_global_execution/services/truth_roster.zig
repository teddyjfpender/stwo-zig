//! Independently typed service truth sources and failure-atomic MAIN/INTER handoff.
//! Explicit optional K/ADD/DOUBLE bridge roster, independently typed truths.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const A = front.rv64_air;
const S = A.crypto.secp256k1.word16_bridge;
const Commit = @import("../../word16_execution/main_ownership.zig").Commit;
const Key = @import("../keccak/shared/key.zig").Key;
const T = @import("types.zig");
const append = @import("../keccak/roster.zig").append;
const Sha = @import("../sha256/roster.zig");
const Arith = @import("../arith256/roster.zig");
const Curve = @import("../curves/roster.zig");
const SecpRow = @import("../secp/row_roster.zig");
const M = core.fields.m31.M31;
const Col = engine.pcs.ColumnEvaluation;
pub fn spanEnd(data: []const M) !usize {
    return std.math.add(usize, @intFromPtr(data.ptr), try std.math.mul(usize, data.len, @sizeOf(M)));
}
pub fn overlap(data: []const M, other_end: usize, other: []const M, end: usize) bool {
    return data.len != 0 and other.len != 0 and @intFromPtr(data.ptr) < other_end and @intFromPtr(other.ptr) < end;
}
pub const Truth = union(enum) {
    keccak: struct { setup: *const @import("../keccak/shared/roster.zig").TruthSetup, first_id: u32, calls: u32 },
    secp: struct { setup: *const @import("../secp/roster.zig").TruthSetup, first_id: u32, calls: u32 },
    sha256: struct { setup: *const Sha.TruthSetup, first_id: u32, calls: u32 },
    arith256_mod: struct { setup: *const Arith.TruthSetup, first_id: u32, calls: u32 },
    curve: struct { setup: *const Curve.TruthSetup, first_id: u32, calls: u32 },
    /// v3 secp256k1 `row_v1` profile (one RCB call per row), families 1/2.
    secp_row: struct { setup: *const SecpRow.TruthSetup, first_id: u32, calls: u32 },
    pub fn family(self: @This()) T.Family {
        return switch (self) {
            .keccak => .keccak,
            .secp => |t| if (t.setup.kind == .add) .add else .double,
            .sha256 => .sha256,
            .arith256_mod => .arith256_mod,
            .curve => |t| T.curveFamily(t.setup.op),
            .secp_row => |t| if (t.setup.kind == .add) .add else .double,
        };
    }
    pub fn first(self: @This()) u32 {
        return switch (self) {
            inline else => |t| t.first_id,
        };
    }
    pub fn count(self: @This()) u32 {
        return switch (self) {
            inline else => |t| t.calls,
        };
    }
    pub fn key(self: @This()) *const Key {
        return switch (self) {
            inline else => |t| &t.setup.key,
        };
    }
    pub fn logs(self: @This(), a: std.mem.Allocator, tree: usize) ![]u32 {
        return switch (self) {
            .keccak => |t| t.setup.logs(a, tree),
            .secp => |t| t.setup.columnLogs(a, tree),
            .sha256 => |t| t.setup.logs(a, tree),
            .arith256_mod => |t| t.setup.logs(a, tree),
            .curve => |t| t.setup.logs(a, tree),
            .secp_row => |t| t.setup.logs(a, tree),
        };
    }
};
pub const TruthSource = union(enum) {
    keccak: @import("../keccak/shared/roster.zig").TruthSource,
    secp: @import("../secp/roster.zig").TruthSource,
    sha256: Sha.TruthSource,
    arith256_mod: Arith.TruthSource,
    curve: Curve.TruthSource,
    secp_row: SecpRow.TruthSource,
    pub fn init(a: std.mem.Allocator, truth: Truth, advice: *const @import("collector.zig").Advice) !TruthSource {
        if (truth.first() == 0) return error.InvalidCombinedTruthSpan;
        const begin: usize = truth.first() - 1;
        const end = begin + truth.count();
        return switch (truth) {
            .keccak => |t| block: {
                const inputs = try a.alloc(A.crypto.keccak.trace.State, t.calls);
                defer a.free(inputs);
                var offset: usize = 0;
                var written: usize = 0;
                for (advice.keccak) |cc| {
                    const lo = @max(begin, offset);
                    const hi = @min(end, offset + cc.len);
                    if (lo < hi) {
                        for (cc[lo - offset .. hi - offset]) |call| {
                            inputs[written] = call.before;
                            written += 1;
                        }
                    }
                    offset += cc.len;
                }
                // Keccak-sponge permutations follow every Keccak-f call in the
                // shared IO11 ID space (shard order, then permutation order).
                for (advice.sponge) |shard| {
                    const lo = @max(begin, offset);
                    const hi = @min(end, offset + shard.inputs.len);
                    if (lo < hi) {
                        for (shard.inputs[lo - offset .. hi - offset]) |state| {
                            inputs[written] = state;
                            written += 1;
                        }
                    }
                    offset += shard.inputs.len;
                }
                if (written != t.calls) return error.InvalidCombinedTruthSpan;
                break :block .{ .keccak = try @import("../keccak/shared/roster.zig").TruthSource.initSpanPolicy(a, inputs, t.first_id, t.setup.log, t.setup.policy) };
            },
            .secp => |t| block: {
                const inputs = try secpSpan(a, advice, @intFromEnum(t.setup.kind) - 1, begin, end, t.calls);
                defer a.free(inputs);
                break :block .{ .secp = try @import("../secp/roster.zig").TruthSource.init(a, t.setup, inputs, t.first_id) };
            },
            .secp_row => |t| block: {
                const inputs = try secpSpan(a, advice, @intFromEnum(t.setup.kind) - 1, begin, end, t.calls);
                defer a.free(inputs);
                break :block .{ .secp_row = try SecpRow.TruthSource.init(a, t.setup, inputs, t.first_id) };
            },
            .sha256 => |t| block: {
                const inputs = try a.alloc(S.types.Call, t.calls);
                defer a.free(inputs);
                var offset: usize = 0;
                var written: usize = 0;
                for (advice.sha256) |cc| {
                    const lo = @max(begin, offset);
                    const hi = @min(end, offset + cc.len);
                    if (lo < hi) {
                        const selected = cc[lo - offset .. hi - offset];
                        @memcpy(inputs[written..][0..selected.len], selected);
                        written += selected.len;
                    }
                    offset += cc.len;
                }
                if (written != t.calls) return error.InvalidCombinedTruthSpan;
                break :block .{ .sha256 = try Sha.TruthSource.init(a, t.setup, inputs, t.first_id) };
            },
            .arith256_mod => |t| block: {
                const inputs = try a.alloc(S.types.Call, t.calls);
                defer a.free(inputs);
                var offset: usize = 0;
                var written: usize = 0;
                for (advice.arith256_mod) |cc| {
                    const lo = @max(begin, offset);
                    const hi = @min(end, offset + cc.len);
                    if (lo < hi) {
                        const selected = cc[lo - offset .. hi - offset];
                        @memcpy(inputs[written..][0..selected.len], selected);
                        written += selected.len;
                    }
                    offset += cc.len;
                }
                if (written != t.calls) return error.InvalidCombinedTruthSpan;
                break :block .{ .arith256_mod = try Arith.TruthSource.init(a, t.setup, inputs, t.first_id) };
            },
            .curve => |t| block: {
                const inputs = try a.alloc(S.types.Call, t.calls);
                defer a.free(inputs);
                const k = @intFromEnum(t.setup.op) - T.FIRST_CURVE;
                var offset: usize = 0;
                var written: usize = 0;
                for (advice.curves) |cc| {
                    const lo = @max(begin, offset);
                    const hi = @min(end, offset + cc[k].len);
                    if (lo < hi) {
                        const selected = cc[k][lo - offset .. hi - offset];
                        @memcpy(inputs[written..][0..selected.len], selected);
                        written += selected.len;
                    }
                    offset += cc[k].len;
                }
                if (written != t.calls) return error.InvalidCombinedTruthSpan;
                break :block .{ .curve = try Curve.TruthSource.init(a, t.setup, inputs, t.first_id) };
            },
        };
    }
    /// Transfers the three original wide allocations, preserving only the
    /// secp BYTE provider's 256 multiplicities as narrow generator input.
    /// Every validation/allocation precedes mutation; PCS consumes Commit.
    pub fn takeMain(self: *TruthSource) !Commit {
        return self.take(1);
    }
    pub fn takeInteraction(self: *TruthSource) !Commit {
        return self.take(2);
    }
    fn take(self: *TruthSource, tree: usize) !Commit {
        if (self.* == .sha256) return takeSha(&self.sha256.source, tree);
        if (self.* == .arith256_mod) return takeArith(&self.arith256_mod.source, tree);
        if (self.* == .curve) return switch (self.curve) {
            inline else => |*s| takeCurve(s, tree),
        };
        if (self.* == .secp_row) return switch (self.secp_row) {
            inline else => |*s| takeCurve(s, tree),
        };
        const a = switch (self.*) {
            .keccak => |s| s.permutation.allocator,
            .secp => |s| s.batch.product.allocator,
            .sha256, .arith256_mod, .curve, .secp_row => unreachable,
        };
        var matrices: [3]*[]M = undefined;
        var expected: [3]usize = undefined;
        var protected: [6][]const M = undefined;
        switch (self.*) {
            .keccak => |*s| {
                if (s.chi.kind != .chi or s.xor5.kind != .xor5) return error.InvalidTruthBufferPhase;
                try s.permutation.validateMetadata();
                try s.chi.validateMetadata();
                try s.xor5.validateMetadata();
                inline for (.{ "permutation", "chi", "xor5" }, 0..) |name, i| {
                    const part = &@field(s, name);
                    if (!A.memory.ownership.same(a, part.allocator) or (tree == 1 and (!part.owns_main or !A.memory.ownership.same(a, part.main_allocator orelse part.allocator) or part.interaction.len != 0))) return error.InvalidTruthBufferOwner;
                    protected[i] = part.fixed;
                    protected[3 + i] = if (tree == 1) part.interaction else part.main;
                    matrices[i] = if (tree == 1) &part.main else &part.interaction;
                    const width: usize = if (i == 0) (if (tree == 1) A.crypto.keccak.layout.MAIN else s.policy().interactionCount()) else (if (tree == 1) 1 else 4);
                    expected[i] = try std.math.mul(usize, width, part.size());
                }
            },
            .secp => |*s| {
                if (s.batch.product.kind != .product or s.batch.linear.kind != .linear) return error.InvalidTruthBufferPhase;
                try s.batch.product.validateMetadata();
                try s.batch.linear.validateMetadata();
                inline for (.{ "product", "linear" }, 0..) |name, i| {
                    const part = &@field(s.batch, name);
                    if (!A.memory.ownership.same(a, part.allocator) or (tree == 1 and (!part.owns_main or !A.memory.ownership.same(a, part.main_allocator orelse part.allocator) or part.interaction.len != 0))) return error.InvalidTruthBufferOwner;
                    protected[i] = part.fixed;
                    protected[3 + i] = if (tree == 1) part.interaction else part.main;
                    matrices[i] = if (tree == 1) &part.main else &part.interaction;
                    expected[i] = try std.math.mul(usize, if (tree == 1) A.crypto.secp256k1.layout.main(part.kind) else A.crypto.secp256k1.layout.interactionFor(part.kind, part.byte_policy), part.size());
                }
                if (!A.memory.ownership.same(a, s.bytes.allocator) or (tree == 1 and s.bytes.interaction.len != 0)) return error.InvalidTruthBufferOwner;
                protected[2] = s.bytes.fixed;
                protected[5] = if (tree == 1) s.bytes.interaction else s.bytes.main;
                matrices[2] = if (tree == 1) &s.bytes.main else &s.bytes.interaction;
                expected[2] = (if (tree == 1) @as(usize, 1) else 8) * 256;
            },
            .sha256, .arith256_mod, .curve, .secp_row => unreachable,
        }
        for (matrices, expected, 0..) |matrix, size, i| {
            if (matrix.len != size) return error.InvalidTruthBufferPhase;
            const end = try spanEnd(matrix.*);
            for (protected) |other| if (overlap(matrix.*, try spanEnd(other), other, end)) return error.AliasedTruthBuffers;
            for (matrices[0..i]) |previous| if (overlap(matrix.*, try spanEnd(previous.*), previous.*, end)) return error.AliasedTruthBuffers;
        }
        const headers = try self.columns(a, tree);
        errdefer a.free(headers);
        const backings = try a.alloc([]M, 3);
        errdefer a.free(backings);
        const byte_counts = if (tree == 1 and self.* == .secp) try a.dupe(M, self.secp.bytes.main) else null;
        // No fallible operation may follow this point.
        for (matrices, backings) |matrix, *backing| {
            backing.* = matrix.*;
            matrix.* = &.{};
        }
        if (tree == 1) switch (self.*) {
            .keccak => |*s| {
                s.permutation.owns_main = false;
                s.chi.owns_main = false;
                s.xor5.owns_main = false;
            },
            .secp => |*s| {
                s.batch.product.owns_main = false;
                s.batch.linear.owns_main = false;
                s.bytes.main = byte_counts.?;
            },
            .sha256, .arith256_mod, .curve, .secp_row => unreachable,
        };
        return .{ .columns = headers, .backings = backings };
    }
    pub fn deinit(self: *TruthSource) void {
        switch (self.*) {
            inline else => |*s| s.deinit(),
        }
    }
    pub fn releaseMain(self: *TruthSource) !void {
        switch (self.*) {
            inline else => |*s| try s.releaseMain(),
        }
    }
    pub fn columns(self: *const TruthSource, a: std.mem.Allocator, tree: usize) ![]Col {
        return switch (self.*) {
            inline else => |s| s.columns(a, tree),
        };
    }
};
/// Bridge calls of secp family `family` (0 ADD, 1 DOUBLE) with global call
/// IDs begin+1..end, in shard order (the same span rule as the RCB truth).
fn secpSpan(a: std.mem.Allocator, advice: *const @import("collector.zig").Advice, family: usize, begin: usize, end: usize, calls: u32) ![]S.types.Call {
    const inputs = try a.alloc(S.types.Call, calls);
    errdefer a.free(inputs);
    var offset: usize = 0;
    var written: usize = 0;
    for (advice.secp) |cc| {
        const lo = @max(begin, offset);
        const hi = @min(end, offset + cc[family].len);
        if (lo < hi) {
            const selected = cc[family][lo - offset .. hi - offset];
            @memcpy(inputs[written..][0..selected.len], selected);
            written += selected.len;
        }
        offset += cc[family].len;
    }
    if (written != calls) return error.InvalidCombinedTruthSpan;
    return inputs;
}
/// One wide SHA-256 MAIN/INTER matrix moves to the PCS; fixed stays key-owned.
fn takeSha(s: *A.crypto.sha256.trace.Source, tree: usize) !Commit {
    const a = s.allocator;
    try s.validateMetadata();
    const L = A.crypto.sha256.layout;
    const matrix = if (tree == 1) &s.main else &s.interaction;
    if (tree == 1 and (!s.owns_main or !A.memory.ownership.same(a, s.main_allocator orelse s.allocator))) return error.InvalidTruthBufferOwner;
    if ((tree == 1 and s.interaction.len != 0) or matrix.len != @as(usize, if (tree == 1) L.MAIN else L.INTERACTION) * s.size()) return error.InvalidTruthBufferPhase;
    const end = try spanEnd(matrix.*);
    const other = if (tree == 1) s.interaction else s.main;
    if (overlap(matrix.*, try spanEnd(s.fixed), s.fixed, end) or overlap(matrix.*, try spanEnd(other), other, end)) return error.AliasedTruthBuffers;
    const headers = try a.alloc(Col, L.widths()[tree]);
    errdefer a.free(headers);
    var at: usize = 0;
    append(headers, &at, matrix.*, s.log_size);
    const backings = try a.alloc([]M, 1);
    // No fallible operation may follow this point.
    backings[0] = matrix.*;
    matrix.* = &.{};
    if (tree == 1) s.owns_main = false;
    return .{ .columns = headers, .backings = backings };
}
/// One wide arith256 MAIN/INTER matrix moves to the PCS; fixed stays key-owned.
fn takeArith(s: *A.crypto.arith256.trace.Source, tree: usize) !Commit {
    const a = s.allocator;
    try s.validateMetadata();
    const L = A.crypto.arith256.layout;
    const matrix = if (tree == 1) &s.main else &s.interaction;
    if (tree == 1 and (!s.owns_main or !A.memory.ownership.same(a, s.main_allocator orelse s.allocator))) return error.InvalidTruthBufferOwner;
    if ((tree == 1 and s.interaction.len != 0) or matrix.len != @as(usize, if (tree == 1) L.MAIN else L.INTERACTION) * s.size()) return error.InvalidTruthBufferPhase;
    const end = try spanEnd(matrix.*);
    const other = if (tree == 1) s.interaction else s.main;
    if (overlap(matrix.*, try spanEnd(s.fixed), s.fixed, end) or overlap(matrix.*, try spanEnd(other), other, end)) return error.AliasedTruthBuffers;
    const headers = try a.alloc(Col, L.widths()[tree]);
    errdefer a.free(headers);
    var at: usize = 0;
    append(headers, &at, matrix.*, s.log_size);
    const backings = try a.alloc([]M, 1);
    // No fallible operation may follow this point.
    backings[0] = matrix.*;
    matrix.* = &.{};
    if (tree == 1) s.owns_main = false;
    return .{ .columns = headers, .backings = backings };
}
/// One wide curve/field MAIN/INTER matrix moves to the PCS; fixed stays key-owned.
fn takeCurve(s: anytype, tree: usize) !Commit {
    const a = s.allocator;
    try s.validateMetadata();
    const Src = @typeInfo(@TypeOf(s)).pointer.child;
    const L = @import("stwo_riscv_frontend").rv64_air.crypto.curves.trace.Trace(Src.OP).L;
    const matrix = if (tree == 1) &s.main else &s.interaction;
    if (tree == 1 and (!s.owns_main or !A.memory.ownership.same(a, s.main_allocator orelse s.allocator))) return error.InvalidTruthBufferOwner;
    if ((tree == 1 and s.interaction.len != 0) or matrix.len != @as(usize, if (tree == 1) L.MAIN else L.INTERACTION) * s.size()) return error.InvalidTruthBufferPhase;
    const end = try spanEnd(matrix.*);
    const other = if (tree == 1) s.interaction else s.main;
    if (overlap(matrix.*, try spanEnd(s.fixed), s.fixed, end) or overlap(matrix.*, try spanEnd(other), other, end)) return error.AliasedTruthBuffers;
    const headers = try a.alloc(Col, L.widths()[tree]);
    errdefer a.free(headers);
    var at: usize = 0;
    append(headers, &at, matrix.*, s.log_size);
    const backings = try a.alloc([]M, 1);
    // No fallible operation may follow this point.
    backings[0] = matrix.*;
    matrix.* = &.{};
    if (tree == 1) s.owns_main = false;
    return .{ .columns = headers, .backings = backings };
}

pub fn appendTrace(out: []@import("stwo_prover_api").device_pcs.TraceColumn, at: *usize, data: []const M, log: u32) void {
    const n = @as(usize, 1) << @intCast(log);
    for (0..data.len / n) |i| {
        out[at.*] = .{ .log_size = log, .encoding = .evaluations, .host = data[i * n ..][0..n] };
        at.* += 1;
    }
}

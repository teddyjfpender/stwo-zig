//! One projection adapter over authentic legacy metadata and the tiny frontier.
//! The frontier consumes the SAME OWNER/range namespace as the real CPU, while
//! its Wire35 term remains an explicit shared global obligation.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const F = A.crypto.keccak_sponge.serialized.frontier;
const Old = @import("../../word16_global_execution/services/gkr_local/native_provider.zig");
const RowSink = @import("../../word16_global_execution/services/gkr_local/inputs.zig").RowSink;
const Frame = @import("frame.zig");
pub const Challenges = @import("../../word16_global_execution/services/gkr_local/challenges.zig").For(O);
pub const Provider = struct {
    legacy: Old.Provider,
    frontier: *const @import("source.zig").Source,
    pub fn emit(self: Provider, instance: Frame.Instance, logical: usize, sink: *RowSink) !void {
        switch (instance) {
            .legacy => |real| {
                if (real.origin == .sponge) return error.SpongeCpuRequiresDetachedSetup;
                try self.legacy.emit(real, logical, sink);
            },
            .frontier => |shape| {
                if (shape.row_log != self.frontier.log) return error.SpongeCpuGeometry;
                const row = try self.frontier.row(logical);
                var adapter = FrontierSink{ .target = sink };
                F.emitRaw(M, &row, M.fromCanonical(self.frontier.ordinal), &adapter);
                if (adapter.local_count != F.LOCAL_QUERIES or adapter.wire_count != 1) return error.SpongeCpuProjectionAuthority;
            },
        }
    }
    pub fn emitRange(self: Provider, instance: Frame.Instance, logical: usize, first: usize, n: []M, d: []O, challenges: Challenges) !void {
        if (logical >= try instance.rows() or first > instance.queries() or n.len != d.len or n.len > instance.queries() - first) return error.SpongeCpuProjectionShape;
        var numerator: [Frame.MAX_LOCAL_TERMS]M = undefined;
        var denominator: [Frame.MAX_LOCAL_TERMS]O = undefined;
        const count = instance.queries();
        var sink = RowSink{ .challenges = &challenges, .numerator = numerator[0..count], .denominator = denominator[0..count] };
        try self.emit(instance, logical, &sink);
        if (sink.invalid or sink.count != count) return error.SpongeCpuProjectionShape;
        @memcpy(n, numerator[first..][0..n.len]);
        @memcpy(d, denominator[first..][0..d.len]);
    }
};
pub const FrontierSink = struct {
    target: *RowSink,
    local_count: usize = 0,
    wire_count: usize = 0,
    pub fn emit(self: *FrontierSink, comptime relation: usize, tuple: anytype, weight: M) void {
        // Compile-time relation and exact arity checks make a source change
        // fail closed instead of accidentally hiding a new local obligation.
        switch (relation) {
            A.crypto.keccak_sponge.equations.OWNER => {
                if (tuple.len != 19) @compileError("frontier OWNER arity changed");
                self.target.emitBase(.owner, tuple, weight);
            },
            A.crypto.keccak_sponge.equations.RANGE16 => {
                if (tuple.len != 1) @compileError("frontier U16 arity changed");
                self.target.emitBase(.range16, tuple, weight);
            },
            A.crypto.keccak_sponge.equations.RANGE8 => {
                if (tuple.len != 1) @compileError("frontier U8 arity changed");
                self.target.emitBase(.range8, tuple, weight);
            },
            F.WIRE => {
                if (tuple.len != 35) @compileError("frontier Wire arity changed");
                self.wire_count += 1;
                return;
            },
            else => @compileError("unaccounted frontier relation"),
        }
        self.local_count += 1;
    }
};
test "sponge CPU frontier local emitter preserves complete OWNER and padded clock debt" {
    const source = @import("source.zig");
    var frontier = try source.Source.init(std.testing.allocator, &.{.{ .pointer = 0x8000000000000fe0, .epoch = 2, .tick = 0x10303 }}, 1, 5, 2, 1);
    defer frontier.deinit();
    // No legacy provider is dereferenced on the explicitly typed frontier.
    const provider = Provider{ .legacy = .{ .source = undefined }, .frontier = &frontier };
    const instance = Frame.Instance{ .frontier = .{ .row_log = 5, .fixed_offset = 0, .main_offset = 0 } };
    const ch = Challenges{ .offsets = @splat(O.fromBase(M.fromCanonical(13))), .coefficients = @splat(@splat(O.one())) };
    var n: [3]M = undefined;
    var d: [3]O = undefined;
    try provider.emitRange(instance, 0, 0, &n, &d, ch);
    const row = try frontier.row(0);
    try std.testing.expectEqual(M.one().neg(), n[0]);
    try std.testing.expectEqual(ch.denominatorBase(.owner, F.owner(M, &row)), d[0]);
    try std.testing.expectEqual(M.one(), n[1]);
    try std.testing.expectEqual(M.one(), n[2]);
    try provider.emitRange(instance, 31, 0, &n, &d, ch);
    try std.testing.expectEqual(M.zero(), n[0]);
    try std.testing.expectEqual(M.one(), n[1]);
    try std.testing.expectEqual(M.one(), n[2]);
}

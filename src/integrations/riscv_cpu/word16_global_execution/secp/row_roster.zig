//! secp256k1 `row_v1` truth keys and witness owners for the canonical services
//! lane (v3 only): one RCB ADD/DOUBLE call per row on the generic curve/field
//! authority (`curves.spec.secpDef`), replacing the product/linear/BYTE RCB
//! providers of `roster.zig`. A key depends only on (kind, log); calls and
//! packets never enter fixed material. Wire declaration: `logs = .{ log, 0 }`
//! (a zero second log is never a valid RCB linear log, so the two profiles
//! are disjoint on the wire).
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const C = A.crypto.curves;
const B = A.crypto.secp256k1.word16_bridge;
const Key = @import("../keccak/shared/key.zig").Key;
const append = @import("../keccak/roster.zig").append;
const M = core.fields.m31.M31;
const Col = engine.pcs.ColumnEvaluation;
pub const Kind = C.spec.SecpKind;
/// Bounded per-truth capacity (2^16 - 1 calls); larger blocks use several spans.
pub const MAX_LOG: u32 = 16;
/// Wire `logs[1]` of a row truth.
pub const PROFILE_WORD: u32 = 0;
/// Transcript identity of the row profile (mixed in `beginTruth`).
pub const IDENTITY: u32 = 0x53524f57; // "SROW"

pub fn widths(kind: Kind) [3]usize {
    return switch (kind) {
        inline else => |k| C.Layout(k).widths(),
    };
}
pub fn validateGeometry(kind: Kind, calls: usize, first_id: u32, log: u32) !void {
    if (log > MAX_LOG) return error.InvalidServicesTruthGeometry;
    return switch (kind) {
        inline else => |k| C.Layout(k).validateGeometry(calls, first_id, log),
    };
}
pub fn logSize(kind: Kind, calls: usize) !u32 {
    return switch (kind) {
        inline else => |k| C.Layout(k).logSize(calls),
    };
}
/// Wire35 fractions per call: every packet coordinate plus each written one.
pub fn wireFractions(kind: Kind) u64 {
    return switch (kind) {
        inline else => |k| C.Layout(k).WIRE_FRACTIONS,
    };
}
/// Committed MAIN + INTERACTION cells of one truth proof of `log`.
pub fn cells(kind: Kind, log: u32) u64 {
    const w = widths(kind);
    return @as(u64, w[1] + w[2]) << @intCast(log);
}
/// Geometry words mixed into a truth's transcript spec.
pub fn geometryWords(kind: Kind) [8]u32 {
    return switch (kind) {
        inline else => |k| blk: {
            const L = C.Layout(k);
            break :blk .{ @intFromEnum(k), C.layout.FIXED, L.MAIN, L.INTERACTION, L.CONSTRAINTS, L.BYTE_QUERIES, L.TAG, L.RELATIONS };
        },
    };
}

pub const TruthSetup = struct {
    allocator: std.mem.Allocator,
    kind: Kind,
    log: u32,
    fixed: []M,
    key: Key,
    pub fn init(a: std.mem.Allocator, kind: Kind, log: u32) !TruthSetup {
        return initWithSuite(a, kind, log, Key.Suite.production());
    }
    pub fn initWithSuite(a: std.mem.Allocator, kind: Kind, log: u32, suite: Key.Suite) !TruthSetup {
        try suite.validate();
        try validateGeometry(kind, 0, 1, log);
        const fixed = try C.trace.fixed(a, log);
        errdefer a.free(fixed);
        var self = TruthSetup{ .allocator = a, .kind = kind, .log = log, .fixed = fixed, .key = undefined };
        const cols = try self.fixedColumns(a);
        defer a.free(cols);
        self.key = try Key.sealWithSuite(a, cols, suite);
        return self;
    }
    pub fn deinit(self: *TruthSetup) void {
        self.key.deinit();
        self.allocator.free(self.fixed);
    }
    pub fn fixedColumns(self: *const TruthSetup, a: std.mem.Allocator) ![]Col {
        const out = try a.alloc(Col, C.layout.FIXED);
        var at: usize = 0;
        append(out, &at, self.fixed, self.log);
        return out;
    }
    pub fn logs(self: *const TruthSetup, a: std.mem.Allocator, tree: usize) ![]u32 {
        const out = try a.alloc(u32, widths(self.kind)[tree]);
        @memset(out, self.log);
        return out;
    }
};

/// Packet bytes of one bridge call (the first 32 * coords bytes of `before`).
pub fn packetOf(comptime kind: Kind, call: *const B.types.Call) C.Native(kind).Packet {
    var out: C.Native(kind).Packet = undefined;
    for (&out, 0..) |*b, i| b.* = @truncate(call.before[i / 8] >> @intCast(8 * (i % 8)));
    return out;
}

/// One typed truth source per kind.
pub const TruthSource = union(Kind) {
    add: C.Trace(Kind.add).Source,
    double: C.Trace(Kind.double).Source,
    pub fn init(a: std.mem.Allocator, setup: *const TruthSetup, calls: []const B.types.Call, first_id: u32) !TruthSource {
        switch (setup.kind) {
            inline else => |kind| {
                const N = C.Native(kind);
                const packets = try a.alloc(N.Packet, calls.len);
                defer a.free(packets);
                for (calls, packets) |*call, *p| p.* = packetOf(kind, call);
                var source = try C.Trace(kind).Source.init(a, packets, first_id, setup.log);
                // The fixed tree is key material; never keep a second copy here.
                a.free(source.fixed);
                source.fixed = setup.fixed;
                source.owns_fixed = false;
                return @unionInit(TruthSource, @tagName(kind), source);
            },
        }
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
        switch (self.*) {
            inline else => |s, kind| {
                const out = try a.alloc(Col, C.Layout(kind).widths()[tree]);
                var at: usize = 0;
                append(out, &at, if (tree == 1) s.main else s.interaction, s.log_size);
                return out;
            },
        }
    }
    pub fn generateInteraction(self: *TruthSource, ch: C.equations.Challenges) !core.fields.qm31.QM31 {
        switch (self.*) {
            inline else => |*s| return s.generateInteraction(ch),
        }
    }
};

/// Typed truth component of one span, runtime-selected by kind.
pub const Component = union(Kind) {
    add: C.Component(Kind.add),
    double: C.Component(Kind.double),
    pub fn init(kind: Kind, log: u32, calls: u32, first_id: u32, claim: core.fields.qm31.QM31, ch: C.equations.Challenges) Component {
        switch (kind) {
            inline else => |k| return @unionInit(Component, @tagName(k), .{ .log_size = log, .public = .{ .calls = calls, .first_id = first_id }, .claim = claim, .challenges = ch }),
        }
    }
    pub fn asProverComponent(self: *const Component) engine.air.component_prover.ComponentProver {
        switch (self.*) {
            inline else => |*c| return c.asProverComponent(),
        }
    }
    pub fn asVerifierComponent(self: *const Component) core.air.components.Component {
        switch (self.*) {
            inline else => |*c| return c.asVerifierComponent(),
        }
    }
};

test "row profile cells and wire geometry" {
    // The receiver's wire accounting and the planner's cost rule.
    try std.testing.expectEqual(@as(u64, 9), wireFractions(.add));
    try std.testing.expectEqual(@as(u64, 6), wireFractions(.double));
    try std.testing.expectEqual(@as(u64, B.types.coordinates(.add) + B.types.written(.add)), wireFractions(.add));
}

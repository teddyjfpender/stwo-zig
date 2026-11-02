//! Curve/field truth keys and witness owners for the canonical services lane.
//! A key depends only on (op, log size); calls/packets never enter fixed material.
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
pub const Op = C.Op;
/// Bounded per-truth capacity; larger blocks use several spans.
pub const MAX_LOG: u32 = 16;

pub fn widths(op: Op) [3]usize {
    return switch (op) {
        inline else => |o| C.Layout(o).widths(),
    };
}
pub fn validateGeometry(op: Op, calls: usize, first_id: u32, log: u32) !void {
    return switch (op) {
        inline else => |o| C.Layout(o).validateGeometry(calls, first_id, log),
    };
}
pub fn logSize(op: Op, calls: usize) !u32 {
    return switch (op) {
        inline else => |o| C.Layout(o).logSize(calls),
    };
}
pub fn wireFractions(op: Op) u64 {
    return switch (op) {
        inline else => |o| C.Layout(o).WIRE_FRACTIONS,
    };
}
/// Geometry words mixed into a truth's transcript spec.
pub fn geometryWords(op: Op) [7]u32 {
    return switch (op) {
        inline else => |o| blk: {
            const L = C.Layout(o);
            break :blk .{ @intFromEnum(o), @import("stwo_riscv_frontend").rv64_air.crypto.curves.layout.FIXED, L.MAIN, L.INTERACTION, L.CONSTRAINTS, L.BYTE_QUERIES, L.TAG };
        },
    };
}

pub const TruthSetup = struct {
    allocator: std.mem.Allocator,
    op: Op,
    log: u32,
    fixed: []M,
    key: Key,
    pub fn init(a: std.mem.Allocator, op: Op, log: u32) !TruthSetup {
        return initWithSuite(a, op, log, Key.Suite.production());
    }
    pub fn initWithSuite(a: std.mem.Allocator, op: Op, log: u32, suite: Key.Suite) !TruthSetup {
        try suite.validate();
        if (log > MAX_LOG) return error.CurveTruthGeometryBudget;
        try validateGeometry(op, 0, 1, log);
        const fixed = try C.trace.fixed(a, log);
        errdefer a.free(fixed);
        var self = TruthSetup{ .allocator = a, .op = op, .log = log, .fixed = fixed, .key = undefined };
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
        const out = try a.alloc(u32, widths(self.op)[tree]);
        @memset(out, self.log);
        return out;
    }
};

/// Packet bytes of one bridge call (the first 32 * coords bytes of `before`).
pub fn packetOf(comptime op: Op, call: *const B.types.Call) C.Native(op).Packet {
    var out: C.Native(op).Packet = undefined;
    for (&out, 0..) |*b, i| b.* = @truncate(call.before[i / 8] >> @intCast(8 * (i % 8)));
    return out;
}

/// One typed truth source per op (runtime-selected by the declared family).
pub const TruthSource = union(Op) {
    bn254_g1_add: C.Trace(.bn254_g1_add).Source,
    bn254_g1_double: C.Trace(.bn254_g1_double).Source,
    bn254_fp2_mul: C.Trace(.bn254_fp2_mul).Source,
    bls12_381_fp2_mul: C.Trace(.bls12_381_fp2_mul).Source,
    arith384_mont: C.Trace(.arith384_mont).Source,
    bls12_381_g1_add: C.Trace(.bls12_381_g1_add).Source,
    bls12_381_g1_double: C.Trace(.bls12_381_g1_double).Source,
    /// Bridge packets for calls first_id..first_id+n-1.
    pub fn init(a: std.mem.Allocator, setup: *const TruthSetup, calls: []const B.types.Call, first_id: u32) !TruthSource {
        switch (setup.op) {
            inline else => |op| {
                const N = C.Native(op);
                const packets = try a.alloc(N.Packet, calls.len);
                defer a.free(packets);
                for (calls, packets) |*call, *p| p.* = packetOf(op, call);
                var source = try C.Trace(op).Source.init(a, packets, first_id, setup.log);
                // The fixed tree is key material; never keep a second copy here.
                a.free(source.fixed);
                source.fixed = setup.fixed;
                source.owns_fixed = false;
                return @unionInit(TruthSource, @tagName(op), source);
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
            inline else => |s, op| {
                const out = try a.alloc(Col, C.Layout(op).widths()[tree]);
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

/// Typed truth component of one span, runtime-selected by op.
pub const Component = union(Op) {
    bn254_g1_add: C.Component(.bn254_g1_add),
    bn254_g1_double: C.Component(.bn254_g1_double),
    bn254_fp2_mul: C.Component(.bn254_fp2_mul),
    bls12_381_fp2_mul: C.Component(.bls12_381_fp2_mul),
    arith384_mont: C.Component(.arith384_mont),
    bls12_381_g1_add: C.Component(.bls12_381_g1_add),
    bls12_381_g1_double: C.Component(.bls12_381_g1_double),
    pub fn init(op: Op, log: u32, calls: u32, first_id: u32, claim: core.fields.qm31.QM31, ch: C.equations.Challenges) Component {
        switch (op) {
            inline else => |o| return @unionInit(Component, @tagName(o), .{ .log_size = log, .public = .{ .calls = calls, .first_id = first_id }, .claim = claim, .challenges = ch }),
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

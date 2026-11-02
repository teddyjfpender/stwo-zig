//! SHA-256 truth key and witness owners for the canonical services lane. The
//! key depends only on log size; calls/inputs never enter fixed material.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const H = A.crypto.sha256;
const B = A.crypto.secp256k1.word16_bridge;
const Key = @import("../keccak/shared/key.zig").Key;
const append = @import("../keccak/roster.zig").append;
const M = core.fields.m31.M31;
const Col = engine.pcs.ColumnEvaluation;
/// Bounded per-truth capacity; larger blocks use several spans.
pub const MAX_LOG: u32 = 13;
pub const TruthSetup = struct {
    allocator: std.mem.Allocator,
    log: u32,
    fixed: []M,
    key: Key,
    pub fn init(a: std.mem.Allocator, log: u32) !TruthSetup {
        return initWithSuite(a, log, Key.Suite.production());
    }
    pub fn initWithSuite(a: std.mem.Allocator, log: u32, suite: Key.Suite) !TruthSetup {
        try suite.validate();
        if (log > MAX_LOG) return error.Sha256TruthGeometryBudget;
        const fixed = try H.trace.fixed(a, log);
        errdefer a.free(fixed);
        var self = TruthSetup{ .allocator = a, .log = log, .fixed = fixed, .key = undefined };
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
        const out = try a.alloc(Col, H.layout.FIXED);
        var at: usize = 0;
        append(out, &at, self.fixed, self.log);
        return out;
    }
    pub fn logs(self: *const TruthSetup, a: std.mem.Allocator, tree: usize) ![]u32 {
        const out = try a.alloc(u32, H.layout.widths()[tree]);
        @memset(out, self.log);
        return out;
    }
};
pub const TruthSource = struct {
    source: H.trace.Source,
    /// Bridge packets (12 words) for calls first_id..first_id+n-1.
    pub fn init(a: std.mem.Allocator, setup: *const TruthSetup, calls: []const B.types.Call, first_id: u32) !TruthSource {
        const inputs = try a.alloc(H.native.Input, calls.len);
        defer a.free(inputs);
        for (calls, inputs) |call, *input| input.* = H.native.fromPacket(call.before[0..12]);
        var source = try H.trace.Source.init(a, inputs, first_id, setup.log);
        // The fixed tree is key material; never keep a second copy here.
        a.free(source.fixed);
        source.fixed = setup.fixed;
        source.owns_fixed = false;
        return .{ .source = source };
    }
    pub fn deinit(self: *TruthSource) void {
        self.source.deinit();
    }
    pub fn releaseMain(self: *TruthSource) !void {
        try self.source.releaseMain();
    }
    pub fn columns(self: *const TruthSource, a: std.mem.Allocator, tree: usize) ![]Col {
        const out = try a.alloc(Col, H.layout.widths()[tree]);
        var at: usize = 0;
        append(out, &at, if (tree == 1) self.source.main else self.source.interaction, self.source.log_size);
        return out;
    }
};

//! Optional concrete Keccak roster materials. The absence variant allocates
//! no permutation, lane bridge or truth-table source. No key/root is forged.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
const K = rv.crypto.keccak;
const Storage = rv.crypto.main_storage;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
pub const Roster = enum(u32) { paired = 1, none = 2 };
pub const FIXED = K.layout.FIXED + 14 + K.bridge.layout.FIXED;
pub const MAIN = K.layout.MAIN + 2 + K.bridge.layout.MAIN;
pub const INTERACTION = K.layout.INTERACTION + 8 + K.bridge.layout.INTERACTION;
fn append(out: []Column, at: *usize, storage: []const M, log: u32) void {
    const n = @as(usize, 1) << @intCast(log);
    for (0..storage.len / n) |c| {
        out[at.*] = .{ .log_size = log, .values = storage[c * n ..][0..n] };
        at.* += 1;
    }
}
pub const Materials = struct {
    allocator: std.mem.Allocator,
    keccak_log: u32,
    bridge_log: u32,
    keccak_fixed: []M,
    bridge_fixed: []M,
    chi: K.tables.Trace,
    xor5: K.tables.Trace,
    pub fn init(a: std.mem.Allocator, klog: u32, blog: u32) !Materials {
        const keccak_fixed = try K.trace.fixedColumnsForLog(a, klog);
        errdefer a.free(keccak_fixed);
        const bridge_fixed = try K.bridge.trace.fixedColumnsForLog(a, blog);
        errdefer a.free(bridge_fixed);
        const chi_zero: [8192]u64 = @splat(0);
        const xor_zero: [1024]u64 = @splat(0);
        var chi = try K.tables.Trace.init(a, .chi, &chi_zero);
        errdefer chi.deinit();
        return .{ .allocator = a, .keccak_log = klog, .bridge_log = blog, .keccak_fixed = keccak_fixed, .bridge_fixed = bridge_fixed, .chi = chi, .xor5 = try K.tables.Trace.init(a, .xor5, &xor_zero) };
    }
    pub fn deinit(self: *Materials) void {
        self.allocator.free(self.keccak_fixed);
        self.allocator.free(self.bridge_fixed);
        self.chi.deinit();
        self.xor5.deinit();
        self.* = undefined;
    }
    pub fn appendFixed(self: *const Materials, out: []Column, at: *usize) void {
        append(out, at, self.keccak_fixed, self.keccak_log);
        append(out, at, self.chi.fixed, 13);
        append(out, at, self.xor5.fixed, 10);
        append(out, at, self.bridge_fixed, self.bridge_log);
    }
};
pub const MainBuffers = struct {
    permutation: []M,
    chi: []M,
    xor5: []M,
    bridge: []M,
    pub fn slices(self: MainBuffers, klog: u32, blog: u32) [4]Storage.Slice {
        return .{ .{ .values = self.permutation, .cells = K.layout.MAIN * (@as(usize, 1) << @intCast(klog)) }, .{ .values = self.chi, .cells = 8192 }, .{ .values = self.xor5, .cells = 1024 }, .{ .values = self.bridge, .cells = K.bridge.layout.MAIN * (@as(usize, 1) << @intCast(blog)) } };
    }
    pub fn validate(self: MainBuffers, calls: usize, first_id: u32, klog: u32, blog: u32) !void {
        try K.layout.validateGeometry(calls, first_id, klog);
        try K.bridge.trace.validateGeometry(calls, first_id, blog);
        try Storage.validate(&self.slices(klog, blog));
    }
};
pub const Claims = struct { permutation: Q, chi: Q, xor5: Q, bridge: Q };
pub const Trace = struct {
    permutation: K.trace.Trace,
    chi: K.tables.Trace,
    xor5: K.tables.Trace,
    bridge: K.bridge.trace.Trace,
    pub fn init(a: std.mem.Allocator, calls: []const K.bridge.trace.Call, first_id: u32, klog: u32, blog: u32) !Trace {
        return initWithMainAllocator(a, a, calls, first_id, klog, blog);
    }
    pub fn initWithMainAllocator(a: std.mem.Allocator, main_allocator: std.mem.Allocator, calls: []const K.bridge.trace.Call, first_id: u32, klog: u32, blog: u32) !Trace {
        return create(a, main_allocator, calls, first_id, klog, blog, null);
    }
    pub fn initWithMainBuffers(a: std.mem.Allocator, calls: []const K.bridge.trace.Call, first_id: u32, klog: u32, blog: u32, main: MainBuffers) !Trace {
        return create(a, a, calls, first_id, klog, blog, main);
    }
    fn create(a: std.mem.Allocator, main_allocator: std.mem.Allocator, calls: []const K.bridge.trace.Call, first_id: u32, klog: u32, blog: u32, main: ?MainBuffers) !Trace {
        if (main) |m| {
            try m.validate(calls.len, first_id, klog, blog);
            try Storage.exclude(&m.slices(klog, blog), std.mem.sliceAsBytes(calls));
        }
        const inputs = try a.alloc(K.trace.State, calls.len);
        defer a.free(inputs);
        for (calls, inputs) |call, *input| input.* = call.before;
        var permutation = if (main) |m| try K.trace.Trace.initWithMainBuffer(a, inputs, first_id, klog, m.permutation) else try K.trace.Trace.initWithLogAndMainAllocator(a, main_allocator, inputs, first_id, klog);
        errdefer permutation.deinit();
        const counts = try K.interaction.Counts.fromTrace(&permutation);
        var chi = if (main) |m| try K.tables.Trace.initWithMainBuffer(a, .chi, &counts.chi, m.chi) else try K.tables.Trace.initWithMainAllocator(a, main_allocator, .chi, &counts.chi);
        errdefer chi.deinit();
        var xor5 = if (main) |m| try K.tables.Trace.initWithMainBuffer(a, .xor5, &counts.xor5, m.xor5) else try K.tables.Trace.initWithMainAllocator(a, main_allocator, .xor5, &counts.xor5);
        errdefer xor5.deinit();
        return .{ .permutation = permutation, .chi = chi, .xor5 = xor5, .bridge = if (main) |m| try K.bridge.trace.Trace.initWithMainBuffer(a, calls, first_id, blog, m.bridge) else try K.bridge.trace.Trace.initWithLogAndMainAllocator(a, main_allocator, calls, first_id, blog) };
    }
    pub fn deinit(self: *Trace) void {
        self.bridge.deinit();
        self.xor5.deinit();
        self.chi.deinit();
        self.permutation.deinit();
        self.* = undefined;
    }
    /// All main storage may be adopted immediately after its root is sealed.
    /// Narrow metadata/fixed/interaction storage remains with the general allocator.
    pub fn takeMain(self: *Trace) ![4][]M {
        if (!self.permutation.owns_main or !self.chi.owns_main or !self.xor5.owns_main or !self.bridge.owns_main) return error.BorrowedCryptoMain;
        try self.permutation.validateMetadata();
        try self.chi.validateMetadata();
        try self.xor5.validateMetadata();
        try self.bridge.validateMetadata();
        if (self.permutation.main.len != K.layout.MAIN * self.permutation.size() or self.chi.main.len != 8192 or self.xor5.main.len != 1024 or self.bridge.main.len != K.bridge.layout.MAIN * self.bridge.size()) return error.InvalidKeccakMainPhase;
        const result = [4][]M{ self.permutation.main, self.chi.main, self.xor5.main, self.bridge.main };
        self.permutation.main = &.{};
        self.chi.main = &.{};
        self.xor5.main = &.{};
        self.bridge.main = &.{};
        if (self.permutation.interaction.len != 0 and self.chi.interaction.len != 0 and self.xor5.interaction.len != 0 and self.bridge.interaction.len != 0) try self.releaseMetadata();
        return result;
    }
    pub fn releaseMain(self: *Trace) !void {
        if (self.permutation.main.len != K.layout.MAIN * self.permutation.size() or self.chi.main.len != 8192 or self.xor5.main.len != 1024 or self.bridge.main.len != K.bridge.layout.MAIN * self.bridge.size()) return error.InvalidKeccakMainPhase;
        try self.permutation.validateMetadata();
        try self.chi.validateMetadata();
        try self.xor5.validateMetadata();
        try self.bridge.validateMetadata();
        try self.permutation.releaseMain();
        try self.chi.releaseMain();
        try self.xor5.releaseMain();
        try self.bridge.releaseMain();
        if (self.permutation.interaction.len != 0 and self.chi.interaction.len != 0 and self.xor5.interaction.len != 0 and self.bridge.interaction.len != 0) try self.releaseMetadata();
    }
    pub fn appendMain(self: *const Trace, out: []Column, at: *usize) void {
        append(out, at, self.permutation.main, self.permutation.log_size);
        append(out, at, self.chi.main, 13);
        append(out, at, self.xor5.main, 10);
        append(out, at, self.bridge.main, self.bridge.log_size);
    }
    pub fn appendInteraction(self: *const Trace, out: []Column, at: *usize) void {
        append(out, at, self.permutation.interaction, self.permutation.log_size);
        append(out, at, self.chi.interaction, 13);
        append(out, at, self.xor5.interaction, 10);
        append(out, at, self.bridge.interaction, self.bridge.log_size);
    }
    pub fn releaseMetadata(self: *Trace) !void {
        if (self.permutation.main.len != 0 or self.chi.main.len != 0 or self.xor5.main.len != 0 or self.bridge.main.len != 0 or self.permutation.interaction.len != K.layout.INTERACTION * self.permutation.size() or self.chi.interaction.len != 4 * 8192 or self.xor5.interaction.len != 4 * 1024 or self.bridge.interaction.len != K.bridge.layout.INTERACTION * self.bridge.size()) return error.InvalidKeccakMainPhase;
        self.permutation.allocator.free(self.permutation.metadata);
        self.permutation.metadata = &.{};
        self.chi.allocator.free(self.chi.multiplicities);
        self.chi.multiplicities = &.{};
        self.xor5.allocator.free(self.xor5.multiplicities);
        self.xor5.multiplicities = &.{};
        self.bridge.allocator.free(self.bridge.metadata);
        self.bridge.metadata = &.{};
    }
    pub fn generate(self: *Trace, keccak: K.equations.Challenges, bridge: K.bridge.equations.Challenges) !Claims {
        return self.generateWithOptions(keccak, bridge, .{ .pool = engine.work_pool.currentScopedPool() });
    }
    pub fn generateWithOptions(self: *Trace, keccak: K.equations.Challenges, bridge: K.bridge.equations.Challenges, options: K.interaction.Options) !Claims {
        const result = Claims{ .permutation = try K.interaction.generateWithOptions(&self.permutation, keccak, options), .chi = try self.chi.generateInteraction(keccak), .xor5 = try self.xor5.generateInteraction(keccak), .bridge = try self.bridge.generateInteraction(bridge) };
        if (self.permutation.main.len == 0 and self.chi.main.len == 0 and self.xor5.main.len == 0 and self.bridge.main.len == 0) try self.releaseMetadata();
        return result;
    }
};

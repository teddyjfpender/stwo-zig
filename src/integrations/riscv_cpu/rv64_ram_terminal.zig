//! ONE final q70/P26 root-observation certificate. Public root equality links
//! this certificate to the last authenticated CPU/RAM after-root; independent
//! LogUp claims are NEVER added. The outer receiver binds absorbing final PC.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const R = frontend.rv64_air.memory;
const Memory = frontend.rv64.memory.Memory;
const graph = @import("rv64_ram_private.zig");
pub const OUTPUT_BYTES = R.terminal_air.OUTPUT_BYTES;
pub const Statement = struct {
    geometry: R.values.Geometry,
    root: R.values.Digest,
    policy: *const R.policy.Policy,
    halt_flag: u64,
    output: [OUTPUT_BYTES]u8,
    pub fn spec(self: Statement) R.terminal_air.Spec {
        return .{ .geometry = self.geometry, .halt_flag = self.halt_flag, .output = self.output };
    }
    pub fn graphStatement(self: Statement) graph.Statement {
        return .{ .geometry = self.geometry, .before = self.root, .after = self.root, .policy = self.policy };
    }
    pub fn validate(self: Statement) !void {
        try self.spec().validate();
        try self.policy.validateImmutableExecution();
        for (self.root) |word| if (word >= 0x7fff_ffff) return error.NonCanonicalDigest;
        _ = try self.policy.find(if (self.geometry == .chunk512) .chunk512 else .page4096, self.spec().base(), 3);
    }
};
/// Bounded private opening from the current final native image. No execution
/// replay, all-RAM snapshot, synthetic memory access, or host output hash claim.
pub fn trace(a: std.mem.Allocator, public: Statement, cache: *const R.values.Cache, memory: *const Memory) !R.private_trace.Trace {
    try public.validate();
    if (cache.geometry != public.geometry or !R.values.equal(cache.root(), public.root)) return error.TerminalRootMismatch;
    var words: [512]u64 = @splat(0);
    const base = public.spec().base();
    const backing = memory.backing.table.get(base >> 12);
    if (backing) |page| for (words[0..public.geometry.cells()], 0..) |*word, i| {
        const offset = @as(usize, @intCast(base & 4095)) + i * 8;
        word.* = std.mem.readInt(u64, page[offset..][0..8], .little);
    };
    const clocks: [512]u32 = @splat(0);
    const rights: [512]u2 = @splat(3);
    const opening = [_]R.batch.Opening{.{ .index = base >> public.geometry.logBytes(), .before = words[0..public.geometry.cells()], .after = words[0..public.geometry.cells()], .terminal_clocks = clocks[0..public.geometry.cells()], .rights = rights[0..public.geometry.cells()] }};
    return R.private_trace.Trace.initObservation(a, cache, public.policy, &opening);
}
pub fn prove(a: std.mem.Allocator, public: Statement, cache: *const R.values.Cache, memory: *const Memory) ![]u8 {
    var witness = try trace(a, public, cache, memory);
    defer witness.deinit();
    return graph.proveTerminalReceipt(a, public.graphStatement(), &witness, public.spec());
}
pub fn verify(a: std.mem.Allocator, public: Statement, bytes: []const u8) !void {
    try public.validate();
    try graph.verifyTerminalReceipt(a, public.graphStatement(), public.spec(), bytes);
}
/// The reduced-security mode is confined to explicitly named diagnostic gates.
pub fn proveDiagnostic(a: std.mem.Allocator, public: Statement, cache: *const R.values.Cache, memory: *const Memory) ![]u8 {
    var witness = try trace(a, public, cache, memory);
    defer witness.deinit();
    return graph.proveTerminalDiagnostic(a, public.graphStatement(), &witness, public.spec());
}
pub fn verifyDiagnostic(a: std.mem.Allocator, public: Statement, bytes: []const u8) !void {
    try public.validate();
    try graph.verifyTerminalDiagnostic(a, public.graphStatement(), public.spec(), bytes);
}

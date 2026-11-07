//! Device node_oods_constraint check (GPU-native design §3.5, host work H22;
//! kernel stwo_rv64_outer_oods_check_v1_on in NAT/rv64/jobs/outer_checks.cu).
//!
//! The host's last proof-level check of an outer node
//! (outer_job_prestage.assemble) evaluates the composition polynomial at the
//! OODS point from the sampled mask values (om31 component.zig
//! evaluateConstraintQuotientsAtPoint over every component, accumulated with
//! the composition coefficient) and requires it to equal the value the
//! composition tree's samples reconstruct (proof extractCompositionOodsEval).
//! On the device the same computation runs from a per-class "OODS program":
//! every component part's authenticated AIR bytecode with its mask reads
//! resolved, at warm, to sample indices of the PCS image (class geometry
//! only; no challenge enters the program). Per node the kernel reads the
//! image samples, the section's z / alpha / coefficient / claims and the
//! drawn OODS point, and writes one Verdict word plus a 16-word diagnostic
//! [evaluated(8) | extracted(8)] that check mode compares with the host's
//! values. Exact OM31 arithmetic (om31.cuh is the host basis), so the verdict
//! is the host's verdict.
const std = @import("std");
const G = @import("gpu_native.zig");

pub const magic: u32 = 0x5344_4f4f; // "OODS"
pub const version: u32 = 1;
pub const H = struct {
    pub const magic = 0;
    pub const version = 1;
    pub const words = 2;
    pub const parts = 3;
    pub const global_log = 4;
    pub const composition_log = 5;
    pub const split = 6;
    pub const composition_sample = 7; // sample index of composition column 0
    pub const samples = 8; // total samples of the image
    pub const scratch_words = 9;
    pub const claims = 10;
    pub const header_words = 16;
};
/// One row per component part (component order, then part order).
pub const Part = struct {
    pub const words = 24;
    pub const component = 0;
    pub const trace_log = 1;
    pub const claim = 2;
    pub const params_at = 3;
    pub const n_params = 4;
    pub const base_at = 5;
    pub const n_base = 6;
    pub const ext_at = 7;
    pub const n_ext = 8;
    pub const roots_at = 9;
    pub const n_roots = 10;
    pub const regs_at = 11; // scratch word offset of the part's registers
    pub const max_base = 12;
    pub const max_ext = 13;
    pub const initial = 14; // M31 x, y of the trace coset's initial point
    pub const half_step = 16; // M31 x, y
    pub const coset_log = 18;
    pub const claim_scale = 19; // M31 inverse of 2^trace_log
};
/// Parameter rows (6 words): kind, w0..w3, power.
pub const ParamKind = enum(u32) { constant = 0, lookup_z = 1, alpha_power = 2, alpha_power_scaled = 3, claimed_sum_scaled = 4 };
/// Instruction rows (6 words). Base: op, dst, a, b, sample0, sample1
/// (reads; sample1 = no_sample except INTER's high half). Ext: op, dst, a, b, c, d.
pub const inst_words = 6;
pub const no_sample: u32 = 0xffff_ffff;

/// Verdict details (Check.node_oods_constraint).
pub const Detail = enum(u16) { descriptor = 1, noncanonical = 2, zero_inverse = 3, mismatch = 4, point = 5 };

pub const Io = extern struct {
    desc: [*]const u32,
    desc_words: u64,
    /// PCS image samples section (8 words per sample).
    samples: [*]const u32,
    sample_words: u64,
    /// claims (8 x desc claims words), z | alpha | coefficient (24 words).
    claims: [*]const u32,
    challenges: [*]const u32,
    /// OODS point x[8], y[8] (native_pcs oods field).
    point: [*]const u32,
    scratch: [*]u32,
    scratch_words: u64,
    verdict: [*]u32,
    /// [evaluated(8) | extracted(8)], written whenever both were computed.
    diag: ?[*]u32,
};
comptime {
    if (@sizeOf(Io) != 88) @compileError("outer OODS Io ABI changed");
}
pub const CheckFn = *const fn (*anyopaque, u32, *const Io) callconv(.c) c_int;
pub const Symbols = struct {
    check: CheckFn,
    pub fn load(addon: *std.DynLib) !Symbols {
        const V = *const fn () callconv(.c) u32;
        const v = addon.lookup(V, "stwo_rv64_outer_oods_check_version") orelse return error.MissingOuterOodsKernel;
        if (v() != version) return error.OuterOodsKernelVersion;
        return .{ .check = addon.lookup(CheckFn, "stwo_rv64_outer_oods_check_v1_on") orelse return error.MissingOuterOodsKernel };
    }
};

/// Validates the header and table bounds of a program (host side, at warm
/// and before upload; the kernel re-checks the header).
pub fn validate(d: []const u32) !void {
    if (d.len < H.header_words or d[H.magic] != magic or d[H.version] != version or d[H.words] != d.len or d[H.parts] == 0) return error.InvalidOuterOodsProgram;
    const parts = d[H.parts];
    if (@as(u64, H.header_words) + @as(u64, parts) * Part.words > d.len) return error.InvalidOuterOodsProgram;
    for (0..parts) |p| {
        const r = d[H.header_words + p * Part.words ..][0..Part.words];
        const spans = [_][2]u64{ .{ r[Part.params_at], 6 * @as(u64, r[Part.n_params]) }, .{ r[Part.base_at], inst_words * @as(u64, r[Part.n_base]) }, .{ r[Part.ext_at], inst_words * @as(u64, r[Part.n_ext]) }, .{ r[Part.roots_at], r[Part.n_roots] } };
        for (spans) |s| if (s[0] + s[1] > d.len) return error.InvalidOuterOodsProgram;
        if (@as(u64, r[Part.regs_at]) + 8 * (@as(u64, r[Part.max_base]) + r[Part.max_ext]) > d[H.scratch_words]) return error.InvalidOuterOodsProgram;
        if (r[Part.claim] >= d[H.claims] or r[Part.trace_log] > d[H.global_log]) return error.InvalidOuterOodsProgram;
    }
}

/// Builder rows (the host builder in outer_job_prestage.zig fills these).
pub const Builder = struct {
    a: std.mem.Allocator,
    words: std.ArrayListUnmanaged(u32) = .empty,
    rows: std.ArrayListUnmanaged([Part.words]u32) = .empty,
    scratch: u64 = 0,
    pub fn deinit(self: *Builder) void {
        self.words.deinit(self.a);
        self.rows.deinit(self.a);
    }
    /// Append a span of words; returns its offset relative to the body.
    pub fn span(self: *Builder, w: []const u32) !u32 {
        const at: u32 = @intCast(self.words.items.len);
        try self.words.appendSlice(self.a, w);
        return at;
    }
    pub fn regs(self: *Builder, max_base: u32, max_ext: u32) u32 {
        const at: u32 = @intCast(self.scratch);
        self.scratch += 8 * (@as(u64, max_base) + max_ext);
        return at;
    }
    pub fn part(self: *Builder, row: [Part.words]u32) !void {
        try self.rows.append(self.a, row);
    }
    /// Header + rows + body, with body offsets relocated past the rows.
    pub fn finish(self: *Builder, header: [H.header_words]u32) ![]u32 {
        const body_at: u32 = @intCast(H.header_words + self.rows.items.len * Part.words);
        const out = try self.a.alloc(u32, body_at + self.words.items.len);
        errdefer self.a.free(out);
        @memcpy(out[0..H.header_words], &header);
        out[H.magic] = magic;
        out[H.version] = version;
        out[H.words] = @intCast(out.len);
        out[H.parts] = @intCast(self.rows.items.len);
        out[H.scratch_words] = @intCast(self.scratch);
        for (self.rows.items, 0..) |row, i| {
            var r = row;
            for ([_]usize{ Part.params_at, Part.base_at, Part.ext_at, Part.roots_at }) |k| r[k] += body_at;
            @memcpy(out[H.header_words + i * Part.words ..][0..Part.words], &r);
        }
        @memcpy(out[body_at..], self.words.items);
        try validate(out);
        return out;
    }
};

test "oods program builder relocates spans and validates bounds" {
    const t = std.testing;
    var b = Builder{ .a = t.allocator };
    defer b.deinit();
    var row: [Part.words]u32 = @splat(0);
    row[Part.params_at] = try b.span(&.{ 1, 2, 3, 4, 5, 0 });
    row[Part.n_params] = 1;
    row[Part.roots_at] = try b.span(&.{0});
    row[Part.n_roots] = 1;
    row[Part.max_base] = 1;
    row[Part.max_ext] = 1;
    row[Part.regs_at] = b.regs(1, 1);
    row[Part.trace_log] = 4;
    try b.part(row);
    var header: [H.header_words]u32 = @splat(0);
    header[H.global_log] = 5;
    header[H.claims] = 11;
    const d = try b.finish(header);
    defer t.allocator.free(d);
    try t.expectEqual(@as(u32, H.header_words + Part.words), d[H.header_words + Part.params_at]);
    try t.expectEqual(@as(u32, 1), d[d[H.header_words + Part.params_at]]);
    try t.expectEqual(@as(u32, 16), d[H.scratch_words]);
    const bad = try t.allocator.dupe(u32, d);
    defer t.allocator.free(bad);
    bad[H.header_words + Part.claim] = 11;
    try t.expectError(error.InvalidOuterOodsProgram, validate(bad));
    _ = G.Check.node_oods_constraint;
}

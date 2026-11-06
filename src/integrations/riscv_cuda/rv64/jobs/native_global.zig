//! Enqueue-only global interaction witness (spec §3.5 item 2: "global
//! interaction (claims stay on device, publicClaims ...)").
//!
//! Same kernels, inputs and arithmetic as the legacy resident stage
//! (rv64/global_stage.zig Job.run, inverse-prefix layout): FIXED/MAIN
//! coefficient ingress, one N2B, the slot's AOT projection
//! (stwo_rv64_global_contiguous_<identity>), then the paired-fraction prefix
//! (stwo_rv64_global_pairs_on) per group. Differences: no lease, no join, no
//! claim/verdict readback. The INTER witness columns stay in a caller-owned
//! device buffer (the INTER commit reads them), and the group claims and the
//! sticky verdict are written into caller-chosen device words — normally slab
//! fields, from which the stage-2 transcript mixes the claims directly
//! (mixManifestAndClaims) and `finish` reads them.
//!
//! publicClaims (cpu_worker.zig) stays a check, not a transcript input: the
//! claims are mixed on device as produced, and the initial/terminal RAM claims
//! are compared with the request's public boundary in `finish` (host, after
//! the single wait). A mismatch fails the proof exactly where the legacy path
//! fails it (before publication); no bytes depend on the check's placement.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_riscv_cpu_integration");
const api = @import("api.zig");
const Abi = @import("../abi.zig");
const Gc = @import("../global_codegen.zig");
const Aot = @import("../global_aot.zig");
const Prefix = @import("../prefix_plan.zig");

const DG = CPU.rv64_gkr_cpu_worker.DeviceGlobal;
const D = CPU.rv64_device_pcs;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
pub const Item = DG.Item;
pub const Shared = DG.Shared;
pub const Descriptor = @FieldType(Item, "descriptor");

const Launch = *const fn (*anyopaque, u32, [*]const u32, [*]const u32, [*]const u32, [*]u32, [*]u32, [*]u32, u32) callconv(.c) c_int;
const N2b = *const fn ([*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
const CopyD2d = *const fn (*anyopaque, *anyopaque, *const anyopaque, usize) callconv(.c) c_int;
const Memset = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;
const Pairs = *const @TypeOf(Abi.stwo_rv64_global_pairs_on);

pub const Symbols = struct {
    copy_d2d: CopyD2d,
    memset: Memset,
    n2b: N2b,
    pairs: Pairs,
    pub fn load(base: *std.DynLib) !Symbols {
        return .{
            .copy_d2d = try lookup(CopyD2d, base, "stwo_exec_context_memcpy_d2d_async"),
            .memset = try lookup(Memset, base, "stwo_exec_context_memset_async"),
            .n2b = try lookup(N2b, base, "stwo_ntt_n2b_columns_on"),
            .pairs = try lookup(Pairs, base, "stwo_rv64_global_pairs_on"),
        };
    }
};
fn lookup(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse {
        std.log.err("native global job: missing base-image symbol {s}", .{name});
        return error.MissingNativeGlobalJobSymbol;
    };
}
fn check(code: c_int) !void {
    if (code != 0) return error.CudaEnqueueFailed;
}

/// Immutable per-descriptor projection artifacts and their AOT launchers
/// (host, built once; global_stage.zig Context.entry).
pub const Catalogue = struct {
    a: std.mem.Allocator,
    base: *std.DynLib,
    entries: std.ArrayListUnmanaged(*Entry) = .empty,
    mutex: std.Thread.Mutex = .{},
    pub const Entry = struct { artifact: Gc.Artifact, launch: Launch };
    pub fn init(a: std.mem.Allocator, base: *std.DynLib) Catalogue {
        return .{ .a = a, .base = base };
    }
    pub fn deinit(self: *Catalogue) void {
        for (self.entries.items) |e| {
            e.artifact.deinit();
            self.a.destroy(e);
        }
        self.entries.deinit(self.a);
        self.* = undefined;
    }
    pub fn entry(self: *Catalogue, descriptor: Descriptor) !*const Entry {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.entries.items) |e| if (std.meta.eql(e.artifact.descriptor, descriptor)) return e;
        const e = try self.a.create(Entry);
        errdefer self.a.destroy(e);
        e.artifact = try Gc.record(self.a, descriptor);
        errdefer e.artifact.deinit();
        const name = try Aot.name(self.a, &e.artifact);
        defer self.a.free(name);
        const z = try self.a.dupeZ(u8, name);
        defer self.a.free(z);
        e.launch = try lookup(Launch, self.base, z);
        try self.entries.append(self.a, e);
        return e;
    }
};

/// Static plan of one slot's global witness (host, challenge-free except the
/// shared global challenges, which are known after the seal barrier).
pub const Plan = struct {
    entry: *const Catalogue.Entry,
    log: u32,
    rows: usize,
    fixed_count: usize,
    main_count: usize,
    groups: [2]u32,
    group_count: usize,
    pairs: usize,
    width: usize,
    scan_words: usize,
    /// Packed projection parameters (OM31 words, artifact slot order).
    parameters: []u32,
    a: std.mem.Allocator,

    pub fn init(a: std.mem.Allocator, catalogue: *Catalogue, item: Item, shared: Shared) !Plan {
        const e = try catalogue.entry(item.descriptor);
        const shape = try Gc.Authority.shape(item.descriptor);
        if (item.fixed.len != shape.fixed or item.main.len != shape.main) return error.InvalidGlobalGeometry;
        const log = item.log_size;
        const boundary = item.descriptor.origin == .core and (item.descriptor.origin.core == .initial or item.descriptor.origin.core == .terminal);
        if (log < 5 or log > (if (boundary) @as(u32, DG.MAX_PUBLIC_BOUNDARY_LOG) else @as(u32, 22))) return error.InvalidGlobalGeometry;
        for (item.fixed) |c| if (c.log_size != log) return error.InvalidGlobalGeometry;
        for (item.main) |c| if (c.log_size != log) return error.InvalidGlobalGeometry;
        var semantic: [Gc.P.count]O = @splat(O.zero());
        semantic[Gc.P.source_public + Gc.Source.Public.sponge_first_id] = O.fromBase(M.fromCanonical(item.sponge_first_id));
        semantic[Gc.P.ram] = shared.ram.offset;
        @memcpy(semantic[Gc.P.ram + 1 ..][0..shared.ram.coefficients.len], &shared.ram.coefficients);
        semantic[Gc.P.kio] = shared.kio.offset;
        @memcpy(semantic[Gc.P.kio + 1 ..][0..shared.kio.coefficients.len], &shared.kio.coefficients);
        semantic[Gc.P.wire] = shared.wire.offset;
        @memcpy(semantic[Gc.P.wire + 1 ..][0..shared.wire.coefficients.len], &shared.wire.coefficients);
        const slots = e.artifact.parameter_slots;
        if (slots.len == 0 or slots.len > 65536) return error.InvalidGlobalGeometry;
        const parameters = try a.alloc(u32, slots.len * 8);
        errdefer a.free(parameters);
        for (slots, 0..) |slot, i| for (semantic[slot].toM31Array(), 0..) |m, j| {
            if (m.v >= core.fields.m31.Modulus) return error.NoncanonicalGlobalParameter;
            parameters[8 * i + j] = m.v;
        };
        const groups = [2]u32{ e.artifact.ram_pairs, e.artifact.other_pairs };
        if (groups[0] == 0 or groups[0] > 640 or groups[1] > 640) return error.InvalidGlobalGeometry;
        const group_count: usize = 1 + @as(usize, @intFromBool(groups[1] != 0));
        const pairs = @as(usize, groups[0]) + groups[1];
        return .{ .entry = e, .log = log, .rows = @as(usize, 1) << @intCast(log), .fixed_count = item.fixed.len, .main_count = item.main.len, .groups = groups, .group_count = group_count, .pairs = pairs, .width = 8 * (pairs + group_count), .scan_words = (try Prefix.Plan.init(log)).scratch_words, .parameters = parameters, .a = a };
    }
    pub fn deinit(self: *Plan) void {
        self.a.free(self.parameters);
        self.* = undefined;
    }
    pub fn outputWords(self: *const Plan) usize {
        return self.width * self.rows;
    }
    pub fn claimWords(self: *const Plan) usize {
        return 8 * self.group_count;
    }
    /// Enqueue-time arena words other than the caller-owned output (64-word granules).
    pub fn enqueueWords(self: *const Plan) usize {
        const g = @import("worker.zig").Arena.granule;
        return std.mem.alignForward(usize, (self.fixed_count + self.main_count) * self.rows, g) + std.mem.alignForward(usize, self.pairs * 8 * self.rows, g) + std.mem.alignForward(usize, self.scan_words + self.claimWords() + 1, g);
    }
    pub fn stagedWords(self: *const Plan, host_fixed: bool) usize {
        const g = @import("worker.zig").Arena.granule;
        return std.mem.alignForward(usize, self.parameters.len, g) + if (host_fixed) std.mem.alignForward(usize, self.fixed_count * self.rows, g) else 0;
    }
    /// The INTER columns of this slot (published view of `output`), as the
    /// legacy stage publishes them: per group 8*(pairs+1) evaluation columns.
    pub fn columnPointer(self: *const Plan, output: api.DeviceBuffer, column: usize) ![*]const u32 {
        if (column >= self.width) return error.InvalidGlobalGeometry;
        return output.ptr + column * self.rows;
    }
};

/// One slot's global witness inside a job.
pub const Global = struct {
    plan: *const Plan,
    sym: *const Symbols,
    /// Persistent key for the host FIXED columns (class-immutable), or null.
    fixed_key: ?[32]u8 = null,
    staged: ?api.DeviceBuffer = null,
    fixed: ?api.DeviceBuffer = null,
    twiddles: ?api.DeviceBuffer = null,

    /// Phase 1. `fixed_host`: the slot's FIXED coefficient columns when they
    /// are host-resident (else empty: device pointers are given to enqueue).
    pub fn stage(self: *Global, a: std.mem.Allocator, s: *api.Stager, fixed_host: []const []const u32) !void {
        const p = self.plan;
        const staged = try s.alloc(p.parameters.len);
        try s.upload(staged, p.parameters);
        self.staged = staged;
        var key: [32]u8 = @splat(0);
        @memcpy(key[0..16], "rv64-m8-glob-twd");
        key[16] = @intCast(p.log);
        var tw = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(p.log).circleDomain().half_coset);
        defer engine.poly.twiddles.deinitM31(a, &tw);
        const twiddles = try s.persistent(key, tw.twiddles.len);
        if (twiddles.fresh) try s.upload(twiddles.buffer, @as([*]const u32, @ptrCast(tw.twiddles.ptr))[0..tw.twiddles.len]);
        self.twiddles = twiddles.buffer;
        self.fixed = null;
        if (fixed_host.len != 0) {
            if (fixed_host.len != p.fixed_count) return error.InvalidGlobalGeometry;
            for (fixed_host) |c| if (c.len != p.rows) return error.InvalidGlobalGeometry;
            var fresh = true;
            const region = if (self.fixed_key) |k| blk: {
                const persistent = try s.persistent(k, p.fixed_count * p.rows);
                fresh = persistent.fresh;
                break :blk persistent.buffer;
            } else try s.alloc(p.fixed_count * p.rows);
            if (fresh) for (fixed_host, 0..) |c, i| try s.upload(try region.slice(i * p.rows, p.rows), c);
            self.fixed = region;
        }
    }

    pub const Outputs = struct {
        /// Caller-owned INTER witness (Plan.outputWords), kept for the INTER commit.
        output: api.DeviceBuffer,
        /// 8 words per group (the slot's claims, centered prefix totals).
        claims: api.DeviceBuffer,
        /// 1 word sticky verdict (0 = accepted).
        status: api.DeviceBuffer,
    };

    /// Phase 2. `fixed_device` / `main_device`: column pointers (device), in
    /// slot column order; FIXED may instead come from `stage`'s host columns.
    pub fn enqueue(self: *Global, e: *api.Enqueue, fixed_device: []const [*]const u32, main_device: []const [*]const u32, out: Outputs) !void {
        const p = self.plan;
        const sym = self.sym;
        const params = self.staged orelse return error.NativeGlobalNotStaged;
        const tw = self.twiddles orelse return error.NativeGlobalNotStaged;
        if (main_device.len != p.main_count or (fixed_device.len != p.fixed_count and !(fixed_device.len == 0 and self.fixed != null))) return error.InvalidGlobalGeometry;
        if (out.output.words < p.outputWords() or out.claims.words < p.claimWords() or out.status.words < 1) return error.InvalidGlobalGeometry;
        const ctx = e.ctx();
        const stream = e.stream();
        const rows = p.rows;
        const source = try e.alloc((p.fixed_count + p.main_count) * rows);
        for (0..p.fixed_count) |i| {
            const from: [*]const u32 = if (fixed_device.len != 0) fixed_device[i] else self.fixed.?.ptr + i * rows;
            try check(sym.copy_d2d(ctx, source.ptr + i * rows, from, rows * 4));
        }
        for (main_device, 0..) |from, i| try check(sym.copy_d2d(ctx, source.ptr + (p.fixed_count + i) * rows, from, rows * 4));
        var launches: u32 = 0;
        const tw_count = @as(u32, 1) << @intCast(p.log - 1);
        try check(sym.n2b(source.ptr, rows, p.log, @intCast(p.fixed_count + p.main_count), tw.ptr + tw.words - tw_count, tw_count, tw_count, stream, &launches));
        const numerator = try e.alloc(p.pairs * 8 * rows);
        const scratch = try e.alloc(p.scan_words + p.claimWords() + 1);
        const claim = scratch.ptr + p.scan_words;
        const status = claim + p.claimWords();
        try check(sym.memset(ctx, status, 0, 4));
        try check(p.entry.launch(ctx, 0, source.ptr, source.ptr + p.fixed_count * rows, params.ptr, numerator.ptr, out.output.ptr, status, p.log));
        var group_offset: usize = 0;
        var pair_offset: usize = 0;
        for (p.groups, 0..) |count, group| {
            if (count == 0) continue;
            var job = Abi.GlobalPairs{ .output = out.output.ptr + group_offset * rows, .contributions = numerator.ptr + pair_offset * 8 * rows, .scan_scratch = scratch.ptr, .claim = claim + group * 8, .status = status, .stride = rows, .scan_words = p.scan_words, .row_log = p.log, .pairs = count };
            try check(sym.pairs(ctx, 0, &job));
            group_offset += 8 * (@as(usize, count) + 1);
            pair_offset += count;
        }
        try check(sym.copy_d2d(ctx, out.claims.ptr, claim, p.claimWords() * 4));
        try check(sym.copy_d2d(ctx, out.status.ptr, status, 4));
        e.free(scratch);
        e.free(numerator);
        e.free(source);
    }
};

/// Finish-time acceptance of one slot (legacy order: verdict, canonical claims).
pub fn accept(claims_words: []const u32, status: u32) ![]const u32 {
    if (status != 0) return error.CudaGlobalWitnessRejected;
    if (claims_words.len % 8 != 0) return error.InvalidGlobalGeometry;
    for (claims_words) |w| if (w >= core.fields.m31.Modulus) return error.NoncanonicalWideCpuClaim;
    return claims_words;
}

test "global job path is fully analyzed" {
    _ = &Symbols.load;
    _ = &Catalogue.entry;
    _ = &Plan.init;
    _ = &Global.stage;
    _ = &Global.enqueue;
}

test "finish acceptance mirrors the legacy verdict and canonical-claim checks" {
    const ok = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };
    _ = try accept(&ok, 0);
    try std.testing.expectError(error.CudaGlobalWitnessRejected, accept(&ok, 1));
    var bad = ok;
    bad[3] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NoncanonicalWideCpuClaim, accept(&bad, 0));
}

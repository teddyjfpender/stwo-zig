//! Opt-in, source-bound Keccak truth role 0. All work runs in one serialized
//! native owner callback on lane zero. The cache is request-local and retired
//! before any later role or final commitment. This is not global admission.
const std = @import("std");
const P = @import("composition_sparse.zig");
const C = @import("composition_codegen.zig");
const SC = @import("session_context.zig");
const N = @import("pcs_native_abi.zig");
const Abi = @import("abi.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Contract = @import("composition_sparse_contract.zig");
comptime {
    if (cache_words != Contract.cache_words or scratch_words != Contract.scratch_words) @compileError("sparse allocation contract drift");
}
const Memory = @import("runtime_memory.zig");
const Admission = @import("footprint_types.zig");
pub const rows: usize = 1 << 20;
pub const source_rows: usize = 1 << 18;
pub const cache_words: usize = 1024 * rows;
const Column = extern struct { words: [*]const u32, count: u64, context_token: u64, generation: u64 };
const Lde = extern struct {
    version: u32 = 1,
    source_log: u32 = 18,
    eval_log: u32 = 20,
    column_count: u32,
    cache_slots: u32 = 1024,
    reserved: u32 = 0,
    session: *anyopaque,
    scope: [8]u32,
    sources: [*]const Column,
    slots: [*]const u32,
    cache: N.Lease,
    tables: N.Lease,
    twiddles: N.Lease,
};
const LdeCall = *const fn (*anyopaque, u32, *const Lde, *u32) callconv(.c) c_int;
const GroupCall = *const fn (*anyopaque, u32, u32, *const Abi.CompositionRole, *u32) callconv(.c) c_int;
// One packed slab: current pointer/index tables, input offsets, invocation
// parameters and powers, denominator, forward/inverse twiddles, last anchor.
const table_at = 0;
const masks_at = table_at + 4 * 512;
const params_at = masks_at + 2 * 6733;
const powers_at = params_at + 8 * 31;
const denom_at = powers_at + 8 * 5650;
const tw_at = denom_at + 4;
const inv_at = tw_at + rows / 2;
const aux_at = inv_at + source_rows / 2;
pub const scratch_words = aux_at + source_rows;
pub fn allocationBytes(new_bucket: bool) [3]u64 {
    return .{ cache_words * 4, scratch_words * 4, if (new_bucket) 8 * rows * 4 else 0 };
}
fn view(lease: N.Lease, at: usize, count: usize) N.Lease {
    std.debug.assert(at <= lease.count and count <= lease.count - at);
    var out = lease;
    out.words = lease.words.? + at;
    out.count = count;
    return out;
}
fn check(code: c_int) !void {
    if (code != 0) return error.SparseCompositionCudaFailed;
}
pub const Runtime = struct {
    allocator: std.mem.Allocator,
    plan: P.Plan,
    cache: P.Cache,
    library: std.DynLib,
    lde: LdeCall,
    group: GroupCall,
    memory_library: ?std.DynLib = null,
    memory_snapshot: ?*const fn (*anyopaque, [*:0]const u8) callconv(.c) c_int = null,
    pub fn init(a: std.mem.Allocator, program: *const C.Program) !?Runtime {
        const value = std.posix.getenv("STWO_RV64_TRUTH_SPARSE_RC") orelse return null;
        if (!std.mem.eql(u8, value, "1")) return null;
        const path = std.posix.getenv("STWO_RV64_TRUTH_SPARSE_LIBRARY") orelse return error.MissingSparseCompositionLibrary;
        var plan = try P.init(a, program, 512);
        errdefer plan.deinit(a);
        try plan.validate(a, program);
        var cache = try P.cache(a, &plan, 1024);
        errdefer cache.deinit(a);
        try cache.validate(a, &plan);
        var lib = try std.DynLib.open(path);
        errdefer lib.close();
        const Identity = *const fn (*[64]u8) callconv(.c) c_int;
        const identity = lib.lookup(Identity, "stwo_rv64_rc_sparse_identity") orelse return error.MissingSparseCompositionSymbol;
        var got: [64]u8 = undefined;
        try check(identity(&got));
        if (!std.mem.eql(u8, got[0..32], &plan.source) or !std.mem.eql(u8, got[32..64], &plan.identity)) return error.SparseCompositionSourceMismatch;
        var memory_library: ?std.DynLib = null;
        errdefer if (memory_library) |*observer_lib| observer_lib.close();
        var memory_snapshot: ?*const fn (*anyopaque, [*:0]const u8) callconv(.c) c_int = null;
        if (std.posix.getenv("STWO_RV64_PROCESS_MEMORY_LIBRARY")) |observer| {
            memory_library = try std.DynLib.open(observer);
            memory_snapshot = memory_library.?.lookup(@TypeOf(memory_snapshot.?), "stwo_rv64_process_memory_snapshot_on") orelse return error.MissingProcessMemoryObserver;
        }
        return .{ .allocator = a, .plan = plan, .cache = cache, .library = lib, .lde = lib.lookup(LdeCall, "stwo_rv64_rc_sparse_lde_on") orelse return error.MissingSparseCompositionSymbol, .memory_library = memory_library, .memory_snapshot = memory_snapshot, .group = lib.lookup(GroupCall, "stwo_rv64_rc_sparse_group_on") orelse return error.MissingSparseCompositionSymbol };
    }
    pub fn selection(self: *const Runtime) Contract.Selection {
        return .{ .source = self.plan.source, .plan = self.plan.identity };
    }
    pub fn deinit(self: *Runtime) void {
        if (self.memory_library) |*value| value.close();
        self.library.close();
        self.cache.deinit(self.allocator);
        self.plan.deinit(self.allocator);
    }
    pub fn matches(self: *const Runtime, source: [32]u8, id: u32, trace_log: u32, eval_log: u32, widths: [3]usize, masks: usize, roots: usize, parameters: usize) bool {
        return id == 0 and trace_log == 18 and eval_log == 20 and std.meta.eql(widths, [3]usize{ 32, 1923, 1561 }) and masks == 6733 and roots == 5650 and parameters == 31 and std.mem.eql(u8, &source, &self.plan.source);
    }
    pub fn run(self: *const Runtime, a: std.mem.Allocator, b: anytype, ctx: *SC.Context, inputs: anytype, direct: []const ?D.DeviceCoefficients, parameters: []const u32, powers: []const u32, denominators: []const u32, forward_twiddles: []const u32, inverse_twiddles: []const u32, bucket: *?N.Lease, retained: *std.ArrayList(N.Lease)) !void {
        if (inputs.len != 6733 or inputs.len != self.plan.input_columns.len or direct.len != 3516 or parameters.len != 248 or powers.len != 45200 or denominators.len != 4 or forward_twiddles.len < rows / 2 or inverse_twiddles.len != source_rows / 2) return error.InvalidSparseCompositionInvocation;
        // Validate the COMPLETE source roster before any allocation or launch.
        // Parameter cache entries and other physical namespaces cannot stand in
        // for a source lease merely because their address matches.
        for (direct[0..3515]) |entry| {
            const d = entry orelse return error.SparseCompositionRequiresResidentSource;
            if (d.count != source_rows) return error.InvalidSparseCompositionDegree;
            try check(ctx.api.validate_range(ctx.session, d.words, d.count, d.context_token, d.generation, &ctx.scope));
        }
        if (direct[3515] != null) return error.InvalidSparseCompositionAuxiliary;
        if (self.memory_snapshot) |observe| try check(observe(ctx.native_context, "sparse_before_allocation"));
        const bytes = allocationBytes(bucket.* == null);
        var needed: Admission.Footprint = .{};
        for (bytes) |size| if (size != 0) {
            needed = try needed.add(try Admission.Footprint.allocation(size));
        };
        var actual = try Memory.query(&b.service.library, ctx.native_context);
        var available = try actual.available();
        if (!available.contains(needed) or actual.largest_virtual_free < cache_words * 4) {
            _ = try Memory.trimUnused(&b.service.library, ctx.session);
            actual = try Memory.query(&b.service.library, ctx.native_context);
            available = try actual.available();
        }
        if (!available.contains(needed) or actual.largest_virtual_free < cache_words * 4) {
            std.debug.print("GPU_RC_SPARSE_REFUSED required_large={} required_small={} available_large={} available_small={}\n", .{ needed.large, needed.small, available.large, available.small });
            return error.SparseCompositionExceedsPhysicalArena;
        }
        var evaluations = try ctx.allocate(cache_words, 0);
        defer if (evaluations.words != null) {
            ctx.release(&evaluations) catch {};
        };
        var scratch = try ctx.allocate(scratch_words, 0);
        defer if (scratch.words != null) {
            ctx.release(&scratch) catch {};
        };
        // A release joins every producer lane. Both request-local owners retire
        // before this function returns; bucket ownership remains in caller list.
        if (bucket.* == null) {
            const value = try ctx.allocate(8 * rows, 0);
            try @import("composition_sparse_ownership.zig").adoptAndClear(a, ctx, retained, bucket, value, b.clear);
        }
        const base = scratch.words.?;
        try check(ctx.api.upload(ctx.native_context, @ptrCast(base + params_at), parameters.ptr, parameters.len * 4));
        try check(ctx.api.upload(ctx.native_context, @ptrCast(base + powers_at), powers.ptr, powers.len * 4));
        try check(ctx.api.upload(ctx.native_context, @ptrCast(base + denom_at), denominators.ptr, denominators.len * 4));
        try check(ctx.api.upload(ctx.native_context, @ptrCast(base + tw_at), forward_twiddles.ptr + forward_twiddles.len - rows / 2, rows / 2 * 4));
        try check(ctx.api.upload(ctx.native_context, @ptrCast(base + inv_at), inverse_twiddles.ptr, inverse_twiddles.len * 4));
        try check(b.clear(ctx.native_context, @ptrCast(base + aux_at), 0, source_rows * 4));
        const one: u32 = 1;
        try check(ctx.api.upload(ctx.native_context, @ptrCast(base + aux_at + 1), &one, 4));
        var stream: ?*anyopaque = null;
        try check(ctx.api.lane_stream(ctx.native_context, 0, &stream));
        var launches: u32 = 0;
        try check(b.b2n(base + aux_at, source_rows, base + aux_at, source_rows, 18, 1, base + inv_at, @intCast(inverse_twiddles.len), @intCast(source_rows / 2), stream.?, &launches));
        const masks = try a.alloc(u64, inputs.len);
        defer a.free(masks);
        var columns: [512]Column = undefined;
        var slots: [512]u32 = undefined;
        for (self.plan.groups, self.cache.steps, 0..) |group, step, index| {
            for (step.loads, 0..) |load, i| {
                const col = self.plan.columns[load.column];
                const physical = switch (col.tree) {
                    0 => col.column,
                    1 => 32 + col.column,
                    2 => 1955 + col.column,
                    else => return error.InvalidSparseCompositionTree,
                };
                if (physical >= direct.len) return error.InvalidSparseCompositionColumn;
                columns[i] = if (direct[physical]) |d| .{ .words = d.words, .count = d.count, .context_token = d.context_token, .generation = d.generation } else .{ .words = base + aux_at, .count = source_rows, .context_token = scratch.context_token, .generation = scratch.generation };
                slots[i] = load.slot;
            }
            if (step.loads.len != 0) {
                const job = Lde{ .column_count = @intCast(step.loads.len), .session = ctx.session, .scope = ctx.scope, .sources = &columns, .slots = &slots, .cache = evaluations, .tables = view(scratch, table_at, 4 * step.loads.len), .twiddles = view(scratch, tw_at, rows / 2) };
                try check(self.lde(ctx.native_context, 0, &job, &launches));
            }
            // Only the current group's physical columns are authorized. Keep
            // each original mask's row offset in generated numerical code.
            @memset(masks, 0);
            for (inputs, self.plan.input_columns, masks) |_, column, *offset| {
                if (std.mem.indexOfScalar(u32, group.columns, column) != null) {
                    const slot = step.column_slots[column];
                    if (slot >= 1024) return error.InvalidSparseCompositionCacheSlot;
                    offset.* = @as(u64, slot) * rows;
                }
            }
            try check(ctx.api.upload(ctx.native_context, @ptrCast(base + masks_at), masks.ptr, masks.len * 8));
            const packet = Abi.CompositionRole{ .role = 0, .trace_log = 18, .eval_log = 20, .first_row = 0, .row_count = rows, .trees = .{ evaluations.words.?, evaluations.words.?, evaluations.words.? }, .tree_words = .{ cache_words, cache_words, cache_words }, .column_offsets = @ptrCast(@alignCast(base + masks_at)), .mask_count = 6733, .parameters = base + params_at, .parameter_count = 31, .powers = base + powers_at, .constraint_count = 5650, .denominator_inverses = base + denom_at, .output = bucket.*.?.words.? };
            try check(self.group(ctx.native_context, 0, @intCast(index), &packet, &launches));
        }
        try ctx.join();
        if (self.memory_snapshot) |observe| try check(observe(ctx.native_context, "sparse_joined_before_retirement"));
        try ctx.release(&scratch);
        try ctx.release(&evaluations);
        std.debug.print("GPU_RC_SPARSE_COMPLETE groups={} fills={} cache_words={} scratch_words={} original_roots=5650 source_log=18 eval_log=20 joined=true\n", .{ self.plan.groups.len, self.cache.fills, cache_words, scratch_words });
    }
};

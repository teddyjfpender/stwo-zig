//! Synchronous proof-owned original framework interactions. All 23 typed AIR
//! cohorts and both table providers retain original claim/transcript order.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const R = @import("../../backends/cuda/abi/runtime.zig");
const Aot = @import("../../backends/cuda/abi/aot.zig");
const Types = @import("../../backends/cuda/abi/types.zig");
const Kernel = @import("../../backends/cuda/runtime/kernel.zig").Kernel;
const check = @import("../../backends/cuda/runtime/error.zig").check;
const Code = @import("../../backends/cuda/framework_interaction_codegen_v1.zig");
const Base = @import("../../backends/cuda/framework_polynomial_codegen_v1.zig");
const Transport = @import("hybrid_quotient_executor_v1.zig");
const API = @import("../../frontends/riscv/recursion/blake3_parent_interaction_executor_v1.zig");
const C = engine.air.component_prover;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const Limits = struct { max_device_bytes: usize = 16 << 30, max_host_scratch_bytes: usize = 256 << 20, max_columns: usize = 65536, max_log: u32 = 24 };
pub const Stats = struct {
    calls: usize = 0,
    rows: usize = 0,
    batches: usize = 0,
    source_columns: usize = 0,
    kernel_launches: usize = 0,
    device_peak_bytes: usize = 0,
    host_peak_bytes: usize = 0,
    h2d_bytes: usize = 0,
    d2h_bytes: usize = 0,
    registers_per_thread_peak: usize = 0,
    local_bytes_peak: usize = 0,
    planning_ns: u64 = 0,
    upload_ns: u64 = 0,
    binding_ns: u64 = 0,
    fraction_ns: u64 = 0,
    scan_ns: u64 = 0,
    download_ns: u64 = 0,
    total_ns: u64 = 0,
};
pub const Call = struct { index: usize, trace_log: u32, layout: u16, batches: usize, delta: Stats };
pub const Observer = struct { context: *anyopaque, record: *const fn (*anyopaque, Call) anyerror!void };
pub const Owner = struct {
    transport: Transport.Owner,
    loader: *anyopaque,
    limits: Limits,
    device: Types.DeviceSnapshot,
    platform: Types.PlatformSnapshot,
    module_identity: [32]u8,
    stats: Stats = .{},
    observer: ?Observer = null,
    poisoned: bool = false,
    active: bool = false,
    pub fn open(device: u32, sm: u32, limits: Limits) !Owner {
        if (limits.max_device_bytes == 0 or limits.max_host_scratch_bytes == 0 or limits.max_log > 24 or limits.max_columns == 0) return error.InvalidCudaInteractionPolicy;
        var transport = try Transport.Owner.open(device, sm, .{ .plan = .{ .max_device_bytes = limits.max_device_bytes } });
        errdefer transport.deinit() catch {};
        var loader: ?*anyopaque = null;
        try check(Aot.stwo_native_aot_loader_create(transport.handle.?, &loader));
        return .{ .transport = transport, .loader = loader orelse return error.InvalidState, .limits = limits, .device = transport.device, .platform = transport.platform, .module_identity = transport.module_identity };
    }
    pub fn deinit(self: *Owner) !void {
        if (self.active) return error.CudaInteractionStillActive;
        if (self.transport.thread != std.Thread.getCurrentId()) return error.ThreadOwnershipViolation;
        try check(Aot.stwo_native_aot_loader_destroy(self.loader));
        try self.transport.deinit();
    }
    pub fn executor(self: *Owner) API.Executor {
        return .{ .context = self, .generate = generate };
    }
    fn generate(context: *anyopaque, allocator: std.mem.Allocator, program: *const API.Program, counts: [3]usize, sources: [2][]const []const M, parameters: API.Parameters, destination: []const []M, claims: []Q) !void {
        const self: *Owner = @ptrCast(@alignCast(context));
        if (self.transport.thread != std.Thread.getCurrentId()) return error.ThreadOwnershipViolation;
        if (self.poisoned or self.active or self.transport.handle == null) return error.InvalidState;
        self.active = true;
        defer self.active = false;
        errdefer self.poisoned = true;
        try API.validate(program, counts, sources, parameters, destination, claims);
        const entry = Code.Entry{ .program = program, .tree_column_counts = &counts };
        try Code.validate(entry);
        if (parameters.trace_log_size > self.limits.max_log or program.inputs.len > self.limits.max_columns) return error.CudaInteractionResourceLimit;
        const rows = @as(usize, 1) << @intCast(parameters.trace_log_size);
        const batches = program.batches.len;
        const scan_batches = claims.len;
        const blocks = (rows + 255) / 256;
        const output_words = try std.math.add(usize, try std.math.mul(usize, program.interaction_columns.len, rows), claims.len * 4);
        var budget = engine.host_budget_allocator.HostBudgetAllocator.init(allocator, self.limits.max_host_scratch_bytes);
        const a = budget.allocator();
        const before = self.stats;
        var total = try std.time.Timer.start();
        var phase = try std.time.Timer.start();
        const id = try Code.identity(a, entry);
        const name = try Code.name(a, id);
        defer a.free(name);
        var unique: std.ArrayList(C.TypedPolynomialColumnV1) = .empty;
        defer unique.deinit(a);
        const offsets = try a.alloc(u64, program.inputs.len);
        defer a.free(offsets);
        for (program.inputs, offsets) |input, *offset| switch (input) {
            .profile_parameter => offset.* = 0,
            .trace_column => |column| {
                var index: usize = 0;
                while (index < unique.items.len and !std.meta.eql(unique.items[index], column)) : (index += 1) {}
                if (index == unique.items.len) try unique.append(a, column);
                offset.* = try std.math.mul(u64, index, rows);
            },
        };
        const profile = try a.alloc(u32, parameters.profile_values.len);
        defer a.free(profile);
        for (profile, parameters.profile_values) |*word, value| word.* = value.toU32();
        const relations = try a.alloc(u32, parameters.relation_values.len * 4);
        defer a.free(relations);
        for (parameters.relation_values, 0..) |value, i| for (value.toM31Array(), 0..) |word, j| {
            relations[i * 4 + j] = word.toU32();
        };
        self.stats.planning_ns += phase.lap();
        var buffers = Buffers{ .owner = self };
        defer buffers.deinit();
        const device_source = try buffers.alloc(try std.math.mul(usize, unique.items.len, rows));
        for (unique.items, 0..) |column, i| try buffers.copy(device_source.ptr + i * rows, sources[column.tree_index][column.column_index].ptr, rows * 4);
        const device_offsets = try buffers.upload(std.mem.sliceAsBytes(offsets));
        const device_profile = try buffers.upload(std.mem.sliceAsBytes(profile));
        const device_relations = try buffers.upload(std.mem.sliceAsBytes(relations));
        const output = try buffers.alloc(output_words);
        const scratch = try buffers.alloc(try std.math.mul(usize, scan_batches * blocks, 4));
        const status = try buffers.alloc(1);
        try check(R.stwo_exec_context_memset_async(self.transport.handle.?, status.ptr, 0, 4));
        try check(R.stwo_exec_context_sync(self.transport.handle.?));
        self.stats.upload_ns += phase.lap();
        var trees = device_source.ptr;
        var off = device_offsets.ptr;
        var prof = device_profile.ptr;
        var rel = device_relations.ptr;
        var out = output.ptr;
        var status_ptr = status.ptr;
        var row_count: u32 = @intCast(rows);
        const fraction_args = [_]?*anyopaque{ @ptrCast(&trees), @ptrCast(&trees), @ptrCast(&off), @ptrCast(&prof), @ptrCast(&rel), @ptrCast(&out), @ptrCast(&status_ptr), @ptrCast(&row_count) };
        self.stats.fraction_ns += try self.launch(id, name, .framework_interaction_fractions_v1, .{ @intCast((rows + 127) / 128), 1, 1 }, .{ 128, 1, 1 }, &fraction_args);
        var status_word: u32 = 0;
        try check(R.stwo_exec_context_memcpy_d2h_async(self.transport.handle.?, &status_word, status.ptr, 4));
        try check(R.stwo_exec_context_sync(self.transport.handle.?));
        self.stats.d2h_bytes += 4;
        // No caller destination or physical claim is published on rejection.
        if (status_word & 4 != 0) return error.NonCanonicalFrameworkInteraction;
        if (status_word & 2 != 0) return error.InvalidFrameworkInteractionSelector;
        if (status_word & 1 != 0) return error.ZeroDenominator;
        if (status_word != 0) return error.InvalidFrameworkInteractionStatus;
        var sums = scratch.ptr;
        var block_count: u32 = @intCast(blocks);
        var batch_count: u32 = @intCast(batches);
        var layout: u32 = @intFromEnum(program.layout);
        const scan_args = [_]?*anyopaque{ @ptrCast(&out), @ptrCast(&sums), @ptrCast(&row_count), @ptrCast(&block_count), @ptrCast(&batch_count), @ptrCast(&layout) };
        inline for (std.meta.tags(Code.Scan)) |kind| {
            const scan_id = try Code.scanIdentity(a, kind);
            const scan_name = try Code.scanName(a, kind, scan_id);
            defer a.free(scan_name);
            const grid: [3]u32 = switch (kind) {
                .blocks => .{ @intCast(scan_batches * blocks), 1, 1 },
                .totals => .{ @intCast((scan_batches + 127) / 128), 1, 1 },
                .finalize => .{ @intCast((rows + 127) / 128), @intCast(scan_batches), 1 },
            };
            self.stats.scan_ns += try self.launch(scan_id, scan_name, .framework_interaction_scan_v1, grid, if (kind == .blocks) .{ 256, 1, 1 } else .{ 128, 1, 1 }, &scan_args);
        }
        phase.reset();
        for (destination, 0..) |column, i| try check(R.stwo_exec_context_memcpy_d2h_async(self.transport.handle.?, column.ptr, output.ptr + i * rows, rows * 4));
        var claim_words: [512]u32 = undefined;
        try check(R.stwo_exec_context_memcpy_d2h_async(self.transport.handle.?, &claim_words, output.ptr + program.interaction_columns.len * rows, claims.len * 16));
        try check(R.stwo_exec_context_sync(self.transport.handle.?));
        for (destination) |column| for (column) |word| if (word.v >= core.fields.m31.Modulus) return error.NonCanonicalFrameworkInteraction;
        for (claims, 0..) |*claim, i| {
            var words: [4]M = undefined;
            for (&words, 0..) |*word, j| {
                const value = claim_words[i * 4 + j];
                if (value >= core.fields.m31.Modulus) return error.NonCanonicalFrameworkInteraction;
                word.* = M.fromCanonical(value);
            }
            claim.* = Q.fromM31Array(words);
        }
        self.stats.d2h_bytes += output_words * 4;
        self.stats.download_ns += phase.lap();
        self.stats.calls += 1;
        self.stats.rows += rows;
        self.stats.batches += batches;
        self.stats.source_columns += unique.items.len;
        self.stats.host_peak_bytes = @max(self.stats.host_peak_bytes, budget.peak_live_bytes);
        self.stats.total_ns += total.read();
        if (self.stats.kernel_launches - before.kernel_launches != 4) return error.CudaInteractionCoverageMismatch;
        if (self.observer) |observer| {
            var delta: Stats = undefined;
            inline for (std.meta.fields(Stats)) |f| @field(delta, f.name) = @field(self.stats, f.name) - @field(before, f.name);
            try observer.record(observer.context, .{ .index = self.stats.calls - 1, .trace_log = parameters.trace_log_size, .layout = @intFromEnum(program.layout), .batches = batches, .delta = delta });
        }
    }
    fn launch(self: *Owner, id: [32]u8, name: [:0]const u8, schema: @import("../../backends/cuda/abi/schema.zig").KernelSchema, grid: [3]u32, block: [3]u32, args: []const ?*anyopaque) !u64 {
        var timer = try std.time.Timer.start();
        const descriptor = Kernel{ .stage = .constraint_evaluation, .abi_schema = schema, .cache_key = Base.cacheKey(id), .name = name, .grid = grid, .block = block, .argument_count = @intCast(args.len) };
        var function: ?*anyopaque = null;
        var receipt: Types.NativeAotFunctionReceipt = undefined;
        try check(Aot.stwo_native_aot_function_bind(self.loader, descriptor.cache_key, @intFromEnum(schema), name.ptr, &grid, &block, 0, descriptor.argument_count, &function, &receipt));
        defer if (function) |f| {
            check(Aot.stwo_native_aot_function_destroy(f)) catch {
                self.poisoned = true;
            };
        };
        try descriptor.validateReceipt(receipt, self.device, self.transport.stream);
        self.stats.registers_per_thread_peak = @max(self.stats.registers_per_thread_peak, receipt.registers_per_thread);
        self.stats.local_bytes_peak = @max(self.stats.local_bytes_peak, @as(usize, @intCast(receipt.local_bytes)));
        self.stats.binding_ns += timer.lap();
        try check(Aot.stwo_native_aot_function_launch(function orelse return error.InvalidState, args.ptr, @intCast(args.len)));
        try check(R.stwo_exec_context_sync(self.transport.handle.?));
        self.stats.kernel_launches += 1;
        return timer.read();
    }
};
const Buffers = struct {
    owner: *Owner,
    pointers: [12][*]u32 = undefined,
    count: usize = 0,
    bytes: usize = 0,
    fn alloc(self: *Buffers, n: usize) ![]u32 {
        const words = @max(n, 1);
        const next = try std.math.add(usize, self.bytes, try std.math.mul(usize, words, 4));
        if (self.count == self.pointers.len or next > self.owner.limits.max_device_bytes) return error.CudaInteractionResourceLimit;
        var pointer: ?[*]u32 = null;
        try check(R.stwo_exec_context_alloc_u32(self.owner.transport.handle.?, words, &pointer));
        const p = pointer orelse return error.InvalidState;
        self.pointers[self.count] = p;
        self.count += 1;
        self.bytes = next;
        self.owner.stats.device_peak_bytes = @max(self.owner.stats.device_peak_bytes, next);
        return p[0..words];
    }
    fn copy(self: *Buffers, dst: *anyopaque, src: *const anyopaque, bytes: usize) !void {
        if (bytes == 0) return;
        try check(R.stwo_exec_context_memcpy_h2d_async(self.owner.transport.handle.?, dst, src, bytes));
        self.owner.stats.h2d_bytes += bytes;
    }
    fn upload(self: *Buffers, bytes: []const u8) ![]u32 {
        if (bytes.len % 4 != 0) return error.InvalidFrameworkInteractionBuffer;
        const result = try self.alloc(bytes.len / 4);
        try self.copy(result.ptr, bytes.ptr, bytes.len);
        return result;
    }
    fn deinit(self: *Buffers) void {
        if (self.count == 0) return;
        check(R.stwo_exec_context_sync(self.owner.transport.handle.?)) catch {
            self.owner.poisoned = true;
        };
        while (self.count != 0) {
            self.count -= 1;
            check(R.stwo_exec_context_free_u32(self.owner.transport.handle.?, self.pointers[self.count])) catch {
                self.owner.poisoned = true;
            };
        }
    }
};

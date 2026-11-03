//! Resident concrete CPU-family source. Only compact facts/events enter the
//! device; MAIN and every shared multiplicity ledger remain proof-scoped.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const Front = @import("stwo_riscv_frontend").rv64_air;
const D = CPU.rv64_device_pcs;
const Headers = CPU.rv64_device_core_headers;
const Inputs = CPU.rv64_family_input;
const Memory = CPU.rv64_memory_input;
const Pipeline = CPU.rv64_device_source_stage;
const Native = @import("pcs_native_abi.zig");
const Service = @import("pcs_native.zig");
const SC = @import("session_context.zig");
const Projection = @import("cpu_projection.zig");
const FamilyJob = extern struct {
    facts: ?[*]const u32,
    main: [*]u32,
    range16: [*]u32,
    and_: [*]u32,
    shift: [*]u32,
    status: [*]u32,
    count: u32,
    log: u32,
    kind: u32,
    reserved: u32 = 0,
};
const MemoryJob = extern struct {
    events: ?[*]const u32,
    main: [*]u32,
    range16: [*]u32,
    range8: [*]u32,
    pairs: [*]u32,
    selection: [*]u32,
    status: [*]u32,
    count: u32,
    log: u32,
    dword: u32,
    fused_pairs: u32,
};
const ArithmeticJob = extern struct {
    requests: ?[*]const u32,
    main: [*]u32,
    range16: [*]u32,
    range8: [*]u32,
    pairs: [*]u32,
    status: [*]u32,
    mul_support: ?[*]u32,
    count: u32,
    log: u32,
    division: u32,
    fused_pairs: u32,
};
const FamilyFn = *const fn (*anyopaque, u32, *const FamilyJob) callconv(.c) c_int;
const MemoryFn = *const fn (*anyopaque, u32, *const MemoryJob) callconv(.c) c_int;
const ArithmeticFn = *const fn (*anyopaque, u32, *const ArithmeticJob) callconv(.c) c_int;
const BoundaryFn = *const fn (*anyopaque, u32, ?[*]const u32, u32, u32, [*]u32, [*]u32) callconv(.c) c_int;
const TableFn = *const fn (*anyopaque, u32, [*]const u32, ?[*]const u32, u32, u32, [*]u32, [*]u32) callconv(.c) c_int;
const Memset = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;
fn checked(status: c_int) !void {
    if (status != 0) return error.CudaFamilyWitnessFailed;
}
fn symbol(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse error.MissingFamilyWitnessSymbol;
}
pub const Ledgers = struct {
    range16: D.DeviceCoefficients,
    range8: D.DeviceCoefficients,
    pairs: D.DeviceCoefficients,
    and_: D.DeviceCoefficients,
    shift: D.DeviceCoefficients,
    selection: D.DeviceCoefficients,
    rom: D.DeviceCoefficients,
    status: D.DeviceCoefficients,
};
pub const Context = struct {
    service: *Service.Context,
    cpu: *Projection.Context,
    api: SC.Api,
    family: FamilyFn,
    memory: MemoryFn,
    arithmetic: ArithmeticFn,
    boundary: BoundaryFn,
    table: TableFn,
    memset: Memset,
    pub fn init(service: *Service.Context, cpu: *Projection.Context) !Context {
        cpu.retain_ledgers = true;
        return .{ .service = service, .cpu = cpu, .api = .{ .allocate = service.lease_allocate, .release = service.lease_release, .validate_range = service.lease_validate_range, .upload = try symbol(Native.Upload, &service.library, "stwo_exec_context_memcpy_h2d_async"), .download = try symbol(Native.Download, &service.library, "stwo_exec_context_memcpy_d2h_async"), .sync = try symbol(Native.Sync, &service.library, "stwo_exec_context_sync"), .lane_stream = try symbol(Native.LaneStream, &service.library, "stwo_exec_context_lane_stream") }, .family = try symbol(FamilyFn, &service.library, "stwo_rv64_family_witness_on"), .memory = try symbol(MemoryFn, &service.library, "stwo_rv64_memory_witness_on"), .arithmetic = try symbol(ArithmeticFn, &service.library, "stwo_rv64_arithmetic_witness_on"), .boundary = try symbol(BoundaryFn, &service.library, "stwo_rv64_boundary_witness_on"), .table = try symbol(TableFn, &service.library, "stwo_rv64_multiplicity_witness_on"), .memset = try symbol(Memset, &service.library, "stwo_exec_context_memset_async") };
    }
    pub fn buildCore(self: *Context, a: std.mem.Allocator, request: Pipeline.Request) !*CoreProjection {
        const out = try a.create(CoreProjection);
        errdefer a.destroy(out);
        out.* = .{ .allocator = a, .backend = self, .scope = request.scope, .request = request };
        errdefer out.destroy();
        out.source = try Headers.take(a, &request.setup.materials, request.native, request.request.base.memory);
        try out.source.?.cpu.projectDevice(self.cpu.stage(), request.scope);
        var split = try CPU.rv64_services_pipeline.splitEvents(a, request.advice.events[request.ordinal], request.setup.bridges.ls_dword != null);
        defer split.deinit(a);
        if (split.general.len != request.request.base.memory.ls_count or split.dword.len != request.request.ls_dword) return error.InvalidCombinedServiceCount;
        out.general_events = try Memory.events(a, split.general);
        defer {
            a.free(out.general_events);
            out.general_events = &.{};
        }
        var job = BuildJob{ .owner = out };
        try out.submit(BuildJob.callback, &job, &job.failure);
        return out;
    }
};
pub const CoreProjection = struct {
    allocator: std.mem.Allocator,
    backend: *Context,
    scope: D.Scope,
    request: Pipeline.Request,
    source: ?Headers.Source = null,
    columns: []D.TraceColumn = &.{},
    ledgers: Ledgers = undefined,
    leases: std.ArrayList(Native.Lease) = .empty,
    general_events: []Memory.Event = &.{},
    finished: bool = false,
    ledger_lease: Native.Lease = .{},
    table_outputs: std.ArrayList(TableOutput) = .empty,
    const TableOutput = struct { kind: u32, log: u32, pointer: [*]u32 };
    fn submit(self: *CoreProjection, callback: Native.Callback, data: *anyopaque, failure: *?anyerror) !void {
        const status = self.backend.service.submit(self.backend.service.session, callback, data);
        if (failure.*) |err| return err;
        try checked(status);
    }
    pub fn finishTables(self: *CoreProjection) !void {
        if (self.finished) return error.DeviceTablesAlreadyFinalized;
        var job = Finish{ .owner = self };
        try self.submit(Finish.callback, &job, &job.failure);
        self.finished = true;
    }
    pub fn takeSource(self: *CoreProjection) !Headers.Source {
        if (!self.finished) return error.DeviceTablesNotFinalized;
        const result = self.source orelse return error.DeviceSourceAlreadyTaken;
        self.source = null;
        return result;
    }
    pub fn release(raw: *anyopaque) void {
        const self: *CoreProjection = @ptrCast(@alignCast(raw));
        const a = self.allocator;
        self.destroy();
        a.destroy(self);
    }
    pub fn deinit(self: *CoreProjection) void {
        release(self);
    }
    fn destroy(self: *CoreProjection) void {
        _ = self.backend.service.submit(self.backend.service.session, releaseLeases, self);
        if (self.source) |*s| s.deinit();
        self.allocator.free(self.columns);
        self.leases.deinit(self.allocator);
        self.table_outputs.deinit(self.allocator);
    }
    fn releaseLeases(_: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *CoreProjection = @ptrCast(@alignCast(data.?));
        var status: c_int = 0;
        for (self.leases.items) |*lease| {
            const rc = self.backend.service.lease_release(self.backend.service.session, lease);
            if (rc != 0) status = rc;
        }
        return status;
    }
    fn allocate(self: *CoreProjection, ctx: *SC.Context, words: usize, kind: u32) !Native.Lease {
        var lease = try ctx.allocate(@max(words, 1), kind);
        errdefer ctx.release(&lease) catch {};
        try self.leases.append(self.allocator, lease);
        return lease;
    }
    fn upload(self: *CoreProjection, ctx: *SC.Context, words: []const u32) !Native.Lease {
        const lease = try self.allocate(ctx, words.len, 0);
        if (words.len != 0) try ctx.upload(try (try ctx.borrow(lease)).sub(0, words.len), words);
        return lease;
    }
    fn output(self: *CoreProjection, ctx: *SC.Context, log: u32, width: usize) ![]D.TraceColumn {
        const n = @as(usize, 1) << @intCast(log);
        const lease = try self.allocate(ctx, n * width, 1);
        const out = try self.allocator.alloc(D.TraceColumn, width);
        for (out, 0..) |*column, i| column.* = .{ .log_size = log, .encoding = .evaluations, .device = descriptor(lease, i * n, n) };
        return out;
    }
    fn familyOutput(self: *CoreProjection, ctx: *SC.Context, batch: *const Inputs.Batch, width: usize) ![]D.TraceColumn {
        errdefer ctx.join() catch {};
        const input = try self.upload(ctx, batch.words());
        const out = try self.output(ctx, batch.log, width);
        errdefer self.allocator.free(out);
        try ctx.join();
        const job = FamilyJob{ .facts = if (batch.facts.len == 0) null else input.words, .main = writable(out[0].device.?), .range16 = writable(self.ledgers.range16), .and_ = writable(self.ledgers.and_), .shift = writable(self.ledgers.shift), .status = writable(self.ledgers.status), .count = @intCast(batch.facts.len), .log = batch.log, .kind = @intFromEnum(batch.kind) };
        try checked(self.backend.family(ctx.native_context, 1, &job));
        try ctx.join();
        return out;
    }
    pub fn formatZbb(self: *CoreProjection, facts: []const Front.word16_v1.binary_zbb_source.Fact, weights: []const u32, log: u32) ![]D.TraceColumn {
        if (self.finished) return error.DeviceTablesAlreadyFinalized;
        var batch = try Inputs.Batch.zbb(self.allocator, facts, weights, log);
        defer batch.deinit();
        var job = ExtraFamily{ .owner = self, .batch = &batch };
        try self.submit(ExtraFamily.callback, &job, &job.failure);
        return job.output;
    }
    pub fn formatDword(self: *CoreProjection, events: []const Front.memory.load_store_v2.native.Event, log: u32) ![]D.TraceColumn {
        if (self.finished) return error.DeviceTablesAlreadyFinalized;
        const encoded = try Memory.events(self.allocator, events);
        defer self.allocator.free(encoded);
        var job = ExtraMemory{ .owner = self, .events = encoded, .log = log };
        try self.submit(ExtraMemory.callback, &job, &job.failure);
        return job.output;
    }
    fn memoryOutput(self: *CoreProjection, ctx: *SC.Context, events: []const Memory.Event, log: u32, dword: bool) ![]D.TraceColumn {
        errdefer ctx.join() catch {};
        const input = try self.upload(ctx, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(events)));
        const out = try self.output(ctx, log, if (dword) 39 else 70);
        errdefer self.allocator.free(out);
        try ctx.join();
        const g = self.request.setup.materials.geometry;
        const job = MemoryJob{ .events = if (events.len == 0) null else input.words, .main = writable(out[0].device.?), .range16 = writable(self.ledgers.range16), .range8 = writable(self.ledgers.range8), .pairs = writable(self.ledgers.pairs), .selection = writable(self.ledgers.selection), .status = writable(self.ledgers.status), .count = @intCast(events.len), .log = log, .dword = @intFromBool(dword), .fused_pairs = @intFromBool(if (dword) g.ls_dword_fused_pairs else g.ls_fused_pairs) };
        try checked(self.backend.memory(ctx.native_context, 1, &job));
        try ctx.join();
        return out;
    }
};
fn descriptor(lease: Native.Lease, offset: usize, count: usize) D.DeviceCoefficients {
    return .{ .words = lease.words.? + offset, .count = count, .context_token = lease.context_token, .generation = lease.generation };
}
fn context(owner: *CoreProjection, raw: *anyopaque, token: u64) SC.Context {
    return .{ .session = owner.backend.service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(owner.scope), .api = &owner.backend.api };
}
const ExtraFamily = struct {
    owner: *CoreProjection,
    batch: *const Inputs.Batch,
    output: []D.TraceColumn = &.{},
    failure: ?anyerror = null,
    fn callback(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *ExtraFamily = @ptrCast(@alignCast(data.?));
        var ctx = context(self.owner, raw, token);
        self.output = self.owner.familyOutput(&ctx, self.batch, 32) catch |err| {
            self.failure = err;
            ctx.join() catch {};
            return 1;
        };
        return 0;
    }
};
const ExtraMemory = struct {
    owner: *CoreProjection,
    events: []const Memory.Event,
    log: u32,
    output: []D.TraceColumn = &.{},
    failure: ?anyerror = null,
    fn callback(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *ExtraMemory = @ptrCast(@alignCast(data.?));
        var ctx = context(self.owner, raw, token);
        self.output = self.owner.memoryOutput(&ctx, self.events, self.log, true) catch |err| {
            self.failure = err;
            ctx.join() catch {};
            return 1;
        };
        return 0;
    }
};
const Finish = struct {
    owner: *CoreProjection,
    failure: ?anyerror = null,
    fn callback(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Finish = @ptrCast(@alignCast(data.?));
        self.run(raw, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn run(self: *Finish, raw: *anyopaque, token: u64) !void {
        const o = self.owner;
        var ctx = context(o, raw, token);
        defer ctx.join() catch {};
        for (o.table_outputs.items) |table| {
            const input = switch (table.kind) {
                0 => o.ledgers.range16,
                1 => o.ledgers.range8,
                2, 3 => o.ledgers.and_,
                4 => o.ledgers.shift,
                5 => o.ledgers.selection,
                6 => o.ledgers.rom,
                else => return error.InvalidTableKind,
            };
            try checked(o.backend.table(raw, 1, input.words, if (table.kind == 3) writable(o.ledgers.pairs) else null, table.log, table.kind, table.pointer, writable(o.ledgers.status)));
        }
        try ctx.join();
        var status: [1]u32 = undefined;
        try ctx.download(try (try ctx.borrow(o.ledger_lease)).sub(o.ledger_lease.count - 1, 1), &status);
        try ctx.join();
        if (status[0] != 0) return error.InvalidDeviceFamilyWitness;
    }
};
const BuildJob = struct {
    owner: *CoreProjection,
    failure: ?anyerror = null,
    fn callback(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *BuildJob = @ptrCast(@alignCast(data.?));
        self.run(raw, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn run(self: *BuildJob, raw: *anyopaque, token: u64) !void {
        const o = self.owner;
        var ctx = context(o, raw, token);
        defer ctx.join() catch {};
        const source = &o.source.?;
        const g = source.materials.geometry;
        const p = o.request.native;
        const cpu = source.cpu.device_ledgers orelse return error.ResidentCpuLedgersRequired;
        const sizes = [_]usize{ 65536, 256, 65536, 65536, 16 * 65536, 2 * 65536, cpu.rom.count, 1 };
        var total: usize = 0;
        for (sizes) |size| total += size;
        const ledger = try o.allocate(&ctx, total, 0);
        o.ledger_lease = ledger;
        try checked(o.backend.memset(raw, ledger.words.?, 0, total * 4));
        var descriptors: [8]D.DeviceCoefficients = undefined;
        var offset: usize = 0;
        for (sizes, 0..) |size, i| {
            descriptors[i] = descriptor(ledger, offset, size);
            offset += size;
        }
        o.ledgers = .{ .range16 = descriptors[0], .range8 = descriptors[1], .pairs = descriptors[2], .and_ = descriptors[3], .shift = descriptors[4], .selection = descriptors[5], .rom = descriptors[6], .status = descriptors[7] };
        const copy = try symbol(Native.CopyDevice, &o.backend.service.library, "stwo_exec_context_memcpy_d2d_async");
        const from = [_]D.DeviceCoefficients{ cpu.range16, cpu.range8, cpu.pairs, cpu.rom };
        const to = [_]D.DeviceCoefficients{ o.ledgers.range16, o.ledgers.range8, o.ledgers.pairs, o.ledgers.rom };
        for (from, to, 0..) |input, output, index| {
            if (input.count != output.count or input.context_token != token) return error.InvalidCpuDeviceLedger;
            // The shared formatter supplies both diagnostic U8 and paired
            // histograms. In pair mode the AIR emits only the pair queries;
            // merging ordinary CPU gap counts would create unmatched debt.
            // This is the native sources.zig CPU c8-zeroing rule as well.
            if (index == 1 and g.cpu_u8_pairs) continue;
            try checked(copy(raw, @ptrCast(writable(output)), @ptrCast(input.words), input.count * 4));
        }
        try ctx.join();
        const shapes = source.materials.shapes();
        var columns: usize = 0;
        for (shapes) |shape| columns += shape.widths[1];
        o.columns = try o.allocator.alloc(D.TraceColumn, columns);
        // DIV creates its two multiplication support facts on-device. Only
        // original guest MUL facts are uploaded, never CPU-derived hints.
        const raw_mul: usize = p.raw_counts.multiplication;
        if (p.multiplication.len != raw_mul + 2 * p.division.len) return error.InvalidMultiplicationSupportCount;
        var mul_batch = try Inputs.Batch.multiplication(o.allocator, p.multiplication[0..raw_mul], g.multiplication_log);
        defer mul_batch.deinit();
        errdefer ctx.join() catch {};
        const mul_input = try o.allocate(&ctx, p.multiplication.len * 8, 0);
        if (raw_mul != 0) try ctx.upload(try (try ctx.borrow(mul_input)).sub(0, raw_mul * 8), mul_batch.words());
        var div_batch = try Inputs.Batch.division(o.allocator, p.division, g.division_log);
        defer div_batch.deinit();
        errdefer ctx.join() catch {};
        const div_input = try o.upload(&ctx, div_batch.words());
        try ctx.join();
        // Arithmetic first, regardless of physical roster ordering.
        for (shapes) |shape| if (shape.role == .division and shape.widths[1] != 0) {
            const cols = try o.output(&ctx, shape.log, shape.widths[1]);
            defer o.allocator.free(cols);
            @memcpy(o.columns[shape.offsets[1]..][0..cols.len], cols);
            const job = ArithmeticJob{ .requests = if (p.division.len == 0) null else div_input.words, .main = writable(cols[0].device.?), .range16 = writable(o.ledgers.range16), .range8 = writable(o.ledgers.range8), .pairs = writable(o.ledgers.pairs), .status = writable(o.ledgers.status), .mul_support = if (p.division.len == 0) null else mul_input.words.? + raw_mul * 8, .count = @intCast(p.division.len), .log = shape.log, .division = 1, .fused_pairs = 0 };
            try checked(o.backend.arithmetic(raw, 1, &job));
        };
        try ctx.join();
        for (shapes) |shape| {
            if (shape.widths[1] == 0 or shape.role == .division) continue;
            const target = o.columns[shape.offsets[1]..][0..shape.widths[1]];
            if (shape.role == .cpu) {
                if (target.len != source.cpu.device_main.len) return error.InvalidCpuDeviceProjection;
                @memcpy(target, source.cpu.device_main);
                continue;
            }
            var output: []D.TraceColumn = undefined;
            switch (shape.role) {
                .alu, .alu_tail => {
                    const start: usize = if (shape.role == .alu) 0 else source.alu.fact_count;
                    const count: usize = if (shape.role == .alu) source.alu.fact_count else source.tails.alu.?.fact_count;
                    var batch = try Inputs.Batch.alu(o.allocator, p.alu.facts[start..][0..count], p.alu.weights[start..][0..count], shape.log);
                    defer batch.deinit();
                    output = try o.familyOutput(&ctx, &batch, shape.widths[1]);
                },
                .binary, .binary_tail => {
                    const start: usize = if (shape.role == .binary) 0 else source.binary.fact_count;
                    const count: usize = if (shape.role == .binary) source.binary.fact_count else source.tails.binary.?.fact_count;
                    var batch = try Inputs.Batch.binary(o.allocator, p.binary.facts[start..][0..count], p.binary.weights[start..][0..count], shape.log);
                    defer batch.deinit();
                    output = try o.familyOutput(&ctx, &batch, shape.widths[1]);
                },
                .shift, .shift_tail => {
                    const start: usize = if (shape.role == .shift) 0 else source.shift.fact_count;
                    const count: usize = if (shape.role == .shift) source.shift.fact_count else source.tails.shift.?.fact_count;
                    var batch = try Inputs.Batch.shift(o.allocator, p.shift[start..][0..count], if (p.shift_weights.len == 0) null else p.shift_weights[start..][0..count], shape.log);
                    defer batch.deinit();
                    output = try o.familyOutput(&ctx, &batch, shape.widths[1]);
                },
                .jalr => {
                    var batch = try Inputs.Batch.jalr(o.allocator, source.jalr.facts, shape.log);
                    defer batch.deinit();
                    output = try o.familyOutput(&ctx, &batch, shape.widths[1]);
                },
                .ls, .ls_tail => {
                    const start: usize = if (shape.role == .ls) 0 else source.memory.ls.rows;
                    const count: usize = if (shape.role == .ls) source.memory.ls.rows else source.memory.ls_tail.?.rows;
                    output = try o.memoryOutput(&ctx, o.general_events[start..][0..count], shape.log, false);
                },
                .initial, .terminal => {
                    const cells = if (shape.role == .initial) source.memory.statement.initial else source.memory.statement.terminal;
                    const encoded = try Memory.cells(o.allocator, cells);
                    defer o.allocator.free(encoded);
                    errdefer ctx.join() catch {};
                    const input = try o.upload(&ctx, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(encoded)));
                    output = try o.output(&ctx, shape.log, shape.widths[1]);
                    try ctx.join();
                    try checked(o.backend.boundary(raw, 1, if (cells.len == 0) null else input.words, @intCast(cells.len), shape.log, writable(output[0].device.?), writable(o.ledgers.status)));
                    try ctx.join();
                },
                .multiplication => {
                    output = try o.output(&ctx, shape.log, shape.widths[1]);
                    const job = ArithmeticJob{ .requests = if (p.multiplication.len == 0) null else mul_input.words, .main = writable(output[0].device.?), .range16 = writable(o.ledgers.range16), .range8 = writable(o.ledgers.range8), .pairs = writable(o.ledgers.pairs), .status = writable(o.ledgers.status), .mul_support = null, .count = @intCast(p.multiplication.len), .log = shape.log, .division = 0, .fused_pairs = @intFromBool(g.mul_u8_pairs) };
                    try checked(o.backend.arithmetic(raw, 1, &job));
                    try ctx.join();
                },
                .rom, .range16, .range8, .and_table, .shift_table, .selection => {
                    output = try o.output(&ctx, shape.log, shape.widths[1]);
                    const kind: u32 = switch (shape.role) {
                        .range16 => 0,
                        .range8 => 1,
                        .and_table => if (g.cpu_u8_pairs) 3 else 2,
                        .shift_table => 4,
                        .selection => 5,
                        .rom => 6,
                        else => unreachable,
                    };
                    try o.table_outputs.append(o.allocator, .{ .kind = kind, .log = shape.log, .pointer = writable(output[0].device.?) });
                },
                else => return error.UnsupportedDeviceCoreRole,
            }
            defer o.allocator.free(output);
            if (output.len != target.len) return error.InvalidDeviceCoreWidth;
            @memcpy(target, output);
        }
    }
};
comptime {
    if (@sizeOf(FamilyJob) != 64 or @sizeOf(MemoryJob) != 72 or @sizeOf(ArithmeticJob) != 72) @compileError("resident family ABI changed");
}

test "resident core family factory bodies are fully typed" {
    std.mem.doNotOptimizeAway(&Context.init);
    std.mem.doNotOptimizeAway(&Context.buildCore);
    std.mem.doNotOptimizeAway(&CoreProjection.formatZbb);
    std.mem.doNotOptimizeAway(&CoreProjection.formatDword);
    std.mem.doNotOptimizeAway(&CoreProjection.finishTables);
}

fn writable(value: D.DeviceCoefficients) [*]u32 {
    return @constCast(value.words);
}

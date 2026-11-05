//! Compact CPU metadata -> resident physical MAIN. Only multiplicities/status
//! return to the host. Immutable ROM is cached by program and fixed authority;
//! neither CPU MAIN nor per-request ROM matrices are constructed on the host.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration").rv64_cpu_source;
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const X = @import("stwo_riscv_frontend").rv64_air.word16_execution;
const Native = @import("pcs_native_abi.zig");
const Service = @import("pcs_native.zig");
const SC = @import("session_context.zig");
const A = @import("abi.zig");
const Ingress = @import("cpu_witness.zig");
const a = std.heap.page_allocator;
const Memset = *const fn (*anyopaque, *anyopaque, c_int, usize) callconv(.c) c_int;
fn symbol(comptime T: type, lib: *std.DynLib, name: [:0]const u8) !T {
    return lib.lookup(T, name) orelse error.MissingCpuProjectionSymbol;
}
fn checked(status: c_int) !void {
    if (status != 0) return error.CudaCpuProjectionFailed;
}
pub const Context = struct {
    retain_ledgers: bool = false,
    service: *Service.Context,
    api: SC.Api,
    kernel: *const @TypeOf(A.stwo_rv64_cpu_witness_on),
    unpack: ?*const @TypeOf(A.stwo_rv64_cpu_unpack_on),
    memset: Memset,
    mutex: std.Thread.Mutex = .{},
    pub fn init(service: *Service.Context) !Context {
        return .{ .service = service, .api = .{
            .allocate = service.lease_allocate,
            .release = service.lease_release,
            .validate_range = service.lease_validate_range,
            .upload = try symbol(Native.Upload, &service.library, "stwo_exec_context_memcpy_h2d_async"),
            .download = try symbol(Native.Download, &service.library, "stwo_exec_context_memcpy_d2h_async"),
            .sync = try symbol(Native.Sync, &service.library, "stwo_exec_context_sync"),
            .lane_stream = try symbol(Native.LaneStream, &service.library, "stwo_exec_context_lane_stream"),
        }, .kernel = try symbol(*const @TypeOf(A.stwo_rv64_cpu_witness_on), &service.library, "stwo_rv64_cpu_witness_on"), .unpack = service.library.lookup(*const @TypeOf(A.stwo_rv64_cpu_unpack_on), "stwo_rv64_cpu_unpack_on"), .memset = try symbol(Memset, &service.library, "stwo_exec_context_memset_async") };
    }
    pub fn residentStage(self: *Context) CPU.ProjectionStage {
        self.retain_ledgers = true;
        return self.stage();
    }
    pub fn stage(self: *Context) CPU.ProjectionStage {
        return .{ .context = self, .project = project };
    }
    pub fn deinit(self: *Context) void {
        self.* = undefined;
    }
    fn project(raw: *anyopaque, source: *const CPU.Source, scope: D.Scope) !CPU.DeviceProjection {
        const self: *Context = @ptrCast(@alignCast(raw));
        if (!std.mem.allEqual(u8, &scope.main, 0)) return error.CpuProjectionRequiresUncommittedMain;
        // The independent fixed authority is already selected before this seam.
        // A retired ROM is reconstructed once from its immutable decoded owner.
        if (!source.compact or !source.program.compact or source.main.len != 0 or source.main_projection_closed or source.metadata.len != source.public.steps or source.public.steps >= source.size() or source.log_size < 5 or source.log_size > 22 or source.public.final_pc & 3 != 0 or !X.features.compactPcAdmitted(source.public.final_pc)) return error.CpuDeviceIngressUnavailable;
        if (!source.program.fixed_retired) _ = try Ingress.Input.fromCapture(source);
        if (source.rom_counts.len != source.program.size()) return error.InvalidCpuRomGeometry;
        var timer = try std.time.Timer.start();
        // Pack off the service owner thread so another worker may keep the
        // GPU fed while this request prepares its compact input.
        const compact_enabled = if (std.posix.getenv("STWO_RV64_CPU_COMPACT_INGRESS")) |v| !std.mem.eql(u8, v, "0") else false;
        if (compact_enabled and self.unpack == null) return error.MissingCpuUnpackKernel;
        var compact_capture: ?Ingress.Compact = if (compact_enabled) try Ingress.Compact.fromCapture(a, source) else null;
        defer if (compact_capture) |*p| p.deinit();
        const pack_ns = timer.lap();
        self.mutex.lock();
        defer self.mutex.unlock();
        const owner = try a.create(Owner);
        errdefer a.destroy(owner);
        owner.* = .{ .service = self.service, .columns = try a.alloc(D.TraceColumn, X.layout.mainCount(true)), .counts16 = &.{}, .counts8 = &.{}, .pairs = &.{} };
        errdefer a.free(owner.columns);
        errdefer a.free(owner.counts16);
        errdefer a.free(owner.counts8);
        errdefer a.free(owner.pairs);
        if (!self.retain_ledgers) {
            owner.counts16 = try a.alloc(u64, 65536);
            owner.counts8 = try a.alloc(u64, 256);
            owner.pairs = try a.alloc(u64, 65536);
        }
        var job = Job{ .backend = self, .source = source, .scope = scope, .owner = owner, .compact = if (compact_capture) |*p| p else null };
        const status = self.service.submit(self.service.session, Job.callback, &job);
        if (job.failure) |err| return err;
        try checked(status);
        std.debug.print("GPU_CPU_PROJECTION rows={} active={} metadata_h2d_bytes={} main_d2h_bytes=0 total_ns={} rom_cache_hit={} compact={} pack_ns={}\n", .{ source.size(), source.metadata.len, if (compact_capture) |p| p.bytes() else source.metadata.len * @sizeOf(CPU.Metadata), timer.read() + pack_ns, job.rom_cache_hit, compact_enabled, pack_ns });
        return .{ .owner = .{ .context = owner, .release = Owner.release }, .columns = owner.columns, .ledgers = owner.ledgers, .counts16 = owner.counts16, .counts8 = owner.counts8, .pair_counts = owner.pairs };
    }
};
const Owner = struct {
    service: *Service.Context,
    eval: Native.Lease = .{},
    ledger_lease: Native.Lease = .{},
    ledgers: ?CPU.DeviceLedgers = null,
    columns: []D.TraceColumn,
    counts16: []u64,
    counts8: []u64,
    pairs: []u64,
    fn release(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        _ = self.service.submit(self.service.session, releaseDevice, self);
        a.free(self.columns);
        a.free(self.counts16);
        a.free(self.counts8);
        a.free(self.pairs);
        a.destroy(self);
    }
    fn releaseDevice(_: *anyopaque, _: u64, raw: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(raw.?));
        var status: c_int = 0;
        if (self.ledger_lease.generation != 0) status = self.service.lease_release(self.service.session, &self.ledger_lease);
        const eval_status = self.service.lease_release(self.service.session, &self.eval);
        return if (status != 0) status else eval_status;
    }
};
const Job = struct {
    backend: *Context,
    source: *const CPU.Source,
    scope: D.Scope,
    owner: *Owner,
    failure: ?anyerror = null,
    rom_cache_hit: bool = false,
    compact: ?*const Ingress.Compact = null,
    fn callback(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Job = @ptrCast(@alignCast(data.?));
        self.run(raw, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn rom(self: *Job, raw: *anyopaque, _: u64) !Native.Lease {
        const b = self.backend;
        const p = self.source.program;
        if (p.log_size < 5 or p.log_size > 24) return error.InvalidCpuRomGeometry;
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("stwo/rv64/cuda/immutable-cpu-rom/v2\x00");
        h.update(&p.identity);
        var log_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &log_bytes, p.log_size, .little);
        h.update(&log_bytes);
        // makeCompact changes the physical ROM tuple without changing the
        // code identity; never reuse the uncompressed decode matrix for it.
        h.update(&.{@intFromBool(p.compact)});
        std.mem.writeInt(u32, &log_bytes, @intFromEnum(p.profile), .little);
        h.update(&log_bytes);
        const digest = h.finalResult();
        var identity: [8]u32 = undefined;
        for (&identity, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
        const scope = @import("pcs_scope.zig").identity(self.scope);
        const count = X.layout.rom.FIXED * p.size();
        if (try b.service.immutableLookup(scope, identity, count)) |lease| {
            self.rom_cache_hit = true;
            return lease;
        }
        const rebuilt = if (p.fixed_retired) try reconstructRom(a, p) else null;
        defer if (rebuilt) |words| a.free(words);
        const words: []const u32 = if (rebuilt) |data| data else std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(p.fixed));
        if (words.len != count) return error.InvalidCpuRomGeometry;
        return b.service.immutableWords(raw, scope, identity, words);
    }
    fn run(self: *Job, raw: *anyopaque, token: u64) !void {
        const b = self.backend;
        const source = self.source;
        const rom_lease = try self.rom(raw, token);
        // The cache owns immutable ROM. This proof owns only the provisional
        // read-only alias, which ends after formatter work has joined.
        defer b.service.releaseImmutableScope(@import("pcs_scope.zig").identity(self.scope)) catch {};
        const metadata = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(source.metadata));
        const scope = @import("pcs_scope.zig").identity(self.scope);
        var ctx = SC.Context{ .session = b.service.session, .native_context = raw, .token = token, .scope = scope, .api = &b.api };
        defer std.debug.print("GPU_NATIVE_H2D role=cpu ordinal={} bytes={} scope=scoped-uploads-only\n", .{ self.scope.ordinal, ctx.uploaded_bytes });
        const rom_rows = source.program.size();
        const count_base = @max(@as(usize, 1), metadata.len);
        const c8_base = count_base + 65536;
        const rom_base = c8_base + 256;
        const status_base = rom_base + rom_rows;
        const pair_base = status_base + 1;
        var scratch = try ctx.allocate(pair_base + 65536, 0);
        var ledger_adopted = false;
        defer {
            ctx.join() catch {};
            if (!ledger_adopted) ctx.release(&scratch) catch {};
        }
        const eval = try ctx.allocate(source.size() * X.layout.mainCount(true), 1);
        var adopted = false;
        defer if (!adopted) {
            var cleanup = eval;
            ctx.join() catch {};
            ctx.release(&cleanup) catch {};
        };
        var compact_input: Native.Lease = .{};
        defer if (compact_input.generation != 0) {
            ctx.join() catch {};
            ctx.release(&compact_input) catch {};
        };
        if (self.compact) |p| {
            const records = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(p.records));
            const seeds = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(p.seeds));
            compact_input = try ctx.allocate(@max(1, records.len + seeds.len), 0);
            if (records.len != 0) try ctx.upload(try (try ctx.borrow(compact_input)).sub(0, records.len), records);
            if (seeds.len != 0) try ctx.upload(try (try ctx.borrow(compact_input)).sub(records.len, seeds.len), seeds);
        } else if (metadata.len != 0) try ctx.upload(try (try ctx.borrow(scratch)).sub(0, metadata.len), metadata);
        try checked(b.memset(raw, scratch.words.? + count_base, 0, (pair_base + 65536 - count_base) * 4));
        try ctx.join();
        if (self.compact) |p| {
            const unpack = A.CpuUnpack{ .records = compact_input.words.?, .seeds = compact_input.words.? + p.records.len * 4, .rom = rom_lease.words.?, .metadata = scratch.words.?, .status = scratch.words.? + status_base, .count = @intCast(p.records.len), .rom_log = source.program.log_size, .chunk_rows = Ingress.compact_chunk_rows };
            try checked(b.unpack.?(raw, 1, &unpack));
        }
        const job = A.CpuWitness{ .metadata = if (metadata.len != 0) scratch.words.? else null, .rom = rom_lease.words.?, .main = eval.words.?, .counts16 = scratch.words.? + count_base, .counts8 = scratch.words.? + c8_base, .rom_counts = scratch.words.? + rom_base, .status = scratch.words.? + status_base, .count = @intCast(source.metadata.len), .log = source.log_size, .rom_log = source.program.log_size, .final_pc = @intCast(source.public.final_pc), .pair_counts = scratch.words.? + pair_base };
        try checked(b.kernel(raw, 1, &job));
        // Downloads use the coordination stream, while the formatter writes
        // on lane1. A join after the download cannot establish that ordering.
        // This is the narrow host histogram boundary, never a MAIN readback.
        try ctx.join();
        if (b.retain_ledgers) {
            var verdict: [1]u32 = undefined;
            try ctx.download(try (try ctx.borrow(scratch)).sub(status_base, 1), &verdict);
            try ctx.join();
            if (verdict[0] != 0) return error.InvalidGpuCpuMetadata;
            self.owner.ledger_lease = scratch;
            self.owner.ledgers = .{
                .metadata = if (metadata.len == 0) null else ledger(scratch, 0, metadata.len),
                .range16 = ledger(scratch, count_base, 65536),
                .range8 = ledger(scratch, c8_base, 256),
                .pairs = ledger(scratch, pair_base, 65536),
                .rom = ledger(scratch, rom_base, rom_rows),
            };
            ledger_adopted = true;
        } else {
            const readback = try a.alloc(u32, pair_base + 65536 - count_base);
            defer a.free(readback);
            try ctx.download(try (try ctx.borrow(scratch)).sub(count_base, readback.len), readback);
            try ctx.join();
            if (readback[status_base - count_base] != 0) return error.InvalidGpuCpuMetadata;
            for (readback[rom_base - count_base ..][0..rom_rows], source.rom_counts) |actual, expected| if (actual != expected) return error.CpuRomMultiplicityMismatch;
            for (self.owner.counts16, readback[0..65536]) |*out, value| out.* = value;
            for (self.owner.counts8, readback[c8_base - count_base ..][0..256]) |*out, value| out.* = value;
            for (self.owner.pairs, readback[pair_base - count_base ..][0..65536]) |*out, value| out.* = value;
        }
        for (self.owner.columns, 0..) |*column, i| column.* = .{ .log_size = source.log_size, .encoding = .evaluations, .device = .{ .words = eval.words.? + i * source.size(), .count = source.size(), .context_token = token, .generation = eval.generation } };
        self.owner.eval = eval;
        adopted = true;
    }
};

fn ledger(lease: Native.Lease, offset: usize, count: usize) D.DeviceCoefficients {
    return .{ .words = lease.words.? + offset, .count = count, .context_token = lease.context_token, .generation = lease.generation };
}

fn reconstructRom(allocator: std.mem.Allocator, program: anytype) ![]u32 {
    const rows = program.size();
    const data = try allocator.alloc(u32, X.layout.rom.FIXED * rows);
    errdefer allocator.free(data);
    @memset(data, 0);
    for (0..rows) |logical| {
        const tuple = try program.tupleAt(logical);
        const physical = X.layout.physical(logical, program.log_size);
        for (tuple, 0..) |value, column| data[column * rows + physical] = value.v;
    }
    data[X.layout.rom.FIRST * rows + X.layout.physical(0, program.log_size)] = 1;
    data[X.layout.rom.LAST * rows + X.layout.physical(rows - 1, program.log_size)] = 1;
    return data;
}

test "resident CPU ROM cache reconstructs exact independently derived compact setup" {
    const allocator = std.testing.allocator;
    const Program = std.meta.Child(@TypeOf(@as(CPU.Source, undefined).program));
    var program = try Program.init(allocator, .{ .base = 4096, .words = &.{ 0x00004033, 0xfe000ee3 } });
    defer program.deinit();
    try program.makeCompact();
    const rebuilt = try reconstructRom(allocator, &program);
    defer allocator.free(rebuilt);
    try std.testing.expectEqualSlices(u32, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(program.fixed)), rebuilt);
    try program.releaseFixedWitness();
    const retired = try reconstructRom(allocator, &program);
    defer allocator.free(retired);
    try std.testing.expectEqualSlices(u32, rebuilt, retired);
}

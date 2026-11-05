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
const CopyD2D = *const fn (*anyopaque, *anyopaque, *const anyopaque, usize) callconv(.c) c_int;
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
    pending: ?*Pending = null,
    prestage_error: ?anyerror = null,
    prestage_serial: u64 = 0,
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
        return .{ .context = self, .project = project, .prestage = prestage, .join_prestage = joinPrestage, .cancel_prestage = cancelPrestage };
    }
    pub fn deinit(self: *Context) void {
        cancelPrestage(self);
        self.* = undefined;
    }
    fn project(raw: *anyopaque, source: *const CPU.Source, scope: D.Scope) !CPU.DeviceProjection {
        const self: *Context = @ptrCast(@alignCast(raw));
        if (self.pending) |pending| if (scope.ordinal == 0) {
            try joinPrestage(self);
            if (pending.promoted) return error.CpuPrestageAlreadyPromoted;
            if (self.service.active_block == null or !std.mem.eql(u8, &self.service.active_block.?, &pending.block)) return error.ForeignCpuPrestageBlock;
            const identity = try pending.requireCapture(source);
            if (!std.mem.allEqual(u8, &scope.main, 0)) return error.CpuProjectionRequiresUncommittedMain;
            const original = pending.result orelse return error.CpuPrestageMissingResult;
            const old: *Owner = @ptrCast(@alignCast(original.owner.?.context));
            const owner = try a.create(Owner);
            errdefer a.destroy(owner);
            owner.* = .{ .service = self.service, .columns = try a.alloc(D.TraceColumn, old.columns.len), .counts16 = &.{}, .counts8 = &.{}, .pairs = &.{} };
            errdefer a.free(owner.columns);
            var copy = Promote{ .backend = self, .old = old, .owner = owner, .old_scope = pending.scope, .scope = scope };
            const begin = utcNs();
            const status = self.service.submit(self.service.session, Promote.callback, &copy);
            if (copy.failure) |err| return err;
            try checked(status);
            original.owner.?.release(original.owner.?.context);
            pending.result = null;
            pending.promoted = true;
            std.debug.print("GPU_CPU_PRESTAGE event=promoted ordinal=0 begin_utc_ns={} end_utc_ns={} metadata_sha256={x}\n", .{ begin, utcNs(), identity });
            return .{ .owner = .{ .context = owner, .release = Owner.release }, .columns = owner.columns, .ledgers = owner.ledgers, .counts16 = &.{}, .counts8 = &.{}, .pair_counts = &.{} };
        };
        return projectFresh(raw, source, scope);
    }
    fn prestage(raw: *anyopaque, source: *const CPU.Source, input_policy: [32]u8) void {
        const self: *Context = @ptrCast(@alignCast(raw));
        if (self.pending != null or self.prestage_error != null) {
            self.prestage_error = error.DuplicateCpuPrestage;
            return;
        }
        if (!self.retain_ledgers or source.epoch != 1) {
            self.prestage_error = error.CpuPrestageRequiresFirstResidentCpu;
            return;
        }
        if (self.service.active_block == null or self.service.admission != null) {
            self.prestage_error = error.CpuPrestageAdmissionUnavailable;
            return;
        }
        self.prestage_serial = std.math.add(u64, self.prestage_serial, 1) catch {
            self.prestage_error = error.CpuPrestageSerialOverflow;
            return;
        };
        const pending = a.create(Pending) catch |err| {
            self.prestage_error = err;
            return;
        };
        pending.* = .{ .backend = self, .source = source.*, .input_policy = input_policy, .block = self.service.active_block.?, .serial = self.prestage_serial };
        self.pending = pending;
        pending.thread = std.Thread.spawn(.{}, Pending.run, .{pending}) catch |err| {
            pending.failure = err;
            return;
        };
        std.debug.print("GPU_CPU_PRESTAGE event=enqueued ordinal=0 utc_ns={} serial={}\n", .{ utcNs(), self.prestage_serial });
    }
    fn joinPrestage(raw: *anyopaque) !void {
        const self: *Context = @ptrCast(@alignCast(raw));
        if (self.prestage_error) |err| return err;
        if (self.pending) |pending| {
            if (pending.thread) |thread| thread.join();
            pending.thread = null;
            if (pending.failure) |err| return err;
        }
    }
    fn cancelPrestage(raw: *anyopaque) void {
        const self: *Context = @ptrCast(@alignCast(raw));
        if (self.pending) |pending| {
            if (pending.thread) |thread| thread.join();
            if (pending.result) |result| if (result.owner) |owner| owner.release(owner.context);
            a.destroy(pending);
        }
        self.pending = null;
        self.prestage_error = null;
    }
    fn projectFresh(raw: *anyopaque, source: *const CPU.Source, scope: D.Scope) !CPU.DeviceProjection {
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
fn utcNs() u64 {
    return @intCast(std.time.nanoTimestamp());
}
/// A private staging identity, never mixed into a transcript. Both early and
/// final sources hash all metadata bytes plus captured publics and the freshly
/// pinned input/policy image. Pointer identity alone never admits promotion.
fn captureIdentity(source: *const CPU.Source, input_policy: [32]u8) ![32]u8 {
    if (source.metadata.len != source.public.steps or source.log_size < 5 or source.log_size > 22 or source.compact != source.program.compact) return error.CpuPrestageShapeChanged;
    const public = try std.json.Stringify.valueAlloc(a, source.public, .{});
    defer a.free(public);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("stwo/rv64/cpu0-private-prestage/captured-input/v1\x00");
    h.update(&input_policy);
    h.update(&source.program.identity);
    var words: [40]u8 = undefined;
    std.mem.writeInt(u64, words[0..8], source.epoch, .little);
    std.mem.writeInt(u64, words[8..16], source.log_size, .little);
    std.mem.writeInt(u64, words[16..24], source.metadata.len, .little);
    std.mem.writeInt(u64, words[24..32], source.program.log_size, .little);
    std.mem.writeInt(u64, words[32..40], @intFromEnum(source.program.profile), .little);
    h.update(&words);
    h.update(&.{@intFromBool(source.compact)});
    h.update(public);
    h.update(std.mem.sliceAsBytes(source.metadata));
    return h.finalResult();
}
const Pending = struct {
    backend: *Context,
    // Borrowed until join, not an owner. No metadata/public/capture field is
    // mutated by staging; the caller joins before retiring program storage.
    source: CPU.Source,
    input_policy: [32]u8,
    block: [32]u8,
    serial: u64,
    identity: [32]u8 = undefined,
    scope: D.Scope = undefined,
    result: ?CPU.DeviceProjection = null,
    thread: ?std.Thread = null,
    failure: ?anyerror = null,
    promoted: bool = false,
    fn requireCapture(self: *const Pending, source: *const CPU.Source) ![32]u8 {
        if (source.log_size != self.source.log_size or source.compact != self.source.compact or source.metadata.len != self.source.metadata.len) return error.CpuPrestageShapeChanged;
        const identity = try captureIdentity(source, self.input_policy);
        if (!std.mem.eql(u8, &identity, &self.identity)) return error.CpuPrestageCaptureChanged;
        return identity;
    }
    fn run(self: *Pending) void {
        self.work() catch |err| {
            self.failure = err;
        };
    }
    fn work(self: *Pending) !void {
        self.identity = try captureIdentity(&self.source, self.input_policy);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("stwo/rv64/cpu0-private-prestage/custody/v1\x00");
        h.update(&self.identity);
        h.update(&self.block);
        var serial: [8]u8 = undefined;
        std.mem.writeInt(u64, &serial, self.serial, .little);
        h.update(&serial);
        self.scope = .{ .statement = h.finalResult(), .fixed = self.source.program.identity, .main = @splat(0), .ordinal = 0 };
        self.result = try Context.projectFresh(self.backend, &self.source, self.scope);
        std.debug.print("GPU_CPU_PRESTAGE event=ready ordinal=0 utc_ns={} metadata_sha256={x}\n", .{ utcNs(), self.identity });
    }
};
const Promote = struct {
    backend: *Context,
    old: *Owner,
    owner: *Owner,
    old_scope: D.Scope,
    scope: D.Scope,
    failure: ?anyerror = null,
    fn callback(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Promote = @ptrCast(@alignCast(data.?));
        self.run(raw, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn run(self: *Promote, raw: *anyopaque, token: u64) !void {
        const b = self.backend;
        if (self.old.service != b.service or self.old.ledgers == null or self.old.counts16.len != 0 or self.old.counts8.len != 0 or self.old.pairs.len != 0) return error.InvalidCpuPrestageOwner;
        var previous = SC.Context{ .session = b.service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(self.old_scope), .api = &b.api };
        // Validate under each buffer's OWN scope; never borrow the provisional
        // allocation as a final proof allocation and never retag a lease.
        _ = try previous.borrow(self.old.eval);
        _ = try previous.borrow(self.old.ledger_lease);
        var ctx = SC.Context{ .session = b.service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(self.scope), .api = &b.api };
        var eval = try ctx.allocate(std.math.cast(usize, self.old.eval.count) orelse return error.InvalidCpuPrestageSize, 1);
        errdefer {
            ctx.join() catch {};
            ctx.release(&eval) catch {};
        }
        var ledger_lease = try ctx.allocate(std.math.cast(usize, self.old.ledger_lease.count) orelse return error.InvalidCpuPrestageSize, 0);
        errdefer {
            ctx.join() catch {};
            ctx.release(&ledger_lease) catch {};
        }
        _ = try ctx.borrow(eval);
        _ = try ctx.borrow(ledger_lease);
        const copy = try symbol(CopyD2D, &b.service.library, "stwo_exec_context_memcpy_d2d_async");
        try checked(copy(raw, eval.words.?, self.old.eval.words.?, @intCast(eval.count * 4)));
        try checked(copy(raw, ledger_lease.words.?, self.old.ledger_lease.words.?, @intCast(ledger_lease.count * 4)));
        try ctx.join();
        for (self.old.columns, self.owner.columns) |old, *column| {
            column.* = old;
            column.device = repoint(old.device.?, self.old.eval, eval);
        }
        var ledgers = self.old.ledgers.?;
        inline for (.{ "range16", "range8", "pairs", "rom" }) |name| @field(ledgers, name) = repoint(@field(ledgers, name), self.old.ledger_lease, ledger_lease);
        if (ledgers.metadata) |metadata| ledgers.metadata = repoint(metadata, self.old.ledger_lease, ledger_lease);
        self.owner.eval = eval;
        self.owner.ledger_lease = ledger_lease;
        self.owner.ledgers = ledgers;
    }
    fn repoint(old: D.DeviceCoefficients, from: Native.Lease, to: Native.Lease) D.DeviceCoefficients {
        const offset = (@intFromPtr(old.words) - @intFromPtr(from.words.?)) / @sizeOf(u32);
        return .{ .words = to.words.? + offset, .count = old.count, .context_token = to.context_token, .generation = to.generation };
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

test "CPU prestage identity binds complete metadata publics shape and input policy" {
    const allocator = std.testing.allocator;
    const Program = std.meta.Child(@TypeOf(@as(CPU.Source, undefined).program));
    var program = try Program.init(allocator, .{ .base = 4096, .words = &.{ 0x00000013, 0x0000006f } });
    defer program.deinit();
    try program.makeCompact();
    var metadata = [_]CPU.Metadata{.{ .values = @splat(0), .clocks = @splat(0), .rom_row = 0 }};
    var source = CPU.Source{ .allocator = allocator, .program = &program, .public = std.mem.zeroes(@FieldType(CPU.Source, "public")), .epoch = 1, .log_size = 5, .metadata = &metadata, .rom_counts = &.{}, .counts16 = &.{}, .counts8 = &.{}, .compact = true };
    source.public.steps = 1;
    const input_policy: [32]u8 = @splat(7);
    var pending = Pending{ .backend = undefined, .source = source, .input_policy = input_policy, .block = @splat(9), .serial = 1, .identity = try captureIdentity(&source, input_policy) };
    _ = try pending.requireCapture(&source);
    metadata[0].values[0] = @as(u64, 1) << 63;
    try std.testing.expectError(error.CpuPrestageCaptureChanged, pending.requireCapture(&source));
    metadata[0].values[0] = 0;
    metadata[0].clocks[2] = 1;
    try std.testing.expectError(error.CpuPrestageCaptureChanged, pending.requireCapture(&source));
    metadata[0].clocks[2] = 0;
    source.epoch = 2;
    try std.testing.expectError(error.CpuPrestageCaptureChanged, pending.requireCapture(&source));
    source.epoch = 1;
    source.public.final_pc = 4;
    try std.testing.expectError(error.CpuPrestageCaptureChanged, pending.requireCapture(&source));
    source.public.final_pc = 0;
    source.log_size = 6;
    try std.testing.expectError(error.CpuPrestageShapeChanged, pending.requireCapture(&source));
    source.log_size = 5;
    program.identity[0] ^= 1;
    try std.testing.expectError(error.CpuPrestageCaptureChanged, pending.requireCapture(&source));
    program.identity[0] ^= 1;
    pending.input_policy[0] ^= 1;
    try std.testing.expectError(error.CpuPrestageCaptureChanged, pending.requireCapture(&source));
}

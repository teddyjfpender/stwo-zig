//! Native global LogUp witness generation from committed device MAIN.
//! Only independently derived setup/manifest metadata enters from the host.
//! Wide rows, paired fractions, inverses and centered prefixes stay on device.
const std = @import("std");
const CopyRun = @import("device_copy_run.zig").Run;
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const W = @import("stwo_riscv_cpu_integration").rv64_gkr_cpu_worker;
const DG = W.DeviceGlobal;
const G = @import("global_codegen.zig");
const Aot = @import("global_aot.zig");
const Service = @import("pcs_native.zig");
const Native = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const Abi = @import("abi.zig");
const Prefix = @import("prefix_plan.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
pub const Launch = *const fn (*anyopaque, u32, [*]const u32, [*]const u32, [*]const u32, [*]u32, [*]u32, [*]u32, u32) callconv(.c) c_int;
pub const Layout = enum { inverse_prefix, cumulative_batches };
pub const Request = struct {
    scope: D.Scope,
    log_size: u32,
    public_boundary: bool = false,
    fixed: []const D.Column,
    main: []const D.Column,
    fixed_offset: usize = 0,
    parameters: []const O,
    projection: Launch,
    groups: [2]u32,
    layout: Layout = .inverse_prefix,
    zero_claim_groups: u2 = 0,
    budget: usize,
};
const Cumulative = extern struct { output: [*]u32, contributions: [*]const u32, stride: u64, row_log: u32, pairs: u32 };
const CumulativeFn = *const fn (*anyopaque, u32, *const Cumulative) callconv(.c) c_int;
const N2b = *const fn ([*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
fn sym(comptime T: type, library: *std.DynLib, name: [:0]const u8) !T {
    return library.lookup(T, name) orelse error.MissingResidentGlobalSymbol;
}
fn checked(status: c_int) !void {
    if (status != 0) return error.CudaGlobalWitnessFailed;
}
fn immutableIdentity(domain: []const u8, root: [32]u8, index: usize, log: u32) [8]u32 {
    var h = std.crypto.hash.blake2.Blake2s256.init(.{});
    h.update(domain);
    h.update(&root);
    var numbers: [12]u8 = undefined;
    std.mem.writeInt(u64, numbers[0..8], index, .little);
    std.mem.writeInt(u32, numbers[8..12], log, .little);
    h.update(&numbers);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    var key: [8]u32 = undefined;
    for (&key, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    return key;
}
const Entry = struct { artifact: G.Artifact, launch: Launch };
pub const Context = struct {
    service: *Service.Context,
    profile_ingress: bool = false,
    api: SC.Api,
    copy: Native.CopyDevice,
    n2b: N2b,
    pairs: *const @TypeOf(Abi.stwo_rv64_global_pairs_on),
    cumulative: ?CumulativeFn,
    entries: std.ArrayList(*Entry) = .empty,
    twiddles: @import("global_twiddle_cache.zig").Table(engine.poly.twiddles.TwiddleTree([]M)) = @splat(null),
    mutex: std.Thread.Mutex = .{},
    pub fn init(service: *Service.Context) !Context {
        return .{ .service = service, .profile_ingress = std.process.hasEnvVarConstant("STWO_RV64_GLOBAL_PROFILE"), .api = .{
            .allocate = service.lease_allocate,
            .release = service.lease_release,
            .validate_range = service.lease_validate_range,
            .upload = try sym(Native.Upload, &service.library, "stwo_exec_context_memcpy_h2d_async"),
            .download = try sym(Native.Download, &service.library, "stwo_exec_context_memcpy_d2h_async"),
            .sync = try sym(Native.Sync, &service.library, "stwo_exec_context_sync"),
            .lane_stream = try sym(Native.LaneStream, &service.library, "stwo_exec_context_lane_stream"),
        }, .copy = try sym(Native.CopyDevice, &service.library, "stwo_exec_context_memcpy_d2d_async"), .n2b = try sym(N2b, &service.library, "stwo_ntt_n2b_columns_on"), .cumulative = service.library.lookup(CumulativeFn, "stwo_rv64_global_cumulative_on"), .pairs = try sym(*const @TypeOf(Abi.stwo_rv64_global_pairs_on), &service.library, "stwo_rv64_global_pairs_on") };
    }
    pub fn deinit(self: *Context) void {
        for (self.entries.items) |cached| {
            cached.artifact.deinit();
            std.heap.page_allocator.destroy(cached);
        }
        self.entries.deinit(std.heap.page_allocator);
        for (&self.twiddles) |*tw| if (tw.*) |*tree| engine.poly.twiddles.deinitM31(std.heap.page_allocator, tree);
        self.* = undefined;
    }
    pub fn stage(self: *Context) DG.Stage {
        return .{ .context = self, .generate = generate };
    }
    fn entry(self: *Context, descriptor: G.Source.Descriptor) !*Entry {
        for (self.entries.items) |e| if (std.meta.eql(e.artifact.descriptor, descriptor)) return e;
        const a = std.heap.page_allocator;
        const e = try a.create(Entry);
        errdefer a.destroy(e);
        e.artifact = try G.record(a, descriptor);
        errdefer e.artifact.deinit();
        const name = try Aot.name(a, &e.artifact);
        defer a.free(name);
        const z = try a.dupeZ(u8, name);
        defer a.free(z);
        e.launch = try sym(Launch, &self.service.library, z);
        try self.entries.append(a, e);
        return e;
    }
    fn generate(raw: *anyopaque, a: std.mem.Allocator, scope: D.Scope, item: DG.Item, shared: DG.Shared, budget: usize) !DG.Witness {
        const self: *Context = @ptrCast(@alignCast(raw));
        self.mutex.lock();
        defer self.mutex.unlock();
        const e = try self.entry(item.descriptor);
        const shape = try G.Authority.shape(item.descriptor);
        if (item.fixed.len != shape.fixed or item.main.len != shape.main) return error.InvalidGlobalGeometry;
        var semantic: [G.P.count]O = @splat(O.zero());
        semantic[G.P.source_public + G.Source.Public.sponge_first_id] = O.fromBase(M.fromCanonical(item.sponge_first_id));
        semantic[G.P.ram] = shared.ram.offset;
        @memcpy(semantic[G.P.ram + 1 ..][0..shared.ram.coefficients.len], &shared.ram.coefficients);
        semantic[G.P.kio] = shared.kio.offset;
        @memcpy(semantic[G.P.kio + 1 ..][0..shared.kio.coefficients.len], &shared.kio.coefficients);
        semantic[G.P.wire] = shared.wire.offset;
        @memcpy(semantic[G.P.wire + 1 ..][0..shared.wire.coefficients.len], &shared.wire.coefficients);
        const parameters = try a.alloc(O, e.artifact.parameter_slots.len);
        defer a.free(parameters);
        for (parameters, e.artifact.parameter_slots) |*value, slot| value.* = semantic[slot];
        var result = try self.generateRationalLocked(a, .{ .scope = scope, .log_size = item.log_size, .public_boundary = item.descriptor.origin == .core and (item.descriptor.origin.core == .initial or item.descriptor.origin.core == .terminal), .fixed = item.fixed, .main = item.main, .fixed_offset = item.fixed_offset, .parameters = parameters, .projection = e.launch, .groups = .{ e.artifact.ram_pairs, e.artifact.other_pairs }, .budget = budget });
        errdefer result.deinit();
        try result.validate(item);
        return result;
    }
    /// Shared concrete device pipeline. Callers obtain projection/groups and
    /// fresh parameters from their original CPU or truth constraint authority.
    /// This routine never selects a relation or invents a challenge/claim.
    pub fn generateRational(self: *Context, a: std.mem.Allocator, request: Request) !DG.Witness {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.generateRationalLocked(a, request);
    }
    fn generateRationalLocked(self: *Context, a: std.mem.Allocator, request: Request) !DG.Witness {
        const log = request.log_size;
        if (log >= self.twiddles.len or log < 5 or log > (if (request.public_boundary) @as(u32, DG.MAX_PUBLIC_BOUNDARY_LOG) else @as(u32, 22)) or request.fixed.len == 0 or request.main.len == 0 or request.parameters.len == 0 or request.parameters.len > 65536 or request.groups[0] == 0 or request.groups[0] > 640 or request.groups[1] > 640) return error.InvalidGlobalGeometry;
        if (request.layout == .cumulative_batches and self.cumulative == null) return error.MissingResidentCumulativeCapability;
        for (request.fixed) |column| if (column.log_size != log) {
            return error.InvalidGlobalGeometry;
        };
        for (request.main) |column| if (column.log_size != log or column.device == null or column.coefficients.len != 0) {
            return error.ResidentGlobalMainRequired;
        };
        for (request.parameters) |parameter| for (parameter.toM31Array()) |word| if (word.v >= core.fields.m31.Modulus) {
            return error.NoncanonicalGlobalParameter;
        };
        const rows = @as(usize, 1) << @intCast(log);
        const groups: usize = 1 + @as(usize, @intFromBool(request.groups[1] != 0));
        if (@as(u8, request.zero_claim_groups) >= (@as(u8, 1) << @intCast(groups))) return error.InvalidGlobalClaimPolicy;
        const pairs = @as(usize, request.groups[0]) + request.groups[1];
        const physical_width = 8 * (pairs + groups);
        const width = if (request.layout == .inverse_prefix) physical_width else 8 * pairs;
        const prefix = try Prefix.Plan.init(log);
        var admitted_words = try std.math.mul(usize, physical_width + request.fixed.len + request.main.len + 8 * pairs, rows);
        admitted_words = try std.math.add(usize, admitted_words, rows + prefix.scratch_words + 17 + request.parameters.len * 8);
        if (try std.math.mul(usize, admitted_words, 4) > request.budget) return error.WideCpuGlobalBudget;
        const owner = try a.create(Owner);
        errdefer a.destroy(owner);
        const columns = try a.alloc(D.TraceColumn, width);
        errdefer a.free(columns);
        const claims = try a.alloc(O, groups);
        errdefer a.free(claims);
        owner.* = .{ .allocator = a, .service = self.service, .columns = columns, .claims = claims };
        errdefer if (owner.output.words != null) {
            _ = self.service.submit(self.service.session, Owner.releaseDevice, owner);
        };
        if (self.twiddles[log] == null) self.twiddles[log] = try engine.poly.twiddles.precomputeM31(std.heap.page_allocator, core.poly.circle.canonic.CanonicCoset.new(log).circleDomain().half_coset);
        var job = Job{ .backend = self, .scope = request.scope, .request = request, .owner = owner };
        const status = self.service.submit(self.service.session, Job.callback, &job);
        if (job.failure) |err| return err;
        try checked(status);
        return .{ .columns = columns, .claims = claims, .owner = owner, .release_fn = Owner.release };
    }
};
const Owner = struct {
    allocator: std.mem.Allocator,
    service: *Service.Context,
    output: Native.Lease = .{},
    columns: []D.TraceColumn,
    claims: []O,
    fn releaseDevice(_: *anyopaque, _: u64, raw: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(raw.?));
        return self.service.lease_release(self.service.session, &self.output);
    }
    fn release(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        _ = self.service.submit(self.service.session, releaseDevice, self);
        self.allocator.free(self.columns);
        self.allocator.free(self.claims);
        self.allocator.destroy(self);
    }
};
const Job = struct {
    backend: *Context,
    scope: D.Scope,
    request: Request,
    owner: *Owner,
    failure: ?anyerror = null,
    fn callback(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Job = @ptrCast(@alignCast(data.?));
        self.run(raw, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn copySegment(self: *Job, ctx: *SC.Context, destination: [*]u32, segment: CopyRun) !void {
        const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
        const slice = Slice{ .address = segment.source, .len = segment.words, .owner = std.math.cast(usize, segment.context_token) orelse return error.SizeOverflow, .generation = segment.generation };
        // One native registry check covers the complete adjacent range under
        // the exact worker scope; no unchecked address-based coalescing.
        const from = try ctx.deviceSlicePointer(u32, slice, segment.words);
        try checked(self.backend.copy(ctx.native_context, @ptrCast(destination + segment.target_word), from, try std.math.mul(usize, segment.words, 4)));
    }
    fn run(self: *Job, raw: *anyopaque, token: u64) !void {
        const b = self.backend;
        const a = self.owner.allocator;
        const rows = @as(usize, 1) << @intCast(self.request.log_size);
        var ctx = SC.Context{ .session = b.service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(self.scope), .api = &b.api };
        var temporary: std.ArrayList(Native.Lease) = .empty;
        defer {
            ctx.join() catch {};
            b.service.releaseImmutableScope(ctx.scope) catch {};
            for (temporary.items) |*lease| ctx.release(lease) catch {};
            temporary.deinit(a);
        }
        const source_words = try std.math.mul(usize, self.request.fixed.len + self.request.main.len, rows);
        const source = try ctx.allocate(source_words, 0);
        try temporary.append(a, source);
        var ingress_timer: ?std.time.Timer = if (b.profile_ingress) try std.time.Timer.start() else null;
        var copies: usize = 0;
        var pending: ?CopyRun = null;
        var offset: usize = 0;
        inline for (.{ self.request.fixed, self.request.main }, 0..) |columns, tree| for (columns) |column| {
            if (column.log_size != self.request.log_size) return error.InvalidGlobalGeometry;
            const device: D.DeviceCoefficients = if (column.device) |resident| blk: {
                if (resident.count != rows or column.coefficients.len != 0) return error.InvalidDeviceTraceColumn;
                break :blk resident;
            } else blk: {
                if (tree != 0 or column.coefficients.len != rows) return error.ResidentGlobalMainRequired;
                if (try b.service.immutableFixedColumn(self.scope, self.request.fixed_offset + offset / rows, column)) |resident| break :blk resident;
                const key = immutableIdentity("rv64/global/fixed-column/v1\x00", self.scope.fixed, self.request.fixed_offset + offset / rows, self.request.log_size);
                const fixed = try b.service.immutableWords(raw, ctx.scope, key, @as([*]const u32, @ptrCast(column.coefficients.ptr))[0..rows]);
                break :blk .{ .words = fixed.words.?, .count = fixed.count, .context_token = fixed.context_token, .generation = fixed.generation };
            };
            const next = try CopyRun.init(@intFromPtr(device.words), offset, rows, device.context_token, device.generation);
            if (pending) |*segment| {
                if (!try segment.append(next)) {
                    try self.copySegment(&ctx, source.words.?, segment.*);
                    copies += 1;
                    pending = next;
                }
            } else pending = next;
            offset += rows;
        };
        if (pending) |segment| {
            try self.copySegment(&ctx, source.words.?, segment);
            copies += 1;
        }
        const tw = &b.twiddles[self.request.log_size].?;
        const twiddle_key = immutableIdentity("rv64/canonic-forward-m31-twiddles/v1\x00", @splat(0), 0, self.request.log_size);
        const twiddle = try b.service.immutableWords(raw, ctx.scope, twiddle_key, @as([*]const u32, @ptrCast(tw.twiddles.ptr))[0..tw.twiddles.len]);
        const parameters = self.request.parameters;
        const parameter = try ctx.allocate(parameters.len * 8, 0);
        try temporary.append(a, parameter);
        try ctx.upload(try ctx.borrow(parameter), @as([*]const u32, @ptrCast(parameters.ptr))[0 .. parameters.len * 8]);
        // All host staging survives the ingress join, including parameters.
        try ctx.join();
        if (ingress_timer) |*timer| std.debug.print("GPU_GLOBAL_INGRESS ordinal={} log={} source_columns={} source_words={} device_copy_calls={} joined_wall_ns={}\n", .{ self.scope.ordinal, self.request.log_size, self.request.fixed.len + self.request.main.len, source_words, copies, timer.read() });
        var stream: ?*anyopaque = null;
        try checked(b.api.lane_stream(raw, 1, &stream));
        const lane = stream orelse return error.InvalidLane;
        var launches: u32 = 0;
        const tw_count = @as(u32, 1) << @intCast(self.request.log_size - 1);
        try checked(b.n2b(source.words.?, rows, self.request.log_size, @intCast(self.request.fixed.len + self.request.main.len), twiddle.words.? + tw.twiddles.len - tw_count, tw_count, tw_count, lane, &launches));
        const groups = self.request.groups;
        const pairs = @as(usize, groups[0]) + groups[1];
        const width = 8 * (pairs + self.owner.claims.len);
        self.owner.output = try ctx.allocate(width * rows, 0);
        const numerator = try ctx.allocate(pairs * 8 * rows, 0);
        try temporary.append(a, numerator);
        const scan = try Prefix.Plan.init(self.request.log_size);
        const scratch = try ctx.allocate(scan.scratch_words + 8 * self.owner.claims.len + 1, 0);
        try temporary.append(a, scratch);
        const claim = scratch.words.? + scan.scratch_words;
        const status = claim + 8 * self.owner.claims.len;
        const verdict_zero = [_]u32{0};
        try ctx.upload(try (try ctx.borrow(scratch)).sub(scratch.count - 1, 1), &verdict_zero);
        try ctx.join();
        try checked(self.request.projection(raw, 1, source.words.?, source.words.? + self.request.fixed.len * rows, parameter.words.?, numerator.words.?, self.owner.output.words.?, status, self.request.log_size));
        var group_offset: usize = 0;
        var pair_offset: usize = 0;
        for (groups, 0..) |count, group| {
            if (count == 0) continue;
            const job = Abi.GlobalPairs{ .output = self.owner.output.words.? + group_offset * rows, .contributions = numerator.words.? + pair_offset * 8 * rows, .scan_scratch = scratch.words.?, .claim = claim + group * 8, .status = status, .stride = rows, .scan_words = scan.scratch_words, .row_log = self.request.log_size, .pairs = count };
            try checked(b.pairs(raw, 1, &job));
            if (self.request.layout == .cumulative_batches) {
                const cumulative = Cumulative{ .output = job.output, .contributions = job.contributions, .stride = rows, .row_log = self.request.log_size, .pairs = count };
                try checked(b.cumulative.?(raw, 1, &cumulative));
            }
            group_offset += 8 * (count + 1);
            pair_offset += count;
        }
        // Producer publishes only the tiny claims and verdict. No witness D2H.
        try ctx.join();
        try ctx.download(try (try ctx.borrow(scratch)).sub(scan.scratch_words, 8 * self.owner.claims.len), @as([*]u32, @ptrCast(self.owner.claims.ptr))[0 .. 8 * self.owner.claims.len]);
        var verdict: [1]u32 = undefined;
        try ctx.download(try (try ctx.borrow(scratch)).sub(scratch.count - 1, 1), &verdict);
        try ctx.join();
        if (verdict[0] != 0) return error.CudaGlobalWitnessRejected;
        for (self.owner.claims, 0..) |claim_value, i| {
            for (claim_value.toM31Array()) |word| if (word.v >= core.fields.m31.Modulus) {
                return error.NoncanonicalWideCpuClaim;
            };
            if ((self.request.zero_claim_groups & (@as(u2, 1) << @intCast(i))) != 0 and !claim_value.isZero()) return error.NonzeroLocalTruthClaim;
        }
        var physical_column: usize = 0;
        var column_index: usize = 0;
        for (groups) |count| {
            if (count == 0) continue;
            const published = 8 * (@as(usize, count) + @as(usize, @intFromBool(self.request.layout == .inverse_prefix)));
            for (self.owner.columns[column_index..][0..published], 0..) |*column, i| column.* = .{ .log_size = self.request.log_size, .encoding = .evaluations, .device = .{ .words = self.owner.output.words.? + (physical_column + i) * rows, .count = rows, .context_token = self.owner.output.context_token, .generation = self.owner.output.generation } };
            column_index += published;
            physical_column += 8 * (@as(usize, count) + 1);
        }
    }
};
test "resident global witness callback is concrete" {
    std.testing.refAllDecls(Context);
}

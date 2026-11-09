//! Explicit detached-source native runtime. Independent source reconstruction,
//! typed two-phase manifest and whole-execution closure; no production selector.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const Request = @import("../../rv64_ethereum_request.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Program = @import("../../word16_execution/program.zig").Program;
const R = @import("../../word16_global_execution/services/roster.zig");
const P = @import("../../word16_global_execution/services/protocol.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const W = @import("../../word16_global_execution/services/wire.zig");
const Bounds = @import("../../word16_global_execution/services/gkr_local/source_bounds.zig");
const Expected = @import("../../word16_global_execution/ethereum/receiver.zig");
const Terminal = @import("../../word16_global_execution/ethereum/terminal.zig");
const Cells = @import("../../word16_execution/cells_wire.zig");
const MetadataCache = @import("../../word16_execution/program_metadata.zig");
const Old = @import("../pure_p2_op_runtime.zig");
const CapturePlan = @import("../pure_p2_op_capture_plan.zig");
const I = @import("inventory.zig");
const CKey = @import("key.zig").Key;
const DKey = @import("../sponge_local_gkr/key.zig").Key;
const DG = @import("../sponge_local_gkr/authority.zig").Geometry;
const Frame = @import("frame.zig");
const Security = @import("security.zig");
const Execution = @import("execution.zig");
const Codec = @import("wire.zig");
const NativeReceiver = @import("receiver.zig");
const Store = @import("../pure_p2_retained_main.zig").Store;
const Profile = @import("../pure_p2_worker_protocol.zig").Profile;
pub const Resources = Old.Resources;
pub const Metadata = struct {
    schema: u32 = 1,
    format: []const u8 = "op-detached-sponge-native/v1",
    profile: Profile,
    cpus: []const W.CpuDeclaration,
    requests: []const W.CompactRequest,
    spans: []const T.OpTowerSpan,
    frontier_logs: []const u32,
    detached: []const DG,
    truths: []const W.TruthDeclaration,
    miller: []const Bounds.OpTowerTruthDeclaration,
    memory_words: u32,
    pub fn validate(self: Metadata) !void {
        const n = self.cpus.len;
        if (self.schema != 1 or !std.mem.eql(u8, self.format, "op-detached-sponge-native/v1") or self.profile == .reference_b2_q24_p0 or n == 0 or n > 256 or n != self.requests.len or n != self.spans.len or n != self.frontier_logs.len or n + self.detached.len + self.truths.len + self.miller.len > 256 or self.memory_words >= 1 << 23) return error.DetachedRuntimeMetadata;
        for (self.cpus, self.frontier_logs, self.requests, 0..) |cpu, log, request, ordinal| {
            if (cpu.bridges.sponge.any()) return error.SpongeCpuRequiresDetachedSetup;
            try A.crypto.keccak_sponge.serialized.frontier.validatePublic(request.sponge.calls, log, request.epoch, @intCast(ordinal));
        }
        for (self.detached) |g| {
            if (!g.detached) return error.SpongeLocalScopeFlavor;
            _ = try g.instances();
        }
    }
    fn legacy(self: Metadata) Old.Metadata {
        return .{ .schema = 3, .profile = self.profile, .cpus = self.cpus, .requests = self.requests, .spans = self.spans, .truths = self.truths, .miller = self.miller, .memory_words = self.memory_words };
    }
};
/// Stable owner. No request image, expected state or transcript enters a key.
pub const Authority = struct {
    allocator: std.mem.Allocator,
    catalog: Old.Authority,
    metadata: MetadataCache.Cache,
    cpu: []I.Cpu,
    detached: []I.Detached,
    catalogs: []I.Catalog,
    setup_owners: std.ArrayList(*R.CpuSetup) = .empty,
    cpu_owners: std.ArrayList(*CKey) = .empty,
    detached_owners: std.ArrayList(*DKey) = .empty,
    bounds: Bounds.DetachedOpReport,
    pub fn deinit(self: *Authority) void {
        const a = self.allocator;
        for (self.detached_owners.items) |v| {
            v.deinit();
            a.destroy(v);
        }
        for (self.cpu_owners.items) |v| {
            v.deinit();
            a.destroy(v);
        }
        for (self.setup_owners.items) |v| {
            v.deinit();
            a.destroy(v);
        }
        self.detached_owners.deinit(a);
        self.cpu_owners.deinit(a);
        self.setup_owners.deinit(a);
        a.free(self.cpu);
        a.free(self.detached);
        a.free(self.catalogs);
        self.metadata.deinit();
        self.catalog.deinit();
        self.bounds.deinit();
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, image: *const Image.Owner, program_log: u32, m: Metadata, requests: []const P.Request, resident: bool, resources: Resources) !Authority {
        try m.validate();
        if (requests.len != m.cpus.len) return error.DetachedRuntimeMetadata;
        // Precise signed relation mass/source geometry admission BEFORE FIXED.
        var bounds = try Bounds.deriveForOpDetached(a, program_log, m.cpus, m.truths, requests, m.spans, m.miller, m.frontier_logs, m.detached);
        errdefer bounds.deinit();
        const MillerAuthority = @import("../miller_local_gkr/authority.zig");
        const miller_geometry = try a.alloc(MillerAuthority.Geometry, m.miller.len);
        defer a.free(miller_geometry);
        for (m.miller, miller_geometry) |d, *g| g.* = .{ .calls = d.calls, .first_id = d.first_id, .frontier_log = d.frontier_log, .arithmetic_log = d.arithmetic_log };
        _ = try Security.preflight(m.profile, &bounds, m.truths, miller_geometry);
        for (m.truths) |d| if (@import("../truth_local_gkr/security.zig").eligible(d)) {
            const plan = try @import("../truth_local_gkr/resource.zig").derive(d, m.profile.config());
            try plan.admit(.{ .live_bytes = resources.truth_live_bytes, .main_bytes = resources.truth_main_bytes, .interaction_bytes = resources.truth_interaction_bytes, .gkr_bytes = resources.gkr_bytes });
        };
        for (miller_geometry) |g| {
            const cost = try MillerAuthority.cost(g);
            if (cost.checkpoint_working_bytes > resources.gkr_bytes or cost.checkpoint_working_bytes > resources.truth_live_bytes) return error.DetachedRuntimeGkrBudget;
        }
        for (m.detached) |g| {
            var bytes: usize = 0;
            for (try g.instances()) |instance| bytes = try std.math.add(usize, bytes, try std.math.mul(usize, try instance.facts(), 52));
            if (bytes > resources.gkr_bytes or bytes > resources.truth_live_bytes) return error.DetachedRuntimeGkrBudget;
        }
        var catalog = try Old.Authority.initCatalog(a, image, m.legacy(), @import("../pure_p2_source_suite.zig").Suite.millerGkr());
        errdefer catalog.deinit();
        var metadata = try MetadataCache.Cache.init(a, 256 << 20);
        errdefer metadata.deinit();
        const cpus = try a.alloc(I.Cpu, m.cpus.len);
        errdefer a.free(cpus);
        const detached = try a.alloc(I.Detached, m.detached.len);
        errdefer a.free(detached);
        const catalogs = try a.alloc(I.Catalog, m.truths.len);
        errdefer a.free(catalogs);
        var self = Authority{ .allocator = a, .catalog = catalog, .metadata = metadata, .cpu = cpus, .detached = detached, .catalogs = catalogs, .bounds = bounds };
        errdefer {
            for (self.detached_owners.items) |v| {
                v.deinit();
                a.destroy(v);
            }
            for (self.cpu_owners.items) |v| {
                v.deinit();
                a.destroy(v);
            }
            for (self.setup_owners.items) |v| {
                v.deinit();
                a.destroy(v);
            }
            self.detached_owners.deinit(a);
            self.cpu_owners.deinit(a);
            self.setup_owners.deinit(a);
        }
        for (m.cpus, requests, m.spans, m.frontier_logs, cpus, 0..) |d, req, span, log, *cpu, ordinal| {
            var reused: ?usize = null;
            for (m.cpus[0..ordinal], m.frontier_logs[0..ordinal], 0..) |prior, prior_log, j| if (prior_log == log and std.meta.eql(prior, d)) {
                reused = j;
                break;
            };
            if (reused) |j| {
                cpu.* = .{ .setup = cpus[j].setup, .key = cpus[j].key, .request = req, .span = span };
                continue;
            }
            try self.setup_owners.ensureUnusedCapacity(a, 1);
            const setup = try a.create(R.CpuSetup);
            setup.* = @import("../pure_p2_op_source_setup.zig").init(a, image, d, &self.metadata) catch |err| {
                a.destroy(setup);
                return err;
            };
            self.setup_owners.appendAssumeCapacity(setup);
            try self.cpu_owners.ensureUnusedCapacity(a, 1);
            const key = try a.create(CKey);
            key.* = (if (resident) CKey.init(a, setup, m.profile, log) else CKey.initDigest(a, setup, m.profile, log)) catch |err| {
                a.destroy(key);
                return err;
            };
            self.cpu_owners.appendAssumeCapacity(key);
            try @import("../pure_p2_op_source_setup.zig").retireLegacy(a, setup);
            cpu.* = .{ .setup = setup, .key = key, .request = req, .span = span };
        }
        for (m.detached, detached) |g, *d| {
            try self.detached_owners.ensureUnusedCapacity(a, 1);
            const key = try a.create(DKey);
            key.* = (if (resident) DKey.init(a, m.profile, g) else DKey.initDigest(a, m.profile, g)) catch |err| {
                a.destroy(key);
                return err;
            };
            self.detached_owners.appendAssumeCapacity(key);
            d.* = .{ .key = key, .geometry = g };
        }
        for (catalogs, self.catalog.native_truth.truths, self.catalog.truth_keys, self.catalog.truth_local_keys) |*out, truth, key, local| out.* = .{ .truth = truth, .key = key, .local_key = local };
        return self;
    }
    pub fn inventory(self: *Authority, profile: Profile, expected: P.Expected) !I.Inventory {
        return I.Inventory.init(self.allocator, profile, self.cpu, self.detached, self.catalogs, self.catalog.miller, expected);
    }
    pub fn checked(self: *Authority, profile: Profile, inv: *const I.Inventory, m: Metadata) !Security.Checked {
        const instances = try self.allocator.alloc([]const Frame.Instance, inv.rosters.len);
        defer self.allocator.free(instances);
        for (instances, inv.rosters) |*out, roster| out.* = roster.instances;
        const miller = try self.allocator.alloc(@import("../miller_local_gkr/authority.zig").Geometry, self.catalog.miller.len);
        defer self.allocator.free(miller);
        for (self.catalog.miller, miller) |source, *g| g.* = try (source.local_key orelse return error.OpMillerSourceSuitePolicy).geometry(source.span);
        return Security.check(profile, &self.bounds, instances, m.detached, m.truths, miller);
    }
};
fn ensureBudget(a: std.mem.Allocator, resources: Resources) !void {
    const owner = engine.host_budget_allocator.SharedHostBudget.fromAllocator(a) orelse return error.OpNativeRequiresSharedHostBudget;
    if (resources.live_bytes == 0 or owner.snapshot().limit > resources.live_bytes) return error.OpSourceBudgetMismatch;
}
pub fn produceDirectory(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources) !void {
    try ensureBudget(a, resources);
    var timer = try std.time.Timer.start();
    var capture = try CapturePlan.Owner.init(a, config, profile, .{ .local_truth = true, .truth_limits = .{ .live_bytes = resources.truth_live_bytes, .main_bytes = resources.truth_main_bytes, .interaction_bytes = resources.truth_interaction_bytes, .gkr_bytes = resources.gkr_bytes }, .detached_sponge = true, .extra_workers = 1 }, &timer);
    defer capture.deinit();
    const logs = try a.alloc(u32, capture.requests.len);
    defer a.free(logs);
    var calls: usize = 0;
    var perms: usize = 0;
    var words: usize = 0;
    for (capture.requests, logs, capture.captured.advice.sponge) |request, *log, source| {
        log.* = @max(5, std.math.log2_int_ceil(u32, request.sponge.calls + 1));
        calls = try std.math.add(usize, calls, request.sponge.calls);
        perms = try std.math.add(usize, perms, request.sponge.perms);
        words = try std.math.add(usize, words, source.words.len);
    }
    const geometries = try a.alloc(DG, @intFromBool(calls != 0));
    defer a.free(geometries);
    var direct: u32 = 0;
    for (capture.requests) |request| direct = try std.math.add(u32, direct, request.calls[0]);
    if (calls != 0) geometries[0] = .{ .calls = @intCast(calls), .permutations = @intCast(perms), .first_id = try std.math.add(u32, direct, 1), .detached = true };
    const metadata = Metadata{ .profile = profile, .cpus = capture.declarations, .requests = capture.compact, .spans = capture.spans, .frontier_logs = logs, .detached = geometries, .truths = capture.truths, .miller = capture.tower, .memory_words = @intCast(capture.captured.advice.initial.len) };
    const capture_done = timer.read();
    var authority = try Authority.init(a, capture.image, capture.program.log_size, metadata, capture.requests, true, resources);
    defer authority.deinit();
    const expected = try Expected.expectedFromRequests(capture.image, capture.program.identity, capture.requests, config.max_steps, config.batch_steps, true);
    var inventory = try authority.inventory(profile, expected);
    defer inventory.deinit();
    const security = try authority.checked(profile, &inventory, metadata);
    const flat_calls = try a.alloc(A.crypto.keccak_sponge.types.Call, calls);
    defer a.free(flat_calls);
    const flat_words = try a.alloc(A.memory.closed_ram.types.State, words);
    defer a.free(flat_words);
    var call_at: usize = 0;
    var word_at: usize = 0;
    var perm_at: u32 = 0;
    for (capture.captured.advice.sponge) |shard| {
        for (shard.calls) |call| {
            flat_calls[call_at] = call;
            flat_calls[call_at].first_word += @intCast(word_at);
            flat_calls[call_at].first_perm += perm_at;
            call_at += 1;
        }
        @memcpy(flat_words[word_at..][0..shard.words.len], shard.words);
        word_at += shard.words.len;
        perm_at += @intCast(shard.inputs.len);
    }
    try std.fs.cwd().makePath(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const parked = try std.fs.path.join(a, &.{ path, "parked-main" });
    defer a.free(parked);
    var store = try Store.init(a, parked, resources.disk_bytes, resources.mapped_bytes);
    defer store.deinit();
    const setup_done = timer.read();
    var bundle = try Execution.produce(a, &inventory, .{ .cpus = authority.cpu, .detached = authority.detached, .catalog = authority.catalogs, .towers = authority.catalog.miller, .native = capture.captured.native, .advice = &capture.captured.advice, .calls = flat_calls, .words = flat_words }, &store, .{ .cpu = .{ .gkr_bytes = resources.gkr_bytes, .global_bytes = resources.global_bytes }, .truth = .{ .live_bytes = resources.truth_live_bytes, .main_bytes = resources.truth_main_bytes, .interaction_bytes = resources.truth_interaction_bytes, .advice_bytes = resources.truth_advice_bytes }, .truth_gkr_bytes = resources.gkr_bytes, .detached_live_bytes = resources.truth_live_bytes, .detached_gkr_bytes = resources.gkr_bytes, .global_bytes = resources.global_bytes, .miller = .{ .live_bytes = resources.truth_live_bytes, .main_bytes = resources.truth_main_bytes, .interaction_bytes = resources.truth_interaction_bytes, .advice_bytes = resources.truth_advice_bytes }, .miller_gkr_bytes = resources.gkr_bytes });
    defer bundle.deinit(a);
    const prove_done = timer.read();
    const bytes = try Codec.encode(a, bundle, .{ .bytes = resources.bundle_bytes, .proof_bytes = resources.proof_bytes });
    defer a.free(bytes);
    try dir.writeFile(.{ .sub_path = "detached-op.bin", .data = bytes });
    try @import("../../word16_execution/driver.zig").writeJson(a, dir, "detached-op.json", metadata);
    try Cells.write(dir, capture.captured.advice.initial, capture.captured.advice.terminal);
    const output = try Terminal.require(capture.image, capture.requests[capture.requests.len - 1].base.cpu, capture.captured.advice.terminal);
    try @import("../../word16_execution/driver.zig").writeJson(a, dir, "detached-op-timing.json", .{ .steps = capture.captured.steps, .output = output, .security = security, .cpu = authority.cpu.len, .detached = authority.detached.len, .truth = authority.catalogs.len, .total_ns = timer.read(), .capture_and_plan_ns = capture_done, .setup_ns = setup_done - capture_done, .prove_ns = prove_done - setup_done, .native_bytes = bytes.len, .production_admission = false });
}

/// Borrowed source authority only. The output is public and unauthenticated
/// until all native proofs/global closure (or the consumer's root proof) pass.
pub const SourceDirectory = struct {
    image: *const Image.Owner,
    metadata: Metadata,
    requests: []const P.Request,
    authority: *Authority,
    inventory: *const I.Inventory,
    expected: P.Expected,
    output: [43]u8,
    cells: Cells.Owned,
    security: Security.Checked,
};
pub fn withSourceDirectory(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, context: ?*anyopaque, callback: *const fn (?*anyopaque, std.mem.Allocator, SourceDirectory) anyerror!void) !void {
    try ensureBudget(a, resources);
    try Request.validateBudgetForOp(config);
    var image = try Image.Owner.initForOp(a, config);
    defer image.deinit();
    var program = try Program.initWithAuthority(a, &image.authority);
    defer program.deinit();
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const raw = try dir.readFileAlloc(a, "detached-op.json", 4 << 20);
    defer a.free(raw);
    const parsed = try std.json.parseFromSlice(Metadata, a, raw, .{});
    defer parsed.deinit();
    const metadata = parsed.value;
    try metadata.validate();
    if (metadata.profile != profile) return error.InvalidOpNativeProfile;
    const compact = metadata.cpus[0].geometry.cpu_compact_decode;
    for (metadata.cpus) |cpu| if (cpu.geometry.cpu_compact_decode != compact) return error.MixedOpProgramRepresentations;
    if (compact) try program.makeCompact();
    const cells = try Cells.read(a, dir, metadata.memory_words);
    defer cells.deinit(a);
    const requests = try a.alloc(P.Request, metadata.requests.len);
    defer a.free(requests);
    for (metadata.requests, requests, 0..) |request, *out, i| out.* = request.expand(if (i == 0) cells.initial else &.{}, if (i + 1 == requests.len) cells.terminal else &.{});
    var authority = try Authority.init(a, &image, program.log_size, metadata, requests, false, resources);
    defer authority.deinit();
    const expected = try Expected.expectedFromRequests(&image, program.identity, requests, config.max_steps, config.batch_steps, true);
    var inventory = try authority.inventory(profile, expected);
    defer inventory.deinit();
    const security = try authority.checked(profile, &inventory, metadata);
    const output = try Terminal.require(&image, requests[requests.len - 1].base.cpu, cells.terminal);
    try callback(context, a, .{ .image = &image, .metadata = metadata, .requests = requests, .authority = &authority, .inventory = &inventory, .expected = expected, .output = output, .cells = cells, .security = security });
}
pub const ReceptionHooks = struct {
    fragments: NativeReceiver.Hooks = .{},
    context: ?*anyopaque = null,
    complete: ?*const fn (?*anyopaque, std.mem.Allocator, SourceDirectory, *const NativeReceiver.Closed) anyerror!void = null,
};
const Reception = struct {
    path: []const u8,
    resources: Resources,
    hooks: ReceptionHooks,
    fn run(raw: ?*anyopaque, a: std.mem.Allocator, source: SourceDirectory) !void {
        const self: *Reception = @ptrCast(@alignCast(raw.?));
        var dir = try std.fs.cwd().openDir(self.path, .{});
        defer dir.close();
        const bytes = try dir.readFileAlloc(a, "detached-op.bin", self.resources.bundle_bytes);
        defer a.free(bytes);
        var bundle = try Codec.decode(a, bytes, source.inventory.execution, source.inventory.workers.len, .{ .bytes = self.resources.bundle_bytes, .proof_bytes = self.resources.proof_bytes });
        defer bundle.deinit(a);
        var closed = try NativeReceiver.verifyWithHooks(a, source.inventory, source.authority.cpu, source.authority.detached, source.authority.catalogs, source.authority.catalog.miller, &bundle, self.hooks.fragments);
        defer closed.deinit(a);
        _ = try Terminal.require(source.image, source.requests[source.requests.len - 1].base.cpu, source.cells.terminal);
        if (self.hooks.complete) |callback| try callback(self.hooks.context, a, source, &closed);
        std.debug.print("OP_DETACHED_RECEIVER accepted=true complete=true CPU={} detached={} catalog={} bytes={} production_admission=false\n", .{ source.authority.cpu.len, source.authority.detached.len, source.authority.catalogs.len, bytes.len });
    }
};
pub fn verifyDirectory(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources) !void {
    return verifyDirectoryWithHooks(a, config, path, profile, resources, .{});
}
pub fn verifyDirectoryWithHooks(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, hooks: ReceptionHooks) !void {
    var reception = Reception{ .path = path, .resources = resources, .hooks = hooks };
    return withSourceDirectory(a, config, path, profile, resources, &reception, Reception.run);
}

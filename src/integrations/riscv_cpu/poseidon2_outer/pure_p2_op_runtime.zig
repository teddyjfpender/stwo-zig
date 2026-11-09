//! Explicit experimental OP pure-P2 native block route. No legacy protocol
//! selector is changed. Fresh reception reconstructs source keys from the pinned
//! image and validates the entire inventory before accepting native claims.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const engine = @import("stwo_prover_engine");
const Request = @import("../rv64_ethereum_request.zig");
const Image = @import("../word16_execution/expected_image.zig");
const Program = @import("../word16_execution/program.zig").Program;
const Capture = @import("pure_p2_op_capture.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const P = @import("../word16_global_execution/services/protocol.zig");
const T = @import("../word16_global_execution/services/types.zig");
const Wire = @import("../word16_global_execution/services/wire.zig");
const Bounds = @import("../word16_global_execution/services/gkr_local/source_bounds.zig");
const Coordinator = @import("../word16_global_execution/services/gkr_local/coordinator.zig");
const Plan = @import("../word16_global_execution/ethereum/plan.zig");
const Receiver = @import("../word16_global_execution/ethereum/receiver.zig");
const Terminal = @import("../word16_global_execution/ethereum/terminal.zig");
const ProgramMetadata = @import("../word16_execution/program_metadata.zig");
const Keys = @import("../word16_global_execution/ethereum/keys.zig");
const Key = @import("pure_p2_fixed_key.zig").Key;
const Truth = @import("pure_p2_truth_worker.zig");
const TruthLocal = @import("truth_local_gkr/worker.zig");
const TruthLocalSecurity = @import("pure_p2_truth_local_security.zig");
const Miller = @import("pure_p2_tower_worker.zig");
const SourceSuite = @import("pure_p2_source_suite.zig").Suite;
const SuiteSecurity = @import("pure_p2_source_suite_security.zig");
const MillerLocal = @import("miller_local_gkr/worker.zig");
const Inv = @import("pure_p2_op_inventory.zig");
const Bundle = @import("pure_p2_op_bundle.zig");
const Producer = @import("pure_p2_op_producer.zig");
const Store = @import("pure_p2_retained_main.zig").Store;
pub const SetupCache = @import("pure_p2_setup_cache.zig").Cache;
const Cells = @import("../word16_execution/cells_wire.zig");
const Profile = @import("pure_p2_worker_protocol.zig").Profile;
pub const Metadata = struct {
    schema: u32 = 1,
    profile: Profile,
    cpus: []const Wire.CpuDeclaration,
    requests: []const Wire.CompactRequest,
    spans: []const T.OpTowerSpan,
    truths: []const Wire.TruthDeclaration,
    miller: []const Bounds.OpTowerTruthDeclaration,
    memory_words: u32,
    fn validate(self: Metadata) !void {
        if ((self.schema != 1 and self.schema != 2 and self.schema != 3) or self.profile == .reference_b2_q24_p0 or self.cpus.len == 0 or self.cpus.len != self.requests.len or self.cpus.len != self.spans.len or self.cpus.len + self.truths.len + self.miller.len > 256 or self.memory_words >= 1 << 23) return error.InvalidOpNativeMetadata;
    }
};
/// Version3 has an explicit suite; legacy metadata has no added nullable field.
const Metadata3 = struct {
    schema: u32 = 3,
    suite: SourceSuite,
    profile: Profile,
    cpus: []const Wire.CpuDeclaration,
    requests: []const Wire.CompactRequest,
    spans: []const T.OpTowerSpan,
    truths: []const Wire.TruthDeclaration,
    miller: []const Bounds.OpTowerTruthDeclaration,
    memory_words: u32,
    fn from(m: Metadata, suite: SourceSuite) Metadata3 {
        return .{ .suite = suite, .profile = m.profile, .cpus = m.cpus, .requests = m.requests, .spans = m.spans, .truths = m.truths, .miller = m.miller, .memory_words = m.memory_words };
    }
    fn plain(self: Metadata3) Metadata {
        return .{ .schema = self.schema, .profile = self.profile, .cpus = self.cpus, .requests = self.requests, .spans = self.spans, .truths = self.truths, .miller = self.miller, .memory_words = self.memory_words };
    }
};
const ParsedMetadata = struct {
    legacy: ?std.json.Parsed(Metadata) = null,
    selected: ?std.json.Parsed(Metadata3) = null,
    value: Metadata,
    suite: ?SourceSuite = null,
    fn deinit(self: *ParsedMetadata) void {
        if (self.legacy) |parsed| parsed.deinit();
        if (self.selected) |parsed| parsed.deinit();
        self.* = undefined;
    }
};
fn effectiveTruth(schema: u32, suite: ?SourceSuite) bool {
    return if (suite) |value| value.truth == .local_gkr else schema == 2;
}
fn validateOptions(options: Options) !void {
    if (options.source_suite) |suite| {
        try suite.validate();
        if (options.truth_local_gkr) return error.AmbiguousOpSourceSuitePolicy;
    }
}
fn parseMetadata(a: std.mem.Allocator, json: []const u8, options: Options) !ParsedMetadata {
    try validateOptions(options);
    const probe = try std.json.parseFromSlice(struct { schema: u32 = 1 }, a, json, .{ .ignore_unknown_fields = true });
    defer probe.deinit();
    if (probe.value.schema == 3) {
        const expected_suite = options.source_suite orelse return error.OpSourceSuiteRequiresExplicitReceiver;
        const header = try std.json.parseFromSlice(struct { schema: u32, suite: SourceSuite }, a, json, .{ .ignore_unknown_fields = true });
        defer header.deinit();
        try header.value.suite.requireExpected(expected_suite);
        const parsed = try std.json.parseFromSlice(Metadata3, a, json, .{});
        errdefer parsed.deinit();
        try parsed.value.suite.requireExpected(options.source_suite);
        const m = parsed.value.plain();
        try m.validate();
        return .{ .selected = parsed, .value = m, .suite = parsed.value.suite };
    }
    if (options.source_suite != null) return error.OpSourceSuitePolicyMismatch;
    const parsed = try std.json.parseFromSlice(Metadata, a, json, .{});
    errdefer parsed.deinit();
    if (parsed.value.schema == 3) return error.InvalidOpNativeMetadata;
    try parsed.value.validate();
    if ((parsed.value.schema == 2) != options.truth_local_gkr) return error.OpNativeSchemaPolicy;
    return .{ .legacy = parsed, .value = parsed.value };
}
pub const Options = struct {
    cache: ?*SetupCache = null,
    /// Schema2 is an explicit protocol authority, never an implicit fallback.
    truth_local_gkr: bool = false,
    source_suite: ?SourceSuite = null,
};
pub const Resources = struct {
    /// Producer-only bounded inactive CPU advice parking; proof bytes unchanged.
    park_cpu_metadata: bool = false,
    retire_source_auxiliaries: bool = false,
    consume_memory_events: bool = true,
    live_bytes: usize = 32 << 30,
    disk_bytes: usize = 192 << 30,
    mapped_bytes: usize = 12 << 30,
    gkr_bytes: usize = 12 << 30,
    global_bytes: usize = 2 << 30,
    truth_live_bytes: usize = 8 << 30,
    truth_main_bytes: usize = 2 << 30,
    truth_interaction_bytes: usize = 4 << 30,
    truth_advice_bytes: usize = 256 << 20,
    proof_bytes: usize = 64 << 20,
    bundle_bytes: usize = 2 << 30,
};
pub const Authority = struct {
    allocator: std.mem.Allocator,
    native_truth: Keys.Owner,
    program_metadata: ProgramMetadata.Cache,
    setups: []*const R.CpuSetup,
    cpu_keys: []*const Key,
    truth_keys: []*const Truth.Key,
    truth_local_keys: []?*const TruthLocal.Key,
    miller: []Inv.MillerDeclaration,
    cpu_owners: std.ArrayList(*R.CpuSetup) = .empty,
    cpu_leases: std.ArrayList(@import("pure_p2_setup_cache.zig").Lease) = .empty,
    key_owners: std.ArrayList(*Key) = .empty,
    truth_owners: std.ArrayList(*Truth.Key) = .empty,
    truth_local_owners: std.ArrayList(*TruthLocal.Key) = .empty,
    miller_owners: std.ArrayList(*Miller.Key) = .empty,
    miller_local_owners: std.ArrayList(*MillerLocal.Key) = .empty,
    pub fn deinit(self: *Authority) void {
        const a = self.allocator;
        for (self.key_owners.items) |key| {
            key.deinit();
            a.destroy(key);
        }
        for (self.cpu_owners.items) |setup| {
            setup.deinit();
            a.destroy(setup);
        }
        for (self.truth_owners.items) |key| {
            key.deinit();
            a.destroy(key);
        }
        for (self.miller_local_owners.items) |key| {
            key.deinit();
            a.destroy(key);
        }
        self.miller_local_owners.deinit(a);
        for (self.miller_owners.items) |key| {
            key.deinit();
            a.destroy(key);
        }
        for (self.cpu_leases.items) |*lease| lease.deinit();
        self.cpu_leases.deinit(a);
        self.key_owners.deinit(a);
        self.cpu_owners.deinit(a);
        for (self.truth_local_owners.items) |key| {
            key.deinit();
            a.destroy(key);
        }
        self.truth_local_owners.deinit(a);
        self.truth_owners.deinit(a);
        self.miller_owners.deinit(a);
        a.free(self.setups);
        a.free(self.cpu_keys);
        a.free(self.truth_keys);
        a.free(self.truth_local_keys);
        a.free(self.miller);
        self.native_truth.deinit();
        self.program_metadata.deinit();
        self.* = undefined;
    }
    fn init(a: std.mem.Allocator, image: *const Image.Owner, m: Metadata, fixed_store: ?*Store, cache: ?*SetupCache, source_suite: ?SourceSuite) !Authority {
        return initMode(a, image, m, fixed_store, cache, source_suite, false);
    }
    /// Independently pinned catalog authority shared by the explicit detached
    /// runtime. CPU setup/key ownership belongs to that runtime, never to a
    /// producer-supplied key or an unused legacy CPU key.
    pub fn initCatalog(a: std.mem.Allocator, image: *const Image.Owner, m: Metadata, source_suite: ?SourceSuite) !Authority {
        return initMode(a, image, m, null, null, source_suite, true);
    }
    fn initMode(a: std.mem.Allocator, image: *const Image.Owner, m: Metadata, fixed_store: ?*Store, cache: ?*SetupCache, source_suite: ?SourceSuite, catalog_only: bool) !Authority {
        try m.validate();
        const cpu_declarations = if (catalog_only) m.cpus[0..0] else m.cpus;
        if ((m.schema == 3) != (source_suite != null)) return error.OpSourceSuitePolicyMismatch;
        if (source_suite) |suite| try suite.validate();
        const setups = try a.alloc(*const R.CpuSetup, cpu_declarations.len);
        errdefer a.free(setups);
        const cpu_keys = try a.alloc(*const Key, cpu_declarations.len);
        errdefer a.free(cpu_keys);
        const truth_keys = try a.alloc(*const Truth.Key, m.truths.len);
        errdefer a.free(truth_keys);
        const truth_local_keys = try a.alloc(?*const TruthLocal.Key, if (effectiveTruth(m.schema, source_suite)) m.truths.len else 0);
        errdefer a.free(truth_local_keys);
        @memset(truth_local_keys, null);
        const miller = try a.alloc(Inv.MillerDeclaration, m.miller.len);
        errdefer a.free(miller);
        var native_truth = try Keys.Owner.init(a, image, &.{}, m.truths);
        errdefer native_truth.deinit();
        var metadata = try ProgramMetadata.Cache.init(a, 256 << 20);
        errdefer metadata.deinit();
        var self = Authority{ .allocator = a, .native_truth = native_truth, .program_metadata = metadata, .setups = setups, .cpu_keys = cpu_keys, .truth_keys = truth_keys, .truth_local_keys = truth_local_keys, .miller = miller };
        // Child-owner cleanup only on error; outer arrays/native_truth retain
        // the preceding error guards until successful return.
        errdefer {
            for (self.key_owners.items) |k| {
                k.deinit();
                a.destroy(k);
            }
            for (self.cpu_owners.items) |s| {
                s.deinit();
                a.destroy(s);
            }
            for (self.truth_owners.items) |k| {
                k.deinit();
                a.destroy(k);
            }
            for (self.miller_local_owners.items) |k| {
                k.deinit();
                a.destroy(k);
            }
            self.miller_local_owners.deinit(a);
            for (self.miller_owners.items) |k| {
                k.deinit();
                a.destroy(k);
            }
            for (self.cpu_leases.items) |*lease| lease.deinit();
            self.cpu_leases.deinit(a);
            self.key_owners.deinit(a);
            self.cpu_owners.deinit(a);
            for (self.truth_local_owners.items) |key| {
                key.deinit();
                a.destroy(key);
            }
            self.truth_local_owners.deinit(a);
            self.truth_owners.deinit(a);
            self.miller_owners.deinit(a);
        }
        for (cpu_declarations, 0..) |d, i| {
            var reused = false;
            for (cpu_declarations[0..i], 0..) |prior, j| if (std.meta.eql(prior, d)) {
                setups[i] = setups[j];
                cpu_keys[i] = cpu_keys[j];
                reused = true;
                break;
            };
            if (reused) continue;
            if (cache) |owner| {
                try self.cpu_leases.ensureUnusedCapacity(a, 1);
                const lease = try owner.acquire(&image.authority, d.geometry, d.bridges, m.profile);
                setups[i] = lease.setup();
                cpu_keys[i] = lease.key();
                self.cpu_leases.appendAssumeCapacity(lease);
                continue;
            }
            try self.cpu_owners.ensureUnusedCapacity(a, 1);
            try self.key_owners.ensureUnusedCapacity(a, 1);
            const setup = try a.create(R.CpuSetup);
            setup.* = @import("pure_p2_op_source_setup.zig").init(a, image, d, &self.program_metadata) catch |err| {
                a.destroy(setup);
                return err;
            };
            self.cpu_owners.appendAssumeCapacity(setup);
            setups[i] = setup;
            const key = try a.create(Key);
            key.* = (if (fixed_store) |store| Key.initForOpParked(a, setup, m.profile, store) else Key.initForOpDigest(a, setup, m.profile)) catch |err| {
                a.destroy(key);
                return err;
            };
            self.key_owners.appendAssumeCapacity(key);
            cpu_keys[i] = key;
            try key.retireLegacySetup(setup);
        }
        for (self.native_truth.truths, 0..) |truth, i| {
            if (effectiveTruth(m.schema, source_suite) and (truth == .keccak or truth == .secp)) {
                var found: ?*TruthLocal.Key = null;
                for (self.truth_local_owners.items) |key| {
                    key.require(truth) catch continue;
                    found = key;
                    break;
                }
                if (found == null) {
                    try self.truth_local_owners.ensureUnusedCapacity(a, 1);
                    const key = try a.create(TruthLocal.Key);
                    key.* = TruthLocal.Key.init(a, truth, m.profile) catch |err| {
                        a.destroy(key);
                        return err;
                    };
                    self.truth_local_owners.appendAssumeCapacity(key);
                    found = key;
                }
                truth_local_keys[i] = found.?;
                // The base is source/geometry authority only. Expected worker
                // identity and statement always come from the local key.
                truth_keys[i] = &found.?.base;
                continue;
            }
            var reused = false;
            for (self.truth_owners.items) |key| {
                key.require(truth) catch continue;
                truth_keys[i] = key;
                reused = true;
                break;
            }
            if (reused) continue;
            try self.truth_owners.ensureUnusedCapacity(a, 1);
            const key = try a.create(Truth.Key);
            key.* = Truth.Key.init(a, truth, m.profile) catch |err| {
                a.destroy(key);
                return err;
            };
            self.truth_owners.appendAssumeCapacity(key);
            truth_keys[i] = key;
        }
        for (m.miller, miller) |d, *out| {
            if (source_suite) |suite| if (suite.miller == .local_gkr) {
                var found: ?*MillerLocal.Key = null;
                for (self.miller_local_owners.items) |key| if (key.base.frontier_log == d.frontier_log and key.base.arithmetic_log == d.arithmetic_log) {
                    found = key;
                    break;
                };
                if (found == null) {
                    try self.miller_local_owners.ensureUnusedCapacity(a, 1);
                    const key = try a.create(MillerLocal.Key);
                    key.* = MillerLocal.Key.init(a, m.profile, d.frontier_log, d.arithmetic_log) catch |err| {
                        a.destroy(key);
                        return err;
                    };
                    self.miller_local_owners.appendAssumeCapacity(key);
                    found = key;
                }
                out.* = .{ .key = &found.?.base, .local_key = found.?, .span = .{ .calls = d.calls, .first_id = d.first_id } };
                continue;
            };

            var found: ?*Miller.Key = null;
            for (self.miller_owners.items) |key| if (key.frontier_log == d.frontier_log and key.arithmetic_log == d.arithmetic_log) {
                found = key;
                break;
            };
            if (found == null) {
                try self.miller_owners.ensureUnusedCapacity(a, 1);
                const key = try a.create(Miller.Key);
                key.* = Miller.Key.init(a, m.profile, d.frontier_log, d.arithmetic_log) catch |err| {
                    a.destroy(key);
                    return err;
                };
                self.miller_owners.appendAssumeCapacity(key);
                found = key;
            }
            out.* = .{ .key = found.?, .span = .{ .calls = d.calls, .first_id = d.first_id } };
        }
        return self;
    }
};
fn requests(a: std.mem.Allocator, m: Metadata, cells: Cells.Owned) ![]P.Request {
    const out = try a.alloc(P.Request, m.requests.len);
    for (m.requests, out, 0..) |r, *v, i| v.* = r.expand(if (i == 0) cells.initial else &.{}, if (i + 1 == out.len) cells.terminal else &.{});
    return out;
}
/// Borrowed only during complete(): all native proofs and zero-sum relations
/// plus independently pinned terminal output have passed before this callback.
pub const CompleteVerified = struct {
    source_suite: ?SourceSuite = null,
    source_security: ?SuiteSecurity.Checked = null,
    image: *const Image.Owner,
    metadata: Metadata,
    requests: []const P.Request,
    expected: P.Expected,
    cpu_keys: []const *const Key,
    truth_keys: []const *const Truth.Key,
    truth_local_keys: []const ?*const TruthLocal.Key = &.{},
    truth_local_security: ?TruthLocalSecurity.Checked = null,
    output_address: u64,
    setups: []const *const R.CpuSetup,
    truths: []const R.Truth,
    miller: []const Inv.MillerDeclaration,
    inventory: *const Inv.Inventory,
    native: *const Bundle.Closed,
    output: [43]u8,
};
pub const ReceptionHooks = struct {
    fragments: Bundle.Hooks = .{},
    context: ?*anyopaque = null,
    complete: ?*const fn (?*anyopaque, std.mem.Allocator, CompleteVerified) anyerror!void = null,
};
/// Receiver: metadata selects cost only. Bounds are checked before constructing
/// any wide source key; the independent config pins software/input/terminal.
pub fn verifyDirectory(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources) !void {
    return verifyDirectoryWithHooks(a, config, path, profile, resources, .{});
}
pub const SourceDirectory = struct {
    source_suite: ?SourceSuite = null,
    source_security: ?SuiteSecurity.Checked = null,
    /// Borrowed source-policy authority only. Public cells/output are NOT
    /// authenticated execution until the consumer verifies its root/proofs.
    image: *const Image.Owner,
    metadata: Metadata,
    requests: []const P.Request,
    setups: []const *const R.CpuSetup,
    cpu_keys: []const *const Key,
    truths: []const R.Truth,
    truth_keys: []const *const Truth.Key,
    truth_local_keys: []const ?*const TruthLocal.Key = &.{},
    truth_local_security: ?TruthLocalSecurity.Checked = null,
    miller: []const Inv.MillerDeclaration,
    inventory: *const Inv.Inventory,
    expected: P.Expected,
    output: [43]u8,
    output_address: u64,
    initial: []const @import("../word16_execution/memory/statement.zig").Cell,
    terminal: []const @import("../word16_execution/memory/statement.zig").Cell,
    image_ns: u64,
    program_ns: u64,
};
/// Shared bounded source admission, NEVER reads native-op.bin or verifies
/// native PCS/GKR. The callback must verify its own root/proofs before treating
/// public cells as authenticated. No borrowed pointer may outlive callback.
pub fn withSourceDirectory(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, context: ?*anyopaque, callback: *const fn (?*anyopaque, std.mem.Allocator, SourceDirectory) anyerror!void) !void {
    return withSourceDirectoryWithCache(a, config, path, profile, resources, null, context, callback);
}
pub fn withSourceDirectoryWithCache(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, cache: ?*SetupCache, context: ?*anyopaque, callback: *const fn (?*anyopaque, std.mem.Allocator, SourceDirectory) anyerror!void) !void {
    return withSourceDirectoryWithOptions(a, config, path, profile, resources, .{ .cache = cache }, context, callback);
}
pub fn withSourceDirectoryWithOptions(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, options: Options, context: ?*anyopaque, callback: *const fn (?*anyopaque, std.mem.Allocator, SourceDirectory) anyerror!void) !void {
    const cache = options.cache;
    var session = if (cache) |owner| try owner.enterRequest(a, resources.disk_bytes, resources.mapped_bytes) else null;
    defer if (session) |*lease| lease.deinit();
    if (!engine.host_budget_allocator.SharedHostBudget.isAllocator(a)) return error.OpNativeRequiresSharedHostBudget;
    const budget = engine.host_budget_allocator.SharedHostBudget.fromAllocator(a).?;
    if (resources.live_bytes == 0 or budget.snapshot().limit > resources.live_bytes) return error.OpSourceBudgetMismatch;
    try Request.validateBudgetForOp(config);
    var timer = try std.time.Timer.start();
    var image = try Image.Owner.initForOp(a, config);
    defer image.deinit();
    const image_ns = timer.read();
    var program = try Program.initWithAuthority(a, &image.authority);
    defer program.deinit();
    const program_ns = timer.read() - image_ns;
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const json = try dir.readFileAlloc(a, "native-op.json", 4 << 20);
    defer a.free(json);
    var parsed = try parseMetadata(a, json, options);
    defer parsed.deinit();
    const m = parsed.value;
    const source_suite = parsed.suite;
    if (m.profile != profile) return error.InvalidOpNativeProfile;
    const compact = m.cpus[0].geometry.cpu_compact_decode;
    for (m.cpus) |cpu| if (cpu.geometry.cpu_compact_decode != compact) return error.MixedOpProgramRepresentations;
    if (compact) try program.makeCompact();
    const cells = try Cells.read(a, dir, m.memory_words);
    defer cells.deinit(a);
    const req = try requests(a, m, cells);
    defer a.free(req);
    var bounds = try Bounds.deriveForOp(a, program.log_size, m.cpus, m.truths, req, m.spans, m.miller);
    defer bounds.deinit();
    const source_security = if (source_suite) |suite| try SuiteSecurity.check(profile, &bounds, m.truths, m.miller, suite) else null;
    const truth_local_security = if (effectiveTruth(m.schema, source_suite)) (if (source_security) |checked| checked.truth else try TruthLocalSecurity.check(profile, &bounds, m.truths)) else null;
    var authority = try Authority.init(a, &image, m, null, cache, source_suite);
    defer authority.deinit();
    const expected = try Receiver.expectedFromRequests(&image, program.identity, req, config.max_steps, config.batch_steps, true);
    var inventory = try Inv.Inventory.initForSourceSuite(a, profile, authority.setups, req, m.spans, authority.cpu_keys, authority.native_truth.truths, authority.truth_keys, authority.miller, expected, authority.truth_local_keys, source_suite);
    defer inventory.deinit();
    if (source_suite == null) if (truth_local_security) |checked| {
        checked.added.augmentShape(&inventory.bounds.base.shape);
        try inventory.bounds.base.shape.validate();
    };
    const output = try Terminal.require(&image, req[req.len - 1].base.cpu, cells.terminal);
    try callback(context, a, .{ .source_suite = source_suite, .source_security = source_security, .image = &image, .metadata = m, .requests = req, .setups = authority.setups, .cpu_keys = authority.cpu_keys, .truths = authority.native_truth.truths, .truth_keys = authority.truth_keys, .truth_local_keys = authority.truth_local_keys, .truth_local_security = truth_local_security, .miller = authority.miller, .inventory = &inventory, .expected = expected, .output = output, .output_address = image.symbols.output_data, .initial = cells.initial, .terminal = cells.terminal, .image_ns = image_ns, .program_ns = program_ns });
}
const NativeReception = struct {
    path: []const u8,
    profile: Profile,
    resources: Resources,
    hooks: ReceptionHooks,
    timer: std.time.Timer,
    fn run(raw: ?*anyopaque, a: std.mem.Allocator, source: SourceDirectory) !void {
        const self: *NativeReception = @ptrCast(@alignCast(raw.?));
        var dir = try std.fs.cwd().openDir(self.path, .{});
        defer dir.close();
        const bytes = try dir.readFileAlloc(a, "native-op.bin", self.resources.bundle_bytes);
        defer a.free(bytes);
        var bundle = if (source.source_suite) |suite| try Bundle.decodeForSuite(a, bytes, source.inventory.workers.len, .{ .bytes = self.resources.bundle_bytes, .proof_bytes = self.resources.proof_bytes }, suite) else try Bundle.decode(a, bytes, source.inventory.workers.len, .{ .bytes = self.resources.bundle_bytes, .proof_bytes = self.resources.proof_bytes });
        defer bundle.deinit(a);
        const verify_start = self.timer.read();
        var closed = if (source.source_suite) |suite| try bundle.verifyWithHooksForSourceSuite(a, source.inventory, source.setups, source.requests, source.metadata.spans, source.cpu_keys, source.truths, source.truth_keys, source.miller, suite, self.hooks.fragments) else if (source.metadata.schema == 2) try bundle.verifyWithHooksForTruthLocal(a, source.inventory, source.setups, source.requests, source.metadata.spans, source.cpu_keys, source.truths, source.truth_keys, source.miller, self.hooks.fragments) else try bundle.verifyWithHooks(a, source.inventory, source.setups, source.requests, source.metadata.spans, source.cpu_keys, source.truths, source.truth_keys, source.miller, self.hooks.fragments);
        defer closed.deinit(a);
        // Recheck AFTER native physical/global verification and callbacks. The
        // source-only helper's earlier policy check authenticates no RAM.
        const output = try Terminal.require(source.image, source.requests[source.requests.len - 1].base.cpu, source.terminal);
        if (self.hooks.complete) |complete| try complete(self.hooks.context, a, .{ .source_suite = source.source_suite, .source_security = source.source_security, .image = source.image, .metadata = source.metadata, .requests = source.requests, .expected = source.expected, .cpu_keys = source.cpu_keys, .truth_keys = source.truth_keys, .truth_local_keys = source.truth_local_keys, .truth_local_security = source.truth_local_security, .output_address = source.output_address, .setups = source.setups, .truths = source.truths, .miller = source.miller, .inventory = source.inventory, .native = &closed, .output = output });
        std.debug.print("OP_NATIVE_RECEIVER accepted=true complete=true steps={} CPU={} truth={} miller={} profile={s} image_ns={} program_ns={} setup_and_decode_ns={} verify_ns={} total_ns={}\n", .{ source.expected.total_steps, source.setups.len, source.truths.len, source.miller.len, @tagName(self.profile), source.image_ns, source.program_ns, verify_start - source.image_ns - source.program_ns, self.timer.read() - verify_start, self.timer.read() });
    }
};
pub fn verifyDirectoryWithHooks(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, hooks: ReceptionHooks) !void {
    var context = NativeReception{ .path = path, .profile = profile, .resources = resources, .hooks = hooks, .timer = try std.time.Timer.start() };
    return withSourceDirectory(a, config, path, profile, resources, &context, NativeReception.run);
}

pub fn verifyDirectoryWithCache(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, cache: *SetupCache) !void {
    var context = NativeReception{ .path = path, .profile = profile, .resources = resources, .hooks = .{}, .timer = try std.time.Timer.start() };
    return withSourceDirectoryWithCache(a, config, path, profile, resources, cache, &context, NativeReception.run);
}
pub fn verifyDirectoryWithOptions(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, options: Options, hooks: ReceptionHooks) !void {
    var context = NativeReception{ .path = path, .profile = profile, .resources = resources, .hooks = hooks, .timer = try std.time.Timer.start() };
    return withSourceDirectoryWithOptions(a, config, path, profile, resources, options, &context, NativeReception.run);
}
pub fn produceDirectoryWithOptions(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, options: Options) !void {
    try validateOptions(options);
    return produceDirectoryMode(a, config, path, profile, resources, .prove, options.cache, options.truth_local_gkr, options.source_suite);
}
pub fn produceDirectory(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources) !void {
    return produceDirectoryMode(a, config, path, profile, resources, .prove, null, false, null);
}
pub fn produceDirectoryWithCache(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, cache: *SetupCache) !void {
    return produceDirectoryMode(a, config, path, profile, resources, .prove, cache, false, null);
}
pub fn prepareDirectoryWithCache(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, cache: *SetupCache) !void {
    return produceDirectoryMode(a, config, path, profile, resources, .prepare, cache, false, null);
}
pub const FixedRootRecord = struct {
    cpu_ordinal: usize,
    identity: [32]u8,
    geometry: [32]u8,
    poseidon_root: @import("pure_p2_worker_protocol.zig").W.H.Hash,
    legacy_blake_root: [32]u8,
};
fn fixedRootRecords(a: std.mem.Allocator, keys: []const *const Key) ![]FixedRootRecord {
    var records: std.ArrayList(FixedRootRecord) = .empty;
    errdefer records.deinit(a);
    for (keys, 0..) |key, ordinal| {
        var seen = false;
        for (records.items) |record| if (std.mem.eql(u8, &record.identity, &key.identity)) {
            seen = true;
            break;
        };
        if (!seen) try records.append(a, .{ .cpu_ordinal = ordinal, .identity = key.identity, .geometry = key.source_geometry, .poseidon_root = key.root, .legacy_blake_root = key.source_root });
    }
    return records.toOwnedSlice(a);
}
fn cellsDigest(cells: []const @import("../word16_execution/memory/statement.zig").Cell) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("opstack-pure-p2/canonical-public-cells/v1\x00");
    var count: [8]u8 = undefined;
    std.mem.writeInt(u64, &count, cells.len, .little);
    hash.update(&count);
    for (cells) |cell| {
        var bytes: [23]u8 = undefined;
        std.mem.writeInt(u64, bytes[0..8], cell.address, .little);
        std.mem.writeInt(u64, bytes[8..16], cell.state.value, .little);
        std.mem.writeInt(u16, bytes[16..18], cell.state.epoch, .little);
        std.mem.writeInt(u32, bytes[18..22], cell.state.tick, .little);
        bytes[22] = cell.state.rights;
        hash.update(&bytes);
    }
    return hash.finalResult();
}
/// Scalar-only diagnostics: geometry classes may share physical FIXED roots.
/// This never trusts producer roots or hashes/reconstructs any fixed witness.
pub fn fixedRootCounts(keys: []const *const Key) struct { poseidon: usize, legacy: usize } {
    return .{ .poseidon = uniqueFixedRoots(keys, "root"), .legacy = uniqueFixedRoots(keys, "source_root") };
}
fn uniqueFixedRoots(keys: []const *const Key, comptime field: []const u8) usize {
    var unique: usize = 0;
    for (keys, 0..) |key, i| {
        var seen = false;
        for (keys[0..i]) |prior| if (std.mem.eql(u8, &@field(prior, field), &@field(key, field))) {
            seen = true;
            break;
        };
        if (!seen) unique += 1;
    }
    return unique;
}
const ProduceMode = enum { capture, prepare, prove };
fn produceDirectoryMode(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, mode: ProduceMode, cache: ?*SetupCache, truth_local_gkr: bool, source_suite: ?SourceSuite) !void {
    try validateOptions(.{ .truth_local_gkr = truth_local_gkr, .source_suite = source_suite });
    const local_truth = if (source_suite) |suite| suite.truth == .local_gkr else truth_local_gkr;
    var session = if (cache) |owner| try owner.enterRequest(a, resources.disk_bytes, resources.mapped_bytes) else null;
    defer if (session) |*lease| lease.deinit();
    if (!engine.host_budget_allocator.SharedHostBudget.isAllocator(a)) return error.OpNativeRequiresSharedHostBudget;
    try Request.validateBudgetForOp(config);
    var timer = try std.time.Timer.start();
    var captured_plan = try @import("pure_p2_op_capture_plan.zig").Owner.init(a, config, profile, .{ .local_truth = local_truth, .truth_limits = .{ .live_bytes = resources.truth_live_bytes, .main_bytes = resources.truth_main_bytes, .interaction_bytes = resources.truth_interaction_bytes, .gkr_bytes = resources.gkr_bytes } }, &timer);
    defer captured_plan.deinit();
    const image = captured_plan.image;
    const program = captured_plan.program;
    const captured = &captured_plan.captured;
    const declarations = captured_plan.declarations;
    const req = captured_plan.requests;
    const spans = captured_plan.spans;
    const compact = captured_plan.compact;
    const count = captured.native.len;
    const tower = struct { items: []Bounds.OpTowerTruthDeclaration }{ .items = captured_plan.tower };
    const truth_declarations = captured_plan.truths;
    const image_ns = captured_plan.timing.image_ns;
    const program_ns = captured_plan.timing.program_ns;
    const capture_ns = captured_plan.timing.capture_ns;
    const captured_at = captured_plan.timing.captured_at;
    const metadata = Metadata{ .schema = if (source_suite != null) 3 else if (local_truth) 2 else 1, .profile = profile, .cpus = declarations, .requests = compact, .spans = spans, .truths = truth_declarations, .miller = tower.items, .memory_words = @intCast(captured.advice.initial.len) };
    try metadata.validate();
    var bounds = try Bounds.deriveForOp(a, program.log_size, declarations, truth_declarations, req, spans, tower.items);
    defer bounds.deinit();
    const source_security = if (source_suite) |suite| try SuiteSecurity.check(profile, &bounds, truth_declarations, tower.items, suite) else null;
    const truth_local_security = if (local_truth) (if (source_security) |checked| checked.truth else try TruthLocalSecurity.check(profile, &bounds, truth_declarations)) else null;
    var cost = try @import("pure_p2_op_cost.zig").derive(a, program, declarations, req, spans, captured.native, &captured.advice, truth_declarations, tower.items, bounds.base.shape.native_trace_cells[1], profile.config().fri_config.log_blowup_factor);
    defer cost.deinit();
    const capture_heap = engine.host_budget_allocator.SharedHostBudget.fromAllocator(a).?.snapshot();
    const Ownership = @import("../word16_global_execution/ethereum/capture_ownership.zig");
    var native_payload: usize = 0;
    for (captured.native) |n| native_payload = try std.math.add(usize, native_payload, Ownership.native(n).total());
    const advice_payload = Ownership.advice(&captured.advice);
    if (mode == .capture) {
        try std.fs.cwd().makePath(path);
        var out = try std.fs.cwd().openDir(path, .{});
        defer out.close();
        try @import("../word16_execution/driver.zig").writeJson(a, out, "native-op-cost.json", .{ .schema = "op-native-capture-cost/v1", .admitted_complete_runtime = false, .main_coefficient_bytes = cost.main_coefficient_bytes, .merkle_node_upper_bytes = cost.merkle_node_upper_bytes, .disk_upper_bytes = cost.disk_upper_bytes, .max_cpu_restore_bytes = cost.max_cpu_restore_bytes, .fixed_classes = cost.fixed_classes, .fixed_coefficient_bytes = cost.fixed_coefficient_bytes, .fixed_merkle_node_upper_bytes = cost.fixed_merkle_node_upper_bytes, .combined_disk_upper_bytes = cost.combined_disk_upper_bytes, .declared_limits = resources, .capture_heap = capture_heap, .native_capture_payload_bytes = native_payload, .advice_capture_payload = advice_payload, .cpus = cost.cpus, .truths = cost.truths, .miller = cost.miller, .caveat = "Truth Merkle floor16 is conservative; fixed setup, GKR/source temporaries and allocator/stack RSS need actual runtime admission. This capture report grants no execution proof acceptance." });
        try @import("../word16_execution/driver.zig").writeJson(a, out, "native-op-plan.json", .{ .proof_verified = false, .complete_execution = true, .steps = captured.steps, .final_pc = captured.final_pc, .final_registers = captured.final_registers, .metadata = metadata, .cells = bounds.base.shape.native_trace_cells, .image_ns = image_ns, .program_ns = program_ns, .capture_ns = capture_ns });
        std.debug.print("OP_NATIVE_CAPTURE complete=true proof_verified=false steps={} CPU={} truth={} miller={} cells={any} capture_ns={}\n", .{ captured.steps, count, truth_declarations.len, tower.items.len, bounds.base.shape.native_trace_cells, capture_ns });
        return;
    }
    const main_disk_limit = if (session) |lease| lease.disk_bytes else resources.disk_bytes;
    const main_mapped_limit = if (session) |lease| lease.mapped_bytes else resources.mapped_bytes;
    if (session != null) {
        if (cost.disk_upper_bytes > main_disk_limit) return error.OpCombinedParkingDiskPlanExceeded;
    } else if (cost.combined_disk_upper_bytes > resources.disk_bytes) return error.OpCombinedParkingDiskPlanExceeded;
    try std.fs.cwd().makePath(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const parking = try std.fs.path.join(a, &.{ path, "parked-main" });
    defer a.free(parking);
    try std.fs.cwd().makePath(parking);
    var store = try Store.init(a, parking, main_disk_limit, main_mapped_limit);
    defer store.deinit();
    var authority = try Authority.init(a, image, metadata, &store, cache, source_suite);
    defer authority.deinit();
    var cpu_metadata_disk_bytes: u64 = 0;
    if (resources.park_cpu_metadata and mode == .prove) {
        const Parking = @import("pure_p2_cpu_metadata_parking.zig");
        for (captured.native) |n| cpu_metadata_disk_bytes = try std.math.add(u64, cpu_metadata_disk_bytes, try Parking.roundedBytes(if (n.cpu) |*cpu| cpu else return error.PreparedExecutionConsumed));
        // FIXED templates were built from independent source authority. Their
        // actual reservation and conservative remaining MAIN+advice share this
        // same Store, while a cache's separate enforced growth reservation was
        // already removed from main_disk_limit by its request lease.
        const remaining = try std.math.add(u64, cost.disk_upper_bytes, cpu_metadata_disk_bytes);
        if (remaining > store.disk_limit - store.reserved) return error.OpCombinedParkingDiskPlanExceeded;
    }
    const expected = try Receiver.expectedFromRequests(image, program.identity, req, config.max_steps, config.batch_steps, true);
    var inventory = try Inv.Inventory.initForSourceSuite(a, profile, authority.setups, req, spans, authority.cpu_keys, authority.native_truth.truths, authority.truth_keys, authority.miller, expected, authority.truth_local_keys, source_suite);
    defer inventory.deinit();
    if (source_suite == null) if (truth_local_security) |checked| {
        checked.added.augmentShape(&inventory.bounds.base.shape);
        try inventory.bounds.base.shape.validate();
    };
    if (mode == .prepare) {
        const admitted_ns = timer.read();
        const cache_snapshot = if (cache) |owner| owner.snapshot() else null;
        const fixed_disk = store.reserved + (if (cache_snapshot) |snapshot| snapshot.parked_bytes else 0);
        const fixed_mapped = store.mapped + (if (cache_snapshot) |snapshot| snapshot.mapped_bytes else 0);
        const fixed_classes = authority.key_owners.items.len + authority.cpu_leases.items.len;
        const root_records = try fixedRootRecords(a, authority.cpu_keys);
        defer a.free(root_records);
        const metadata_bytes = try std.json.Stringify.valueAlloc(a, metadata, .{});
        defer a.free(metadata_bytes);
        var metadata_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(metadata_bytes, &metadata_digest, .{});
        const initial_digest = cellsDigest(captured.advice.initial);
        const terminal_digest = cellsDigest(captured.advice.terminal);
        const output = try Terminal.require(image, req[req.len - 1].base.cpu, captured.advice.terminal);
        const prepared_heap = engine.host_budget_allocator.SharedHostBudget.fromAllocator(a).?.snapshot();
        try @import("../word16_execution/driver.zig").writeJson(a, dir, "native-op-prepare-metadata.json", metadata);
        try @import("../word16_execution/driver.zig").writeJson(a, dir, "native-op-prepare.json", .{
            .schema = "op-native-source-prepare/v1",
            .truth_local_security = truth_local_security,
            .proof_verified = false,
            .production_admitted = false,
            .steps = captured.steps,
            .cpu_workers = count,
            .truth_workers = truth_declarations.len,
            .miller_workers = tower.items.len,
            .cpu_fixed_classes = fixed_classes,
            .fixed_root_distribution = root_records,
            .metadata_sha256 = metadata_digest,
            .initial_cells_sha256 = initial_digest,
            .terminal_cells_sha256 = terminal_digest,
            .final_pc = captured.final_pc,
            .final_registers = captured.final_registers,
            .output = output,
            .immutable_cache = cache_snapshot,
            .cache_limits = if (cache) |owner| owner.configuredLimits() else null,
            .unique_poseidon_fixed_roots = uniqueFixedRoots(authority.cpu_keys, "root"),
            .unique_legacy_fixed_roots = uniqueFixedRoots(authority.cpu_keys, "source_root"),
            .actual_immutable_fixed_disk_bytes = fixed_disk,
            .actual_fixed_mapping_bytes = fixed_mapped,
            .planned_combined_disk_upper_bytes = cost.combined_disk_upper_bytes,
            .admitted_combined_disk_upper_bytes = if (cache) |owner| try std.math.add(u64, cost.disk_upper_bytes, owner.configuredLimits().disk_bytes) else cost.combined_disk_upper_bytes,
            .request_main_disk_limit = main_disk_limit,
            .request_main_mapped_limit = main_mapped_limit,
            .max_cpu_main_restore_bytes = cost.max_cpu_restore_bytes,
            .capture_heap = capture_heap,
            .prepared_heap = prepared_heap,
            .declared_limits = resources,
            .source_cells = bounds.base.shape.native_trace_cells,
            .image_ns = image_ns,
            .program_ns = program_ns,
            .capture_ns = capture_ns,
            .setup_and_admission_ns = admitted_ns - captured_at,
            .diagnostics_and_publish_ns = timer.read() - admitted_ns,
            .caveat = "Source and immutable-setup admission only; no MAIN, GKR or execution proof. Active source/prover scratch remains subject to hard budgets. Uncached parked files retire on return; source-owned cache entries survive until cache teardown.",
        });
        std.debug.print("OP_NATIVE_PREPARE admitted_source=true proof_verified=false steps={} CPU={} truth={} miller={} fixed_classes={} fixed_disk={} mapped={}\n", .{ captured.steps, count, truth_declarations.len, tower.items.len, fixed_classes, fixed_disk, fixed_mapped });
        return;
    }
    var observations = try @import("../word16_global_execution/ethereum/observations.zig").Owner.init(a, if (config.profile_stages) inventory.workers.len else 0);
    defer observations.deinit();
    var phases: Producer.Timing = .{};
    const ready_ns = timer.read();
    const setup_heap = engine.host_budget_allocator.SharedHostBudget.fromAllocator(a).?.snapshot();
    const immutable_cache = if (cache) |owner| owner.snapshot() else null;
    const immutable_fixed_disk_bytes = store.reserved + (if (immutable_cache) |snapshot| snapshot.parked_bytes else 0);
    const producer_limits = Producer.Limits{
        .consume_memory_events = resources.consume_memory_events,
        .park_cpu_metadata = resources.park_cpu_metadata,
        .retire_source_auxiliaries = resources.retire_source_auxiliaries,
        .truth_local_gkr_bytes = resources.gkr_bytes,
        .miller_local_gkr_bytes = resources.gkr_bytes,
        .recorders = observations.pointers,
        .timing = &phases,
        .cpu = .{ .gkr_bytes = resources.gkr_bytes, .global_bytes = resources.global_bytes },
        .truth = .{ .live_bytes = resources.truth_live_bytes, .main_bytes = resources.truth_main_bytes, .interaction_bytes = resources.truth_interaction_bytes, .advice_bytes = resources.truth_advice_bytes },
        .miller = .{ .live_bytes = resources.truth_live_bytes, .main_bytes = resources.truth_main_bytes, .interaction_bytes = resources.truth_interaction_bytes, .advice_bytes = resources.truth_advice_bytes },
    };
    var bundle = if (source_suite) |suite| try Producer.produceForSourceSuite(a, &inventory, authority.setups, req, spans, authority.cpu_keys, authority.native_truth.truths, authority.truth_keys, authority.miller, captured.native, &captured.advice, &store, producer_limits, suite) else try Producer.produce(a, &inventory, authority.setups, req, spans, authority.cpu_keys, authority.native_truth.truths, authority.truth_keys, authority.miller, captured.native, &captured.advice, &store, producer_limits);
    defer bundle.deinit(a);
    const prove_ns = timer.read() - ready_ns;
    const publish_start = timer.read();
    const bytes = if (source_suite) |suite| try Bundle.encodeForSuite(a, &bundle, .{ .bytes = resources.bundle_bytes, .proof_bytes = resources.proof_bytes }, suite) else try Bundle.encode(a, &bundle, .{ .bytes = resources.bundle_bytes, .proof_bytes = resources.proof_bytes });
    defer a.free(bytes);
    try @import("../rv64_ethereum_batch_receipt.zig").writeExclusive(dir, "native-op.bin", bytes);
    if (source_suite) |suite| try @import("../word16_execution/driver.zig").writeJson(a, dir, "native-op.json", Metadata3.from(metadata, suite)) else try @import("../word16_execution/driver.zig").writeJson(a, dir, "native-op.json", metadata);
    try Cells.write(dir, captured.advice.initial, captured.advice.terminal);
    if (config.profile_stages) {
        const profiling = @import("../word16_global_execution/services/profiling.zig").Options{ .recorders = observations.pointers, .directory = dir };
        for (observations.pointers, 0..) |_, i| try profiling.finish(a, i);
    }
    try @import("../word16_execution/driver.zig").writeJson(a, dir, "native-op-timing.json", .{ .schema = "op-pure-p2-native-block/v1", .source_security = source_security, .truth_local_security = truth_local_security, .complete = true, .steps = captured.steps, .cpu = count, .truth = truth_declarations.len, .miller = tower.items.len, .native_bytes = bytes.len, .image_ns = image_ns, .program_ns = program_ns, .capture_ns = capture_ns, .setup_and_admission_ns = ready_ns - captured_at, .setup_heap = setup_heap, .immutable_fixed_classes = authority.key_owners.items.len + authority.cpu_leases.items.len, .immutable_fixed_cache = immutable_cache, .immutable_fixed_disk_bytes = immutable_fixed_disk_bytes, .peak_parked_mapping_bytes = store.peak_mapped, .runtime_heap = engine.host_budget_allocator.SharedHostBudget.fromAllocator(a).?.snapshot(), .cpu_metadata_disk_bytes = cpu_metadata_disk_bytes, .planned_combined_disk_upper_bytes = cost.combined_disk_upper_bytes, .seal_and_park_ns = phases.stage_one_ns, .manifest_ns = phases.manifest_ns, .stage_two_prove_ns = phases.stage_two_ns, .prove_ns = prove_ns, .publish_payload_ns = timer.read() - publish_start, .total_before_receipt_ns = timer.read(), .production_admitted = false });
    try std.posix.fsync(dir.fd);
    std.debug.print("OP_NATIVE_PRODUCER complete=true steps={} CPU={} truth={} miller={} bytes={} capture_ns={} prove_ns={}\n", .{ captured.steps, count, truth_declarations.len, tower.items.len, bytes.len, capture_ns, prove_ns });
}

/// Explicit executable entrypoint; never attached to the legacy Ethereum CLI.
pub fn main() !void {
    const base = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(base);
    defer std.process.argsFree(base, args);
    const command = try @import("pure_p2_op_cli.zig").parse(args);
    const raw = try std.fs.cwd().readFileAlloc(base, command.config, 16384);
    defer base.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, base, raw, .{});
    defer config.deinit();
    var resources: Resources = .{};
    var owner: ?std.json.Parsed(Resources) = null;
    defer if (owner) |*v| v.deinit();
    if (command.resources) |resource_path| {
        const bytes = try std.fs.cwd().readFileAlloc(base, resource_path, 16384);
        defer base.free(bytes);
        owner = try std.json.parseFromSlice(Resources, base, bytes, .{});
        resources = owner.?.value;
    }
    if (resources.live_bytes == 0 or resources.disk_bytes == 0 or resources.mapped_bytes == 0) return error.InvalidOpNativeResources;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(base, resources.live_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = if (config.value.workers != 0) config.value.workers else 8 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const profile = Profile.op_target_b4_q72_p0_fold4_v1;
    const source_suite: ?SourceSuite = if (command.miller_local_gkr) .{ .truth = if (command.truth_local_gkr) .local_gkr else .classic, .miller = .local_gkr } else null;
    const legacy_truth = command.truth_local_gkr and source_suite == null;
    if (command.detached_sponge) {
        const detached = @import("sponge_cpu/runtime.zig");
        if (std.mem.eql(u8, command.mode, "verify")) try detached.verifyDirectory(a, config.value, command.directory, profile, resources) else try detached.produceDirectory(a, config.value, command.directory, profile, resources);
    } else {
        if (std.mem.eql(u8, command.mode, "verify")) try verifyDirectoryWithOptions(a, config.value, command.directory, profile, resources, .{ .truth_local_gkr = legacy_truth, .source_suite = source_suite }, .{}) else try produceDirectoryMode(a, config.value, command.directory, profile, resources, if (std.mem.eql(u8, command.mode, "capture")) .capture else if (std.mem.eql(u8, command.mode, "prepare")) .prepare else .prove, null, legacy_truth, source_suite);
    }
    const final = budget.snapshot();
    if (final.live_bytes != 0) return error.OpNativeRuntimeCustodyLeak;
    std.debug.print("OP_NATIVE_TEARDOWN heap={} external={} peak={} exceeded={}\n", .{ final.host_live_bytes, final.external_live_bytes, final.peak_live_bytes, final.exceeded });
}

test "OP metadata source suite requires independent schema policy and preserves legacy JSON" {
    const a = std.testing.allocator;
    const cpus = [_]Wire.CpuDeclaration{std.mem.zeroes(Wire.CpuDeclaration)};
    const req = [_]Wire.CompactRequest{std.mem.zeroes(Wire.CompactRequest)};
    const spans = [_]T.OpTowerSpan{.{}};
    const m = Metadata{ .schema = 1, .profile = .op_target_b4_q72_p0_fold4_v1, .cpus = &cpus, .requests = &req, .spans = &spans, .truths = &.{}, .miller = &.{}, .memory_words = 0 };
    const old = try std.json.Stringify.valueAlloc(a, m, .{});
    defer a.free(old);
    try std.testing.expect(std.mem.indexOf(u8, old, "suite") == null);
    var legacy = try parseMetadata(a, old, .{});
    defer legacy.deinit();
    try std.testing.expect(legacy.suite == null and legacy.value.schema == 1);
    const suite = SourceSuite.millerGkr();
    const new = try std.json.Stringify.valueAlloc(a, Metadata3.from(m, suite), .{});
    defer a.free(new);
    try std.testing.expectError(error.OpSourceSuiteRequiresExplicitReceiver, parseMetadata(a, new, .{}));
    try std.testing.expectError(error.OpSourceSuitePolicyMismatch, parseMetadata(a, new, .{ .source_suite = SourceSuite{} }));
    try std.testing.expectError(error.AmbiguousOpSourceSuitePolicy, parseMetadata(a, new, .{ .source_suite = suite, .truth_local_gkr = true }));
    var selected = try parseMetadata(a, new, .{ .source_suite = suite });
    defer selected.deinit();
    try std.testing.expectEqualDeep(suite, selected.suite.?);
    try std.testing.expectEqual(@as(u32, 3), selected.value.schema);
    try std.testing.expectError(error.OpSourceSuitePolicyMismatch, parseMetadata(a, old, .{ .source_suite = suite }));
}

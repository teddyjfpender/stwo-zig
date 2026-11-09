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
const Keys = @import("../word16_global_execution/ethereum/keys.zig");
const Key = @import("pure_p2_fixed_key.zig").Key;
const Truth = @import("pure_p2_truth_worker.zig");
const Miller = @import("pure_p2_tower_worker.zig");
const Inv = @import("pure_p2_op_inventory.zig");
const Bundle = @import("pure_p2_op_bundle.zig");
const Producer = @import("pure_p2_op_producer.zig");
const Store = @import("pure_p2_retained_main.zig").Store;
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
        if (self.schema != 1 or self.profile == .reference_b2_q24_p0 or self.cpus.len == 0 or self.cpus.len != self.requests.len or self.cpus.len != self.spans.len or self.cpus.len + self.truths.len + self.miller.len > 256 or self.memory_words >= 1 << 23) return error.InvalidOpNativeMetadata;
    }
};
pub const Resources = struct {
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
const Authority = struct {
    allocator: std.mem.Allocator,
    native_truth: Keys.Owner,
    setups: []*const R.CpuSetup,
    cpu_keys: []*const Key,
    truth_keys: []*const Truth.Key,
    miller: []Inv.MillerDeclaration,
    cpu_owners: std.ArrayList(*R.CpuSetup) = .empty,
    key_owners: std.ArrayList(*Key) = .empty,
    truth_owners: std.ArrayList(*Truth.Key) = .empty,
    miller_owners: std.ArrayList(*Miller.Key) = .empty,
    fn deinit(self: *Authority) void {
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
        for (self.miller_owners.items) |key| {
            key.deinit();
            a.destroy(key);
        }
        self.key_owners.deinit(a);
        self.cpu_owners.deinit(a);
        self.truth_owners.deinit(a);
        self.miller_owners.deinit(a);
        a.free(self.setups);
        a.free(self.cpu_keys);
        a.free(self.truth_keys);
        a.free(self.miller);
        self.native_truth.deinit();
        self.* = undefined;
    }
    fn init(a: std.mem.Allocator, image: *const Image.Owner, m: Metadata) !Authority {
        try m.validate();
        const setups = try a.alloc(*const R.CpuSetup, m.cpus.len);
        errdefer a.free(setups);
        const cpu_keys = try a.alloc(*const Key, m.cpus.len);
        errdefer a.free(cpu_keys);
        const truth_keys = try a.alloc(*const Truth.Key, m.truths.len);
        errdefer a.free(truth_keys);
        const miller = try a.alloc(Inv.MillerDeclaration, m.miller.len);
        errdefer a.free(miller);
        var native_truth = try Keys.Owner.init(a, image, &.{}, m.truths);
        errdefer native_truth.deinit();
        var self = Authority{ .allocator = a, .native_truth = native_truth, .setups = setups, .cpu_keys = cpu_keys, .truth_keys = truth_keys, .miller = miller };
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
            for (self.miller_owners.items) |k| {
                k.deinit();
                a.destroy(k);
            }
            self.key_owners.deinit(a);
            self.cpu_owners.deinit(a);
            self.truth_owners.deinit(a);
            self.miller_owners.deinit(a);
        }
        for (m.cpus, 0..) |d, i| {
            var reused = false;
            for (m.cpus[0..i], 0..) |prior, j| if (std.meta.eql(prior, d)) {
                setups[i] = setups[j];
                cpu_keys[i] = cpu_keys[j];
                reused = true;
                break;
            };
            if (reused) continue;
            try self.cpu_owners.ensureUnusedCapacity(a, 1);
            try self.key_owners.ensureUnusedCapacity(a, 1);
            const setup = try a.create(R.CpuSetup);
            setup.* = R.CpuSetup.initForOpWithAuthorityAndSuiteAndCaches(a, &image.authority, d.geometry, d.bridges, @import("../word16_execution/pcs_suite.zig").Suite.production(), .{}) catch |err| {
                a.destroy(setup);
                return err;
            };
            self.cpu_owners.appendAssumeCapacity(setup);
            setups[i] = setup;
            const key = try a.create(Key);
            key.* = Key.initForOp(a, setup, m.profile) catch |err| {
                a.destroy(key);
                return err;
            };
            self.key_owners.appendAssumeCapacity(key);
            cpu_keys[i] = key;
        }
        for (self.native_truth.truths, 0..) |truth, i| {
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
    image: *const Image.Owner,
    metadata: Metadata,
    requests: []const P.Request,
    expected: P.Expected,
    cpu_keys: []const *const Key,
    truth_keys: []const *const Truth.Key,
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
    /// Borrowed source-policy authority only. Public cells/output are NOT
    /// authenticated execution until the consumer verifies its root/proofs.
    image: *const Image.Owner,
    metadata: Metadata,
    requests: []const P.Request,
    setups: []const *const R.CpuSetup,
    cpu_keys: []const *const Key,
    truths: []const R.Truth,
    truth_keys: []const *const Truth.Key,
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
    if (!engine.host_budget_allocator.SharedHostBudget.isAllocator(a)) return error.OpNativeRequiresSharedHostBudget;
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
    const parsed = try std.json.parseFromSlice(Metadata, a, json, .{});
    defer parsed.deinit();
    const m = parsed.value;
    try m.validate();
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
    var authority = try Authority.init(a, &image, m);
    defer authority.deinit();
    const expected = try Receiver.expectedFromRequests(&image, program.identity, req, config.max_steps, config.batch_steps, true);
    var inventory = try Inv.Inventory.init(a, profile, authority.setups, req, m.spans, authority.cpu_keys, authority.native_truth.truths, authority.truth_keys, authority.miller, expected);
    defer inventory.deinit();
    _ = resources;
    const output = try Terminal.require(&image, req[req.len - 1].base.cpu, cells.terminal);
    try callback(context, a, .{ .image = &image, .metadata = m, .requests = req, .setups = authority.setups, .cpu_keys = authority.cpu_keys, .truths = authority.native_truth.truths, .truth_keys = authority.truth_keys, .miller = authority.miller, .inventory = &inventory, .expected = expected, .output = output, .output_address = image.symbols.output_data, .initial = cells.initial, .terminal = cells.terminal, .image_ns = image_ns, .program_ns = program_ns });
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
        var bundle = try Bundle.decode(a, bytes, source.inventory.workers.len, .{ .bytes = self.resources.bundle_bytes, .proof_bytes = self.resources.proof_bytes });
        defer bundle.deinit(a);
        const verify_start = self.timer.read();
        var closed = try bundle.verifyWithHooks(a, source.inventory, source.setups, source.requests, source.metadata.spans, source.cpu_keys, source.truths, source.truth_keys, source.miller, self.hooks.fragments);
        defer closed.deinit(a);
        // Recheck AFTER native physical/global verification and callbacks. The
        // source-only helper's earlier policy check authenticates no RAM.
        const output = try Terminal.require(source.image, source.requests[source.requests.len - 1].base.cpu, source.terminal);
        if (self.hooks.complete) |complete| try complete(self.hooks.context, a, .{ .image = source.image, .metadata = source.metadata, .requests = source.requests, .expected = source.expected, .cpu_keys = source.cpu_keys, .truth_keys = source.truth_keys, .output_address = source.output_address, .setups = source.setups, .truths = source.truths, .miller = source.miller, .inventory = source.inventory, .native = &closed, .output = output });
        std.debug.print("OP_NATIVE_RECEIVER accepted=true complete=true steps={} CPU={} truth={} miller={} profile={s} image_ns={} program_ns={} setup_and_decode_ns={} verify_ns={} total_ns={}\n", .{ source.expected.total_steps, source.setups.len, source.truths.len, source.miller.len, @tagName(self.profile), source.image_ns, source.program_ns, verify_start - source.image_ns - source.program_ns, self.timer.read() - verify_start, self.timer.read() });
    }
};
pub fn verifyDirectoryWithHooks(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, hooks: ReceptionHooks) !void {
    var context = NativeReception{ .path = path, .profile = profile, .resources = resources, .hooks = hooks, .timer = try std.time.Timer.start() };
    return withSourceDirectory(a, config, path, profile, resources, &context, NativeReception.run);
}

pub fn produceDirectory(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources) !void {
    return produceDirectoryMode(a, config, path, profile, resources, false);
}
fn produceDirectoryMode(a: std.mem.Allocator, config: Request.Config, path: []const u8, profile: Profile, resources: Resources, capture_only: bool) !void {
    if (!engine.host_budget_allocator.SharedHostBudget.isAllocator(a)) return error.OpNativeRequiresSharedHostBudget;
    try Request.validateBudgetForOp(config);
    var timer = try std.time.Timer.start();
    var image = try Image.Owner.initForOp(a, config);
    defer image.deinit();
    const image_ns = timer.read();
    var program = try Program.initWithAuthority(a, &image.authority);
    defer program.deinit();
    const layout = Plan.CpuLayout.forOpGkr();
    try program.makeCompact();
    const program_ns = timer.read() - image_ns;
    const capture_start = timer.read();
    var captured = try Capture.Owner.init(a, config, &image, &program);
    defer captured.deinit();
    const captured_at = timer.read();
    const capture_ns = captured_at - capture_start;
    const count = captured.native.len;
    const declarations = try a.alloc(Wire.CpuDeclaration, count);
    defer a.free(declarations);
    const req = try a.alloc(P.Request, count);
    defer a.free(req);
    const spans = try a.alloc(T.OpTowerSpan, count);
    defer a.free(spans);
    const compact = try a.alloc(Wire.CompactRequest, count);
    defer a.free(compact);
    var next: u32 = 1;
    var total: [T.FAMILIES]u32 = @splat(0);
    for (captured.native, 0..) |n, i| {
        declarations[i] = try Plan.cpuForSegment(n, &captured.advice, i, count, captured.advice.initial.len, layout);
        const calls = std.math.cast(u32, captured.advice.tower[i].len) orelse return error.InvalidOpTowerCoverage;
        spans[i] = if (calls == 0) .{} else .{ .calls = calls, .first_id = next };
        next = try std.math.add(u32, next, calls);
        if (calls != 0) declarations[i].bridges.tower = try @import("../word16_execution/coverage.zig").minimalPrefixLog(try std.math.mul(u32, calls, 32));
        req[i] = try Coordinator.requestView(captured.native, &captured.advice, i);
        try Coordinator.routeDword(&req[i], declarations[i].bridges, captured.advice.events[i]);
        for (&total, req[i].calls) |*sum, value| sum.* = try std.math.add(u32, sum.*, value);
        total[0] = try std.math.add(u32, total[0], req[i].sponge.perms);
    }
    try Coordinator.assignSpongeIds(req);
    for (req, compact) |r, *out| out.* = Wire.CompactRequest.from(r);
    const truth_declarations = try Plan.truthsForServiceCounts(a, total, .{}, 18);
    defer a.free(truth_declarations);
    var tower = std.ArrayList(Bounds.OpTowerTruthDeclaration).empty;
    defer tower.deinit(a);
    var first: u32 = 1;
    while (first < next) {
        const calls = @min(1023, next - first);
        const log = @max(15, try @import("../word16_execution/coverage.zig").minimalPrefixLog(try std.math.mul(u32, calls, 32)));
        try tower.append(a, .{ .calls = calls, .first_id = first, .frontier_log = log, .arithmetic_log = log });
        first += calls;
    }
    const metadata = Metadata{ .profile = profile, .cpus = declarations, .requests = compact, .spans = spans, .truths = truth_declarations, .miller = tower.items, .memory_words = @intCast(captured.advice.initial.len) };
    try metadata.validate();
    var bounds = try Bounds.deriveForOp(a, program.log_size, declarations, truth_declarations, req, spans, tower.items);
    defer bounds.deinit();
    var cost = try @import("pure_p2_op_cost.zig").derive(a, &program, declarations, req, spans, captured.native, &captured.advice, truth_declarations, tower.items, bounds.base.shape.native_trace_cells[1], profile.config().fri_config.log_blowup_factor);
    defer cost.deinit();
    const capture_heap = engine.host_budget_allocator.SharedHostBudget.fromAllocator(a).?.snapshot();
    const Ownership = @import("../word16_global_execution/ethereum/capture_ownership.zig");
    var native_payload: usize = 0;
    for (captured.native) |n| native_payload = try std.math.add(usize, native_payload, Ownership.native(n).total());
    const advice_payload = Ownership.advice(&captured.advice);
    if (capture_only) {
        try std.fs.cwd().makePath(path);
        var out = try std.fs.cwd().openDir(path, .{});
        defer out.close();
        try @import("../word16_execution/driver.zig").writeJson(a, out, "native-op-cost.json", .{ .schema = "op-native-capture-cost/v1", .admitted_complete_runtime = false, .main_coefficient_bytes = cost.main_coefficient_bytes, .merkle_node_upper_bytes = cost.merkle_node_upper_bytes, .disk_upper_bytes = cost.disk_upper_bytes, .max_cpu_restore_bytes = cost.max_cpu_restore_bytes, .declared_limits = resources, .capture_heap = capture_heap, .native_capture_payload_bytes = native_payload, .advice_capture_payload = advice_payload, .cpus = cost.cpus, .truths = cost.truths, .miller = cost.miller, .caveat = "Truth Merkle floor16 is conservative; fixed setup, GKR/source temporaries and allocator/stack RSS need actual runtime admission. This capture report grants no execution proof acceptance." });
        try @import("../word16_execution/driver.zig").writeJson(a, out, "native-op-plan.json", .{ .proof_verified = false, .complete_execution = true, .steps = captured.steps, .final_pc = captured.final_pc, .final_registers = captured.final_registers, .metadata = metadata, .cells = bounds.base.shape.native_trace_cells, .image_ns = image_ns, .program_ns = program_ns, .capture_ns = capture_ns });
        std.debug.print("OP_NATIVE_CAPTURE complete=true proof_verified=false steps={} CPU={} truth={} miller={} cells={any} capture_ns={}\n", .{ captured.steps, count, truth_declarations.len, tower.items.len, bounds.base.shape.native_trace_cells, capture_ns });
        return;
    }
    var authority = try Authority.init(a, &image, metadata);
    defer authority.deinit();
    const expected = try Receiver.expectedFromRequests(&image, program.identity, req, config.max_steps, config.batch_steps, true);
    var inventory = try Inv.Inventory.init(a, profile, authority.setups, req, spans, authority.cpu_keys, authority.native_truth.truths, authority.truth_keys, authority.miller, expected);
    defer inventory.deinit();
    try std.fs.cwd().makePath(path);
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const parking = try std.fs.path.join(a, &.{ path, "parked-main" });
    defer a.free(parking);
    try std.fs.cwd().makePath(parking);
    var store = try Store.init(a, parking, resources.disk_bytes, resources.mapped_bytes);
    defer store.deinit();
    var observations = try @import("../word16_global_execution/ethereum/observations.zig").Owner.init(a, if (config.profile_stages) inventory.workers.len else 0);
    defer observations.deinit();
    var phases: Producer.Timing = .{};
    const ready_ns = timer.read();
    var bundle = try Producer.produce(a, &inventory, authority.setups, req, spans, authority.cpu_keys, authority.native_truth.truths, authority.truth_keys, authority.miller, captured.native, &captured.advice, &store, .{
        .recorders = observations.pointers,
        .timing = &phases,
        .cpu = .{ .gkr_bytes = resources.gkr_bytes, .global_bytes = resources.global_bytes },
        .truth = .{ .live_bytes = resources.truth_live_bytes, .main_bytes = resources.truth_main_bytes, .interaction_bytes = resources.truth_interaction_bytes, .advice_bytes = resources.truth_advice_bytes },
        .miller = .{ .live_bytes = resources.truth_live_bytes, .main_bytes = resources.truth_main_bytes, .interaction_bytes = resources.truth_interaction_bytes, .advice_bytes = resources.truth_advice_bytes },
    });
    defer bundle.deinit(a);
    const prove_ns = timer.read() - ready_ns;
    const publish_start = timer.read();
    const bytes = try Bundle.encode(a, &bundle, .{ .bytes = resources.bundle_bytes, .proof_bytes = resources.proof_bytes });
    defer a.free(bytes);
    try @import("../rv64_ethereum_batch_receipt.zig").writeExclusive(dir, "native-op.bin", bytes);
    try @import("../word16_execution/driver.zig").writeJson(a, dir, "native-op.json", metadata);
    try Cells.write(dir, captured.advice.initial, captured.advice.terminal);
    if (config.profile_stages) {
        const profiling = @import("../word16_global_execution/services/profiling.zig").Options{ .recorders = observations.pointers, .directory = dir };
        for (observations.pointers, 0..) |_, i| try profiling.finish(a, i);
    }
    try @import("../word16_execution/driver.zig").writeJson(a, dir, "native-op-timing.json", .{ .schema = "op-pure-p2-native-block/v1", .complete = true, .steps = captured.steps, .cpu = count, .truth = truth_declarations.len, .miller = tower.items.len, .native_bytes = bytes.len, .image_ns = image_ns, .program_ns = program_ns, .capture_ns = capture_ns, .setup_and_admission_ns = ready_ns - captured_at, .seal_and_park_ns = phases.stage_one_ns, .manifest_ns = phases.manifest_ns, .stage_two_prove_ns = phases.stage_two_ns, .prove_ns = prove_ns, .publish_payload_ns = timer.read() - publish_start, .total_before_receipt_ns = timer.read(), .production_admitted = false });
    try std.posix.fsync(dir.fd);
    std.debug.print("OP_NATIVE_PRODUCER complete=true steps={} CPU={} truth={} miller={} bytes={} capture_ns={} prove_ns={}\n", .{ captured.steps, count, truth_declarations.len, tower.items.len, bytes.len, capture_ns, prove_ns });
}

/// Explicit executable entrypoint; never attached to the legacy Ethereum CLI.
pub fn main() !void {
    const base = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(base);
    defer std.process.argsFree(base, args);
    if (args.len < 4 or args.len > 5 or (!std.mem.eql(u8, args[1], "prove") and !std.mem.eql(u8, args[1], "verify") and !std.mem.eql(u8, args[1], "capture"))) return error.ExpectedOpNativeModeConfigDirectoryAndOptionalResources;
    const raw = try std.fs.cwd().readFileAlloc(base, args[2], 16384);
    defer base.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, base, raw, .{});
    defer config.deinit();
    var resources: Resources = .{};
    var owner: ?std.json.Parsed(Resources) = null;
    defer if (owner) |*v| v.deinit();
    if (args.len == 5) {
        const bytes = try std.fs.cwd().readFileAlloc(base, args[4], 16384);
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
    if (std.mem.eql(u8, args[1], "verify")) try verifyDirectory(a, config.value, args[3], profile, resources) else try produceDirectoryMode(a, config.value, args[3], profile, resources, std.mem.eql(u8, args[1], "capture"));
}

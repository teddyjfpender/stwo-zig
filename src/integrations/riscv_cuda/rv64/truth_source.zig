//! Device-owned service source pipeline. Compact call records enter once;
//! native MAIN/INTER, FFTs and commitments never materialize on the host.
const std = @import("std");
const core = @import("stwo_core");
const CPU = @import("stwo_riscv_cpu_integration");
const A = @import("stwo_riscv_frontend").rv64_air;
const S = CPU.rv64_gkr_truth_device_source;
const D = CPU.rv64_device_pcs;
const N = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const Native = @import("pcs_native.zig");
const Trace = @import("trace_commit.zig");
const Rational = @import("global_stage.zig");
const Raw = @import("truth_interaction_codegen.zig");
const T = @import("truth_codegen.zig");
const O = D.O;
const Truth = @FieldType(S.Prepare, "truth");
const Launch = *const fn (*anyopaque, u32, [*]const u32, [*]const u32, [*]const u32, [*]u32, [*]u32, [*]u32, u32) callconv(.c) c_int;
const Keccak = extern struct { inputs: [*]const u32, main: [*]u32, chi: [*]u32, xor5: [*]u32, status: [*]u32, input_words: u64, main_words: u64, calls: u32, first_id: u32, log: u32, policy: u32 = 0 };
const Sha = extern struct { inputs: [*]const u32, main: [*]u32, status: [*]u32, input_words: u64, main_words: u64, calls: u32, first_id: u32, log: u32, reserved: u32 = 0 };
const Arith = extern struct { inputs: [*]const u32, main: [*]u32, byte_counts: [*]u32, status: [*]u32, input_words: u64, main_words: u64, calls: u32, first_id: u32, log: u32, reserved: u32 = 0 };
const Secp = extern struct { inputs: [*]const u32, main: [*]u32, byte_counts: [*]u32, status: [*]u32, input_words: u64, main_words: u64, calls: u32, first_id: u32, log: u32, kind: u32 };
const SecpFn = *const fn (*anyopaque, u32, *const Secp) callconv(.c) c_int;
const ArithFn = *const fn (*anyopaque, u32, *const Arith) callconv(.c) c_int;
const KeccakFn = *const fn (*anyopaque, u32, *const Keccak) callconv(.c) c_int;
const ShaFn = *const fn (*anyopaque, u32, *const Sha) callconv(.c) c_int;
const Entry = struct { slots: []u32, groups: [2]u32, launch: Launch };
fn checked(status: c_int) !void {
    if (status != 0) return error.DeviceTruthKernelFailed;
}
fn symbol(comptime Type: type, lib: *std.DynLib, name: [:0]const u8) !Type {
    return lib.lookup(Type, name) orelse error.MissingDeviceTruthSymbol;
}
fn rows(log: u32) !usize {
    if (log < 5 or log > 22) return error.InvalidDeviceTruthGeometry;
    return @as(usize, 1) << @intCast(log);
}
fn logSize(truth: Truth) !u32 {
    return if (truth == .keccak) truth.keccak.setup.log else T.V3Catalog.logSize(truth);
}
fn mainWidth(truth: Truth) !usize {
    return if (truth == .keccak) A.crypto.keccak.layout.MAIN else (try T.V3Catalog.shape(truth)).main;
}
/// No CUDA work or wide witness construction is needed for admission. Charge
/// narrow descriptor/cache capacity conservatively; native context byte caps
/// independently govern transient planes, idle allocation caches and setup.
pub fn retainedForTruth(a: std.mem.Allocator, truth: Truth, replay: bool) !S.Retained {
    const compact = try S.compactInputBytes(truth);
    var header_count: usize = 0;
    var main_bytes: usize = 0;
    for (0..3) |tree| {
        const logs = try truth.logs(a, @intCast(tree));
        defer a.free(logs);
        header_count = try std.math.add(usize, header_count, logs.len);
        if (tree == 1) for (logs) |log| {
            main_bytes = try std.math.add(usize, main_bytes, try std.math.mul(usize, try rows(log), 4));
        };
    }
    return .{ .compact_input_bytes = compact, .narrow_metadata_bytes = try std.math.add(usize, @sizeOf(Owner) + 65536, try std.math.mul(usize, header_count, 256)), .kept_device_bytes = if (replay) 0 else main_bytes, .main_replayed = replay };
}
pub const Context = struct {
    allocator: std.mem.Allocator,
    service: *Native.Context,
    trace: *Trace.Context,
    rational: *Rational.Context,
    api: SC.Api,
    replay_main: bool = true,
    composition: ?*@import("resident_composition.zig").Context = null,
    rebind: N.LeaseRebind,
    keccak: KeccakFn,
    sha: ?ShaFn,
    arith: ?ArithFn,
    secp: ?SecpFn,
    curve: ?SecpFn,
    entries: [15]?Entry = @splat(null),
    mutex: std.Thread.Mutex = .{},
    pub fn init(a: std.mem.Allocator, service: *Native.Context, trace: *Trace.Context, rational: *Rational.Context) !Context {
        return .{ .allocator = a, .service = service, .trace = trace, .rational = rational, .api = .{ .allocate = service.lease_allocate, .release = service.lease_release, .validate_range = service.lease_validate_range, .upload = try symbol(N.Upload, &service.library, "stwo_exec_context_memcpy_h2d_async"), .download = try symbol(N.Download, &service.library, "stwo_exec_context_memcpy_d2h_async"), .sync = try symbol(N.Sync, &service.library, "stwo_exec_context_sync"), .lane_stream = try symbol(N.LaneStream, &service.library, "stwo_exec_context_lane_stream") }, .rebind = try symbol(N.LeaseRebind, &service.library, "stwo_rv64_gpu_lease_rebind"), .keccak = try symbol(KeccakFn, &service.library, "stwo_rv64_keccak_witness_on"), .arith = service.library.lookup(ArithFn, "stwo_rv64_arith256_witness_on"), .secp = service.library.lookup(SecpFn, "stwo_rv64_secp_witness_on"), .curve = service.library.lookup(SecpFn, "stwo_rv64_curve_witness_on"), .sha = service.library.lookup(ShaFn, "stwo_rv64_sha256_witness_on") };
    }
    pub fn deinit(self: *Context) void {
        for (&self.entries) |*cached| if (cached.*) |value| self.allocator.free(value.slots);
        self.* = undefined;
    }
    pub fn stage(self: *Context) S.Stage {
        return .{ .context = self, .prepare = prepare, .retained_upper_bound = retainedUpperBound };
    }
    fn retainedUpperBound(raw: *anyopaque, request: S.RetentionRequest) !S.Retained {
        const self: *Context = @ptrCast(@alignCast(raw));
        return retainedForTruth(self.allocator, request.truth, self.replay_main);
    }
    fn entry(self: *Context, id: u32) !*const Entry {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.entries[id] == null) {
            var cold = try Raw.record(self.allocator, id);
            defer cold.deinit();
            const name = try Raw.name(self.allocator, id);
            defer self.allocator.free(name);
            const z = try self.allocator.dupeZ(u8, name);
            defer self.allocator.free(z);
            const launch = try symbol(Launch, &self.service.library, z);
            const slots = cold.parameter_slots;
            cold.parameter_slots = &.{};
            self.entries[id] = .{ .slots = slots, .groups = cold.groups, .launch = launch };
        }
        return &self.entries[id].?;
    }
    fn prepare(raw: *anyopaque, a: std.mem.Allocator, request: S.Prepare) !S.Owner {
        const self: *Context = @ptrCast(@alignCast(raw));
        if (request.budget == 0 or request.truth.count() == 0) return error.InvalidDeviceTruthBudget;
        switch (request.truth) {
            .keccak => |truth| {
                const base = try T.classicKernelId(truth.setup.policy, .keccak);
                for (base..base + 3) |id| _ = try self.entry(@intCast(id));
            },
            .sha256 => {
                if (self.sha == null) return error.MissingDeviceTruthSymbol;
                _ = try self.entry(3);
            },
            .arith256_mod => {
                if (self.arith == null) return error.MissingDeviceTruthSymbol;
                _ = try self.entry(4);
            },
            .secp_row => |truth| {
                if (self.secp == null) return error.MissingDeviceTruthSymbol;
                _ = try self.entry(if (truth.setup.kind == .add) 5 else 6);
            },
            .curve => |truth| {
                const id = try @import("truth_codegen.zig").curveKernelId(truth.setup.op);
                if (self.curve == null) return error.MissingDeviceTruthSymbol;
                _ = try self.entry(id);
            },
            else => return error.UnsupportedDeviceTruthFamily,
        }
        const owner = try a.create(Owner);
        errdefer a.destroy(owner);
        owner.* = .{ .allocator = a, .backend = self, .truth = request.truth, .scope = .{ .statement = request.expected.statement, .fixed = request.expected.fixed, .main = @splat(0), .ordinal = @intCast(request.expected.ordinal) }, .budget = request.budget, .pcs_config = request.config };
        owner.inputs = try compactInputs(a, request);
        owner.compact_words = owner.inputs.len;
        return .{ .context = owner, .seal_main = Owner.seal, .generate_interactions = Owner.generate, .release = Owner.destroy };
    }
};
const Owner = struct {
    allocator: std.mem.Allocator,
    backend: *Context,
    truth: Truth,
    scope: D.Scope,
    budget: usize,
    pcs_config: @FieldType(S.Prepare, "config") = undefined,
    inputs: []u32 = &.{},
    compact: ?N.Lease = null,
    compact_words: usize = 0,
    fixed: []D.Column = &.{},
    main: ?D.Tree = null,
    raw_leases: [3]?N.Lease = @splat(null),
    raw_columns: []D.TraceColumn = &.{},
    fn seal(raw: *anyopaque, a: std.mem.Allocator, request: S.Sealed) !D.Tree {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (self.main != null or !std.meta.eql(self.scope, request.scope)) return error.InvalidDeviceTruthSealPhase;
        self.fixed = try self.allocator.dupe(D.Column, request.fixed.columns);
        try self.runMain(request.fixed.columns);
        defer self.releaseRaw();
        const stage = self.backend.trace.stage();
        const committed = try stage.commit(stage.context, a, .{ .scope = request.scope, .tree_index = 1, .config = request.config, .columns = self.raw_columns });
        self.main = committed;
        const previous_scope = self.scope;
        self.scope.main = committed.root;
        var promotion = Promote{ .owner = self, .previous = previous_scope };
        if (self.backend.service.submit(self.backend.service.session, Promote.callback, &promotion) != 0) return error.DeviceTruthCompactPromotionFailed;
        try self.releaseRawChecked();
        if (self.backend.replay_main) {
            try self.backend.service.discardRetainedMain(self.scope);
        }
        self.allocator.free(self.inputs);
        self.inputs = &.{};
        return committed;
    }
    fn generate(raw: *anyopaque, a: std.mem.Allocator, local: S.Local, shared: S.Shared) !S.Interactions {
        const self: *Owner = @ptrCast(@alignCast(raw));
        var main = self.main orelse return error.InvalidDeviceTruthSealPhase;
        if (self.backend.replay_main) {
            try self.runMain(self.fixed);
            defer self.releaseRaw();
            const committer = self.backend.trace.stage();
            main = try committer.commit(committer.context, a, .{ .scope = self.scope, .tree_index = 1, .config = self.config(), .columns = self.raw_columns, .expected_main_root = self.scope.main });
            self.main = main;
        }
        var generated: [3]?CPU.rv64_gkr_cpu_worker.DeviceGlobal.Witness = @splat(null);
        defer for (&generated) |*value| if (value.*) |*w| w.deinit();
        var columns: std.ArrayList(D.TraceColumn) = .empty;
        defer columns.deinit(a);
        const count: usize = if (self.truth == .keccak) 5 else 1;
        const claims = try a.alloc(O, count);
        errdefer a.free(claims);
        @memset(claims, O.zero());
        if (self.truth == .keccak) {
            if (local != .classic) return error.DeviceTruthChallengeMismatch;
            var fixed_offset: usize = 0;
            var main_offset: usize = 0;
            const base = try T.classicKernelId(self.truth.keccak.setup.policy, .keccak);
            for (0..3) |id| {
                const entry = try self.backend.entry(base + @as(u32, @intCast(id)));
                const log: u32 = if (id == 0) self.truth.keccak.setup.log else self.truth.keccak.setup.policy.tableLog(if (id == 1) .chi else .xor5);
                const widths: [2]usize = if (id == 0) .{ 32, 1923 } else .{ 7, 1 };
                const component = T.Role.Component{ .kind = if (id == 0) .keccak else if (id == 1) .chi else .xor5, .log_size = log, .calls = if (id == 0) self.truth.count() else 0, .first_id = if (id == 0) self.truth.first() else 1, .keccak_policy = self.truth.keccak.setup.policy, .local = local.classic, .shared = shared, .claim = O.zero(), .global_claim = O.zero(), .split = 2 };
                const metadata = T.nativeMetadata(&component);
                const parameters = try a.alloc(O, entry.slots.len);
                defer a.free(parameters);
                for (parameters, entry.slots) |*value, slot| value.* = metadata[slot];
                generated[id] = try self.backend.rational.generateRational(a, .{ .scope = self.scope, .log_size = log, .fixed = self.fixed[fixed_offset..][0..widths[0]], .main = main.columns[main_offset..][0..widths[1]], .fixed_offset = fixed_offset, .parameters = parameters, .projection = entry.launch, .groups = entry.groups, .layout = .inverse_prefix, .budget = self.budget, .zero_claim_groups = 0 });
                const witness = &generated[id].?;
                if (witness.claims.len != (if (id == 0) @as(usize, 2) else 1)) return error.DeviceTruthClaimMismatch;
                claims[id] = witness.claims[0];
                if (id == 0) claims[3] = witness.claims[1];
                try columns.appendSlice(a, witness.columns);
                fixed_offset += widths[0];
                main_offset += widths[1];
            }
            if (!claims[0].add(claims[1]).add(claims[2]).isZero()) return error.DeviceTruthLocalClosure;
        } else {
            if (local != .delegated) return error.DeviceTruthChallengeMismatch;
            const entry = try self.backend.entry(if (self.truth == .curve) try @import("truth_codegen.zig").curveKernelId(self.truth.curve.setup.op) else if (self.truth == .sha256) 3 else if (self.truth == .arith256_mod) 4 else if (self.truth.secp_row.setup.kind == .add) 5 else 6);
            const component = T.V3Role.Component{ .truth = self.truth, .wire = shared.wire, .bytes = local.delegated, .claim = O.zero() };
            const metadata = T.nativeMetadataV3(&component);
            const parameters = try a.alloc(O, entry.slots.len);
            defer a.free(parameters);
            for (parameters, entry.slots) |*value, slot| value.* = metadata[slot];
            generated[0] = try self.backend.rational.generateRational(a, .{ .scope = self.scope, .log_size = try logSize(self.truth), .fixed = self.fixed, .main = main.columns, .fixed_offset = 0, .parameters = parameters, .projection = entry.launch, .groups = entry.groups, .layout = .cumulative_batches, .budget = self.budget, .zero_claim_groups = if (entry.groups[1] != 0) 1 else 0 });
            if (generated[0].?.claims.len != (if (entry.groups[1] != 0) @as(usize, 2) else 1)) return error.DeviceTruthClaimMismatch;
            if (entry.groups[1] != 0 and !generated[0].?.claims[0].isZero()) return error.DeviceTruthLocalClosure;
            claims[0] = generated[0].?.claims[generated[0].?.claims.len - 1];
            try columns.appendSlice(a, generated[0].?.columns);
        }
        const stage = self.backend.trace.stage();
        const tree = try stage.commit(stage.context, a, .{ .scope = self.scope, .tree_index = 2, .config = self.config(), .columns = columns.items });
        return .{ .tree = tree, .claims = claims, .main = if (self.backend.replay_main) main else null };
    }
    fn config(self: *const Owner) @FieldType(S.Prepare, "config") {
        return self.pcs_config;
    }
    fn runMain(self: *Owner, fixed: []const D.Column) !void {
        var job = MainJob{ .owner = self, .fixed = fixed };
        if (self.backend.service.submit(self.backend.service.session, MainJob.callback, &job) != 0) return job.failure orelse error.DeviceTruthKernelFailed;
    }
    fn releaseRawChecked(self: *Owner) !void {
        var cleanup = Cleanup{ .owner = self };
        if (self.backend.service.submit(self.backend.service.session, Cleanup.callback, &cleanup) != 0) return error.DeviceTruthReleaseFailed;
        self.allocator.free(self.raw_columns);
        self.raw_columns = &.{};
    }
    fn releaseRaw(self: *Owner) void {
        self.releaseRawChecked() catch {};
    }
    fn destroy(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        self.releaseRaw();
        var cleanup = CompactCleanup{ .owner = self };
        _ = self.backend.service.submit(self.backend.service.session, CompactCleanup.callback, &cleanup);
        self.allocator.free(self.inputs);
        self.allocator.free(self.fixed);
        const a = self.allocator;
        a.destroy(self);
    }
};
const Cleanup = struct {
    owner: *Owner,
    fn callback(raw: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Cleanup = @ptrCast(@alignCast(data.?));
        for (&self.owner.raw_leases) |*lease| if (lease.*) |*value| {
            if (self.owner.backend.service.lease_release(self.owner.backend.service.session, value) != 0) return 1;
            lease.* = null;
        };
        return self.owner.backend.api.sync(raw);
    }
};
const Promote = struct {
    owner: *Owner,
    previous: D.Scope,
    fn callback(_: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Promote = @ptrCast(@alignCast(data.?));
        const old = @import("pcs_scope.zig").identity(self.previous);
        const current = @import("pcs_scope.zig").identity(self.owner.scope);
        return self.owner.backend.rebind(self.owner.backend.service.session, &self.owner.compact.?, &old, &current);
    }
};
const CompactCleanup = struct {
    owner: *Owner,
    fn callback(raw: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *CompactCleanup = @ptrCast(@alignCast(data.?));
        if (self.owner.compact) |*lease| {
            if (self.owner.backend.service.lease_release(self.owner.backend.service.session, lease) != 0) return 1;
            self.owner.compact = null;
        }
        return self.owner.backend.api.sync(raw);
    }
};
const MainJob = struct {
    owner: *Owner,
    fixed: []const D.Column,
    failure: ?anyerror = null,
    fn callback(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *MainJob = @ptrCast(@alignCast(data.?));
        // Replay keeps the compact input live; only the initial witness opens
        // a new node epoch. A replay must retain that existing attribution.
        var observed = @import("allocation_observer.zig").Range.begin(&self.owner.backend.service.library, raw, self.owner.scope, 2, if (self.owner.compact != null) .native_main_replay else .main_witness, 0) catch |err| {
            self.failure = err;
            return 1;
        };
        defer observed.deinit();
        self.run(raw, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn run(self: *MainJob, raw: *anyopaque, token: u64) !void {
        const o = self.owner;
        const b = o.backend;
        const a = o.allocator;
        const log = try logSize(o.truth);
        const n = try rows(log);
        const width = try mainWidth(o.truth);
        if (try std.math.mul(usize, try std.math.mul(usize, width, n), 4) > o.budget) return error.DeviceTruthBudgetExceeded;
        var context = SC.Context{ .session = b.service.session, .native_context = raw, .token = token, .scope = @import("pcs_scope.zig").identity(o.scope), .api = &b.api };
        defer context.active = false;
        if (comptime @hasDecl(Native.Context, "immutableFixed")) {
            // Witness generation uses no FIXED columns; avoid provisional MAIN aliases.
            if (!std.mem.allEqual(u8, &o.scope.main, 0)) _ = try b.service.immutableFixed(raw, o.scope, self.fixed);
        }
        if (o.compact == null) {
            o.compact = try context.allocate(o.compact_words, 0);
            try checked(b.api.upload(raw, @ptrCast(o.compact.?.words.?), o.inputs.ptr, o.inputs.len * 4));
        }
        const input = o.compact.?;
        var status = try context.allocate(1, 0);
        var status_live = true;
        errdefer if (status_live) context.release(&status) catch {};
        const zero_status: u32 = 0;
        try checked(b.api.upload(raw, @ptrCast(status.words.?), &zero_status, 4));
        o.raw_leases[0] = try context.allocate(width * n, 0);
        if (o.truth == .keccak) {
            o.raw_leases[1] = try context.allocate(@as(usize, 1) << @intCast(o.truth.keccak.setup.policy.tableLog(.chi)), 0);
            o.raw_leases[2] = try context.allocate(@as(usize, 1) << @intCast(o.truth.keccak.setup.policy.tableLog(.xor5)), 0);
            const packet = Keccak{ .inputs = input.words.?, .main = o.raw_leases[0].?.words.?, .chi = o.raw_leases[1].?.words.?, .xor5 = o.raw_leases[2].?.words.?, .status = status.words.?, .input_words = o.compact_words, .main_words = width * n, .calls = o.truth.count(), .first_id = o.truth.first(), .log = log, .policy = if (o.truth.keccak.setup.policy == .triple_v2) 1 else 0 };
            try context.join();
            try checked(b.keccak(raw, 1, &packet));
        } else if (o.truth == .arith256_mod) {
            o.raw_leases[1] = try context.allocate(256, 0);
            const packet = Arith{ .inputs = input.words.?, .main = o.raw_leases[0].?.words.?, .byte_counts = o.raw_leases[1].?.words.?, .status = status.words.?, .input_words = o.compact_words, .main_words = width * n, .calls = o.truth.count(), .first_id = o.truth.first(), .log = log };
            try context.join();
            try checked((b.arith orelse return error.MissingDeviceTruthSymbol)(raw, 1, &packet));
        } else if (o.truth == .secp_row or o.truth == .curve) {
            o.raw_leases[1] = try context.allocate(256, 0);
            const packet = Secp{ .inputs = input.words.?, .main = o.raw_leases[0].?.words.?, .byte_counts = o.raw_leases[1].?.words.?, .status = status.words.?, .input_words = o.compact_words, .main_words = width * n, .calls = o.truth.count(), .first_id = o.truth.first(), .log = log, .kind = if (o.truth == .curve) @intFromEnum(o.truth.curve.setup.op) - 5 else if (o.truth.secp_row.setup.kind == .add) 0 else 1 };
            try context.join();
            try checked(((if (o.truth == .curve) b.curve else b.secp) orelse return error.MissingDeviceTruthSymbol)(raw, 1, &packet));
        } else {
            const packet = Sha{ .inputs = input.words.?, .main = o.raw_leases[0].?.words.?, .status = status.words.?, .input_words = o.compact_words, .main_words = width * n, .calls = o.truth.count(), .first_id = o.truth.first(), .log = log };
            try context.join();
            try checked((b.sha orelse return error.MissingDeviceTruthSymbol)(raw, 1, &packet));
        }
        try context.join();
        var verdict: u32 = 0;
        try checked(b.api.download(raw, &verdict, @ptrCast(status.words.?), 4));
        try context.join();
        if (verdict != 0) return error.DeviceTruthWitnessRejected;
        try context.release(&status);
        status_live = false;
        try context.join();
        const total = width + @as(usize, if (o.truth == .keccak) 2 else 0);
        o.raw_columns = try a.alloc(D.TraceColumn, total);
        for (o.raw_columns[0..width], 0..) |*column, i| column.* = evalColumn(o.raw_leases[0].?, i * n, log);
        if (o.truth == .keccak) {
            o.raw_columns[width] = evalColumn(o.raw_leases[1].?, 0, o.truth.keccak.setup.policy.tableLog(.chi));
            o.raw_columns[width + 1] = evalColumn(o.raw_leases[2].?, 0, o.truth.keccak.setup.policy.tableLog(.xor5));
        }
    }
};
fn evalColumn(lease: N.Lease, offset: usize, log: u32) D.TraceColumn {
    return .{ .log_size = log, .encoding = .evaluations, .device = .{ .words = lease.words.? + offset, .count = @as(u64, 1) << @intCast(log), .context_token = lease.context_token, .generation = lease.generation } };
}
fn compactInputs(a: std.mem.Allocator, request: S.Prepare) ![]u32 {
    const words: usize = if (request.truth == .keccak) 50 else if (request.truth == .sha256) 24 else if (request.truth == .arith256_mod) 40 else if (request.truth == .curve) curveWords(request.truth.curve.setup.op) else if (request.truth.secp_row.setup.kind == .add) 48 else 24;
    const output = try a.alloc(u32, try std.math.mul(usize, request.truth.count(), words));
    errdefer a.free(output);
    const begin: usize = request.truth.first() - 1;
    const end = begin + request.truth.count();
    var offset: usize = 0;
    var written: usize = 0;
    if (request.truth == .keccak) {
        for (request.advice.keccak) |chunk| for (chunk) |call| {
            if (offset >= begin and offset < end) {
                for (call.before, 0..) |value, i| {
                    output[written * 50 + 2 * i] = @truncate(value);
                    output[written * 50 + 2 * i + 1] = @truncate(value >> 32);
                }
                written += 1;
            }
            offset += 1;
        };
        for (request.advice.sponge) |chunk| for (chunk.inputs) |state| {
            if (offset >= begin and offset < end) {
                for (state, 0..) |value, i| {
                    output[written * 50 + 2 * i] = @truncate(value);
                    output[written * 50 + 2 * i + 1] = @truncate(value >> 32);
                }
                written += 1;
            }
            offset += 1;
        };
    } else {
        const chunks = if (request.truth == .sha256) request.advice.sha256 else if (request.truth == .arith256_mod) request.advice.arith256_mod else if (request.truth == .curve) return compactCurve(request, output) else return compactSecp(a, request, output);
        for (chunks) |chunk| for (chunk) |call| {
            if (offset >= begin and offset < end) {
                for (call.before[0 .. words / 2], 0..) |value, i| {
                    output[written * words + 2 * i] = @truncate(value);
                    output[written * words + 2 * i + 1] = @truncate(value >> 32);
                }
                written += 1;
            }
            offset += 1;
        };
    }
    if (written != request.truth.count()) return error.InvalidDeviceTruthSpan;
    return output;
}

fn curveWords(op: A.crypto.curves.spec.Op) usize {
    return switch (op) {
        inline else => |kind| A.crypto.curves.Layout(kind).PACKET_BYTES / 4,
    };
}
fn compactCurve(request: S.Prepare, output: []u32) ![]u32 {
    const index = @intFromEnum(request.truth.curve.setup.op) - 5;
    const words = curveWords(request.truth.curve.setup.op);
    const begin: usize = request.truth.first() - 1;
    const end = begin + request.truth.count();
    var offset: usize = 0;
    var written: usize = 0;
    for (request.advice.curves) |chunk| for (chunk[index]) |call| {
        if (offset >= begin and offset < end) {
            for (call.before[0 .. words / 2], 0..) |word, i| {
                output[written * words + 2 * i] = @truncate(word);
                output[written * words + 2 * i + 1] = @truncate(word >> 32);
            }
            written += 1;
        }
        offset += 1;
    };
    if (written != request.truth.count()) return error.InvalidDeviceTruthSpan;
    return output;
}

fn compactSecp(a: std.mem.Allocator, request: S.Prepare, output: []u32) ![]u32 {
    _ = a;
    const kind: usize = if (request.truth.secp_row.setup.kind == .add) 0 else 1;
    const words: usize = if (kind == 0) 48 else 24;
    const begin: usize = request.truth.first() - 1;
    const end = begin + request.truth.count();
    var offset: usize = 0;
    var written: usize = 0;
    for (request.advice.secp) |chunk| for (chunk[kind]) |call| {
        if (offset >= begin and offset < end) {
            for (call.before[0 .. words / 2], 0..) |word, i| {
                output[written * words + 2 * i] = @truncate(word);
                output[written * words + 2 * i + 1] = @truncate(word >> 32);
            }
            written += 1;
        }
        offset += 1;
    };
    if (written != request.truth.count()) return error.InvalidDeviceTruthSpan;
    return output;
}

test "device truth source factory exposes a typed owner without a CPU witness fallback" {
    var context: Context = undefined;
    const stage = context.stage();
    try std.testing.expectEqual(@intFromPtr(&context), @intFromPtr(stage.context));
    try std.testing.expect(@intFromPtr(stage.prepare) != 0);
    _ = Context.init;
}

test "truth replay retention is compact and nonreplay still charges native MAIN" {
    const Setup = @typeInfo(@FieldType(@FieldType(Truth, "curve"), "setup")).pointer.child;
    const ops = [_]A.crypto.curves.spec.Op{ .bn254_g1_add, .bn254_g1_double, .bn254_fp2_mul, .bls12_381_fp2_mul, .arith384_mont };
    inline for (ops) |op| {
        var setup = Setup{ .allocator = std.testing.allocator, .op = op, .log = 8, .fixed = &.{}, .key = undefined };
        const truth = Truth{ .curve = .{ .setup = &setup, .first_id = 1, .calls = 9 } };
        const replay = try retainedForTruth(std.testing.allocator, truth, true);
        const native = try retainedForTruth(std.testing.allocator, truth, false);
        const expected_main = A.crypto.curves.Layout(op).MAIN * 256 * 4;
        try std.testing.expectEqual(@as(usize, A.crypto.curves.Layout(op).PACKET_BYTES * 9), replay.compact_input_bytes);
        try std.testing.expectEqual(@as(usize, 0), replay.kept_device_bytes);
        try std.testing.expectEqual(@as(usize, expected_main), native.kept_device_bytes);
        try std.testing.expectEqual(try replay.total(replay.compact_input_bytes, expected_main) + expected_main, try native.total(replay.compact_input_bytes, expected_main));
        setup.log = 9;
        const taller = try retainedForTruth(std.testing.allocator, truth, true);
        try std.testing.expectEqual(try replay.total(replay.compact_input_bytes, expected_main), try taller.total(replay.compact_input_bytes, 2 * expected_main));
    }
}

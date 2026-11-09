//! Independently constructed source inventory for the closed detached route.
//! Keys and requests come from pinned receiver policy/source construction;
//! wire declarations cannot select these sources. This returns metadata and
//! pending proof obligations, never execution acceptance or a security claim.
//! CPU permutation spans are deterministic planner metadata, not a claim that
//! the frontier authenticates each CPU's permutation count. Physical authority
//! is per-CPU CALL/OWNER/clock/epoch plus aggregate detached P and global IO.
//! No semantic acceptance or mass bound relies on that advisory partition.
const std = @import("std");
const P = @import("../../word16_global_execution/services/protocol.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const T = @import("../../word16_global_execution/services/types.zig");
const Base = @import("../pure_p2_manifest.zig");
const M = @import("manifest.zig");
const Frame = @import("frame.zig");
const Kio = @import("kio_plan.zig");
const Mass = @import("mass.zig");
const CpuKey = @import("key.zig").Key;
const DetachedKey = @import("../sponge_local_gkr/key.zig").Key;
const Geometry = @import("../sponge_local_gkr/authority.zig").Geometry;
const Truth = @import("../pure_p2_truth_worker.zig");
const TruthLocal = @import("../truth_local_gkr/worker.zig");
const Tower = @import("../pure_p2_op_inventory.zig").MillerDeclaration;
const Profile = @import("../pure_p2_worker_protocol.zig").Profile;
pub const Cpu = struct { setup: *const R.CpuSetup, request: P.Request, span: T.OpTowerSpan, key: *const CpuKey };
pub const Detached = struct { key: *const DetachedKey, geometry: Geometry };
pub const Catalog = struct { truth: R.Truth, key: *const Truth.Key, local_key: ?*const TruthLocal.Key = null };
pub const Inventory = struct {
    allocator: std.mem.Allocator,
    workers: []M.Expected,
    rosters: []Frame.Roster,
    first_ids: [][T.FAMILIES]u32,
    kio: Kio.Plan,
    execution: [32]u8,
    cpu_count: usize,
    detached_count: usize,
    truth_count: usize,
    pub fn deinit(self: *Inventory) void {
        for (self.rosters) |*roster| roster.deinit();
        self.allocator.free(self.rosters);
        self.allocator.free(self.workers);
        self.allocator.free(self.first_ids);
        self.kio.deinit();
        self.* = undefined;
    }
    pub fn init(a: std.mem.Allocator, profile: Profile, cpus: []const Cpu, detached: []const Detached, catalog: []const Catalog, towers: []const Tower, expected: P.Expected) !Inventory {
        const count = try std.math.add(usize, try std.math.add(usize, cpus.len, detached.len), try std.math.add(usize, catalog.len, towers.len));
        if (cpus.len == 0 or count > Base.MAX_WORKERS or profile == .reference_b2_q24_p0) return error.DetachedInventoryRoster;
        const setups = try a.alloc(*const R.CpuSetup, cpus.len);
        defer a.free(setups);
        const requests = try a.alloc(P.Request, cpus.len);
        defer a.free(requests);
        const spans = try a.alloc(T.OpTowerSpan, cpus.len);
        defer a.free(spans);
        const logs = try a.alloc(u32, cpus.len);
        defer a.free(logs);
        for (cpus, setups, requests, spans, logs) |cpu, *setup, *request, *span, *log| {
            if (cpu.key.profile != profile) return error.InvalidOpNativeProfile;
            try cpu.key.require(cpu.setup);
            setup.* = cpu.setup;
            request.* = cpu.request;
            span.* = cpu.span;
            log.* = cpu.key.frontier_log;
        }
        const truths = try a.alloc(R.Truth, catalog.len);
        defer a.free(truths);
        for (catalog, truths) |source, *truth| truth.* = source.truth;
        _ = try P.admitForOpDetached(a, setups, truths, requests, expected, spans, logs);
        var kio = try Kio.Plan.init(a, requests, .{});
        errdefer kio.deinit();
        try kio.requireRequests(requests);
        const ids = try a.alloc([T.FAMILIES]u32, cpus.len);
        errdefer a.free(ids);
        for (ids, 0..) |*first, ordinal| first.* = try P.firstIds(requests, ordinal);
        try kio.requireFirstIds(ids);
        const truth_spans = try a.alloc(Kio.Span, catalog.len);
        defer a.free(truth_spans);
        var n_keccak: usize = 0;
        for (catalog) |source| if (source.truth == .keccak) {
            truth_spans[n_keccak] = .{ .first = source.truth.first(), .count = source.truth.count() };
            n_keccak += 1;
        };
        try kio.requireTruthCoverage(truth_spans[0..n_keccak]);
        // The detached workers form one exact partition of the canonical
        // Sponge permutation suffix. Wire matches each call's original CPU
        // ordinal/epoch and full OWNER tuple, not a new per-worker numbering.
        var call_total: u64 = 0;
        for (requests) |request| call_total = try std.math.add(u64, call_total, request.sponge.calls);
        // Absence is exact: never fabricate a zero-call detached provider.
        if ((detached.len == 0) != (call_total == 0 and kio.total_sponge == 0)) return error.DetachedInventoryCoverage;
        var next: u64 = kio.detached_first;
        var covered: u64 = 0;
        var calls: u64 = 0;
        for (detached) |source| {
            const geometry = source.geometry;
            if (!geometry.detached or source.key.profile != profile or geometry.first_id != next) return error.DetachedInventoryCoverage;
            try source.key.require(geometry);
            _ = try geometry.instances();
            next = try std.math.add(u64, next, geometry.permutations);
            covered = try std.math.add(u64, covered, geometry.permutations);
            calls = try std.math.add(u64, calls, geometry.calls);
            if (covered > kio.total_sponge or calls > call_total) return error.DetachedInventoryCoverage;
        }
        if (covered != kio.total_sponge or calls != call_total) return error.DetachedInventoryCoverage;
        var tower_calls: u64 = 0;
        for (spans) |span| tower_calls = try std.math.add(u64, tower_calls, span.calls);
        var next_tower: u64 = 1;
        for (towers) |source| {
            if (source.key.profile != profile or source.span.calls == 0 or source.span.first_id != next_tower) return error.DetachedInventoryTowerCoverage;
            _ = try source.key.expected(source.span, 0);
            next_tower = try std.math.add(u64, next_tower, source.span.calls);
        }
        if (next_tower - 1 != tower_calls) return error.DetachedInventoryTowerCoverage;
        const workers = try a.alloc(M.Expected, count);
        errdefer a.free(workers);
        const rosters = try a.alloc(Frame.Roster, cpus.len);
        errdefer a.free(rosters);
        var made: usize = 0;
        errdefer for (rosters[0..made]) |*roster| roster.deinit();
        for (cpus, rosters, workers[0..cpus.len], ids, 0..) |cpu, *roster, *worker, first, ordinal| {
            roster.* = try Frame.Roster.init(a, cpu.setup, cpu.request.sponge.calls, cpu.key.frontier_log, cpu.request.base.epoch, @intCast(ordinal));
            made += 1;
            worker.* = .{ .authority = .{
                .kind = .sponge_cpu,
                .ordinal = @intCast(ordinal),
                .profile = profile,
                .fixed_identity = cpu.key.identity,
                .fixed = cpu.key.root,
                .statement = try cpu.key.statement(cpu.setup, cpu.request, first, cpu.span, @intCast(ordinal)),
                .mass = try Mass.cpu(cpu.setup, cpu.request, cpu.span),
                .global_relations = .{ .ram = true, .kio = cpu.setup.bridges.keccak != null, .wire = @import("../../word16_global_execution/services/gkr_local/cpu_worker.zig").wirePresent(cpu.setup.bridges) or cpu.span.calls != 0 or cpu.request.sponge.calls != 0 },
            }, .cpu = .{ .epoch = std.math.cast(u16, cpu.request.base.epoch) orelse return error.SpongeCpuGeometry, .calls = cpu.request.sponge.calls, .instances = roster.instances } };
        }
        var ordinal = cpus.len;
        for (detached) |source| {
            workers[ordinal] = .{ .authority = .{ .kind = .detached, .ordinal = @intCast(ordinal), .profile = profile, .fixed_identity = source.key.identity, .fixed = source.key.root, .statement = try source.key.statementDetached(source.geometry), .mass = try Mass.detached(source.geometry), .global_relations = .{ .ram = true, .kio = true, .wire = true } } };
            ordinal += 1;
        }
        for (catalog) |source| {
            try source.key.require(source.truth);
            if (source.key.profile != profile) return error.InvalidOpNativeProfile;
            const authority = if (source.local_key) |local| blk: {
                try local.require(source.truth);
                if (local.base.profile != profile or !std.mem.eql(u8, &local.base.identity, &source.key.identity) or !std.mem.eql(u8, &local.base.root, &source.key.root)) return error.InvalidOpTruthLocalInventory;
                break :blk try local.expected(source.truth, @intCast(ordinal));
            } else try source.key.expected(source.truth, @intCast(ordinal));
            workers[ordinal] = .{ .authority = try catalogAuthority(authority) };
            ordinal += 1;
        }
        for (towers) |source| {
            const authority = if (source.local_key) |local| blk: {
                _ = try local.geometry(source.span);
                if (local.base.profile != profile or !std.mem.eql(u8, &local.base.identity, &source.key.identity) or !std.mem.eql(u8, &local.base.root, &source.key.root)) return error.OpMillerSourceSuitePolicy;
                break :blk try local.expected(source.span, @intCast(ordinal));
            } else try source.key.expected(source.span, @intCast(ordinal));
            workers[ordinal] = .{ .authority = try catalogAuthority(authority) };
            ordinal += 1;
        }
        try M.validateExpected(workers);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("op-detached-sponge-complete-execution/v1\x00");
        h.update(&profile.identity());
        h.update(&expected.program_identity);
        h.update(&expected.admission.image_identity);
        for ([_]u64{ expected.admission.initial_pc, expected.total_steps, expected.final_pc }) |word| mix(&h, word);
        for (expected.admission.initial_registers) |word| mix(&h, word);
        for (expected.final_registers) |word| mix(&h, word);
        var writer = @import("../pure_p2_native.zig").ReceiptWriter{};
        kio.emit(&writer);
        h.update(&try writer.finish());
        for (workers) |worker| {
            h.update(&worker.authority.statement);
            h.update(&worker.authority.fixed_identity);
            h.update(&worker.authority.fixed);
        }
        return .{ .allocator = a, .workers = workers, .rosters = rosters, .first_ids = ids, .kio = kio, .execution = h.finalResult(), .cpu_count = cpus.len, .detached_count = detached.len, .truth_count = catalog.len };
    }
};
fn catalogAuthority(source: Base.Expected) !M.Authority {
    if (source.local_instances != null) return error.DetachedInventorySourceKind;
    const kind: M.Kind = switch (source.kind) {
        .cpu => return error.DetachedInventorySourceKind,
        .keccak => .keccak,
        .secp_add => .secp_add,
        .secp_double => .secp_double,
        .delegation => .delegation,
    };
    return .{ .kind = kind, .ordinal = source.ordinal, .profile = source.profile, .fixed_identity = source.fixed_identity, .fixed = source.fixed, .statement = source.statement, .mass = source.mass, .global_relations = source.global_relations };
}
fn mix(hash: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    hash.update(&bytes);
}

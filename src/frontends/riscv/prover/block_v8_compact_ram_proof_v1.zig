//! One compact global RAM original with separately anchored initial/final
//! boundaries and exact ordering-range requests. Tuple canonicality is NOT
//! proved here: publication must freshly verify the local execution originals
//! and late bridge, then close their transition sum against this proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const E = @import("block_v7_execution_epoch_v1.zig");
const Scope = @import("block_v8_compact_ram_scope_v1.zig");
const K = @import("block_v8_compact_ram_kernel_v1.zig");
const C = @import("block_v8_compact_ram_component_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const Range = @import("block_v7_provider_component_v1.zig").For(.range16);
const RangeInteractions = @import("block_v7_window_memory_joint_v1.zig").providerInteractions;
const Placement = @import("block_v7_heterogeneous_components_v1.zig");
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
const RamAdapter = @import("block_v5_word_quotient_adapter_v1.zig").For(C.Spec);
const BoundaryAdapter = @import("block_v5_word_quotient_adapter_v1.zig").For(C.BoundarySpec);
const RangeAdapter = @import("block_v5_word_quotient_adapter_v1.zig").For(Range);
pub const Policy = Scope.Policy;
pub const production_active = false;
pub const TRACE_TREES = 7;
pub const maps = .{ [_]usize{ 0, 1, 4 }, [_]usize{ 0, 2, 5 }, [_]usize{ 0, 3, 6 } };
pub const Limits = struct { max_events: u32 = 1 << 24, max_boundary_rows: u32 = 8_000_032, max_row_log: u32 = 24, max_matrix_bytes: usize = 2 << 30, max_live_bytes: usize = 12 << 30 };
pub const Claims = struct { ram: [6]R.Q, boundary: [2]R.Q, ranges: [2]R.Q };
pub const Open = struct { transition: R.Q, event_count: u32, scope: enum { conditional_compact_memory } = .conditional_compact_memory };
pub const Proof = struct {
    a: std.mem.Allocator,
    budget: *engine.host_budget_allocator.SharedHostBudget,
    event_count: u32,
    roots: [4][32]u8,
    claims: Claims,
    stark: S.Proof,
    pub fn deinit(self: *Proof) void {
        const budget = self.budget;
        self.stark.deinit(self.a);
        budget.destroy();
        self.* = undefined;
    }
};
fn checkResources(policy: Policy, limits: Limits) !void {
    try policy.validate();
    if (limits.max_live_bytes == 0 or policy.event_count > limits.max_events or policy.window.selection.?.addresses.len > limits.max_boundary_rows or policy.ramLog() > limits.max_row_log or policy.boundaryLog() > limits.max_row_log) return error.CompactRamResourceLimit;
}
/// Pure accounting only. Every input scalar must first be authenticated by
/// this original STARK; its transition remains open for the verified bridge.
pub fn closeClaims(event_count: u32, claims: Claims) !Open {
    inline for (.{ claims.ram, claims.boundary, claims.ranges }) |group| for (group) |claim| for (claim.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.NonCanonicalCompactRamClaim;
    if (!claims.ram[1].add(claims.boundary[0]).isZero() or !claims.ram[2].add(claims.boundary[1]).isZero()) return error.UnclosedCompactRamBoundaries;
    if (!claims.ram[3].add(claims.ram[4]).add(claims.ranges[0]).isZero() or !claims.ram[5].eql(claims.ranges[1])) return error.UnclosedCompactRamRanges;
    const requests = try T.natural(claims.ram[5]);
    if (requests > @as(u64, event_count) * 3) return error.InvalidCompactRamRangeCensus;
    return .{ .transition = claims.ram[0], .event_count = event_count };
}
fn rangeAdd(counts: []u32, value: u32) !void {
    if (value >= counts.len or counts[value] >= core.fields.m31.Modulus - 1) return error.InvalidCompactRamRange;
    counts[value] += 1;
}
fn boundaryIndex(addresses: []const u32, address: u32) !usize {
    var low: usize = 0;
    var high = addresses.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (addresses[middle] < address) low = middle + 1 else high = middle;
    }
    if (low == addresses.len or addresses[low] != address) return error.MissingCompactRamBoundaryAddress;
    return low;
}
fn afterValue(window: *const @import("block_v7_real_window_policy_v2.zig").Owned, address: u32, before: u32) u32 {
    var low: usize = 0;
    var high = window.changes.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (window.changes[middle].address < address) low = middle + 1 else high = middle;
    }
    return if (low < window.changes.len and window.changes[low].address == address) window.changes[low].after else before;
}
pub fn fixedRam(a: std.mem.Allocator, policy: Policy, maximum: usize) !T.Matrix {
    var matrix = try T.Matrix.init(a, policy.ramLog(), 3, maximum);
    errdefer matrix.deinit();
    for (0..policy.event_count) |i| {
        matrix.set(0, i, R.M.one());
        matrix.set(1, i, if (i == 0) R.M.one() else R.M.zero());
        matrix.set(2, i, if (i + 1 == policy.event_count) R.M.one() else R.M.zero());
    }
    return matrix;
}
pub fn fixedBoundary(a: std.mem.Allocator, policy: Policy, maximum: usize) !T.Matrix {
    const addresses = policy.window.selection.?.addresses;
    var matrix = try T.Matrix.init(a, policy.boundaryLog(), 8, maximum);
    errdefer matrix.deinit();
    for (addresses, 0..) |address, i| {
        if (address & 3 != 0 or address >= 1 << 30 or (i > 0 and addresses[i - 1] >= address)) return error.InvalidCompactRamBoundaryAddress;
        const initial = try policy.window.initial.find(address);
        // Endpoint range validity does NOT grant write/read permission. The
        // independently derived ELF/snapshot policy remains authoritative.
        if (!initial.allowed or initial.private) return error.ForbiddenCompactRamAddress;
        const before = initial.value;
        const after = afterValue(policy.window, address, before);
        const row = [8]R.M{ R.M.one(), R.M.fromCanonical(address & 65535), R.M.fromCanonical(address >> 16), R.M.fromCanonical(before & 65535), R.M.fromCanonical(before >> 16), R.M.fromCanonical(after & 65535), R.M.fromCanonical(after >> 16), R.M.fromCanonical(@intFromBool(before != after)) };
        for (row, 0..) |cell, column| matrix.set(column, i, cell);
    }
    return matrix;
}
pub const Fixed = struct {
    ram: T.Matrix,
    boundary: T.Matrix,
    ranges: T.Matrix,
    a: std.mem.Allocator,
    pub fn init(a: std.mem.Allocator, policy: Policy, limits: Limits) !Fixed {
        var ram = try fixedRam(a, policy, limits.max_matrix_bytes);
        errdefer ram.deinit();
        var boundary = try fixedBoundary(a, policy, limits.max_matrix_bytes);
        errdefer boundary.deinit();
        var ranges = try T.Matrix.init(a, 16, 2, limits.max_matrix_bytes);
        errdefer ranges.deinit();
        for (0..65536) |i| {
            ranges.set(0, i, R.M.one());
            ranges.set(1, i, R.M.fromCanonical(@intCast(i)));
        }
        return .{ .ram = ram, .boundary = boundary, .ranges = ranges, .a = a };
    }
    pub fn columns(self: *const Fixed) ![]Column {
        return std.mem.concat(self.a, Column, &.{ self.ram.columns, self.boundary.columns, self.ranges.columns });
    }
    pub fn deinit(self: *Fixed) void {
        self.ranges.deinit();
        self.boundary.deinit();
        self.ram.deinit();
    }
};
pub fn Components(comptime proving: bool) type {
    const Placed = Placement.For(maps, TRACE_TREES, proving);
    return struct {
        a: std.mem.Allocator,
        ram: RamAdapter,
        boundary: BoundaryAdapter,
        ranges: RangeAdapter,
        placed: ?Placed = null,
        pub fn init(a: std.mem.Allocator, policy: Policy, drawn: E.Drawn, claims: Claims) !*@This() {
            const self = try a.create(@This());
            errdefer a.destroy(self);
            self.* = .{ .a = a, .ram = .{ .log_size = policy.ramLog(), .spec = .{ .challenges = C.fromEpoch(drawn), .sums = claims.ram } }, .boundary = .{ .log_size = policy.boundaryLog(), .spec = .{ .challenge = .from(drawn.word.initial), .sums = claims.boundary } }, .ranges = .{ .log_size = 16, .spec = .{ .challenges = drawn.memory, .sums = claims.ranges } } };
            self.placed = if (proving)
                try Placed.init(a, .{ &.{self.ram.asProverComponent()}, &.{self.boundary.asProverComponent()}, &.{self.ranges.asProverComponent()} }, .{ 3, 8, 2 })
            else
                try Placed.init(a, .{ &.{self.ram.asVerifierComponent()}, &.{self.boundary.asVerifierComponent()}, &.{self.ranges.asVerifierComponent()} }, .{ 3, 8, 2 });
            return self;
        }
        pub fn deinit(self: *@This()) void {
            if (self.placed) |*placed| placed.deinit(self.a);
            self.a.destroy(self);
        }
    };
}
const RamTerms = struct {
    ch: C.Challenges(R.Q),
    pub fn termsAt(self: @This(), matrix: T.Matrix, logical: usize) ![6]R.Term(R.Q) {
        return C.terms(R.Q, self.ch, matrix.row(3, 0, logical), matrix.row(12, 3, logical), matrix.row(12, 3, if (logical == 0) matrix.size() - 1 else logical - 1));
    }
};
const BoundaryTerms = struct {
    challenge: R.Relation(R.Q, 5),
    pub fn termsAt(self: @This(), matrix: T.Matrix, logical: usize) ![2]R.Term(R.Q) {
        return C.BoundarySpec.termsFor(R.Q, self.challenge, matrix.row(8, 0, logical), matrix.row(1, 8, logical));
    }
};
pub const Stage = struct {
    a: std.mem.Allocator,
    budget: *engine.host_budget_allocator.SharedHostBudget,
    policy: Policy,
    limits: Limits,
    ram: T.Matrix,
    boundary: T.Matrix,
    ranges: T.Matrix,
    scheme: Scheme,
    roots: [4][32]u8,
    owns_scheme: bool = true,
    consumed: bool = false,
    pub fn init(backing: std.mem.Allocator, policy: Policy, events: []const K.Transition, limits: Limits) !*Stage {
        try checkResources(policy, limits);
        if (events.len != policy.event_count) return error.InvalidCompactRamEventCount;
        const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(backing, limits.max_live_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        const self = try a.create(Stage);
        errdefer a.destroy(self);
        var fixed = try Fixed.init(a, policy, limits);
        defer fixed.deinit();
        var ram = try T.Matrix.init(a, policy.ramLog(), 15, limits.max_matrix_bytes);
        errdefer ram.deinit();
        for (0..3) |i| @memcpy(@constCast(ram.columns[i].values), fixed.ram.columns[i].values);
        var boundary = try T.Matrix.init(a, policy.boundaryLog(), 9, limits.max_matrix_bytes);
        errdefer boundary.deinit();
        for (0..8) |i| @memcpy(@constCast(boundary.columns[i].values), fixed.boundary.columns[i].values);
        const counts = try a.alloc(u32, 65536);
        defer a.free(counts);
        @memset(counts, 0);
        const addresses = policy.window.selection.?.addresses;
        for (events, 0..) |event, i| {
            const previous: ?K.Transition = if (i == 0) null else events[i - 1];
            const row = try K.construct(.{ .cohort_count = policy.cohortCount() }, event, previous);
            try K.checkRanges(row);
            for (row, 0..) |cell, column| ram.set(3 + column, i, cell);
            const index = try boundaryIndex(addresses, event.address);
            boundary.set(8, index, R.M.one());
            if (i != 0) {
                if (row[K.Col.same].isZero()) {
                    try rangeAdd(counts, row[K.Col.gap_low].v);
                    try rangeAdd(counts, row[K.Col.gap_high].v);
                    try rangeAdd(counts, row[K.Col.gap_high].v * 16);
                } else try rangeAdd(counts, row[K.Col.clock_gap].v);
            }
        }
        var ranges = try T.range16(a, counts, limits.max_matrix_bytes);
        errdefer ranges.deinit();
        var scheme = try Scheme.init(a, policy.config);
        errdefer scheme.deinit(a);
        scheme.setCoefficientRetentionPolicy(.always);
        const fixed_columns = try fixed.columns();
        defer a.free(fixed_columns);
        var channel = S.Channel{};
        channel.mixU32s(&.{ Scope.TAG, Scope.VERSION, 4 });
        channel.mixRoot(try policy.digest());
        try scheme.commitBorrowedStreaming(a, fixed_columns, 8, &channel);
        try scheme.commitBorrowedStreaming(a, ram.columns[3..], 8, &channel);
        try scheme.commitBorrowedStreaming(a, boundary.columns[8..], 8, &channel);
        try scheme.commitBorrowedStreaming(a, ranges.columns[2..], 8, &channel);
        const roots = [4][32]u8{ scheme.trees.items[0].root(), scheme.trees.items[1].root(), scheme.trees.items[2].root(), scheme.trees.items[3].root() };
        self.* = .{ .a = a, .budget = budget, .policy = policy, .limits = limits, .ram = ram, .boundary = boundary, .ranges = ranges, .scheme = scheme, .roots = roots };
        return self;
    }
    pub fn entry(self: *const Stage) !E.Entry {
        return self.policy.entry(self.roots);
    }
    pub fn deinit(self: *Stage) void {
        const a = self.a;
        const budget = self.budget;
        if (self.owns_scheme) self.scheme.deinit(a);
        self.ranges.deinit();
        self.boundary.deinit();
        self.ram.deinit();
        a.destroy(self);
        budget.destroy();
    }
    pub fn proveConditional(self: *Stage, epoch: E.Epoch, roster: []const E.Entry) !Proof {
        if (self.consumed or !self.owns_scheme) return error.InvalidCompactRamPhase;
        try self.policy.requireEpoch(epoch, roster, self.roots);
        self.consumed = true;
        const a = self.a;
        const drawn = try epoch.draw(a);
        var ram = try T.interactions(6, a, self.ram, RamTerms{ .ch = C.fromEpoch(drawn) }, self.limits.max_matrix_bytes);
        defer ram.deinit();
        var boundary = try T.interactions(2, a, self.boundary, BoundaryTerms{ .challenge = .from(drawn.word.initial) }, self.limits.max_matrix_bytes);
        defer boundary.deinit();
        var ranges = try RangeInteractions(.range16, a, self.ranges, drawn.memory, self.limits.max_matrix_bytes);
        defer ranges.deinit();
        const claims = Claims{ .ram = ram.sums, .boundary = boundary.sums, .ranges = ranges.sums };
        _ = try closeClaims(self.policy.event_count, claims);
        var channel = drawn.channel;
        try Scope.recordClaims(&channel, epoch, self.roots, claims.ram, claims.boundary, claims.ranges);
        const context = try Components(true).init(a, self.policy, drawn, claims);
        defer context.deinit();
        for ([_][]const Column{ ram.matrix.columns, boundary.matrix.columns, ranges.matrix.columns }) |columns| try self.scheme.commitBorrowedStreaming(a, columns, 8, &channel);
        self.owns_scheme = false;
        const stark = try engine.prove.prove(Cpu, S.Hasher, S.MerkleChannel, a, context.placed.?.handles, &channel, self.scheme);
        return .{ .a = a, .budget = self.budget.retain(), .event_count = self.policy.event_count, .roots = self.roots, .claims = claims, .stark = stark };
    }
};
/// Independent receiver-derived fixed commitment. No producer columns or
/// successful receipt enter this key reconstruction.
pub fn requireFixedRoot(backing: std.mem.Allocator, policy: Policy, expected: [32]u8, limits: Limits) !void {
    try checkResources(policy, limits);
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(backing, limits.max_live_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    var fixed = try Fixed.init(a, policy, limits);
    defer fixed.deinit();
    const columns = try fixed.columns();
    defer a.free(columns);
    var scheme = try Scheme.init(a, policy.config);
    defer scheme.deinit(a);
    scheme.setCoefficientRetentionPolicy(.never);
    var channel = S.Channel{};
    try scheme.commitBorrowedStreaming(a, columns, 8, &channel);
    if (!std.meta.eql(scheme.trees.items[0].root(), expected)) return error.UntrustedCompactRamFixedRoot;
}
pub fn verifyConditional(backing: std.mem.Allocator, policy: Policy, epoch: E.Epoch, roster: []const E.Entry, proof: *const Proof, limits: Limits) !Open {
    var captured = try verifyAndCaptureConditional(backing, policy, epoch, roster, proof, limits);
    defer captured.deinit();
    return captured.open;
}
pub const VerifiedCapture = struct {
    a: std.mem.Allocator,
    budget: *engine.host_budget_allocator.SharedHostBudget,
    proof: core.verifier.ProofCapture(S.Hasher),
    final_channel: S.Channel,
    open: Open,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.a);
        self.budget.destroy();
        self.* = undefined;
    }
};
pub fn verifyAndCaptureConditional(backing: std.mem.Allocator, policy: Policy, epoch: E.Epoch, roster: []const E.Entry, proof: *const Proof, limits: Limits) !VerifiedCapture {
    try checkResources(policy, limits);
    if (proof.event_count != policy.event_count or !std.meta.eql(proof.stark.commitment_scheme_proof.config, policy.config)) return error.UntrustedCompactRamProof;
    const roots = proof.stark.commitment_scheme_proof.commitments.items;
    if (roots.len != TRACE_TREES + 1 or !std.meta.eql(roots[0..4].*, proof.roots)) return error.UntrustedCompactRamProof;
    try policy.requireEpoch(epoch, roster, proof.roots);
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(backing, limits.max_live_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    var fixed = try Fixed.init(a, policy, limits);
    defer fixed.deinit();
    const columns = try fixed.columns();
    defer a.free(columns);
    var key = try Scheme.init(a, policy.config);
    defer key.deinit(a);
    var ignored = S.Channel{};
    try key.commitBorrowedStreaming(a, columns, 8, &ignored);
    if (!std.meta.eql(key.trees.items[0].root(), proof.roots[0])) return error.UntrustedCompactRamFixedRoot;
    const drawn = try epoch.draw(a);
    var channel = drawn.channel;
    try Scope.recordClaims(&channel, epoch, proof.roots, proof.claims.ram, proof.claims.boundary, proof.claims.ranges);
    const context = try Components(false).init(a, policy, drawn, proof.claims);
    defer context.deinit();
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, policy.config);
    defer verifier.deinit(a);
    const fixed_logs = try a.alloc(u32, columns.len);
    defer a.free(fixed_logs);
    for (columns, fixed_logs) |column, *log| log.* = column.log_size;
    const Log = struct {
        fn repeat(allocator: std.mem.Allocator, n: usize, log: u32) ![]u32 {
            const value = try allocator.alloc(u32, n);
            @memset(value, log);
            return value;
        }
    };
    const ram_main = try Log.repeat(a, 12, policy.ramLog());
    defer a.free(ram_main);
    const boundary_main = [1]u32{policy.boundaryLog()};
    const range_main = [1]u32{16};
    const ram_interaction = try Log.repeat(a, 24, policy.ramLog());
    defer a.free(ram_interaction);
    const boundary_interaction: [8]u32 = @splat(policy.boundaryLog());
    const range_interaction: [8]u32 = @splat(16);
    const logs = [TRACE_TREES][]const u32{ fixed_logs, ram_main, &boundary_main, &range_main, ram_interaction, &boundary_interaction, &range_interaction };
    for (logs, 0..) |log, tree| try verifier.commit(a, roots[tree], log, if (tree < 4) &ignored else &channel);
    var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
    try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, context.placed.?.handles, &channel, &verifier, &proof.stark, &capture);
    errdefer capture.deinit(a);
    const open = try closeClaims(policy.event_count, proof.claims);
    return .{ .a = a, .budget = budget, .proof = capture, .final_channel = channel, .open = open };
}

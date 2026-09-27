//! Genuine isolated classification PCS/STARK. Its source partition is open
//! until receiver internally fresh-verifies matching native/caller proof bytes.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Protocol = @import("block_v5_readonly_input_protocol_v1.zig");
const Air = @import("block_v5_readonly_input_component_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
pub const Limits = struct {
    max_events: u64 = 16_777_216,
    max_log: u32 = 24,
    max_matrix_bytes: usize = 512 * 1024 * 1024,
    max_intervals: usize = 2_000_001,
};
pub const Pin = struct {
    plan_digest: [32]u8,
    source_identity: [32]u8,
    events: u32,
    row_log: u32,
    roots: [2][32]u8,
    config: core.pcs.PcsConfig,
    limits: Limits = .{},
    pub fn validate(self: Pin) !void {
        try @import("blake3_execution_protocol.zig").validateConfig(self.config);
        if (self.events == 0 or self.events > self.limits.max_events or self.events >= core.fields.m31.Modulus or
            self.row_log < 1 or self.row_log > self.limits.max_log or self.row_log > 24 or
            self.events > (@as(u32, 1) << @intCast(self.row_log)) or
            self.row_log + self.config.fri_config.log_blowup_factor >= core.circle.M31_CIRCLE_LOG_ORDER)
            return error.InvalidReadonlyInputProofGeometry;
        const rows: usize = @as(usize, 1) << @intCast(self.row_log);
        const cells = try std.math.mul(usize, rows, Air.Spec.MAIN_COUNT + Air.Spec.FIXED_COUNT + Air.Spec.INTERACTION_COUNT);
        if (try std.math.mul(usize, cells, @sizeOf(M)) > self.limits.max_matrix_bytes) return error.ReadonlyInputProofResourceLimit;
    }
};
pub const Proof = struct {
    stark: core.proof_suites.Blake3.Proof,
    claim: Protocol.Claim,
    counters: []u64,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.free(self.counters);
        self.* = undefined;
    }
};
pub const Trace = struct {
    storage: []M,
    fixed: [1]Column,
    main: [Air.Spec.MAIN_COUNT]Column,
    counters: []u64,
    /// Mutation is restricted to the trace's owned matrix. PCS descriptors
    /// expose immutable borrows and never require casting away constness.
    pub fn mainValues(self: *Trace, index: usize) []M {
        std.debug.assert(index < Air.Spec.MAIN_COUNT);
        const rows = self.fixed[0].values.len;
        return self.storage[(index + 1) * rows ..][0..rows];
    }
    pub fn deinit(self: *Trace, a: std.mem.Allocator) void {
        a.free(self.storage);
        a.free(self.counters);
        self.* = undefined;
    }
    /// Exactly one source's ALL-RW event stream. No sorting/clock conversion:
    /// original aligned byte addresses and full u64 clocks are retained.
    pub fn init(a: std.mem.Allocator, plan: Plan.Owned, events: []const @import("../air/block/memory_transition.zig").Transition, pin: Pin) !Trace {
        return initIntervals(a, plan.intervals, plan.digest, events, pin);
    }
    /// Physical proposal construction from independently admitted intervals.
    /// This does not admit a final Plan or authorize a readonly receipt.
    pub fn initIntervals(a: std.mem.Allocator, intervals: []const Plan.Interval, interval_digest: [32]u8, events: []const @import("../air/block/memory_transition.zig").Transition, pin: Pin) !Trace {
        try pin.validate();
        if (events.len != pin.events or !std.meta.eql(interval_digest, pin.plan_digest) or intervals.len > pin.limits.max_intervals) return error.UntrustedReadonlyInputTrace;
        const rows: usize = @as(usize, 1) << @intCast(pin.row_log);
        const storage = try a.alloc(M, rows * (1 + Air.Spec.MAIN_COUNT));
        errdefer a.free(storage);
        @memset(storage, M.zero());
        const counters = try a.alloc(u64, intervals.len);
        errdefer a.free(counters);
        @memset(counters, 0);
        var result = Trace{ .storage = storage, .fixed = .{.{ .values = storage[0..rows], .log_size = pin.row_log }}, .main = undefined, .counters = counters };
        for (&result.main, 0..) |*column, index| column.* = .{ .values = storage[(1 + index) * rows ..][0..rows], .log_size = pin.row_log };
        for (events, 0..) |event, logical| {
            const interval = try Plan.findInterval(intervals, event.address);
            const values = try Air.witnessRow(event, intervals[interval]);
            const physical = Framework.committedRow(logical, pin.row_log);
            result.storage[physical] = M.one();
            for (values, 0..) |value, column| result.mainValues(column)[physical] = value;
            counters[interval] = try std.math.add(u64, counters[interval], 1);
        }
        return result;
    }
    pub fn require(self: *const Trace, pin: Pin) !void {
        try pin.validate();
        const rows: usize = @as(usize, 1) << @intCast(pin.row_log);
        if (self.storage.len != rows * (1 + Air.Spec.MAIN_COUNT) or self.counters.len > pin.limits.max_intervals) return error.UntrustedReadonlyInputTrace;
        if (self.fixed[0].values.ptr != self.storage.ptr or self.fixed[0].coefficient_values != null) return error.UntrustedReadonlyInputTrace;
        for (self.fixed) |column| if (column.log_size != pin.row_log or column.values.len != rows) return error.UntrustedReadonlyInputTrace;
        for (self.main, 0..) |column, index| if (column.log_size != pin.row_log or column.values.len != rows or
            column.coefficient_values != null or column.values.ptr != self.storage[(1 + index) * rows ..].ptr) return error.UntrustedReadonlyInputTrace;
    }
};
pub const Open = struct { claim: Protocol.Claim, mutable_events: u64, source_identity: [32]u8, plan_digest: [32]u8, sealed_digest: [32]u8 };

pub fn sourceIdentity(kind: enum { native, caller }, index: u32, sealed: [32]u8, instance: [32]u8, roots: [2][32]u8, access: [32]u8) [32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, @intFromEnum(kind), index });
    channel.mixRoot(Protocol.abiId());
    channel.mixRoot(sealed);
    channel.mixRoot(instance);
    for (roots) |root| channel.mixRoot(root);
    channel.mixRoot(access);
    return channel.digestBytes();
}
pub fn firstChannel(pin: Pin) core.proof_suites.Blake3.Channel {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, pin.events, pin.row_log });
    channel.mixRoot(Protocol.abiId());
    channel.mixRoot(pin.plan_digest);
    channel.mixRoot(pin.source_identity);
    pin.config.mixInto(&channel);
    return channel;
}
pub fn pcsChannel(a: std.mem.Allocator, pin: Pin, sealed: Seal.Sealed, claim: Protocol.Claim, counters: []const u64) !core.proof_suites.Blake3.Channel {
    var channel = sealed.sharedChannel();
    _ = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.drawFromChannel(a, &channel);
    channel.mixU32s(&.{ Protocol.TAG, Protocol.VERSION });
    channel.mixRoot(Protocol.abiId());
    channel.mixRoot(pin.plan_digest);
    channel.mixRoot(pin.source_identity);
    for (pin.roots) |root| channel.mixRoot(root);
    const discard = try channel.drawSecureFelts(a, 4);
    a.free(discard);
    for ([_]Q{ claim.source_sum, claim.mutable_sum, claim.classification_sum, claim.read_sum }) |sum| {
        if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&sum)) return error.InvalidReadonlyInputClaim;
        for (sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
    }
    channel.mixU64(claim.readonly_count);
    channel.mixU64(counters.len);
    for (counters) |count| channel.mixU64(count);
    return channel;
}
/// Independently derived public providers close both classification and reads.
/// Exact nonnegative integer mass is checked before any rational arithmetic.
pub fn checkProviders(plan: Plan.Owned, pin: Pin, claim: Protocol.Claim, counters: []const u64, challenges: *const Protocol.Challenges) !void {
    for ([_]Q{ claim.source_sum, claim.mutable_sum, claim.classification_sum, claim.read_sum }) |sum| {
        if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&sum)) return error.InvalidReadonlyInputClaim;
    }
    if (counters.len != plan.intervals.len or counters.len > pin.limits.max_intervals or claim.readonly_count > pin.events) return error.InvalidReadonlyInputProviderCensus;
    var count: u64 = 0;
    var readonly: u64 = 0;
    for (counters, plan.intervals) |mass, interval| {
        if (mass > pin.events) return error.InvalidReadonlyInputProviderCensus;
        count = try std.math.add(u64, count, mass);
        if (interval.readonly) readonly = try std.math.add(u64, readonly, mass);
    }
    if (count != pin.events or readonly != claim.readonly_count) return error.InvalidReadonlyInputProviderCensus;
    var classification = Q.zero();
    var read = Q.zero();
    for (counters, plan.intervals) |mass, interval| {
        if (mass == 0) continue;
        const weight = M.fromCanonical(@intCast(mass));
        classification = classification.add((try challenges.classification.combineBase(Protocol.intervalTuple(interval)).inv()).mulM31(weight));
        if (interval.readonly) read = read.add((try challenges.read.combineBase(Protocol.inputTuple(interval.lower * 4, interval.value)).inv()).mulM31(weight));
    }
    if (!classification.eql(claim.classification_sum) or !read.eql(claim.read_sum)) return error.UnclosedReadonlyInputProviders;
}
pub const Generated = struct {
    storage: []M,
    columns: [20]Column,
    claim: Protocol.Claim,
    pub fn deinit(self: *Generated, a: std.mem.Allocator) void {
        a.free(self.storage);
        self.* = undefined;
    }
};
pub fn generateInteraction(a: std.mem.Allocator, trace: *const Trace, pin: Pin, challenges: *const Protocol.Challenges) !Generated {
    try trace.require(pin);
    const rows: usize = @as(usize, 1) << @intCast(pin.row_log);
    const storage = try a.alloc(M, rows * 20);
    errdefer a.free(storage);
    var result = Generated{ .storage = storage, .columns = undefined, .claim = undefined };
    for (&result.columns, 0..) |*column, index| column.* = .{ .values = storage[index * rows ..][0..rows], .log_size = pin.row_log };
    var total: [5]Q = @splat(Q.zero());
    for (0..rows) |physical| {
        var row: [Air.Layout.len]Q = undefined;
        for (&row, trace.main) |*value, column| value.* = Q.fromBase(column.values[physical]);
        const active = Q.fromBase(trace.fixed[0].values[physical]);
        const d = Air.Algebra(Q).denominators(row, challenges);
        const n = Air.Algebra(Q).numerators(active, row);
        for (0..5) |i| {
            const term = if (n[i].isZero()) Q.zero() else if (i < 4) try n[i].div(d[i]) else n[i];
            total[i] = total[i].add(term);
            for (term.toM31Array(), 0..) |limb, j| storage[(4 * i + j) * rows + physical] = limb;
        }
    }
    const readonly = total[4].toM31Array();
    for (readonly[1..]) |limb| if (!limb.isZero()) return error.InvalidReadonlyInputProviderCensus;
    result.claim = .{ .source_sum = total[0], .mutable_sum = total[1], .classification_sum = total[2], .read_sum = total[3], .readonly_count = readonly[0].toU32() };
    var prefix: [5]Q = @splat(Q.zero());
    for (0..rows) |logical| {
        const physical = Framework.committedRow(logical, pin.row_log);
        for (0..5) |i| {
            var term: [4]M = undefined;
            for (&term, 0..) |*out, j| out.* = result.columns[4 * i + j].values[physical];
            prefix[i] = prefix[i].add(Q.fromM31Array(term)).sub(try total[i].divM31(M.fromCanonical(@intCast(rows))));
            for (prefix[i].toM31Array(), 0..) |limb, j| storage[(4 * i + j) * rows + physical] = limb;
        }
    }
    for (prefix) |value| if (!value.isZero()) return error.InvalidReadonlyInputPrefix;
    return result;
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const PCS = @import("block_v5_word_pcs_v1.zig").For(Backend, Air.Spec);
        pub const First = PCS.First;
        pub fn commit(a: std.mem.Allocator, trace: *const Trace, proposed: Pin) !First {
            try trace.require(proposed);
            return PCS.commit(a, &trace.fixed, &trace.main, firstChannel(proposed), proposed.config, false);
        }
        pub fn prove(a: std.mem.Allocator, first: *First, trace: *const Trace, pin: Pin, plan: Plan.Owned, sealed: Seal.Sealed, seal_pins: Seal.Pins, entries: []const Seal.Entry) !Proof {
            try pin.validate();
            try sealed.require(seal_pins, entries);
            if (!std.meta.eql(plan.digest, pin.plan_digest) or !std.meta.eql(first.roots, pin.roots) or !std.meta.eql(first.scheme.config, pin.config) or
                !std.meta.eql(pin.config, seal_pins.config) or !first.owns_scheme or first.scheme.trees.items.len != 2) return error.UntrustedReadonlyInputFirstRound;
            const challenges = try Protocol.Challenges.draw(a, sealed, plan.digest, pin.source_identity, pin.roots);
            var generated = try generateInteraction(a, trace, pin, &challenges);
            defer generated.deinit(a);
            try checkProviders(plan, pin, generated.claim, trace.counters, &challenges);
            const counters = try a.dupe(u64, trace.counters);
            errdefer a.free(counters);
            const stark = try PCS.prove(a, first, .{ .claim = generated.claim, .challenges = &challenges }, pin.row_log, &generated.columns, try pcsChannel(a, pin, sealed, generated.claim, counters));
            return .{ .stark = stark, .claim = generated.claim, .counters = counters };
        }
        pub const Captured = struct {
            core_capture: core.verifier.ProofCapture(core.proof_suites.Blake3.Hasher),
            challenges: Protocol.Challenges,
            final_channel: core.proof_suites.Blake3.Channel,
            receipt: Open,
            counters: []u64,
            pub fn deinit(self: *Captured, a: std.mem.Allocator) void {
                self.core_capture.deinit(a);
                a.free(self.counters);
                self.* = undefined;
            }
        };
        /// Identical original scalar verifier with an owned real core capture.
        /// The original proof remains borrowed; no scalar substitute is minted.
        pub fn verifyCaptureBorrowed(a: std.mem.Allocator, received: *const Proof, pin: Pin, plan: Plan.Owned, sealed: Seal.Sealed, seal_pins: Seal.Pins, entries: []const Seal.Entry) !Captured {
            var prepared = try prepareVerifier(a, received, pin, plan, sealed, seal_pins, entries);
            defer prepared.deinit(a);
            const counters = try a.dupe(u64, received.counters);
            errdefer a.free(counters);
            var captured = try PCS.verifyCaptureBorrowed(a, &received.stark, .{ .claim = received.claim, .challenges = &prepared.challenges }, pin.row_log, &prepared.fixed, pin.roots, pin.config, firstChannel(pin), prepared.channel);
            errdefer captured.deinit(a);
            return .{ .core_capture = captured.proof, .challenges = prepared.challenges, .final_channel = captured.final_channel, .receipt = open(received.claim, pin, plan, sealed), .counters = counters };
        }
        /// Consumes classification proof on every path. Caller must additionally
        /// close source_sum against internally fresh native/caller source bytes.
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, pin: Pin, plan: Plan.Owned, sealed: Seal.Sealed, seal_pins: Seal.Pins, entries: []const Seal.Entry) !Open {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            var prepared = try prepareVerifier(a, &proof, pin, plan, sealed, seal_pins, entries);
            defer prepared.deinit(a);
            const result = open(proof.claim, pin, plan, sealed);
            a.free(proof.counters);
            owns = false;
            try PCS.verifyOwned(a, proof.stark, .{ .claim = proof.claim, .challenges = &prepared.challenges }, pin.row_log, &prepared.fixed, pin.roots, pin.config, firstChannel(pin), prepared.channel);
            return result;
        }
    };
}

const VerifierPrepared = struct {
    challenges: Protocol.Challenges,
    channel: core.proof_suites.Blake3.Channel,
    fixed: [1]Column,
    fn deinit(self: *VerifierPrepared, a: std.mem.Allocator) void {
        a.free(self.fixed[0].values);
        self.* = undefined;
    }
};
fn prepareVerifier(a: std.mem.Allocator, proof: *const Proof, pin: Pin, plan: Plan.Owned, sealed: Seal.Sealed, seal_pins: Seal.Pins, entries: []const Seal.Entry) !VerifierPrepared {
    try pin.validate();
    try sealed.require(seal_pins, entries);
    if (!std.meta.eql(pin.config, seal_pins.config) or !std.meta.eql(plan.digest, pin.plan_digest)) return error.UntrustedReadonlyInputPlan;
    const challenges = try Protocol.Challenges.draw(a, sealed, plan.digest, pin.source_identity, pin.roots);
    try checkProviders(plan, pin, proof.claim, proof.counters, &challenges);
    const channel = try pcsChannel(a, pin, sealed, proof.claim, proof.counters);
    const rows: usize = @as(usize, 1) << @intCast(pin.row_log);
    const fixed_values = try a.alloc(M, rows);
    @memset(fixed_values, M.zero());
    for (0..pin.events) |logical| fixed_values[Framework.committedRow(logical, pin.row_log)] = M.one();
    return .{ .challenges = challenges, .channel = channel, .fixed = .{.{ .values = fixed_values, .log_size = pin.row_log }} };
}
fn open(claim: Protocol.Claim, pin: Pin, plan: Plan.Owned, sealed: Seal.Sealed) Open {
    return .{ .claim = claim, .mutable_events = pin.events - claim.readonly_count, .source_identity = pin.source_identity, .plan_digest = plan.digest, .sealed_digest = sealed.digest };
}

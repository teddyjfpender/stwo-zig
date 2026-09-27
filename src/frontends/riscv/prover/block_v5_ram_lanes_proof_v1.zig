//! Genuine lane proof lifecycle over shared PCS. Receipts stay open until
//! independently pinned source, range and execution buses close freshly.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const Protocol = @import("block_v5_ram_lanes_protocol_v1.zig");
const Trace = @import("../air/block/word_memory_lanes_trace_v1.zig");
const Air = @import("../air/block/word_memory_lanes_v1.zig");
const Interaction = @import("block_v5_ram_lanes_interaction_v1.zig");
const Component = @import("block_v5_ram_lanes_component_v1.zig");
const Range = @import("block_v5_range16_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Pcs = @import("block_v5_word_pcs_v1.zig");
pub const Limits = struct {
    max_row_log: u32 = 22,
    max_fixed_bytes: usize = 1 << 30,
    max_interaction_bytes: usize = 4 << 30,
    pub fn require(self: Limits, claim: Protocol.Claim) !void {
        try claim.validate();
        return self.requireGeometry(claim.row_log);
    }
    /// The planner and actual proof phase share these exact owned-buffer caps.
    /// This does not validate endpoints or create a claim/proof admission.
    pub fn requireGeometry(self: Limits, row_log: u32) !void {
        if (row_log < 1 or row_log > 24 or row_log > self.max_row_log or self.max_fixed_bytes == 0 or self.max_interaction_bytes == 0)
            return error.V5RamLanesResourceLimit;
        const rows: usize = @as(usize, 1) << @intCast(row_log);
        const fixed_bytes = try std.math.mul(usize, rows, Component.Spec.FIXED_COUNT * @sizeOf(core.fields.m31.M31));
        const interaction_bytes = try std.math.add(usize, try std.math.mul(usize, rows, Interaction.COLUMN_COUNT * @sizeOf(core.fields.m31.M31)), Interaction.SCRATCH_BYTES);
        if (fixed_bytes > self.max_fixed_bytes or interaction_bytes > self.max_interaction_bytes)
            return error.V5RamLanesResourceLimit;
    }
};
pub const Proof = struct {
    stark: suite.Proof,
    claim: Interaction.Claim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
};
/// Plain first-round metadata, not an admission or proof receipt. The caller
/// independently pins this proposal before SourceSeal or artifact decode.
pub const Pin = struct {
    claim: Protocol.Claim,
    index: u32,
    roots: [2][32]u8,
    request_count: u64,
    counter_digest: [32]u8,
    config: core.pcs.PcsConfig,
    pub fn validate(self: Pin) !void {
        try self.claim.validate();
        try validateConfig(self.claim, self.config);
        const bounds = @import("../air/block/word_memory_v5.zig").rangeCountBounds(self.claim.legacy());
        if (self.request_count < bounds.minimum or self.request_count > bounds.maximum or
            std.mem.allEqual(u8, &self.counter_digest, 0)) return error.UntrustedV5RamLanesPin;
        for (self.roots) |root| if (std.mem.allEqual(u8, &root, 0)) return error.UntrustedV5RamLanesPin;
    }
    pub fn entry(self: Pin) !Seal.Entry {
        try self.validate();
        return .{ .family = .memory, .index = self.index, .instance_id = try instanceId(self), .roots = self.roots };
    }
    pub fn identity(self: Pin) ![32]u8 {
        try self.validate();
        var channel = firstChannel(self.claim, self.index, self.config);
        channel.mixRoot(try instanceId(self));
        channel.mixRoot(self.counter_digest);
        channel.mixU64(self.request_count);
        return channel.digestBytes();
    }
};
pub const OpenReceipt = struct {
    pin: Pin,
    sums: Interaction.Claim,
    sealed_digest: [32]u8,
    // Strict space1 is proved. Register endpoints are absent, never an
    // unverified scalar supplied by a producer or carried in the artifact.
    pub fn registerEndpointSum(_: *const OpenReceipt) Q {
        return Q.zero();
    }
    pub fn registerEndpointCount(_: *const OpenReceipt) u64 {
        return 0;
    }
};
pub fn collectCounter(trace: *const Trace.Trace, counter: *Range.Counter) !u64 {
    if (!trace.sealed or trace.written != trace.claim.events) return error.InvalidV5RamLanesPhase;
    try trace.claim.validate();
    const start = counter.total;
    for (0..trace.claim.occupiedRows()) |logical| for (Air.rangePoints(trace.fixedAt(logical), trace.rowAt(logical))) |point| {
        if (point.weight.isZero()) continue;
        if (!point.weight.eql(Q.one())) return error.InvalidV5RamLanesMultiplicity;
        const words = point.value.toM31Array();
        for (words[1..]) |word| if (!word.isZero()) return error.InvalidWordRangeValue;
        try counter.add(words[0].toU32());
    };
    return counter.total - start;
}
pub fn instanceId(pin: Pin) ![32]u8 {
    try pin.claim.validate();
    var channel = firstChannel(pin.claim, pin.index, pin.config);
    channel.mixRoot(try Protocol.instanceId(pin.claim, pin.roots));
    channel.mixRoot(pin.counter_digest);
    channel.mixU64(pin.request_count);
    return channel.digestBytes();
}
/// Geometry and security are independently pinned together. Reject impossible
/// physical FRI/LDE domains before scanning counters or allocating a PCS.
pub fn validateConfig(claim: Protocol.Claim, config: core.pcs.PcsConfig) !void {
    try claim.validate();
    return validateGeometry(claim.row_log, config);
}
pub fn validateGeometry(row_log: u32, config: core.pcs.PcsConfig) !void {
    try @import("blake3_execution_protocol.zig").validateConfig(config);
    const fri = config.fri_config;
    // CanonicCoset.odds(log) needs a subgroup generator at log+1.
    if (row_log < 1 or row_log > 24 or row_log + fri.log_blowup_factor >= core.circle.M31_CIRCLE_LOG_ORDER or
        row_log < fri.fold_step or
        row_log - fri.fold_step < fri.log_last_layer_degree_bound)
        return error.InvalidV5RamLanesPcsGeometry;
}
pub fn firstChannel(claim: Protocol.Claim, index: u32, config: core.pcs.PcsConfig) suite.Channel {
    var channel = suite.Channel{};
    channel.mixRoot(Protocol.abiId());
    channel.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, 0x46525354, index }); // FRST
    claim.mix(&channel);
    config.mixInto(&channel);
    return channel;
}
pub fn mixClaims(channel: anytype, claim: Interaction.Claim) void {
    channel.mixU64(claim.event_count);
    for ([_]Q{ claim.transition_sum, claim.link_sum, claim.initial_sum, claim.endpoint_sum } ++ claim.range_sums) |sum|
        for (sum.toM31Array()) |word| channel.mixU32s(&.{word.toU32()});
    channel.mixU64(claim.endpoint_count);
    channel.mixU64(claim.range_count);
}
pub fn proofChannel(a: std.mem.Allocator, sealed: Seal.Sealed, pin: Pin, claim: Interaction.Claim) !suite.Channel {
    _ = try Interaction.normalize(claim, pin.claim);
    var channel = sealed.sharedChannel();
    // Replay the identical shared universal prefix and typed word suffix
    // before this new proof domain. No reset/branch after drawing challenges.
    _ = try @import("block_v5_word_memory_protocol_v1.zig").Challenges.drawFromChannel(a, &channel);
    channel.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, 0x50524f46 }); // PROF
    channel.mixRoot(Protocol.abiId());
    channel.mixRoot(try pin.identity());
    mixClaims(&channel, claim);
    return channel;
}
pub fn admit(pin: Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry) !void {
    try pin.validate();
    try sealed.require(pins, entries);
    if (sealed.register_custody_mode != 1 or pins.register_custody_mode != 1 or
        pin.index >= sealed.memory_instance_count or !std.meta.eql(pin.config, pins.config)) return error.UntrustedV5RamLanesSeal;
    const expected = try pin.entry();
    for (entries) |entry| if (entry.family == .memory and entry.index == pin.index) {
        if (!std.meta.eql(entry, expected)) return error.UntrustedV5RamLanesEntry;
        return;
    };
    return error.MissingV5RamLanesEntry;
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Api = Pcs.For(Backend, Component.Spec);
        pub const FirstRound = struct {
            pcs_first: Api.First,
            pin: Pin,
            pub fn deinit(self: *FirstRound, a: std.mem.Allocator) void {
                self.pcs_first.deinit(a);
                self.* = undefined;
            }
            pub fn require(self: *FirstRound, a: std.mem.Allocator, trace: *const Trace.Trace, expected: Pin) !void {
                try expected.validate();
                if (!self.pcs_first.owns_scheme or !trace.sealed or trace.written != trace.claim.events or
                    self.pcs_first.scheme.coefficient_retention_policy != .always or
                    !std.meta.eql(self.pin, expected) or !std.meta.eql(trace.claim, expected.claim) or
                    !std.meta.eql(self.pcs_first.roots, expected.roots) or
                    !std.meta.eql(self.pcs_first.scheme.config, expected.config)) return error.UntrustedV5RamLanesWarmFirst;
                var roots = try self.pcs_first.scheme.roots(a);
                defer roots.deinit(a);
                if (roots.items.len != 2 or !std.meta.eql(roots.items[0..2].*, expected.roots)) return error.UntrustedV5RamLanesWarmFirst;
            }
        };
        pub fn commitFirstRound(a: std.mem.Allocator, trace: *const Trace.Trace, index: u32, config: core.pcs.PcsConfig, retain: bool, limits: Limits) !FirstRound {
            var local = try Range.Counter.init(a);
            defer local.deinit();
            return commitFirstRoundWithCounter(a, trace, index, config, retain, limits, &local);
        }
        /// Emits the exact local histogram during the same scan. On any error
        /// discard the caller's local counter; never merge it into providers.
        pub fn commitFirstRoundWithCounter(a: std.mem.Allocator, trace: *const Trace.Trace, index: u32, config: core.pcs.PcsConfig, retain: bool, limits: Limits, local: *Range.Counter) !FirstRound {
            try limits.require(trace.claim);
            try validateConfig(trace.claim, config);
            if (local.total != 0 or local.values.len != Range.TABLE_SIZE or !std.mem.allEqual(u32, local.values, 0))
                return error.InvalidV5RamLanesLocalCounter;
            const count = try collectCounter(trace, local);
            var fixed: [Component.Spec.FIXED_COUNT]Pcs.Column = undefined;
            var main: [Component.Spec.MAIN_COUNT]Pcs.Column = undefined;
            for (&fixed, 0..) |*column, i| column.* = .{ .log_size = trace.claim.row_log, .values = trace.fixedColumn(i) };
            for (&main, 0..) |*column, i| column.* = .{ .log_size = trace.claim.row_log, .values = trace.mainColumn(i) };
            var first = try Api.commit(a, &fixed, &main, firstChannel(trace.claim, index, config), config, retain);
            errdefer first.deinit(a);
            const pin = Pin{ .claim = trace.claim, .index = index, .roots = first.roots, .request_count = count, .counter_digest = local.digest(), .config = config };
            try pin.validate();
            return .{ .pcs_first = first, .pin = pin };
        }
        pub fn provePrepared(a: std.mem.Allocator, first: *FirstRound, trace: *const Trace.Trace, expected: Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, table: *const Interaction.RangeInverses, limits: Limits) !Proof {
            try limits.require(trace.claim);
            try admit(expected, sealed, pins, entries);
            try first.require(a, trace, expected);
            const challenges = try Protocol.Challenges.draw(a, sealed);
            var local = try Range.Counter.init(a);
            defer local.deinit();
            var generated = try Interaction.generatePrepared(a, trace, &challenges, &local, table, limits.max_interaction_bytes);
            defer generated.deinit(a);
            if (generated.claim.range_count != expected.request_count or !std.meta.eql(local.digest(), expected.counter_digest))
                return error.V5RamLanesCounterReplayMismatch;
            var columns: [Interaction.COLUMN_COUNT]Pcs.Column = undefined;
            for (&columns, generated.columns) |*column, values| column.* = .{ .log_size = expected.claim.row_log, .values = values };
            const spec = Component.Spec{ .claim = expected.claim, .interaction_claim = generated.claim, .challenges = &challenges };
            return .{ .stark = try Api.prove(a, &first.pcs_first, spec, expected.claim.row_log, &columns, try proofChannel(a, sealed, expected, generated.claim)), .claim = generated.claim };
        }
        /// Borrows independently admitted resident sorted records and returns
        /// a provisional physical commitment; source ownership stays caller's.
        pub fn commitFirstRoundResident(a: std.mem.Allocator, source: *const @import("block_v5_ram_lanes_resident_source_v1.zig").Lease, session: anytype, index: u32, config: core.pcs.PcsConfig, limits: Limits, local: *Range.Counter) !FirstRound {
            try limits.require(source.claim);
            try validateConfig(source.claim, config);
            try source.require(source.claim, session.limits.max_resident_bytes);
            try source.copyCounter(local);
            const words = try @import("block_v5_ram_lanes_resident_source_v1.zig").metadata(source.claim);
            var witness = try session.witness(source.buffer, &words, source.claim.row_log);
            defer witness.deinit();
            var first = try Api.commitResident(a, session, &witness, source.claim.row_log, firstChannel(source.claim, index, config), config, source.buffer.byte_length);
            errdefer first.deinit(a);
            const pin = Pin{ .claim = source.claim, .index = index, .roots = first.roots, .request_count = local.total, .counter_digest = local.digest(), .config = config };
            try pin.validate();
            return .{ .pcs_first = first, .pin = pin };
        }
        /// The warm replay's resident sorted records are provisional. Fresh
        /// fixed/main root equality authenticates them before fractions or
        /// claims can advance the sealed transcript.
        pub fn proveResident(a: std.mem.Allocator, source: *const @import("block_v5_ram_lanes_resident_source_v1.zig").Lease, session: anytype, expected: Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !Proof {
            try limits.require(expected.claim);
            try admit(expected, sealed, pins, entries);
            try source.require(expected.claim, session.limits.max_resident_bytes);
            var local = try Range.Counter.init(a);
            defer local.deinit();
            try source.copyCounter(&local);
            if (local.total != expected.request_count or !std.meta.eql(local.digest(), expected.counter_digest)) return error.V5RamLanesTraceReplayMismatch;
            const Source = @import("block_v5_ram_lanes_resident_source_v1.zig");
            const Resident = Backend.RamLaneResident;
            try session.noteIngress(source.uploaded_bytes, false);
            const metadata = try Source.metadata(expected.claim);
            var witness = try session.witness(source.buffer, &metadata, expected.claim.row_log);
            var owns_witness = true;
            defer if (owns_witness) witness.deinit();
            var first = try Api.commitResident(a, session, &witness, expected.claim.row_log, firstChannel(expected.claim, expected.index, expected.config), expected.config, source.buffer.byte_length);
            defer first.deinit(a);
            if (!std.meta.eql(first.roots, expected.roots)) return error.V5RamLanesTraceReplayMismatch;
            const challenges = try Protocol.Challenges.draw(a, sealed);
            const provisional = Interaction.Claim{ .event_count = expected.claim.events, .transition_sum = Q.zero(), .link_sum = Q.zero(), .initial_sum = Q.zero(), .endpoint_sum = Q.zero(), .endpoint_count = 0, .range_count = expected.request_count, .range_sums = @splat(Q.zero()) };
            var program = try @import("block_v5_ram_lanes_gpu_program_v1.zig").fractions(a, .{ .claim = expected.claim, .interaction_claim = provisional, .challenges = &challenges }, expected.claim.rowCapacity());
            defer program.deinit();
            const pcs_bytes = try std.math.add(usize, try Resident.retainedBytes(.lane_fixed, expected.claim.row_log), try Resident.retainedBytes(.lane_main, expected.claim.row_log));
            const other_live = try std.math.add(usize, pcs_bytes, source.buffer.byte_length);
            var generated = try session.interaction(a, &program, &witness, other_live);
            var owns_generated = true;
            defer if (owns_generated) generated.deinit();
            if (generated.batches != 23 or generated.claim_count != 23) return error.InvalidV5RamLanesInteractionCensus;
            const totals = try session.readClaims(23, &generated);
            const claim = try Source.claim(totals, expected.claim, expected.request_count);
            const spec = Component.Spec{ .claim = expected.claim, .interaction_claim = claim, .challenges = &challenges };
            const transcript = try proofChannel(a, sealed, expected, claim);
            witness.deinit();
            owns_witness = false;
            owns_generated = false;
            return .{ .stark = try Api.proveResident(a, &first, spec, expected.claim.row_log, session, generated, other_live, transcript), .claim = claim };
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, expected: Pin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, limits: Limits) !OpenReceipt {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            try limits.require(expected.claim);
            try admit(expected, sealed, pins, entries);
            _ = try Interaction.normalize(proof.claim, expected.claim);
            if (proof.claim.range_count != expected.request_count) return error.UntrustedV5RamLanesRangeCensus;
            const challenges = try Protocol.Challenges.draw(a, sealed);
            var fixed = try Trace.FixedTrace.init(a, expected.claim, limits.max_fixed_bytes);
            defer fixed.deinit();
            var columns: [Component.Spec.FIXED_COUNT]Pcs.Column = undefined;
            for (&columns, 0..) |*column, i| column.* = .{ .log_size = expected.claim.row_log, .values = fixed.column(i) };
            const spec = Component.Spec{ .claim = expected.claim, .interaction_claim = proof.claim, .challenges = &challenges };
            const result = OpenReceipt{ .pin = expected, .sums = proof.claim, .sealed_digest = sealed.digest };
            const transcript = try proofChannel(a, sealed, expected, proof.claim);
            owns = false;
            try Api.verifyOwned(a, proof.stark, spec, expected.claim.row_log, &columns, expected.roots, expected.config, firstChannel(expected.claim, expected.index, expected.config), transcript);
            return result;
        }
    };
}

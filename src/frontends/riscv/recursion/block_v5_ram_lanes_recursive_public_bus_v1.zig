//! Independently derived original lane transcript and equation public supply.
//! Native roots, endpoint/census and all61 equation inputs stay external to
//! reusable setup while actual Merkle/FRI/DEEP equations remain recursive.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Admission = @import("../prover/block_v5_ram_lanes_recursive_admission_v1.zig");
const Lane = @import("../prover/block_v5_ram_lanes_proof_v1.zig");
const Interaction = @import("../prover/block_v5_ram_lanes_interaction_v1.zig");
const Composition = @import("air/block_v5_ram_lanes_composition_v1.zig");
const universal = @import("air/universal_challenges.zig");
pub const VERSION: u32 = 1;
pub const PUBLIC_CIRCUIT: u32 = 4_200_007;
pub const MAX_WIRES: usize = 256;
pub const Source = enum(u8) { sealed, pin_identity, fixed_root, main_root, claim_words, equation };
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, source: Source, coordinate: u32 };
pub const Values = struct {
    template: [32]u8,
    sealed: [32]u8,
    pin: Lane.Pin,
    sums: Interaction.Claim,
    equation_inputs: [Composition.PUBLIC_COUNT]Q,
    pub fn fromLanes(admitted: *const Admission.Prepared, receipt: Lane.OpenReceipt) !Values {
        try admitted.validate(admitted.template_id);
        if (!std.meta.eql(receipt.pin, admitted.pin) or !std.meta.eql(receipt.sealed_digest, admitted.sealed.digest)) return error.UntrustedRamPublicInputs;
        const result = Values{ .template = admitted.template_id, .sealed = admitted.sealed.digest, .pin = admitted.pin, .sums = receipt.sums, .equation_inputs = try deriveInputs(admitted.pin, receipt.sums, admitted.sealed.digest) };
        try result.validate();
        return result;
    }
    pub fn validate(self: Values) !void {
        try self.pin.validate();
        _ = try Interaction.normalize(self.sums, self.pin.claim);
        if (self.sums.range_count != self.pin.request_count or std.mem.allEqual(u8, &self.sealed, 0) or
            !std.meta.eql(self.template, Admission.templateId(self.pin.config, self.pin.claim.row_log)) or
            !std.meta.eql(self.equation_inputs, try deriveInputs(self.pin, self.sums, self.sealed))) return error.InvalidRamPublicInputs;
    }
    pub fn claimWords(self: Values) [90]u32 {
        var result: [90]u32 = undefined;
        result[0] = @truncate(self.sums.event_count);
        result[1] = @truncate(self.sums.event_count >> 32);
        const sums = [_]Q{ self.sums.transition_sum, self.sums.link_sum, self.sums.initial_sum, self.sums.endpoint_sum } ++ self.sums.range_sums;
        for (sums, 0..) |sum, i| {
            for (sum.toM31Array(), 0..) |word, j| result[2 + 4 * i + j] = word.toU32();
        }
        result[86] = @truncate(self.sums.endpoint_count);
        result[87] = @truncate(self.sums.endpoint_count >> 32);
        result[88] = @truncate(self.sums.range_count);
        result[89] = @truncate(self.sums.range_count >> 32);
        return result;
    }
    pub fn at(self: Values, source: Source, coordinate: u32) ![4]M {
        if (source == .equation) {
            if (coordinate >= Composition.PUBLIC_COUNT) return error.InvalidRamPublicSchedule;
            return self.equation_inputs[coordinate].toM31Array();
        }
        const word: u32 = if (source == .claim_words) value: {
            if (coordinate >= 90) return error.InvalidRamPublicSchedule;
            break :value self.claimWords()[coordinate];
        } else value: {
            if (coordinate >= 8) return error.InvalidRamPublicSchedule;
            const digest = switch (source) {
                .sealed => self.sealed,
                .pin_identity => try self.pin.identity(),
                .fixed_root => self.pin.roots[0],
                .main_root => self.pin.roots[1],
                else => unreachable,
            };
            break :value std.mem.readInt(u32, digest[4 * @as(usize, coordinate) ..][0..4], .little);
        };
        var bytes: [4]M = undefined;
        for (&bytes, 0..) |*out, i| out.* = M.fromCanonical((word >> @as(u5, @intCast(8 * i))) & 255);
        return bytes;
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42354c49, VERSION }); // B5LI
        channel.mixRoot(self.template);
        channel.mixRoot(self.sealed);
        // validate() has admitted pin; equivalent original framing preserves
        // all u64 ordinals, clocks, typed source census and physical row log.
        self.pin.claim.mix(channel);
        for (self.pin.roots) |root| channel.mixRoot(root);
        channel.mixRoot(self.pin.counter_digest);
        channel.mixU64(self.pin.request_count);
        channel.mixU32s(&.{self.pin.index});
        self.pin.config.mixInto(channel);
        Lane.mixClaims(channel, self.sums);
        channel.mixFelts(&self.equation_inputs);
    }
};
fn deriveInputs(pin: Lane.Pin, sums: Interaction.Claim, sealed: [32]u8) ![Composition.PUBLIC_COUNT]Q {
    // Only104+10 secure draws, freed in draw order. This is policy derivation,
    // not a witness-sized allocation or a substitute for native verification.
    var scratch: [8192]u8 = undefined;
    var buffer = std.heap.FixedBufferAllocator.init(&scratch);
    return Composition.publicInputs(buffer.allocator(), pin, sums, sealed);
}
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > MAX_WIRES) return error.InvalidRamPublicSchedule;
    if (!@import("public_wire_uniqueness_v1.zig").For(Wire, MAX_WIRES).unique(wires)) return error.InvalidRamPublicSchedule;
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42354c57, VERSION, @intCast(wires.len) }); // B5LW
    for (wires) |wire| {
        if (wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus or wire.uses == 0 or wire.uses >= core.fields.m31.Modulus) return error.InvalidRamPublicSchedule;
        const maximum: usize = switch (wire.source) {
            .equation => Composition.PUBLIC_COUNT,
            .claim_words => 90,
            else => 8,
        };
        if (wire.coordinate >= maximum) return error.InvalidRamPublicSchedule;
        channel.mixU32s(&.{ wire.circuit, wire.wire, wire.uses, @intFromEnum(wire.source), wire.coordinate });
    }
    return channel.digestBytes();
}
pub fn supply(wires: []const Wire, values: Values, relations: universal.UniversalRelations) !Q {
    _ = try scheduleDigest(wires);
    try values.validate();
    const elements = try relations.getExact(.recursion_wire);
    var sum = Q.zero();
    for (wires) |wire| {
        const denominator = try elements.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire.source, wire.coordinate)));
        if (denominator.isZero()) return error.RamPublicDenominatorZero;
        sum = sum.add(Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv()));
    }
    return sum;
}
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    recursive: @import("blake3_execution_parent_preparation.zig").Prepared,
    wires: []Wire,
    values: Values,
    pub fn deinit(self: *Prepared) void {
        self.recursive.deinit();
        self.allocator.free(self.wires);
        self.budget.destroy();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const @import("../prover/block_v5_ram_lanes_recursive_capture_v1.zig").VerifiedCapture, capacity: u32) !Prepared {
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(a, admitted.limits.max_preparation_bytes);
    errdefer budget.destroy();
    const bounded = budget.allocator();
    const values = try Values.fromLanes(admitted, capture.receipt);
    var planned = try @import("blake3_execution_parent_preparation.zig").State.plan(bounded, admitted, capture, admitted.template_id, capacity);
    defer planned.deinit();
    const state = planned.state.?;
    const transcript = &planned.transcript.?;
    // Preserve original fresh public-value comparisons before shared routing.
    for (state.composition.sources, 0..) |source, node| if (source == .public_input) {
        if (source.public_input >= Composition.PUBLIC_COUNT or !std.meta.eql(try values.at(.equation, source.public_input), state.composition.inputs[node].toM31Array())) return error.UntrustedRamPublicInputs;
    };
    const path_reads = std.math.cast(u32, capture.proof.queries.raw.len) orelse return error.InvalidRamPublicSchedule;
    const wires = try @import("air/block_v5_word_public_schedule_v1.zig").For(.ram_lanes, @This()).collect(bounded, &transcript.plan, &state.composition, path_reads);
    errdefer bounded.free(wires);
    const emitted = try planned.emit();
    defer emitted.deinit();
    var recursive = try emitted.finishReleasingRows();
    errdefer recursive.deinit();
    return .{ .allocator = bounded, .budget = budget, .recursive = recursive, .wires = wires, .values = values };
}

//! Independently pinned full group/first-root/claim public supply. Exact six
//! claims remain open for the block's field-safe requester group closure.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Admission = @import("../prover/block_v5_native_lookup_recursive_admission_v1.zig");
const Native = @import("../prover/block_v5_native_lookup_proof_v1.zig");
const universal = @import("air/universal_challenges.zig");
pub const VERSION: u32 = 1;
pub const PUBLIC_CIRCUIT: u32 = 4_200_008;
pub const MAX_WIRES: usize = 128;
pub const Source = enum(u8) { sealed, plan, fixed_root, main_root, claim_words, claim };
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, source: Source, coordinate: u32 };
pub const Values = struct {
    template: [32]u8,
    sealed: [32]u8,
    plan: Native.Plan,
    plan_id: [32]u8,
    roots: [2][32]u8,
    claims: [6]Q,
    pub fn fromLookup(admitted: *const Admission.Prepared, receipt: Native.OpenReceipt) !Values {
        try admitted.validate(admitted.template_id);
        var total = Q.zero();
        for (receipt.claims) |claim| {
            if (!@import("air/universal_provider_relations.zig").secureIsCanonical(&claim)) return error.InvalidLookupPublicInputs;
            total = total.add(claim);
        }
        if (!std.meta.eql(receipt.plan_id, try admitted.plan.identity()) or !std.meta.eql(receipt.roots, admitted.roots) or
            !std.meta.eql(receipt.sealed_digest, admitted.sealed.digest) or !total.eql(receipt.total)) return error.UntrustedLookupPublicInputs;
        const result = Values{ .template = admitted.template_id, .sealed = admitted.sealed.digest, .plan = admitted.plan, .plan_id = receipt.plan_id, .roots = admitted.roots, .claims = receipt.claims };
        try result.validate();
        return result;
    }
    pub fn validate(self: Values) !void {
        try self.plan.validate();
        if (self.plan.index >= core.fields.m31.Modulus or !std.meta.eql(self.plan_id, try self.plan.identity())) return error.InvalidLookupPublicInputs;
        for (self.claims) |claim| for (claim.toM31Array()) |value| if (value.v >= core.fields.m31.Modulus) return error.InvalidLookupPublicInputs;
        for ([_][32]u8{ self.template, self.sealed, self.plan_id, self.roots[0], self.roots[1] }) |digest| if (std.mem.allEqual(u8, &digest, 0)) return error.InvalidLookupPublicInputs;
    }
    pub fn at(self: Values, source: Source, coordinate: u32) ![4]M {
        if (source == .claim) {
            if (coordinate >= 6) return error.InvalidLookupPublicSchedule;
            return self.claims[coordinate].toM31Array();
        }
        const word: u32 = if (source == .claim_words) blk: {
            if (coordinate >= 24) return error.InvalidLookupPublicSchedule;
            break :blk self.claims[coordinate / 4].toM31Array()[coordinate % 4].toU32();
        } else blk: {
            if (coordinate >= 8) return error.InvalidLookupPublicSchedule;
            const digest = switch (source) {
                .sealed => self.sealed,
                .plan => self.plan_id,
                .fixed_root => self.roots[0],
                .main_root => self.roots[1],
                else => unreachable,
            };
            break :blk std.mem.readInt(u32, digest[4 * @as(usize, coordinate) ..][0..4], .little);
        };
        var bytes: [4]M = undefined;
        for (&bytes, 0..) |*byte, i| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * i))) & 255);
        return bytes;
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42354c49, VERSION, self.plan.index, self.plan.first_execution, self.plan.execution_count });
        for (self.plan.max_requests) |count| channel.mixU64(count);
        for ([_][32]u8{ self.template, self.sealed, self.plan_id, self.roots[0], self.roots[1] }) |digest| channel.mixRoot(digest);
        channel.mixFelts(&self.claims);
    }
};
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > MAX_WIRES) return error.InvalidLookupPublicSchedule;
    if (!@import("public_wire_uniqueness_v1.zig").For(Wire, MAX_WIRES).unique(wires)) return error.InvalidLookupPublicSchedule;
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42354c57, VERSION, @intCast(wires.len) });
    for (wires) |wire| {
        const maximum: u32 = switch (wire.source) {
            .claim => 6,
            .claim_words => 24,
            else => 8,
        };
        if (wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus or wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or wire.coordinate >= maximum) return error.InvalidLookupPublicSchedule;
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
        if (denominator.isZero()) return error.LookupPublicDenominatorZero;
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
fn append(a: std.mem.Allocator, wires: *std.ArrayList(Wire), wire: Wire) !void {
    for (wires.items) |*existing| if (existing.circuit == wire.circuit and existing.wire == wire.wire) {
        if (existing.source != wire.source or existing.coordinate != wire.coordinate) return error.InvalidLookupPublicSchedule;
        existing.uses = try std.math.add(u32, existing.uses, wire.uses);
        return;
    };
    try wires.append(a, wire);
}
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const @import("../prover/block_v5_native_lookup_recursive_capture_v1.zig").VerifiedCapture, capacity: u32) !Prepared {
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(a, admitted.limits.max_preparation_bytes);
    errdefer budget.destroy();
    const bounded = budget.allocator();
    const values = try Values.fromLookup(admitted, capture.receipt);
    var planned = try @import("blake3_execution_parent_preparation.zig").State.plan(bounded, admitted, capture, admitted.template_id, capacity);
    defer planned.deinit();
    const state = planned.state.?;
    const transcript = &planned.transcript.?;
    var wires: std.ArrayList(Wire) = .empty;
    errdefer wires.deinit(bounded);
    const root_circuit = @import("air/blake3_root_sources.zig").CIRCUIT;
    const path_reads = std.math.cast(u32, capture.proof.queries.raw.len) orelse return error.InvalidLookupPublicSchedule;
    for (0..2) |root| for (0..8) |coordinate| try append(bounded, &wires, .{ .circuit = root_circuit, .wire = @intCast(root * 8 + coordinate), .uses = path_reads, .source = if (root == 0) .fixed_root else .main_root, .coordinate = @intCast(coordinate) });
    for (transcript.plan.fixed.root_reads) |receipt| {
        const source: Source = if (receipt.source.circuit == PUBLIC_CIRCUIT) switch (receipt.source.first_wire) {
            0 => .sealed,
            8 => .plan,
            else => return error.InvalidLookupPublicSchedule,
        } else if (receipt.source.circuit == root_circuit and receipt.source.first_wire < 16) (if (receipt.source.first_wire == 0) .fixed_root else .main_root) else continue;
        if (receipt.uses.len != 8) return error.InvalidLookupPublicSchedule;
        for (receipt.uses, 0..) |uses, coordinate| try append(bounded, &wires, .{ .circuit = receipt.source.circuit, .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)), .uses = uses, .source = source, .coordinate = @intCast(coordinate) });
    }
    for (transcript.plan.fixed.payload_reads) |receipt| if (receipt.source.circuit == PUBLIC_CIRCUIT) {
        if (receipt.source.first_wire < 16 or receipt.source.first_wire >= 40 or (receipt.source.first_wire - 16) % 4 != 0 or receipt.uses.len != 4) return error.InvalidLookupPublicSchedule;
        for (receipt.uses, 0..) |uses, coordinate| try append(bounded, &wires, .{ .circuit = PUBLIC_CIRCUIT, .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)), .uses = uses, .source = .claim_words, .coordinate = receipt.source.first_wire - 16 + @as(u32, @intCast(coordinate)) });
    };
    const counts = try bounded.alloc(u32, state.composition.circuit.nodes.len);
    defer bounded.free(counts);
    const uses = try @import("air/verifier_arithmetic_lowering.zig").computeUseCountsInto(state.composition.circuit.graph(), counts);
    for (state.composition.sources, 0..) |source, node| if (source == .public_input) {
        if (source.public_input >= 6 or !std.meta.eql(values.claims[source.public_input], state.composition.inputs[node])) return error.UntrustedLookupPublicInputs;
        try append(bounded, &wires, .{ .circuit = 1500, .wire = @intCast(node), .uses = uses[node], .source = .claim, .coordinate = source.public_input });
    };
    _ = try scheduleDigest(wires.items);
    const emitted = try planned.emit();
    defer emitted.deinit();
    var recursive = try emitted.finishReleasingRows();
    errdefer recursive.deinit();
    return .{ .allocator = bounded, .budget = budget, .recursive = recursive, .wires = try wires.toOwnedSlice(bounded), .values = values };
}

//! Full caller arithmetic public authority. Proposed sums are authenticated by
//! the actual recursive proof, and remain OPEN to program/memory/table closure.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Admission = @import("../prover/block_v5_caller_arithmetic_recursive_admission_v1.zig");
const Family = @import("../prover/block_v5_precompile_family_proof_v1.zig");
const Composition = @import("air/block_v5_caller_arithmetic_composition_v1.zig");
const universal = @import("air/universal_challenges.zig");
pub const VERSION: u32 = 1;
pub const PUBLIC_CIRCUIT: u32 = 4_200_009;
pub const INDEX_WORD_BASE: u32 = 48;
pub const CLAIM_WORD_BASE: u32 = 64;
pub const MAX_WIRES: usize = 8 * Composition.MAX_PUBLIC_CLAIMS + 128;
pub const Source = enum(u8) { sealed, execution, key, caller, fixed_root, main_root, index_words, claim_words, claim, open_sum };
pub const Wire = struct { circuit: u32, wire: u32, uses: u32, source: Source, coordinate: u32 };
pub const Values = struct {
    template: [32]u8,
    statement: Admission.Profile.admission.Statement,
    total_steps: u32,
    config: core.pcs.PcsConfig,
    binding: Family.CallerBinding,
    claims: Admission.Profile.ExtensionClaim,
    open_sum: Q,
    pub fn fromCaller(admitted: *const Admission.Prepared, receipt: Family.OpenReceipt, claims: Admission.Profile.ExtensionClaim) !Values {
        try admitted.validate(admitted.template_id);
        if (!std.meta.eql(receipt.binding, admitted.binding)) return error.UntrustedCallerRecursivePublicInputs;
        const result = Values{ .template = admitted.template_id, .statement = admitted.statement, .total_steps = admitted.total_steps, .config = admitted.config, .binding = receipt.binding, .claims = claims, .open_sum = receipt.open_sum };
        try result.validate();
        return result;
    }
    pub fn validate(self: Values) !void {
        try Admission.Protocol.validate(&self.statement, self.total_steps, self.config);
        try self.claims.validate(&self.statement);
        if (!self.open_sum.eql(self.claims.componentSum()) or !std.meta.eql(self.binding.caller_key_id, try Admission.Protocol.keyId(&self.statement, self.total_steps, self.config, self.binding.first_roots[0])) or !std.meta.eql(self.binding.caller_instance_id, Admission.Protocol.instanceId(self.binding.caller_key_id, self.binding.execution_instance_id, self.binding.execution_index, self.binding.first_roots)) or self.binding.execution_index != self.binding.caller_entry_index or self.binding.execution_index >= core.fields.m31.Modulus) return error.UntrustedCallerRecursivePublicInputs;
        for (self.open_sum.toM31Array()) |word| if (word.v >= core.fields.m31.Modulus) return error.UntrustedCallerRecursivePublicInputs;
        for ([_][32]u8{ self.template, self.binding.sealed_digest, self.binding.execution_instance_id, self.binding.caller_key_id, self.binding.caller_instance_id, self.binding.first_roots[0], self.binding.first_roots[1] }) |digest| if (std.mem.allEqual(u8, &digest, 0)) return error.UntrustedCallerRecursivePublicInputs;
    }
    pub fn claimAt(self: Values, index: u32) !Q {
        var offset: usize = 0;
        for (self.claims.componentClaims()) |view| {
            if (index >= offset and index - offset < view.detailed.len) return view.detailed[index - offset];
            offset += view.detailed.len;
            if (view.has_batch_frame) {
                if (index == offset) return view.total;
                offset += 1;
            }
        }
        return error.InvalidCallerRecursiveSchedule;
    }
    pub fn claimCount(self: Values) usize {
        var count: usize = 0;
        for (self.claims.componentClaims()) |view| count += view.detailed.len + @intFromBool(view.has_batch_frame);
        return count;
    }
    pub fn at(self: Values, source: Source, coordinate: u32) ![4]M {
        if (source == .claim) return (try self.claimAt(coordinate)).toM31Array();
        if (source == .open_sum) {
            if (coordinate != 0) return error.InvalidCallerRecursiveSchedule;
            return self.open_sum.toM31Array();
        }
        const word: u32 = switch (source) {
            .claim_words => (try self.claimAt(coordinate / 4)).toM31Array()[coordinate % 4].toU32(),
            .index_words => switch (coordinate) {
                0 => Admission.Protocol.TAG,
                1 => Admission.Protocol.VERSION,
                2 => self.binding.execution_index,
                else => return error.InvalidCallerRecursiveSchedule,
            },
            else => blk: {
                if (coordinate >= 8) return error.InvalidCallerRecursiveSchedule;
                const digest = switch (source) {
                    .sealed => self.binding.sealed_digest,
                    .execution => self.binding.execution_instance_id,
                    .key => self.binding.caller_key_id,
                    .caller => self.binding.caller_instance_id,
                    .fixed_root => self.binding.first_roots[0],
                    .main_root => self.binding.first_roots[1],
                    else => unreachable,
                };
                break :blk std.mem.readInt(u32, digest[4 * @as(usize, coordinate) ..][0..4], .little);
            },
        };
        var bytes: [4]M = undefined;
        for (&bytes, 0..) |*byte, i| byte.* = M.fromCanonical((word >> @as(u5, @intCast(8 * i))) & 255);
        return bytes;
    }
    pub fn mix(self: Values, channel: anytype) void {
        channel.mixU32s(&.{ 0x42354149, VERSION, self.total_steps });
        channel.mixRoot(self.template);
        self.config.mixInto(channel);
        channel.mixU32s(&.{ self.binding.execution_index, self.binding.caller_entry_index });
        channel.mixRoot(self.binding.execution_instance_id);
        channel.mixRoot(self.binding.caller_instance_id);
        channel.mixRoot(self.binding.caller_key_id);
        for (self.binding.first_roots) |root| channel.mixRoot(root);
        channel.mixRoot(self.binding.sealed_digest);
        self.claims.mixInto(channel);
        channel.mixFelts(&.{self.open_sum});
    }
};
fn maximum(source: Source) u32 {
    return switch (source) {
        .claim => Composition.MAX_PUBLIC_CLAIMS,
        .claim_words => 4 * Composition.MAX_PUBLIC_CLAIMS,
        .index_words => 3,
        .open_sum => 1,
        else => 8,
    };
}
pub fn scheduleDigest(wires: []const Wire) ![32]u8 {
    if (wires.len == 0 or wires.len > MAX_WIRES) return error.InvalidCallerRecursiveSchedule;
    if (!@import("public_wire_uniqueness_v1.zig").For(Wire, MAX_WIRES).unique(wires)) return error.InvalidCallerRecursiveSchedule;
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ 0x42354157, VERSION, @intCast(wires.len) });
    for (wires) |wire| {
        if (wire.circuit >= core.fields.m31.Modulus or wire.wire >= core.fields.m31.Modulus or wire.uses == 0 or wire.uses >= core.fields.m31.Modulus or wire.coordinate >= maximum(wire.source)) return error.InvalidCallerRecursiveSchedule;
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
        if (denominator.isZero()) return error.CallerRecursivePublicDenominatorZero;
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
    if (wire.uses == 0) return;
    for (wires.items) |*existing| if (existing.circuit == wire.circuit and existing.wire == wire.wire) {
        if (existing.source != wire.source or existing.coordinate != wire.coordinate) return error.InvalidCallerRecursiveSchedule;
        existing.uses = try std.math.add(u32, existing.uses, wire.uses);
        return;
    };
    if (wires.items.len >= MAX_WIRES) return error.CallerRecursiveResourceLimit;
    try wires.append(a, wire);
}
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const @import("../prover/block_v5_caller_arithmetic_recursive_capture_v1.zig").VerifiedCapture, capacity: u32) !Prepared {
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(a, admitted.limits.max_preparation_bytes);
    errdefer budget.destroy();
    const bounded = budget.allocator();
    const values = try Values.fromCaller(admitted, capture.receipt, capture.original.claims);
    var planned = try @import("blake3_execution_parent_preparation.zig").State.plan(bounded, admitted, capture, admitted.template_id, capacity);
    defer planned.deinit();
    const state = planned.state.?;
    const transcript = &planned.transcript.?;
    var wires: std.ArrayList(Wire) = .empty;
    errdefer wires.deinit(bounded);
    const root_circuit = @import("air/blake3_root_sources.zig").CIRCUIT;
    const path_reads = std.math.cast(u32, capture.proof.queries.raw.len) orelse return error.InvalidCallerRecursiveSchedule;
    for (0..2) |root| {
        for (0..8) |coordinate| try append(bounded, &wires, .{ .circuit = root_circuit, .wire = @intCast(root * 8 + coordinate), .uses = path_reads, .source = if (root == 0) .fixed_root else .main_root, .coordinate = @intCast(coordinate) });
    }
    for (transcript.plan.fixed.root_reads) |receipt| {
        const source: Source = if (receipt.source.circuit == PUBLIC_CIRCUIT) switch (receipt.source.first_wire) {
            0 => .sealed,
            8 => .execution,
            16 => .key,
            24 => .caller,
            32 => .fixed_root,
            40 => .main_root,
            else => return error.InvalidCallerRecursiveSchedule,
        } else if (receipt.source.circuit == root_circuit and receipt.source.first_wire < 16) (if (receipt.source.first_wire == 0) .fixed_root else .main_root) else continue;
        for (receipt.uses, 0..) |uses, coordinate| try append(bounded, &wires, .{ .circuit = receipt.source.circuit, .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)), .uses = uses, .source = source, .coordinate = @intCast(coordinate) });
    }
    for (transcript.plan.fixed.payload_reads) |receipt| if (receipt.source.circuit == PUBLIC_CIRCUIT) {
        const index_frame = receipt.source.first_wire == INDEX_WORD_BASE;
        if (index_frame) {
            if (receipt.uses.len != 3) return error.InvalidCallerRecursiveSchedule;
        } else if (receipt.source.first_wire < CLAIM_WORD_BASE or receipt.source.first_wire - CLAIM_WORD_BASE + receipt.uses.len > 4 * values.claimCount()) return error.InvalidCallerRecursiveSchedule;
        for (receipt.uses, 0..) |uses, coordinate| try append(bounded, &wires, .{ .circuit = PUBLIC_CIRCUIT, .wire = receipt.source.first_wire + @as(u32, @intCast(coordinate)), .uses = uses, .source = if (index_frame) .index_words else .claim_words, .coordinate = @intCast(if (index_frame) coordinate else receipt.source.first_wire - CLAIM_WORD_BASE + coordinate) });
    };
    const counts = try bounded.alloc(u32, state.composition.circuit.nodes.len);
    defer bounded.free(counts);
    const uses = try @import("air/verifier_arithmetic_lowering.zig").computeUseCountsInto(state.composition.circuit.graph(), counts);
    for (state.composition.sources, 0..) |source, node| if (source == .public_input) {
        const open = source.public_input == values.claimCount();
        const expected = if (open) values.open_sum else try values.claimAt(source.public_input);
        if (!expected.eql(state.composition.inputs[node])) return error.UntrustedCallerRecursivePublicInputs;
        try append(bounded, &wires, .{ .circuit = 1500, .wire = @intCast(node), .uses = uses[node], .source = if (open) .open_sum else .claim, .coordinate = if (open) 0 else source.public_input });
    };
    _ = try scheduleDigest(wires.items);
    const emitted = try planned.emit();
    defer emitted.deinit();
    var recursive = try emitted.finishReleasingRows();
    errdefer recursive.deinit();
    return .{ .allocator = bounded, .budget = budget, .recursive = recursive, .wires = try wires.toOwnedSlice(bounded), .values = values };
}

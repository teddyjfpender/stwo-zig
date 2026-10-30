//! Genuine native-only execution/global closure graph over the original
//! physical claim ports and receiver-derived statement byte ports. No computed
//! closure residual or successful host receipt is accepted as an input.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const G = @import("composition_graph_recorder.zig");
const S = G.Scalar;
const A = @import("block_v8_window_closure_algebra_v1.zig");
const Public = @import("../block_v8_union_closed_public_v1.zig");
const Scoped = @import("../block_v5_heterogeneous_scoped_public_bus_v1.zig");
const Capsule = @import("../block_v7_union_compiler_capsule_v1.zig").Capsule;
const OriginalRows = @import("block_v5_heterogeneous_scoped_graph_rows_v1.zig");
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    circuit: G.Circuit,
    inputs: []Q,
    values: []Q,
    sources: []Scoped.Wire,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Prepared) void {
        self.circuit.deinit();
        self.allocator.free(self.inputs);
        self.allocator.free(self.values);
        self.allocator.free(self.sources);
        self.* = undefined;
    }
    pub fn graph(self: *const Prepared) OriginalRows.Graph {
        return .{ .circuit = &self.circuit, .inputs = self.inputs, .values = self.values, .sources = self.sources };
    }
};
const Reader = struct {
    a: std.mem.Allocator,
    b: *G.Builder,
    public: Public.Values,
    inputs: std.ArrayList(Q) = .empty,
    sources: std.ArrayList(Scoped.Wire) = .empty,
    fn input(self: *Reader, wire: Scoped.Wire) !S {
        const symbol = (try self.b.input()).value;
        try self.inputs.append(self.a, Q.fromM31Array(try self.public.atClosure(wire)));
        try self.sources.append(self.a, wire);
        return symbol;
    }
};
fn word(bytes: [4]S) S {
    var result = S.zero();
    for (bytes, 0..) |byte, index| result = result.add(byte.mul(S.fromBase(M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(8 * index))))));
    return result;
}
fn halves(bytes: [4]S) [2]S {
    const radix = S.fromBase(M.fromCanonical(256));
    return .{ bytes[0].add(bytes[1].mul(radix)), bytes[2].add(bytes[3].mul(radix)) };
}
fn relation(comptime n: usize, z: S, alpha: S) A.Relation(S, n) {
    var result = A.Relation(S, n){ .z = z, .powers = undefined };
    var power = S.one();
    for (&result.powers) |*item| {
        item.* = power;
        power = power.mul(alpha);
    }
    return result;
}
pub fn prepare(a: std.mem.Allocator, capsule: *const Capsule, public: Public.Values) !Prepared {
    return build(a, capsule, public, true);
}
/// Cold key reconstruction deliberately does not evaluate closure success.
/// Invalid public claims must be rejected by the actual proof equations, not
/// by using a successful host closure as an admission token.
pub fn compile(a: std.mem.Allocator, capsule: *const Capsule, public: Public.Values) !Prepared {
    return build(a, capsule, public, false);
}
fn build(a: std.mem.Allocator, capsule: *const Capsule, public: Public.Values, evaluate: bool) !Prepared {
    try public.validate();
    const profile = capsule.profile();
    const c = capsule.compiler();
    const i = profile.statement.input;
    if (i.callers.len != 0 or i.natives.len == 0 or public.words[0] != i.natives.len) return error.UnsupportedClosedUnionCaller;
    if (i.memory_geometry[0].total_events > (core.fields.m31.Modulus - 1) / 24) return error.UnboundedClosedUnionCounts;
    var fetch_bound: u64 = i.natives.len;
    var event_bound: u64 = 0;
    for (c.admission.components.context.natives) |n| {
        for (n.component.layout.slots) |slot| if (slot.kind == .program) {
            fetch_bound += @as(u64, 1) << @intCast(slot.log_size);
        };
        for (n.component.slots) |slot| event_bound += @as(u64, 1) << @intCast(slot.log_size);
    }
    if (fetch_bound >= core.fields.m31.Modulus or event_bound >= core.fields.m31.Modulus) return error.UnboundedClosedUnionCounts;
    var b = G.Builder.init(a);
    defer b.deinit();
    var reader = Reader{ .a = a, .b = &b, .public = public };
    errdefer reader.inputs.deinit(a);
    errdefer reader.sources.deinit(a);
    const ports = try a.alloc(S, public.original.public.len);
    defer a.free(ports);
    for (ports, 0..) |*port, index| port.* = try reader.input(.{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_term, .child = 0, .coordinate = @intCast(index) });
    var draws: [106]S = undefined;
    for (&draws, 0..) |*port, index| port.* = try reader.input(.{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_term, .child = 1, .coordinate = @intCast(index) });
    const words = try a.alloc([4]S, public.words.len);
    defer a.free(words);
    for (words, 0..) |*bytes, index| {
        for (bytes, 0..) |*byte, part| byte.* = try reader.input(.{ .circuit = 0, .wire = 0, .uses = 1, .kind = .child_cell, .child = 1, .coordinate = @intCast(index), .part = @intCast(part) });
    }
    const exports = try a.alloc(A.SourceExports(S), i.natives.len);
    defer a.free(exports);
    const ram = try a.alloc([31]S, i.memory_geometry.len);
    defer a.free(ram);
    try b.activate();
    defer if (b.active) b.deactivate();
    var pair_draws: [47][2]S = undefined;
    for (&pair_draws, 0..) |*pair, index| pair.* = draws[2 * index ..][0..2].*;
    const universal = try G.ChallengeSet.init(pair_draws);
    const state_element = universal.get(.registers_state);
    const memory_element = universal.get(.memory_access);
    const program_element = universal.get(.program_access);
    const state_relation = A.Relation(S, 2){ .z = state_element.z, .powers = state_element.alpha_powers[0..2].* };
    const memory_relation = A.Relation(S, 7){ .z = memory_element.z, .powers = memory_element.alpha_powers[0..7].* };
    var offset: usize = 0;
    for (c.admission.components.context.natives, i.natives, 0..) |n, pin, index| {
        const base = 4 + Public.NATIVE_WORDS * index;
        var boundary = A.Boundary(S){ .initial_pc = word(words[base]), .final_pc = word(words[base + 1]), .final_clock_plus_one = word(words[base + 2]).add(S.one()), .initial_register_bytes = undefined, .final_register_bytes = undefined, .register_last_clock = undefined };
        for (0..32) |reg| {
            boundary.initial_register_bytes[reg] = words[base + 3 + reg];
            boundary.final_register_bytes[reg] = words[base + 35 + reg];
            boundary.register_last_clock[reg] = word(words[base + 67 + reg]);
        }
        if (index != 0) {
            const previous = base - Public.NATIVE_WORDS;
            try b.constrainZero(boundary.initial_pc.sub(word(words[previous + 1])));
            for (0..32) |reg| for (0..4) |byte| try b.constrainZero(words[base + 3 + reg][byte].sub(words[previous + 35 + reg][byte]));
        }
        try b.constrainZero(word(words[base + 99]).sub(boundary.final_pc));
        const projections = n.component.layout.slots;
        const native = try A.native(S, projections, ports[offset + 8 ..][0..projections.len], boundary, state_relation, memory_relation);
        var source = A.SourceExports(S){ .program = S.zero(), .transition = S.zero(), .fetches = S.one(), .events = S.zero(), .tables = native.tables, .byte_requests = S.zero() };
        var program_tuple: [5]S = undefined;
        for (&program_tuple, 0..) |*value, part| value.* = word(words[base + 99 + part]);
        source.program = (try program_element.combine(&program_tuple)).inverse().neg();
        for (projections, 0..) |slot, slot_index| if (slot.kind == .program) {
            source.program = source.program.add(ports[offset + 8 + slot_index]);
            source.fetches = source.fetches.add(S.fromBase(M.fromCanonical(slot.n_rows)));
        };
        var opposite = S.zero();
        const accesses_start = offset + 8 + projections.len;
        for (n.component.slots, 0..) |_, slot_index| {
            const at = accesses_start + 10 * slot_index;
            source.transition = source.transition.add(ports[at]);
            opposite = opposite.add(ports[at + 1]);
            source.events = source.events.add(ports[at + 2]);
            for (ports[at + 3 ..][0..7]) |claim| source.byte_requests = source.byte_requests.add(claim);
        }
        for (A.nativeConstraints(S, native, S.zero(), S.zero(), opposite)) |constraint| try b.constrainZero(constraint);
        exports[index] = source;
        offset += try @import("block_v6_partitioned_composition_v1.zig").publicCount(projections.len, n.component.slots.len);
        _ = pin;
    }
    const program_provider = ports[offset];
    const table_providers = ports[offset + 1 ..][0..6].*;
    offset += 7;
    for (ram) |*claims| {
        @memcpy(claims[0..29], ports[offset..][0..29]);
        @memcpy(claims[29..31], ports[offset + 84 ..][0..2]);
        offset += 86;
    }
    const interval = ports[offset..][0..2].*;
    const ranges = ports[offset + 2 ..][0..2].*;
    if (offset + 4 != ports.len) return error.InvalidClosedUnionOperandMap;
    const delta_relation = relation(5, draws[98], draws[99]);
    var delta = S.zero();
    const changes_base = 4 + Public.NATIVE_WORDS * i.natives.len;
    for (0..public.words[1]) |index| {
        const at = changes_base + 3 * index;
        const address = halves(words[at]);
        const before = halves(words[at + 1]);
        const after = halves(words[at + 2]);
        delta = delta.add(delta_relation.combine(.{ S.one(), address[0], address[1], after[0], after[1] }).inverse());
        delta = delta.sub(delta_relation.combine(.{ S.one(), address[0], address[1], before[0], before[1] }).inverse());
    }
    const memory = try A.memory(S, ram, interval, ranges, delta);
    for (memory.constraints) |constraint| try b.constrainZero(constraint);
    for (A.global(S, exports, program_provider, memory.transition, table_providers, word(words[2]), word(words[3]))) |constraint| try b.constrainZero(constraint);
    b.deactivate();
    var circuit = try b.finish();
    errdefer circuit.deinit();
    const evaluated = try a.alloc(Q, if (evaluate) circuit.nodes.len else 0);
    errdefer a.free(evaluated);
    if (evaluate) try circuit.evaluateInto(reader.inputs.items, evaluated);
    const inputs = try reader.inputs.toOwnedSlice(a);
    errdefer a.free(inputs);
    return .{ .allocator = a, .circuit = circuit, .inputs = inputs, .values = evaluated, .sources = try reader.sources.toOwnedSlice(a) };
}

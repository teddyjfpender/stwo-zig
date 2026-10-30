//! Symbolic closure equations for a future geometry-key family. These are
//! equations, not proof authority. Inputs MUST be the SAME authenticated
//! physical claim ports and statement-word/byte ports used by the child
//! verifier. In particular expected_delta is not a free witness: it must be
//! independently derived from admitted snapshots or a proved state provider.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Part = @import("../../prover/block_v5_native_lookup_request_source_v1.zig").Partition;
const Source = @import("../../prover/block_v5_native_projection_fused_source_v1.zig");
pub fn Memory(comptime S: type) type {
    return struct {
        transition: S,
        constraints: [6]S,
    };
}
/// Complete six nonterminal memory provider equalities. Counter boundedness
/// still follows the independently admitted finite geometry and authenticated
/// count planes; generic field equations cannot replace that admission.
pub fn memory(comptime S: type, ram: []const [31]S, interval: [2]S, range16: [2]S, expected_delta: S) !Memory(S) {
    if (ram.len == 0) return error.InvalidWindowClosureShape;
    var transition = S.zero();
    var link = S.zero();
    var initial = interval[0];
    var range = range16[0];
    var first_count = S.zero();
    var range_count = S.zero();
    var delta = expected_delta.neg();
    for (ram) |sums| {
        transition = transition.add(sums[0]);
        link = link.add(sums[1]);
        initial = initial.add(sums[2]);
        for (sums[3..27]) |sum| range = range.add(sum);
        first_count = first_count.add(sums[27]);
        range_count = range_count.add(sums[28]);
        delta = delta.add(sums[29]).add(sums[30]);
    }
    return .{ .transition = transition, .constraints = .{
        link, initial, range, first_count.sub(interval[1]), range_count.sub(range16[1]), delta,
    } };
}
pub fn Boundary(comptime S: type) type {
    return struct {
        initial_pc: S,
        final_pc: S,
        final_clock_plus_one: S,
        initial_register_bytes: [32][4]S,
        final_register_bytes: [32][4]S,
        register_last_clock: [32]S,
    };
}
pub fn Relation(comptime S: type, comptime n: usize) type {
    return struct {
        z: S,
        powers: [n]S,
        pub fn combine(self: @This(), tuple: [n]S) S {
            var result = self.z.neg();
            for (tuple, self.powers) |value, power| result = result.add(value.mul(power));
            return result;
        }
    };
}
pub fn Native(comptime S: type) type {
    return struct {
        state: S,
        registers: S,
        ordinary_memory: S,
        clock_memory: S,
        tables: [6]S,
    };
}
/// Derive native closure operands from authenticated projection claims, rather
/// than introducing precomputed residuals as free public/witness inputs. Both
/// register boundary tuples and PC/clock boundary tuples remain symbolic.
pub fn native(comptime S: type, slots: []const Source.Slot, claims: []const S, boundary: Boundary(S), state_relation: Relation(S, 2), memory_relation: Relation(S, 7)) !Native(S) {
    if (slots.len != claims.len) return error.InvalidWindowClosureShape;
    var partitions: [@import("../../prover/block_v5_native_lookup_request_source_v1.zig").PARTITION_COUNT]S = @splat(S.zero());
    for (slots, claims) |slot, claim| switch (slot.kind) {
        .program => {},
        .lookup => |lookup| {
            const at = @intFromEnum(lookup.partition);
            partitions[at] = partitions[at].add(claim);
        },
    };
    var state = try inverse(S, state_relation.combine(.{ boundary.initial_pc, S.one() }));
    state = state.sub(try inverse(S, state_relation.combine(.{ boundary.final_pc, boundary.final_clock_plus_one })));
    var registers = S.zero();
    for (0..32) |index| {
        const address = S.fromBase(M.fromCanonical(@intCast(index)));
        registers = registers.add(try inverse(S, memory_relation.combine(.{ S.zero(), address, S.zero() } ++ boundary.initial_register_bytes[index])));
        registers = registers.sub(try inverse(S, memory_relation.combine(.{ S.zero(), address, boundary.register_last_clock[index] } ++ boundary.final_register_bytes[index])));
    }
    return .{ .state = state.add(partitions[@intFromEnum(Part.registers_state)]), .registers = registers.add(partitions[@intFromEnum(Part.register_memory_access)]).add(partitions[@intFromEnum(Part.register_clock_memory_access)]), .ordinary_memory = partitions[@intFromEnum(Part.ordinary_memory_access)], .clock_memory = partitions[@intFromEnum(Part.clock_memory_access)], .tables = partitions[0..6].* };
}
fn inverse(comptime S: type, value: S) !S {
    if (comptime @hasDecl(S, "inverse")) return value.inverse();
    return value.inv();
}
/// The explicit source mode determines how ordinary memory closes. Legacy V7
/// adds an opposite per-access sidecar; endpoint V8 instead supplies a proved
/// unique endpoint table. Callers must not silently mix these semantics.
pub fn nativeConstraints(comptime S: type, value: Native(S), caller_state: S, caller_registers: S, ordinary_supplier: S) [4]S {
    return .{ value.state.add(caller_state), value.registers.add(caller_registers), value.ordinary_memory.add(ordinary_supplier), value.clock_memory };
}

pub fn SourceExports(comptime S: type) type {
    return struct {
        program: S,
        transition: S,
        fetches: S,
        events: S,
        tables: [6]S,
        byte_requests: S,
    };
}
/// Global ROM, RAM-transition, six lookup tables and exact count equalities.
/// Every source operand is derived from authenticated physical claims, not a
/// separately supplied residual. The containing compiler MUST admit integer
/// total-count bounds strictly below the base-field modulus, or use a proved
/// limb-count gadget instead; field equality alone does not prevent wraparound.
pub fn global(comptime S: type, sources: []const SourceExports(S), program_provider: S, memory_transition: S, table_providers: [6]S, expected_fetches: S, expected_events: S) [10]S {
    var program = program_provider;
    var transition = memory_transition;
    var tables = table_providers;
    var fetches = expected_fetches.neg();
    var events = expected_events.neg();
    for (sources) |source| {
        program = program.add(source.program);
        transition = transition.add(source.transition);
        fetches = fetches.add(source.fetches);
        events = events.add(source.events);
        for (&tables, source.tables) |*sum, request| sum.* = sum.add(request);
        const byte_pair = @intFromEnum(@import("../../air/lookups/tables/schema.zig").Kind.range_check_8_8);
        tables[byte_pair] = tables[byte_pair].add(source.byte_requests);
    }
    return .{ program, transition } ++ tables ++ .{ fetches, events };
}

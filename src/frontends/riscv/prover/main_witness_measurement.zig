//! Exact generic-program measurement for the main-witness work authority.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_api = @import("stwo_prover_api");
const clock_update_interaction = @import("../air/clock_update_interaction.zig");
const guest_components = @import("../air/guest_precompile/component_registry.zig");
const lookup_counter = @import("../air/lookups/tables/counter.zig");
const lookup_schema = @import("../air/lookups/tables/schema.zig");
const memory_interaction = @import("../air/memory_commitment/interaction.zig");
const program_commitment = @import("../air/program/commitment.zig");
const program_interaction = @import("../air/program/interaction.zig");
const semantic_eval = @import("../air/semantic_eval.zig");
const opcode_entries = @import("../air/lookups/opcode_entries.zig");
const trace = @import("../runner/trace.zig");

pub const MeasuredLookup = struct {
    operations: prover_api.work_profile.FieldOperations,
    fixed_table_entries: u64,
};

threadlocal var active_measurement: ?*prover_api.work_profile.FieldOperations = null;

const CountingScalar = struct {
    value: M31,

    pub fn zero() CountingScalar {
        return fromBase(M31.zero());
    }
    pub fn one() CountingScalar {
        return fromBase(M31.one());
    }
    pub fn fromBase(value: M31) CountingScalar {
        return .{ .value = value };
    }
    pub fn isZero(self: CountingScalar) bool {
        return self.value.isZero();
    }
    pub fn eql(lhs: CountingScalar, rhs: CountingScalar) bool {
        return lhs.value.eql(rhs.value);
    }
    pub fn add(lhs: CountingScalar, rhs: CountingScalar) CountingScalar {
        active_measurement.?.additions += 1;
        return fromBase(lhs.value.add(rhs.value));
    }
    pub fn sub(lhs: CountingScalar, rhs: CountingScalar) CountingScalar {
        active_measurement.?.additions += 1;
        return fromBase(lhs.value.sub(rhs.value));
    }
    pub fn neg(self: CountingScalar) CountingScalar {
        return fromBase(self.value.neg());
    }
    pub fn mul(lhs: CountingScalar, rhs: CountingScalar) CountingScalar {
        active_measurement.?.multiplications += 1;
        return fromBase(lhs.value.mul(rhs.value));
    }
    pub fn square(self: CountingScalar) CountingScalar {
        active_measurement.?.multiplications += 1;
        return fromBase(self.value.square());
    }
};

fn beginMeasurement(operations: *prover_api.work_profile.FieldOperations) !void {
    if (active_measurement != null) return error.NestedMainWitnessWorkMeasurement;
    operations.* = .{};
    active_measurement = operations;
}

fn endMeasurement() void {
    active_measurement = null;
}

pub fn measureOpcodeLookupBuild(family: trace.OpcodeFamily) !MeasuredLookup {
    var columns: [trace.MAX_FAMILY_COLUMNS]CountingScalar = undefined;
    for (&columns, 0..) |*column, index|
        column.* = .fromBase(M31.fromU64(index + 1));
    var operations: prover_api.work_profile.FieldOperations = undefined;
    try beginMeasurement(&operations);
    defer endMeasurement();
    const list = try opcode_entries.Entries(CountingScalar).fromMain(
        family,
        columns[0..trace.nColumnsForFamily(family)],
    );
    var fixed_table_entries: u64 = 0;
    for (list.entries[0..list.len]) |item| {
        if (lookup_counter.kindForDomain(item.domain) != null)
            fixed_table_entries += 1;
    }
    return .{
        .operations = operations,
        .fixed_table_entries = fixed_table_entries,
    };
}

pub fn measureAuditRow(
    family: trace.OpcodeFamily,
) !prover_api.work_profile.FieldOperations {
    var columns: [trace.MAX_FAMILY_COLUMNS]CountingScalar = undefined;
    for (&columns, 0..) |*column, index|
        column.* = .fromBase(M31.fromU64(index + 7));
    var operations: prover_api.work_profile.FieldOperations = undefined;
    try beginMeasurement(&operations);
    defer endMeasurement();
    _ = try semantic_eval.Eval(CountingScalar).evaluate(
        family,
        columns[0..semantic_eval.BaseEval.mainColumnCount(family)],
        CountingScalar.one(),
    );
    return operations;
}

pub fn measureProgramEntryBuild() !prover_api.work_profile.FieldOperations {
    const main = [_]CountingScalar{CountingScalar.one()} **
        program_commitment.N_MAIN_COLUMNS;
    var operations: prover_api.work_profile.FieldOperations = undefined;
    try beginMeasurement(&operations);
    defer endMeasurement();
    _ = program_interaction.entriesGeneric(CountingScalar, main);
    return operations;
}

pub fn measureMemoryEntryBuild() !prover_api.work_profile.FieldOperations {
    const main = [_]CountingScalar{CountingScalar.one()} ** 8;
    var operations: prover_api.work_profile.FieldOperations = undefined;
    try beginMeasurement(&operations);
    defer endMeasurement();
    _ = memory_interaction.entriesGeneric(
        CountingScalar,
        main,
        CountingScalar.one(),
    );
    return operations;
}

pub fn measureClockEntryBuild() !prover_api.work_profile.FieldOperations {
    const Row = clock_update_interaction.RowFor(CountingScalar);
    const one = CountingScalar.one();
    const row = Row{
        .enabler = one,
        .addr_space = one,
        .addr = one,
        .clock_prev = one,
        .value = .{ one, one, one, one },
        .clock_prev_low20 = one,
        .clock_prev_high6 = one,
    };
    var operations: prover_api.work_profile.FieldOperations = undefined;
    try beginMeasurement(&operations);
    defer endMeasurement();
    _ = clock_update_interaction.orderedEntriesGeneric(CountingScalar, row);
    return operations;
}

pub fn guestCallerTraceRowWork() prover_api.work_profile.FieldOperations {
    const identity = guest_components.CallerConstraintIdentity.canonical();
    const words: u64 = identity.canonical_words;
    // Per word, canonicalBase executes four subtractions, three additions,
    // and six squarings. The prefix and reverse Montgomery sweeps add three
    // multiplications per word; the whole batch performs one inversion.
    return .{
        .additions = words * 7,
        .multiplications = words * 9,
        .inversions = 1,
    };
}

pub fn guestLookupRequestsPerRow() !u64 {
    var result: u64 = 0;
    for (guest_components.caller_fixed_table_demand) |count| {
        result = try add(result, count);
    }
    return result;
}

pub fn guestLookupRowWork() !prover_api.work_profile.FieldOperations {
    const identity = guest_components.CallerConstraintIdentity.canonical();
    const access_gaps: u64 = 1 + @as(u64, identity.lanes);
    const checked_passes: u64 = 2;
    // Each access-clock gap executes four additions and one multiplication.
    // The span-end request scales one high byte per pass. Only the mutation
    // pass subtracts one from each requested dense-table coefficient.
    return .{
        .additions = try add(
            try mul(try mul(access_gaps, 4), checked_passes),
            try guestLookupRequestsPerRow(),
        ),
        .multiplications = try mul(
            try add(access_gaps, 1),
            checked_passes,
        ),
    };
}

pub fn fixedTableCells() !u64 {
    var result: u64 = 0;
    for (0..lookup_schema.KIND_COUNT) |index| {
        const kind: lookup_schema.Kind = @enumFromInt(index);
        result = try add(result, @intCast(lookup_schema.size(kind)));
    }
    return result;
}

fn add(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch error.MainWitnessWorkOverflow;
}

fn mul(lhs: u64, rhs: u64) !u64 {
    return std.math.mul(u64, lhs, rhs) catch error.MainWitnessWorkOverflow;
}

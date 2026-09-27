//! Host read optimization parity; the reference uses complete caller/state
//! rows through the generic algebraic bridge, including inactive padding.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const External = @import("block_execution_external_trace_v2.zig");
const bridge = @import("block_execution_external_access_bridge_v2.zig");
const integer = @import("block_execution_integer_bridge_v2.zig");
const framework = @import("../recursion/air/framework_interaction.zig");
const keccak = @import("../air/guest_precompile/keccakf_caller.zig");
const state = @import("../air/guest_precompile/keccakf_witness.zig");
const layout = @import("../air/guest_precompile/keccakf_trace.zig").Layout;
const sha = @import("../air/guest_precompile/sha256_memory_caller.zig");
const signer = @import("../air/guest_precompile/secp256k1_recovery_caller.zig");

fn trace(kind: External.Kind, slot: usize, fixed: []const Column, main: []const Column) External.Trace {
    return .{ .allocator = std.testing.allocator, .descriptor = .{ .kind = kind, .slot = slot, .log_size = 5, .fixed_offset = 0, .main_offset = 0, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 32 } }, .fixed = fixed, .main = main, .log_size = 5, .base_clock = 0, .storage = undefined, .witness = undefined };
}

test "block-v5 selected Keccak quotient words match full algebraic tuples" {
    var caller: [keccak.Layout.main_columns]Q = undefined;
    for (&caller, 0..) |*value, i| value.* = Q.fromM31Array(.{ M.fromCanonical(@intCast(i + 3)), M.fromCanonical(@intCast(i + 7)), M.one(), M.fromCanonical(11) });
    var input: [state.state_cell_count]Q = undefined;
    var output: [state.state_cell_count]Q = undefined;
    for (&input, &output, 0..) |*before, *after, i| {
        // Deliberately nonbinary/nonbase: quotient and OODS inputs are field
        // evaluations, and zero enablers must not erase their expressions.
        before.* = Q.fromM31Array(.{ M.fromCanonical(@intCast(17 + i)), M.fromCanonical(23), M.one(), M.fromCanonical(31) });
        after.* = Q.fromM31Array(.{ M.fromCanonical(@intCast(37 + 3 * i)), M.fromCanonical(41), M.fromCanonical(43), M.one() });
    }
    for ([_]Q{ Q.zero(), Q.fromBase(M.fromCanonical(7)), Q.fromM31(M.one(), M.one(), M.one(), M.one()) }) |active| {
        caller[keccak.Layout.enabler] = active;
        for (0..bridge.KECCAK_ACCESS_COUNT) |slot| {
            const input_word: [32]Q = if (slot == 0) @splat(Q.zero()) else input[(slot - 1) * 32 ..][0..32].*;
            const output_word: [32]Q = if (slot == 0) @splat(Q.zero()) else output[(slot - 1) * 32 ..][0..32].*;
            const selected = try bridge.keccakPairFromWordBits(Q, &caller, input_word, output_word, slot);
            const reference = try bridge.keccakPair(Q, &caller, &input, &output, slot);
            try std.testing.expectEqualDeep(reference, selected);
            if (slot != 0) {
                try std.testing.expect(!selected.before[0].isZero());
                var changed = output_word;
                changed[0] = changed[0].add(Q.one());
                const wrong = try bridge.keccakPairFromWordBits(Q, &caller, input_word, changed, slot);
                try std.testing.expect(!wrong.after[0].eql(selected.after[0]));
            }
        }
    }
    try std.testing.expectError(error.InvalidKeccakAccessSlot, bridge.keccakPairFromWordBits(Q, &caller, @splat(Q.zero()), @splat(Q.zero()), bridge.KECCAK_ACCESS_COUNT));
}

test "block-v5 optimized Keccak host tuples match full state reference including output wrap" {
    const a = std.testing.allocator;
    const columns = try a.alloc(Column, layout.main_columns);
    defer a.free(columns);
    var initialized: usize = 0;
    defer for (columns[0..initialized]) |column| a.free(column.values);
    for (columns) |*column| {
        const values = try a.alloc(M, 32);
        @memset(values, M.zero());
        column.* = .{ .log_size = 5, .values = values };
        initialized += 1;
    }
    // Distinct bit patterns at every logical row make a wrong word, physical
    // ordering, or +27 wrap disagree with the complete-state reference.
    for (0..32) |logical| {
        const physical = framework.committedRow(logical, 5);
        for (0..state.state_cell_count) |cell| {
            const word = cell / 32;
            const bits = ((word + 1) * 0x9e37 + (logical + 1) * 0x79b9) ^ ((logical + 3) * (word + 7) * 0x45d9);
            @constCast(columns[layout.state + cell].values)[physical] = M.fromCanonical(@intCast((bits >> @intCast(cell % 32)) & 1));
        }
        for (0..keccak.Layout.main_columns) |i|
            @constCast(columns[layout.caller + i].values)[physical] = M.fromCanonical(@intCast(11 + i));
        @constCast(columns[layout.caller + keccak.Layout.enabler].values)[physical] = if (logical == 0 or logical == 1 or logical == 31) M.one() else M.zero();
        @constCast(columns[layout.caller + keccak.Layout.pointer_register].values)[physical] = M.fromCanonical(17);
        @constCast(columns[layout.caller + keccak.Layout.pointer_double_word_index].values)[physical] = M.fromCanonical(0x12345);
        @constCast(columns[layout.caller + keccak.Layout.execution_clock].values)[physical] = M.fromCanonical(@intCast(0x1234 + logical));
    }
    for ([_]usize{ 0, 1, 31, 2, 30 }) |logical| {
        const physical = framework.committedRow(logical, 5);
        const output_row = framework.committedRow((logical + 27) % 32, 5);
        var caller: [keccak.Layout.main_columns]Q = undefined;
        for (&caller, 0..) |*value, i| value.* = Q.fromBase(columns[layout.caller + i].values[physical]);
        var input: [state.state_cell_count]Q = undefined;
        var output: [state.state_cell_count]Q = undefined;
        for (&input, &output, 0..) |*before, *after, cell| {
            before.* = Q.fromBase(columns[layout.state + cell].values[physical]);
            after.* = Q.fromBase(columns[layout.state + cell].values[output_row]);
        }
        for (0..bridge.KECCAK_ACCESS_COUNT) |slot| {
            const current = trace(.keccak, slot, &.{}, columns);
            const actual = try current.pairAt(logical);
            const reference = try bridge.keccakPair(Q, &caller, &input, &output, slot);
            if (!reference.active.isZero()) try std.testing.expectEqualDeep(reference, actual);
            // Inactive raw tuples may differ, but both must emit the exact
            // canonical zero integer witness and no active memory event.
            try std.testing.expectEqualDeep((try integer.Witness.fromPair(reference, 0)).columns(), (try integer.Witness.fromPair(actual, 0)).columns());
            try std.testing.expectEqual(reference.active.isZero(), actual.active.isZero());
        }
    }
    // Pointer and inactive slots must not touch any state column. Keep the
    // complete descriptors/logs and temporarily deny state values to catch
    // accidental reads; production init still requires all selected values.
    const saved = try a.alloc([]const M, state.state_cell_count);
    defer a.free(saved);
    for (saved, 0..) |*values, cell| {
        values.* = columns[layout.state + cell].values;
        columns[layout.state + cell].values = &.{};
    }
    defer for (saved, 0..) |values, cell| {
        columns[layout.state + cell].values = values;
    };
    const pointer = trace(.keccak, 0, &.{}, columns);
    try std.testing.expect(!(try pointer.pairAt(31)).active.isZero());
    for (0..bridge.KECCAK_ACCESS_COUNT) |slot| {
        const inactive = trace(.keccak, slot, &.{}, columns);
        try std.testing.expect((try inactive.pairAt(30)).active.isZero());
    }
    const descriptor = pointer.descriptor;
    const fixed = try a.alloc(Column, layout.preprocessed_columns);
    defer a.free(fixed);
    for (fixed) |*column| column.* = .{ .log_size = 5, .values = &.{} };
    try std.testing.expectError(error.InvalidExternalAccessTrace, External.Trace.initSelected(a, descriptor, fixed, columns));
}

test "block-v5 inactive SHA and signer host rows preserve canonical zero witness" {
    const a = std.testing.allocator;
    const widths = [_]usize{ sha.PHYSICAL_MAIN_COLUMN_COUNT, signer.Layout.main_columns };
    for ([_]External.Kind{ .sha, .signer }, widths) |kind, width| {
        const columns = try a.alloc(Column, width);
        defer a.free(columns);
        // Only the base-domain enabler is readable: inactive host rows must
        // not scan payloads. This does not bypass production init validation.
        for (columns) |*column| column.* = .{ .log_size = 5, .values = &.{} };
        const zero: [32]M = @splat(M.zero());
        const fixed = [_]Column{.{ .log_size = 5, .values = &zero }};
        if (kind == .signer) columns[signer.Layout.is_active].values = &zero;
        const count = if (kind == .sha) bridge.SHA_ACCESS_COUNT else bridge.SIGNER_ACCESS_COUNT;
        for (0..count) |slot| {
            const current = trace(kind, slot, &fixed, columns);
            const actual = try current.pairAt(31);
            try std.testing.expect(actual.active.isZero());
            try std.testing.expectEqualDeep(integer.Witness.zero().columns(), (try integer.Witness.fromPair(actual, 0)).columns());
        }
        try std.testing.expectError(error.InvalidExternalAccessTrace, External.Trace.initSelected(a, trace(kind, 0, &fixed, columns).descriptor, &fixed, columns));
    }
}

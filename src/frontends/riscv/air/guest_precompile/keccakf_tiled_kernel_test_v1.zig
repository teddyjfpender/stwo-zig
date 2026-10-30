const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const A = @import("keccakf_authority.zig");
const W = @import("keccakf_witness.zig");
const Tiled = @import("keccakf_tiled_kernel_v1.zig");
const Sink = struct {
    chi_count: usize = 0,
    xor_count: usize = 0,
    pub fn constraint(_: *@This(), value: M, degree: u8) !void {
        if (degree > 3) return error.UnderestimatedTiledKeccakDegree;
        if (!value.isZero()) return error.InvalidTiledKeccakConstraint;
    }
    pub fn chi(self: *@This(), tuple: anytype, weight: M) !void {
        if (weight.isZero()) return;
        if (weight.v != 1) return error.InvalidTiledKeccakWeight;
        if (tuple.len == 6) {
            var code = tuple[0].v;
            var a: [5]u8 = undefined;
            var b: [5]u8 = undefined;
            for (&a, &b) |*x, *y| {
                const digit = code % 28;
                code /= 28;
                x.* = @intCast(digit % 8);
                y.* = @intCast(digit / 8);
            }
            if (code > 1) return error.InvalidTiledKeccakChi;
            const entry = try A.chiTableEntry(try A.chiTableRow(a, b, code == 1));
            if (entry.packed_input != tuple[0].v) return error.InvalidTiledKeccakChi;
            for (entry.output, tuple[1..]) |expected, actual| if (expected != actual.v) return error.InvalidTiledKeccakChi;
            self.chi_count += 1;
            return;
        }
        var encoded = tuple[0].v;
        var theta: [3]u8 = undefined;
        for (&theta) |*value| {
            value.* = @intCast(encoded % 28);
            encoded /= 28;
        }
        if (encoded > 1) return error.InvalidTiledKeccakChi;
        const original = A.compactChiTableEntry(try A.compactChiTableRow(theta, encoded == 1)) catch return error.InvalidTiledKeccakChi;
        if (tuple[1].v != original.output) return error.InvalidTiledKeccakChi;
        self.chi_count += 1;
    }
    pub fn xor(self: *@This(), tuple: anytype, weight: M) !void {
        if (weight.isZero()) return;
        if (weight.v != 1) return error.InvalidTiledKeccakWeight;
        if (tuple.len == 6) {
            var sums: [3][2]u8 = undefined;
            for (&sums, tuple[0..3]) |*pair, value| {
                if (value.v > 45) return error.InvalidTiledKeccakXor;
                pair.* = .{ @intCast(value.v % 8), @intCast(value.v / 8) };
            }
            const entry = try A.xor5TableEntry(try A.xor5TableRow(sums));
            for (entry.sliced_parities, tuple[3..]) |expected, actual| if (expected != actual.v) return error.InvalidTiledKeccakXor;
            self.xor_count += 1;
            return;
        }
        var encoded = tuple[0].v;
        var inputs: [5]u8 = undefined;
        for (&inputs) |*value| {
            value.* = @intCast(encoded % 16);
            encoded /= 16;
        }
        if (encoded != 0) return error.InvalidTiledKeccakXor;
        const original = try A.compactXor5TableEntry(try A.compactXor5TableRow(inputs));
        if (tuple[1].v != original.output) return error.InvalidTiledKeccakXor;
        self.xor_count += 1;
    }
};
fn check(comptime K: type, trace: *const K.Trace) !void {
    var sink = Sink{};
    for (0..trace.rows.len) |row| {
        const fixed = try K.fixed(row, trace.calls);
        try K.evaluate(M, trace.view(row), &fixed, &sink);
    }
    const slots = (trace.calls + 1) / 2;
    try std.testing.expectEqual(slots * A.round_count * A.width_bits, sink.chi_count);
    try std.testing.expectEqual(slots * A.round_count * A.geometry.parity_positions, sink.xor_count);
}
test "tiled Keccak paired lane kernel preserves all rounds tables boundaries and rejects mutations" {
    inline for (.{ 1, 5 }) |lanes| {
        const K = Tiled.Kernel(lanes);
        const a = std.testing.allocator;
        var input_a: A.State = undefined;
        var input_b: A.State = undefined;
        for (&input_a, &input_b, 0..) |*x, *y, i| {
            x.* = 0x123456789abcdef0 ^ (@as(u64, i) *% 0x9876543212345678);
            y.* = ~x.* ^ (@as(u64, i) *% 0xabcdef0123456789);
        }
        inline for (.{ @as(usize, 0), 1, 2, 3 }) |calls| {
            var slots: [(calls + 1) / 2]W.Slot = undefined;
            for (&slots, 0..) |*slot, i| {
                slot.* = try W.buildSlot(input_a, if (i * 2 + 1 < calls) input_b else null);
                try W.validateSlot(slot);
            }
            var trace = try K.fromSlots(a, &slots, calls);
            defer trace.deinit();
            try check(K, &trace);
            if (calls == 0) continue;
            const cases = [_]struct { row: usize, column: usize }{
                .{ .row = 0, .column = 0 },
                .{ .row = 2 * K.rows_per_state, .column = 0 },
                .{ .row = 2 * K.rows_per_state, .column = K.parity },
                .{ .row = 2 * K.rows_per_state, .column = K.chi },
                .{ .row = 2 * K.rows_per_state, .column = K.xor },
                .{ .row = 27 * K.rows_per_state, .column = 0 },
            };
            for (cases) |fault| {
                const saved = trace.rows[fault.row][fault.column];
                trace.rows[fault.row][fault.column] = saved.add(M.one());
                if (check(K, &trace)) |_| return error.AcceptedTiledKeccakMutation else |err| if (err == error.OutOfMemory) return err;
                trace.rows[fault.row][fault.column] = saved;
            }
            std.debug.print("KECCAK_TILE lanes={d} calls={d} rows={d} main={d} fixed={d} main_fixed_cells={d} private_lookup_events={d} proof_qualified=false\n", .{ lanes, calls, trace.rows.len, K.main_columns, K.fixed_columns, trace.rows.len * (K.main_columns + K.fixed_columns), ((calls + 1) / 2) * A.round_count * (A.width_bits + A.geometry.parity_positions) });
        }
    }
}

test "tiled Keccak exact shifted-mask and complete permutation-area model" {
    inline for (.{ 1, 5 }) |lanes| {
        const K = Tiled.Kernel(lanes);
        const MaskView = struct {
            seen: *[K.main_columns][4 * K.rows_per_state + 1]bool,
            pub fn read(self: @This(), offset: i32, column: usize) !M {
                const index = offset + @as(i32, 2 * K.rows_per_state);
                if (column >= K.main_columns or index < 0 or index >= @as(i32, @intCast(self.seen[0].len))) return error.InvalidTiledMask;
                self.seen[column][@intCast(index)] = true;
                return M.zero();
            }
        };
        var masks: [K.main_columns][4 * K.rows_per_state + 1]bool = @splat(@splat(false));
        const selectors: K.Fixed = @splat(M.zero());
        var sink = Sink{};
        try K.evaluate(M, MaskView{ .seen = &masks }, &selectors, &sink);
        var main_samples: usize = 0;
        for (masks) |mask| {
            var count: usize = 0;
            for (mask) |used| count += @intFromBool(used);
            try std.testing.expect(count > 0);
            main_samples += count;
        }
        // Separate private χ/xor partitions, two fractions per LogUp batch.
        // These are modeled columns; no interaction producer is implemented.
        const interaction = 4 * ((K.state_width + 1) / 2 + (K.parity_width + 1) / 2);
        const domain = std.math.ceilPowerOfTwoAssert(usize, K.rows_per_slot);
        const columns = K.main_columns + K.fixed_columns + interaction;
        const samples = main_samples + K.fixed_columns + 2 * interaction;
        std.debug.print("KECCAK_TILE_MODEL lanes={d} paired_calls=2 active_rows={d} padded_rows={d} main={d} fixed={d} modeled_interaction={d} all_cells={d} main_samples={d} modeled_all_samples={d} caller_io_included=false proof_qualified=false\n", .{ lanes, K.rows_per_slot, domain, K.main_columns, K.fixed_columns, interaction, columns * domain, main_samples, samples });
        var leaf_calls: usize = 0;
        for ([_]usize{ K.fixed_columns, K.main_columns, interaction }) |words| {
            const bytes = core.channel.blake3.PROTOCOL_ID.len + 1 + 4 * words;
            leaf_calls += (bytes + 63) / 64 + (bytes + 1023) / 1024 - 1;
        }
        const depth: usize = std.math.log2_int(usize, domain) + 1; // diagnostic blowup1
        const path_calls = 3 * depth * 2; // framed64-byte nodes require2 blocks
        std.debug.print("KECCAK_TILE_HASH_MODEL lanes={d} leaf_G_per_query={d} path_G_per_query={d} total_G_per_query={d} query_sharing_excluded=true other_components_excluded=true\n", .{ lanes, leaf_calls * 56, path_calls * 56, (leaf_calls + path_calls) * 56 });
        // A claimed saving must count masks as well as current-row columns.
        try std.testing.expect(main_samples > K.main_columns);
        try std.testing.expect(columns * domain > 204768);
        try std.testing.expect(samples < 18781);
    }
}

fn checkVariant(comptime K: type, trace: *const K.Trace, full_chi: bool, full_xor: bool) !void {
    var sink = Sink{};
    for (0..trace.rows.len) |row| {
        const selectors = try K.fixed(row, trace.calls);
        try K.evaluate(M, trace.view(row), &selectors, &sink);
    }
    const slots = (trace.calls + 1) / 2;
    try std.testing.expectEqual(slots * A.round_count * (if (full_chi) @as(usize, 320) else 1600), sink.chi_count);
    const xor_per_round = if (full_xor) K.xor_event_columns * K.rows_per_state else A.geometry.parity_positions;
    try std.testing.expectEqual(slots * A.round_count * xor_per_round, sink.xor_count);
}
test "tiled Keccak full and hybrid table universes preserve every original output independently" {
    inline for (.{ 1, 5 }) |lanes| inline for (.{ false, true }) |full_chi| inline for (.{ false, true }) |full_xor| {
        const K = Tiled.KernelWithTables(lanes, full_chi, full_xor);
        const a = std.testing.allocator;
        var input_a: A.State = undefined;
        var input_b: A.State = undefined;
        for (&input_a, &input_b, 0..) |*x, *y, i| {
            x.* = 0x123456789abcdef0 ^ (@as(u64, i) *% 0x9876543212345678);
            y.* = ~x.* ^ (@as(u64, i) *% 0xabcdef0123456789);
        }
        for ([_]usize{ 1, 2, 3 }) |calls| {
            var slots: [2]W.Slot = undefined;
            for (slots[0 .. (calls + 1) / 2], 0..) |*slot, i| slot.* = try W.buildSlot(input_a, if (i * 2 + 1 < calls) input_b else null);
            var trace = try K.fromSlots(a, slots[0 .. (calls + 1) / 2], calls);
            defer trace.deinit();
            try checkVariant(K, &trace, full_chi, full_xor);
            // Attack paired-column cancellation in a would-be packed five-output tuple:
            // +16 in one output and -1 in the adjacent output preserve that packing.
            // Each actual output is a separate lookup coordinate and must fail.
            const first = 3 * K.rows_per_state;
            trace.rows[first][0] = trace.rows[first][0].add(M.fromCanonical(16));
            const second_row = first + 1 / lanes;
            const second_col = (1 % lanes) * 64;
            trace.rows[second_row][second_col] = trace.rows[second_row][second_col].sub(M.one());
            if (checkVariant(K, &trace, full_chi, full_xor)) |_| return error.AcceptedPackedOutputAlias else |err| if (err == error.OutOfMemory) return err;
        }
    };
}

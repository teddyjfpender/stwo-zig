//! Replays the uniqueness board's `sat` counterexamples against the AIR itself.
//!
//! A `sat` from `scripts/air_uniqueness_board.py` is a claim about a *model* of
//! the AIR: two witness assignments satisfying the modelled constraints and
//! table memberships that agree on the architectural inputs and disagree on an
//! output. Before such a pair is treated as a real under-constraint it must be
//! decided by the production oracle: both sides are rebuilt as full committed
//! rows and fed to `row_admissibility.verdict`, which evaluates the family's
//! direct constraints and every activated preprocessed-table request.
//!
//!   - both rows accepted: the AIR really admits two rows with the same
//!     architectural inputs and different outputs — a row-local under-constraint;
//!   - either row rejected: the model admits something the AIR does not, and the
//!     verdict names the constraint set or the specific table request the query
//!     is missing.
//!
//! Bus relations stay outside the verdict on both sides, and identically so:
//! the query skips them and `row_admissibility` does not decide them, so an
//! accept/accept result here is exactly "row-local under-constraint", not a
//! statement about global closure.
//!
//! Runtime: milliseconds — a handful of single-row constraint evaluations; the
//! replay test skips when no board export is present.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const lookup_entry = @import("stwo_riscv_frontend").air.lookups.entry;
const lookup_table = @import("stwo_riscv_frontend").air.lookups.tables.schema;
const row_admissibility = @import("row_admissibility.zig");
const semantic_eval = @import("stwo_riscv_frontend").air.semantic_eval;
const shifts_imm_test_oracle =
    @import("stwo_riscv_frontend").testing.shifts_imm_semantics.Semantics(QM31);
const shifts_reg_test_oracle =
    @import("stwo_riscv_frontend").testing.shifts_reg_semantics.Semantics(QM31);
const trace_mod = @import("stwo_riscv_frontend").runner.trace;
const uniqueness_ir = @import("uniqueness_ir_test.zig");

const OpcodeFamily = trace_mod.OpcodeFamily;

/// One rebuilt side of a counterexample pair.
const Row = struct {
    values: [trace_mod.MAX_FAMILY_COLUMNS]QM31,
    len: usize,

    fn columns(self: *const Row) []const QM31 {
        return self.values[0..self.len];
    }
};

fn jsonInt(value: std.json.Value, name: []const u8) !u64 {
    switch (value) {
        .integer => |raw| {
            if (raw < 0) {
                std.debug.print("  column {s}: negative value {d}\n", .{ name, raw });
                return error.MalformedCounterexample;
            }
            return @intCast(raw);
        },
        else => {
            std.debug.print("  column {s}: not an integer\n", .{name});
            return error.MalformedCounterexample;
        },
    }
}

/// Rebuild one copy as the exact committed row: every layout column must be
/// present in the payload (the solver's don't-care columns are exported as 0),
/// and alias columns such as `next_pc` are not committed, so they are simply
/// never looked up.
fn buildRow(
    comptime family: OpcodeFamily,
    shared: std.json.ObjectMap,
    witness: std.json.ObjectMap,
    outputs: std.json.ObjectMap,
) !Row {
    const names = comptime uniqueness_ir.columnNames(family);
    var row = Row{
        .values = .{QM31.zero()} ** trace_mod.MAX_FAMILY_COLUMNS,
        .len = names.len,
    };
    for (names, 0..) |name, index| {
        const cell = shared.get(name) orelse witness.get(name) orelse outputs.get(name) orelse {
            std.debug.print("  column {s}: missing from counterexample\n", .{name});
            return error.MalformedCounterexample;
        };
        row.values[index] = QM31.fromBase(M31.fromU64(try jsonInt(cell, name)));
    }
    return row;
}

fn describeVerdict(label: []const u8, verdict: row_admissibility.Verdict) void {
    switch (verdict) {
        .accepted => std.debug.print("    copy {s}: accepted\n", .{label}),
        .direct_constraints => std.debug.print(
            "    copy {s}: REJECTED by direct constraints\n",
            .{label},
        ),
        .table => |rejection| std.debug.print(
            "    copy {s}: REJECTED by table request {d} ({s})\n",
            .{ label, rejection.index, @tagName(rejection.domain) },
        ),
    }
}

/// Where a rejected row disagrees with the model: name each non-vanishing
/// direct constraint so a modelling gap is attributable from the output alone.
fn explainDirectRejection(comptime family: OpcodeFamily, row: *const Row) !void {
    const evaluation = try semantic_eval.evaluate(family, row.columns(), QM31.one());
    for (evaluation.values[0..evaluation.len], 0..) |value, index| {
        if (!value.isZero()) {
            std.debug.print("      constraint {d} does not vanish\n", .{index});
        }
    }
}

fn decidePair(comptime family: OpcodeFamily, root: std.json.ObjectMap) !void {
    const shared = root.get("shared_inputs").?.object;
    const witnesses = root.get("witnesses").?.object;
    const first = witnesses.get("a").?.object;
    const second = witnesses.get("b").?.object;

    const row_a = try buildRow(
        family,
        shared,
        first.get("witness").?.object,
        first.get("outputs").?.object,
    );
    const row_b = try buildRow(
        family,
        shared,
        second.get("witness").?.object,
        second.get("outputs").?.object,
    );

    // The pair only demonstrates non-uniqueness if it really differs on a
    // committed cell; a pair differing solely on an alias output would be
    // asking the oracle to decide a column it cannot see.
    var differs = false;
    for (row_a.columns(), row_b.columns()) |a, b| {
        if (!a.eql(b)) differs = true;
    }
    if (!differs) return error.CounterexampleDoesNotDiffer;

    const verdict_a = try row_admissibility.verdict(family, row_a.columns());
    const verdict_b = try row_admissibility.verdict(family, row_b.columns());
    describeVerdict("a", verdict_a);
    describeVerdict("b", verdict_b);
    if (verdict_a == .direct_constraints) try explainDirectRejection(family, &row_a);
    if (verdict_b == .direct_constraints) try explainDirectRejection(family, &row_b);
}

fn setCell(comptime family: OpcodeFamily, row: *Row, name: []const u8, value: u32) void {
    const names = comptime uniqueness_ir.columnNames(family);
    for (names, 0..) |candidate, index| {
        if (std.mem.eql(u8, candidate, name)) {
            row.values[index] = QM31.fromBase(M31.fromU64(value));
            return;
        }
    }
    @panic("setCell: unknown column");
}

/// `SRA rd, x0, 31` with every input byte-clean: rs1 reads zero, the shift
/// amount is 31 (`bit_multiplier_right = 128`), and the honest result is zero.
fn honestSraRow(comptime family: OpcodeFamily) Row {
    const names = comptime uniqueness_ir.columnNames(family);
    var row = Row{
        .values = .{QM31.zero()} ** trace_mod.MAX_FAMILY_COLUMNS,
        .len = names.len,
    };
    // Access clocks are derived from the one-based instruction clock. Leaving
    // this at the zero-filled default would make the honest baseline wrap
    // before the carry-window mutation is even applied.
    setCell(family, &row, "clock", 1);
    setCell(family, &row, "opcode_sra_flag", 1);
    setCell(family, &row, "bit_multiplier_right", 128);
    setCell(family, &row, "bit_shift_marker_7", 1);
    setCell(family, &row, "limb_shift_marker_3", 1);
    setCell(family, &row, "rd_addr", 1);
    setCell(family, &row, "rd_nonzero", 1);
    setCell(family, &row, "rd_inv", 1);
    switch (family) {
        // The register operand must agree with the marker-encoded amount
        // through the `range_check_20` request on `7 - (rs2 - amount) / 32`.
        .shifts_reg => {
            setCell(family, &row, "rs2_addr", 2);
            setCell(family, &row, "rs2_prev_0", 31);
            setCell(family, &row, "rs2_next_0", 31);
        },
        .shifts_imm => setCell(family, &row, "imm_truncated", 31),
        else => @compileError("not a register-shift family"),
    }
    return row;
}

// The legacy carry lookup sent only `(bit_multiplier - 1) - carry` to an
// 8-bit box. It therefore admitted negative carries even though the witness
// recurrence produces carries only in `[0, bit_multiplier)`. For this
// amount-31 row, `carry_3 = -128` and `result[0] = 1` satisfy every direct
// equation over a zero operand and move the architectural register write.
//
// The production request now pairs each carry with its complement, so this
// concrete former counterexample must reach the fourth carry pair and be
// rejected there in both shift families.
test "uniqueness counterexamples: SRA negative carry is rejected by the carry window" {
    inline for ([_]OpcodeFamily{ .shifts_imm, .shifts_reg }) |family| {
        const honest = honestSraRow(family);

        var forged = honest;
        setCell(family, &forged, "bit_shift_carry_3", (1 << 31) - 1 - 128);
        setCell(family, &forged, "result_0", 1);
        setCell(family, &forged, "rd_next_0", 1);

        // Same architectural inputs by construction; only the honest written
        // register is now row-locally admissible.
        try std.testing.expectEqual(
            row_admissibility.Verdict.accepted,
            try row_admissibility.verdict(family, honest.columns()),
        );
        const carry_pair_index: usize = switch (family) {
            .shifts_imm => 9,
            .shifts_reg => 13,
            else => unreachable,
        };
        switch (try row_admissibility.verdict(family, forged.columns())) {
            .table => |rejection| {
                try std.testing.expectEqual(lookup_entry.Domain.range_check_8_8, rejection.domain);
                try std.testing.expectEqual(carry_pair_index, rejection.index);
            },
            else => return error.NegativeCarryWasNotRejected,
        }
    }
}

test "shift carry window: every byte candidate is admitted iff below the multiplier" {
    const marker_names = [_][]const u8{
        "bit_shift_marker_0", "bit_shift_marker_1",
        "bit_shift_marker_2", "bit_shift_marker_3",
        "bit_shift_marker_4", "bit_shift_marker_5",
        "bit_shift_marker_6", "bit_shift_marker_7",
    };
    const carry_names = [_][]const u8{
        "bit_shift_carry_0", "bit_shift_carry_1",
        "bit_shift_carry_2", "bit_shift_carry_3",
    };
    inline for ([_]OpcodeFamily{ .shifts_imm, .shifts_reg }) |family| {
        const module = switch (family) {
            .shifts_imm => shifts_imm_test_oracle,
            .shifts_reg => shifts_reg_test_oracle,
            else => unreachable,
        };
        inline for (0..8) |bit_shift| {
            const multiplier: u32 = @as(u32, 1) << bit_shift;
            inline for (0..4) |carry_index| {
                for (0..256) |carry| {
                    var committed = honestSraRow(family);
                    inline for (0..8) |marker| {
                        setCell(
                            family,
                            &committed,
                            marker_names[marker],
                            @intFromBool(marker == bit_shift),
                        );
                    }
                    setCell(family, &committed, "bit_multiplier_right", multiplier);
                    setCell(
                        family,
                        &committed,
                        carry_names[carry_index],
                        @intCast(carry),
                    );

                    const row = try module.Row.fromOracleColumns(committed.columns());
                    const pairs = module.carryRangePairs(row.semantic);
                    if (carry < multiplier) {
                        _ = try lookup_table.indexSecure(
                            .range_check_8_8,
                            &pairs[carry_index],
                        );
                    } else {
                        try std.testing.expectError(
                            error.ValueOutOfRange,
                            lookup_table.indexSecure(
                                .range_check_8_8,
                                &pairs[carry_index],
                            ),
                        );
                    }
                }
            }
        }
    }
}

test "uniqueness counterexamples: decide each exported sat pair on the row oracle" {
    const allocator = std.testing.allocator;
    var dir = std.fs.cwd().openDir("zig-out/uniqueness-counterexamples", .{ .iterate = true }) catch {
        return error.SkipZigTest;
    };
    defer dir.close();

    var iterator = dir.iterate();
    var decided: usize = 0;
    while (try iterator.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".json")) continue;

        const bytes = try dir.readFileAlloc(allocator, entry.name, 1 << 20);
        defer allocator.free(bytes);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
        defer parsed.deinit();

        const root = parsed.value.object;
        const family_name = root.get("family").?.string;
        const family = std.meta.stringToEnum(OpcodeFamily, family_name) orelse
            return error.UnknownFamily;
        std.debug.print("\n  {s}:\n", .{family_name});
        switch (family) {
            inline else => |comptime_family| try decidePair(comptime_family, root),
        }
        decided += 1;
    }
    std.debug.print("\n  decided {d} counterexample pair(s)\n", .{decided});
    try std.testing.expect(decided > 0);
}

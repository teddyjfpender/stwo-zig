//! Exact relation-entry sequences for all proof-bearing RV32IM families.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("entry.zig");
const semantics = @import("../semantics/mod.zig");
const trace = @import("../../runner/trace.zig");

pub const List = entry.List;

pub fn entryCount(family: trace.OpcodeFamily) usize {
    return switch (family) {
        .base_alu_reg => 18,
        .base_alu_imm => 16,
        // Four carry/complement byte pairs close every sub-byte carry window,
        // two requests beyond the pinned Stark-V vectors.
        .shifts_reg => 20,
        .shifts_imm => 16,
        .lt_reg => 14,
        .lt_imm => 11,
        .branch_eq => 9,
        .branch_lt => 11,
        .lui => 7,
        .auipc => 12,
        // 12 pinned Stark-V entries plus the row-local source, target, and
        // immediate bindings (see semantics/jalr.zig).
        .jalr => 18,
        .jal => 8,
        .load_store => 16,
        .mul => 16,
        .mulh => 22,
        // 22 pinned Stark-V entries plus two divisor-byte checks and one
        // quotient-sign check.
        .div => 25,
        .fence => 3,
    };
}

pub fn batchSize(family: trace.OpcodeFamily) usize {
    return switch (family) {
        .mul, .mulh, .div => 1,
        else => 2,
    };
}

pub fn batchCount(family: trace.OpcodeFamily) usize {
    return (entryCount(family) + batchSize(family) - 1) / batchSize(family);
}

pub fn interactionColumnCount(family: trace.OpcodeFamily) usize {
    return batchCount(family) * 4;
}

/// Reconstruct the exact committed family row from a runner row. This is used
/// only by witness generation; AIR evaluation calls `fromMain` directly.
pub fn fromTraceRow(row: trace.TraceRow, family: trace.OpcodeFamily) !List {
    var values: [trace.MAX_FAMILY_COLUMNS]M31 = .{M31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    var columns: [trace.MAX_FAMILY_COLUMNS][]M31 = undefined;
    for (0..trace.MAX_FAMILY_COLUMNS) |index| columns[index] = values[index .. index + 1];
    trace.fillFamilyColumns(&columns, 0, row, family);
    const count = trace.nColumnsForFamily(family);
    var secure: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
    for (values[0..count], secure[0..count]) |value, *dst| dst.* = QM31.fromBase(value);
    return fromMain(family, secure[0..count]);
}

pub fn Entries(comptime S: type) type {
    return struct {
        const e = entry.Builder(S);
        const sem = semantics.Families(S);

        pub fn fromMain(
            family: trace.OpcodeFamily,
            columns: []const S,
        ) !e.List {
            const result = switch (family) {
                .base_alu_reg => try baseAluReg(columns),
                .base_alu_imm => try baseAluImm(columns),
                .shifts_reg => try shiftsReg(columns),
                .shifts_imm => try shiftsImm(columns),
                .lt_reg => try ltReg(columns),
                .lt_imm => try ltImm(columns),
                .branch_eq => try branchEq(columns),
                .branch_lt => try branchLt(columns),
                .lui => try lui(columns),
                .auipc => try auipc(columns),
                .jalr => try jalr(columns),
                .jal => try jal(columns),
                .load_store => try loadStore(columns),
                .mul => try mul(columns),
                .mulh => try mulh(columns),
                .div => try div(columns),
                .fence => try fence(columns),
            };
            std.debug.assert(result.len == entryCount(family));
            std.debug.assert(result.batch_size == batchSize(family));
            return result;
        }

        fn parse(comptime module: type, columns: []const S) !module.Row {
            if (@hasDecl(module.Row, "fromOracleColumns")) return module.Row.fromOracleColumns(columns);
            return module.Row.fromMainColumns(columns);
        }

        fn addProgram(list: *e.List, request: anytype) void {
            e.program(list, request.numerator, request.tuple);
        }

        fn addState(list: *e.List, requests: anytype) void {
            e.stateRequests(list, requests);
        }

        fn baseAluReg(columns: []const S) !e.List {
            const module = sem.base_alu_reg;
            const row = try parse(module, columns);
            const active = row.active();
            const accesses = module.accessLookups(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.stateChain(&list, sem.common.registersStateChain(row.pc, row.clk), active);
            e.accessChain(&list, accesses.rs1, active);
            e.accessChain(&list, accesses.rs2, active);
            const bitwise_active = module.bitwiseLookupEnabler(row);
            for (module.bitwiseLookups(row)) |tuple| e.bitwise(&list, bitwise_active.neg(), tuple);
            e.range88(&list, active.neg(), .{ row.result[0], row.result[1] });
            e.range88(&list, active.neg(), .{ row.result[2], row.result[3] });
            e.accessChain(&list, accesses.rd, active);
            return list;
        }

        fn baseAluImm(columns: []const S) !e.List {
            const module = sem.base_alu_imm;
            const row = try parse(module, columns);
            const active = row.active();
            const accesses = module.accessLookups(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.range811(&list, active.neg(), module.immediateRangeLookup(row));
            e.stateChain(&list, sem.common.registersStateChain(row.pc, row.clk), active);
            e.accessChain(&list, accesses.rs1, active);
            const bitwise_active = module.bitwiseLookupEnabler(row);
            for (module.bitwiseLookups(row)) |tuple| e.bitwise(&list, bitwise_active.neg(), tuple);
            e.range88(&list, active.neg(), .{ row.result[0], row.result[1] });
            e.range88(&list, active.neg(), .{ row.result[2], row.result[3] });
            e.accessChain(&list, accesses.rd, active);
            return list;
        }

        fn shiftsReg(columns: []const S) !e.List {
            const module = sem.shifts_reg;
            const row = try parse(module, columns);
            const active = row.semantic.active();
            const accesses = module.accessLookups(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.stateChain(&list, module.stateLookup(row), active);
            e.accessChain(&list, accesses.rs1, active);
            e.accessChain(&list, accesses.rs2, active);
            e.range20(&list, active.neg(), module.shiftAmountRangeLookup(row));
            for (module.carryRangePairs(row.semantic)) |values| e.range88(&list, active.neg(), values);
            for (module.rdRangePairs(row.semantic)) |values| e.range88(&list, active.neg(), values);
            e.accessChain(&list, accesses.rd, active);
            e.rangeM31(&list, row.semantic.is_sra.neg(), module.signRangeLookup(row.semantic));
            return list;
        }

        fn shiftsImm(columns: []const S) !e.List {
            const module = sem.shifts_imm;
            const row = try parse(module, columns);
            const active = row.semantic.active();
            const accesses = module.accessLookups(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.stateChain(&list, module.stateLookup(row), active);
            e.accessChain(&list, accesses.rs1, active);
            for (module.carryRangePairs(row.semantic)) |values| e.range88(&list, active.neg(), values);
            for (module.rdRangePairs(row.semantic)) |values| e.range88(&list, active.neg(), values);
            e.accessChain(&list, accesses.rd, active);
            e.rangeM31(&list, row.semantic.is_sra.neg(), module.signRangeLookup(row.semantic));
            return list;
        }

        fn ltReg(columns: []const S) !e.List {
            const module = sem.lt_reg;
            const row = try parse(module, columns);
            const active = row.active();
            const accesses = module.accessLookups(row);
            const positive = module.positiveDiffLookup(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.stateChain(&list, module.stateLookup(row), active);
            e.accessChain(&list, accesses.rs1, active);
            e.accessChain(&list, accesses.rs2, active);
            e.range88(&list, active.neg(), module.mslRangeLookup(row));
            e.range20(&list, positive.numerator.neg(), positive.value);
            e.accessChain(&list, accesses.rd, active);
            return list;
        }

        fn ltImm(columns: []const S) !e.List {
            const module = sem.lt_imm;
            const row = try parse(module, columns);
            const active = row.active();
            const accesses = module.accessLookups(row);
            const positive = module.positiveDiffLookup(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.range884(&list, active.neg(), module.immediateRangeLookup(row));
            e.stateChain(&list, module.stateLookup(row), active);
            e.accessChain(&list, accesses.rs1, active);
            e.range20(&list, positive.numerator.neg(), positive.value);
            e.accessChain(&list, accesses.rd, active);
            return list;
        }

        fn branchEq(columns: []const S) !e.List {
            const module = sem.branch_eq;
            const row = try parse(module, columns);
            const requests = module.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            e.access(&list, requests.rs1);
            e.access(&list, requests.rs2);
            addState(&list, requests.state);
            return list;
        }

        fn branchLt(columns: []const S) !e.List {
            const module = sem.branch_lt;
            const row = try parse(module, columns);
            const requests = module.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            e.access(&list, requests.rs1);
            e.access(&list, requests.rs2);
            e.range88(&list, requests.ranges.shifted_msls.numerator, requests.ranges.shifted_msls.tuple.values());
            e.range20(&list, requests.ranges.positive_difference.numerator, requests.ranges.positive_difference.tuple.value);
            return list;
        }

        fn lui(columns: []const S) !e.List {
            const module = sem.lui;
            const row = try parse(module, columns);
            const requests = module.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            e.range884(&list, requests.immediate_range.numerator, requests.immediate_range.tuple.values());
            e.memory(&list, requests.rd.consume.numerator, requests.rd.consume.tuple);
            e.memory(&list, requests.rd.emit.numerator, requests.rd.emit.tuple);
            e.range20(&list, requests.rd.clock_gap.numerator, requests.rd.clock_gap.tuple.value);
            return list;
        }

        fn auipc(columns: []const S) !e.List {
            const module = sem.auipc;
            const row = try parse(module, columns);
            const requests = module.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            for (requests.ranges.result) |request|
                e.range88(&list, request.numerator, request.tuple.values());
            e.range88(
                &list,
                requests.ranges.pc[0].numerator,
                requests.ranges.pc[0].tuple.values(),
            );
            e.rangeM31(
                &list,
                requests.ranges.pc[1].numerator,
                requests.ranges.pc[1].tuple.values(),
            );
            e.range88(
                &list,
                requests.ranges.immediate[0].numerator,
                requests.ranges.immediate[0].tuple.values(),
            );
            e.rangeM31(
                &list,
                requests.ranges.immediate[1].numerator,
                requests.ranges.immediate[1].tuple.values(),
            );
            e.access(&list, requests.rd);
            return list;
        }

        fn jalr(columns: []const S) !e.List {
            const module = sem.jalr;
            const row = try parse(module, columns);
            const requests = module.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            e.access(&list, requests.rs1);
            e.range88(&list, requests.rs1_middle_bytes.numerator, requests.rs1_middle_bytes.tuple.values());
            e.range88(&list, requests.rs1_outer_bytes.numerator, requests.rs1_outer_bytes.tuple.values());
            e.range20(
                &list,
                requests.target_word_low_20.numerator,
                requests.target_word_low_20.tuple.value,
            );
            e.range88(
                &list,
                requests.target_word_high_8.numerator,
                requests.target_word_high_8.tuple.values(),
            );
            e.range88(
                &list,
                requests.target_middle_bytes.numerator,
                requests.target_middle_bytes.tuple.values(),
            );
            e.rangeM31(&list, requests.target_m31.numerator, requests.target_m31.tuple.values());
            e.range884(
                &list,
                requests.immediate_range.numerator,
                requests.immediate_range.tuple.values(),
            );
            addState(&list, requests.state);
            e.range88(&list, requests.rd_middle_bytes.numerator, requests.rd_middle_bytes.tuple.values());
            e.rangeM31(&list, requests.rd_m31.numerator, requests.rd_m31.tuple.values());
            e.access(&list, requests.rd);
            return list;
        }

        fn jal(columns: []const S) !e.List {
            const module = sem.jal;
            const row = try parse(module, columns);
            const requests = module.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            e.range88(&list, requests.ranges.middle_bytes.numerator, requests.ranges.middle_bytes.tuple.values());
            e.rangeM31(&list, requests.ranges.m31_split.numerator, requests.ranges.m31_split.tuple.values());
            // The operative pinned schema has one predecessor request. Do not use the
            // stale duplicated helper entry retained for historical adapter tests.
            e.memory(&list, requests.rd.consume[0].numerator, requests.rd.consume[0].tuple);
            e.memory(&list, requests.rd.emit.numerator, requests.rd.emit.tuple);
            e.range20(&list, requests.rd.clock_gap.numerator, requests.rd.clock_gap.tuple.value);
            return list;
        }

        fn loadStore(columns: []const S) !e.List {
            const module = sem.load_store;
            const row = try parse(module, columns);
            const active = row.active();
            const accesses = module.accessLookups(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.stateChain(&list, module.stateLookup(row), active);
            e.accessChain(&list, accesses.rs1, active);
            e.range20(&list, active.neg(), module.alignedAddressRangeLookup(row));
            e.rangeM31(&list, active.neg(), module.baseAddressM31Lookup(row));
            e.accessChain(&list, accesses.src, active);
            e.accessChain(&list, accesses.dst, active);
            const sign_ranges = module.signRangeLookups(row);
            e.rangeM31(&list, row.is_lb.neg(), sign_ranges[0]);
            e.rangeM31(&list, row.is_lh.neg(), sign_ranges[1]);
            return list;
        }

        fn mul(columns: []const S) !e.List {
            const module = sem.mul;
            const row = try parse(module, columns);
            const requests = module.lookups(row);
            var list = e.List{ .batch_size = 1 };
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            e.access(&list, requests.rs1);
            e.access(&list, requests.rs2);
            for (requests.product_ranges) |request| {
                e.range811(&list, request.numerator, request.tuple.values());
            }
            e.access(&list, requests.rd);
            return list;
        }

        fn mulh(columns: []const S) !e.List {
            const module = sem.mulh;
            const row = try parse(module, columns);
            const requests = module.lookups(row);
            var list = e.List{ .batch_size = 1 };
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            e.access(&list, requests.rs1);
            e.access(&list, requests.rs2);
            for (requests.product_ranges) |request| {
                e.range811(&list, request.numerator, request.tuple.values());
            }
            for (requests.sign_ranges) |request| {
                e.rangeM31(&list, request.numerator, request.tuple.values());
            }
            e.access(&list, requests.rd);
            return list;
        }

        fn div(columns: []const S) !e.List {
            const module = sem.div;
            const row = try parse(module, columns);
            const requests = module.lookups(row);
            var list = e.List{ .batch_size = 1 };
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            e.access(&list, requests.rs1);
            e.access(&list, requests.rs2);
            for (requests.divisor_ranges) |request| {
                e.range88(&list, request.numerator, request.tuple.values());
            }
            for (requests.quotient_remainder_ranges) |request| {
                e.range811(&list, request.numerator, request.tuple.values());
            }
            e.rangeM31(
                &list,
                requests.quotient_sign_range.numerator,
                requests.quotient_sign_range.tuple.values(),
            );
            e.range88(&list, requests.sign_range.numerator, requests.sign_range.tuple.values());
            e.range20(
                &list,
                requests.positive_remainder_diff.numerator,
                requests.positive_remainder_diff.tuple.value,
            );
            e.access(&list, requests.rd);
            return list;
        }

        fn fence(columns: []const S) !e.List {
            const module = sem.fence;
            const row = try parse(module, columns);
            const requests = module.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            return list;
        }
    };
}

const shipped = Entries(QM31);

pub const fromMain = shipped.fromMain;

test "opcode lookup matrix preserves reviewed family geometry" {
    const expected_entries = [_]usize{ 18, 16, 20, 16, 14, 11, 9, 11, 7, 12, 18, 8, 16, 16, 22, 25, 3 };
    const expected_batches = [_]usize{ 9, 8, 10, 8, 7, 6, 5, 6, 4, 6, 9, 4, 8, 16, 22, 25, 2 };
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        try std.testing.expectEqual(expected_entries[index], entryCount(family));
        try std.testing.expectEqual(expected_batches[index], batchCount(family));
    }
}

test "opcode lookup vectors preserve exact domain order and batching" {
    const D = entry.Domain;
    const expected = [_][]const D{
        // base_alu_reg
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .bitwise, .bitwise, .bitwise, .bitwise, .range_check_8_8, .range_check_8_8, .memory_access, .memory_access, .range_check_20 },
        // base_alu_imm
        &.{ .program_access, .range_check_8_11, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .bitwise, .bitwise, .bitwise, .bitwise, .range_check_8_8, .range_check_8_8, .memory_access, .memory_access, .range_check_20 },
        // shifts_reg
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_20, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_8_8, .memory_access, .memory_access, .range_check_20, .range_check_m31 },
        // shifts_imm
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_8_8, .memory_access, .memory_access, .range_check_20, .range_check_m31 },
        // lt_reg
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_8_8, .range_check_20, .memory_access, .memory_access, .range_check_20 },
        // lt_imm
        &.{ .program_access, .range_check_8_8_4, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .range_check_20, .memory_access, .memory_access, .range_check_20 },
        // branch_eq
        &.{ .program_access, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .registers_state, .registers_state },
        // branch_lt
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_8_8, .range_check_20 },
        // lui
        &.{ .program_access, .registers_state, .registers_state, .range_check_8_8_4, .memory_access, .memory_access, .range_check_20 },
        // auipc
        &.{ .program_access, .registers_state, .registers_state, .range_check_8_8, .range_check_8_8, .range_check_8_8, .range_check_m31, .range_check_8_8, .range_check_m31, .memory_access, .memory_access, .range_check_20 },
        // jalr
        &.{ .program_access, .memory_access, .memory_access, .range_check_20, .range_check_8_8, .range_check_8_8, .range_check_20, .range_check_8_8, .range_check_8_8, .range_check_m31, .range_check_8_8_4, .registers_state, .registers_state, .range_check_8_8, .range_check_m31, .memory_access, .memory_access, .range_check_20 },
        // jal
        &.{ .program_access, .registers_state, .registers_state, .range_check_8_8, .range_check_m31, .memory_access, .memory_access, .range_check_20 },
        // load_store
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .range_check_20, .range_check_m31, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_m31, .range_check_m31 },
        // mul
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .memory_access, .memory_access, .range_check_20 },
        // mulh
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_m31, .range_check_m31, .memory_access, .memory_access, .range_check_20 },
        // div
        &.{ .program_access, .registers_state, .registers_state, .memory_access, .memory_access, .range_check_20, .memory_access, .memory_access, .range_check_20, .range_check_8_8, .range_check_8_8, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_8_11, .range_check_m31, .range_check_8_8, .range_check_20, .memory_access, .memory_access, .range_check_20 },
        // fence
        &.{ .program_access, .registers_state, .registers_state },
    };

    var columns = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        const list = try fromMain(family, columns[0..trace.nColumnsForFamily(family)]);
        try std.testing.expectEqual(expected[index].len, list.len);
        for (expected[index], list.entries[0..list.len]) |want, actual| {
            try std.testing.expectEqual(want, actual.domain);
        }
        try std.testing.expectEqual(batchSize(family), list.batch_size);
        try std.testing.expectEqual(batchCount(family), list.batchCount());
        for (0..list.batchCount()) |batch| {
            const first = batch * list.batch_size;
            const entries_in_batch = @min(list.batch_size, list.len - first);
            try std.testing.expect(entries_in_batch == 1 or entries_in_batch == 2);
            if (family == .mul or family == .mulh or family == .div) {
                try std.testing.expectEqual(@as(usize, 1), entries_in_batch);
            }
        }
    }
}

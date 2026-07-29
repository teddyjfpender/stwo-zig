//! Canonical typed construction of one production opcode-family AIR program.
//!
//! Direct constraints and ordered lookup events used to have independent row
//! parsers and family dispatches.  `Builder(S)` is now their shared production
//! source: the shipped QM31 evaluator requests only the direct section, the
//! LogUp layer requests only the lookup section, and formal extraction requests
//! the complete `ConstraintProgram`.  The section views keep the hot per-row
//! paths from constructing a large unused sibling section.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("lookups/entry.zig");
const semantics = @import("semantics/mod.zig");
const trace = @import("../runner/trace.zig");

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
        // immediate bindings.
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

pub fn Builder(comptime S: type) type {
    return struct {
        const Self = @This();
        const e = entry.Builder(S);
        const sem = semantics.Families(S);

        pub const MAX_DIRECT_CONSTRAINTS: usize = sem.div.N_CONSTRAINTS + 1;

        pub const DirectConstraints = struct {
            /// Only `values[0..len]` is meaningful.
            values: [Self.MAX_DIRECT_CONSTRAINTS]S = undefined,
            len: usize = 0,

            pub fn allZero(self: @This()) bool {
                for (self.values[0..self.len]) |value| {
                    if (!value.isZero()) return false;
                }
                return true;
            }
        };

        /// Complete per-row program used by formal serialization.
        pub const ConstraintProgram = struct {
            active_row: S,
            direct_constraints: Self.DirectConstraints,
            lookup_entries: e.List,
        };

        /// Direct-only production view.  It deliberately omits the large lookup
        /// list so direct evaluation retains its prior stack/work profile.
        pub const DirectView = struct {
            direct_constraints: Self.DirectConstraints,
        };

        /// Lookup-only production view.  It deliberately does not evaluate the
        /// direct polynomial array.
        pub const LookupView = struct {
            lookup_entries: e.List,
        };

        const Section = enum { direct, lookups, full };

        pub fn mainColumnCount(family: trace.OpcodeFamily) usize {
            return switch (family) {
                .base_alu_reg => moduleColumnCount(sem.base_alu_reg),
                .base_alu_imm => moduleColumnCount(sem.base_alu_imm),
                .shifts_reg => moduleColumnCount(sem.shifts_reg),
                .shifts_imm => moduleColumnCount(sem.shifts_imm),
                .lt_reg => moduleColumnCount(sem.lt_reg),
                .lt_imm => moduleColumnCount(sem.lt_imm),
                .branch_eq => moduleColumnCount(sem.branch_eq),
                .branch_lt => moduleColumnCount(sem.branch_lt),
                .lui => moduleColumnCount(sem.lui),
                .auipc => moduleColumnCount(sem.auipc),
                .jalr => moduleColumnCount(sem.jalr),
                .jal => moduleColumnCount(sem.jal),
                .load_store => moduleColumnCount(sem.load_store),
                .mul => moduleColumnCount(sem.mul),
                .mulh => moduleColumnCount(sem.mulh),
                .div => moduleColumnCount(sem.div),
                .fence => moduleColumnCount(sem.fence),
            };
        }

        pub fn constraintCount(family: trace.OpcodeFamily) usize {
            return switch (family) {
                .base_alu_reg => moduleConstraintCount(sem.base_alu_reg),
                .base_alu_imm => moduleConstraintCount(sem.base_alu_imm),
                .shifts_reg => moduleConstraintCount(sem.shifts_reg),
                .shifts_imm => moduleConstraintCount(sem.shifts_imm),
                .lt_reg => moduleConstraintCount(sem.lt_reg),
                .lt_imm => moduleConstraintCount(sem.lt_imm),
                .branch_eq => moduleConstraintCount(sem.branch_eq),
                .branch_lt => moduleConstraintCount(sem.branch_lt),
                .lui => moduleConstraintCount(sem.lui),
                .auipc => moduleConstraintCount(sem.auipc),
                .jalr => moduleConstraintCount(sem.jalr),
                .jal => moduleConstraintCount(sem.jal),
                .load_store => moduleConstraintCount(sem.load_store),
                .mul => moduleConstraintCount(sem.mul),
                .mulh => moduleConstraintCount(sem.mulh),
                .div => moduleConstraintCount(sem.div),
                .fence => moduleConstraintCount(sem.fence),
            };
        }

        /// Build direct constraints and lookups from one parsed production row.
        pub fn build(
            family: trace.OpcodeFamily,
            columns: []const S,
            is_active: S,
        ) !Self.ConstraintProgram {
            return construct(.full, family, columns, is_active);
        }

        /// Build the exact section consumed by `semantic_eval`.
        pub fn buildDirect(
            family: trace.OpcodeFamily,
            columns: []const S,
            is_active: S,
        ) !Self.DirectView {
            return construct(.direct, family, columns, is_active);
        }

        /// Build the exact section consumed by `opcode_entries`.
        pub fn buildLookups(
            family: trace.OpcodeFamily,
            columns: []const S,
        ) !Self.LookupView {
            return construct(.lookups, family, columns, {});
        }

        fn PlacementArg(comptime section: Section) type {
            return if (section == .lookups) void else S;
        }

        fn Result(comptime section: Section) type {
            return switch (section) {
                .direct => Self.DirectView,
                .lookups => Self.LookupView,
                .full => Self.ConstraintProgram,
            };
        }

        fn construct(
            comptime section: Section,
            family: trace.OpcodeFamily,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            return switch (family) {
                .base_alu_reg => constructFamily(section, .base_alu_reg, sem.base_alu_reg, columns, is_active),
                .base_alu_imm => constructFamily(section, .base_alu_imm, sem.base_alu_imm, columns, is_active),
                .shifts_reg => constructFamily(section, .shifts_reg, sem.shifts_reg, columns, is_active),
                .shifts_imm => constructFamily(section, .shifts_imm, sem.shifts_imm, columns, is_active),
                .lt_reg => constructFamily(section, .lt_reg, sem.lt_reg, columns, is_active),
                .lt_imm => constructFamily(section, .lt_imm, sem.lt_imm, columns, is_active),
                .branch_eq => constructFamily(section, .branch_eq, sem.branch_eq, columns, is_active),
                .branch_lt => constructFamily(section, .branch_lt, sem.branch_lt, columns, is_active),
                .lui => constructFamily(section, .lui, sem.lui, columns, is_active),
                .auipc => constructFamily(section, .auipc, sem.auipc, columns, is_active),
                .jalr => constructFamily(section, .jalr, sem.jalr, columns, is_active),
                .jal => constructFamily(section, .jal, sem.jal, columns, is_active),
                .load_store => constructFamily(section, .load_store, sem.load_store, columns, is_active),
                .mul => constructFamily(section, .mul, sem.mul, columns, is_active),
                .mulh => constructFamily(section, .mulh, sem.mulh, columns, is_active),
                .div => constructFamily(section, .div, sem.div, columns, is_active),
                .fence => constructFamily(section, .fence, sem.fence, columns, is_active),
            };
        }

        fn constructFamily(
            comptime section: Section,
            comptime family: trace.OpcodeFamily,
            comptime Module: type,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            const row = try parse(section, Module, columns);
            return switch (section) {
                .direct => .{
                    .direct_constraints = directConstraints(Module, row, is_active),
                },
                .lookups => .{
                    .lookup_entries = lookupEntries(family, row),
                },
                .full => .{
                    .active_row = activeExpression(Module, row),
                    .direct_constraints = directConstraints(Module, row, is_active),
                    .lookup_entries = lookupEntries(family, row),
                },
            };
        }

        fn moduleColumnCount(comptime Module: type) usize {
            return if (@hasDecl(Module, "N_ORACLE_COLUMNS"))
                Module.N_ORACLE_COLUMNS
            else
                Module.N_MAIN_COLUMNS;
        }

        fn moduleConstraintCount(comptime Module: type) usize {
            return Module.N_CONSTRAINTS + 1;
        }

        fn parse(
            comptime section: Section,
            comptime Module: type,
            columns: []const S,
        ) !Module.Row {
            // Preserve semantic_eval's public shape error while retaining the
            // family adapter's historic error for lookup-only callers.
            if (section != .lookups) {
                const n_columns = comptime moduleColumnCount(Module);
                if (columns.len != n_columns) return error.InvalidMainTraceShape;
                var sampled: [n_columns]S = undefined;
                @memcpy(&sampled, columns);
                if (@hasDecl(Module.Row, "fromOracleColumns"))
                    return Module.Row.fromOracleColumns(&sampled);
                return Module.Row.fromMainColumns(&sampled);
            }
            if (@hasDecl(Module.Row, "fromOracleColumns"))
                return Module.Row.fromOracleColumns(columns);
            return Module.Row.fromMainColumns(columns);
        }

        /// Return the source expression used on the left side of the placement
        /// equality, without manufacturing an algebraically equivalent DAG node.
        fn activeExpression(comptime Module: type, row: Module.Row) S {
            if (@hasField(Module.Row, "semantic")) return row.semantic.active();
            if (@hasDecl(Module.Row, "active")) return row.active();
            if (@hasDecl(Module.Row, "enabler")) return row.enabler();
            if (@hasField(Module.Row, "enabler")) return row.enabler;
            @compileError("opcode family row has no active-row expression");
        }

        fn directConstraints(
            comptime Module: type,
            row: Module.Row,
            is_active: S,
        ) Self.DirectConstraints {
            const constraints = Module.evaluate(row);
            var result = Self.DirectConstraints{};
            for (constraints.values) |constraint| {
                result.values[result.len] = constraint;
                result.len += 1;
            }
            result.values[result.len] = Module.placementConstraint(row, is_active);
            result.len += 1;
            std.debug.assert(result.len == moduleConstraintCount(Module));
            return result;
        }

        fn lookupEntries(comptime family: trace.OpcodeFamily, row: anytype) e.List {
            const result = switch (family) {
                .base_alu_reg => baseAluReg(row),
                .base_alu_imm => baseAluImm(row),
                .shifts_reg => shiftsReg(row),
                .shifts_imm => shiftsImm(row),
                .lt_reg => ltReg(row),
                .lt_imm => ltImm(row),
                .branch_eq => branchEq(row),
                .branch_lt => branchLt(row),
                .lui => lui(row),
                .auipc => auipc(row),
                .jalr => jalr(row),
                .jal => jal(row),
                .load_store => loadStore(row),
                .mul => mul(row),
                .mulh => mulh(row),
                .div => div(row),
                .fence => fence(row),
            };
            std.debug.assert(result.len == entryCount(family));
            std.debug.assert(result.batch_size == batchSize(family));
            return result;
        }

        fn addProgram(list: *e.List, request: anytype) void {
            e.program(list, request.numerator, request.tuple);
        }

        fn addState(list: *e.List, requests: anytype) void {
            e.stateRequests(list, requests);
        }

        fn baseAluReg(row: sem.base_alu_reg.Row) e.List {
            const module = sem.base_alu_reg;
            const active = row.active();
            const accesses = module.accessLookups(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.stateChain(&list, sem.common.registersStateChain(row.pc, row.clk), active);
            e.accessChainAt(&list, accesses.rs1, active, 1);
            e.accessChainAt(&list, accesses.rs2, active, 2);
            const bitwise_active = module.bitwiseLookupEnabler(row);
            for (module.bitwiseLookups(row)) |tuple| e.bitwise(&list, bitwise_active.neg(), tuple);
            e.range88(&list, active.neg(), .{ row.result[0], row.result[1] });
            e.range88(&list, active.neg(), .{ row.result[2], row.result[3] });
            e.accessChainAt(&list, accesses.rd, active, 3);
            return list;
        }

        fn baseAluImm(row: sem.base_alu_imm.Row) e.List {
            const module = sem.base_alu_imm;
            const active = row.active();
            const accesses = module.accessLookups(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.range811(&list, active.neg(), module.immediateRangeLookup(row));
            e.stateChain(&list, sem.common.registersStateChain(row.pc, row.clk), active);
            e.accessChainAt(&list, accesses.rs1, active, 1);
            const bitwise_active = module.bitwiseLookupEnabler(row);
            for (module.bitwiseLookups(row)) |tuple| e.bitwise(&list, bitwise_active.neg(), tuple);
            e.range88(&list, active.neg(), .{ row.result[0], row.result[1] });
            e.range88(&list, active.neg(), .{ row.result[2], row.result[3] });
            e.accessChainAt(&list, accesses.rd, active, 2);
            return list;
        }

        fn shiftsReg(row: sem.shifts_reg.Row) e.List {
            const module = sem.shifts_reg;
            const active = row.semantic.active();
            const accesses = module.accessLookups(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.stateChain(&list, module.stateLookup(row), active);
            e.accessChainAt(&list, accesses.rs1, active, 1);
            e.accessChainAt(&list, accesses.rs2, active, 2);
            e.range20(&list, active.neg(), module.shiftAmountRangeLookup(row));
            for (module.carryRangePairs(row.semantic)) |values| e.range88(&list, active.neg(), values);
            for (module.rdRangePairs(row.semantic)) |values| e.range88(&list, active.neg(), values);
            e.accessChainAt(&list, accesses.rd, active, 3);
            e.rangeM31(&list, row.semantic.is_sra.neg(), module.signRangeLookup(row.semantic));
            return list;
        }

        fn shiftsImm(row: sem.shifts_imm.Row) e.List {
            const module = sem.shifts_imm;
            const active = row.semantic.active();
            const accesses = module.accessLookups(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.stateChain(&list, module.stateLookup(row), active);
            e.accessChainAt(&list, accesses.rs1, active, 1);
            for (module.carryRangePairs(row.semantic)) |values| e.range88(&list, active.neg(), values);
            for (module.rdRangePairs(row.semantic)) |values| e.range88(&list, active.neg(), values);
            e.accessChainAt(&list, accesses.rd, active, 2);
            e.rangeM31(&list, row.semantic.is_sra.neg(), module.signRangeLookup(row.semantic));
            return list;
        }

        fn ltReg(row: sem.lt_reg.Row) e.List {
            const module = sem.lt_reg;
            const active = row.active();
            const accesses = module.accessLookups(row);
            const positive = module.positiveDiffLookup(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.stateChain(&list, module.stateLookup(row), active);
            e.accessChainAt(&list, accesses.rs1, active, 1);
            e.accessChainAt(&list, accesses.rs2, active, 2);
            e.range88(&list, active.neg(), module.mslRangeLookup(row));
            e.range20(&list, positive.numerator.neg(), positive.value);
            e.accessChainAt(&list, accesses.rd, active, 3);
            return list;
        }

        fn ltImm(row: sem.lt_imm.Row) e.List {
            const module = sem.lt_imm;
            const active = row.active();
            const accesses = module.accessLookups(row);
            const positive = module.positiveDiffLookup(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.range884(&list, active.neg(), module.immediateRangeLookup(row));
            e.stateChain(&list, module.stateLookup(row), active);
            e.accessChainAt(&list, accesses.rs1, active, 1);
            e.range20(&list, positive.numerator.neg(), positive.value);
            e.accessChainAt(&list, accesses.rd, active, 2);
            return list;
        }

        fn branchEq(row: sem.branch_eq.Row) e.List {
            const requests = sem.branch_eq.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            e.accessAt(&list, requests.rs1, 1);
            e.accessAt(&list, requests.rs2, 2);
            addState(&list, requests.state);
            return list;
        }

        fn branchLt(row: sem.branch_lt.Row) e.List {
            const requests = sem.branch_lt.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            e.accessAt(&list, requests.rs1, 1);
            e.accessAt(&list, requests.rs2, 2);
            e.range88(&list, requests.ranges.shifted_msls.numerator, requests.ranges.shifted_msls.tuple.values());
            e.range20(&list, requests.ranges.positive_difference.numerator, requests.ranges.positive_difference.tuple.value);
            return list;
        }

        fn lui(row: sem.lui.Row) e.List {
            const requests = sem.lui.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            e.range884(&list, requests.immediate_range.numerator, requests.immediate_range.tuple.values());
            e.memoryEventAt(&list, .consume, 1, requests.rd.consume.numerator, requests.rd.consume.tuple);
            e.memoryEventAt(&list, .emit, 1, requests.rd.emit.numerator, requests.rd.emit.tuple);
            e.range20At(&list, 1, requests.rd.clock_gap.numerator, requests.rd.clock_gap.tuple.value);
            return list;
        }

        fn auipc(row: sem.auipc.Row) e.List {
            const requests = sem.auipc.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            for (requests.ranges.result) |request|
                e.range88(&list, request.numerator, request.tuple.values());
            e.range88(&list, requests.ranges.pc[0].numerator, requests.ranges.pc[0].tuple.values());
            e.rangeM31(&list, requests.ranges.pc[1].numerator, requests.ranges.pc[1].tuple.values());
            e.range88(&list, requests.ranges.immediate[0].numerator, requests.ranges.immediate[0].tuple.values());
            e.rangeM31(&list, requests.ranges.immediate[1].numerator, requests.ranges.immediate[1].tuple.values());
            e.accessAt(&list, requests.rd, 1);
            return list;
        }

        fn jalr(row: sem.jalr.Row) e.List {
            const requests = sem.jalr.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            e.accessAt(&list, requests.rs1, 1);
            e.range88(&list, requests.rs1_middle_bytes.numerator, requests.rs1_middle_bytes.tuple.values());
            e.range88(&list, requests.rs1_outer_bytes.numerator, requests.rs1_outer_bytes.tuple.values());
            e.range20(&list, requests.target_word_low_20.numerator, requests.target_word_low_20.tuple.value);
            e.range88(&list, requests.target_word_high_8.numerator, requests.target_word_high_8.tuple.values());
            e.range88(&list, requests.target_middle_bytes.numerator, requests.target_middle_bytes.tuple.values());
            e.rangeM31(&list, requests.target_m31.numerator, requests.target_m31.tuple.values());
            e.range884(&list, requests.immediate_range.numerator, requests.immediate_range.tuple.values());
            addState(&list, requests.state);
            e.range88(&list, requests.rd_middle_bytes.numerator, requests.rd_middle_bytes.tuple.values());
            e.rangeM31(&list, requests.rd_m31.numerator, requests.rd_m31.tuple.values());
            e.accessAt(&list, requests.rd, 2);
            return list;
        }

        fn jal(row: sem.jal.Row) e.List {
            const requests = sem.jal.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            e.range88(&list, requests.ranges.middle_bytes.numerator, requests.ranges.middle_bytes.tuple.values());
            e.rangeM31(&list, requests.ranges.m31_split.numerator, requests.ranges.m31_split.tuple.values());
            // The operative pinned schema has one predecessor request.
            e.memoryEventAt(&list, .consume, 1, requests.rd.consume[0].numerator, requests.rd.consume[0].tuple);
            e.memoryEventAt(&list, .emit, 1, requests.rd.emit.numerator, requests.rd.emit.tuple);
            e.range20At(&list, 1, requests.rd.clock_gap.numerator, requests.rd.clock_gap.tuple.value);
            return list;
        }

        fn loadStore(row: sem.load_store.Row) e.List {
            const module = sem.load_store;
            const active = row.active();
            const accesses = module.accessLookups(row);
            var list = e.List{};
            e.program(&list, active.neg(), module.programLookup(row));
            e.stateChain(&list, module.stateLookup(row), active);
            e.accessChainAt(&list, accesses.rs1, active, 1);
            e.range20(&list, active.neg(), module.alignedAddressRangeLookup(row));
            e.rangeM31(&list, active.neg(), module.baseAddressM31Lookup(row));
            e.accessChainAt(&list, accesses.src, active, 2);
            e.accessChainAt(&list, accesses.dst, active, 3);
            const sign_ranges = module.signRangeLookups(row);
            e.rangeM31(&list, row.is_lb.neg(), sign_ranges[0]);
            e.rangeM31(&list, row.is_lh.neg(), sign_ranges[1]);
            return list;
        }

        fn mul(row: sem.mul.Row) e.List {
            const requests = sem.mul.lookups(row);
            var list = e.List{ .batch_size = 1 };
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            e.accessAt(&list, requests.rs1, 1);
            e.accessAt(&list, requests.rs2, 2);
            for (requests.product_ranges) |request|
                e.range811(&list, request.numerator, request.tuple.values());
            e.accessAt(&list, requests.rd, 3);
            return list;
        }

        fn mulh(row: sem.mulh.Row) e.List {
            const requests = sem.mulh.lookups(row);
            var list = e.List{ .batch_size = 1 };
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            e.accessAt(&list, requests.rs1, 1);
            e.accessAt(&list, requests.rs2, 2);
            for (requests.product_ranges) |request|
                e.range811(&list, request.numerator, request.tuple.values());
            for (requests.sign_ranges) |request|
                e.rangeM31(&list, request.numerator, request.tuple.values());
            e.accessAt(&list, requests.rd, 3);
            return list;
        }

        fn div(row: sem.div.Row) e.List {
            const requests = sem.div.lookups(row);
            var list = e.List{ .batch_size = 1 };
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            e.accessAt(&list, requests.rs1, 1);
            e.accessAt(&list, requests.rs2, 2);
            for (requests.divisor_ranges) |request|
                e.range88(&list, request.numerator, request.tuple.values());
            for (requests.quotient_remainder_ranges) |request|
                e.range811(&list, request.numerator, request.tuple.values());
            e.rangeM31(&list, requests.quotient_sign_range.numerator, requests.quotient_sign_range.tuple.values());
            e.range88(&list, requests.sign_range.numerator, requests.sign_range.tuple.values());
            e.range20(&list, requests.positive_remainder_diff.numerator, requests.positive_remainder_diff.tuple.value);
            e.accessAt(&list, requests.rd, 3);
            return list;
        }

        fn fence(row: sem.fence.Row) e.List {
            const requests = sem.fence.lookups(row);
            var list = e.List{};
            addProgram(&list, requests.program);
            addState(&list, requests.state);
            return list;
        }
    };
}

const shipped = Builder(QM31);

pub const ConstraintProgram = shipped.ConstraintProgram;
pub const DirectConstraints = shipped.DirectConstraints;
pub const DirectView = shipped.DirectView;
pub const LookupView = shipped.LookupView;
pub const MAX_DIRECT_CONSTRAINTS = shipped.MAX_DIRECT_CONSTRAINTS;
pub const mainColumnCount = shipped.mainColumnCount;
pub const constraintCount = shipped.constraintCount;
pub const build = shipped.build;
pub const buildDirect = shipped.buildDirect;
pub const buildLookups = shipped.buildLookups;

test "constraint program full and section views preserve every ordered event" {
    var columns = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    columns[0] = QM31.one();

    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        const main = columns[0..mainColumnCount(family)];
        const full = try build(family, main, QM31.one());
        const direct = try buildDirect(family, main, QM31.one());
        const lookups = try buildLookups(family, main);

        try std.testing.expectEqual(full.direct_constraints.len, direct.direct_constraints.len);
        for (
            full.direct_constraints.values[0..full.direct_constraints.len],
            direct.direct_constraints.values[0..direct.direct_constraints.len],
        ) |want, got| try std.testing.expect(want.eql(got));

        try std.testing.expectEqual(full.lookup_entries.len, lookups.lookup_entries.len);
        try std.testing.expectEqual(full.lookup_entries.batch_size, lookups.lookup_entries.batch_size);
        for (
            full.lookup_entries.entries[0..full.lookup_entries.len],
            lookups.lookup_entries.entries[0..lookups.lookup_entries.len],
        ) |want, got| {
            try std.testing.expectEqual(want.domain, got.domain);
            try std.testing.expectEqual(want.role, got.role);
            try std.testing.expectEqual(want.access_ordinal, got.access_ordinal);
            try std.testing.expectEqual(want.arity, got.arity);
            try std.testing.expect(want.numerator.eql(got.numerator));
            for (want.values[0..want.arity], got.values[0..got.arity]) |want_value, got_value|
                try std.testing.expect(want_value.eql(got_value));
        }
    }
}

test "constraint program access groups are explicit contiguous triples" {
    var columns = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        const view = try buildLookups(family, columns[0..mainColumnCount(family)]);
        var event_index: usize = 0;
        var next_access_ordinal: u8 = 1;
        while (event_index < view.lookup_entries.len) {
            const event = view.lookup_entries.entries[event_index];
            const access_ordinal = event.access_ordinal orelse {
                try std.testing.expect(event.domain != .memory_access);
                if (event.role != .request)
                    try std.testing.expectEqual(entry.Domain.registers_state, event.domain);
                event_index += 1;
                continue;
            };

            try std.testing.expectEqual(next_access_ordinal, access_ordinal);
            try std.testing.expectEqual(entry.Domain.memory_access, event.domain);
            try std.testing.expectEqual(entry.EventRole.consume, event.role);
            try std.testing.expect(event_index + 2 < view.lookup_entries.len);

            const emitted = view.lookup_entries.entries[event_index + 1];
            try std.testing.expectEqual(entry.Domain.memory_access, emitted.domain);
            try std.testing.expectEqual(entry.EventRole.emit, emitted.role);
            try std.testing.expectEqual(access_ordinal, emitted.access_ordinal.?);

            const gap = view.lookup_entries.entries[event_index + 2];
            try std.testing.expectEqual(entry.Domain.range_check_20, gap.domain);
            try std.testing.expectEqual(entry.EventRole.request, gap.role);
            try std.testing.expectEqual(access_ordinal, gap.access_ordinal.?);

            next_access_ordinal += 1;
            event_index += 3;
        }
    }
}

test "constraint program active row is the exact placement left operand" {
    var columns: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
    for (&columns, 0..) |*column, index|
        column.* = QM31.fromBase(M31.fromU64(index * 1_000_003 + 17));
    const placement_selector = QM31.fromBase(M31.fromU64(0x1234_5678));

    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        const program = try build(
            family,
            columns[0..mainColumnCount(family)],
            placement_selector,
        );
        const placement = program.direct_constraints.values[program.direct_constraints.len - 1];
        try std.testing.expect(placement.eql(program.active_row.sub(placement_selector)));
    }
}

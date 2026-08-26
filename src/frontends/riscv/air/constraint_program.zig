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
const composition_manifest = @import("lang/opcode_composition_manifest.zig");
const typed_auipc_authority = @import("lang/typed_auipc_authority.zig");
const typed_base_alu_imm_authority = @import("lang/typed_base_alu_imm_authority.zig");
const typed_base_alu_reg_authority = @import("lang/typed_base_alu_reg_authority.zig");
const typed_branch_eq_authority = @import("lang/typed_branch_eq_authority.zig");
const typed_branch_lt_authority = @import("lang/typed_branch_lt_authority.zig");
const typed_fence_authority = @import("lang/typed_fence_authority.zig");
const typed_jal_authority = @import("lang/typed_jal_authority.zig");
const typed_jalr_authority = @import("lang/typed_jalr_authority.zig");
const typed_lt_imm_authority = @import("lang/typed_lt_imm_authority.zig");
const typed_lt_reg_authority = @import("lang/typed_lt_reg_authority.zig");
const typed_lui_authority = @import("lang/typed_lui_authority.zig");
const typed_shifts_imm_authority = @import("lang/typed_shifts_imm_authority.zig");
const typed_shifts_reg_authority = @import("lang/typed_shifts_reg_authority.zig");
const typed_load_store_authority = @import("lang/typed_load_store_authority.zig");
const typed_mul_authority = @import("lang/typed_mul_authority.zig");
const typed_mulh_authority = @import("lang/typed_mulh_authority.zig");
const typed_div_authority = @import("lang/typed_div_authority.zig");
const trace = @import("../runner/trace.zig");
const constructor_support = @import("constraint_program_constructors.zig");

pub fn entryCount(family: trace.OpcodeFamily) usize {
    return composition_manifest.lookupEventCount(family);
}

pub fn batchSize(family: trace.OpcodeFamily) usize {
    return composition_manifest.lookupBatchSize(family);
}

pub fn Builder(comptime S: type) type {
    return struct {
        const Self = @This();
        const e = entry.Builder(S);
        const typed_auipc_eval = typed_auipc_authority.Evaluator(S);
        const typed_base_alu_imm_eval = typed_base_alu_imm_authority.Evaluator(S);
        const typed_base_alu_reg_eval = typed_base_alu_reg_authority.Evaluator(S);
        const typed_branch_eq_eval = typed_branch_eq_authority.Evaluator(S);
        const typed_branch_lt_eval = typed_branch_lt_authority.Evaluator(S);
        const typed_fence_eval = typed_fence_authority.Evaluator(S);
        const typed_jal_eval = typed_jal_authority.Evaluator(S);
        const typed_jalr_eval = typed_jalr_authority.Evaluator(S);
        const typed_lt_imm_eval = typed_lt_imm_authority.Evaluator(S);
        const typed_lt_reg_eval = typed_lt_reg_authority.Evaluator(S);
        const typed_lui_eval = typed_lui_authority.Evaluator(S);
        const typed_shifts_imm_eval = typed_shifts_imm_authority.Evaluator(S);
        const typed_shifts_reg_eval = typed_shifts_reg_authority.Evaluator(S);
        const typed_load_store_eval = typed_load_store_authority.Evaluator(S);
        const typed_mul_eval = typed_mul_authority.Evaluator(S);
        const typed_mulh_eval = typed_mulh_authority.Evaluator(S);
        const typed_div_eval = typed_div_authority.Evaluator(S);

        pub const MAX_DIRECT_CONSTRAINTS: usize =
            composition_manifest.MAX_DIRECT_CONSTRAINTS;

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
            return composition_manifest.mainColumnCount(family);
        }

        pub fn constraintCount(family: trace.OpcodeFamily) usize {
            return composition_manifest.directConstraintCount(family);
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
            var direct_constraints: Self.DirectConstraints = undefined;
            try Self.buildDirectInto(
                family,
                columns,
                is_active,
                &direct_constraints,
            );
            return .{ .direct_constraints = direct_constraints };
        }

        /// Evaluate direct roots into caller-owned storage.
        ///
        /// The production row loop uses this seam to avoid returning and
        /// copying `MAX_DIRECT_CONSTRAINTS` values for small families. Every
        /// branch is compile-time specialized and writes exactly the family's
        /// declared roots plus placement, with no allocation or indirect call.
        pub fn buildDirectInto(
            family: trace.OpcodeFamily,
            columns: []const S,
            is_active: S,
            result: *Self.DirectConstraints,
        ) !void {
            // Fixed typed evaluators deliberately unroll their complete root
            // recipes. The aggregate family switch is also instantiated by
            // compile-time geometry guards, so admit that bounded analysis
            // without changing emitted runtime work.
            @setEvalBranchQuota(100_000);
            switch (family) {
                .base_alu_reg => adaptBaseAluRegDirectInto(
                    try typed_base_alu_reg_eval.direct(columns, is_active),
                    result,
                ),
                .base_alu_imm => adaptBaseAluImmDirectInto(
                    try typed_base_alu_imm_eval.direct(columns, is_active),
                    result,
                ),
                .shifts_reg => adaptTypedDirectInto(try typed_shifts_reg_eval.direct(columns, is_active), result),
                .shifts_imm => adaptTypedDirectInto(try typed_shifts_imm_eval.direct(columns, is_active), result),
                .lt_reg => adaptTypedDirectInto(try typed_lt_reg_eval.direct(columns, is_active), result),
                .lt_imm => adaptLtImmDirectInto(
                    try typed_lt_imm_eval.direct(columns, is_active),
                    result,
                ),
                .branch_eq => adaptBranchEqDirectInto(
                    try typed_branch_eq_eval.direct(columns, is_active),
                    result,
                ),
                .branch_lt => {
                    const polynomials = try branchLtPolynomials(columns);
                    adaptBranchLtDirectInto(
                        try typed_branch_lt_eval.direct(
                            columns,
                            polynomials.pc,
                            polynomials.target,
                            is_active,
                        ),
                        result,
                    );
                },
                .lui => adaptLuiDirectInto(
                    try typed_lui_eval.direct(columns, is_active),
                    result,
                ),
                .auipc => adaptAuipcDirectInto(
                    try typed_auipc_eval.direct(columns, is_active),
                    result,
                ),
                .jalr => adaptJalrDirectInto(
                    try typed_jalr_eval.direct(
                        columns,
                        try jalrPcPolynomial(columns),
                        is_active,
                    ),
                    result,
                ),
                .jal => adaptJalDirectInto(
                    try typed_jal_eval.direct(
                        columns,
                        try jalPcPolynomial(columns),
                        is_active,
                    ),
                    result,
                ),
                .load_store => adaptTypedDirectInto(try typed_load_store_eval.direct(columns, is_active), result),
                .mul => adaptTypedDirectInto(try typed_mul_eval.direct(columns, is_active), result),
                .mulh => adaptTypedDirectInto(try typed_mulh_eval.direct(columns, is_active), result),
                .div => adaptTypedDirectInto(try typed_div_eval.direct(columns, is_active), result),
                .fence => adaptFenceDirectInto(
                    try typed_fence_eval.direct(columns, is_active),
                    result,
                ),
            }
        }

        /// Statically selected BRANCH_EQ direct hot path. Production's
        /// component facade uses this after its one family check, avoiding a
        /// second dynamic family dispatch on every control-flow row.
        pub inline fn buildBranchEqDirectInto(
            columns: []const S,
            is_active: S,
            result: *Self.DirectConstraints,
        ) !void {
            adaptBranchEqDirectInto(
                try typed_branch_eq_eval.direct(columns, is_active),
                result,
            );
        }

        /// Statically selected BASE_ALU_IMM direct hot path. This family is
        /// common enough to avoid entering the aggregate family dispatcher,
        /// whose Debug stack frame must otherwise cover every typed recipe.
        pub inline fn buildBaseAluImmDirectInto(
            columns: []const S,
            is_active: S,
            result: *Self.DirectConstraints,
        ) !void {
            adaptBaseAluImmDirectInto(
                try typed_base_alu_imm_eval.direct(columns, is_active),
                result,
            );
        }

        /// Statically selected BASE_ALU_REG direct hot path. Register ALU rows
        /// share the same aggregate-dispatch avoidance and exact typed recipe.
        pub inline fn buildBaseAluRegDirectInto(
            columns: []const S,
            is_active: S,
            result: *Self.DirectConstraints,
        ) !void {
            adaptBaseAluRegDirectInto(
                try typed_base_alu_reg_eval.direct(columns, is_active),
                result,
            );
        }

        pub inline fn buildLuiDirectInto(
            columns: []const S,
            is_active: S,
            result: *Self.DirectConstraints,
        ) !void {
            adaptLuiDirectInto(try typed_lui_eval.direct(columns, is_active), result);
        }

        pub inline fn buildAuipcDirectInto(
            columns: []const S,
            is_active: S,
            result: *Self.DirectConstraints,
        ) !void {
            adaptAuipcDirectInto(try typed_auipc_eval.direct(columns, is_active), result);
        }

        pub inline fn buildJalrDirectInto(
            columns: []const S,
            is_active: S,
            result: *Self.DirectConstraints,
        ) !void {
            adaptJalrDirectInto(
                try typed_jalr_eval.direct(
                    columns,
                    try jalrPcPolynomial(columns),
                    is_active,
                ),
                result,
            );
        }

        pub inline fn buildJalDirectInto(
            columns: []const S,
            is_active: S,
            result: *Self.DirectConstraints,
        ) !void {
            adaptJalDirectInto(
                try typed_jal_eval.direct(
                    columns,
                    try jalPcPolynomial(columns),
                    is_active,
                ),
                result,
            );
        }

        pub inline fn buildFenceDirectInto(
            columns: []const S,
            is_active: S,
            result: *Self.DirectConstraints,
        ) !void {
            adaptFenceDirectInto(try typed_fence_eval.direct(columns, is_active), result);
        }

        /// Statically selected BRANCH_LT direct hot path. The PC and selected
        /// target scalar views are admitted from the exact 37-column shape
        /// before entering the fixed authority recipe.
        pub inline fn buildBranchLtDirectInto(
            columns: []const S,
            is_active: S,
            result: *Self.DirectConstraints,
        ) !void {
            const polynomials = try branchLtPolynomials(columns);
            adaptBranchLtDirectInto(
                try typed_branch_lt_eval.direct(
                    columns,
                    polynomials.pc,
                    polynomials.target,
                    is_active,
                ),
                result,
            );
        }

        /// Statically selected LT_IMM direct hot path. The family facade
        /// admits the row shape once and enters the fixed authority without a
        /// second dynamic family dispatch.
        pub inline fn buildLtImmDirectInto(
            columns: []const S,
            is_active: S,
            result: *Self.DirectConstraints,
        ) !void {
            adaptLtImmDirectInto(
                try typed_lt_imm_eval.direct(columns, is_active),
                result,
            );
        }

        /// Build the exact section consumed by `opcode_entries`.
        pub fn buildLookups(
            family: trace.OpcodeFamily,
            columns: []const S,
        ) !Self.LookupView {
            var lookup_entries: e.List = undefined;
            try buildLookupsInto(family, columns, &lookup_entries);
            return .{ .lookup_entries = lookup_entries };
        }

        /// Build lookup entries directly in caller-owned storage.
        ///
        /// This is the prepared evaluator's allocation-free hot path. Keeping
        /// the large list out of nested error-union returns prevents Debug
        /// builds from retaining a full copy at every adapter boundary.
        pub fn buildLookupsInto(
            family: trace.OpcodeFamily,
            columns: []const S,
            result: *e.List,
        ) anyerror!void {
            @setEvalBranchQuota(100_000);
            // BRANCH_EQ is both lookup-light and exceptionally frequent in
            // control-heavy guests. Keep its fixed authority on a direct
            // call edge; the generic function-pointer table costs more than
            // the nine-entry recipe itself on this family.
            if (family == .branch_eq) {
                try buildBranchEqLookupsInto(columns, result);
                return;
            }
            if (family == .branch_lt) {
                try buildBranchLtLookupsInto(columns, result);
                return;
            }
            if (family == .lt_imm) {
                try buildLtImmLookupsInto(columns, result);
                return;
            }
            if (family == .lt_reg) return buildLtRegLookupsInto(columns, result);
            if (family == .shifts_imm) return buildShiftsImmLookupsInto(columns, result);
            if (family == .shifts_reg) return buildShiftsRegLookupsInto(columns, result);
            if (family == .load_store) return buildLoadStoreLookupsInto(columns, result);
            if (family == .mul) return buildMulLookupsInto(columns, result);
            if (family == .mulh) return buildMulhLookupsInto(columns, result);
            if (family == .div) return buildDivLookupsInto(columns, result);
            const DispatchFn = *const fn ([]const S, *e.List) anyerror!void;
            const dispatch: DispatchFn = switch (family) {
                .base_alu_reg => BaseAluRegLookupConstructor.run,
                .base_alu_imm => BaseAluImmLookupConstructor.run,
                .shifts_reg, .shifts_imm, .lt_reg => unreachable,
                .lt_imm => unreachable,
                .branch_eq => unreachable,
                .branch_lt => unreachable,
                .lui => LuiLookupConstructor.run,
                .auipc => AuipcLookupConstructor.run,
                .jalr => JalrLookupConstructor.run,
                .jal => JalLookupConstructor.run,
                .load_store, .mul, .mulh, .div => unreachable,
                .fence => FenceLookupConstructor.run,
            };
            try dispatch(columns, result);
        }

        /// Statically selected BRANCH_EQ relation hot path. The lookup facade
        /// admits the family once and then calls this fixed recipe directly.
        pub inline fn buildBranchEqLookupsInto(
            columns: []const S,
            result: *e.List,
        ) !void {
            try typed_branch_eq_eval.lookupsInto(columns, result);
        }

        /// Statically selected BRANCH_LT relation hot path. This avoids a
        /// dynamic constructor call around the authority's eleven entries.
        pub inline fn buildBranchLtLookupsInto(
            columns: []const S,
            result: *e.List,
        ) !void {
            try typed_branch_lt_eval.lookupsInto(columns, result);
        }

        /// Statically selected LT_IMM relation hot path. Immediate compares
        /// are common enough that an indirect constructor around eleven fixed
        /// entries is measurable and unnecessary.
        pub inline fn buildLtImmLookupsInto(
            columns: []const S,
            result: *e.List,
        ) !void {
            try typed_lt_imm_eval.lookupsInto(columns, result);
        }

        pub inline fn buildLtRegDirectInto(columns: []const S, is_active: S, result: *Self.DirectConstraints) !void {
            adaptTypedDirectInto(try typed_lt_reg_eval.direct(columns, is_active), result);
        }

        pub inline fn buildShiftsImmDirectInto(columns: []const S, is_active: S, result: *Self.DirectConstraints) !void {
            adaptTypedDirectInto(try typed_shifts_imm_eval.direct(columns, is_active), result);
        }

        pub inline fn buildShiftsRegDirectInto(columns: []const S, is_active: S, result: *Self.DirectConstraints) !void {
            adaptTypedDirectInto(try typed_shifts_reg_eval.direct(columns, is_active), result);
        }

        pub inline fn buildLoadStoreDirectInto(columns: []const S, is_active: S, result: *Self.DirectConstraints) !void {
            adaptTypedDirectInto(try typed_load_store_eval.direct(columns, is_active), result);
        }

        pub inline fn buildMulDirectInto(columns: []const S, is_active: S, result: *Self.DirectConstraints) !void {
            adaptTypedDirectInto(try typed_mul_eval.direct(columns, is_active), result);
        }

        pub inline fn buildMulhDirectInto(columns: []const S, is_active: S, result: *Self.DirectConstraints) !void {
            adaptTypedDirectInto(try typed_mulh_eval.direct(columns, is_active), result);
        }

        pub inline fn buildDivDirectInto(columns: []const S, is_active: S, result: *Self.DirectConstraints) !void {
            adaptTypedDirectInto(try typed_div_eval.direct(columns, is_active), result);
        }

        pub inline fn buildLtRegLookupsInto(columns: []const S, result: *e.List) !void {
            try typed_lt_reg_eval.lookupsInto(columns, result);
        }

        pub inline fn buildShiftsImmLookupsInto(columns: []const S, result: *e.List) !void {
            try typed_shifts_imm_eval.lookupsInto(columns, result);
        }

        pub inline fn buildShiftsRegLookupsInto(columns: []const S, result: *e.List) !void {
            try typed_shifts_reg_eval.lookupsInto(columns, result);
        }

        pub inline fn buildLoadStoreLookupsInto(columns: []const S, result: *e.List) !void {
            try typed_load_store_eval.lookupsInto(columns, result);
        }

        pub inline fn buildMulLookupsInto(columns: []const S, result: *e.List) !void {
            try typed_mul_eval.lookupsInto(columns, result);
        }

        pub inline fn buildMulhLookupsInto(columns: []const S, result: *e.List) !void {
            try typed_mulh_eval.lookupsInto(columns, result);
        }

        pub inline fn buildDivLookupsInto(columns: []const S, result: *e.List) !void {
            try typed_div_eval.lookupsInto(columns, result);
        }

        const constructors = constructor_support.Constructors(.{
            .S = S,
            .Self = Self,
            .e = e,
            .Section = Section,
            .trace = trace,
            .typed_branch_lt_authority = typed_branch_lt_authority,
            .typed_jal_authority = typed_jal_authority,
            .typed_jalr_authority = typed_jalr_authority,
            .typed_auipc_eval = typed_auipc_eval,
            .typed_base_alu_imm_eval = typed_base_alu_imm_eval,
            .typed_base_alu_reg_eval = typed_base_alu_reg_eval,
            .typed_branch_eq_eval = typed_branch_eq_eval,
            .typed_branch_lt_eval = typed_branch_lt_eval,
            .typed_fence_eval = typed_fence_eval,
            .typed_jal_eval = typed_jal_eval,
            .typed_jalr_eval = typed_jalr_eval,
            .typed_lt_imm_eval = typed_lt_imm_eval,
            .typed_lt_reg_eval = typed_lt_reg_eval,
            .typed_lui_eval = typed_lui_eval,
            .typed_shifts_imm_eval = typed_shifts_imm_eval,
            .typed_shifts_reg_eval = typed_shifts_reg_eval,
            .typed_load_store_eval = typed_load_store_eval,
            .typed_mul_eval = typed_mul_eval,
            .typed_mulh_eval = typed_mulh_eval,
            .typed_div_eval = typed_div_eval,
        });
        const PlacementArg = constructors.PlacementArg;
        const Result = constructors.Result;
        const construct = constructors.construct;
        const constructTyped = constructors.constructTyped;
        const LuiLookupConstructor = constructors.LuiLookupConstructor;
        const BaseAluImmLookupConstructor = constructors.BaseAluImmLookupConstructor;
        const BaseAluRegLookupConstructor = constructors.BaseAluRegLookupConstructor;
        const AuipcLookupConstructor = constructors.AuipcLookupConstructor;
        const FenceLookupConstructor = constructors.FenceLookupConstructor;
        const JalLookupConstructor = constructors.JalLookupConstructor;
        const JalrLookupConstructor = constructors.JalrLookupConstructor;
        const constructLui = constructors.constructLui;
        const constructBaseAluImm = constructors.constructBaseAluImm;
        const constructBaseAluReg = constructors.constructBaseAluReg;
        const constructBranchEq = constructors.constructBranchEq;
        const constructBranchLt = constructors.constructBranchLt;
        const BranchLtPolynomials = constructors.BranchLtPolynomials;
        const branchLtPolynomials = constructors.branchLtPolynomials;
        const constructLtImm = constructors.constructLtImm;
        const constructAuipc = constructors.constructAuipc;
        const constructJal = constructors.constructJal;
        const jalPcPolynomial = constructors.jalPcPolynomial;
        const constructJalr = constructors.constructJalr;
        const jalrPcPolynomial = constructors.jalrPcPolynomial;
        const constructFence = constructors.constructFence;
        const adaptLuiDirect = constructors.adaptLuiDirect;
        const adaptTypedDirect = constructors.adaptTypedDirect;
        const adaptTypedDirectInto = constructors.adaptTypedDirectInto;
        const adaptBaseAluImmDirect = constructors.adaptBaseAluImmDirect;
        const adaptBaseAluRegDirect = constructors.adaptBaseAluRegDirect;
        const adaptBranchEqDirect = constructors.adaptBranchEqDirect;
        const adaptBranchLtDirect = constructors.adaptBranchLtDirect;
        const adaptLtImmDirect = constructors.adaptLtImmDirect;
        const adaptAuipcDirect = constructors.adaptAuipcDirect;
        const adaptJalDirect = constructors.adaptJalDirect;
        const adaptJalrDirect = constructors.adaptJalrDirect;
        const adaptAuipcDirectInto = constructors.adaptAuipcDirectInto;
        const adaptJalDirectInto = constructors.adaptJalDirectInto;
        const adaptJalrDirectInto = constructors.adaptJalrDirectInto;
        const adaptBaseAluImmDirectInto = constructors.adaptBaseAluImmDirectInto;
        const adaptBaseAluRegDirectInto = constructors.adaptBaseAluRegDirectInto;
        const adaptBranchEqDirectInto = constructors.adaptBranchEqDirectInto;
        const adaptBranchLtDirectInto = constructors.adaptBranchLtDirectInto;
        const adaptLtImmDirectInto = constructors.adaptLtImmDirectInto;
        const adaptLuiDirectInto = constructors.adaptLuiDirectInto;
        const adaptFenceDirect = constructors.adaptFenceDirect;
        const adaptFenceDirectInto = constructors.adaptFenceDirectInto;
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
pub const buildDirectInto = shipped.buildDirectInto;
pub const buildLookups = shipped.buildLookups;

test "constraint program full and section views preserve every ordered event" {
    var columns = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    columns[0] = QM31.one();

    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        const main = columns[0..mainColumnCount(family)];
        const full = try build(family, main, QM31.one());
        const direct = try buildDirect(family, main, QM31.one());
        var direct_into: DirectConstraints = undefined;
        try buildDirectInto(family, main, QM31.one(), &direct_into);
        const lookups = try buildLookups(family, main);

        try std.testing.expectEqual(full.direct_constraints.len, direct.direct_constraints.len);
        try std.testing.expectEqual(direct.direct_constraints.len, direct_into.len);
        for (
            full.direct_constraints.values[0..full.direct_constraints.len],
            direct.direct_constraints.values[0..direct.direct_constraints.len],
        ) |want, got| try std.testing.expect(want.eql(got));
        for (
            direct.direct_constraints.values[0..direct.direct_constraints.len],
            direct_into.values[0..direct_into.len],
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

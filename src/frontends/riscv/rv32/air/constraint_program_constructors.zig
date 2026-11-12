//! Family-specific construction and direct-root adaptation for constraint programs.

pub fn Constructors(comptime context: anytype) type {
    return struct {
        const S = context.S;
        const Self = context.Self;
        const e = context.e;
        const Section = context.Section;
        const trace = context.trace;
        const typed_branch_lt_authority = context.typed_branch_lt_authority;
        const typed_jal_authority = context.typed_jal_authority;
        const typed_jalr_authority = context.typed_jalr_authority;
        const typed_auipc_eval = context.typed_auipc_eval;
        const typed_base_alu_imm_eval = context.typed_base_alu_imm_eval;
        const typed_base_alu_reg_eval = context.typed_base_alu_reg_eval;
        const typed_branch_eq_eval = context.typed_branch_eq_eval;
        const typed_branch_lt_eval = context.typed_branch_lt_eval;
        const typed_fence_eval = context.typed_fence_eval;
        const typed_jal_eval = context.typed_jal_eval;
        const typed_jalr_eval = context.typed_jalr_eval;
        const typed_lt_imm_eval = context.typed_lt_imm_eval;
        const typed_lt_reg_eval = context.typed_lt_reg_eval;
        const typed_lui_eval = context.typed_lui_eval;
        const typed_shifts_imm_eval = context.typed_shifts_imm_eval;
        const typed_shifts_reg_eval = context.typed_shifts_reg_eval;
        const typed_load_store_eval = context.typed_load_store_eval;
        const typed_mul_eval = context.typed_mul_eval;
        const typed_mulh_eval = context.typed_mulh_eval;
        const typed_div_eval = context.typed_div_eval;

        pub fn PlacementArg(comptime section: Section) type {
            return if (section == .lookups) void else S;
        }

        pub fn Result(comptime section: Section) type {
            return switch (section) {
                .direct => Self.DirectView,
                .lookups => Self.LookupView,
                .full => Self.ConstraintProgram,
            };
        }

        pub fn construct(
            comptime section: Section,
            family: trace.OpcodeFamily,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            @setEvalBranchQuota(100_000);
            return switch (family) {
                .base_alu_reg => constructBaseAluReg(section, columns, is_active),
                .base_alu_imm => constructBaseAluImm(section, columns, is_active),
                .shifts_reg => constructTyped(typed_shifts_reg_eval, section, columns, is_active),
                .shifts_imm => constructTyped(typed_shifts_imm_eval, section, columns, is_active),
                .lt_reg => constructTyped(typed_lt_reg_eval, section, columns, is_active),
                .lt_imm => constructLtImm(section, columns, is_active),
                .branch_eq => constructBranchEq(section, columns, is_active),
                .branch_lt => constructBranchLt(section, columns, is_active),
                .lui => constructLui(section, columns, is_active),
                .auipc => constructAuipc(section, columns, is_active),
                .jalr => constructJalr(section, columns, is_active),
                .jal => constructJal(section, columns, is_active),
                .load_store => constructTyped(typed_load_store_eval, section, columns, is_active),
                .mul => constructTyped(typed_mul_eval, section, columns, is_active),
                .mulh => constructTyped(typed_mulh_eval, section, columns, is_active),
                .div => constructTyped(typed_div_eval, section, columns, is_active),
                .fence => constructFence(section, columns, is_active),
            };
        }

        pub fn constructTyped(
            comptime Eval: type,
            comptime section: Section,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            return switch (section) {
                .direct => .{ .direct_constraints = adaptTypedDirect(try Eval.direct(columns, is_active)) },
                .lookups => blk: {
                    var lookups: e.List = undefined;
                    try Eval.lookupsInto(columns, &lookups);
                    break :blk .{ .lookup_entries = lookups };
                },
                .full => blk: {
                    const compiled = try Eval.build(columns, is_active);
                    break :blk .{
                        .active_row = compiled.active_row,
                        .direct_constraints = adaptTypedDirect(compiled.direct_constraints),
                        .lookup_entries = compiled.lookup_entries,
                    };
                },
            };
        }

        pub const LuiLookupConstructor = struct {
            pub fn run(columns: []const S, result: *e.List) anyerror!void {
                try typed_lui_eval.lookupsInto(columns, result);
            }
        };

        pub const BaseAluImmLookupConstructor = struct {
            pub fn run(columns: []const S, result: *e.List) anyerror!void {
                try typed_base_alu_imm_eval.lookupsInto(columns, result);
            }
        };

        pub const BaseAluRegLookupConstructor = struct {
            pub fn run(columns: []const S, result: *e.List) anyerror!void {
                try typed_base_alu_reg_eval.lookupsInto(columns, result);
            }
        };

        pub const AuipcLookupConstructor = struct {
            pub fn run(columns: []const S, result: *e.List) anyerror!void {
                try typed_auipc_eval.lookupsInto(columns, result);
            }
        };

        pub const FenceLookupConstructor = struct {
            pub fn run(columns: []const S, result: *e.List) anyerror!void {
                try typed_fence_eval.lookupsInto(columns, result);
            }
        };

        pub const JalLookupConstructor = struct {
            pub fn run(columns: []const S, result: *e.List) anyerror!void {
                try typed_jal_eval.lookupsInto(columns, result);
            }
        };

        pub const JalrLookupConstructor = struct {
            pub fn run(columns: []const S, result: *e.List) anyerror!void {
                try typed_jalr_eval.lookupsInto(columns, result);
            }
        };

        /// Production LUI bypasses the retained Stark-V-shaped semantic
        /// module and consumes the fixed evaluator authenticated against the
        /// typed definition. This is the AIR/lookup half of the first opcode
        /// SSOT cutover; the old module remains only as an independent test
        /// oracle until the formal/Sail receipt is frozen.
        pub fn constructLui(
            comptime section: Section,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            return switch (section) {
                .direct => .{
                    .direct_constraints = adaptLuiDirect(try typed_lui_eval.direct(columns, is_active)),
                },
                .lookups => blk: {
                    var lookups: e.List = undefined;
                    try typed_lui_eval.lookupsInto(columns, &lookups);
                    break :blk .{ .lookup_entries = lookups };
                },
                .full => blk: {
                    const compiled = try typed_lui_eval.build(columns, is_active);
                    break :blk .{
                        .active_row = compiled.active_row,
                        .direct_constraints = adaptLuiDirect(
                            compiled.direct_constraints,
                        ),
                        .lookup_entries = compiled.lookup_entries,
                    };
                },
            };
        }

        /// Production BASE_ALU_IMM is evaluated only through the fixed typed
        /// authority authenticated against the complete four-opcode graph.
        pub fn constructBaseAluImm(
            comptime section: Section,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            return switch (section) {
                .direct => .{
                    .direct_constraints = adaptBaseAluImmDirect(
                        try typed_base_alu_imm_eval.direct(columns, is_active),
                    ),
                },
                .lookups => blk: {
                    var lookups: e.List = undefined;
                    try typed_base_alu_imm_eval.lookupsInto(columns, &lookups);
                    break :blk .{ .lookup_entries = lookups };
                },
                .full => blk: {
                    const compiled = try typed_base_alu_imm_eval.build(columns, is_active);
                    break :blk .{
                        .active_row = compiled.active_row,
                        .direct_constraints = adaptBaseAluImmDirect(
                            compiled.direct_constraints,
                        ),
                        .lookup_entries = compiled.lookup_entries,
                    };
                },
            };
        }

        /// Production BASE_ALU_REG is evaluated only through the fixed typed
        /// authority authenticated against the complete five-opcode graph.
        pub fn constructBaseAluReg(
            comptime section: Section,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            return switch (section) {
                .direct => .{
                    .direct_constraints = adaptBaseAluRegDirect(
                        try typed_base_alu_reg_eval.direct(columns, is_active),
                    ),
                },
                .lookups => blk: {
                    var lookups: e.List = undefined;
                    try typed_base_alu_reg_eval.lookupsInto(columns, &lookups);
                    break :blk .{ .lookup_entries = lookups };
                },
                .full => blk: {
                    const compiled = try typed_base_alu_reg_eval.build(columns, is_active);
                    break :blk .{
                        .active_row = compiled.active_row,
                        .direct_constraints = adaptBaseAluRegDirect(
                            compiled.direct_constraints,
                        ),
                        .lookup_entries = compiled.lookup_entries,
                    };
                },
            };
        }

        /// Production BRANCH_EQ is constructed only through the fixed typed
        /// authority shared by execution, witness projection, direct roots,
        /// ordered lookups, and formal extraction.
        pub fn constructBranchEq(
            comptime section: Section,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            return switch (section) {
                .direct => .{
                    .direct_constraints = adaptBranchEqDirect(
                        try typed_branch_eq_eval.direct(columns, is_active),
                    ),
                },
                .lookups => blk: {
                    var lookups: e.List = undefined;
                    try typed_branch_eq_eval.lookupsInto(columns, &lookups);
                    break :blk .{ .lookup_entries = lookups };
                },
                .full => blk: {
                    const compiled = try typed_branch_eq_eval.build(
                        columns,
                        is_active,
                    );
                    break :blk .{
                        .active_row = compiled.active_row,
                        .direct_constraints = adaptBranchEqDirect(
                            compiled.direct_constraints,
                        ),
                        .lookup_entries = compiled.lookup_entries,
                    };
                },
            };
        }

        /// Production BRANCH_LT is constructed only through the fixed typed
        /// authority shared by retirement, witness projection, roots, ordered
        /// relations, and formal extraction.
        pub fn constructBranchLt(
            comptime section: Section,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            return switch (section) {
                .direct => blk: {
                    const polynomials = try branchLtPolynomials(columns);
                    break :blk .{
                        .direct_constraints = adaptBranchLtDirect(
                            try typed_branch_lt_eval.direct(
                                columns,
                                polynomials.pc,
                                polynomials.target,
                                is_active,
                            ),
                        ),
                    };
                },
                .lookups => blk: {
                    var lookups: e.List = undefined;
                    try typed_branch_lt_eval.lookupsInto(columns, &lookups);
                    break :blk .{ .lookup_entries = lookups };
                },
                .full => blk: {
                    const polynomials = try branchLtPolynomials(columns);
                    const compiled = try typed_branch_lt_eval.build(
                        columns,
                        polynomials.pc,
                        polynomials.target,
                        is_active,
                    );
                    break :blk .{
                        .active_row = compiled.active_row,
                        .direct_constraints = adaptBranchLtDirect(
                            compiled.direct_constraints,
                        ),
                        .lookup_entries = compiled.lookup_entries,
                    };
                },
            };
        }

        pub const BranchLtPolynomials = struct { pc: S, target: S };

        pub inline fn branchLtPolynomials(
            columns: []const S,
        ) !BranchLtPolynomials {
            if (columns.len != typed_branch_lt_authority.MAIN_COLUMN_COUNT)
                return error.InvalidMainTraceShape;
            return .{ .pc = columns[1], .target = columns[32] };
        }

        /// Production LT_IMM is constructed only through the fixed typed
        /// authority shared by retirement, witness projection, roots, ordered
        /// relations, and formal extraction.
        pub fn constructLtImm(
            comptime section: Section,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            return switch (section) {
                .direct => .{
                    .direct_constraints = adaptLtImmDirect(
                        try typed_lt_imm_eval.direct(columns, is_active),
                    ),
                },
                .lookups => blk: {
                    var lookups: e.List = undefined;
                    try typed_lt_imm_eval.lookupsInto(columns, &lookups);
                    break :blk .{ .lookup_entries = lookups };
                },
                .full => blk: {
                    const compiled = try typed_lt_imm_eval.build(
                        columns,
                        is_active,
                    );
                    break :blk .{
                        .active_row = compiled.active_row,
                        .direct_constraints = adaptLtImmDirect(
                            compiled.direct_constraints,
                        ),
                        .lookup_entries = compiled.lookup_entries,
                    };
                },
            };
        }

        /// Production AUIPC consumes the fixed typed evaluator for direct
        /// roots and ordered relations. Architectural retirement uses the
        /// same pinned capability through `auipc_retirement.zig`.
        pub fn constructAuipc(
            comptime section: Section,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            return switch (section) {
                .direct => .{
                    .direct_constraints = adaptAuipcDirect(
                        try typed_auipc_eval.direct(columns, is_active),
                    ),
                },
                .lookups => blk: {
                    var lookups: e.List = undefined;
                    try typed_auipc_eval.lookupsInto(columns, &lookups);
                    break :blk .{ .lookup_entries = lookups };
                },
                .full => blk: {
                    const compiled = try typed_auipc_eval.build(
                        columns,
                        is_active,
                    );
                    break :blk .{
                        .active_row = compiled.active_row,
                        .direct_constraints = adaptAuipcDirect(
                            compiled.direct_constraints,
                        ),
                        .lookup_entries = compiled.lookup_entries,
                    };
                },
            };
        }

        /// Production JAL consumes the fixed typed evaluator for the exact
        /// direct roots and ordered relations. The historic direct equation
        /// uses physical PC column two as its scalar polynomial view; bind it
        /// only after the complete twenty-column shape has been admitted.
        pub fn constructJal(
            comptime section: Section,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            return switch (section) {
                .direct => .{
                    .direct_constraints = adaptJalDirect(
                        try typed_jal_eval.direct(
                            columns,
                            try jalPcPolynomial(columns),
                            is_active,
                        ),
                    ),
                },
                .lookups => blk: {
                    var lookups: e.List = undefined;
                    try typed_jal_eval.lookupsInto(columns, &lookups);
                    break :blk .{ .lookup_entries = lookups };
                },
                .full => blk: {
                    const compiled = try typed_jal_eval.build(
                        columns,
                        try jalPcPolynomial(columns),
                        is_active,
                    );
                    break :blk .{
                        .active_row = compiled.active_row,
                        .direct_constraints = adaptJalDirect(
                            compiled.direct_constraints,
                        ),
                        .lookup_entries = compiled.lookup_entries,
                    };
                },
            };
        }

        pub inline fn jalPcPolynomial(columns: []const S) !S {
            if (columns.len != typed_jal_authority.MAIN_COLUMN_COUNT)
                return error.InvalidMainTraceShape;
            return columns[2];
        }

        /// Production JALR consumes the fixed typed evaluator for the exact
        /// direct roots and ordered relations. Its historic PC equation uses
        /// physical column two, which is exposed only after the complete
        /// forty-one-column row shape has been admitted.
        pub fn constructJalr(
            comptime section: Section,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            return switch (section) {
                .direct => .{
                    .direct_constraints = adaptJalrDirect(
                        try typed_jalr_eval.direct(
                            columns,
                            try jalrPcPolynomial(columns),
                            is_active,
                        ),
                    ),
                },
                .lookups => blk: {
                    var lookups: e.List = undefined;
                    try typed_jalr_eval.lookupsInto(columns, &lookups);
                    break :blk .{ .lookup_entries = lookups };
                },
                .full => blk: {
                    const compiled = try typed_jalr_eval.build(
                        columns,
                        try jalrPcPolynomial(columns),
                        is_active,
                    );
                    break :blk .{
                        .active_row = compiled.active_row,
                        .direct_constraints = adaptJalrDirect(
                            compiled.direct_constraints,
                        ),
                        .lookup_entries = compiled.lookup_entries,
                    };
                },
            };
        }

        pub inline fn jalrPcPolynomial(columns: []const S) !S {
            if (columns.len != typed_jalr_authority.MAIN_COLUMN_COUNT)
                return error.InvalidMainTraceShape;
            return columns[2];
        }

        /// Production FENCE uses the typed fixed evaluator. This deliberately
        /// exercises the zero-access edge case without routing through the
        /// retired generic semantic adapter.
        pub fn constructFence(
            comptime section: Section,
            columns: []const S,
            is_active: PlacementArg(section),
        ) !Result(section) {
            return switch (section) {
                .direct => .{
                    .direct_constraints = adaptFenceDirect(try typed_fence_eval.direct(columns, is_active)),
                },
                .lookups => blk: {
                    var lookups: e.List = undefined;
                    try typed_fence_eval.lookupsInto(columns, &lookups);
                    break :blk .{ .lookup_entries = lookups };
                },
                .full => blk: {
                    const compiled = try typed_fence_eval.build(columns, is_active);
                    break :blk .{
                        .active_row = compiled.active_row,
                        .direct_constraints = adaptFenceDirect(
                            compiled.direct_constraints,
                        ),
                        .lookup_entries = compiled.lookup_entries,
                    };
                },
            };
        }

        pub fn adaptLuiDirect(
            direct: typed_lui_eval.DirectConstraints,
        ) Self.DirectConstraints {
            var result: Self.DirectConstraints = undefined;
            adaptLuiDirectInto(direct, &result);
            return result;
        }

        pub fn adaptTypedDirect(direct: anytype) Self.DirectConstraints {
            var result: Self.DirectConstraints = undefined;
            adaptTypedDirectInto(direct, &result);
            return result;
        }

        pub inline fn adaptTypedDirectInto(
            direct: anytype,
            result: *Self.DirectConstraints,
        ) void {
            inline for (direct.values, 0..) |value, index|
                result.values[index] = value;
            result.len = direct.values.len;
        }

        pub fn adaptBaseAluImmDirect(
            direct: typed_base_alu_imm_eval.DirectConstraints,
        ) Self.DirectConstraints {
            var result: Self.DirectConstraints = undefined;
            adaptBaseAluImmDirectInto(direct, &result);
            return result;
        }

        pub fn adaptBaseAluRegDirect(
            direct: typed_base_alu_reg_eval.DirectConstraints,
        ) Self.DirectConstraints {
            var result: Self.DirectConstraints = undefined;
            adaptBaseAluRegDirectInto(direct, &result);
            return result;
        }

        pub fn adaptBranchEqDirect(
            direct: typed_branch_eq_eval.DirectConstraints,
        ) Self.DirectConstraints {
            var result: Self.DirectConstraints = undefined;
            adaptBranchEqDirectInto(direct, &result);
            return result;
        }

        pub fn adaptBranchLtDirect(
            direct: typed_branch_lt_eval.DirectConstraints,
        ) Self.DirectConstraints {
            var result: Self.DirectConstraints = undefined;
            adaptBranchLtDirectInto(direct, &result);
            return result;
        }

        pub fn adaptLtImmDirect(
            direct: typed_lt_imm_eval.DirectConstraints,
        ) Self.DirectConstraints {
            var result: Self.DirectConstraints = undefined;
            adaptLtImmDirectInto(direct, &result);
            return result;
        }

        pub fn adaptAuipcDirect(
            direct: typed_auipc_eval.DirectConstraints,
        ) Self.DirectConstraints {
            var result: Self.DirectConstraints = undefined;
            adaptAuipcDirectInto(direct, &result);
            return result;
        }

        pub fn adaptJalDirect(
            direct: typed_jal_eval.DirectConstraints,
        ) Self.DirectConstraints {
            var result: Self.DirectConstraints = undefined;
            adaptJalDirectInto(direct, &result);
            return result;
        }

        pub fn adaptJalrDirect(
            direct: typed_jalr_eval.DirectConstraints,
        ) Self.DirectConstraints {
            var result: Self.DirectConstraints = undefined;
            adaptJalrDirectInto(direct, &result);
            return result;
        }

        pub inline fn adaptAuipcDirectInto(
            direct: typed_auipc_eval.DirectConstraints,
            result: *Self.DirectConstraints,
        ) void {
            inline for (direct.values, 0..) |value, index|
                result.values[index] = value;
            result.len = direct.values.len;
        }

        pub inline fn adaptJalDirectInto(
            direct: typed_jal_eval.DirectConstraints,
            result: *Self.DirectConstraints,
        ) void {
            inline for (direct.values, 0..) |value, index|
                result.values[index] = value;
            result.len = direct.values.len;
        }

        pub inline fn adaptJalrDirectInto(
            direct: typed_jalr_eval.DirectConstraints,
            result: *Self.DirectConstraints,
        ) void {
            inline for (direct.values, 0..) |value, index|
                result.values[index] = value;
            result.len = direct.values.len;
        }

        pub inline fn adaptBaseAluImmDirectInto(
            direct: typed_base_alu_imm_eval.DirectConstraints,
            result: *Self.DirectConstraints,
        ) void {
            inline for (direct.values, 0..) |value, index|
                result.values[index] = value;
            result.len = direct.values.len;
        }

        pub inline fn adaptBaseAluRegDirectInto(
            direct: typed_base_alu_reg_eval.DirectConstraints,
            result: *Self.DirectConstraints,
        ) void {
            inline for (direct.values, 0..) |value, index|
                result.values[index] = value;
            result.len = direct.values.len;
        }

        pub inline fn adaptBranchEqDirectInto(
            direct: typed_branch_eq_eval.DirectConstraints,
            result: *Self.DirectConstraints,
        ) void {
            inline for (direct.values, 0..) |value, index|
                result.values[index] = value;
            result.len = direct.values.len;
        }

        pub inline fn adaptBranchLtDirectInto(
            direct: typed_branch_lt_eval.DirectConstraints,
            result: *Self.DirectConstraints,
        ) void {
            inline for (direct.values, 0..) |value, index|
                result.values[index] = value;
            result.len = direct.values.len;
        }

        pub inline fn adaptLtImmDirectInto(
            direct: typed_lt_imm_eval.DirectConstraints,
            result: *Self.DirectConstraints,
        ) void {
            inline for (direct.values, 0..) |value, index|
                result.values[index] = value;
            result.len = direct.values.len;
        }

        pub inline fn adaptLuiDirectInto(
            direct: typed_lui_eval.DirectConstraints,
            result: *Self.DirectConstraints,
        ) void {
            inline for (direct.values, 0..) |value, index|
                result.values[index] = value;
            result.len = direct.values.len;
        }

        pub fn adaptFenceDirect(
            direct: typed_fence_eval.DirectConstraints,
        ) Self.DirectConstraints {
            var result: Self.DirectConstraints = undefined;
            adaptFenceDirectInto(direct, &result);
            return result;
        }

        pub inline fn adaptFenceDirectInto(
            direct: typed_fence_eval.DirectConstraints,
            result: *Self.DirectConstraints,
        ) void {
            inline for (direct.values, 0..) |value, index|
                result.values[index] = value;
            result.len = direct.values.len;
        }
    };
}

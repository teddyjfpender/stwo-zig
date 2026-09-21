//! Typed AIR admission and point verification without prover or witness dependencies.
//! Prover-capable adapters reuse these methods over their existing public fields.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const circle = core.circle;
const CirclePointQM31 = circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;
const core_air_components = core.air.components;
const core_air_accumulation = core.air.accumulation;
const core_air_derive = core.air.derive;
const core_constraints = core.constraints;
const direct_program = @import("direct_constraint_program.zig");
const logup = @import("../../air/logup_equations.zig");
const types = @import("../../air/lang/types.zig");
const universal = @import("universal_challenges.zig");
const typed_geometry = @import("universal_typed_geometry.zig");
const manifestGeometryForAir = typed_geometry.manifestGeometryForAir;
const support = @import("universal_typed_verifier_support.zig");
const sampledSecure = support.sampledSecure;
const emptyOrFilledLogs = support.emptyOrFilledLogs;
const currentPointColumns = support.currentPointColumns;
const freePointColumns = support.freePointColumns;
const checkedEnd = support.checkedEnd;

pub fn Layout(comptime Air: type, comptime Relation: type) type {
    return struct {
        pub const Runtime = Relation.Runtime;
        pub const DIRECT_COUNT = Air.DIRECT_CONSTRAINT_COUNT;
        pub const LOGUP_COUNT = Air.INTERACTION_BATCH_COUNT;
        pub const CONSTRAINT_COUNT = DIRECT_COUNT + LOGUP_COUNT;
        pub const PP_COUNT = Air.PREPROCESSED_COLUMN_COUNT;
        pub const MAIN_COUNT = Air.PHYSICAL_MAIN_COLUMN_COUNT;
        pub const PARAMETER_COUNT = @import("universal_typed_geometry.zig").parameterColumnCount(Air);
        // Proof-kind and circuit parameters are verifier-owned scalars, not PCS
        // columns.  Keeping them out of the extension source array avoids both
        // uninitialized Poly descriptors and needless interpolation work.
        pub const SOURCE_COUNT = MAIN_COUNT + PP_COUNT + Air.INTERACTION_COLUMN_COUNT;
        // The local static profile describes direct compiler roots, while a
        // component may publish the exact degree of its compiler-lowered LogUp
        // recurrence.  That lowered bound is authoritative for this adapter: a
        // pinned source declaration describes the borrowed AIR, but must never
        // under-size quotient geometry after lowering introduces derived tuple
        // expressions. Components without an explicit lowered audit retain the
        // compatibility-v1 source declaration and cubic interaction floor.
        pub const PROTOCOL_MAXIMUM_DEGREE: u32 = typed_geometry.protocolMaximumConstraintDegree(Air);
        // Even a quadratic constraint needs one evaluation-domain extension: the
        // trace-domain vanishing polynomial is zero on the unextended domain and
        // therefore cannot be inverted there.  Degree still describes the AIR;
        // this floor is strictly a quotient-evaluation geometry requirement.
        pub const QUOTIENT_LOG_BLOWUP: u32 = @max(
            @as(u32, 1),
            std.math.log2_int_ceil(u32, PROTOCOL_MAXIMUM_DEGREE - 1),
        );
        pub const DENOMINATOR_COUNT: usize = @as(usize, 1) <<
            @intCast(QUOTIENT_LOG_BLOWUP);

        comptime {
            if (Runtime.LOGICAL_INPUT_COUNT != Air.LOGICAL_INPUT_COUNT or
                Runtime.BATCH_COUNT != LOGUP_COUNT or
                Runtime.INTERACTION_COLUMN_COUNT != Air.INTERACTION_COLUMN_COUNT or
                Air.INTERACTION_COLUMN_COUNT != 4 * LOGUP_COUNT or
                CONSTRAINT_COUNT > direct_program.MAX_CONSTRAINTS)
            {
                @compileError("generic recursion component geometry drifted");
            }
            if (PP_COUNT > std.math.maxInt(u16) or
                MAIN_COUNT > std.math.maxInt(u16) or
                Air.INTERACTION_COLUMN_COUNT > std.math.maxInt(u16) or
                DIRECT_COUNT > std.math.maxInt(u16) or
                LOGUP_COUNT > std.math.maxInt(u16) or
                PROTOCOL_MAXIMUM_DEGREE > std.math.maxInt(u8) or
                Air.MAXIMUM_CONSTRAINT_DEGREE > std.math.maxInt(u8))
            {
                @compileError("generic recursion component manifest geometry overflow");
            }
        }
    };
}

/// A verifier-only concrete component. All pointers retain the ordinary stable-address contract.
pub fn ComponentForManifest(comptime Air: type, comptime Relation: type, comptime manifest_mod: type) type {
    const Shape = Layout(Air, Relation);
    return struct {
        const Self = @This();
        const Shared = Methods(Self, Air, Relation, manifest_mod);
        pub const PARAMETER_COLUMN_COUNT = Shape.PARAMETER_COUNT;
        pub const RelationRuntime = Relation.Runtime;
        log_size: u32,
        placement: manifest_mod.Placement,
        parameters: [Shape.PARAMETER_COUNT]M31,
        relations: *const universal.UniversalRelations,
        claimed_sum: QM31,
        claimed_sum_shift: QM31,
        direct: direct_program.Program,
        relation_plan: Relation.Runtime.Plan,
        pub const manifestGeometry = Shared.manifestGeometry;
        pub const init = Shared.init;
        pub const asVerifierComponent = Shared.asVerifierComponent;
        pub const nConstraints = Shared.nConstraints;
        pub const maxConstraintLogDegreeBound = Shared.maxConstraintLogDegreeBound;
        pub const traceLogDegreeBounds = Shared.traceLogDegreeBounds;
        pub const maskPoints = Shared.maskPoints;
        pub const evaluateBaseRowInto = Shared.evaluateBaseRowInto;
        pub const preprocessedColumnIndices = Shared.preprocessedColumnIndices;
        pub const evaluateConstraintQuotientsAtPoint = Shared.evaluateConstraintQuotientsAtPoint;
    };
}

pub fn Methods(comptime Self: type, comptime Air: type, comptime Relation: type, comptime manifest_mod: type) type {
    const Shape = Layout(Air, Relation);
    const Runtime = Shape.Runtime;
    const DIRECT_COUNT = Shape.DIRECT_COUNT;
    const LOGUP_COUNT = Shape.LOGUP_COUNT;
    const CONSTRAINT_COUNT = Shape.CONSTRAINT_COUNT;
    const PP_COUNT = Shape.PP_COUNT;
    const MAIN_COUNT = Shape.MAIN_COUNT;
    const PARAMETER_COUNT = Shape.PARAMETER_COUNT;
    const PROTOCOL_MAXIMUM_DEGREE = Shape.PROTOCOL_MAXIMUM_DEGREE;
    const QUOTIENT_LOG_BLOWUP = Shape.QUOTIENT_LOG_BLOWUP;
    return struct {
        pub fn manifestGeometry(
            comptime roster_row: manifest_mod.ComponentKey,
            log_size: u32,
        ) manifest_mod.Geometry {
            return manifestGeometryForAir(
                Air,
                manifest_mod,
                roster_row,
                log_size,
            );
        }

        pub fn init(
            definition: *const Air.Definition,
            relation_plan: Runtime.Plan,
            manifest: *const manifest_mod.Manifest,
            comptime roster_row: manifest_mod.ComponentKey,
            log_size: u32,
            parameters: [PARAMETER_COUNT]M31,
            relations: *const universal.UniversalRelations,
            claimed_sum: QM31,
        ) !Self {
            if (log_size == 0 or log_size >= circle.M31_CIRCLE_LOG_ORDER)
                return error.InvalidProofShape;
            try definition.validate();
            try relations.validate();
            try relation_plan.validateAgainst(
                &definition.arena,
                Air.SEMANTIC_DIGEST,
                eventIds(definition),
            );
            const direct = try direct_program.authenticate(
                &definition.arena,
                Air.SEMANTIC_DIGEST,
                Air.LOGICAL_INPUT_COUNT,
            );
            if (direct.constraint_count != DIRECT_COUNT)
                return error.InvalidProofShape;

            const placement = try manifest.placement(roster_row);
            const geometry = placement.geometry;
            if (geometry.roster_row != manifest_mod.keyIndex(roster_row) or
                geometry.log_size != log_size or
                geometry.preprocessed_columns != PP_COUNT or
                geometry.main_columns != MAIN_COUNT or
                geometry.interaction_columns != Air.INTERACTION_COLUMN_COUNT or
                geometry.direct_constraints != DIRECT_COUNT or
                geometry.interaction_batches != LOGUP_COUNT or
                geometry.protocol_constraint_degree != PROTOCOL_MAXIMUM_DEGREE or
                geometry.profiled_constraint_degree != Air.MAXIMUM_CONSTRAINT_DEGREE or
                !std.mem.eql(u8, &geometry.semantic_digest, &Air.SEMANTIC_DIGEST))
            {
                return error.InvalidProofShape;
            }

            const n = M31.fromU64(@as(u64, 1) << @intCast(log_size));
            return .{
                .log_size = log_size,
                .placement = placement,
                .parameters = parameters,
                .relations = relations,
                .claimed_sum = claimed_sum,
                .claimed_sum_shift = try claimed_sum.divM31(n),
                .direct = direct,
                .relation_plan = relation_plan,
            };
        }

        pub fn asVerifierComponent(self: *const Self) core_air_components.Component {
            return core_air_derive.ComponentAdapter(Self, void, void, void).asVerifierComponent(self);
        }

        pub fn nConstraints(_: *const Self) usize {
            return CONSTRAINT_COUNT;
        }

        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + QUOTIENT_LOG_BLOWUP;
        }

        pub fn traceLogDegreeBounds(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) !core_air_components.TraceLogDegreeBounds {
            const pp = try emptyOrFilledLogs(allocator, PP_COUNT, self.log_size);
            errdefer allocator.free(pp);
            const main = try emptyOrFilledLogs(allocator, MAIN_COUNT, self.log_size);
            errdefer allocator.free(main);
            const interaction = try emptyOrFilledLogs(
                allocator,
                Air.INTERACTION_COLUMN_COUNT,
                self.log_size,
            );
            errdefer allocator.free(interaction);
            const trees = try allocator.alloc([]u32, manifest_mod.TREE_COUNT);
            trees[0] = pp;
            trees[1] = main;
            trees[2] = interaction;
            return core_air_components.TraceLogDegreeBounds.initOwned(trees);
        }

        pub fn maskPoints(
            self: *const Self,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            max_log_degree_bound: u32,
        ) !core_air_components.MaskPoints {
            // The core callback supplies the largest committed trace degree,
            // not the larger quotient-evaluation degree.
            if (max_log_degree_bound < self.log_size)
                return error.InvalidProofShape;
            const pp = try currentPointColumns(allocator, PP_COUNT, point);
            errdefer freePointColumns(allocator, pp);
            const main = try currentPointColumns(allocator, MAIN_COUNT, point);
            errdefer freePointColumns(allocator, main);
            const interaction = try interactionPointColumns(
                allocator,
                point,
                max_log_degree_bound,
            );
            errdefer freePointColumns(allocator, interaction);
            const trees = try allocator.alloc(
                [][]CirclePointQM31,
                manifest_mod.TREE_COUNT,
            );
            trees[0] = pp;
            trees[1] = main;
            trees[2] = interaction;
            return core_air_components.MaskPoints.initOwned(trees);
        }

        pub fn evaluateBaseRowInto(
            self: *const Self,
            row: Runtime.Row,
            current: [LOGUP_COUNT]QM31,
            final_previous: QM31,
            roots: *[CONSTRAINT_COUNT]QM31,
        ) !void {
            var direct_scratch: [direct_program.MAX_NODES]M31 = undefined;
            var direct_roots: [DIRECT_COUNT]M31 = undefined;
            try self.direct.evaluateBaseInto(&row, &direct_scratch, &direct_roots);
            for (direct_roots, roots[0..DIRECT_COUNT]) |root, *target|
                target.* = QM31.fromBase(root);
            const pairs = try self.relation_plan.preparedRowPairs(
                row,
                self.relations,
            );
            for (pairs, DIRECT_COUNT..) |pair, constraint| {
                const batch = constraint - DIRECT_COUNT;
                roots[constraint] = frameworkConstraint(
                    current[batch],
                    if (batch + 1 == LOGUP_COUNT) final_previous else QM31.zero(),
                    if (batch == 0) QM31.zero() else current[batch - 1],
                    if (batch + 1 == LOGUP_COUNT)
                        self.claimed_sum_shift
                    else
                        QM31.zero(),
                    pair,
                );
            }
        }

        pub fn preprocessedColumnIndices(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) ![]usize {
            const result = try allocator.alloc(usize, PP_COUNT);
            for (result, 0..) |*index, local|
                index.* = try checkedEnd(self.placement.preprocessed_offset, local);
            return result;
        }

        pub fn evaluateConstraintQuotientsAtPoint(
            self: *const Self,
            point: CirclePointQM31,
            mask: *const core_air_components.MaskValues,
            accumulator: *core_air_accumulation.PointEvaluationAccumulator,
            max_log_degree_bound: u32,
        ) !void {
            if (max_log_degree_bound < self.log_size or
                mask.items.len < manifest_mod.TREE_COUNT)
            {
                return error.InvalidProofShape;
            }
            const pp_end = try checkedEnd(
                self.placement.preprocessed_offset,
                PP_COUNT,
            );
            const main_end = try checkedEnd(self.placement.main_offset, MAIN_COUNT);
            const interaction_end = try checkedEnd(
                self.placement.interaction_offset,
                Air.INTERACTION_COLUMN_COUNT,
            );
            const pp_tree = mask.items[manifest_mod.PREPROCESSED_TREE_INDEX];
            const main_tree = mask.items[manifest_mod.MAIN_TREE_INDEX];
            const interaction_tree = mask.items[manifest_mod.INTERACTION_TREE_INDEX];
            if (pp_tree.len < pp_end or main_tree.len < main_end or
                interaction_tree.len < interaction_end)
            {
                return error.InvalidProofShape;
            }

            var row: Runtime.SecureRow = undefined;
            for (row[0..MAIN_COUNT], main_tree[self.placement.main_offset..main_end]) |
                *value,
                column,
            | {
                if (column.len != 1) return error.InvalidProofShape;
                value.* = column[0];
            }
            for (row[MAIN_COUNT .. MAIN_COUNT + PP_COUNT], pp_tree[self.placement.preprocessed_offset..pp_end]) |*value, column| {
                if (column.len != 1) return error.InvalidProofShape;
                value.* = column[0];
            }
            for (row[MAIN_COUNT + PP_COUNT ..], self.parameters) |*value, parameter|
                value.* = QM31.fromBase(parameter);

            var direct_scratch: [direct_program.MAX_NODES]QM31 = undefined;
            var direct_roots: [DIRECT_COUNT]QM31 = undefined;
            try self.direct.evaluateSecureInto(&row, &direct_scratch, &direct_roots);
            const pairs = try self.relation_plan.preparedSecureRowPairs(
                row,
                self.relations,
            );
            const interaction = interaction_tree[self.placement.interaction_offset..interaction_end];
            const denominator_inverse = try core_constraints.cosetVanishing(
                QM31,
                canonic.CanonicCoset.new(self.log_size).coset(),
                point.repeatedDouble(max_log_degree_bound - self.log_size),
            ).inv();
            for (direct_roots) |root|
                accumulator.accumulate(root.mul(denominator_inverse));
            for (0..LOGUP_COUNT) |batch| {
                const final = batch + 1 == LOGUP_COUNT;
                const current = try sampledSecure(
                    interaction,
                    4 * batch,
                    if (final) 1 else 0,
                );
                const previous_column = if (batch == 0)
                    QM31.zero()
                else
                    try sampledSecure(interaction, 4 * (batch - 1), 0);
                const previous_row = if (final)
                    try sampledSecure(interaction, 4 * batch, 0)
                else
                    QM31.zero();
                const shift = if (final)
                    self.claimed_sum_shift
                else
                    QM31.zero();
                accumulator.accumulate(frameworkConstraint(
                    current,
                    previous_row,
                    previous_column,
                    shift,
                    pairs[batch],
                ).mul(denominator_inverse));
            }
        }

        fn interactionPointColumns(
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            max_log_degree_bound: u32,
        ) ![][]CirclePointQM31 {
            const columns = try allocator.alloc(
                []CirclePointQM31,
                Air.INTERACTION_COLUMN_COUNT,
            );
            var initialized: usize = 0;
            errdefer {
                for (columns[0..initialized]) |column| allocator.free(column);
                allocator.free(columns);
            }
            const final_start = 4 * (LOGUP_COUNT - 1);
            for (columns, 0..) |*column, index| {
                column.* = if (index < final_start)
                    try allocator.dupe(CirclePointQM31, &.{point})
                else
                    try allocator.dupe(CirclePointQM31, &.{
                        logup.prevRowPoint(max_log_degree_bound, point),
                        point,
                    });
                initialized += 1;
            }
            return columns;
        }

        fn eventIds(
            definition: *const Air.Definition,
        ) [Air.RELATION_EVENT_COUNT]types.EffectId {
            if (comptime @hasDecl(Relation, "events")) {
                return Relation.events(definition);
            } else if (comptime @hasField(Air.Definition, "events")) {
                const Events = @TypeOf(definition.events);
                if (comptime @typeInfo(Events) == .array)
                    return definition.events;
                if (comptime @hasDecl(Events, "ordered"))
                    return definition.events.ordered();
                @compileError(
                    "typed recursion relation events must expose canonical order",
                );
            } else if (comptime Air.RELATION_EVENT_COUNT == 1 and
                @hasField(Air.Definition, "event"))
            {
                return .{definition.event};
            } else {
                @compileError(
                    "typed recursion relation must expose canonical event order",
                );
            }
        }
    };
}

pub inline fn frameworkConstraint(
    current: QM31,
    previous_row: QM31,
    previous_column: QM31,
    shift: QM31,
    pair: logup.RowPair,
) QM31 {
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    const denominator = pair.d1.mul(pair.d2);
    return current.sub(previous_row).sub(previous_column).add(shift)
        .mul(denominator).sub(numerator);
}

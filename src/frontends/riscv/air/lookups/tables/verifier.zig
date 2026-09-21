//! Native lookup-table point verifier, sharing all equations with the prover.
const std = @import("std");
const core = @import("stwo_core");
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const core_air_derive = core.air.derive;
const core_constraints = core.constraints;
const circle = core.circle;
const CirclePointQM31 = circle.CirclePointQM31;
const QM31 = core.fields.qm31.QM31;
const canonic = core.poly.circle.canonic;
const relations_mod = @import("../../relation_challenges.zig");
const schema = @import("schema_definition.zig");
const interaction = @import("equations.zig");
const logup = @import("../../logup_equations.zig");
const point_support = @import("../../component_point_support.zig");
const currentPointColumns = point_support.currentPointColumns;
const freePointColumns = point_support.freePointColumns;
pub const N_CONSTRAINTS = @import("layout.zig").N_CONSTRAINTS;
pub const ConstructionMetadata = @import("layout.zig").ConstructionMetadata;

pub const LookupTableVerifier = struct {
    const Shared = Methods(@This());
    kind: schema.Kind,
    is_first_col_idx: usize,
    tuple_col_indices: [schema.MAX_ARITY]usize,
    main_col_offset: usize,
    interaction_col_offset: usize,
    relations: *const relations_mod.Relations,
    claim: QM31,
    pub const initVerifier = Shared.initVerifier;
    pub const metadata = Shared.metadata;
    pub const asVerifierComponent = Shared.asVerifierComponent;
    pub const nConstraints = Shared.nConstraints;
    pub const maxConstraintLogDegreeBound = Shared.maxConstraintLogDegreeBound;
    pub const traceLogDegreeBounds = Shared.traceLogDegreeBounds;
    pub const maskPoints = Shared.maskPoints;
    pub const preprocessedColumnIndices = Shared.preprocessedColumnIndices;
    pub const evaluateConstraintQuotientsAtPoint = Shared.evaluateConstraintQuotientsAtPoint;
    pub const evaluateRow = Shared.evaluateRow;
};

pub fn Methods(comptime Self: type) type {
    return struct {
        pub fn initVerifier(
            kind: schema.Kind,
            is_first_col_idx: usize,
            tuple_col_indices: []const usize,
            main_col_offset: usize,
            interaction_col_offset: usize,
            relations: *const relations_mod.Relations,
            claim: QM31,
        ) !Self {
            return init(
                kind,
                is_first_col_idx,
                tuple_col_indices,
                main_col_offset,
                interaction_col_offset,
                relations,
                claim,
            );
        }

        pub fn metadata(self: *const Self) ConstructionMetadata {
            return ConstructionMetadata.forKind(self.kind);
        }

        pub fn asVerifierComponent(self: *const Self) core_air_components.Component {
            return core_air_derive.ComponentAdapter(Self, void, void, void).asVerifierComponent(self);
        }

        pub fn nConstraints(_: *const Self) usize {
            return N_CONSTRAINTS;
        }

        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return schema.logSize(self.kind) + 1;
        }

        pub fn traceLogDegreeBounds(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) !core_air_components.TraceLogDegreeBounds {
            const log_size = schema.logSize(self.kind);
            const n_preprocessed = 1 + schema.arity(self.kind);
            const preprocessed = try allocator.alloc(u32, n_preprocessed);
            errdefer allocator.free(preprocessed);
            @memset(preprocessed, log_size);
            const main = try allocator.dupe(u32, &.{log_size});
            errdefer allocator.free(main);
            const secure = try allocator.alloc(u32, interaction.N_COLUMNS);
            errdefer allocator.free(secure);
            @memset(secure, log_size);
            return core_air_components.TraceLogDegreeBounds.initOwned(
                try allocator.dupe([]u32, &.{ preprocessed, main, secure }),
            );
        }

        pub fn maskPoints(
            self: *const Self,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            max_log_degree_bound: u32,
        ) !core_air_components.MaskPoints {
            if (max_log_degree_bound < schema.logSize(self.kind)) return error.InvalidProofShape;
            const preprocessed = try currentPointColumns(
                allocator,
                1 + schema.arity(self.kind),
                point,
            );
            errdefer freePointColumns(allocator, preprocessed);
            const main = try currentPointColumns(allocator, 1, point);
            errdefer freePointColumns(allocator, main);
            // The PCS folds a log-(k+1) commitment at a point derived from the
            // maximal composition domain. Shifting the request by that maximal
            // step becomes exactly one trace-row shift after folding.
            const previous_point = logup.prevRowPoint(max_log_degree_bound, point);
            const secure = try allocator.alloc([]CirclePointQM31, interaction.N_COLUMNS);
            var initialized_secure: usize = 0;
            errdefer {
                for (secure[0..initialized_secure]) |column| allocator.free(column);
                allocator.free(secure);
            }
            for (secure) |*column| {
                column.* = try allocator.dupe(CirclePointQM31, &.{ point, previous_point });
                initialized_secure += 1;
            }
            return core_air_components.MaskPoints.initOwned(
                try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, secure }),
            );
        }

        pub fn preprocessedColumnIndices(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) ![]usize {
            const result = try allocator.alloc(usize, 1 + schema.arity(self.kind));
            result[0] = self.is_first_col_idx;
            @memcpy(result[1..], self.tuple_col_indices[0..schema.arity(self.kind)]);
            return result;
        }

        pub fn evaluateConstraintQuotientsAtPoint(
            self: *const Self,
            point: CirclePointQM31,
            mask: *const core_air_components.MaskValues,
            accumulator: *core_air_accumulation.PointEvaluationAccumulator,
            max_log_degree_bound: u32,
        ) !void {
            const log_size = schema.logSize(self.kind);
            if (max_log_degree_bound < log_size or mask.items.len < 3)
                return error.InvalidProofShape;
            const preprocessed = mask.items[0];
            const main = mask.items[1];
            const secure = mask.items[2];
            if (preprocessed.len <= self.is_first_col_idx or
                main.len <= self.main_col_offset or
                main[self.main_col_offset].len < 1 or
                secure.len < self.interaction_col_offset + interaction.N_COLUMNS)
                return error.InvalidProofShape;

            var tuple: [schema.MAX_ARITY]QM31 = undefined;
            for (self.tuple_col_indices[0..schema.arity(self.kind)], tuple[0..schema.arity(self.kind)]) |column_index, *value| {
                if (preprocessed.len <= column_index or preprocessed[column_index].len < 1)
                    return error.InvalidProofShape;
                value.* = preprocessed[column_index][0];
            }
            if (preprocessed[self.is_first_col_idx].len < 1) return error.InvalidProofShape;
            const current = try sampledSecure(secure, self.interaction_col_offset, 0);
            const previous = try sampledSecure(secure, self.interaction_col_offset, 1);
            const constraint = try self.evaluateRow(
                tuple[0..schema.arity(self.kind)],
                main[self.main_col_offset][0],
                current,
                previous,
                preprocessed[self.is_first_col_idx][0],
            );
            const fold = max_log_degree_bound - log_size;
            const denominator_inv = try core_constraints.cosetVanishing(
                QM31,
                canonic.CanonicCoset.new(log_size).coset(),
                point.repeatedDouble(fold),
            ).inv();
            accumulator.accumulate(constraint.mul(denominator_inv));
        }

        pub fn evaluateRow(
            self: *const Self,
            tuple: []const QM31,
            signed_multiplicity: QM31,
            current: QM31,
            previous: QM31,
            is_first: QM31,
        ) !QM31 {
            return interaction.evaluate(
                self.kind,
                tuple,
                signed_multiplicity,
                current,
                previous,
                is_first,
                self.claim,
                self.relations,
            );
        }

        pub fn init(
            kind: schema.Kind,
            is_first_col_idx: usize,
            tuple_col_indices: []const usize,
            main_col_offset: usize,
            interaction_col_offset: usize,
            relations: *const relations_mod.Relations,
            claim: QM31,
        ) !Self {
            if (tuple_col_indices.len != schema.arity(kind)) return error.InvalidTraceShape;
            var stored_indices = [_]usize{0} ** schema.MAX_ARITY;
            for (tuple_col_indices, 0..) |column, index| {
                if (column == is_first_col_idx) return error.InvalidTraceShape;
                for (tuple_col_indices[0..index]) |prior| {
                    if (column == prior) return error.InvalidTraceShape;
                }
                stored_indices[index] = column;
            }
            return .{
                .kind = kind,
                .is_first_col_idx = is_first_col_idx,
                .tuple_col_indices = stored_indices,
                .main_col_offset = main_col_offset,
                .interaction_col_offset = interaction_col_offset,
                .relations = relations,
                .claim = claim,
            };
        }
    };
}

pub fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
    var coordinates: [interaction.N_COLUMNS]QM31 = undefined;
    for (&coordinates, 0..) |*value, index| {
        if (columns.len <= offset + index or columns[offset + index].len <= point)
            return error.InvalidProofShape;
        value.* = columns[offset + index][point];
    }
    return QM31.fromPartialEvals(coordinates);
}

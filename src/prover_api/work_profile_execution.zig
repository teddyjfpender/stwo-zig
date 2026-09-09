//! Backend-authenticated execution receipts for FFT, quotient, sampled-value, and FRI work.

const std = @import("std");
const core = @import("work_profile_core.zig");
const math = @import("work_profile_math.zig");

const Error = core.Error;
const Counters = core.Counters;
const FieldOperations = core.FieldOperations;
const addCounter = math.addCounter;
const multiplyCounter = math.multiplyCounter;
const logicalFftButterflies = math.logicalFftButterflies;
const logicalM31ForwardFftFieldOperations = math.logicalM31ForwardFftFieldOperations;
const logicalM31InterpolationExecutionWork = math.logicalM31InterpolationExecutionWork;

pub const M31_INTERPOLATION_EXECUTION_SCHEMA_VERSION: u16 = 1;

/// Backend-returned execution geometry for a completed M31 interpolation.
/// Batch count is explicit because normalization inversions are shared within
/// a batch and therefore legitimately differ between CPU and device paths.
pub const M31InterpolationExecution = struct {
    schema_version: u16 = M31_INTERPOLATION_EXECUTION_SCHEMA_VERSION,
    log_size: u32,
    column_count: u64,
    batch_count: u64,

    pub fn validate(self: M31InterpolationExecution) Error!void {
        if (self.schema_version != M31_INTERPOLATION_EXECUTION_SCHEMA_VERSION or
            self.log_size == 0 or self.log_size >= @bitSizeOf(u64) or
            self.column_count == 0 or self.batch_count == 0 or
            self.batch_count > self.column_count)
        {
            return error.InvalidCounterGroup;
        }
    }

    pub fn exactWork(self: M31InterpolationExecution) Error!Counters {
        try self.validate();
        return logicalM31InterpolationExecutionWork(
            self.log_size,
            self.column_count,
            self.batch_count,
        );
    }

    /// Backend-invariant comparison projection: each logical coordinate owns
    /// one batch. This is diagnostic only; executed receipts use `exactWork`.
    pub fn perColumnBatchProjection(
        self: M31InterpolationExecution,
    ) Error!Counters {
        try self.validate();
        return logicalM31InterpolationExecutionWork(
            self.log_size,
            self.column_count,
            self.column_count,
        );
    }
};

pub const M31ForwardFftExecution = struct {
    log_size: u32,
    column_count: u64,
    skipped_layers: u32 = 0,

    pub fn validate(self: M31ForwardFftExecution) Error!void {
        if (self.log_size >= @bitSizeOf(u64) or self.column_count == 0 or
            self.skipped_layers > self.log_size)
        {
            return error.InvalidCounterGroup;
        }
    }

    pub fn exactWork(self: M31ForwardFftExecution) Error!Counters {
        try self.validate();
        const butterflies = try multiplyCounter(
            try logicalFftButterflies(self.log_size, self.skipped_layers),
            self.column_count,
        );
        const fields = try logicalM31ForwardFftFieldOperations(butterflies);
        return .{
            .field_additions = fields.additions,
            .field_multiplications = fields.multiplications,
            .field_inversions = fields.inversions,
            .fft_butterflies = butterflies,
        };
    }
};

pub const M31_CIRCLE_LDE_EXECUTION_SCHEMA_VERSION: u16 = 1;

/// One backend-completed inverse-base/forward-extension transform pair.
pub const M31CircleLdeExecution = struct {
    schema_version: u16 = M31_CIRCLE_LDE_EXECUTION_SCHEMA_VERSION,
    interpolation: M31InterpolationExecution,
    forward: M31ForwardFftExecution,

    pub fn validate(self: M31CircleLdeExecution) Error!void {
        if (self.schema_version != M31_CIRCLE_LDE_EXECUTION_SCHEMA_VERSION)
            return error.InvalidCounterGroup;
        try self.interpolation.validate();
        try self.forward.validate();
        if (self.interpolation.column_count != self.forward.column_count or
            self.forward.log_size <= self.interpolation.log_size)
        {
            return error.InvalidCounterGroup;
        }
    }

    pub fn exactWork(self: M31CircleLdeExecution) Error!Counters {
        try self.validate();
        return (try self.interpolation.exactWork()).add(
            try self.forward.exactWork(),
        );
    }
};

/// Backend interpolation dispatch result. Only `transformed` carries work;
/// already-coefficient admission is an exact zero and declined dispatch falls
/// through to the generic owner.
pub const M31InterpolationBackendResult = union(enum) {
    declined,
    already_coefficients,
    transformed: M31InterpolationExecution,

    pub fn validate(self: M31InterpolationBackendResult) Error!void {
        switch (self) {
            .declined, .already_coefficients => {},
            .transformed => |execution| try execution.validate(),
        }
    }
};

pub const SAMPLED_COEFFICIENT_EXECUTION_SCHEMA_VERSION: u16 = 1;

/// Backend-returned geometry for one completed sampled coefficient-evaluation
/// epoch. The receipt names the logical tasks that actually reached the
/// device, together with the threadgroup widths selected by the live Metal
/// pipelines. `basis_multiplications` is returned explicitly because the
/// optimized 256-lane basis kernel intentionally recomputes low-byte products
/// per block; its executed work is not the host subset-product schedule.
pub const SampledCoefficientExecution = struct {
    schema_version: u16 = SAMPLED_COEFFICIENT_EXECUTION_SCHEMA_VERSION,
    plan_count: u64,
    basis_task_count: u64,
    evaluation_task_count: u64,
    evaluation_coefficient_terms: u64,
    basis_multiplications: u64,
    basis_threadgroup_width: u32,
    evaluation_threadgroup_width: u32,

    pub fn validate(self: SampledCoefficientExecution) Error!void {
        if (self.schema_version != SAMPLED_COEFFICIENT_EXECUTION_SCHEMA_VERSION)
            return error.InvalidCounterGroup;
        if (self.evaluation_task_count == 0) {
            if (self.plan_count != 0 or self.basis_task_count != 0 or
                self.evaluation_coefficient_terms != 0 or
                self.basis_multiplications != 0 or
                self.basis_threadgroup_width != 0 or
                self.evaluation_threadgroup_width != 0)
            {
                return error.InvalidCounterGroup;
            }
            return;
        }
        if (self.plan_count == 0 or self.basis_task_count == 0 or
            self.basis_task_count > self.evaluation_task_count or
            self.evaluation_coefficient_terms < self.evaluation_task_count or
            self.basis_threadgroup_width == 0 or
            self.basis_threadgroup_width > 256 or
            self.evaluation_threadgroup_width == 0 or
            self.evaluation_threadgroup_width > 256)
        {
            return error.InvalidCounterGroup;
        }
    }

    pub fn exactWork(self: SampledCoefficientExecution) Error!Counters {
        try self.validate();
        if (self.evaluation_task_count == 0) return .{};
        var reduction_additions_per_task: u64 = 0;
        var stride = self.evaluation_threadgroup_width >> 1;
        while (stride != 0) : (stride >>= 1) {
            reduction_additions_per_task = try addCounter(
                reduction_additions_per_task,
                stride,
            );
        }
        return .{
            .field_additions = try addCounter(
                self.evaluation_coefficient_terms,
                try multiplyCounter(
                    self.evaluation_task_count,
                    reduction_additions_per_task,
                ),
            ),
            .field_multiplications = try addCounter(
                self.basis_multiplications,
                self.evaluation_coefficient_terms,
            ),
        };
    }
};

pub const SAMPLED_BARYCENTRIC_EXECUTION_SCHEMA_VERSION: u16 = 1;

/// Exact execution geometry for one backend-owned evaluation-form sampled
/// value epoch.  The receipt separates point/domain reuse from column work so
/// a backend cannot report an idealized batch inverse or hide repeated domain
/// construction.  `domain_circle_multiplications` counts calls to the circle
/// group multiplication primitive; `exactWork` expands each call to its four
/// field multiplications and two field additions.
pub const SampledBarycentricExecution = struct {
    schema_version: u16 = SAMPLED_BARYCENTRIC_EXECUTION_SCHEMA_VERSION,
    point_plan_count: u64,
    domain_plan_count: u64,
    evaluation_task_count: u64,
    weight_value_count: u64,
    dot_product_terms: u64,
    domain_circle_multiplications: u64,
    scale_double_count: u64,
    inverse_tree_block_count: u64,
    direct_inversion_count: u64,
    reduction_addition_count: u64,
    constant_addition_count: u64,
    constant_multiplication_count: u64,
    constant_inversion_count: u64,

    pub fn validate(self: SampledBarycentricExecution) Error!void {
        if (self.schema_version != SAMPLED_BARYCENTRIC_EXECUTION_SCHEMA_VERSION)
            return error.InvalidCounterGroup;
        if (self.evaluation_task_count == 0) {
            if (self.point_plan_count != 0 or self.domain_plan_count != 0 or
                self.weight_value_count != 0 or self.dot_product_terms != 0 or
                self.domain_circle_multiplications != 0 or
                self.scale_double_count != 0 or
                self.inverse_tree_block_count != 0 or
                self.direct_inversion_count != 0 or
                self.reduction_addition_count != 0 or
                self.constant_addition_count != 0 or
                self.constant_multiplication_count != 0 or
                self.constant_inversion_count != 0)
            {
                return error.InvalidCounterGroup;
            }
            return;
        }
        if (self.point_plan_count == 0 or self.domain_plan_count == 0 or
            self.domain_plan_count > self.point_plan_count or
            self.evaluation_task_count > self.dot_product_terms or
            self.weight_value_count < try multiplyCounter(self.point_plan_count, 2) or
            self.domain_circle_multiplications == 0 or
            self.reduction_addition_count < self.evaluation_task_count or
            self.constant_multiplication_count == 0 or
            self.constant_inversion_count != self.domain_plan_count)
        {
            return error.InvalidCounterGroup;
        }
        const inverse_tree_values = try multiplyCounter(
            self.inverse_tree_block_count,
            1_024,
        );
        if (self.weight_value_count != try addCounter(
            inverse_tree_values,
            self.direct_inversion_count,
        )) return error.InvalidCounterGroup;
    }

    pub fn exactWork(self: SampledBarycentricExecution) Error!Counters {
        try self.validate();
        if (self.evaluation_task_count == 0) return .{};

        // Per point: rotate the sampled point (A=1,M=2), execute every
        // double-X (A=2,M=1), then multiply by si0 (M=1).
        const scale_additions = try addCounter(
            self.point_plan_count,
            try multiplyCounter(self.scale_double_count, 2),
        );
        const scale_multiplications = try addCounter(
            try multiplyCounter(self.point_plan_count, 3),
            self.scale_double_count,
        );

        // Per weight: parts (A=3,M=4) and finish (M=2).  Each 1024-value
        // inverse tree executes 2,976 multiplications and 32 inversions; the
        // short-domain path performs one direct inversion per value.
        const weight_additions = try multiplyCounter(self.weight_value_count, 3);
        const weight_multiplications = try addCounter(
            try multiplyCounter(self.weight_value_count, 6),
            try multiplyCounter(self.inverse_tree_block_count, 2_976),
        );
        const inversion_count = try addCounter(
            self.constant_inversion_count,
            try addCounter(
                self.direct_inversion_count,
                try multiplyCounter(self.inverse_tree_block_count, 32),
            ),
        );

        return .{
            .field_additions = try addCounter(
                self.constant_addition_count,
                try addCounter(
                    try multiplyCounter(self.domain_circle_multiplications, 2),
                    try addCounter(
                        scale_additions,
                        try addCounter(
                            weight_additions,
                            try addCounter(
                                self.dot_product_terms,
                                self.reduction_addition_count,
                            ),
                        ),
                    ),
                ),
            ),
            .field_multiplications = try addCounter(
                self.constant_multiplication_count,
                try addCounter(
                    try multiplyCounter(self.domain_circle_multiplications, 4),
                    try addCounter(
                        scale_multiplications,
                        try addCounter(weight_multiplications, self.dot_product_terms),
                    ),
                ),
            ),
            .field_inversions = inversion_count,
        };
    }
};

pub const QUOTIENT_PREPARATION_EXECUTION_SCHEMA_VERSION: u16 = 1;
pub const QUOTIENT_ROW_EXECUTION_SCHEMA_VERSION: u16 = 1;

/// Completed backend-independent preparation of the quotient sample geometry.
///
/// `input_sample_count` names transcript samples. Columns sampled at exactly
/// two points add one periodicity sample, so `expanded_sample_count` is the
/// exact number of random-power advances and conjugate-line constructions.
/// `periodicity_doubles` is the sum of the sampled columns' log sizes, i.e. the
/// circle doublings actually executed while deriving the periodicity points.
pub const QuotientPreparationExecution = struct {
    schema_version: u16 = QUOTIENT_PREPARATION_EXECUTION_SCHEMA_VERSION,
    lifting_log_size: u32,
    tree_count: u64,
    column_count: u64,
    sampled_column_count: u64,
    input_sample_count: u64,
    periodic_sample_count: u64,
    expanded_sample_count: u64,
    distinct_batch_count: u64,
    periodicity_doubles: u64,

    pub fn validate(self: QuotientPreparationExecution) Error!void {
        if (self.schema_version != QUOTIENT_PREPARATION_EXECUTION_SCHEMA_VERSION or
            self.lifting_log_size == 0 or
            self.lifting_log_size >= @bitSizeOf(u64) or
            self.tree_count == 0 or self.column_count == 0 or
            self.sampled_column_count == 0 or
            self.sampled_column_count > self.column_count or
            self.input_sample_count == 0 or
            self.periodic_sample_count > self.sampled_column_count or
            self.expanded_sample_count != try addCounter(
                self.input_sample_count,
                self.periodic_sample_count,
            ) or
            self.distinct_batch_count == 0 or
            self.distinct_batch_count > self.expanded_sample_count or
            self.periodicity_doubles > try multiplyCounter(
                self.periodic_sample_count,
                self.lifting_log_size,
            ))
        {
            return error.InvalidCounterGroup;
        }
    }

    pub fn exactWork(self: QuotientPreparationExecution) Error!Counters {
        try self.validate();
        // Per expanded sample: one random-power multiplication, the
        // conjugate-line schedule (A=3, M=5), and two linear-term additions.
        // Per distinct batch: determinant (A=1, M=2). Each periodicity point
        // executes its exact circle doubles and one secure-circle addition.
        return .{
            .field_additions = try addCounter(
                try addCounter(
                    try multiplyCounter(self.expanded_sample_count, 5),
                    self.distinct_batch_count,
                ),
                try multiplyCounter(
                    try addCounter(self.periodicity_doubles, self.periodic_sample_count),
                    2,
                ),
            ),
            .field_multiplications = try addCounter(
                try addCounter(
                    try multiplyCounter(self.expanded_sample_count, 6),
                    try multiplyCounter(self.distinct_batch_count, 2),
                ),
                try multiplyCounter(
                    try addCounter(self.periodicity_doubles, self.periodic_sample_count),
                    4,
                ),
            ),
        };
    }
};

/// Schedule selected by the completed quotient-row implementation. The tag is
/// diagnostic and admission-critical: host batch inversions and Metal direct
/// inversions cannot impersonate one another even when their aggregate counts
/// happen to coincide.
pub const QuotientRowPath = enum(u3) {
    host_streaming,
    host_bounded_scalar,
    host_bounded_batched,
    metal_combined,
    metal_raw_direct,
    metal_raw_segmented,
    metal_raw_grouped_partials,
};

/// Exact aggregate geometry returned only after every quotient row completes.
///
/// The fixed row law contributes `A=5D, M=4D` per row. Numerator fields carry
/// the actual selected CPU/device schedule (including native-size grouped
/// partials), while combined-plan source cells each contribute four M31 adds
/// and multiplies. Circle additions include every bit-reversed walk/device
/// point construction and expand to `A=2, M=4` here. Batch-inverse products
/// and inversion calls are reported from the actual chunk/dispatch shape.
pub const QuotientRowExecution = struct {
    schema_version: u16 = QUOTIENT_ROW_EXECUTION_SCHEMA_VERSION,
    path: QuotientRowPath,
    lifting_log_size: u32,
    row_count: u64,
    sample_batch_count: u64,
    contribution_count: u64,
    combined_view_count: u64,
    grouped_partial_count: u64,
    numerator_additions: u64,
    numerator_multiplications: u64,
    combined_plan_source_cells: u64,
    domain_circle_additions: u64,
    batch_inverse_multiplications: u64,
    batch_inverse_calls: u64,

    pub fn validate(self: QuotientRowExecution) Error!void {
        if (self.schema_version != QUOTIENT_ROW_EXECUTION_SCHEMA_VERSION or
            self.lifting_log_size == 0 or
            self.lifting_log_size >= @bitSizeOf(u64) or
            self.row_count != (@as(u64, 1) << @intCast(self.lifting_log_size)) or
            self.sample_batch_count == 0 or
            self.batch_inverse_calls == 0)
        {
            return error.InvalidCounterGroup;
        }

        switch (self.path) {
            .host_streaming => {
                if (self.grouped_partial_count != 0) {
                    return error.InvalidCounterGroup;
                }
            },
            .host_bounded_scalar, .host_bounded_batched => {
                if (self.combined_view_count != 0 or
                    self.combined_plan_source_cells != 0)
                {
                    return error.InvalidCounterGroup;
                }
            },
            .metal_combined => {
                if (self.grouped_partial_count != 0 or
                    self.batch_inverse_multiplications != 0 or
                    self.batch_inverse_calls != try multiplyCounter(
                        self.row_count,
                        self.sample_batch_count,
                    ))
                {
                    return error.InvalidCounterGroup;
                }
            },
            .metal_raw_direct, .metal_raw_segmented => {
                if (self.combined_view_count != 0 or
                    self.grouped_partial_count != 0 or
                    self.combined_plan_source_cells != 0 or
                    self.batch_inverse_multiplications != 0 or
                    self.batch_inverse_calls != try multiplyCounter(
                        self.row_count,
                        self.sample_batch_count,
                    ))
                {
                    return error.InvalidCounterGroup;
                }
            },
            .metal_raw_grouped_partials => {
                if (self.combined_view_count != 0 or
                    self.grouped_partial_count == 0 or
                    self.combined_plan_source_cells != 0 or
                    self.batch_inverse_multiplications != 0 or
                    self.batch_inverse_calls != try multiplyCounter(
                        self.row_count,
                        self.sample_batch_count,
                    ))
                {
                    return error.InvalidCounterGroup;
                }
            },
        }
    }

    pub fn exactWork(self: QuotientRowExecution) Error!Counters {
        try self.validate();
        const batch_rows = try multiplyCounter(self.row_count, self.sample_batch_count);
        const fixed_additions = try multiplyCounter(batch_rows, 5);
        const fixed_multiplications = try multiplyCounter(batch_rows, 4);
        const plan_operations = try multiplyCounter(self.combined_plan_source_cells, 4);
        return .{
            .field_additions = try addCounter(
                try addCounter(
                    try addCounter(fixed_additions, self.numerator_additions),
                    plan_operations,
                ),
                try multiplyCounter(self.domain_circle_additions, 2),
            ),
            .field_multiplications = try addCounter(
                try addCounter(
                    try addCounter(
                        fixed_multiplications,
                        self.numerator_multiplications,
                    ),
                    plan_operations,
                ),
                try addCounter(
                    try multiplyCounter(self.domain_circle_additions, 4),
                    self.batch_inverse_multiplications,
                ),
            ),
            .field_inversions = self.batch_inverse_calls,
        };
    }
};

pub const FRI_FOLD_EXECUTION_SCHEMA_VERSION: u16 = 1;
pub const FRI_LINE_INTERPOLATION_EXECUTION_SCHEMA_VERSION: u16 = 1;
pub const MAX_FRI_FOLD_EXECUTIONS: usize = @bitSizeOf(u64) + 1;

/// The inverse-coordinate schedule that actually completed for a FRI fold.
///
/// Host folds walk the coset and execute the scalar M31 batch-inverse
/// implementation. Large Metal folds construct every requested point and
/// invert its selected coordinate independently on a cache miss; a retained
/// cache hit executes no field work for inverse preparation.
pub const FriInversePath = enum(u2) {
    host_batch,
    metal_direct,
    retained,
};

pub const FriFoldKind = enum(u1) {
    circle_to_line,
    line,
};

/// Backend-returned geometry for one completed FRI fold transaction. A
/// transaction may contain several consecutive line halvings, including the
/// resident Metal cascade. Domain indices are recorded because the direct
/// Metal point-construction cost depends on the set bits of each exponent.
pub const FriFoldExecution = struct {
    schema_version: u16 = FRI_FOLD_EXECUTION_SCHEMA_VERSION,
    kind: FriFoldKind,
    initial_count: u64,
    fold_count: u32,
    domain_log_size: u32,
    domain_initial_index: u32,
    domain_step_size: u32,
    inverse_path: FriInversePath,
    /// QM31 squares performed while advancing powers of the folding challenge.
    alpha_squares: u32,
    /// Host `LineDomain.double` calls completed inside this transaction.
    domain_doubles: u32,
    /// Metal's circle kernel exploits the known-zero destination and therefore
    /// omits the generic accumulator multiplication and addition.
    optimized_zero_accumulator: bool = false,

    pub fn validate(self: FriFoldExecution) Error!void {
        if (self.schema_version != FRI_FOLD_EXECUTION_SCHEMA_VERSION or
            self.initial_count < 2 or
            !std.math.isPowerOfTwo(self.initial_count) or
            self.fold_count == 0 or
            self.fold_count > std.math.log2_int(u64, self.initial_count) or
            self.domain_initial_index >= (@as(u32, 1) << 31) or
            self.domain_step_size == 0 or
            self.domain_step_size >= (@as(u32, 1) << 31))
        {
            return error.InvalidCounterGroup;
        }

        const input_log: u32 = @intCast(std.math.log2_int(u64, self.initial_count));
        switch (self.kind) {
            .circle_to_line => {
                if (self.fold_count != 1 or input_log == 0 or
                    self.domain_log_size != input_log - 1 or
                    self.domain_doubles != 0 or
                    self.alpha_squares != @intFromBool(!self.optimized_zero_accumulator))
                {
                    return error.InvalidCounterGroup;
                }
            },
            .line => {
                if (self.domain_log_size != input_log or
                    self.optimized_zero_accumulator or
                    self.alpha_squares > self.fold_count or
                    self.domain_doubles > 2 * self.fold_count)
                {
                    return error.InvalidCounterGroup;
                }
            },
        }
    }

    pub fn exactWork(self: FriFoldExecution) Error!Counters {
        try self.validate();

        var additions: u64 = 0;
        var multiplications: u64 = 0;
        var inversions: u64 = 0;
        var folds: u64 = 0;
        var current_count = self.initial_count;
        var current_initial = self.domain_initial_index;
        var current_step = self.domain_step_size;

        var fold: u32 = 0;
        while (fold < self.fold_count) : (fold += 1) {
            const output_count = current_count >> 1;
            const inverse_work = try friInversePreparationWork(
                self.inverse_path,
                output_count,
                current_initial,
                current_step,
            );
            additions = try addCounter(additions, inverse_work.additions);
            multiplications = try addCounter(
                multiplications,
                inverse_work.multiplications,
            );
            inversions = try addCounter(inversions, inverse_work.inversions);

            const additions_per_fold: u64 = switch (self.kind) {
                .circle_to_line => if (self.optimized_zero_accumulator) 3 else 4,
                .line => 3,
            };
            const multiplications_per_fold: u64 = switch (self.kind) {
                .circle_to_line => if (self.optimized_zero_accumulator) 2 else 3,
                .line => 2,
            };
            additions = try addCounter(
                additions,
                try multiplyCounter(output_count, additions_per_fold),
            );
            multiplications = try addCounter(
                multiplications,
                try multiplyCounter(output_count, multiplications_per_fold),
            );
            folds = try addCounter(folds, output_count);
            current_count = output_count;
            current_initial = (current_initial << 1) & 0x7fff_ffff;
            current_step = (current_step << 1) & 0x7fff_ffff;
        }

        additions = try addCounter(
            additions,
            try multiplyCounter(self.domain_doubles, 4),
        );
        multiplications = try addCounter(
            multiplications,
            try addCounter(
                try multiplyCounter(self.domain_doubles, 8),
                self.alpha_squares,
            ),
        );
        return .{
            .field_additions = additions,
            .field_multiplications = multiplications,
            .field_inversions = inversions,
            .fri_folds = folds,
        };
    }
};

const FriInverseWork = struct {
    additions: u64,
    multiplications: u64,
    inversions: u64,
};

fn friInversePreparationWork(
    path: FriInversePath,
    element_count: u64,
    initial_index: u32,
    step_size: u32,
) Error!FriInverseWork {
    if (element_count == 0 or !std.math.isPowerOfTwo(element_count))
        return error.InvalidCounterGroup;
    return switch (path) {
        .host_batch => .{
            // Every iterator `next` advances one M31 circle point.
            .additions = try multiplyCounter(element_count, 2),
            .multiplications = try addCounter(
                try multiplyCounter(element_count, 4),
                try logicalM31BatchInverseMultiplications(element_count),
            ),
            .inversions = 1,
        },
        .metal_direct => blk: {
            const log_size: u32 = @intCast(std.math.log2_int(u64, element_count));
            var circle_multiplications: u64 = 0;
            var row: u64 = 0;
            while (row < element_count) : (row += 1) {
                const natural = if (log_size == 0)
                    0
                else
                    @bitReverse(@as(u32, @intCast(row))) >>
                        @intCast(32 - log_size);
                const global = @as(u64, initial_index) +
                    @as(u64, step_size) * natural;
                const exponent: u32 = @intCast(global & 0x7fff_ffff);
                if (exponent != 0) {
                    const bit_length: u64 = 32 - @clz(exponent);
                    circle_multiplications = try addCounter(
                        circle_multiplications,
                        try addCounter(bit_length, @popCount(exponent)),
                    );
                }
            }
            break :blk .{
                .additions = try multiplyCounter(circle_multiplications, 2),
                .multiplications = try multiplyCounter(circle_multiplications, 4),
                .inversions = element_count,
            };
        },
        .retained => .{ .additions = 0, .multiplications = 0, .inversions = 0 },
    };
}

/// Exact multiplication count of `batchInverseInPlace(M31, ...)`. The M31
/// path uses the 8-way striped schedule above eight elements, the 4-way
/// schedule at eight elements, and the classic schedule below that.
pub fn logicalM31BatchInverseMultiplications(element_count: u64) Error!u64 {
    if (element_count == 0) return error.InvalidCounterGroup;
    if (element_count > 8 and element_count & 7 == 0)
        return addCounter(try multiplyCounter(element_count, 3), 5);
    if (element_count > 4 and element_count & 3 == 0)
        return addCounter(try multiplyCounter(element_count, 3), 1);
    return multiplyCounter(element_count - 1, 3);
}

/// Fixed-capacity, fail-closed receipt ledger shared by generic and fused FRI
/// paths. Backends append only after the corresponding transaction succeeds.
pub const FriFoldExecutionLedger = struct {
    executions: [MAX_FRI_FOLD_EXECUTIONS]FriFoldExecution = undefined,
    count: usize = 0,
    complete: bool = true,

    pub fn observe(self: *FriFoldExecutionLedger, execution: FriFoldExecution) void {
        if (!self.complete) return;
        execution.validate() catch {
            self.complete = false;
            return;
        };
        if (self.count >= self.executions.len) {
            self.complete = false;
            return;
        }
        self.executions[self.count] = execution;
        self.count += 1;
    }

    pub fn exactWork(self: *const FriFoldExecutionLedger) Error!Counters {
        if (!self.complete or self.count == 0) return error.InvalidCounterGroup;
        var total: Counters = .{};
        for (self.executions[0..self.count]) |execution| {
            total = try total.add(try execution.exactWork());
        }
        return total;
    }
};

/// Completed terminal line interpolation. Its IFFT walks `N/2` domain points
/// at every level, directly inverts each x-coordinate, executes one QM31
/// butterfly per point, doubles the domain, and finally normalizes all N
/// coefficients with one shared inverse.
pub const FriLineInterpolationExecution = struct {
    schema_version: u16 = FRI_LINE_INTERPOLATION_EXECUTION_SCHEMA_VERSION,
    log_size: u32,

    pub fn validate(self: FriLineInterpolationExecution) Error!void {
        if (self.schema_version != FRI_LINE_INTERPOLATION_EXECUTION_SCHEMA_VERSION or
            self.log_size >= @bitSizeOf(u64))
        {
            return error.InvalidCounterGroup;
        }
    }

    pub fn exactWork(self: FriLineInterpolationExecution) Error!Counters {
        try self.validate();
        const element_count = @as(u64, 1) << @intCast(self.log_size);
        const butterflies = try logicalFftButterflies(self.log_size, 0);
        return .{
            .field_additions = try addCounter(
                try multiplyCounter(butterflies, 4),
                try multiplyCounter(self.log_size, 4),
            ),
            .field_multiplications = try addCounter(
                try multiplyCounter(butterflies, 5),
                try addCounter(
                    try multiplyCounter(self.log_size, 8),
                    element_count,
                ),
            ),
            .field_inversions = try addCounter(butterflies, 1),
            .fft_butterflies = butterflies,
        };
    }
};

/// Executed QM31 multiplications for one sampled-value basis task. The Metal
/// shader has two deliberate schedules: a generic per-index popcount walk for
/// narrower pipelines, and a 256-lane block schedule that recomputes each
/// block's low-byte products to expose independent threadgroups.
pub fn logicalSampledCoefficientBasisMultiplications(
    log_size: u32,
    threadgroup_width: u32,
) Error!u64 {
    if (threadgroup_width == 0 or threadgroup_width > 256 or
        log_size >= @bitSizeOf(u64))
    {
        return error.InvalidCounterGroup;
    }
    const basis_len = @as(u64, 1) << @intCast(log_size);
    if (threadgroup_width != 256) {
        if (log_size == 0) return 0;
        return multiplyCounter(log_size, basis_len >> 1);
    }

    const block_count = ((basis_len - 1) / 256) + 1;
    const low_log = @min(log_size, 8);
    const low_products = try multiplyCounter(
        block_count,
        try multiplyCounter(low_log, 128),
    );
    const high_log = log_size - low_log;
    const high_products = if (high_log == 0)
        0
    else
        try multiplyCounter(
            high_log,
            @as(u64, 1) << @intCast(high_log - 1),
        );
    const block_products = basis_len - @min(basis_len, 256);
    return addCounter(
        try addCounter(low_products, high_products),
        block_products,
    );
}

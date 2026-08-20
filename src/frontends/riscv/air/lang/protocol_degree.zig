//! Complete algebraic and quotient-degree model for the current RISC-V row AIR.
//!
//! Logical expression degree is only the first layer. This pass models the
//! shipped direct-constraint boundary and the exact pairs-batched LogUp
//! recurrence, including current/previous interaction masks, the `is_first`
//! boundary term, relation denominators, signed numerators, and vanishing-
//! polynomial division. It does not model a proposed lowering.

const std = @import("std");
const degree = @import("degree.zig");
const shadow_program = @import("shadow_program.zig");
const types = @import("types.zig");

pub const Degree = degree.Degree;

pub const DirectConstraint = struct {
    constraint: types.ConstraintId,
    expression: Degree,
    explicit_gate: ?Degree,
    /// The current semantic component applies no mask outside the imported
    /// root. Its placement selector is already a source expression.
    external_row_mask: Degree,
    final: Degree,
    quotient_expansion_bits: u8,
    required_log_degree_bound: u32,
};

pub const Lookup = struct {
    index: u32,
    numerator: Degree,
    denominator: Degree,
    maximum_field: Degree,
};

pub const FractionDegree = struct {
    numerator: Degree,
    denominator: Degree,
};

/// Degrees contributed by compiler-owned row-window and boundary nodes.
///
/// Keeping this context explicit lets typed shifted-column lowering reuse the
/// exact production recurrence without baking `degree == 1` into a second
/// analysis pass. `interactionTerms` remains the compat-v1 convenience entry
/// point and supplies the shipped values.
pub const InteractionContext = struct {
    row_window: Degree,
    boundary_selector: Degree,
    boundary_claim: Degree,
};

pub const InteractionTerms = struct {
    row_window: Degree,
    boundary_selector: Degree,
    boundary_claim: Degree,
    delta: Degree,
    denominator_product: Degree,
    combined_numerator: Degree,
    final: Degree,
};

pub const InteractionConstraint = struct {
    batch: u32,
    first_lookup: u32,
    entry_count: u8,
    /// Both current and previous samples are masks of one committed secure
    /// column and therefore retain degree one.
    row_window: Degree,
    boundary_selector: Degree,
    boundary_claim: Degree,
    delta: Degree,
    denominator_product: Degree,
    combined_numerator: Degree,
    final: Degree,
    quotient_expansion_bits: u8,
    required_log_degree_bound: u32,
};

pub const Error = std.mem.Allocator.Error ||
    degree.Error ||
    shadow_program.ValidationError ||
    error{
        DegreeOverflow,
        InvalidBatchLayout,
        LogDegreeOverflow,
    };

pub const Analysis = struct {
    allocator: std.mem.Allocator,
    trace_log_size: u32,
    direct: []DirectConstraint,
    lookups: []Lookup,
    interactions: []InteractionConstraint,
    maximum_direct_degree: Degree,
    maximum_lookup_numerator_degree: Degree,
    maximum_lookup_denominator_degree: Degree,
    maximum_interaction_degree: Degree,
    required_direct_log_degree_bound: u32,
    required_interaction_log_degree_bound: u32,

    pub fn deinit(self: *Analysis) void {
        self.allocator.free(self.interactions);
        self.allocator.free(self.lookups);
        self.allocator.free(self.direct);
        self.* = undefined;
    }

    pub fn requiredCompositionLogDegreeBound(self: *const Analysis) u32 {
        return @max(
            self.required_direct_log_degree_bound,
            self.required_interaction_log_degree_bound,
        );
    }
};

pub fn analyze(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    trace_log_size: u32,
) Error!Analysis {
    try imported.validate();
    var logical = try degree.analyze(allocator, &imported.imported.arena);
    defer logical.deinit();

    const direct = try allocator.alloc(
        DirectConstraint,
        imported.direct_constraints.len,
    );
    errdefer allocator.free(direct);
    var maximum_direct: Degree = 0;
    var required_direct = trace_log_size;
    for (imported.direct_constraints, direct) |constraint_id, *result| {
        const item = logical.constraint(constraint_id) orelse
            return error.InvalidConstraintMap;
        const final = item.total;
        const expansion = quotientExpansionBits(final);
        const required = try addLogExpansion(trace_log_size, expansion);
        result.* = .{
            .constraint = constraint_id,
            .expression = item.expression,
            .explicit_gate = item.gate,
            .external_row_mask = 0,
            .final = final,
            .quotient_expansion_bits = expansion,
            .required_log_degree_bound = required,
        };
        maximum_direct = @max(maximum_direct, final);
        required_direct = @max(required_direct, required);
    }

    const lookups = try allocator.alloc(Lookup, imported.lookups.len);
    errdefer allocator.free(lookups);
    var maximum_numerator: Degree = 0;
    var maximum_denominator: Degree = 0;
    for (imported.lookups, lookups, 0..) |lookup, *result, index| {
        const numerator = logical.value(lookup.numerator) orelse
            return error.InvalidNumerator;
        const fields = imported.lookupFields(index) orelse
            return error.InvalidLookupRange;
        var maximum_field: Degree = 0;
        for (fields) |field| {
            const field_degree = logical.value(field) orelse
                return error.InvalidLookupValue;
            maximum_field = @max(maximum_field, field_degree);
        }
        // A relation denominator is z plus a challenge-linear combination of
        // tuple fields, so addition and constant coefficients do not increase
        // the maximum field degree.
        result.* = .{
            .index = std.math.cast(u32, index) orelse
                return error.InvalidBatchLayout,
            .numerator = numerator,
            .denominator = maximum_field,
            .maximum_field = maximum_field,
        };
        maximum_numerator = @max(maximum_numerator, numerator);
        maximum_denominator = @max(maximum_denominator, maximum_field);
    }

    const interactions = try allocator.alloc(
        InteractionConstraint,
        imported.batchCount(),
    );
    errdefer allocator.free(interactions);
    var maximum_interaction: Degree = 0;
    var required_interaction = trace_log_size;
    var first_lookup: usize = 0;
    for (interactions, 0..) |*result, batch| {
        if (first_lookup >= lookups.len) return error.InvalidBatchLayout;
        const remaining = lookups.len - first_lookup;
        const entry_count = @min(@as(usize, imported.batch_size), remaining);
        if (entry_count == 0 or entry_count > 2)
            return error.InvalidBatchLayout;

        const first = FractionDegree{
            .numerator = lookups[first_lookup].numerator,
            .denominator = lookups[first_lookup].denominator,
        };
        const second = if (entry_count == 2)
            FractionDegree{
                .numerator = lookups[first_lookup + 1].numerator,
                .denominator = lookups[first_lookup + 1].denominator,
            }
        else
            null;
        const terms = try interactionTerms(first, second);
        const expansion = quotientExpansionBits(terms.final);
        const required = try addLogExpansion(trace_log_size, expansion);
        result.* = .{
            .batch = std.math.cast(u32, batch) orelse
                return error.InvalidBatchLayout,
            .first_lookup = std.math.cast(u32, first_lookup) orelse
                return error.InvalidBatchLayout,
            .entry_count = @intCast(entry_count),
            .row_window = terms.row_window,
            .boundary_selector = terms.boundary_selector,
            .boundary_claim = terms.boundary_claim,
            .delta = terms.delta,
            .denominator_product = terms.denominator_product,
            .combined_numerator = terms.combined_numerator,
            .final = terms.final,
            .quotient_expansion_bits = expansion,
            .required_log_degree_bound = required,
        };
        maximum_interaction = @max(maximum_interaction, terms.final);
        required_interaction = @max(required_interaction, required);
        first_lookup += entry_count;
    }
    if (first_lookup != lookups.len) return error.InvalidBatchLayout;

    return .{
        .allocator = allocator,
        .trace_log_size = trace_log_size,
        .direct = direct,
        .lookups = lookups,
        .interactions = interactions,
        .maximum_direct_degree = maximum_direct,
        .maximum_lookup_numerator_degree = maximum_numerator,
        .maximum_lookup_denominator_degree = maximum_denominator,
        .maximum_interaction_degree = maximum_interaction,
        .required_direct_log_degree_bound = required_direct,
        .required_interaction_log_degree_bound = required_interaction,
    };
}

/// Degree recurrence for the exact shipped LogUp row equation. `second ==
/// null` models `RowPair.single`, whose synthetic `n2 = 0, d2 = 1` both have
/// degree zero.
pub fn interactionTerms(
    first: FractionDegree,
    second: ?FractionDegree,
) error{DegreeOverflow}!InteractionTerms {
    // S(x), S(x*g^-1), and is_first(x) are committed/preprocessed columns;
    // the claimed sum and relation challenges are transcript constants.
    return interactionTermsWithContext(first, second, .{
        .row_window = 1,
        .boundary_selector = 1,
        .boundary_claim = 0,
    });
}

/// Degree recurrence for an explicitly lowered typed row-window context.
pub fn interactionTermsWithContext(
    first: FractionDegree,
    second: ?FractionDegree,
    context: InteractionContext,
) error{DegreeOverflow}!InteractionTerms {
    const boundary_term = try addDegree(
        context.boundary_selector,
        context.boundary_claim,
    );
    const delta = @max(context.row_window, boundary_term);
    const second_denominator = if (second) |item| item.denominator else 0;
    const denominator_product = try addDegree(
        first.denominator,
        second_denominator,
    );
    const first_numerator_term = try addDegree(
        first.numerator,
        second_denominator,
    );
    const second_numerator_term = if (second) |item|
        try addDegree(item.numerator, first.denominator)
    else
        0;
    const combined_numerator = @max(
        first_numerator_term,
        second_numerator_term,
    );
    const transition_term = try addDegree(delta, denominator_product);
    return .{
        .row_window = context.row_window,
        .boundary_selector = context.boundary_selector,
        .boundary_claim = context.boundary_claim,
        .delta = delta,
        .denominator_product = denominator_product,
        .combined_numerator = combined_numerator,
        .final = @max(transition_term, combined_numerator),
    };
}

/// After division by the trace-domain vanishing polynomial, an algebraic
/// degree-`d` constraint needs coefficient capacity for at most `(d - 1)`
/// trace-degree units. This is the standard stwo expansion convention: cubic
/// constraints need one extra log bit; degree four or five need two.
pub fn quotientExpansionBits(final_degree: Degree) u8 {
    const units = @max(@as(Degree, 1), final_degree -| 1);
    if (units <= 1) return 0;
    return @intCast(@bitSizeOf(Degree) - @clz(units - 1));
}

fn addDegree(lhs: Degree, rhs: Degree) error{DegreeOverflow}!Degree {
    return std.math.add(Degree, lhs, rhs) catch error.DegreeOverflow;
}

fn addLogExpansion(
    trace_log_size: u32,
    expansion: u8,
) error{LogDegreeOverflow}!u32 {
    return std.math.add(u32, trace_log_size, expansion) catch
        error.LogDegreeOverflow;
}

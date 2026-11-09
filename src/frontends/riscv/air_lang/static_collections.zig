//! Statically shaped authoring collections for the typed AIR language.
//!
//! A `StaticArray(element, len)` is an authoring-time collection of scalar IR
//! values. It is deliberately not an opaque array expression: maps, zip maps,
//! and folds expand eagerly in ascending index order, making every resulting
//! scalar node visible to degree analysis and deterministic materialization.
//!
//! Collection provenance is retained separately from structural node identity.
//! Consequently, two expansions may share one CSE'd `ValueId` while keeping
//! distinct source spans for diagnostics. The collection helpers themselves
//! emit only scalar expression nodes: they never add constraints, hints, or
//! effects implicitly.

const std = @import("std");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const CollectionError = error{
    ElementTypeMismatch,
    EmptyCollection,
    IndexOutOfBounds,
    ShapeMismatch,
    StaticLengthOverflow,
};

pub const Error = ir.Error || CollectionError;

/// One scalar value together with the semantic expansion site that produced
/// or selected it. This span need not equal the structurally interned node's
/// primary span: the first construction owns that span, while every unrolled
/// collection element retains its own diagnostic site here.
pub const SourcedValue = struct {
    value: types.ValueId,
    source_span: source.SourceSpan,
};

/// Validates a collection length before narrowing it into the IR's canonical
/// `u16` static-array representation.
pub fn validateStaticLength(length: usize) CollectionError!u16 {
    if (length == 0) return error.EmptyCollection;
    return std.math.cast(u16, length) orelse error.StaticLengthOverflow;
}

/// Returns the scalar semantic type represented by an array element tag.
pub fn scalarType(element: types.ArrayElement) types.Type {
    return switch (element) {
        .felt => .felt,
        .bit => .bit,
        .byte => .byte,
        .uint16 => .uint16,
        .uint20 => .uint20,
        .word32 => .word32,
        .register_index => .register_index,
        .address => .address,
        .pc => .pc,
        .clock => .clock,
        .selector => .selector,
    };
}

/// Scalar-expression convenience passed to static collection callbacks.
///
/// Its fixed span is the source site assigned to the current unrolled
/// expansion. Its methods intentionally omit assertion, hint, effect, input,
/// and function constructors. This is an authoring contract rather than a Zig
/// security boundary: callbacks and their contexts are trusted construction
/// code, and whole-program validation remains authoritative.
pub const ScalarBuilder = struct {
    arena: *ir.Arena,
    expansion_span: source.SourceSpan,

    pub fn span(self: ScalarBuilder) source.SourceSpan {
        return self.expansion_span;
    }

    pub fn constantField(self: ScalarBuilder, canonical: u32) Error!types.ValueId {
        return self.arena.constantField(canonical, self.expansion_span);
    }

    pub fn constantUnsigned(
        self: ScalarBuilder,
        ty: types.Type,
        value: u32,
    ) Error!types.ValueId {
        return self.arena.constantUnsigned(ty, value, self.expansion_span);
    }

    pub fn add(
        self: ScalarBuilder,
        lhs: types.ValueId,
        rhs: types.ValueId,
    ) Error!types.ValueId {
        return self.arena.add(lhs, rhs, self.expansion_span);
    }

    pub fn sub(
        self: ScalarBuilder,
        lhs: types.ValueId,
        rhs: types.ValueId,
    ) Error!types.ValueId {
        return self.arena.sub(lhs, rhs, self.expansion_span);
    }

    pub fn mul(
        self: ScalarBuilder,
        lhs: types.ValueId,
        rhs: types.ValueId,
    ) Error!types.ValueId {
        return self.arena.mul(lhs, rhs, self.expansion_span);
    }

    pub fn neg(self: ScalarBuilder, value: types.ValueId) Error!types.ValueId {
        return self.arena.neg(value, self.expansion_span);
    }

    pub fn select(
        self: ScalarBuilder,
        selector: types.ValueId,
        when_true: types.ValueId,
        when_false: types.ValueId,
    ) Error!types.ValueId {
        return self.arena.select(
            selector,
            when_true,
            when_false,
            self.expansion_span,
        );
    }
};

/// A nonempty fixed-size array whose scalar semantic type and length are part
/// of its Zig type. Invalid lengths are reported by constructors and
/// `semanticType`; no constraints are inserted by construction or traversal.
pub fn StaticArray(
    comptime element: types.ArrayElement,
    comptime static_len: usize,
) type {
    return struct {
        items: [static_len]SourcedValue,

        const Self = @This();

        pub const element_tag = element;
        pub const len = static_len;

        /// Builds a typed collection and derives each diagnostic span from its
        /// scalar node's primary source.
        pub fn fromValues(
            arena: *const ir.Arena,
            values: []const types.ValueId,
        ) Error!Self {
            if (comptime static_len == 0) {
                return error.EmptyCollection;
            } else {
                try requireShape(values.len);
                var result: Self = undefined;
                for (values, 0..) |value, index| {
                    const node = arena.node(value) orelse return error.UnknownValue;
                    if (!std.meta.eql(node.key.ty, scalarType(element)))
                        return error.ElementTypeMismatch;
                    try arena.validateSpan(node.primary_source);
                    result.items[index] = .{
                        .value = value,
                        .source_span = node.primary_source,
                    };
                }
                return result;
            }
        }

        /// Builds a typed collection with explicit per-expansion provenance.
        /// Every value and span is validated before the collection is returned.
        pub fn fromSourced(
            arena: *const ir.Arena,
            values: []const SourcedValue,
        ) Error!Self {
            if (comptime static_len == 0) {
                return error.EmptyCollection;
            } else {
                try requireShape(values.len);
                var result: Self = undefined;
                for (values, 0..) |value, index| {
                    try validateSourced(arena, scalarType(element), value);
                    result.items[index] = value;
                }
                return result;
            }
        }

        /// Canonical semantic array type corresponding to this static shape.
        pub fn semanticType() Error!types.Type {
            const encoded_len = try validateStaticLength(static_len);
            return types.Type.staticArray(element, encoded_len);
        }

        /// Revalidates values and provenance against an arena. Lowering passes
        /// may use this at trust boundaries without allocating.
        pub fn validate(self: Self, arena: *const ir.Arena) Error!void {
            _ = try validateStaticLength(static_len);
            for (self.items) |item| {
                try validateSourced(arena, scalarType(element), item);
            }
        }

        pub fn sourcedAt(self: Self, index: usize) Error!SourcedValue {
            if (index >= static_len) return error.IndexOutOfBounds;
            return self.items[index];
        }

        pub fn valueAt(self: Self, index: usize) Error!types.ValueId {
            return (try self.sourcedAt(index)).value;
        }

        /// Functional element replacement; the original array remains intact.
        pub fn replaced(
            self: Self,
            arena: *const ir.Arena,
            index: usize,
            replacement: SourcedValue,
        ) Error!Self {
            if (index >= static_len) return error.IndexOutOfBounds;
            try self.validate(arena);
            try validateSourced(arena, scalarType(element), replacement);
            var result = self;
            result.items[index] = replacement;
            return result;
        }

        /// Maps one source span over every element in canonical index order.
        ///
        /// The callback signature is
        /// `fn (ScalarBuilder, Context, usize, ValueId) Error!ValueId`.
        pub fn map(
            self: Self,
            arena: *ir.Arena,
            comptime output_element: types.ArrayElement,
            expansion_span: source.SourceSpan,
            context: anytype,
            comptime mapper: anytype,
        ) Error!StaticArray(output_element, static_len) {
            const spans = [_]source.SourceSpan{expansion_span} ** static_len;
            return self.mapWithSpans(
                arena,
                output_element,
                &spans,
                context,
                mapper,
            );
        }

        /// Maps explicit per-element source spans in canonical index order.
        /// All input and span validation happens before the first callback.
        pub fn mapWithSpans(
            self: Self,
            arena: *ir.Arena,
            comptime output_element: types.ArrayElement,
            expansion_spans: []const source.SourceSpan,
            context: anytype,
            comptime mapper: anytype,
        ) Error!StaticArray(output_element, static_len) {
            try self.validate(arena);
            try validateSpans(arena, static_len, expansion_spans);

            const checkpoint = arena.nodeCheckpoint();
            errdefer arena.rollbackToNodeCheckpoint(checkpoint);

            var result: StaticArray(output_element, static_len) = undefined;
            for (self.items, expansion_spans, 0..) |item, span_value, index| {
                const builder = ScalarBuilder{
                    .arena = arena,
                    .expansion_span = span_value,
                };
                const output = try mapper(builder, context, index, item.value);
                try validateValue(arena, scalarType(output_element), output);
                result.items[index] = .{
                    .value = output,
                    .source_span = span_value,
                };
            }
            return result;
        }

        /// Zips equally shaped arrays in canonical index order. Equal length is
        /// enforced by the parameter type, while scalar types remain explicit.
        ///
        /// The callback signature is
        /// `fn (ScalarBuilder, Context, usize, ValueId, ValueId) Error!ValueId`.
        pub fn zipMap(
            self: Self,
            arena: *ir.Arena,
            comptime rhs_element: types.ArrayElement,
            rhs: StaticArray(rhs_element, static_len),
            comptime output_element: types.ArrayElement,
            expansion_span: source.SourceSpan,
            context: anytype,
            comptime mapper: anytype,
        ) Error!StaticArray(output_element, static_len) {
            const spans = [_]source.SourceSpan{expansion_span} ** static_len;
            return self.zipMapWithSpans(
                arena,
                rhs_element,
                rhs,
                output_element,
                &spans,
                context,
                mapper,
            );
        }

        pub fn zipMapWithSpans(
            self: Self,
            arena: *ir.Arena,
            comptime rhs_element: types.ArrayElement,
            rhs: StaticArray(rhs_element, static_len),
            comptime output_element: types.ArrayElement,
            expansion_spans: []const source.SourceSpan,
            context: anytype,
            comptime mapper: anytype,
        ) Error!StaticArray(output_element, static_len) {
            try self.validate(arena);
            try rhs.validate(arena);
            try validateSpans(arena, static_len, expansion_spans);

            const checkpoint = arena.nodeCheckpoint();
            errdefer arena.rollbackToNodeCheckpoint(checkpoint);

            var result: StaticArray(output_element, static_len) = undefined;
            for (
                self.items,
                rhs.items,
                expansion_spans,
                0..,
            ) |lhs_item, rhs_item, span_value, index| {
                const builder = ScalarBuilder{
                    .arena = arena,
                    .expansion_span = span_value,
                };
                const output = try mapper(
                    builder,
                    context,
                    index,
                    lhs_item.value,
                    rhs_item.value,
                );
                try validateValue(arena, scalarType(output_element), output);
                result.items[index] = .{
                    .value = output,
                    .source_span = span_value,
                };
            }
            return result;
        }

        /// Left-folds in ascending index order using one expansion span.
        ///
        /// The callback signature is
        /// `fn (ScalarBuilder, Context, usize, ValueId, ValueId) Error!ValueId`,
        /// where the final two values are accumulator and current element.
        pub fn fold(
            self: Self,
            arena: *ir.Arena,
            comptime accumulator_element: types.ArrayElement,
            initial: SourcedValue,
            expansion_span: source.SourceSpan,
            context: anytype,
            comptime reducer: anytype,
        ) Error!SourcedValue {
            const spans = [_]source.SourceSpan{expansion_span} ** static_len;
            return self.foldWithSpans(
                arena,
                accumulator_element,
                initial,
                &spans,
                context,
                reducer,
            );
        }

        /// Left-folds with one explicit diagnostic span per unrolled step.
        pub fn foldWithSpans(
            self: Self,
            arena: *ir.Arena,
            comptime accumulator_element: types.ArrayElement,
            initial: SourcedValue,
            expansion_spans: []const source.SourceSpan,
            context: anytype,
            comptime reducer: anytype,
        ) Error!SourcedValue {
            try self.validate(arena);
            try validateSourced(arena, scalarType(accumulator_element), initial);
            try validateSpans(arena, static_len, expansion_spans);

            const checkpoint = arena.nodeCheckpoint();
            errdefer arena.rollbackToNodeCheckpoint(checkpoint);

            var accumulator = initial;
            for (self.items, expansion_spans, 0..) |item, span_value, index| {
                const builder = ScalarBuilder{
                    .arena = arena,
                    .expansion_span = span_value,
                };
                const output = try reducer(
                    builder,
                    context,
                    index,
                    accumulator.value,
                    item.value,
                );
                try validateValue(arena, scalarType(accumulator_element), output);
                accumulator = .{
                    .value = output,
                    .source_span = span_value,
                };
            }
            return accumulator;
        }

        fn requireShape(actual_len: usize) Error!void {
            _ = try validateStaticLength(static_len);
            if (actual_len != static_len) return error.ShapeMismatch;
        }
    };
}

fn validateSourced(
    arena: *const ir.Arena,
    expected_type: types.Type,
    item: SourcedValue,
) Error!void {
    try arena.validateSpan(item.source_span);
    try validateValue(arena, expected_type, item.value);
}

fn validateValue(
    arena: *const ir.Arena,
    expected_type: types.Type,
    value: types.ValueId,
) Error!void {
    const node = arena.node(value) orelse return error.UnknownValue;
    if (!std.meta.eql(node.key.ty, expected_type))
        return error.ElementTypeMismatch;
}

fn validateSpans(
    arena: *const ir.Arena,
    expected_len: usize,
    spans: []const source.SourceSpan,
) Error!void {
    if (spans.len != expected_len) return error.ShapeMismatch;
    for (spans) |span_value| try arena.validateSpan(span_value);
}

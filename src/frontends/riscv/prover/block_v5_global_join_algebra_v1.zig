//! The existing detached joins expressed once over either QM31 or recorded
//! arithmetic. These equations grant no authority to supplied claims: callers
//! must bind every input to fresh proofs and independently admitted coverage.
//! In particular source authentication, exact counts, and typed absence remain
//! obligations of the enclosing receiver, not conclusions of this module.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Schema = @import("../air/lookups/tables/schema.zig");

pub fn Accounting(comptime S: type) type {
    return struct {
        native_open_sum: S,
        precompile_open_sum: S,
        public_program_boundary_sum: S,
        program_provider_sum: S,
        table_provider_sum: S,
        ordinary_memory_opposite: S,
        external_memory_opposite: S,
        auxiliary_clock_memory_sum: S,
        register_compensation_sum: S,
    };
}
pub const ScalarSink = struct {
    pub fn zero(_: *@This(), value: Q, failure: anyerror) !void {
        if (!value.isZero()) return failure;
    }
};
pub fn Algebra(comptime S: type) type {
    return struct {
        pub const TableClaims = [Schema.KIND_COUNT]S;
        pub const LookupTotals = struct { provider_sum: S, consumer_table_sum: S };

        /// Scope is one execution/window, never the sum of multiple windows.
        pub fn states(sink: anytype, claims: []const S) !void {
            for (claims) |claim| try sink.zero(claim, error.UnclosedV5NativePublicState);
        }
        pub fn registers(sink: anytype, mode: u32, claims: []const S) !void {
            if (mode > 1) return error.UntrustedV5RegisterCustodyMode;
            if (mode == 1) for (claims) |claim| try sink.zero(claim, error.UnclosedV5RegisterWindow);
        }
        /// The independently reconstructed provider plan chooses this exact
        /// execution slice. Each of six kinds closes separately within it.
        /// Byte requests enter only range_check_8_8, exactly once.
        pub fn lookupGroup(sink: anytype, supply: TableClaims, requests: []const TableClaims, byte_parts: anytype) !LookupTotals {
            if (requests.len != byte_parts.len) return error.UntrustedV5TableByteCensus;
            var consumer: TableClaims = @splat(S.zero());
            var consumer_table_sum = S.zero();
            for (requests, byte_parts) |request, byte_part| {
                for (&consumer, request) |*sum, value| {
                    sum.* = sum.add(value);
                    consumer_table_sum = consumer_table_sum.add(value);
                }
                const byte_kind = @intFromEnum(Schema.Kind.range_check_8_8);
                consumer[byte_kind] = consumer[byte_kind].add(byte_part.sum);
            }
            var provider_sum = S.zero();
            for (supply, consumer) |provider, demand| {
                try sink.zero(provider.add(demand), error.UnclosedV5NativeLookupGroup);
                provider_sum = provider_sum.add(provider);
            }
            return .{ .provider_sum = provider_sum, .consumer_table_sum = consumer_table_sum };
        }
        pub fn transition(sink: anytype, requests: S, provider: S) !void {
            try sink.zero(requests.add(provider), error.UnclosedV5PackedTransitionBus);
        }
        pub fn program(sink: anytype, provider: S, requests: anytype) !void {
            var sum = provider;
            for (requests) |request| sum = sum.add(request.claim);
            try sink.zero(sum, error.UnclosedProgramRelation);
        }
        /// Preserve the original auxiliary-clock subtraction and register
        /// compensation addition. This is the final accounting check after
        /// every individual bus/census/source obligation has closed.
        pub fn residual(inputs: Accounting(S), byte_parts: anytype) S {
            var sum = inputs.native_open_sum.add(inputs.precompile_open_sum)
                .add(inputs.public_program_boundary_sum).add(inputs.program_provider_sum)
                .add(inputs.table_provider_sum).add(inputs.ordinary_memory_opposite)
                .add(inputs.external_memory_opposite).sub(inputs.auxiliary_clock_memory_sum)
                .add(inputs.register_compensation_sum);
            for (byte_parts) |part| sum = sum.add(part.sum);
            return sum;
        }
        pub fn accounting(sink: anytype, inputs: Accounting(S), byte_parts: anytype) !void {
            try sink.zero(residual(inputs, byte_parts), error.UnclosedV5GlobalAccounting);
        }
    };
}

test "global join algebra: execution and register windows cannot cancel across scopes" {
    var sink = ScalarSink{};
    const opposite = Q.zero().sub(Q.one());
    try std.testing.expect(Q.one().add(opposite).isZero());
    try std.testing.expectError(error.UnclosedV5NativePublicState, Algebra(Q).states(&sink, &.{ Q.one(), opposite }));
    try std.testing.expectError(error.UnclosedV5RegisterWindow, Algebra(Q).registers(&sink, 1, &.{ Q.one(), opposite }));
    try Algebra(Q).registers(&sink, 0, &.{Q.one()});
}
test "global join algebra: six table kinds and provider groups do not cancel across scopes" {
    const A = Algebra(Q);
    var sink = ScalarSink{};
    var demand: A.TableClaims = @splat(Q.zero());
    demand[0] = Q.one();
    var supply: A.TableClaims = @splat(Q.zero());
    supply[1] = Q.zero().sub(Q.one());
    const bytes = [_]struct { sum: Q }{.{ .sum = Q.zero() }};
    try std.testing.expectError(error.UnclosedV5NativeLookupGroup, A.lookupGroup(&sink, supply, &.{demand}, &bytes));
    supply[0] = Q.zero().sub(Q.one());
    supply[1] = Q.zero();
    _ = try A.lookupGroup(&sink, supply, &.{demand}, &bytes);
    // A deficit and surplus in two distinct groups remain unclosed even
    // though flattening all their claims would produce zero.
    try std.testing.expectError(error.UnclosedV5NativeLookupGroup, A.lookupGroup(&sink, @splat(Q.zero()), &.{demand}, &bytes));
}

test "global join algebra: recorded accounting preserves auxiliary sign and includes each byte request once" {
    const R = @import("../recursion/air/composition_graph_recorder.zig");
    const S = R.Scalar;
    var builder = R.Builder.init(std.testing.allocator);
    defer builder.deinit();
    var values: [11]Q = undefined;
    var symbols: [11]S = undefined;
    for (&values, &symbols, 0..) |*value, *symbol, i| {
        value.* = Q.fromBase(core.fields.m31.M31.fromCanonical(@intCast(i + 1)));
        symbol.* = (try builder.input()).value;
    }
    var input: Accounting(S) = undefined;
    inline for (std.meta.fields(Accounting(S)), 0..) |field, i| @field(input, field.name) = symbols[i];
    const byte_parts = [_]struct { sum: S }{ .{ .sum = symbols[9] }, .{ .sum = symbols[10] } };
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const expected = S.fromBase(core.fields.m31.M31.fromCanonical(50));
    try builder.constrainZero(Algebra(S).residual(input, &byte_parts).sub(expected));
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const output = try std.testing.allocator.alloc(Q, circuit.nodes.len);
    defer std.testing.allocator.free(output);
    try circuit.evaluateInto(&values, output);
    // Auxiliary clock contributes negatively; independent byte claims remain
    // distinct inputs, and omitting either one cannot satisfy the anchor.
    values[7] = values[7].add(Q.one());
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(&values, output));
    values[7] = values[7].sub(Q.one());
    values[10] = Q.zero();
    try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(&values, output));
}

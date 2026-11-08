//! Shared fixtures for function-activation LogUp adversarial tests.

const std = @import("std");
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const activation = @import("function_activation_logup.zig");
const frames = @import("function_frames.zig");
const functions = @import("functions.zig");
const ir = @import("ir.zig");
const logup = @import("../logup.zig");
const source = @import("source.zig");
const types = @import("types.zig");

const generated = source.SourceSpan.generated();

pub fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try ActivationFixture.init(allocator, true);
    defer fixture.deinit();
    var plan = try frames.compile(allocator, &fixture.arena);
    defer plan.deinit();
    var channel = Blake2sChannel{};
    const before_digest = channel.digestBytes();
    const before_draws = channel.n_draws;
    var protocol = activation.compileAndDraw(
        allocator,
        &fixture.arena,
        &plan,
        &channel,
    ) catch |err| {
        try std.testing.expectEqual(before_draws, channel.n_draws);
        const after_digest = channel.digestBytes();
        try std.testing.expectEqualSlices(u8, &before_digest, &after_digest);
        return err;
    };
    defer protocol.deinit();
    try protocol.validateAgainst(allocator, &fixture.arena, &plan);
}

pub const Witness = struct {
    batches: [4]activation.EventBatch,
    rows: [4]activation.ActivationRow,
    values: [8]M31,
};

pub const PublicWitness = struct {
    roots: [1]activation.PublicRoot,
    values: [2]M31,
};

pub fn balancedPublicWitness() PublicWitness {
    return .{
        .roots = .{.{
            .event_index = 3,
            .tuple = .{ .start = 0, .len = 2 },
            .multiplicity = 1,
        }},
        .values = .{ M31.fromCanonical(7), M31.fromCanonical(8) },
    };
}

pub fn balancedWitness() Witness {
    return .{
        .batches = .{
            .{ .event_index = 0, .origin = .trace, .rows = .{ .start = 0, .len = 1 } },
            .{ .event_index = 1, .origin = .trace, .rows = .{ .start = 1, .len = 1 } },
            .{ .event_index = 2, .origin = .trace, .rows = .{ .start = 2, .len = 1 } },
            .{ .event_index = 3, .origin = .public_statement, .rows = .{ .start = 3, .len = 1 } },
        },
        .rows = .{
            .{ .tuple = .{ .start = 0, .len = 2 }, .multiplicity = M31.one() },
            .{ .tuple = .{ .start = 2, .len = 2 }, .multiplicity = M31.one() },
            .{ .tuple = .{ .start = 4, .len = 2 }, .multiplicity = M31.one() },
            .{ .tuple = .{ .start = 6, .len = 2 }, .multiplicity = M31.one() },
        },
        .values = .{
            M31.fromCanonical(7), M31.fromCanonical(8),
            M31.fromCanonical(7), M31.fromCanonical(8),
            M31.fromCanonical(7), M31.fromCanonical(8),
            M31.fromCanonical(7), M31.fromCanonical(8),
        },
    };
}

pub const ActivationFixture = struct {
    arena: ir.Arena,
    leaf: types.FunctionId,
    wrapper: types.FunctionId,

    pub fn init(allocator: std.mem.Allocator, owned: bool) !ActivationFixture {
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const one = try arena.constantField(1, generated);

        const leaf_input = try arena.input("activation.leaf.input", .felt, generated);
        const leaf = if (owned)
            try functions.beginBody(
                &arena,
                "activation.leaf",
                &.{leaf_input},
                generated,
            )
        else
            try functions.begin(
                &arena,
                "activation.leaf",
                &.{leaf_input},
                generated,
            );
        const leaf_output = try arena.add(leaf_input, one, generated);
        const leaf_residual = try arena.sub(leaf_output, leaf_output, generated);
        _ = try arena.assertZero(
            "activation.leaf.output",
            leaf_residual,
            null,
            .semantic,
            generated,
        );
        try functions.finish(&arena, leaf, &.{leaf_output});

        const wrapper_input = try arena.input("activation.wrapper.input", .felt, generated);
        const wrapper = if (owned)
            try functions.beginBody(
                &arena,
                "activation.wrapper",
                &.{wrapper_input},
                generated,
            )
        else
            try functions.begin(
                &arena,
                "activation.wrapper",
                &.{wrapper_input},
                generated,
            );
        const call = try functions.call(
            &arena,
            leaf,
            &.{wrapper_input},
            .relation_backed,
            generated,
        );
        const output = functions.callOutputs(&arena, call).?[0];
        const expected = try arena.add(wrapper_input, one, generated);
        const residual = try arena.sub(output, expected, generated);
        _ = try arena.assertZero(
            "activation.wrapper.call_output",
            residual,
            null,
            .semantic,
            generated,
        );
        try functions.finish(&arena, wrapper, &.{output});

        const root_input = try arena.input("activation.root.input", .felt, generated);
        _ = try functions.call(
            &arena,
            wrapper,
            &.{root_input},
            .relation_backed,
            generated,
        );
        return .{ .arena = arena, .leaf = leaf, .wrapper = wrapper };
    }

    pub fn deinit(self: *ActivationFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const CollisionChannel = struct {
    mixed: u64 = 0,

    pub fn mixU64(self: *CollisionChannel, value: u64) void {
        self.mixed +%= value;
    }

    pub fn mixU32s(self: *CollisionChannel, values: []const u32) void {
        for (values) |value| self.mixed +%= value;
    }

    pub fn mixFelts(self: *CollisionChannel, values: []const QM31) void {
        self.mixed +%= values.len;
    }

    pub fn drawSecureFelts(
        self: *CollisionChannel,
        allocator: std.mem.Allocator,
        count: usize,
    ) ![]QM31 {
        if (count != 4) return error.UnexpectedDrawCount;
        const result = try allocator.alloc(QM31, count);
        const alpha0 = QM31.fromU32Unchecked(2, 3, 5, 7);
        result[0] = QM31.fromBase(M31.fromCanonical(7))
            .add(alpha0.mulM31(M31.fromCanonical(8)));
        result[1] = alpha0;
        result[2] = QM31.fromU32Unchecked(11, 13, 17, 19);
        result[3] = QM31.fromU32Unchecked(23, 29, 31, 37);
        self.mixed +%= count;
        return result;
    }
};

pub const ZeroAlphaChannel = struct {
    mixed: u64 = 0,

    pub fn mixU64(self: *ZeroAlphaChannel, value: u64) void {
        self.mixed +%= value;
    }

    pub fn mixU32s(self: *ZeroAlphaChannel, values: []const u32) void {
        for (values) |value| self.mixed +%= value;
    }

    pub fn drawSecureFelts(
        self: *ZeroAlphaChannel,
        allocator: std.mem.Allocator,
        count: usize,
    ) ![]QM31 {
        if (count != 4) return error.UnexpectedDrawCount;
        const result = try allocator.alloc(QM31, count);
        result[0] = QM31.fromU32Unchecked(2, 3, 5, 7);
        result[1] = QM31.zero();
        result[2] = QM31.fromU32Unchecked(11, 13, 17, 19);
        result[3] = QM31.fromU32Unchecked(23, 29, 31, 37);
        self.mixed +%= count;
        return result;
    }
};

pub fn sentinel() QM31 {
    return QM31.fromU32Unchecked(101, 103, 107, 109);
}

pub fn sentinelPair() logup.RowPair {
    return .{
        .n1 = sentinel(),
        .d1 = sentinel(),
        .n2 = sentinel(),
        .d2 = sentinel(),
    };
}

pub fn expectPublishedSentinels(
    pairs: []const logup.RowPair,
    event_claims: []const QM31,
    relation_claims: []const QM31,
) !void {
    for (pairs) |pair| try std.testing.expectEqualDeep(sentinelPair(), pair);
    for (event_claims) |claim| try std.testing.expect(claim.eql(sentinel()));
    for (relation_claims) |claim| try std.testing.expect(claim.eql(sentinel()));
}

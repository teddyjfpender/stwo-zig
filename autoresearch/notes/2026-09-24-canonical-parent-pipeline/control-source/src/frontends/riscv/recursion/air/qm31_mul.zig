//! Typed-AIR substrate for standalone recursion-local QM31 multiplication.
//!
//! This is the arithmetic kernel of Stark-V's universal `qm31_mul` component:
//! twelve committed M31 coordinates and four degree-two product identities.
//! Circuit schedule preprocessing and `wire` relation closure deliberately do
//! not live here yet; the inventory labels this slice as substrate rather than
//! a complete recursive-verifier component.

const std = @import("std");
const digest = @import("../../air/lang/digest.zig");
const ir = @import("../../air/lang/ir.zig");
const program = @import("../../air/lang/program.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");
const validate_mod = @import("../../air/lang/validate.zig");

pub const PHYSICAL_COLUMN_COUNT: usize = 12;
pub const CONSTRAINT_COUNT: usize = 4;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 2;
pub const SEMANTIC_DIGEST_HEX =
    "03f84e6f279603a554e836fa815d303e16cca5697be263681bd52dbc2934e29e";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid recursion QM31 multiplication semantic digest",
);

pub const COLUMN_NAMES = [PHYSICAL_COLUMN_COUNT][]const u8{
    "recursion.qm31_mul.a.0",
    "recursion.qm31_mul.a.1",
    "recursion.qm31_mul.a.2",
    "recursion.qm31_mul.a.3",
    "recursion.qm31_mul.b.0",
    "recursion.qm31_mul.b.1",
    "recursion.qm31_mul.b.2",
    "recursion.qm31_mul.b.3",
    "recursion.qm31_mul.c.0",
    "recursion.qm31_mul.c.1",
    "recursion.qm31_mul.c.2",
    "recursion.qm31_mul.c.3",
};

pub const Location = union(enum) {
    generated,
    file: struct {
        path: []const u8,
        start: source.Position,
        end: source.Position,
    },

    pub fn install(self: Location, arena: *ir.Arena) !source.SourceSpan {
        return switch (self) {
            .generated => source.SourceSpan.generated(),
            .file => |file| source.SourceSpan.init(
                try arena.addSource(file.path),
                file.start,
                file.end,
            ),
        };
    }
};

pub const Columns = struct {
    a: [4]types.ValueId,
    b: [4]types.ValueId,
    c: [4]types.ValueId,

    pub fn physical(self: Columns) [PHYSICAL_COLUMN_COUNT]types.ValueId {
        return self.a ++ self.b ++ self.c;
    }
};

pub const ValidationError = validate_mod.Error || error{
    InvalidQm31MulDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    expected: [4]types.ValueId,
    roots: [4]types.ValueId,
    constraints: [CONSTRAINT_COUNT]types.ConstraintId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const identity = try digest.computeIdentity(&self.arena);
        if (identity.format_version != digest.format_version or
            !std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != CONSTRAINT_COUNT or
            self.arena.effectsView().len != 0 or
            self.arena.hints.items.len != 0 or
            self.arena.functions.items.len != 0 or
            self.arena.calls.items.len != 0 or
            self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidQm31MulDefinition;
        }

        for (self.columns.physical(), COLUMN_NAMES, 0..) |value, name, index| {
            if (types.idIndex(value) != index)
                return error.InvalidQm31MulDefinition;
            const node = self.arena.node(value) orelse
                return error.InvalidQm31MulDefinition;
            if (!std.meta.eql(node.key.ty, types.Type.felt))
                return error.InvalidQm31MulDefinition;
            const name_id = switch (node.key.op) {
                .input => |input_name| input_name,
                else => return error.InvalidQm31MulDefinition,
            };
            const actual_name = self.arena.name(name_id) orelse
                return error.InvalidQm31MulDefinition;
            if (!std.mem.eql(u8, actual_name, name))
                return error.InvalidQm31MulDefinition;
        }

        for (self.constraints, self.roots, 0..) |constraint_id, root, index| {
            if (types.idIndex(constraint_id) != index)
                return error.InvalidQm31MulDefinition;
            const constraint = self.arena.constraint(constraint_id) orelse
                return error.InvalidQm31MulDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidQm31MulDefinition;
            }
            const operands = switch ((self.arena.node(root) orelse
                return error.InvalidQm31MulDefinition).key.op) {
                .sub => |binary| binary,
                else => return error.InvalidQm31MulDefinition,
            };
            if (operands.lhs != self.expected[index] or
                operands.rhs != self.columns.c[index])
            {
                return error.InvalidQm31MulDefinition;
            }
            var name_storage: [64]u8 = undefined;
            const expected_name = std.fmt.bufPrint(
                &name_storage,
                "recursion.qm31_mul.product.{d}",
                .{index},
            ) catch return error.InvalidQm31MulDefinition;
            const actual_name = self.arena.name(constraint.name) orelse
                return error.InvalidQm31MulDefinition;
            if (!std.mem.eql(u8, expected_name, actual_name))
                return error.InvalidQm31MulDefinition;
        }
    }
};

pub fn build(allocator: std.mem.Allocator, location: Location) !Definition {
    var result = try buildDefinition(allocator, location);
    errdefer result.deinit();
    try result.validate();
    return result;
}

fn buildDefinition(allocator: std.mem.Allocator, location: Location) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = try location.install(&arena);

    var physical: [PHYSICAL_COLUMN_COUNT]types.ValueId = undefined;
    for (&physical, COLUMN_NAMES) |*value, name| {
        value.* = try arena.input(name, .felt, span);
    }
    const columns = Columns{
        .a = physical[0..4].*,
        .b = physical[4..8].*,
        .c = physical[8..12].*,
    };
    const expected = try productCoordinates(&arena, columns.a, columns.b, span);
    var roots: [CONSTRAINT_COUNT]types.ValueId = undefined;
    var constraints: [CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&roots, &constraints, expected, columns.c, 0..) |
        *root,
        *constraint,
        expected_coordinate,
        committed_coordinate,
        coordinate,
    | {
        root.* = try arena.sub(expected_coordinate, committed_coordinate, span);
        var name_storage: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(
            &name_storage,
            "recursion.qm31_mul.product.{d}",
            .{coordinate},
        );
        constraint.* = try arena.assertZero(
            name,
            root.*,
            null,
            program.ConstraintCategory.semantic,
            span,
        );
    }
    return .{
        .arena = arena,
        .columns = columns,
        .expected = expected,
        .roots = roots,
        .constraints = constraints,
    };
}

/// Canonical `(A + Bu)(C + Du)` expansion for `u^2 = 2 + i`.
///
/// This is the only handwritten limb identity in this component. The witness
/// path invokes the optimized canonical `QM31.mul` implementation and the test
/// gate proves it agrees with these typed roots over boundary and random data.
pub fn productCoordinates(
    arena: *ir.Arena,
    a: [4]types.ValueId,
    b: [4]types.ValueId,
    span: source.SourceSpan,
) ![4]types.ValueId {
    const ac_real = try arena.sub(
        try arena.mul(a[0], b[0], span),
        try arena.mul(a[1], b[1], span),
        span,
    );
    const ac_imag = try arena.add(
        try arena.mul(a[0], b[1], span),
        try arena.mul(a[1], b[0], span),
        span,
    );
    const bd_real = try arena.sub(
        try arena.mul(a[2], b[2], span),
        try arena.mul(a[3], b[3], span),
        span,
    );
    const bd_imag = try arena.add(
        try arena.mul(a[2], b[3], span),
        try arena.mul(a[3], b[2], span),
        span,
    );
    const first_real = try arena.add(
        ac_real,
        try arena.sub(try arena.add(bd_real, bd_real, span), bd_imag, span),
        span,
    );
    const first_imag = try arena.add(
        ac_imag,
        try arena.add(bd_real, try arena.add(bd_imag, bd_imag, span), span),
        span,
    );
    const second_real = try arena.sub(
        try arena.add(
            try arena.sub(
                try arena.mul(a[0], b[2], span),
                try arena.mul(a[1], b[3], span),
                span,
            ),
            try arena.mul(a[2], b[0], span),
            span,
        ),
        try arena.mul(a[3], b[1], span),
        span,
    );
    const second_imag = try arena.add(
        try arena.add(
            try arena.mul(a[0], b[3], span),
            try arena.mul(a[1], b[2], span),
            span,
        ),
        try arena.add(
            try arena.mul(a[2], b[1], span),
            try arena.mul(a[3], b[0], span),
            span,
        ),
        span,
    );
    return .{ first_real, first_imag, second_real, second_imag };
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

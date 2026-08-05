//! Canonical scalar expression nodes.
//!
//! Structural identity excludes source locations. The first construction owns
//! the primary diagnostic span; rebuilding the same expression from another
//! site returns the same value ID.

const std = @import("std");
const program = @import("program.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const Constant = union(enum) {
    field: u32,
    unsigned: u32,
};

pub const Binary = struct {
    lhs: types.ValueId,
    rhs: types.ValueId,
};

pub const Selection = struct {
    selector: types.ValueId,
    when_true: types.ValueId,
    when_false: types.ValueId,
};

pub const Op = union(enum) {
    constant: Constant,
    input: types.NameId,
    add: Binary,
    sub: Binary,
    mul: Binary,
    neg: types.ValueId,
    select: Selection,
    hint_output: program.HintOutput,
    call_output: program.CallOutput,
};

pub const Key = struct {
    ty: types.Type,
    op: Op,
};

pub const Node = struct {
    key: Key,
    primary_source: source.SourceSpan,
};

/// Hashing is explicit so padding bytes, pointers, and rendered source text can
/// never become structural identity.
pub const KeyContext = struct {
    pub fn hash(_: KeyContext, key: Key) u64 {
        var state: u64 = 0xcbf29ce484222325;
        hashType(&state, key.ty);
        hashOp(&state, key.op);
        return state;
    }

    pub fn eql(_: KeyContext, lhs: Key, rhs: Key) bool {
        return std.meta.eql(lhs, rhs);
    }
};

pub const Map = std.HashMap(
    Key,
    types.ValueId,
    KeyContext,
    std.hash_map.default_max_load_percentage,
);

fn mix(state: *u64, value: u64) void {
    state.* ^= value;
    state.* *%= 0x100000001b3;
}

fn hashType(state: *u64, ty: types.Type) void {
    mix(state, @intFromEnum(std.meta.activeTag(ty)));
    switch (ty) {
        .bounded_uint => |bounded| {
            mix(state, bounded.bits);
            mix(state, @intFromEnum(std.meta.activeTag(bounded.representation)));
            switch (bounded.representation) {
                .canonical_field => {},
                .little_endian_limbs => |layout| {
                    mix(state, layout.limb_bits);
                    mix(state, layout.limb_count);
                },
            }
        },
        .array => |array| {
            mix(state, @intFromEnum(array.element));
            mix(state, array.len);
        },
        else => {},
    }
}

fn hashOp(state: *u64, op: Op) void {
    mix(state, @intFromEnum(std.meta.activeTag(op)));
    switch (op) {
        .constant => |constant| {
            mix(state, @intFromEnum(std.meta.activeTag(constant)));
            switch (constant) {
                .field => |value| mix(state, value),
                .unsigned => |value| mix(state, value),
            }
        },
        .input => |name| mix(state, @intFromEnum(name)),
        .add, .sub, .mul => |binary| {
            mix(state, @intFromEnum(binary.lhs));
            mix(state, @intFromEnum(binary.rhs));
        },
        .neg => |value| mix(state, @intFromEnum(value)),
        .select => |selection| {
            mix(state, @intFromEnum(selection.selector));
            mix(state, @intFromEnum(selection.when_true));
            mix(state, @intFromEnum(selection.when_false));
        },
        .hint_output => |output| {
            mix(state, @intFromEnum(output.hint));
            mix(state, output.index);
        },
        .call_output => |output| {
            mix(state, @intFromEnum(output.call));
            mix(state, output.index);
        },
    }
}

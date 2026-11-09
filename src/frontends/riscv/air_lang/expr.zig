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

pub const RegisterAddress = struct {
    index: types.ValueId,
};

pub const AlignedWordAddress = struct {
    word_index: types.ValueId,
};

pub const AccessClock = struct {
    instruction_clock: types.ValueId,
    phase: types.AccessPhase,
};

pub const StrictClockGap = struct {
    current_clock: types.ValueId,
    previous_clock: types.ValueId,
    active: types.ValueId,
    phase: types.AccessPhase,
};

pub const InstructionNextPc = struct {
    current: types.ValueId,
};

pub const InstructionNextClock = struct {
    current: types.ValueId,
};

/// Closed machine refinements whose result type and polynomial meaning are
/// fixed by the variant. This is intentionally not a general cast or affine
/// expression escape hatch.
pub const MachineDerivedTag = enum(u8) {
    register_address = 0,
    access_clock = 1,
    strict_clock_gap = 2,
    aligned_word_address = 3,
    instruction_next_pc = 4,
    instruction_next_clock = 5,
};

pub const MachineDerived = union(MachineDerivedTag) {
    register_address: RegisterAddress,
    access_clock: AccessClock,
    strict_clock_gap: StrictClockGap,
    aligned_word_address: AlignedWordAddress,
    instruction_next_pc: InstructionNextPc,
    instruction_next_clock: InstructionNextClock,
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
    machine_derived: MachineDerived,
};

pub const Key = struct {
    ty: types.Type,
    op: Op,
};

pub const Node = struct {
    key: Key,
    primary_source: source.SourceSpan,
};

/// Trace-order offsets supported by the append-only physical expression IR.
/// The PCS layer remains cyclic; a window authority must separately bind the
/// row-zero correction for every admitted previous-row read.
pub const RowOffset = enum(i8) {
    previous = -1,
    current = 0,
};

pub const WindowBinary = struct {
    lhs: types.WindowValueId,
    rhs: types.WindowValueId,
};

/// Scalar expressions over already-authenticated committed-column samples.
/// A shifted read names a `ShiftedColumnId` from a versioned row-window plan;
/// the plan digest, owner, column type, offset, and boundary are validated by
/// the physical compiler before this graph may be evaluated.
pub const WindowOp = union(enum) {
    constant: u32,
    shifted_column: types.ShiftedColumnId,
    add: WindowBinary,
    sub: WindowBinary,
    mul: WindowBinary,
    neg: types.WindowValueId,
};

pub const WindowKey = struct {
    op: WindowOp,
};

pub const WindowNode = struct {
    key: WindowKey,
    primary_source: source.SourceSpan,
};

pub const WindowKeyContext = struct {
    pub fn hash(_: WindowKeyContext, key: WindowKey) u64 {
        var state: u64 = 0xcbf29ce484222325;
        mix(&state, @intFromEnum(std.meta.activeTag(key.op)));
        switch (key.op) {
            .constant => |value| mix(&state, value),
            .shifted_column => |column| mix(&state, @intFromEnum(column)),
            .add, .sub, .mul => |binary| {
                mix(&state, @intFromEnum(binary.lhs));
                mix(&state, @intFromEnum(binary.rhs));
            },
            .neg => |value| mix(&state, @intFromEnum(value)),
        }
        return state;
    }

    pub fn eql(_: WindowKeyContext, lhs: WindowKey, rhs: WindowKey) bool {
        return std.meta.eql(lhs, rhs);
    }
};

pub const WindowMap = std.HashMap(
    WindowKey,
    types.WindowValueId,
    WindowKeyContext,
    std.hash_map.default_max_load_percentage,
);

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
        .machine_derived => |derived| {
            mix(state, @intFromEnum(std.meta.activeTag(derived)));
            switch (derived) {
                .register_address => |address| {
                    mix(state, @intFromEnum(address.index));
                },
                .aligned_word_address => |address| {
                    mix(state, @intFromEnum(address.word_index));
                },
                .access_clock => |clock| {
                    mix(state, @intFromEnum(clock.instruction_clock));
                    mix(state, @intFromEnum(clock.phase));
                },
                .strict_clock_gap => |gap| {
                    mix(state, @intFromEnum(gap.current_clock));
                    mix(state, @intFromEnum(gap.previous_clock));
                    mix(state, @intFromEnum(gap.active));
                    mix(state, @intFromEnum(gap.phase));
                },
                .instruction_next_pc => |next| {
                    mix(state, @intFromEnum(next.current));
                },
                .instruction_next_clock => |next| {
                    mix(state, @intFromEnum(next.current));
                },
            }
        },
    }
}

//! Whole-program records stored beside the canonical expression DAG.

const std = @import("std");
const source = @import("source.zig");
const types = @import("types.zig");

pub const RangeError = error{ReferenceRangeOverflow};

/// A canonical range into one of the program's typed reference pools.
pub const RefRange = struct {
    start: u32,
    len: u32,

    pub fn init(start: usize, len: usize) RangeError!RefRange {
        return .{
            .start = std.math.cast(u32, start) orelse
                return error.ReferenceRangeOverflow,
            .len = std.math.cast(u32, len) orelse
                return error.ReferenceRangeOverflow,
        };
    }

    pub fn slice(
        self: RefRange,
        values: []const types.ValueId,
    ) ?[]const types.ValueId {
        const start: usize = self.start;
        const len: usize = self.len;
        const end = std.math.add(usize, start, len) catch return null;
        if (end > values.len) return null;
        return values[start..end];
    }
};

pub const ConstraintCategory = enum {
    semantic,
    materialization,
    type_range,
    hint_binding,
    boundary,
    transition,
    relation_transition,
};

pub const Constraint = struct {
    name: types.NameId,
    root: types.ValueId,
    gate: ?types.ValueId,
    category: ConstraintCategory,
    source_span: source.SourceSpan,
};

pub const HintOutput = struct {
    hint: types.HintId,
    index: u16,
};

pub const CallOutput = struct {
    call: types.CallId,
    index: u16,
};

pub const Hint = struct {
    recipe: types.NameId,
    inputs: RefRange,
    outputs: RefRange,
    source_span: source.SourceSpan,
};

pub const EffectKind = enum {
    program_fetch,
    register_read,
    register_write,
    memory_read,
    memory_write,
    range_request,
    state_consume,
    state_produce,
    component_call,
    public_consume,
    public_produce,
};

pub const Effect = struct {
    kind: EffectKind,
    values: RefRange,
    liveness: ?types.ValueId,
    access_ordinal: ?u8,
    source_span: source.SourceSpan,
};

pub const Function = struct {
    name: types.NameId,
    inputs: RefRange,
    outputs: RefRange,
    source_span: source.SourceSpan,
    complete: bool,
};

pub const CallStrategy = enum {
    inline_expansion,
    relation_backed,
};

pub const Call = struct {
    caller: ?types.FunctionId,
    callee: types.FunctionId,
    strategy: CallStrategy,
    arguments: RefRange,
    outputs: RefRange,
    source_span: source.SourceSpan,
};

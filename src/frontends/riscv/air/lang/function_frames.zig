//! Compiler-owned Cairo-style function frames and activation relations.
//!
//! The logical AIR arena interns one global expression DAG.  That is useful
//! for authoring, but it is not a frame boundary: without this pass a function
//! output can accidentally depend on an undeclared input and a
//! `relation_backed` call is only descriptive metadata.  This cold compiler
//! pass derives a canonical per-function frame and the exact LogUp activation
//! events needed by later table lowering.
//!
//! A frame reads only its declared arguments.  Every non-input/non-constant
//! value in its transitive closure is one write-once local, retained in
//! topological value order.  Call and hint outputs are committed locals.  A
//! hint invocation may belong to only one frame.  Relation-backed functions
//! must be deterministic in their returned values: an untrusted hint may not
//! flow into the activation tuple, while calls to already-proven-pure callees
//! remain admissible.
//!
//! Activation relations are deliberately function-local, not padded into the
//! fixed zkVM relation registry.  Their challenge order is function declaration
//! order and their ABI digest binds the current semantic program identity,
//! stable function name, and exact argument/return types.  A later proof
//! adapter must draw one challenge per required relation and lower the events;
//! this module never claims that merely constructing the plan changes the live
//! protocol.

const std = @import("std");
const compile_impl = @import("function_frames_compile.zig");
const digest = @import("digest.zig");
const expr = @import("expr.zig");
const functions = @import("functions.zig");
const hints = @import("hints.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const types = @import("types.zig");
const validate_program = @import("validate.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const POLICY_VERSION: u16 = 1;
pub const BODY_OWNERSHIP_VERSION: u16 = 1;
pub const MAX_ACTIVATION_ARITY: usize = 64;
pub const DIGEST_DOMAIN = "stwo-zig/typed-air/function-frame-plan/v1\x00";
pub const RELATION_DOMAIN = "stwo-zig/typed-air/function-activation-abi/v1\x00";
pub const Digest = [32]u8;

pub const FunctionRelationId = enum(u32) { _ };

pub const Range = struct {
    start: u32,
    len: u32,

    pub fn init(start: usize, len: usize) Error!Range {
        return .{
            .start = std.math.cast(u32, start) orelse return error.CountOverflow,
            .len = std.math.cast(u32, len) orelse return error.CountOverflow,
        };
    }

    pub fn slice(self: Range, values: []const types.ValueId) ?[]const types.ValueId {
        const start: usize = self.start;
        const len: usize = self.len;
        const end = std.math.add(usize, start, len) catch return null;
        if (end > values.len) return null;
        return values[start..end];
    }
};

/// One independently lowered AIR table.  Arguments occupy the conceptual
/// negative frame window and `writes` occupy `[fp, fp + frame_size)`.
pub const Frame = struct {
    function: types.FunctionId,
    relation: FunctionRelationId,
    argument_count: u32,
    return_count: u32,
    writes: Range,
    activation_tuple: Range,
    body_constraints: Range,
    body_effects: Range,
    body_hints: Range,
    body_calls: Range,
    deterministic: bool,
    relation_required: bool,
    relation_digest: Digest,
};

/// Canonical call-site projection.  `tuple` is arguments followed by the
/// caller-owned return cells.
pub const CallBinding = struct {
    call: types.CallId,
    caller: ?types.FunctionId,
    callee: types.FunctionId,
    strategy: program.CallStrategy,
    argument_count: u32,
    return_count: u32,
    tuple: Range,
};

pub const ActivationKind = enum(u8) {
    /// A row of the callee table consumes its `(args..., rets...)` tuple.
    callee_consume = 0,
    /// An enabled caller row emits the callee tuple.
    caller_emit = 1,
    /// The verifier/public statement emits one entry activation.
    public_emit = 2,
};

pub const ActivationRole = enum(u8) {
    consume = 0,
    emit = 1,
};

pub const WeightSource = enum(u8) {
    callee_enabler = 0,
    caller_enabler = 1,
    public_multiplicity = 2,
};

pub const ActivationEvent = struct {
    kind: ActivationKind,
    role: ActivationRole,
    weight: WeightSource,
    relation: FunctionRelationId,
    callee: types.FunctionId,
    owner: ?types.FunctionId,
    call: ?types.CallId,
    tuple: Range,
};

pub const Error = std.mem.Allocator.Error || validate_program.Error || error{
    ActivationArityTooLarge,
    CountOverflow,
    CrossFrameHint,
    DigestMismatch,
    EmptyActivationTuple,
    FrameReadsUndeclaredInput,
    InvalidActivationEvent,
    InvalidCallBinding,
    InvalidFrame,
    InvalidFrameRange,
    InvalidFormat,
    InvalidRelationAbi,
    NonDeterministicActivation,
    NonFieldActivationValue,
};

pub const OwnedPlan = struct {
    allocator: std.mem.Allocator,
    format_version: u16,
    policy_version: u16,
    /// Zero preserves the frozen v1 projection; one authenticates the four
    /// explicit per-function proof-record pools below.
    body_ownership_version: u16,
    semantic_identity_format_version: u16,
    semantic_digest: Digest,
    frames: []Frame,
    frame_values: []types.ValueId,
    constraint_ids: []types.ConstraintId,
    effect_ids: []types.EffectId,
    hint_ids: []types.HintId,
    call_ids: []types.CallId,
    calls: []CallBinding,
    tuple_values: []types.ValueId,
    events: []ActivationEvent,
    plan_digest: Digest,

    pub fn deinit(self: *OwnedPlan) void {
        self.allocator.free(self.events);
        self.allocator.free(self.tuple_values);
        self.allocator.free(self.calls);
        self.allocator.free(self.call_ids);
        self.allocator.free(self.hint_ids);
        self.allocator.free(self.effect_ids);
        self.allocator.free(self.constraint_ids);
        self.allocator.free(self.frame_values);
        self.allocator.free(self.frames);
        self.* = undefined;
    }

    pub fn frame(self: *const OwnedPlan, id: types.FunctionId) ?*const Frame {
        const index = types.idIndex(id);
        if (index >= self.frames.len) return null;
        const result = &self.frames[index];
        if (result.function != id) return null;
        return result;
    }

    pub fn call(self: *const OwnedPlan, id: types.CallId) ?*const CallBinding {
        const index = types.idIndex(id);
        if (index >= self.calls.len) return null;
        const result = &self.calls[index];
        if (result.call != id) return null;
        return result;
    }

    pub fn writes(self: *const OwnedPlan, item: Frame) ?[]const types.ValueId {
        return item.writes.slice(self.frame_values);
    }

    pub fn tuple(self: *const OwnedPlan, range: Range) ?[]const types.ValueId {
        return range.slice(self.tuple_values);
    }

    pub fn bodyConstraints(
        self: *const OwnedPlan,
        item: Frame,
    ) ?[]const types.ConstraintId {
        return sliceRange(types.ConstraintId, item.body_constraints, self.constraint_ids);
    }

    pub fn bodyEffects(
        self: *const OwnedPlan,
        item: Frame,
    ) ?[]const types.EffectId {
        return sliceRange(types.EffectId, item.body_effects, self.effect_ids);
    }

    pub fn bodyHints(
        self: *const OwnedPlan,
        item: Frame,
    ) ?[]const types.HintId {
        return sliceRange(types.HintId, item.body_hints, self.hint_ids);
    }

    pub fn bodyCalls(
        self: *const OwnedPlan,
        item: Frame,
    ) ?[]const types.CallId {
        return sliceRange(types.CallId, item.body_calls, self.call_ids);
    }

    /// Binary search over the canonical topological write list.
    pub fn ownsWrite(
        self: *const OwnedPlan,
        function: types.FunctionId,
        value: types.ValueId,
    ) bool {
        const item = self.frame(function) orelse return false;
        const values = self.writes(item.*) orelse return false;
        var low: usize = 0;
        var high: usize = values.len;
        const wanted = types.idIndex(value);
        while (low < high) {
            const middle = low + (high - low) / 2;
            const actual = types.idIndex(values[middle]);
            if (actual < wanted) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        return low < values.len and values[low] == value;
    }

    /// Allocation-free validation of the owned canonical representation.
    pub fn validate(self: *const OwnedPlan) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.policy_version != POLICY_VERSION or
            self.body_ownership_version > BODY_OWNERSHIP_VERSION or
            self.semantic_identity_format_version == 0)
        {
            return error.InvalidFormat;
        }
        if ((self.body_ownership_version == 0 and
            self.semantic_identity_format_version == digest.function_body_format_version) or
            (self.body_ownership_version == BODY_OWNERSHIP_VERSION and
                self.semantic_identity_format_version != digest.function_body_format_version))
        {
            return error.InvalidFormat;
        }

        var write_cursor: usize = 0;
        var tuple_cursor: usize = 0;
        var constraint_cursor: usize = 0;
        var effect_cursor: usize = 0;
        var hint_cursor: usize = 0;
        var call_id_cursor: usize = 0;
        for (self.frames, 0..) |item, index| {
            if (types.idIndex(item.function) != index or
                @intFromEnum(item.relation) != index or
                item.writes.start != write_cursor or
                item.activation_tuple.start != tuple_cursor or
                item.body_constraints.start != constraint_cursor or
                item.body_effects.start != effect_cursor or
                item.body_hints.start != hint_cursor or
                item.body_calls.start != call_id_cursor)
            {
                return error.InvalidFrame;
            }
            const writes_slice = item.writes.slice(self.frame_values) orelse
                return error.InvalidFrameRange;
            const tuple_slice = item.activation_tuple.slice(self.tuple_values) orelse
                return error.InvalidFrameRange;
            const constraint_slice = sliceRange(
                types.ConstraintId,
                item.body_constraints,
                self.constraint_ids,
            ) orelse return error.InvalidFrameRange;
            const effect_slice = sliceRange(
                types.EffectId,
                item.body_effects,
                self.effect_ids,
            ) orelse return error.InvalidFrameRange;
            const hint_slice = sliceRange(
                types.HintId,
                item.body_hints,
                self.hint_ids,
            ) orelse return error.InvalidFrameRange;
            const call_id_slice = sliceRange(
                types.CallId,
                item.body_calls,
                self.call_ids,
            ) orelse return error.InvalidFrameRange;
            if (self.body_ownership_version == 0 and
                (constraint_slice.len != 0 or effect_slice.len != 0 or
                    hint_slice.len != 0 or call_id_slice.len != 0))
            {
                return error.InvalidFrame;
            }
            try validateStrictlyIncreasing(types.ConstraintId, constraint_slice);
            try validateStrictlyIncreasing(types.EffectId, effect_slice);
            try validateStrictlyIncreasing(types.HintId, hint_slice);
            try validateStrictlyIncreasing(types.CallId, call_id_slice);
            for (call_id_slice) |call_id| {
                const call_index = types.idIndex(call_id);
                if (call_index >= self.calls.len or
                    self.calls[call_index].caller != item.function)
                {
                    return error.InvalidFrame;
                }
            }
            const expected_arity = std.math.add(
                usize,
                item.argument_count,
                item.return_count,
            ) catch return error.CountOverflow;
            if (tuple_slice.len != expected_arity or
                (item.relation_required and
                    (expected_arity == 0 or expected_arity > MAX_ACTIVATION_ARITY or
                        !item.deterministic)) or
                digestIsZero(item.relation_digest))
            {
                return error.InvalidRelationAbi;
            }
            var previous: ?usize = null;
            for (writes_slice) |value| {
                const current = types.idIndex(value);
                if (previous != null and current <= previous.?)
                    return error.InvalidFrame;
                previous = current;
            }
            write_cursor = std.math.add(usize, write_cursor, writes_slice.len) catch
                return error.CountOverflow;
            tuple_cursor = std.math.add(usize, tuple_cursor, tuple_slice.len) catch
                return error.CountOverflow;
            constraint_cursor += constraint_slice.len;
            effect_cursor += effect_slice.len;
            hint_cursor += hint_slice.len;
            call_id_cursor += call_id_slice.len;
        }
        if (write_cursor != self.frame_values.len or
            constraint_cursor != self.constraint_ids.len or
            effect_cursor != self.effect_ids.len or
            hint_cursor != self.hint_ids.len or
            call_id_cursor != self.call_ids.len)
            return error.InvalidFrameRange;
        try validateStrictlyIncreasing(types.ConstraintId, self.constraint_ids);
        try validateStrictlyIncreasing(types.EffectId, self.effect_ids);
        try validateStrictlyIncreasing(types.HintId, self.hint_ids);
        try validateStrictlyIncreasing(types.CallId, self.call_ids);

        for (self.calls, 0..) |item, index| {
            if (types.idIndex(item.call) != index or
                types.idIndex(item.callee) >= self.frames.len or
                item.tuple.start != tuple_cursor)
            {
                return error.InvalidCallBinding;
            }
            if (item.caller) |caller| {
                if (types.idIndex(caller) >= self.frames.len or
                    types.idIndex(item.callee) >= types.idIndex(caller))
                {
                    return error.InvalidCallBinding;
                }
            }
            const tuple_slice = item.tuple.slice(self.tuple_values) orelse
                return error.InvalidFrameRange;
            const expected_arity = std.math.add(
                usize,
                item.argument_count,
                item.return_count,
            ) catch return error.CountOverflow;
            if (tuple_slice.len != expected_arity)
                return error.InvalidCallBinding;
            if (item.strategy == .relation_backed) {
                const target = self.frames[types.idIndex(item.callee)];
                if (!target.relation_required or !target.deterministic or
                    expected_arity == 0 or expected_arity > MAX_ACTIVATION_ARITY)
                {
                    return error.InvalidRelationAbi;
                }
            }
            tuple_cursor = std.math.add(usize, tuple_cursor, tuple_slice.len) catch
                return error.CountOverflow;
        }
        if (tuple_cursor != self.tuple_values.len)
            return error.InvalidFrameRange;

        var event_cursor: usize = 0;
        for (self.frames) |item| {
            if (!item.relation_required) continue;
            if (event_cursor >= self.events.len or
                !std.meta.eql(self.events[event_cursor], ActivationEvent{
                    .kind = .callee_consume,
                    .role = .consume,
                    .weight = .callee_enabler,
                    .relation = item.relation,
                    .callee = item.function,
                    .owner = item.function,
                    .call = null,
                    .tuple = item.activation_tuple,
                }))
            {
                return error.InvalidActivationEvent;
            }
            event_cursor += 1;
        }
        for (self.calls) |item| {
            if (item.strategy != .relation_backed) continue;
            const target = self.frames[types.idIndex(item.callee)];
            const expected = if (item.caller) |caller| ActivationEvent{
                .kind = .caller_emit,
                .role = .emit,
                .weight = .caller_enabler,
                .relation = target.relation,
                .callee = item.callee,
                .owner = caller,
                .call = item.call,
                .tuple = item.tuple,
            } else ActivationEvent{
                .kind = .public_emit,
                .role = .emit,
                .weight = .public_multiplicity,
                .relation = target.relation,
                .callee = item.callee,
                .owner = null,
                .call = item.call,
                .tuple = item.tuple,
            };
            if (event_cursor >= self.events.len or
                !std.meta.eql(self.events[event_cursor], expected))
            {
                return error.InvalidActivationEvent;
            }
            event_cursor += 1;
        }
        if (event_cursor != self.events.len)
            return error.InvalidActivationEvent;

        const actual_digest = hashPlan(self);
        if (!std.mem.eql(u8, &actual_digest, &self.plan_digest))
            return error.DigestMismatch;
    }

    /// Cold, strong authentication against the complete logical authority.
    pub fn validateAgainst(
        self: *const OwnedPlan,
        allocator: std.mem.Allocator,
        arena: *const ir.Arena,
    ) Error!void {
        try self.validate();
        var expected = try compile(allocator, arena);
        defer expected.deinit();
        if (!semanticEqual(self, &expected)) return error.DigestMismatch;
    }
};

/// Compile a validated logical program into canonical frames and activation
/// events.  This is a cold operation; all returned hot-path views are owned,
/// pointer-free records and `OwnedPlan.validate` allocates nothing.
pub fn compile(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error!OwnedPlan {
    return compile_impl.compile(@This(), allocator, arena);
}
fn validateActivationAbi(arena: *const ir.Arena, frame: *const Frame) Error!void {
    if (!frame.deterministic) return error.NonDeterministicActivation;
    const tuple = frame.activation_tuple;
    const arity: usize = tuple.len;
    if (arity == 0) return error.EmptyActivationTuple;
    if (arity > MAX_ACTIVATION_ARITY)
        return error.ActivationArityTooLarge;
    const function_inputs = functions.inputs(arena, frame.function) orelse
        return error.InvalidFrame;
    const function_outputs = functions.outputs(arena, frame.function) orelse
        return error.InvalidFrame;
    for (function_inputs) |value| try requireFieldScalar(arena, value);
    for (function_outputs) |value| try requireFieldScalar(arena, value);
}

fn requireFieldScalar(arena: *const ir.Arena, value: types.ValueId) Error!void {
    const node = arena.node(value) orelse return error.InvalidFrame;
    if (!node.key.ty.isFieldScalar()) return error.NonFieldActivationValue;
}

fn mark(reachable: []bool, value: types.ValueId) Error!void {
    const index = types.idIndex(value);
    if (index >= reachable.len) return error.InvalidFrame;
    reachable[index] = true;
}

fn itemRangeEnd(range: program.ItemRange) usize {
    return @as(usize, range.start) + @as(usize, range.len);
}

fn sliceRange(
    comptime T: type,
    range: Range,
    values: []const T,
) ?[]const T {
    const start: usize = range.start;
    const len: usize = range.len;
    const end = std.math.add(usize, start, len) catch return null;
    if (end > values.len) return null;
    return values[start..end];
}

fn validateStrictlyIncreasing(comptime T: type, values: []const T) Error!void {
    var previous: ?usize = null;
    for (values) |value| {
        const current = types.idIndex(value);
        if (previous != null and current <= previous.?) return error.InvalidFrame;
        previous = current;
    }
}

fn containsValue(values: []const types.ValueId, wanted: types.ValueId) bool {
    return std.mem.indexOfScalar(types.ValueId, values, wanted) != null;
}

fn rejectDuplicateValues(values: []const types.ValueId) Error!void {
    for (values, 0..) |value, index| {
        if (std.mem.indexOfScalar(types.ValueId, values[0..index], value) != null)
            return error.InvalidFrame;
    }
}

fn idFromIndex(comptime Id: type, index: usize) Id {
    return types.idFromIndex(Id, index) catch unreachable;
}

fn relationDigest(
    arena: *const ir.Arena,
    semantic_identity: digest.Identity,
    function_id: types.FunctionId,
) Digest {
    var hash = Sha256.init(.{});
    hash.update(RELATION_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, semantic_identity.format_version);
    hash.update(&semantic_identity.bytes);
    hashInt(&hash, u32, @intFromEnum(function_id));
    const declaration = functions.get(arena, function_id).?;
    const name = arena.name(declaration.name).?;
    hashBytes(&hash, name);
    const input_values = functions.inputs(arena, function_id).?;
    const output_values = functions.outputs(arena, function_id).?;
    hashInt(&hash, u32, @intCast(input_values.len));
    for (input_values) |value| hashType(&hash, arena.node(value).?.key.ty);
    hashInt(&hash, u32, @intCast(output_values.len));
    for (output_values) |value| hashType(&hash, arena.node(value).?.key.ty);
    return hash.finalResult();
}

fn hashPlan(plan: *const OwnedPlan) Digest {
    var hash = Sha256.init(.{});
    hash.update(DIGEST_DOMAIN);
    hashInt(&hash, u16, plan.format_version);
    hashInt(&hash, u16, plan.policy_version);
    hashInt(&hash, u16, plan.semantic_identity_format_version);
    hash.update(&plan.semantic_digest);
    hashInt(&hash, u32, @intCast(plan.frames.len));
    hashInt(&hash, u32, @intCast(plan.frame_values.len));
    hashInt(&hash, u32, @intCast(plan.calls.len));
    hashInt(&hash, u32, @intCast(plan.tuple_values.len));
    hashInt(&hash, u32, @intCast(plan.events.len));
    for (plan.frames) |item| {
        hashInt(&hash, u32, @intFromEnum(item.function));
        hashInt(&hash, u32, @intFromEnum(item.relation));
        hashInt(&hash, u32, item.argument_count);
        hashInt(&hash, u32, item.return_count);
        hashRange(&hash, item.writes);
        hashRange(&hash, item.activation_tuple);
        hashInt(&hash, u8, @intFromBool(item.deterministic));
        hashInt(&hash, u8, @intFromBool(item.relation_required));
        hash.update(&item.relation_digest);
    }
    for (plan.frame_values) |value| hashInt(&hash, u32, @intFromEnum(value));
    for (plan.calls) |item| {
        hashInt(&hash, u32, @intFromEnum(item.call));
        hashOptionalFunction(&hash, item.caller);
        hashInt(&hash, u32, @intFromEnum(item.callee));
        hashInt(&hash, u8, callStrategyTag(item.strategy));
        hashInt(&hash, u32, item.argument_count);
        hashInt(&hash, u32, item.return_count);
        hashRange(&hash, item.tuple);
    }
    for (plan.tuple_values) |value| hashInt(&hash, u32, @intFromEnum(value));
    for (plan.events) |item| {
        hashInt(&hash, u8, @intFromEnum(item.kind));
        hashInt(&hash, u8, @intFromEnum(item.role));
        hashInt(&hash, u8, @intFromEnum(item.weight));
        hashInt(&hash, u32, @intFromEnum(item.relation));
        hashInt(&hash, u32, @intFromEnum(item.callee));
        hashOptionalFunction(&hash, item.owner);
        hashOptionalCall(&hash, item.call);
        hashRange(&hash, item.tuple);
    }
    if (plan.body_ownership_version != 0) {
        hashInt(&hash, u16, plan.body_ownership_version);
        hashInt(&hash, u32, @intCast(plan.constraint_ids.len));
        hashInt(&hash, u32, @intCast(plan.effect_ids.len));
        hashInt(&hash, u32, @intCast(plan.hint_ids.len));
        hashInt(&hash, u32, @intCast(plan.call_ids.len));
        for (plan.frames) |item| {
            hashRange(&hash, item.body_constraints);
            hashRange(&hash, item.body_effects);
            hashRange(&hash, item.body_hints);
            hashRange(&hash, item.body_calls);
        }
        for (plan.constraint_ids) |id| hashInt(&hash, u32, @intFromEnum(id));
        for (plan.effect_ids) |id| hashInt(&hash, u32, @intFromEnum(id));
        for (plan.hint_ids) |id| hashInt(&hash, u32, @intFromEnum(id));
        for (plan.call_ids) |id| hashInt(&hash, u32, @intFromEnum(id));
    }
    return hash.finalResult();
}

fn semanticEqual(lhs: *const OwnedPlan, rhs: *const OwnedPlan) bool {
    return lhs.format_version == rhs.format_version and
        lhs.policy_version == rhs.policy_version and
        lhs.body_ownership_version == rhs.body_ownership_version and
        lhs.semantic_identity_format_version == rhs.semantic_identity_format_version and
        std.mem.eql(u8, &lhs.semantic_digest, &rhs.semantic_digest) and
        slicesEql(Frame, lhs.frames, rhs.frames) and
        std.mem.eql(types.ValueId, lhs.frame_values, rhs.frame_values) and
        std.mem.eql(types.ConstraintId, lhs.constraint_ids, rhs.constraint_ids) and
        std.mem.eql(types.EffectId, lhs.effect_ids, rhs.effect_ids) and
        std.mem.eql(types.HintId, lhs.hint_ids, rhs.hint_ids) and
        std.mem.eql(types.CallId, lhs.call_ids, rhs.call_ids) and
        slicesEql(CallBinding, lhs.calls, rhs.calls) and
        std.mem.eql(types.ValueId, lhs.tuple_values, rhs.tuple_values) and
        slicesEql(ActivationEvent, lhs.events, rhs.events) and
        std.mem.eql(u8, &lhs.plan_digest, &rhs.plan_digest);
}

fn slicesEql(comptime T: type, lhs: []const T, rhs: []const T) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |left, right| {
        if (!std.meta.eql(left, right)) return false;
    }
    return true;
}

fn hashRange(hash: *Sha256, range: Range) void {
    hashInt(hash, u32, range.start);
    hashInt(hash, u32, range.len);
}

fn hashOptionalFunction(hash: *Sha256, value: ?types.FunctionId) void {
    if (value) |present| {
        hashInt(hash, u8, 1);
        hashInt(hash, u32, @intFromEnum(present));
    } else {
        hashInt(hash, u8, 0);
    }
}

fn hashOptionalCall(hash: *Sha256, value: ?types.CallId) void {
    if (value) |present| {
        hashInt(hash, u8, 1);
        hashInt(hash, u32, @intFromEnum(present));
    } else {
        hashInt(hash, u8, 0);
    }
}

fn hashBytes(hash: *Sha256, bytes: []const u8) void {
    hashInt(hash, u32, @intCast(bytes.len));
    hash.update(bytes);
}

fn hashType(hash: *Sha256, ty: types.Type) void {
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(ty)));
    switch (ty) {
        .bounded_uint => |bounded| {
            hashInt(hash, u8, bounded.bits);
            hashInt(hash, u8, @intFromEnum(std.meta.activeTag(bounded.representation)));
            switch (bounded.representation) {
                .canonical_field => {},
                .little_endian_limbs => |layout| {
                    hashInt(hash, u8, layout.limb_bits);
                    hashInt(hash, u8, layout.limb_count);
                },
            }
        },
        .array => |array| {
            hashInt(hash, u8, @intFromEnum(array.element));
            hashInt(hash, u16, array.len);
        },
        else => {},
    }
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn callStrategyTag(strategy: program.CallStrategy) u8 {
    return switch (strategy) {
        .inline_expansion => 0,
        .relation_backed => 1,
    };
}

fn digestIsZero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

/// Internal dependency surface for the cold compiler pass. Keeping this
/// explicit prevents the implementation shard from becoming a second public
/// authority for the frame ABI.
pub const CompilerHooks = struct {
    pub const containsValue = functionFramesContainsValue;
    pub const hashPlan = functionFramesHashPlan;
    pub const idFromIndex = functionFramesIdFromIndex;
    pub const itemRangeEnd = functionFramesItemRangeEnd;
    pub const mark = functionFramesMark;
    pub const rejectDuplicateValues = functionFramesRejectDuplicateValues;
    pub const relationDigest = functionFramesRelationDigest;
    pub const requireFieldScalar = functionFramesRequireFieldScalar;
    pub const validateActivationAbi = functionFramesValidateActivationAbi;
};

const functionFramesContainsValue = containsValue;
const functionFramesHashPlan = hashPlan;
const functionFramesIdFromIndex = idFromIndex;
const functionFramesItemRangeEnd = itemRangeEnd;
const functionFramesMark = mark;
const functionFramesRejectDuplicateValues = rejectDuplicateValues;
const functionFramesRelationDigest = relationDigest;
const functionFramesRequireFieldScalar = requireFieldScalar;
const functionFramesValidateActivationAbi = validateActivationAbi;

//! Authenticated, allocation-free witness execution for typed Poseidon2-M31.
//!
//! Construction is the trust boundary. It revalidates the H-003 plan and the
//! complete H-004 physical binding, then compiles only the canonical H-002
//! output closure into compact local-slot instructions. The resulting executor
//! borrows no arena, plan, or binding memory.
//!
//! Execution writes caller-owned final columns directly. Every fallible shape
//! and alias check runs before the first write; after that point evaluation,
//! zero padding, and logical-to-committed placement are infallible. An executor
//! owns one scratch vector and is therefore deliberately non-reentrant. Create
//! one executor per worker when parallel row generation is required.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const core_utils = @import("stwo_core").utils;
const compat = @import("typed_poseidon2_compat.zig");
const digest = @import("digest.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const poseidon = @import("typed_poseidon2.zig");
const production = @import("../memory_commitment/poseidon2_air.zig");
const types = @import("types.zig");

pub const N_MAIN_COLUMNS: usize = compat.N_MAIN_COLUMNS;
pub const WIDTH: usize = compat.WIDTH;
pub const Call = production.Call;
pub const EXECUTION_DIGEST_FORMAT_VERSION: u16 = 1;
pub const EXECUTION_DIGEST_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/poseidon2-witness-executor/v1";

pub const ConstructionError = materializer.Error || compat.BindingError || error{
    BindingSnapshotMismatch,
    ExecutionPlanMismatch,
    InvalidExpressionGraph,
    UnsupportedExpression,
};

pub const ExecutionError = error{
    AddressOverflow,
    AliasedDestination,
    AliasedInput,
    CorruptExecutor,
    InvalidTraceShape,
};

const no_slot = std.math.maxInt(u32);
const m31_modulus = m31.Modulus;

const Binary = struct {
    lhs: u32,
    rhs: u32,
};

const Selection = struct {
    selector: u32,
    when_true: u32,
    when_false: u32,
};

const Instruction = union(enum) {
    constant: M31,
    input: u8,
    add: Binary,
    sub: Binary,
    mul: Binary,
    neg: u32,
    select: Selection,
};

/// Complete external identity copied at the authenticated construction
/// boundary. Exact H-004 entry IDs and values are retained so a later caller
/// can reauthenticate an independently transported binding against this
/// compiled executor, not merely against its geometry.
pub const Identity = struct {
    compatibility: compat.Identity,
    materializer_policy_version: u16,
    program_digest: digest.Digest,
    gate: types.ValueId,
    policy: materializer.Policy,
    function: types.FunctionId,
    inputs: [WIDTH]types.ValueId,
    outputs: [WIDTH]types.ValueId,
    plan_materializations: [compat.N_MATERIALIZATIONS]materializer.MaterializationId,
    values: [compat.N_MATERIALIZATIONS]types.ValueId,

    fn from(
        definition: poseidon.Definition,
        binding: *const compat.OwnedBinding,
    ) Identity {
        var plan_materializations: [compat.N_MATERIALIZATIONS]materializer.MaterializationId =
            undefined;
        var values: [compat.N_MATERIALIZATIONS]types.ValueId = undefined;
        for (binding.entries, 0..) |entry, index| {
            plan_materializations[index] = entry.plan_materialization;
            values[index] = entry.value;
        }
        return .{
            .compatibility = binding.identity,
            .materializer_policy_version = binding.materializer_policy_version,
            .program_digest = binding.program_digest,
            .gate = binding.gate,
            .policy = binding.policy,
            .function = definition.function,
            .inputs = poseidon.values(definition.inputs),
            .outputs = poseidon.values(definition.outputs),
            .plan_materializations = plan_materializations,
            .values = values,
        };
    }

    fn matches(
        self: *const Identity,
        definition: poseidon.Definition,
        binding: *const compat.OwnedBinding,
    ) bool {
        if (!std.meta.eql(self.compatibility, binding.identity) or
            self.materializer_policy_version != binding.materializer_policy_version or
            !std.mem.eql(u8, &self.program_digest, &binding.program_digest) or
            self.gate != binding.gate or
            !std.meta.eql(self.policy, binding.policy) or
            self.function != definition.function or
            binding.entries.len != compat.N_MATERIALIZATIONS)
        {
            return false;
        }
        const inputs = poseidon.values(definition.inputs);
        const outputs = poseidon.values(definition.outputs);
        if (!std.mem.eql(types.ValueId, &self.inputs, &inputs) or
            !std.mem.eql(types.ValueId, &self.outputs, &outputs))
        {
            return false;
        }
        for (binding.entries, self.plan_materializations, self.values) |
            entry,
            plan_materialization,
            value,
        | {
            if (entry.plan_materialization != plan_materialization or
                entry.value != value)
            {
                return false;
            }
        }
        return true;
    }
};

/// A compiled, self-contained typed Poseidon witness executor.
///
/// The owned scratch makes mutation explicit in the receiver type. There are
/// no allocations after `init`, including for padding or bit-reversal maps.
pub const Executor = struct {
    allocator: std.mem.Allocator,
    identity: Identity,
    execution_digest: digest.Digest,
    instructions: []Instruction,
    scratch: []M31,
    input_slots: [WIDTH]u32,
    materialization_slots: [compat.N_MATERIALIZATIONS]u32,

    pub fn init(
        allocator: std.mem.Allocator,
        arena: *const ir.Arena,
        definition: poseidon.Definition,
        spans: poseidon.DefinitionSpans,
        plan_value: *const materializer.Plan,
        binding: *const compat.OwnedBinding,
    ) ConstructionError!Executor {
        // This is deliberately first: no binding field is trusted by the
        // compiler until H-004 has reconstructed the canonical correspondence.
        try binding.validateAgainst(
            allocator,
            arena,
            definition,
            spans,
            plan_value,
        );

        const node_count = arena.nodeCount();
        const reachable = try allocator.alloc(bool, node_count);
        defer allocator.free(reachable);
        @memset(reachable, false);
        const definition_outputs = poseidon.values(definition.outputs);
        for (definition_outputs) |value| {
            const index = types.idIndex(value);
            if (index >= node_count) return error.InvalidExpressionGraph;
            reachable[index] = true;
        }
        try closeReachability(arena, reachable);

        const local_slots = try allocator.alloc(u32, node_count);
        defer allocator.free(local_slots);
        @memset(local_slots, no_slot);

        var instruction_count: usize = 0;
        for (reachable) |is_reachable| {
            instruction_count += @intFromBool(is_reachable);
        }
        if (instruction_count == 0 or
            instruction_count > std.math.maxInt(u32))
        {
            return error.InvalidExpressionGraph;
        }

        const instructions = try allocator.alloc(Instruction, instruction_count);
        errdefer allocator.free(instructions);
        const scratch = try allocator.alloc(M31, instruction_count);
        errdefer allocator.free(scratch);

        const definition_inputs = poseidon.values(definition.inputs);
        var input_slots: [WIDTH]u32 = undefined;
        @memset(&input_slots, no_slot);
        var cursor: usize = 0;
        for (arena.nodesView(), 0..) |node, node_index| {
            if (!reachable[node_index]) continue;
            if (!node.key.ty.isFieldScalar()) return error.UnsupportedExpression;
            const local: u32 = @intCast(cursor);
            local_slots[node_index] = local;
            instructions[cursor] = try compileInstruction(
                node.key.op,
                node_index,
                local_slots,
                &definition_inputs,
            );
            switch (instructions[cursor]) {
                .input => |lane| input_slots[lane] = local,
                else => {},
            }
            cursor += 1;
        }
        if (cursor != instruction_count) return error.InvalidExpressionGraph;
        for (input_slots) |slot| {
            if (slot == no_slot) return error.InvalidExpressionGraph;
        }

        var materialization_slots: [compat.N_MATERIALIZATIONS]u32 = undefined;
        for (binding.entries, 0..) |entry, ordinal| {
            const index = types.idIndex(entry.value);
            if (index >= local_slots.len or local_slots[index] == no_slot or
                entry.materialization.ordinal != ordinal or
                entry.materialization.column != compat.TEMPORARY_START + ordinal)
            {
                return error.InvalidExpressionGraph;
            }
            materialization_slots[ordinal] = local_slots[index];
        }

        const identity = Identity.from(definition, binding);
        if (!identity.matches(definition, binding))
            return error.BindingSnapshotMismatch;
        const execution_digest = computeExecutionDigest(
            &identity,
            instructions,
            &input_slots,
            &materialization_slots,
        );
        return .{
            .allocator = allocator,
            .identity = identity,
            .execution_digest = execution_digest,
            .instructions = instructions,
            .scratch = scratch,
            .input_slots = input_slots,
            .materialization_slots = materialization_slots,
        };
    }

    pub fn deinit(self: *Executor) void {
        self.allocator.free(self.scratch);
        self.allocator.free(self.instructions);
        self.* = undefined;
    }

    pub fn instructionCount(self: *const Executor) usize {
        return self.instructions.len;
    }

    /// Returns the canonical H-005 executable identity after rechecking every
    /// owned instruction and slot. The digest preimage is deliberately the
    /// same one used since H-005; exposing it does not mint a second identity.
    pub fn identityDigest(self: *const Executor) ExecutionError!digest.Digest {
        if (!self.hasValidExecutableShape()) return error.CorruptExecutor;
        const actual = computeExecutionDigest(
            &self.identity,
            self.instructions,
            &self.input_slots,
            &self.materialization_slots,
        );
        if (!std.mem.eql(u8, &self.execution_digest, &actual))
            return error.CorruptExecutor;
        return actual;
    }

    /// Complete authenticated envelope copied when this executor was built.
    /// Consumers use this snapshot to reject cross-program component mixing.
    pub fn identitySnapshot(self: *const Executor) ExecutionError!Identity {
        _ = try self.identityDigest();
        return self.identity;
    }

    /// Re-establishes authenticity after a new ownership or transport boundary
    /// and proves that the supplied binding describes this exact compiled
    /// executor. Ordinary execution needs no arena because `init` already
    /// copied all executable semantics and identity into owned storage.
    pub fn reauthenticate(
        self: *const Executor,
        allocator: std.mem.Allocator,
        arena: *const ir.Arena,
        definition: poseidon.Definition,
        spans: poseidon.DefinitionSpans,
        plan_value: *const materializer.Plan,
        binding: *const compat.OwnedBinding,
    ) ConstructionError!void {
        // Recompile from the authenticated arena rather than accepting a
        // checksum derived from this executor. This catches complete but
        // internally well-formed instruction and slot-map replacement.
        var canonical = try Executor.init(
            allocator,
            arena,
            definition,
            spans,
            plan_value,
            binding,
        );
        defer canonical.deinit();
        if (!self.executableEql(&canonical)) return error.ExecutionPlanMismatch;
    }

    /// Generates final column-major main storage with exact production
    /// logical-to-committed placement. `narrow_output` is intentionally ignored
    /// just as it is by production main-trace generation; it is an interaction
    /// generation shortcut, not part of the committed permutation row.
    pub fn generateMainInto(
        self: *Executor,
        columns: *[N_MAIN_COLUMNS][]M31,
        calls: []const Call,
        log_size: u32,
    ) ExecutionError!void {
        const shape = try self.preflight(columns, calls, log_size);

        // No `try`, allocation, or other fallible operation is permitted below
        // this line. Every error therefore leaves all caller bytes untouched.
        for (columns) |column| @memset(column, M31.zero());
        for (calls, 0..) |call, logical_row| {
            self.evaluate(call.input);
            const committed_row = committedRow(logical_row, log_size);
            columns[compat.ENABLER_COLUMN][committed_row] = M31.one();
            for (self.input_slots, 0..) |slot, lane| {
                columns[compat.INPUT_START + lane][committed_row] = self.scratch[slot];
            }
            for (self.materialization_slots, 0..) |slot, ordinal| {
                columns[compat.TEMPORARY_START + ordinal][committed_row] =
                    self.scratch[slot];
            }
            columns[compat.WIDE_COLUMN][committed_row] =
                M31.fromU64(@intFromBool(call.wide));
            columns[compat.IO_COLUMN][committed_row] =
                M31.fromU64(@intFromBool(call.io));
        }
        std.debug.assert(shape == columns[0].len);
    }

    fn preflight(
        self: *const Executor,
        columns: *const [N_MAIN_COLUMNS][]M31,
        calls: []const Call,
        log_size: u32,
    ) ExecutionError!usize {
        if (!self.hasValidExecutableShape() or
            !std.mem.eql(u8, &self.execution_digest, &computeExecutionDigest(
                &self.identity,
                self.instructions,
                &self.input_slots,
                &self.materialization_slots,
            )))
        {
            return error.CorruptExecutor;
        }
        // `cosetIndexToCircleDomainIndex` uses `2 << log_size`, so retain one
        // headroom bit in addition to making the domain-size shift valid.
        if (log_size >= @bitSizeOf(usize) - 1)
            return error.InvalidTraceShape;
        const size = @as(usize, 1) << @intCast(log_size);
        if (calls.len > size) return error.InvalidTraceShape;

        var destinations: [N_MAIN_COLUMNS]AddressRange = undefined;
        for (columns, 0..) |column, index| {
            if (column.len != size) return error.InvalidTraceShape;
            destinations[index] = (try rangeOf(M31, column)).?;
        }
        const descriptors = try objectRange(columns);
        const executor_storage = try objectRange(self);
        const instructions = try rangeOf(Instruction, self.instructions);
        const scratch = try rangeOf(M31, self.scratch);
        const call_storage = try rangeOf(Call, calls);

        if (call_storage) |input| {
            if (input.overlaps(descriptors) or
                input.overlaps(executor_storage) or
                (instructions != null and input.overlaps(instructions.?)) or
                (scratch != null and input.overlaps(scratch.?)))
            {
                return error.AliasedInput;
            }
        }

        for (destinations, 0..) |destination, index| {
            if (destination.overlaps(descriptors) or
                destination.overlaps(executor_storage) or
                (instructions != null and destination.overlaps(instructions.?)) or
                (scratch != null and destination.overlaps(scratch.?)) or
                (call_storage != null and destination.overlaps(call_storage.?)))
            {
                return if (call_storage != null and
                    destination.overlaps(call_storage.?))
                    error.AliasedInput
                else
                    error.AliasedDestination;
            }
            for (destinations[0..index]) |previous| {
                if (destination.overlaps(previous))
                    return error.AliasedDestination;
            }
        }
        return size;
    }

    fn executableEql(self: *const Executor, other: *const Executor) bool {
        if (!std.meta.eql(self.identity, other.identity) or
            !std.mem.eql(u8, &self.execution_digest, &other.execution_digest) or
            self.instructions.len != other.instructions.len or
            self.scratch.len != other.scratch.len or
            !std.mem.eql(u32, &self.input_slots, &other.input_slots) or
            !std.mem.eql(
                u32,
                &self.materialization_slots,
                &other.materialization_slots,
            ))
        {
            return false;
        }
        for (self.instructions, other.instructions) |actual, expected| {
            if (!std.meta.eql(actual, expected)) return false;
        }
        return true;
    }

    fn hasValidExecutableShape(self: *const Executor) bool {
        if (!std.meta.eql(self.identity.compatibility, compat.Identity.canonical()) or
            self.identity.materializer_policy_version != materializer.policy_version or
            self.identity.policy.maximum_constraint_degree !=
                compat.MAXIMUM_CONSTRAINT_DEGREE or
            self.identity.policy.row_mask_degree != 0 or
            self.instructions.len == 0 or
            self.instructions.len != self.scratch.len)
        {
            return false;
        }
        var seen_inputs = [_]bool{false} ** WIDTH;
        for (self.instructions, 0..) |instruction, index| {
            switch (instruction) {
                .constant => |value| if (value.toU32() >= m31_modulus) return false,
                .input => |lane| {
                    if (lane >= WIDTH or seen_inputs[lane]) return false;
                    seen_inputs[lane] = true;
                },
                .add, .sub, .mul => |binary| {
                    if (binary.lhs >= index or binary.rhs >= index) return false;
                },
                .neg => |operand| if (operand >= index) return false,
                .select => |selection| {
                    if (selection.selector >= index or
                        selection.when_true >= index or
                        selection.when_false >= index)
                    {
                        return false;
                    }
                },
            }
        }
        for (self.input_slots, 0..) |slot, lane| {
            if (slot >= self.instructions.len or !seen_inputs[lane]) return false;
            switch (self.instructions[slot]) {
                .input => |actual_lane| if (actual_lane != lane) return false,
                else => return false,
            }
        }
        for (self.materialization_slots, 0..) |slot, index| {
            if (slot >= self.instructions.len) return false;
            for (self.materialization_slots[0..index]) |previous| {
                if (slot == previous) return false;
            }
        }
        return true;
    }

    inline fn evaluate(self: *Executor, input: [WIDTH]u32) void {
        for (self.instructions, 0..) |instruction, index| {
            self.scratch[index] = switch (instruction) {
                .constant => |value| value,
                .input => |lane| M31.fromU64(input[lane]),
                .add => |operands| self.scratch[operands.lhs].add(
                    self.scratch[operands.rhs],
                ),
                .sub => |operands| self.scratch[operands.lhs].sub(
                    self.scratch[operands.rhs],
                ),
                .mul => |operands| self.scratch[operands.lhs].mul(
                    self.scratch[operands.rhs],
                ),
                .neg => |operand| self.scratch[operand].neg(),
                .select => |selection| if (!self.scratch[selection.selector].isZero())
                    self.scratch[selection.when_true]
                else
                    self.scratch[selection.when_false],
            };
        }
    }
};

fn closeReachability(arena: *const ir.Arena, reachable: []bool) ConstructionError!void {
    var cursor = arena.nodeCount();
    while (cursor != 0) {
        cursor -= 1;
        if (!reachable[cursor]) continue;
        const node = arena.nodesView()[cursor];
        switch (node.key.op) {
            .constant, .input => {},
            .add, .sub, .mul => |binary| {
                try markReachable(reachable, cursor, binary.lhs);
                try markReachable(reachable, cursor, binary.rhs);
            },
            .neg => |operand| try markReachable(reachable, cursor, operand),
            .select => |selection| {
                try markReachable(reachable, cursor, selection.selector);
                try markReachable(reachable, cursor, selection.when_true);
                try markReachable(reachable, cursor, selection.when_false);
            },
            .hint_output, .call_output => return error.UnsupportedExpression,
        }
    }
}

fn markReachable(
    reachable: []bool,
    parent: usize,
    child: types.ValueId,
) ConstructionError!void {
    const child_index = types.idIndex(child);
    if (child_index >= parent or child_index >= reachable.len)
        return error.InvalidExpressionGraph;
    reachable[child_index] = true;
}

fn compileInstruction(
    op: @import("expr.zig").Op,
    node_index: usize,
    local_slots: []const u32,
    inputs: *const [WIDTH]types.ValueId,
) ConstructionError!Instruction {
    return switch (op) {
        .constant => |constant| .{ .constant = switch (constant) {
            .field => |value| M31.fromCanonical(value),
            .unsigned => |value| M31.fromU64(value),
        } },
        .input => blk: {
            const value: types.ValueId = @enumFromInt(node_index);
            break :blk .{ .input = inputLane(inputs, value) orelse
                return error.UnsupportedExpression };
        },
        .add => |binary| .{ .add = try compileBinary(binary, node_index, local_slots) },
        .sub => |binary| .{ .sub = try compileBinary(binary, node_index, local_slots) },
        .mul => |binary| .{ .mul = try compileBinary(binary, node_index, local_slots) },
        .neg => |operand| .{ .neg = try localSlot(operand, node_index, local_slots) },
        .select => |selection| .{ .select = .{
            .selector = try localSlot(selection.selector, node_index, local_slots),
            .when_true = try localSlot(selection.when_true, node_index, local_slots),
            .when_false = try localSlot(selection.when_false, node_index, local_slots),
        } },
        .hint_output, .call_output => error.UnsupportedExpression,
    };
}

fn compileBinary(
    binary: @import("expr.zig").Binary,
    node_index: usize,
    local_slots: []const u32,
) ConstructionError!Binary {
    return .{
        .lhs = try localSlot(binary.lhs, node_index, local_slots),
        .rhs = try localSlot(binary.rhs, node_index, local_slots),
    };
}

fn localSlot(
    value: types.ValueId,
    parent: usize,
    local_slots: []const u32,
) ConstructionError!u32 {
    const index = types.idIndex(value);
    if (index >= parent or index >= local_slots.len or local_slots[index] == no_slot)
        return error.InvalidExpressionGraph;
    return local_slots[index];
}

fn inputLane(inputs: *const [WIDTH]types.ValueId, value: types.ValueId) ?u8 {
    for (inputs, 0..) |input, lane| {
        if (input == value) return @intCast(lane);
    }
    return null;
}

/// Canonical projection of every executable bit. Padding, allocation
/// addresses, and scratch contents are excluded. This is a cheap accidental
/// corruption guard at the mutation boundary; `reauthenticate` additionally
/// recompiles from the arena to establish an independent authority.
fn computeExecutionDigest(
    identity: *const Identity,
    instructions: []const Instruction,
    input_slots: *const [WIDTH]u32,
    materialization_slots: *const [compat.N_MATERIALIZATIONS]u32,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(EXECUTION_DIGEST_DOMAIN_SEPARATOR);
    hashInt(&hash, u16, EXECUTION_DIGEST_FORMAT_VERSION);
    hashInt(&hash, u16, identity.compatibility.format_version);
    hashInt(&hash, u32, @intFromEnum(identity.compatibility.policy));
    hashInt(&hash, u16, identity.compatibility.policy_version);
    hashInt(&hash, u8, identity.compatibility.maximum_constraint_degree);
    hashInt(&hash, u16, identity.compatibility.width);
    hashInt(&hash, u16, identity.compatibility.materializations);
    hashInt(&hash, u16, identity.compatibility.main_columns);
    hashInt(&hash, u16, identity.materializer_policy_version);
    hash.update(&identity.program_digest);
    hashInt(&hash, u32, @intFromEnum(identity.gate));
    hashInt(&hash, u64, identity.policy.maximum_constraint_degree);
    hashInt(&hash, u64, identity.policy.row_mask_degree);
    hashInt(&hash, u32, @intFromEnum(identity.function));
    for (identity.inputs) |value| hashInt(&hash, u32, @intFromEnum(value));
    for (identity.outputs) |value| hashInt(&hash, u32, @intFromEnum(value));
    for (identity.plan_materializations) |value| {
        hashInt(&hash, u32, @intFromEnum(value));
    }
    for (identity.values) |value| hashInt(&hash, u32, @intFromEnum(value));

    hashInt(&hash, u64, @intCast(instructions.len));
    for (instructions) |instruction| switch (instruction) {
        .constant => |value| {
            hashInt(&hash, u8, 0);
            hashInt(&hash, u32, value.toU32());
        },
        .input => |lane| {
            hashInt(&hash, u8, 1);
            hashInt(&hash, u8, lane);
        },
        .add => |binary| hashBinaryInstruction(&hash, 2, binary),
        .sub => |binary| hashBinaryInstruction(&hash, 3, binary),
        .mul => |binary| hashBinaryInstruction(&hash, 4, binary),
        .neg => |operand| {
            hashInt(&hash, u8, 5);
            hashInt(&hash, u32, operand);
        },
        .select => |selection| {
            hashInt(&hash, u8, 6);
            hashInt(&hash, u32, selection.selector);
            hashInt(&hash, u32, selection.when_true);
            hashInt(&hash, u32, selection.when_false);
        },
    };
    for (input_slots) |slot| hashInt(&hash, u32, slot);
    for (materialization_slots) |slot| hashInt(&hash, u32, slot);
    return hash.finalResult();
}

fn hashBinaryInstruction(hash: anytype, tag: u8, binary: Binary) void {
    hashInt(hash, u8, tag);
    hashInt(hash, u32, binary.lhs);
    hashInt(hash, u32, binary.rhs);
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

const AddressRange = struct {
    start: usize,
    end: usize,

    inline fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn rangeOf(comptime T: type, values: []const T) ExecutionError!?AddressRange {
    if (values.len == 0) return null;
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    const end = std.math.add(usize, start, byte_len) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

fn objectRange(pointer: anytype) ExecutionError!AddressRange {
    const Pointer = @TypeOf(pointer);
    const info = @typeInfo(Pointer);
    if (info != .pointer or info.pointer.size != .one)
        @compileError("objectRange requires a single-item pointer");
    const start = @intFromPtr(pointer);
    const end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

inline fn committedRow(logical_row: usize, log_size: u32) usize {
    return core_utils.bitReverseIndex(
        core_utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}

comptime {
    if (compat.N_MAIN_COLUMNS != production.N_MAIN_COLUMNS or
        compat.N_MATERIALIZATIONS != production.N_TEMPORARIES or
        compat.WIDTH != production.WIDTH or
        compat.ENABLER_COLUMN != 0 or
        compat.INPUT_START != 1 or
        compat.TEMPORARY_START != compat.INPUT_START + compat.WIDTH or
        compat.WIDE_COLUMN != compat.TEMPORARY_START + compat.N_MATERIALIZATIONS or
        compat.IO_COLUMN != compat.WIDE_COLUMN + 1)
    {
        @compileError("typed Poseidon witness geometry drifted from production");
    }
}

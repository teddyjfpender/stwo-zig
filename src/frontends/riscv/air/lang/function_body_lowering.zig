//! Authenticated executable lowering for pure inline typed-AIR functions.
//!
//! `function_frames.zig` establishes frame ownership and call ABI identity, but
//! a `.call_output` node is still only a logical placeholder.  Treating that
//! placeholder as a committed leaf would leave an inline result unconstrained.
//! This pass closes that gap for the pure field-scalar surface: it substitutes
//! formal arguments through every nested inline call and emits one canonical,
//! flat SSA tape whose destinations are implicit and topological.
//!
//! Compilation is deliberately cold and may allocate.  The resulting program
//! owns all storage, carries both semantic and frame-plan identities, and has a
//! strict finite expansion policy.  `executeInto` accepts no allocator.  It
//! validates shape, digest, and alias safety before the first store, then runs
//! a branch-bounded tape directly into caller-owned scratch.
//!
//! Relation-backed calls, hints, machine refinements, and non-field values fail
//! closed.  They require their respective proof-aware lowering paths; silently
//! reclassifying any of them as an external input would recreate the exact
//! unconstrained-cell escape hatch this module exists to remove.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const m31 = @import("stwo_core").fields.m31;
const compiler_impl = @import("function_body_lowering_compiler.zig");
const semantic_digest = @import("digest.zig");
const expr = @import("expr.zig");
const frames = @import("function_frames.zig");
const functions = @import("functions.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const types = @import("types.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const POLICY_VERSION: u16 = 1;
pub const BODY_OWNERSHIP_VERSION: u16 = 1;
pub const DIGEST_DOMAIN = "stwo-zig/typed-air/function-body-lowering/v1\x00";
pub const Digest = [32]u8;

/// Absolute parser/compiler ceilings.  A caller may select tighter limits but
/// cannot use an authenticated program to smuggle an unbounded expansion into
/// a later verifier or witness process.
pub const HARD_MAX_INLINE_DEPTH: u16 = 64;
pub const HARD_MAX_INLINE_INVOCATIONS: u32 = 65_536;
pub const HARD_MAX_INSTRUCTIONS: u32 = 1 << 22;
pub const HARD_MAX_REGISTERS: u32 = 1 << 22;
pub const HARD_MAX_ARGUMENTS: u16 = 1_024;
pub const HARD_MAX_OUTPUTS: u16 = 1_024;

pub const Limits = struct {
    max_inline_depth: u16 = 32,
    max_inline_invocations: u32 = 4_096,
    max_instructions: u32 = 1 << 20,
    max_registers: u32 = 1 << 20,

    pub fn validate(self: Limits) ValidationError!void {
        if (self.max_inline_depth == 0 or
            self.max_inline_depth > HARD_MAX_INLINE_DEPTH or
            self.max_inline_invocations == 0 or
            self.max_inline_invocations > HARD_MAX_INLINE_INVOCATIONS or
            self.max_instructions == 0 or
            self.max_instructions > HARD_MAX_INSTRUCTIONS or
            self.max_registers == 0 or
            self.max_registers > HARD_MAX_REGISTERS)
        {
            return error.InvalidLimits;
        }
    }
};

pub const Opcode = enum(u8) {
    constant = 0,
    add = 1,
    sub = 2,
    mul = 3,
    neg = 4,
    select = 5,
};

/// Destination register is `input_count + instruction_index`.  Unused
/// operands must be zero so padding and incidental memory never enter either
/// identity or execution semantics.
pub const Instruction = struct {
    opcode: Opcode,
    operand_a: u32,
    operand_b: u32,
    operand_c: u32,
};

/// One direct AIR constraint instantiated in a concrete inline call context.
/// Registers name the same canonical SSA tape used for witness execution, so
/// a call result can never be accepted as an unconstrained committed leaf.
pub const ConstraintCheck = struct {
    root_register: u32,
    gate_register: ?u32,
};

pub const ValidationError = error{
    CountOverflow,
    DigestMismatch,
    InvalidInstruction,
    InvalidLimits,
    InvalidProgramShape,
    NonCanonicalInstruction,
};

pub const CompileError = std.mem.Allocator.Error || frames.Error || ValidationError || error{
    InlineCycle,
    InlineDepthExceeded,
    InlineInvocationLimitExceeded,
    InstructionLimitExceeded,
    InvalidCall,
    InvalidFunction,
    FunctionBodyRequiresOwnedLowering,
    UnownedFunctionBody,
    NonFieldValue,
    NonTopologicalInlineCall,
    RegisterLimitExceeded,
    RelationBackedCall,
    RootCallMustBePublicInline,
    UnsupportedEffect,
    UnsupportedHint,
    UnsupportedMachineDerived,
};

pub const ExecuteError = ValidationError || error{
    AddressOverflow,
    AliasedBuffer,
    InvalidExecutionShape,
    ConstraintViolation,
};

pub const OwnedProgram = struct {
    allocator: std.mem.Allocator,
    format_version: u16,
    policy_version: u16,
    body_ownership_version: u16,
    semantic_identity_format_version: u16,
    semantic_digest: Digest,
    frame_plan_digest: Digest,
    root_call: types.CallId,
    limits: Limits,
    input_count: u16,
    output_count: u16,
    expanded_inline_invocations: u32,
    register_count: u32,
    instructions: []Instruction,
    constraint_checks: []ConstraintCheck,
    output_registers: []u32,
    program_digest: Digest,

    pub fn deinit(self: *OwnedProgram) void {
        self.allocator.free(self.output_registers);
        self.allocator.free(self.constraint_checks);
        self.allocator.free(self.instructions);
        self.* = undefined;
    }

    pub fn scratchLen(self: *const OwnedProgram) usize {
        return self.register_count;
    }

    /// Exact owned payload bytes, excluding allocator metadata and the small
    /// by-value program header.
    pub fn ownedPayloadBytes(self: *const OwnedProgram) ValidationError!usize {
        const instructions_bytes = std.math.mul(
            usize,
            self.instructions.len,
            @sizeOf(Instruction),
        ) catch return error.CountOverflow;
        const outputs_bytes = std.math.mul(
            usize,
            self.output_registers.len,
            @sizeOf(u32),
        ) catch return error.CountOverflow;
        const checks_bytes = std.math.mul(
            usize,
            self.constraint_checks.len,
            @sizeOf(ConstraintCheck),
        ) catch return error.CountOverflow;
        const tape_bytes = std.math.add(usize, instructions_bytes, checks_bytes) catch
            return error.CountOverflow;
        return std.math.add(usize, tape_bytes, outputs_bytes) catch
            error.CountOverflow;
    }

    /// Allocation-free validation of the complete hot representation.
    pub fn validate(self: *const OwnedProgram) ValidationError!void {
        if (self.format_version != FORMAT_VERSION or
            self.policy_version != POLICY_VERSION or
            self.body_ownership_version > BODY_OWNERSHIP_VERSION or
            self.semantic_identity_format_version == 0 or
            digestIsZero(self.semantic_digest) or
            digestIsZero(self.frame_plan_digest))
        {
            return error.InvalidProgramShape;
        }
        if ((self.body_ownership_version == 0 and
            self.semantic_identity_format_version == semantic_digest.function_body_format_version) or
            (self.body_ownership_version == BODY_OWNERSHIP_VERSION and
                self.semantic_identity_format_version != semantic_digest.function_body_format_version))
        {
            return error.InvalidProgramShape;
        }
        try self.limits.validate();
        if (self.input_count > HARD_MAX_ARGUMENTS or
            self.output_count > HARD_MAX_OUTPUTS or
            self.output_registers.len != self.output_count or
            self.expanded_inline_invocations == 0 or
            self.expanded_inline_invocations > self.limits.max_inline_invocations or
            self.instructions.len > self.limits.max_instructions)
        {
            return error.InvalidProgramShape;
        }
        const expected_register_count = std.math.add(
            usize,
            self.input_count,
            self.instructions.len,
        ) catch return error.CountOverflow;
        if (expected_register_count != self.register_count or
            expected_register_count > self.limits.max_registers)
        {
            return error.InvalidProgramShape;
        }

        for (self.instructions, 0..) |instruction, index| {
            const destination = std.math.add(usize, self.input_count, index) catch
                return error.CountOverflow;
            try validateInstruction(instruction, destination);
        }
        for (self.output_registers) |register| {
            if (register >= self.register_count)
                return error.InvalidProgramShape;
        }
        if (self.body_ownership_version == 0 and self.constraint_checks.len != 0)
            return error.InvalidProgramShape;
        for (self.constraint_checks) |check| {
            if (check.root_register >= self.register_count or
                (check.gate_register != null and
                    check.gate_register.? >= self.register_count))
            {
                return error.InvalidProgramShape;
            }
        }
        const actual_digest = hashProgram(self);
        if (!std.mem.eql(u8, &actual_digest, &self.program_digest))
            return error.DigestMismatch;
    }

    /// Cold strong authentication against the logical arena and frame plan.
    /// The recompile is intentionally separate from hot execution.
    pub fn validateAgainst(
        self: *const OwnedProgram,
        allocator: std.mem.Allocator,
        arena: *const ir.Arena,
        frame_plan: *const frames.OwnedPlan,
    ) CompileError!void {
        try self.validate();
        var expected = if (self.body_ownership_version == 0)
            try compile(allocator, arena, frame_plan, self.root_call, self.limits)
        else
            try compileOwnedBody(allocator, arena, frame_plan, self.root_call, self.limits);
        defer expected.deinit();
        if (!semanticEqual(self, &expected)) return error.DigestMismatch;
    }

    /// Authenticate once before a repeated hot execution loop.  The returned
    /// capability borrows this program's immutable payload and performs no
    /// hashing or allocation while executing.  It must not outlive `self` or
    /// race a mutation/deinitialization of `self`.
    pub fn prepare(self: *const OwnedProgram) ValidationError!PreparedProgram {
        try self.validate();
        return .{
            .input_count = self.input_count,
            .output_count = self.output_count,
            .register_count = self.register_count,
            .instructions = self.instructions,
            .constraint_checks = self.constraint_checks,
            .output_registers = self.output_registers,
        };
    }

    /// Execute the authenticated tape without allocation.
    ///
    /// Shape/alias checks precede the first write. For owned bodies, direct AIR
    /// checks run after the tape and before output publication: outputs remain
    /// failure-atomic while caller-provided scratch is explicitly work memory.
    /// Inputs, scratch, outputs, the program header, and both owned payloads
    /// must be pairwise disjoint.  This stronger-than-necessary contract keeps
    /// failure atomicity obvious and prevents adversarial slices from mutating
    /// instructions while they are being consumed.
    pub fn executeInto(
        self: *const OwnedProgram,
        inputs: []const M31,
        registers: []M31,
        outputs: []M31,
    ) ExecuteError!void {
        const prepared = try self.prepare();
        try prepared.executeInto(inputs, registers, outputs);
    }
};

/// Validated immutable hot-loop view.  `prepare` pays the SHA-256 and full
/// structural validation once; each execution then performs only constant-size
/// shape/alias preflight plus the linear field-operation tape.
pub const PreparedProgram = struct {
    input_count: u16,
    output_count: u16,
    register_count: u32,
    instructions: []const Instruction,
    constraint_checks: []const ConstraintCheck,
    output_registers: []const u32,

    pub fn scratchLen(self: PreparedProgram) usize {
        return self.register_count;
    }

    pub fn executeInto(
        self: *const PreparedProgram,
        inputs: []const M31,
        registers: []M31,
        outputs: []M31,
    ) ExecuteError!void {
        try preflightExecution(self, inputs, registers, outputs);

        @memcpy(registers[0..inputs.len], inputs);
        for (self.instructions, 0..) |instruction, index| {
            const destination: usize = @as(usize, self.input_count) + index;
            registers[destination] = evaluateInstruction(instruction, registers);
        }
        for (self.constraint_checks) |check| {
            const root = registers[check.root_register];
            const residual = if (check.gate_register) |gate|
                root.mul(registers[gate])
            else
                root;
            if (!residual.isZero()) return error.ConstraintViolation;
        }
        for (self.output_registers, outputs) |register, *output| {
            output.* = registers[register];
        }
    }
};

/// Compile one public `.inline_expansion` call into an executable flat tape.
/// The supplied frame plan is re-authenticated against the arena before any
/// result is published.
pub fn compile(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    frame_plan: *const frames.OwnedPlan,
    root_call: types.CallId,
    limits: Limits,
) CompileError!OwnedProgram {
    return compileInternal(
        allocator,
        arena,
        frame_plan,
        root_call,
        limits,
        false,
    );
}

/// Production-compatible lowering for the opt-in owned-body authority. Every
/// reachable inline invocation instantiates its direct constraints, including
/// calls whose outputs are otherwise dead. Proof-aware effects, hints, and
/// relation-backed calls are rejected until a dedicated lowering owns them.
pub fn compileOwnedBody(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    frame_plan: *const frames.OwnedPlan,
    root_call: types.CallId,
    limits: Limits,
) CompileError!OwnedProgram {
    return compileInternal(
        allocator,
        arena,
        frame_plan,
        root_call,
        limits,
        true,
    );
}

fn compileInternal(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    frame_plan: *const frames.OwnedPlan,
    root_call: types.CallId,
    limits: Limits,
    owned_body: bool,
) CompileError!OwnedProgram {
    return compiler_impl.compileInternal(
        @This(),
        allocator,
        arena,
        frame_plan,
        root_call,
        limits,
        owned_body,
    );
}
const Visit = enum(u8) { unseen, active, complete };

fn validateInlineGraph(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    root: types.FunctionId,
    limits: Limits,
) CompileError!void {
    const function_count = functions.view(arena).len;
    if (types.idIndex(root) >= function_count) return error.InvalidFunction;
    const visits = try allocator.alloc(Visit, function_count);
    defer allocator.free(visits);
    @memset(visits, .unseen);
    try visitInlineFunction(arena, visits, root, 1, limits.max_inline_depth);
}

fn visitInlineFunction(
    arena: *const ir.Arena,
    visits: []Visit,
    function: types.FunctionId,
    depth: u16,
    max_depth: u16,
) CompileError!void {
    const index = types.idIndex(function);
    if (index >= visits.len) return error.InvalidFunction;
    if (visits[index] == .active) return error.InlineCycle;
    if (visits[index] == .complete) return;
    if (depth > max_depth) return error.InlineDepthExceeded;
    visits[index] = .active;
    errdefer visits[index] = .unseen;
    for (functions.calls(arena)) |call| {
        if (call.caller == null or call.caller.? != function or
            call.strategy != .inline_expansion)
        {
            continue;
        }
        const callee_index = types.idIndex(call.callee);
        if (callee_index >= visits.len) return error.InvalidFunction;
        if (visits[callee_index] == .active) return error.InlineCycle;
        if (callee_index >= index) return error.NonTopologicalInlineCall;
        const next_depth = std.math.add(u16, depth, 1) catch
            return error.InlineDepthExceeded;
        try visitInlineFunction(arena, visits, call.callee, next_depth, max_depth);
    }
    visits[index] = .complete;
}

fn requireFieldScalars(
    arena: *const ir.Arena,
    values: []const types.ValueId,
) CompileError!void {
    for (values) |value| {
        const node = arena.node(value) orelse return error.InvalidFunction;
        if (!node.key.ty.isFieldScalar()) return error.NonFieldValue;
    }
}

fn validateInstruction(
    instruction: Instruction,
    destination: usize,
) ValidationError!void {
    const a: usize = instruction.operand_a;
    const b: usize = instruction.operand_b;
    const c: usize = instruction.operand_c;
    switch (instruction.opcode) {
        .constant => {
            if (instruction.operand_a >= m31.Modulus)
                return error.InvalidInstruction;
            if (instruction.operand_b != 0 or instruction.operand_c != 0)
                return error.NonCanonicalInstruction;
        },
        .add, .mul => {
            if (a >= destination or b >= destination)
                return error.InvalidInstruction;
            if (instruction.operand_b < instruction.operand_a or
                instruction.operand_c != 0)
            {
                return error.NonCanonicalInstruction;
            }
        },
        .sub => {
            if (a >= destination or b >= destination)
                return error.InvalidInstruction;
            if (instruction.operand_c != 0)
                return error.NonCanonicalInstruction;
        },
        .neg => {
            if (a >= destination) return error.InvalidInstruction;
            if (instruction.operand_b != 0 or instruction.operand_c != 0)
                return error.NonCanonicalInstruction;
        },
        .select => if (a >= destination or b >= destination or c >= destination)
            return error.InvalidInstruction,
    }
}

inline fn evaluateInstruction(
    instruction: Instruction,
    registers: []const M31,
) M31 {
    return switch (instruction.opcode) {
        .constant => M31.fromCanonical(instruction.operand_a),
        .add => registers[instruction.operand_a].add(registers[instruction.operand_b]),
        .sub => registers[instruction.operand_a].sub(registers[instruction.operand_b]),
        .mul => registers[instruction.operand_a].mul(registers[instruction.operand_b]),
        .neg => registers[instruction.operand_a].neg(),
        .select => blk: {
            const selector = registers[instruction.operand_a];
            const when_true = registers[instruction.operand_b];
            const when_false = registers[instruction.operand_c];
            break :blk when_false.add(selector.mul(when_true.sub(when_false)));
        },
    };
}

fn preflightExecution(
    executable: *const PreparedProgram,
    inputs: []const M31,
    registers: []M31,
    outputs: []M31,
) ExecuteError!void {
    if (inputs.len != executable.input_count or
        registers.len != executable.register_count or
        outputs.len != executable.output_count)
    {
        return error.InvalidExecutionShape;
    }

    const input_range = try sliceRange(M31, inputs);
    const register_range = try sliceRange(M31, registers);
    const output_range = try sliceRange(M31, outputs);
    const header_range = try objectRange(executable);
    const instruction_range = try sliceRange(Instruction, executable.instructions);
    const constraint_range = try sliceRange(ConstraintCheck, executable.constraint_checks);
    const register_map_range = try sliceRange(u32, executable.output_registers);

    const mutable_ranges = [_]?AddressRange{ register_range, output_range };
    const all_buffers = [_]?AddressRange{ input_range, register_range, output_range };
    for (all_buffers, 0..) |candidate, index| {
        const present = candidate orelse continue;
        for (all_buffers[0..index]) |prior| {
            if (prior != null and present.overlaps(prior.?))
                return error.AliasedBuffer;
        }
        if (present.overlaps(header_range) or
            (instruction_range != null and present.overlaps(instruction_range.?)) or
            (constraint_range != null and present.overlaps(constraint_range.?)) or
            (register_map_range != null and present.overlaps(register_map_range.?)))
        {
            return error.AliasedBuffer;
        }
    }
    // Keep this assertion local to the preflight: future read-only buffers
    // added above must not accidentally omit a mutable-pair overlap check.
    if (mutable_ranges[0] != null and mutable_ranges[1] != null and
        mutable_ranges[0].?.overlaps(mutable_ranges[1].?))
    {
        return error.AliasedBuffer;
    }
}

const AddressRange = struct {
    start: usize,
    end: usize,

    inline fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn sliceRange(comptime T: type, values: []const T) ExecuteError!?AddressRange {
    if (values.len == 0) return null;
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    const end = std.math.add(usize, start, byte_len) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

fn objectRange(pointer: anytype) ExecuteError!AddressRange {
    const info = @typeInfo(@TypeOf(pointer));
    if (info != .pointer or info.pointer.size != .one)
        @compileError("program storage must be a single-item pointer");
    const start = @intFromPtr(pointer);
    const end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
        return error.AddressOverflow;
    return .{ .start = start, .end = end };
}

fn hashProgram(executable: *const OwnedProgram) Digest {
    var hash = Sha256.init(.{});
    hash.update(DIGEST_DOMAIN);
    hashInt(&hash, u16, executable.format_version);
    hashInt(&hash, u16, executable.policy_version);
    hashInt(&hash, u16, executable.semantic_identity_format_version);
    hash.update(&executable.semantic_digest);
    hash.update(&executable.frame_plan_digest);
    hashInt(&hash, u32, @intFromEnum(executable.root_call));
    hashInt(&hash, u16, executable.limits.max_inline_depth);
    hashInt(&hash, u32, executable.limits.max_inline_invocations);
    hashInt(&hash, u32, executable.limits.max_instructions);
    hashInt(&hash, u32, executable.limits.max_registers);
    hashInt(&hash, u16, executable.input_count);
    hashInt(&hash, u16, executable.output_count);
    hashInt(&hash, u32, executable.expanded_inline_invocations);
    hashInt(&hash, u32, executable.register_count);
    hashInt(&hash, u32, @intCast(executable.instructions.len));
    for (executable.instructions) |instruction| {
        hashInt(&hash, u8, @intFromEnum(instruction.opcode));
        hashInt(&hash, u32, instruction.operand_a);
        hashInt(&hash, u32, instruction.operand_b);
        hashInt(&hash, u32, instruction.operand_c);
    }
    hashInt(&hash, u32, @intCast(executable.output_registers.len));
    for (executable.output_registers) |register|
        hashInt(&hash, u32, register);
    if (executable.body_ownership_version != 0) {
        hashInt(&hash, u16, executable.body_ownership_version);
        hashInt(&hash, u32, @intCast(executable.constraint_checks.len));
        for (executable.constraint_checks) |check| {
            hashInt(&hash, u32, check.root_register);
            hashOptionalRegister(&hash, check.gate_register);
        }
    }
    return hash.finalResult();
}

fn semanticEqual(lhs: *const OwnedProgram, rhs: *const OwnedProgram) bool {
    return lhs.format_version == rhs.format_version and
        lhs.policy_version == rhs.policy_version and
        lhs.body_ownership_version == rhs.body_ownership_version and
        lhs.semantic_identity_format_version == rhs.semantic_identity_format_version and
        std.mem.eql(u8, &lhs.semantic_digest, &rhs.semantic_digest) and
        std.mem.eql(u8, &lhs.frame_plan_digest, &rhs.frame_plan_digest) and
        lhs.root_call == rhs.root_call and
        std.meta.eql(lhs.limits, rhs.limits) and
        lhs.input_count == rhs.input_count and
        lhs.output_count == rhs.output_count and
        lhs.expanded_inline_invocations == rhs.expanded_inline_invocations and
        lhs.register_count == rhs.register_count and
        slicesEql(Instruction, lhs.instructions, rhs.instructions) and
        slicesEql(ConstraintCheck, lhs.constraint_checks, rhs.constraint_checks) and
        std.mem.eql(u32, lhs.output_registers, rhs.output_registers) and
        std.mem.eql(u8, &lhs.program_digest, &rhs.program_digest);
}

fn itemRangeEnd(range: program.ItemRange) usize {
    return @as(usize, range.start) + @as(usize, range.len);
}

fn idFromIndex(comptime Id: type, index: usize) Id {
    return types.idFromIndex(Id, index) catch unreachable;
}

fn hashOptionalRegister(hash: *Sha256, register: ?u32) void {
    if (register) |present| {
        hashInt(hash, u8, 1);
        hashInt(hash, u32, present);
    } else {
        hashInt(hash, u8, 0);
    }
}

fn slicesEql(comptime T: type, lhs: []const T, rhs: []const T) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |left, right| {
        if (!std.meta.eql(left, right)) return false;
    }
    return true;
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn digestIsZero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

/// Narrow dependency surface for the allocation-heavy compiler shard. The
/// authoritative program ABI and validation rules stay in this module.
pub const CompilerHooks = struct {
    pub const hashProgram = functionBodyHashProgram;
    pub const idFromIndex = functionBodyIdFromIndex;
    pub const itemRangeEnd = functionBodyItemRangeEnd;
    pub const requireFieldScalars = functionBodyRequireFieldScalars;
    pub const validateInlineGraph = functionBodyValidateInlineGraph;
    pub const validateInstruction = functionBodyValidateInstruction;
};

const functionBodyHashProgram = hashProgram;
const functionBodyIdFromIndex = idFromIndex;
const functionBodyItemRangeEnd = itemRangeEnd;
const functionBodyRequireFieldScalars = requireFieldScalars;
const functionBodyValidateInlineGraph = validateInlineGraph;
const functionBodyValidateInstruction = validateInstruction;

//! Allocation-heavy compiler for authenticated inline function bodies.
//!
//! The stable program ABI, validation, and allocation-free executor remain in
//! `function_body_lowering.zig`; this shard owns canonical SSA construction.

const std = @import("std");
const expr = @import("expr.zig");
const frames = @import("function_frames.zig");
const functions = @import("functions.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const types = @import("types.zig");

pub fn compileInternal(
    comptime api: type,
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    frame_plan: *const frames.OwnedPlan,
    root_call: types.CallId,
    limits: api.Limits,
    owned_body: bool,
) api.CompileError!api.OwnedProgram {
    const Impl = Implementation(api);
    const Compiler = Impl.Compiler;
    const OwnedProgram = api.OwnedProgram;
    const Range = Impl.Range;
    const BODY_OWNERSHIP_VERSION = api.BODY_OWNERSHIP_VERSION;
    const FORMAT_VERSION = api.FORMAT_VERSION;
    const HARD_MAX_ARGUMENTS = api.HARD_MAX_ARGUMENTS;
    const HARD_MAX_OUTPUTS = api.HARD_MAX_OUTPUTS;
    const POLICY_VERSION = api.POLICY_VERSION;
    const hashProgram = api.CompilerHooks.hashProgram;
    const requireFieldScalars = api.CompilerHooks.requireFieldScalars;
    const validateInlineGraph = api.CompilerHooks.validateInlineGraph;
    try limits.validate();
    const root = functions.getCall(arena, root_call) orelse
        return error.InvalidCall;
    if (root.caller != null or root.strategy != .inline_expansion)
        return error.RootCallMustBePublicInline;
    const root_arguments = functions.callArguments(arena, root_call) orelse
        return error.InvalidCall;
    const root_outputs = functions.callOutputs(arena, root_call) orelse
        return error.InvalidCall;
    if (root_arguments.len > HARD_MAX_ARGUMENTS or
        root_outputs.len > HARD_MAX_OUTPUTS)
    {
        return error.InvalidCall;
    }
    try requireFieldScalars(arena, root_arguments);

    if (owned_body) {
        if (frame_plan.body_ownership_version != frames.BODY_OWNERSHIP_VERSION)
            return error.UnownedFunctionBody;
    } else if (frame_plan.body_ownership_version != 0) {
        return error.FunctionBodyRequiresOwnedLowering;
    }

    // This explicit graph walk gives corrupted/cyclic programs a deterministic
    // failure before the broader frame-plan recompile reports identity drift.
    try validateInlineGraph(allocator, arena, root.callee, limits);
    try frame_plan.validateAgainst(allocator, arena);

    var compiler = Compiler.init(
        allocator,
        arena,
        limits,
        @intCast(root_arguments.len),
        owned_body,
    );
    defer compiler.deinit();

    const argument_start = compiler.context_registers.items.len;
    for (root_arguments, 0..) |_, index| {
        try compiler.context_registers.append(allocator, @intCast(index));
    }
    const root_context = try compiler.appendContext(.{
        .function = root.callee,
        .arguments = try Range.init(argument_start, root_arguments.len),
        .depth = 1,
        .parent = null,
    });
    if (owned_body) try compiler.compileContextBody(root_context);

    const function_outputs = functions.outputs(arena, root.callee) orelse
        return error.InvalidFunction;
    if (function_outputs.len != root_outputs.len) return error.InvalidCall;
    for (function_outputs) |value| {
        try compiler.final_outputs.append(
            allocator,
            try compiler.compileValue(root_context, value),
        );
    }

    const instructions = try compiler.instructions.toOwnedSlice(allocator);
    var instructions_owned = true;
    errdefer if (instructions_owned) allocator.free(instructions);
    const constraint_checks = try compiler.constraint_checks.toOwnedSlice(allocator);
    var constraints_owned = true;
    errdefer if (constraints_owned) allocator.free(constraint_checks);
    const output_registers = try compiler.final_outputs.toOwnedSlice(allocator);
    var outputs_owned = true;
    errdefer if (outputs_owned) allocator.free(output_registers);

    const register_count = std.math.add(
        usize,
        root_arguments.len,
        instructions.len,
    ) catch return error.CountOverflow;
    if (register_count > limits.max_registers)
        return error.RegisterLimitExceeded;

    var result = OwnedProgram{
        .allocator = allocator,
        .format_version = FORMAT_VERSION,
        .policy_version = POLICY_VERSION,
        .body_ownership_version = if (owned_body) BODY_OWNERSHIP_VERSION else 0,
        .semantic_identity_format_version = frame_plan.semantic_identity_format_version,
        .semantic_digest = frame_plan.semantic_digest,
        .frame_plan_digest = frame_plan.plan_digest,
        .root_call = root_call,
        .limits = limits,
        .input_count = @intCast(root_arguments.len),
        .output_count = @intCast(root_outputs.len),
        .expanded_inline_invocations = @intCast(compiler.contexts.items.len),
        .register_count = @intCast(register_count),
        .instructions = instructions,
        .constraint_checks = constraint_checks,
        .output_registers = output_registers,
        .program_digest = .{0} ** 32,
    };
    instructions_owned = false;
    constraints_owned = false;
    outputs_owned = false;
    errdefer result.deinit();
    result.program_digest = hashProgram(&result);
    try result.validate();
    return result;
}

fn Implementation(comptime api: type) type {
    return struct {
        const CompileError = api.CompileError;
        const ConstraintCheck = api.ConstraintCheck;
        const Instruction = api.Instruction;
        const Limits = api.Limits;
        const Opcode = api.Opcode;
        const ValidationError = api.ValidationError;
        const idFromIndex = api.CompilerHooks.idFromIndex;
        const itemRangeEnd = api.CompilerHooks.itemRangeEnd;
        const requireFieldScalars = api.CompilerHooks.requireFieldScalars;
        const validateInstruction = api.CompilerHooks.validateInstruction;

        const Range = struct {
            start: u32,
            len: u32,

            fn init(start: usize, len: usize) ValidationError!Range {
                return .{
                    .start = std.math.cast(u32, start) orelse return error.CountOverflow,
                    .len = std.math.cast(u32, len) orelse return error.CountOverflow,
                };
            }

            fn slice(self: Range, values: []const u32) ?[]const u32 {
                const start: usize = self.start;
                const len: usize = self.len;
                const end = std.math.add(usize, start, len) catch return null;
                if (end > values.len) return null;
                return values[start..end];
            }
        };

        const Context = struct {
            function: types.FunctionId,
            arguments: Range,
            depth: u16,
            parent: ?u32,
        };

        const MemoKey = struct {
            context: u32,
            value: u32,
        };

        const CallKey = struct {
            context: u32,
            call: u32,
        };

        const InstructionKey = struct {
            opcode: Opcode,
            operand_a: u32,
            operand_b: u32,
            operand_c: u32,
        };

        const Compiler = struct {
            allocator: std.mem.Allocator,
            arena: *const ir.Arena,
            limits: Limits,
            input_count: u32,
            owned_body: bool,
            instructions: std.ArrayList(Instruction),
            constraint_checks: std.ArrayList(ConstraintCheck),
            instruction_intern: std.AutoHashMap(InstructionKey, u32),
            contexts: std.ArrayList(Context),
            context_registers: std.ArrayList(u32),
            memo: std.AutoHashMap(MemoKey, u32),
            call_expansions: std.AutoHashMap(CallKey, Range),
            call_output_registers: std.ArrayList(u32),
            final_outputs: std.ArrayList(u32),

            fn init(
                allocator: std.mem.Allocator,
                arena: *const ir.Arena,
                limits: Limits,
                input_count: u32,
                owned_body: bool,
            ) Compiler {
                return .{
                    .allocator = allocator,
                    .arena = arena,
                    .limits = limits,
                    .input_count = input_count,
                    .owned_body = owned_body,
                    .instructions = .empty,
                    .constraint_checks = .empty,
                    .instruction_intern = std.AutoHashMap(InstructionKey, u32).init(allocator),
                    .contexts = .empty,
                    .context_registers = .empty,
                    .memo = std.AutoHashMap(MemoKey, u32).init(allocator),
                    .call_expansions = std.AutoHashMap(CallKey, Range).init(allocator),
                    .call_output_registers = .empty,
                    .final_outputs = .empty,
                };
            }

            fn deinit(self: *Compiler) void {
                self.final_outputs.deinit(self.allocator);
                self.call_output_registers.deinit(self.allocator);
                self.call_expansions.deinit();
                self.memo.deinit();
                self.context_registers.deinit(self.allocator);
                self.contexts.deinit(self.allocator);
                self.instruction_intern.deinit();
                self.constraint_checks.deinit(self.allocator);
                self.instructions.deinit(self.allocator);
                self.* = undefined;
            }

            fn appendContext(self: *Compiler, context: Context) CompileError!u32 {
                if (self.contexts.items.len >= self.limits.max_inline_invocations)
                    return error.InlineInvocationLimitExceeded;
                if (context.depth == 0 or context.depth > self.limits.max_inline_depth)
                    return error.InlineDepthExceeded;
                const index = std.math.cast(u32, self.contexts.items.len) orelse
                    return error.CountOverflow;
                try self.contexts.append(self.allocator, context);
                return index;
            }

            /// Compile every proof-bearing record owned by one concrete invocation.
            /// Calls are expanded even when no output is read, closing the dead-call
            /// escape hatch. Constraints are appended in stable body order after all
            /// nested calls, yielding one deterministic post-order check tape.
            fn compileContextBody(
                self: *Compiler,
                context_index: u32,
            ) CompileError!void {
                if (!self.owned_body) return error.UnownedFunctionBody;
                const context_usize: usize = context_index;
                if (context_usize >= self.contexts.items.len)
                    return error.InvalidFunction;
                const context = self.contexts.items[context_usize];
                const declaration = functions.get(self.arena, context.function) orelse
                    return error.InvalidFunction;
                const body = declaration.body orelse return error.UnownedFunctionBody;
                if (body.effects.len != 0) return error.UnsupportedEffect;
                if (body.hints.len != 0) return error.UnsupportedHint;

                for (@as(usize, body.calls.start)..itemRangeEnd(body.calls)) |call_index| {
                    _ = try self.expandCall(
                        context_index,
                        idFromIndex(types.CallId, call_index),
                    );
                }
                for (@as(usize, body.constraints.start)..itemRangeEnd(body.constraints)) |constraint_index| {
                    const constraint = self.arena.constraintsView()[constraint_index];
                    const root_register = try self.compileValue(context_index, constraint.root);
                    const gate_register = if (constraint.gate) |gate|
                        try self.compileValue(context_index, gate)
                    else
                        null;
                    try self.constraint_checks.append(self.allocator, .{
                        .root_register = root_register,
                        .gate_register = gate_register,
                    });
                }
            }

            fn compileValue(
                self: *Compiler,
                context_index: u32,
                value: types.ValueId,
            ) CompileError!u32 {
                const key = MemoKey{
                    .context = context_index,
                    .value = @intFromEnum(value),
                };
                if (self.memo.get(key)) |existing| return existing;
                const context_usize: usize = context_index;
                if (context_usize >= self.contexts.items.len)
                    return error.InvalidFunction;
                const context = self.contexts.items[context_usize];
                const node = self.arena.node(value) orelse return error.InvalidFunction;
                if (!node.key.ty.isFieldScalar()) return error.NonFieldValue;

                const register = switch (node.key.op) {
                    .constant => |constant| try self.internInstruction(.{
                        .opcode = .constant,
                        .operand_a = switch (constant) {
                            .field => |canonical| canonical,
                            .unsigned => |canonical| canonical,
                        },
                        .operand_b = 0,
                        .operand_c = 0,
                    }),
                    .input => try self.inputRegister(context, value),
                    .add => |binary_op| try self.binary(
                        context_index,
                        .add,
                        binary_op,
                        true,
                    ),
                    .sub => |binary_op| try self.binary(
                        context_index,
                        .sub,
                        binary_op,
                        false,
                    ),
                    .mul => |binary_op| try self.binary(
                        context_index,
                        .mul,
                        binary_op,
                        true,
                    ),
                    .neg => |operand| try self.internInstruction(.{
                        .opcode = .neg,
                        .operand_a = try self.compileValue(context_index, operand),
                        .operand_b = 0,
                        .operand_c = 0,
                    }),
                    .select => |selection| blk: {
                        const selector = try self.compileValue(context_index, selection.selector);
                        const when_true = try self.compileValue(context_index, selection.when_true);
                        const when_false = try self.compileValue(context_index, selection.when_false);
                        break :blk try self.internInstruction(.{
                            .opcode = .select,
                            .operand_a = selector,
                            .operand_b = when_true,
                            .operand_c = when_false,
                        });
                    },
                    .call_output => |output| try self.callOutputRegister(
                        context_index,
                        output,
                    ),
                    .hint_output => return error.UnsupportedHint,
                    .machine_derived => return error.UnsupportedMachineDerived,
                };
                try self.memo.put(key, register);
                return register;
            }

            fn inputRegister(
                self: *Compiler,
                context: Context,
                value: types.ValueId,
            ) CompileError!u32 {
                const declared = functions.inputs(self.arena, context.function) orelse
                    return error.InvalidFunction;
                const arguments = context.arguments.slice(self.context_registers.items) orelse
                    return error.InvalidFunction;
                if (arguments.len != declared.len) return error.InvalidFunction;
                const position = std.mem.indexOfScalar(types.ValueId, declared, value) orelse
                    return error.InvalidFunction;
                return arguments[position];
            }

            fn binary(
                self: *Compiler,
                context_index: u32,
                opcode: Opcode,
                binary_op: expr.Binary,
                commutative: bool,
            ) CompileError!u32 {
                var lhs = try self.compileValue(context_index, binary_op.lhs);
                var rhs = try self.compileValue(context_index, binary_op.rhs);
                if (commutative and rhs < lhs) std.mem.swap(u32, &lhs, &rhs);
                return self.internInstruction(.{
                    .opcode = opcode,
                    .operand_a = lhs,
                    .operand_b = rhs,
                    .operand_c = 0,
                });
            }

            fn callOutputRegister(
                self: *Compiler,
                context_index: u32,
                output: program.CallOutput,
            ) CompileError!u32 {
                const range = try self.expandCall(context_index, output.call);
                const registers = range.slice(self.call_output_registers.items) orelse
                    return error.InvalidCall;
                const output_index: usize = output.index;
                if (output_index >= registers.len) return error.InvalidCall;
                return registers[output_index];
            }

            fn expandCall(
                self: *Compiler,
                parent_index: u32,
                call_id: types.CallId,
            ) CompileError!Range {
                const key = CallKey{
                    .context = parent_index,
                    .call = @intFromEnum(call_id),
                };
                if (self.call_expansions.get(key)) |existing| return existing;
                const parent_usize: usize = parent_index;
                if (parent_usize >= self.contexts.items.len) return error.InvalidCall;
                const parent = self.contexts.items[parent_usize];
                const call = functions.getCall(self.arena, call_id) orelse
                    return error.InvalidCall;
                if (call.caller == null or call.caller.? != parent.function)
                    return error.InvalidCall;
                if (call.strategy != .inline_expansion)
                    return error.RelationBackedCall;
                if (types.idIndex(call.callee) >= types.idIndex(parent.function))
                    return error.NonTopologicalInlineCall;
                if (self.hasAncestor(parent_index, call.callee))
                    return error.InlineCycle;
                const next_depth = std.math.add(u16, parent.depth, 1) catch
                    return error.InlineDepthExceeded;
                if (next_depth > self.limits.max_inline_depth)
                    return error.InlineDepthExceeded;

                const arguments = functions.callArguments(self.arena, call_id) orelse
                    return error.InvalidCall;
                const declared = functions.inputs(self.arena, call.callee) orelse
                    return error.InvalidFunction;
                if (arguments.len != declared.len) return error.InvalidCall;
                try requireFieldScalars(self.arena, declared);
                var compiled_arguments: std.ArrayList(u32) = .empty;
                defer compiled_arguments.deinit(self.allocator);
                try compiled_arguments.ensureTotalCapacity(self.allocator, arguments.len);
                for (arguments) |argument| {
                    try compiled_arguments.append(
                        self.allocator,
                        try self.compileValue(parent_index, argument),
                    );
                }
                const argument_start = self.context_registers.items.len;
                try self.context_registers.appendSlice(self.allocator, compiled_arguments.items);
                const child_index = try self.appendContext(.{
                    .function = call.callee,
                    .arguments = try Range.init(argument_start, arguments.len),
                    .depth = next_depth,
                    .parent = parent_index,
                });
                if (self.owned_body) try self.compileContextBody(child_index);

                const outputs = functions.outputs(self.arena, call.callee) orelse
                    return error.InvalidFunction;
                const call_outputs = functions.callOutputs(self.arena, call_id) orelse
                    return error.InvalidCall;
                if (outputs.len != call_outputs.len) return error.InvalidCall;
                var compiled_outputs: std.ArrayList(u32) = .empty;
                defer compiled_outputs.deinit(self.allocator);
                try compiled_outputs.ensureTotalCapacity(self.allocator, outputs.len);
                for (outputs) |value| {
                    try compiled_outputs.append(
                        self.allocator,
                        try self.compileValue(child_index, value),
                    );
                }
                const output_start = self.call_output_registers.items.len;
                try self.call_output_registers.appendSlice(self.allocator, compiled_outputs.items);
                const result = try Range.init(output_start, outputs.len);
                try self.call_expansions.put(key, result);
                return result;
            }

            fn hasAncestor(
                self: *const Compiler,
                context_index: u32,
                function: types.FunctionId,
            ) bool {
                var cursor: ?u32 = context_index;
                while (cursor) |index| {
                    const item = self.contexts.items[index];
                    if (item.function == function) return true;
                    cursor = item.parent;
                }
                return false;
            }

            fn internInstruction(
                self: *Compiler,
                instruction: Instruction,
            ) CompileError!u32 {
                const key = InstructionKey{
                    .opcode = instruction.opcode,
                    .operand_a = instruction.operand_a,
                    .operand_b = instruction.operand_b,
                    .operand_c = instruction.operand_c,
                };
                if (self.instruction_intern.get(key)) |existing| return existing;
                if (self.instructions.items.len >= self.limits.max_instructions)
                    return error.InstructionLimitExceeded;
                const destination = std.math.add(
                    usize,
                    self.input_count,
                    self.instructions.items.len,
                ) catch return error.CountOverflow;
                if (destination >= self.limits.max_registers)
                    return error.RegisterLimitExceeded;
                const register = std.math.cast(u32, destination) orelse
                    return error.CountOverflow;
                try validateInstruction(instruction, destination);
                try self.instructions.append(self.allocator, instruction);
                errdefer _ = self.instructions.pop();
                try self.instruction_intern.put(key, register);
                return register;
            }
        };
    };
}

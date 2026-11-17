const std = @import("std");
const program_mod = @import("program.zig");
const arena_plan = @import("stwo_backend_contracts").arena_plan;
const recovery = @import("stwo_backend_contracts").recovery;

/// Shared execution state for every output column of one recorded Cairo
/// witness program. The epoch runner is serial at this boundary, so one scratch
/// allocation is reused across all column recipes and all rows.
pub const ProgramState = struct {
    allocator: std.mem.Allocator,
    program: program_mod.Program,
    input_columns: []const []const u32,
    registers: []u32,
    deduce_args: []u32,
    tables: program_mod.TableContext,
    deduce: program_mod.DeduceContext,
    execution_runs: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        program: program_mod.Program,
        input_columns: []const []const u32,
        tables: program_mod.TableContext,
        deduce: program_mod.DeduceContext,
    ) !ProgramState {
        try program.validate();
        if (input_columns.len < program.n_inputs) return error.InvalidInput;
        const registers = try allocator.alloc(u32, program.n_regs);
        errdefer allocator.free(registers);
        const deduce_args = try allocator.alloc(u32, program.n_regs);
        return .{
            .allocator = allocator,
            .program = program,
            .input_columns = input_columns,
            .registers = registers,
            .deduce_args = deduce_args,
            .tables = tables,
            .deduce = deduce,
        };
    }

    pub fn deinit(self: *ProgramState) void {
        self.allocator.free(self.registers);
        self.allocator.free(self.deduce_args);
        self.* = undefined;
    }
};

pub const ColumnRecipe = struct {
    state: *ProgramState,
    column_index: u32,

    pub fn recipe(self: *ColumnRecipe, logical_id: u32) recovery.Recipe {
        return .{ .logical_id = logical_id, .context = self, .run = run };
    }

    fn run(raw: *anyopaque, _: u16, binding: arena_plan.Binding, destination_bytes: []u8) !void {
        const self: *ColumnRecipe = @ptrCast(@alignCast(raw));
        if (destination_bytes.len % @sizeOf(u32) != 0) return recovery.RecoveryError.BindingSizeMismatch;
        const aligned: []align(@alignOf(u32)) u8 = @alignCast(destination_bytes);
        const destination = std.mem.bytesAsSlice(u32, aligned);
        if (binding.size_bytes != destination_bytes.len) return recovery.RecoveryError.BindingSizeMismatch;
        try program_mod.executeColumn(
            self.state.program,
            self.state.input_columns,
            self.column_index,
            destination,
            self.state.registers,
            self.state.deduce_args,
            self.state.tables,
            self.state.deduce,
        );
    }
};

/// One grouped recipe covers every BaseTrace binding produced by a component.
/// The first hook in a tick executes the program for all columns; the remaining
/// hooks observe `last_tick` and do no duplicate work.
pub const ComponentRecipe = struct {
    allocator: std.mem.Allocator,
    state: *ProgramState,
    access: recovery.BufferAccess,
    output_bindings: []const arena_plan.Binding,
    lookup_binding: ?arena_plan.Binding,
    sub_binding: ?arena_plan.Binding,
    multiplicity_bindings: []const arena_plan.Binding,
    destinations: [][]u32,
    multiplicity_destinations: [][]u32,
    last_tick: ?u16 = null,

    pub fn init(
        allocator: std.mem.Allocator,
        state: *ProgramState,
        access: recovery.BufferAccess,
        output_bindings: []const arena_plan.Binding,
    ) !ComponentRecipe {
        return initWithAux(allocator, state, access, output_bindings, null, null, &.{});
    }

    pub fn initWithAux(
        allocator: std.mem.Allocator,
        state: *ProgramState,
        access: recovery.BufferAccess,
        output_bindings: []const arena_plan.Binding,
        lookup_binding: ?arena_plan.Binding,
        sub_binding: ?arena_plan.Binding,
        multiplicity_bindings: []const arena_plan.Binding,
    ) !ComponentRecipe {
        if (output_bindings.len != state.program.n_cols) return error.WitnessShapeMismatch;
        if ((lookup_binding == null) != (state.program.n_lookup_words == 0) or
            (sub_binding == null) != (state.program.n_sub_words == 0) or
            multiplicity_bindings.len != state.program.n_mult_tables)
            return error.WitnessShapeMismatch;
        const destinations = try allocator.alloc([]u32, output_bindings.len);
        errdefer allocator.free(destinations);
        const multiplicity_destinations = try allocator.alloc([]u32, multiplicity_bindings.len);
        return .{
            .allocator = allocator,
            .state = state,
            .access = access,
            .output_bindings = output_bindings,
            .lookup_binding = lookup_binding,
            .sub_binding = sub_binding,
            .multiplicity_bindings = multiplicity_bindings,
            .destinations = destinations,
            .multiplicity_destinations = multiplicity_destinations,
        };
    }

    pub fn deinit(self: *ComponentRecipe) void {
        self.allocator.free(self.destinations);
        self.allocator.free(self.multiplicity_destinations);
        self.* = undefined;
    }

    pub fn makeRecipes(self: *ComponentRecipe, allocator: std.mem.Allocator) ![]recovery.Recipe {
        const count = self.output_bindings.len + @intFromBool(self.lookup_binding != null) +
            @intFromBool(self.sub_binding != null) + self.multiplicity_bindings.len;
        const recipes = try allocator.alloc(recovery.Recipe, count);
        var index: usize = 0;
        for (self.output_bindings) |binding| {
            recipes[index] = .{ .logical_id = binding.logical_id, .context = self, .run = run };
            index += 1;
        }
        if (self.lookup_binding) |binding| {
            recipes[index] = .{ .logical_id = binding.logical_id, .context = self, .run = run };
            index += 1;
        }
        if (self.sub_binding) |binding| {
            recipes[index] = .{ .logical_id = binding.logical_id, .context = self, .run = run };
            index += 1;
        }
        for (self.multiplicity_bindings) |binding| {
            recipes[index] = .{ .logical_id = binding.logical_id, .context = self, .run = run };
            index += 1;
        }
        std.debug.assert(index == recipes.len);
        return recipes;
    }

    fn run(raw: *anyopaque, tick: u16, requested: arena_plan.Binding, _: []u8) !void {
        const self: *ComponentRecipe = @ptrCast(@alignCast(raw));
        if (self.last_tick == tick) return;
        var requested_found = false;
        for (self.output_bindings, self.destinations) |binding, *destination| {
            requested_found = requested_found or binding.logical_id == requested.logical_id;
            const bytes = try self.access.bytes(binding);
            if (bytes.len != binding.size_bytes or bytes.len % @sizeOf(u32) != 0)
                return recovery.RecoveryError.BindingSizeMismatch;
            const aligned: []align(@alignOf(u32)) u8 = @alignCast(bytes);
            destination.* = std.mem.bytesAsSlice(u32, aligned);
        }
        if (self.lookup_binding) |binding| requested_found = requested_found or binding.logical_id == requested.logical_id;
        if (self.sub_binding) |binding| requested_found = requested_found or binding.logical_id == requested.logical_id;
        for (self.multiplicity_bindings) |binding| requested_found = requested_found or binding.logical_id == requested.logical_id;
        if (!requested_found) return recovery.RecoveryError.MissingRecipe;
        var lookup_words: []u32 = @constCast(&[_]u32{});
        if (self.lookup_binding) |binding| lookup_words = try words(self.access, binding);
        var sub_words: []u32 = @constCast(&[_]u32{});
        if (self.sub_binding) |binding| sub_words = try words(self.access, binding);
        for (self.multiplicity_bindings, self.multiplicity_destinations) |binding, *destination| {
            destination.* = try words(self.access, binding);
        }
        const auxiliary: ?program_mod.AuxiliaryOutputs = if (self.lookup_binding != null or self.sub_binding != null or self.multiplicity_bindings.len != 0)
            .{ .lookup_words = lookup_words, .sub_words = sub_words, .multiplicity_tables = self.multiplicity_destinations }
        else
            null;
        try program_mod.executeAll(
            self.state.program,
            self.state.input_columns,
            self.destinations,
            auxiliary,
            self.state.registers,
            self.state.deduce_args,
            self.state.tables,
            self.state.deduce,
        );
        self.state.execution_runs += 1;
        self.last_tick = tick;
    }

    fn words(access: recovery.BufferAccess, binding: arena_plan.Binding) ![]u32 {
        const bytes = try access.bytes(binding);
        if (bytes.len != binding.size_bytes or bytes.len % @sizeOf(u32) != 0)
            return recovery.RecoveryError.BindingSizeMismatch;
        const aligned: []align(@alignOf(u32)) u8 = @alignCast(bytes);
        return std.mem.bytesAsSlice(u32, aligned);
    }
};

test "Cairo recovery: recorded witness column refills its arena binding" {
    const insts = [_]program_mod.Inst{
        .{ .op = @intFromEnum(program_mod.Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(program_mod.Op.constant), .dst = 1, .a = 0, .b = 0, .imm = 5 },
        .{ .op = @intFromEnum(program_mod.Op.u32_mul), .dst = 2, .a = 0, .b = 1, .imm = 0 },
        .{ .op = @intFromEnum(program_mod.Op.col_write), .dst = 0, .a = 2, .b = 0, .imm = 0 },
    };
    const program = program_mod.Program{ .insts = &insts, .n_regs = 3, .n_inputs = 1, .n_cols = 1, .n_mult_tables = 0, .n_lookup_words = 0, .n_sub_words = 0 };
    const input = [_]u32{ 2, 3, 7, 11 };
    const input_columns = [_][]const u32{&input};
    var state = try ProgramState.init(std.testing.allocator, program, &input_columns, .zero(), .unsupported());
    defer state.deinit();
    var column_recipe = ColumnRecipe{ .state = &state, .column_index = 0 };
    var registry = try recovery.RecipeRegistry.init(std.testing.allocator, &.{column_recipe.recipe(41)});
    defer registry.deinit();
    var destination align(16) = [_]u32{0} ** input.len;
    const binding = arena_plan.Binding{
        .logical_id = 41,
        .slot = 0,
        .offset_bytes = 0,
        .size_bytes = @sizeOf(@TypeOf(destination)),
        .materialization = .recompute,
        .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
    };
    try registry.execute(1, binding, std.mem.sliceAsBytes(&destination));
    try std.testing.expectEqualSlices(u32, &.{ 10, 15, 35, 55 }, &destination);
    var failure: ?@import("stwo_core").error_codes.Entry = @import("stwo_backend_contracts").error_codes.fromRecovery(error.MissingRecipe);
    @memset(&destination, 0);
    try registry.executeDiagnosed(1, binding, std.mem.sliceAsBytes(&destination), &failure);
    try std.testing.expectEqualSlices(u32, &.{ 10, 15, 35, 55 }, &destination);
    try std.testing.expect(failure == null);
    var unaligned = binding;
    unaligned.size_bytes = 3;
    var three: [3]u8 = @splat(0);
    try std.testing.expectError(error.BindingSizeMismatch, registry.executeDiagnosed(1, unaligned, &three, &failure));
    try std.testing.expect(failure == null); // Actual Cairo callback, not registry admission.
}

test "Cairo recovery: grouped recipe executes once for every component column" {
    const insts = [_]program_mod.Inst{
        .{ .op = @intFromEnum(program_mod.Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(program_mod.Op.constant), .dst = 1, .a = 0, .b = 0, .imm = 2 },
        .{ .op = @intFromEnum(program_mod.Op.u32_add), .dst = 2, .a = 0, .b = 1, .imm = 0 },
        .{ .op = @intFromEnum(program_mod.Op.col_write), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(program_mod.Op.col_write), .dst = 0, .a = 2, .b = 0, .imm = 1 },
    };
    const program = program_mod.Program{ .insts = &insts, .n_regs = 3, .n_inputs = 1, .n_cols = 2, .n_mult_tables = 0, .n_lookup_words = 0, .n_sub_words = 0 };
    const input = [_]u32{ 3, 5, 8, 13 };
    const input_columns = [_][]const u32{&input};
    var state = try ProgramState.init(std.testing.allocator, program, &input_columns, .zero(), .unsupported());
    defer state.deinit();
    var storage align(16) = [_]u32{0} ** 8;
    const Access = struct {
        storage: *[8]u32,
        fn bytes(raw: *anyopaque, binding: arena_plan.Binding) ![]u8 {
            const self: *@This() = @ptrCast(@alignCast(raw));
            const start: usize = @intCast(binding.offset_bytes / 4);
            return std.mem.sliceAsBytes(self.storage[start .. start + @as(usize, @intCast(binding.size_bytes / 4))]);
        }
    };
    var access_context = Access{ .storage = &storage };
    const occupied = [_]u64{0} ** (arena_plan.max_ticks / 64);
    const bindings = [_]arena_plan.Binding{
        .{ .logical_id = 10, .slot = 0, .offset_bytes = 0, .size_bytes = 16, .materialization = .recompute, .occupied = occupied },
        .{ .logical_id = 11, .slot = 1, .offset_bytes = 16, .size_bytes = 16, .materialization = .recompute, .occupied = occupied },
    };
    var grouped = try ComponentRecipe.init(
        std.testing.allocator,
        &state,
        .{ .context = &access_context, .bytes_fn = Access.bytes },
        &bindings,
    );
    defer grouped.deinit();
    const recipes = try grouped.makeRecipes(std.testing.allocator);
    defer std.testing.allocator.free(recipes);
    var registry = try recovery.RecipeRegistry.init(std.testing.allocator, recipes);
    defer registry.deinit();
    try registry.execute(7, bindings[0], std.mem.sliceAsBytes(storage[0..4]));
    try registry.execute(7, bindings[1], std.mem.sliceAsBytes(storage[4..8]));
    try std.testing.expectEqual(@as(u64, 1), state.execution_runs);
    try std.testing.expectEqualSlices(u32, &input, storage[0..4]);
    try std.testing.expectEqualSlices(u32, &.{ 5, 7, 10, 15 }, storage[4..8]);
}

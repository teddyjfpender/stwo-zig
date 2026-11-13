//! Native typed AIR authorship for compatibility-exact RV32 FENCE.
//!
//! FENCE is a single-hart state-only no-op, but its reserved encoding fields
//! remain part of the authenticated program tuple. This definition owns those
//! six committed fields, both direct roots, and all three ordered effects.

const std = @import("std");
const constraints_mod = @import("typed_fence_constraints.zig");
const digest = @import("digest.zig");
const effects = @import("effects.zig");
const instruction_effects = @import("instruction_effects.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate_mod = @import("validate.zig");

pub const MAIN_COLUMN_COUNT: usize = 6;
pub const DIRECT_CONSTRAINT_COUNT = constraints_mod.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = 3;
pub const OPCODE_ID: u32 = 45;
pub const SEMANTIC_DIGEST_HEX =
    "ed5fd16042ad5918b843e6afd45393d527b0dfb3dfba2dcf29fe93caf041d3f2";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid typed FENCE semantic digest",
);

pub const Location = union(enum) {
    generated,
    file: struct {
        path: []const u8,
        start: source.Position,
        end: source.Position,
    },

    fn install(self: Location, arena: *ir.Arena) !source.SourceSpan {
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
    enabler: types.ValueId,
    clock: types.ValueId,
    pc: types.ValueId,
    rd: types.ValueId,
    rs1: types.ValueId,
    immediate: types.ValueId,

    pub fn physical(self: Columns) [MAIN_COLUMN_COUNT]types.ValueId {
        return .{ self.enabler, self.clock, self.pc, self.rd, self.rs1, self.immediate };
    }
};

pub const Events = struct {
    program_fetch: types.EffectId,
    retirement: instruction_effects.SequentialRetirement,
};

pub const ValidationError = validate_mod.Error || relation.Error || error{
    InvalidFenceDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
    model: constraints_mod.Result,
    events: Events,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const identity = try digest.computeIdentity(&self.arena);
        if (identity.format_version != digest.sequential_retirement_format_version or
            !std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != LOOKUP_COUNT or
            self.arena.range_refinements.items.len != 0 or
            self.arena.fixed_table_requests.items.len != 0)
        {
            return error.InvalidFenceDefinition;
        }

        for (self.columns.physical(), 0..) |value, index| {
            if (types.idIndex(value) != index) return error.InvalidFenceDefinition;
        }
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT)
            return error.InvalidFenceDefinition;
        var input_count: usize = 0;
        for (self.arena.nodesView()) |node| switch (node.key.op) {
            .input => input_count += 1,
            else => {},
        };
        if (input_count != MAIN_COLUMN_COUNT + 1)
            return error.InvalidFenceDefinition;

        for (self.model.constraints, self.model.roots, 0..) |id, root, index| {
            if (types.idIndex(id) != index) return error.InvalidFenceDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidFenceDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidFenceDefinition;
            }
            var name_buffer: [64]u8 = undefined;
            const expected = std.fmt.bufPrint(
                &name_buffer,
                "compat.riscv.fence.direct.{d}",
                .{index},
            ) catch return error.InvalidFenceDefinition;
            const actual = self.arena.name(constraint.name) orelse
                return error.InvalidFenceDefinition;
            if (!std.mem.eql(u8, expected, actual))
                return error.InvalidFenceDefinition;
        }

        const expected_ids = self.orderedEventIds();
        for (self.arena.effectsView(), expected_shapes, expected_ids, 0..) |
            effect,
            shape,
            id,
            index,
        | {
            if (types.idIndex(id) != index) return error.InvalidFenceDefinition;
            const binding = effect.binding orelse return error.InvalidFenceDefinition;
            const values = self.arena.effectValues(id) orelse
                return error.InvalidFenceDefinition;
            if (effect.kind != shape.kind or
                binding.schema != relation.id(shape.domain) or
                binding.role != shape.role or
                values.len != shape.arity or
                effect.access_ordinal != null or
                effect.liveness != self.columns.enabler)
            {
                return error.InvalidFenceDefinition;
            }
            _ = try relation.validateEventShape(
                binding.schema,
                binding.role,
                values.len,
                null,
            );
        }
        const program_values = self.arena.effectValues(self.events.program_fetch) orelse
            return error.InvalidFenceDefinition;
        if (!std.mem.eql(types.ValueId, program_values, &.{
            self.columns.pc,
            self.model.opcode,
            self.columns.rd,
            self.columns.rs1,
            self.columns.immediate,
        })) return error.InvalidFenceDefinition;
    }

    pub fn orderedEventIds(self: *const Definition) [LOOKUP_COUNT]types.EffectId {
        return .{
            self.events.program_fetch,
            self.events.retirement.events.consume,
            self.events.retirement.events.produce,
        };
    }
};

const Shape = struct {
    kind: program.EffectKind,
    domain: relation.Domain,
    role: relation.Role,
    arity: u8,
};

const expected_shapes = [LOOKUP_COUNT]Shape{
    .{ .kind = .program_fetch, .domain = .program_access, .role = .request, .arity = 5 },
    .{ .kind = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2 },
    .{ .kind = .state_produce, .domain = .registers_state, .role = .emit, .arity = 2 },
};

pub fn build(allocator: std.mem.Allocator, location: Location) !Definition {
    var definition = try buildDefinition(allocator, location);
    errdefer definition.deinit();
    try definition.validate();
    return definition;
}

fn buildDefinition(allocator: std.mem.Allocator, location: Location) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = try location.install(&arena);
    const immediate_type = try types.Type.boundedField(12);
    const columns = Columns{
        .enabler = try arena.input("enabler", .bit, span),
        .clock = try arena.input("clock", .clock, span),
        .pc = try arena.input("pc", .pc, span),
        .rd = try arena.input("rd", .register_index, span),
        .rs1 = try arena.input("rs1", .register_index, span),
        .immediate = try arena.input("immediate", immediate_type, span),
    };
    const is_active = try arena.input("is_active", .selector, span);
    const model = try constraints_mod.author(&arena, columns.enabler, is_active, span);
    const program_fetch = try effects.programFetch(&arena, .{
        .pc = columns.pc,
        .opcode_id = model.opcode,
        .rd = columns.rd,
        .rs1 = columns.rs1,
        .operand = columns.immediate,
    }, columns.enabler, span);
    const retirement = try instruction_effects.retireSequential(
        &arena,
        .{ .pc = columns.pc, .clock = columns.clock },
        columns.enabler,
        span,
    );
    return .{
        .arena = arena,
        .columns = columns,
        .is_active = is_active,
        .model = model,
        .events = .{ .program_fetch = program_fetch, .retirement = retirement },
    };
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

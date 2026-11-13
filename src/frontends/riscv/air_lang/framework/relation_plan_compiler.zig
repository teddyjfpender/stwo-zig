//! Authenticated relation-DAG input checks, reachability and exact evaluation-tape compilation.

pub fn For(comptime owner_context: anytype) type {
    const machine = owner_context.machine;
    const AuthenticationError = owner_context.AuthenticationError;
    const BatchPlan = owner_context.BatchPlan;
    const BinarySlots = owner_context.BinarySlots;
    const Error = owner_context.Error;
    const EvalNode = owner_context.EvalNode;
    const EvalOp = owner_context.EvalOp;
    const EventPlan = owner_context.EventPlan;
    const FORMAT_VERSION = owner_context.FORMAT_VERSION;
    const MAX_ARENA_NODES = owner_context.MAX_ARENA_NODES;
    const MAX_ARITY = owner_context.MAX_ARITY;
    const MAX_COMPILED_NODES = owner_context.MAX_COMPILED_NODES;
    const NO_SLOT = owner_context.NO_SLOT;
    const digest = owner_context.digest;
    const emptyEvalNode = owner_context.emptyEvalNode;
    const emptyEventPlan = owner_context.emptyEventPlan;
    const expr = owner_context.expr;
    const ir = owner_context.ir;
    const lower_effects = owner_context.lower_effects;
    const relation = owner_context.relation;
    const std = owner_context.std;
    const types = owner_context.types;
    const LOGICAL_INPUT_COUNT = owner_context.LOGICAL_INPUT_COUNT;
    const EVENT_COUNT = owner_context.EVENT_COUNT;
    const BATCH_COUNT = owner_context.BATCH_COUNT;
    const BATCH_SIZE = owner_context.BATCH_SIZE;
    const Plan = owner_context.Plan;
    const fixed_addresses = owner_context.fixed_addresses;
    const program_pcs = owner_context.program_pcs;
    const main_column_count = owner_context.main_column_count;
    return struct {
        const Visit = enum(u8) { unseen, active, done };
        pub fn compilePlan(
            arena: *const ir.Arena,
            expected_digest: digest.Digest,
            event_ids: [EVENT_COUNT]types.EffectId,
        ) AuthenticationError!Plan {
            const identity = try digest.computeIdentity(arena);
            if (!machine.supportedFormat(identity.format_version) or
                !std.mem.eql(u8, &identity.bytes, &expected_digest))
            {
                return error.BindingSealMismatch;
            }
            if (arena.effectsView().len != EVENT_COUNT)
                return error.EventPlanMismatch;
            if (arena.nodesView().len > MAX_ARENA_NODES)
                return error.ArenaNodeLimitExceeded;
            try validateInputs(arena);

            const lowered = try lower_effects.ValidatedProgram.init(arena);
            var required = [_]bool{false} ** MAX_ARENA_NODES;
            var events = [_]EventPlan{emptyEventPlan()} ** EVENT_COUNT;
            for (&events, event_ids, 0..) |*plan, effect_id, ordinal| {
                if (types.idIndex(effect_id) != ordinal)
                    return error.EventPlanMismatch;
                const event = lowered.event(effect_id) orelse
                    return error.EventPlanMismatch;
                const schema = relation.getById(event.schema) orelse
                    return error.EventPlanMismatch;
                _ = relation.requireExactUniversalSchema(schema.domain) catch
                    return error.EventPlanMismatch;
                const supported_kind = switch (event.kind) {
                    .component_call, .state_consume, .state_produce, .program_fetch => true,
                    else => false,
                };
                if (!supported_kind or
                    event.schema_version != schema.version or
                    event.access_ordinal != null or
                    event.values.len != schema.fields.len)
                {
                    return error.EventPlanMismatch;
                }
                try markExpression(arena, event.liveness, &required, .{});
                for (event.values) |value|
                    try markExpression(arena, value, &required, .{});
                plan.* = .{
                    .ordinal = @intCast(ordinal),
                    .effect = event.effect,
                    .schema = event.schema,
                    .schema_version = event.schema_version,
                    .domain = schema.domain,
                    .role = event.role,
                    .numerator_slot = NO_SLOT,
                    .value_slots = [_]u16{NO_SLOT} ** MAX_ARITY,
                    .arity = @intCast(event.values.len),
                };
            }

            var mapping = [_]u16{NO_SLOT} ** MAX_ARENA_NODES;
            for (0..LOGICAL_INPUT_COUNT) |index| mapping[index] = @intCast(index);
            var compiled_nodes = [_]EvalNode{emptyEvalNode()} ** MAX_COMPILED_NODES;
            var compiled_count: usize = 0;
            for (arena.nodesView(), 0..) |node, source_index| {
                if (source_index < LOGICAL_INPUT_COUNT or !required[source_index])
                    continue;
                if (compiled_count == MAX_COMPILED_NODES)
                    return error.CompiledNodeLimitExceeded;
                const destination_index = std.math.add(
                    usize,
                    LOGICAL_INPUT_COUNT,
                    compiled_count,
                ) catch return error.SlotOverflow;
                if (destination_index >= NO_SLOT) return error.SlotOverflow;
                const source_id = types.idFromIndex(types.ValueId, source_index) catch
                    return error.SlotOverflow;
                const destination: u16 = @intCast(destination_index);
                compiled_nodes[compiled_count] = .{
                    .source = source_id,
                    .destination = destination,
                    .op = try compileOp(node.key.op, &mapping),
                };
                mapping[source_index] = destination;
                compiled_count += 1;
            }

            for (&events, event_ids) |*plan, effect_id| {
                const event = lowered.event(effect_id) orelse
                    return error.EventPlanMismatch;
                plan.numerator_slot = try mappedSlot(event.liveness, &mapping);
                for (event.values, 0..) |value, index| {
                    plan.value_slots[index] = try mappedSlot(value, &mapping);
                }
            }

            var batches: [BATCH_COUNT]BatchPlan = undefined;
            for (&batches, 0..) |*batch, ordinal| {
                const first = ordinal * BATCH_SIZE;
                batch.* = .{
                    .ordinal = @intCast(ordinal),
                    .first = @intCast(first),
                    .second = if (BATCH_SIZE >= 2 and first + 1 < EVENT_COUNT)
                        @intCast(first + 1)
                    else
                        null,
                    .third = if (BATCH_SIZE >= 3 and first + 2 < EVENT_COUNT) @intCast(first + 2) else null,
                    .fourth = if (BATCH_SIZE >= 4 and first + 3 < EVENT_COUNT) @intCast(first + 3) else null,
                    .interaction_column_start = @intCast(4 * ordinal),
                };
            }
            return .{
                .format_version = FORMAT_VERSION,
                .semantic_format_version = identity.format_version,
                .semantic_digest = expected_digest,
                .registry_order_digest = relation.registryOrderDigest(),
                .compiled_node_count = @intCast(compiled_count),
                .compiled_nodes = compiled_nodes,
                .events = events,
                .batches = batches,
            };
        }

        pub fn validateInputs(arena: *const ir.Arena) Error!void {
            if (arena.nodesView().len < LOGICAL_INPUT_COUNT)
                return error.InvalidInputGeometry;
            for (fixed_addresses, 0..) |index, ordinal| {
                if (index < main_column_count or index >= LOGICAL_INPUT_COUNT or
                    (arena.nodesView()[index].key.ty != .address and arena.nodesView()[index].key.ty != .pc)) return error.InvalidInputGeometry;
                for (fixed_addresses[0..ordinal]) |earlier| if (earlier == index) return error.InvalidInputGeometry;
            }
            for (program_pcs, 0..) |index, ordinal| {
                if (index >= main_column_count or index >= LOGICAL_INPUT_COUNT or arena.nodesView()[index].key.ty != .pc) return error.InvalidInputGeometry;
                for (program_pcs[0..ordinal]) |earlier| if (earlier == index) return error.InvalidInputGeometry;
                const pc: types.ValueId = @enumFromInt(index);
                var active: ?types.ValueId = null;
                for (arena.effectsView()) |effect| {
                    const binding = effect.binding orelse continue;
                    const values = effect.values.slice(arena.effectValuesView()) orelse return error.InvalidInputGeometry;
                    if (binding.schema == relation.id(.program_access) and binding.role == .request and values.len == 5 and values[0] == pc) {
                        if (active != null and active != effect.liveness) return error.InvalidInputGeometry;
                        active = effect.liveness orelse return error.InvalidInputGeometry;
                    }
                }
                if (active == null) return error.InvalidInputGeometry;
                var dependent = [_]bool{false} ** MAX_ARENA_NODES;
                dependent[index] = true;
                for (arena.nodesView(), 0..) |node, node_index| {
                    const operands: [3]?types.ValueId = switch (node.key.op) {
                        .input, .constant => .{ null, null, null },
                        .add, .sub, .mul => |v| .{ v.lhs, v.rhs, null },
                        .neg => |v| .{ v, null, null },
                        .select => |v| .{ v.selector, v.when_true, v.when_false },
                        .machine_derived => |v| machine.operands(v),
                        .hint_output, .call_output => return error.UnsupportedRelationExpression,
                    };
                    for (operands) |operand| if (operand) |id| {
                        const source_index = types.idIndex(id);
                        if (source_index >= node_index) return error.InvalidInputGeometry;
                        dependent[node_index] = dependent[node_index] or dependent[source_index];
                    };
                }
                for (arena.effectsView()) |effect| {
                    const values = effect.values.slice(arena.effectValuesView()) orelse return error.InvalidInputGeometry;
                    for (values) |value| {
                        const value_index = types.idIndex(value);
                        if (value_index >= arena.nodesView().len) return error.InvalidInputGeometry;
                        if (dependent[value_index] and effect.liveness != active) return error.InvalidInputGeometry;
                    }
                }
            }
            for (arena.nodesView()[0..LOGICAL_INPUT_COUNT], 0..) |node, index| {
                switch (node.key.op) {
                    .input => {},
                    else => return error.InvalidInputGeometry,
                }
                const fixed_address = (node.key.ty == .address or node.key.ty == .pc) and std.mem.indexOfScalar(usize, fixed_addresses, index) != null;
                if (!node.key.ty.isFieldScalar() and !fixed_address and std.mem.indexOfScalar(usize, program_pcs, index) == null)
                    return error.InvalidInputGeometry;
            }
            for (arena.nodesView()[LOGICAL_INPUT_COUNT..]) |node| switch (node.key.op) {
                .input => return error.InvalidInputGeometry,
                else => {},
            };
        }

        pub fn markExpression(
            arena: *const ir.Arena,
            value: types.ValueId,
            required: *[MAX_ARENA_NODES]bool,
            _: struct {},
        ) Error!void {
            var visiting = [_]Visit{.unseen} ** MAX_ARENA_NODES;
            return markRecursive(arena, value, required, &visiting);
        }

        pub fn markRecursive(
            arena: *const ir.Arena,
            value: types.ValueId,
            required: *[MAX_ARENA_NODES]bool,
            visiting: *[MAX_ARENA_NODES]Visit,
        ) Error!void {
            const index = types.idIndex(value);
            if (index >= arena.nodesView().len or index >= MAX_ARENA_NODES)
                return error.EventPlanMismatch;
            if (index < LOGICAL_INPUT_COUNT) return;
            if (visiting[index] == .active) return error.ExpressionCycle;
            if (required[index] or visiting[index] == .done) return;
            visiting[index] = .active;
            const node = arena.node(value) orelse return error.EventPlanMismatch;
            switch (node.key.op) {
                .machine_derived => |v| {
                    for (machine.operands(v)) |operand| if (operand) |id| {
                        try markRecursive(arena, id, required, visiting);
                    };
                },
                .constant => {},
                .add, .sub, .mul => |binary| {
                    try markRecursive(arena, binary.lhs, required, visiting);
                    try markRecursive(arena, binary.rhs, required, visiting);
                },
                .neg => |operand| try markRecursive(arena, operand, required, visiting),
                .select => |selection| {
                    try markRecursive(arena, selection.selector, required, visiting);
                    try markRecursive(arena, selection.when_true, required, visiting);
                    try markRecursive(arena, selection.when_false, required, visiting);
                },
                else => return error.UnsupportedRelationExpression,
            }
            visiting[index] = .done;
            required[index] = true;
        }

        pub fn compileOp(
            op: expr.Op,
            mapping: *const [MAX_ARENA_NODES]u16,
        ) Error!EvalOp {
            return switch (op) {
                .constant => |constant| .{ .constant = switch (constant) {
                    .field => |value| value,
                    .unsigned => |value| value,
                } },
                .add => |binary| .{ .add = try compileBinary(binary, mapping) },
                .sub => |binary| .{ .sub = try compileBinary(binary, mapping) },
                .mul => |binary| .{ .mul = try compileBinary(binary, mapping) },
                .neg => |operand| .{ .neg = try mappedSlot(operand, mapping) },
                .select => |selection| .{ .select = .{
                    .selector = try mappedSlot(selection.selector, mapping),
                    .when_true = try mappedSlot(selection.when_true, mapping),
                    .when_false = try mappedSlot(selection.when_false, mapping),
                } },
                .machine_derived => |v| .{ .machine = try machine.mapped(v, struct {
                    slots: *const [MAX_ARENA_NODES]u16,
                    pub fn get(self: @This(), id: types.ValueId) Error!types.ValueId {
                        return @enumFromInt(try mappedSlot(id, self.slots));
                    }
                }{ .slots = mapping }) },
                else => error.UnsupportedRelationExpression,
            };
        }

        pub fn compileBinary(
            binary: expr.Binary,
            mapping: *const [MAX_ARENA_NODES]u16,
        ) Error!BinarySlots {
            return .{
                .lhs = try mappedSlot(binary.lhs, mapping),
                .rhs = try mappedSlot(binary.rhs, mapping),
            };
        }

        pub fn mappedSlot(
            value: types.ValueId,
            mapping: *const [MAX_ARENA_NODES]u16,
        ) Error!u16 {
            const index = types.idIndex(value);
            if (index >= mapping.len or mapping[index] == NO_SLOT)
                return error.EventPlanMismatch;
            return mapping[index];
        }
    };
}

//! Internal shard of relation_interaction.zig; use the facade.

const dependency_0 = @import("relation_interaction_tuple_ledger.zig");

const AuthenticationError = dependency_0.AuthenticationError;
const BatchPlan = dependency_0.BatchPlan;
const BinarySlots = dependency_0.BinarySlots;
const ClaimError = dependency_0.ClaimError;
const DomainAudit = dependency_0.DomainAudit;
const DomainAuditError = dependency_0.DomainAuditError;
const Entry = dependency_0.Entry;
const Error = dependency_0.Error;
const EvalNode = dependency_0.EvalNode;
const EvalOp = dependency_0.EvalOp;
const EventPlan = dependency_0.EventPlan;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const InteractionError = dependency_0.InteractionError;
const M31 = dependency_0.M31;
const MAX_ARENA_NODES = dependency_0.MAX_ARENA_NODES;
const MAX_ARITY = dependency_0.MAX_ARITY;
const MAX_COMPILED_NODES = dependency_0.MAX_COMPILED_NODES;
const NO_SLOT = dependency_0.NO_SLOT;
const QM31 = dependency_0.QM31;
const RowError = dependency_0.RowError;
const TupleLedger = dependency_0.TupleLedger;
const claims_derivation = dependency_0.claims_derivation;
const digest = dependency_0.digest;
const domain_audit = dependency_0.domain_audit;
const emptyEvalNode = dependency_0.emptyEvalNode;
const emptyEventPlan = dependency_0.emptyEventPlan;
const entry_validation = dependency_0.entry_validation;
const expr = dependency_0.expr;
const fields = dependency_0.fields;
const ir = dependency_0.ir;
const logup = dependency_0.logup;
const lower_effects = dependency_0.lower_effects;
const pairSum = dependency_0.pairSum;
const permutation = dependency_0.permutation;
const relation = dependency_0.relation;
const signedNumerator = dependency_0.signedNumerator;
const std = dependency_0.std;
const traceSize = dependency_0.traceSize;
const tuple_audit = dependency_0.tuple_audit;
const types = dependency_0.types;
const universal = dependency_0.universal;
const validate = dependency_0.validate;

pub fn Runtime(
    comptime logical_input_count: usize,
    comptime event_count: usize,
    comptime batch_size: u8,
) type {
    comptime {
        if (logical_input_count == 0 or
            logical_input_count > std.math.maxInt(u16))
        {
            @compileError("relation interaction logical input geometry must fit u16");
        }
        if (event_count == 0 or event_count > std.math.maxInt(u8))
            @compileError("relation interaction event geometry must fit u8");
        if (batch_size != 1 and batch_size != 2)
            @compileError("recursion LogUp batch size must be one or two");
    }
    const batch_count = (event_count + batch_size - 1) / batch_size;
    const interaction_column_count = 4 * batch_count;
    const slot_count = logical_input_count + MAX_COMPILED_NODES;

    return struct {
        const Self = @This();

        pub const LOGICAL_INPUT_COUNT = logical_input_count;
        pub const EVENT_COUNT = event_count;
        pub const BATCH_SIZE = batch_size;
        pub const BATCH_COUNT = batch_count;
        pub const INTERACTION_COLUMN_COUNT = interaction_column_count;
        pub const Row = [LOGICAL_INPUT_COUNT]M31;
        pub const SecureRow = [LOGICAL_INPUT_COUNT]QM31;
        pub const DomainAuditResult = DomainAudit;
        pub const DomainAuditErrorSet = DomainAuditError;
        pub const TupleLedgerType = TupleLedger;
        pub const EntryType = Entry;
        pub const AuthenticationErrorSet = AuthenticationError;
        pub const ClaimErrorSet = ClaimError;
        pub const QM31Type = QM31;
        pub const pairSumPrepared = pairSum;

        pub const Plan = struct {
            format_version: u16,
            semantic_format_version: u16,
            semantic_digest: digest.Digest,
            registry_order_digest: [32]u8,
            compiled_node_count: u16,
            compiled_nodes: [MAX_COMPILED_NODES]EvalNode,
            events: [EVENT_COUNT]EventPlan,
            batches: [BATCH_COUNT]BatchPlan,

            pub fn validateAgainst(
                self: *const Plan,
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
            ) AuthenticationError!void {
                if (self.format_version != FORMAT_VERSION)
                    return error.FormatVersionMismatch;
                if (self.semantic_format_version != digest.typed_effect_format_version or
                    !std.mem.eql(u8, &self.semantic_digest, &expected_digest))
                {
                    return error.BindingSealMismatch;
                }
                if (!std.mem.eql(
                    u8,
                    &self.registry_order_digest,
                    &relation.registryOrderDigest(),
                )) return error.RegistryOrderMismatch;

                const expected = try compilePlan(arena, expected_digest, event_ids);
                if (!std.meta.eql(self.*, expected))
                    return error.EventPlanMismatch;
            }

            pub fn entries(
                self: *const Plan,
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
                row: Row,
            ) AuthenticationError![EVENT_COUNT]Entry {
                try self.validateAgainst(arena, expected_digest, event_ids);
                return entriesUnchecked(self, &row);
            }

            pub fn validateEntries(
                self: *const Plan,
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
                row: Row,
                actual: [EVENT_COUNT]Entry,
            ) AuthenticationError!void {
                return entry_validation.validateEntries(
                    Self,
                    self,
                    arena,
                    expected_digest,
                    event_ids,
                    row,
                    actual,
                );
            }

            pub fn rowPairs(
                self: *const Plan,
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
                row: Row,
                relations: *const universal.UniversalRelations,
            ) RowError![BATCH_COUNT]logup.RowPair {
                try self.validateAgainst(arena, expected_digest, event_ids);
                try relations.validate();
                return rowPairsUnchecked(self, &row, relations);
            }

            /// Allocation-free base-field evaluation for a plan and challenge
            /// bundle that were authenticated once at component construction.
            /// This is the hot-path seam used by concrete prover adapters; the
            /// caller must first call `validateAgainst` and `relations.validate`.
            pub inline fn preparedRowPairs(
                self: *const Plan,
                row: Row,
                relations: *const universal.UniversalRelations,
            ) universal.Error![BATCH_COUNT]logup.RowPair {
                return rowPairsUnchecked(self, &row, relations);
            }

            /// Secure-field counterpart of `preparedRowPairs`. OODS samples
            /// are extension-field values, so a concrete verifier adapter must
            /// evaluate the exact authenticated expression DAG over QM31 rather
            /// than lift a base-field paraphrase.
            pub inline fn preparedSecureRowPairs(
                self: *const Plan,
                row: SecureRow,
                relations: *const universal.UniversalRelations,
            ) universal.Error![BATCH_COUNT]logup.RowPair {
                return rowPairsSecureUnchecked(self, &row, relations);
            }

            pub inline fn preparedEntries(
                self: *const Plan,
                row: Row,
            ) [EVENT_COUNT]Entry {
                return entriesUnchecked(self, &row);
            }

            /// Replays the authenticated plan into an exact per-domain claim.
            /// This cold diagnostic leaves the proving hot path unchanged.
            pub fn auditPreparedDomainSums(
                self: *const Plan,
                allocator: std.mem.Allocator,
                rows: []const Row,
                relations: *const universal.UniversalRelations,
                expected_claimed_sum: QM31,
            ) DomainAuditError!DomainAudit {
                return domain_audit.auditPreparedDomainSums(
                    Self,
                    self,
                    allocator,
                    rows,
                    relations,
                    expected_claimed_sum,
                );
            }

            /// Appends exact signed tuples to the selected diagnostic domains.
            pub fn appendPreparedTupleContributions(
                self: *const Plan,
                ledger: *TupleLedger,
                component: u8,
                rows: []const Row,
                domain_mask: u64,
            ) std.mem.Allocator.Error!void {
                return tuple_audit.appendPreparedTupleContributions(
                    Self,
                    self,
                    ledger,
                    component,
                    rows,
                    domain_mask,
                );
            }

            pub fn rowClaims(
                self: *const Plan,
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
                row: Row,
                relations: *const universal.UniversalRelations,
            ) ClaimError!Claims {
                return claims_derivation.rowClaims(
                    Self,
                    self,
                    arena,
                    expected_digest,
                    event_ids,
                    row,
                    relations,
                );
            }

            pub fn generateInteraction(
                self: *const Plan,
                allocator: std.mem.Allocator,
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
                rows: []const Row,
                log_size: u32,
                relations: *const universal.UniversalRelations,
            ) InteractionError!Interaction {
                try self.validateAgainst(arena, expected_digest, event_ids);
                try relations.validate();
                return generateInteractionUnchecked(
                    self,
                    allocator,
                    rows,
                    log_size,
                    relations,
                );
            }

            pub fn validateInteraction(
                self: *const Plan,
                allocator: std.mem.Allocator,
                arena: *const ir.Arena,
                expected_digest: digest.Digest,
                event_ids: [EVENT_COUNT]types.EffectId,
                rows: []const Row,
                log_size: u32,
                relations: *const universal.UniversalRelations,
                actual: *const Interaction,
            ) InteractionError!void {
                try self.validateAgainst(arena, expected_digest, event_ids);
                try relations.validate();
                const size = traceSize(log_size) catch
                    return error.InvalidTraceShape;
                const storage_len = std.math.mul(
                    usize,
                    INTERACTION_COLUMN_COUNT,
                    size,
                ) catch return error.InvalidTraceShape;
                if (actual.storage.len != storage_len)
                    return error.InteractionGeometryMismatch;
                for (actual.columns) |column| if (column.len != size)
                    return error.InteractionGeometryMismatch;

                var expected = try generateInteractionUnchecked(
                    self,
                    allocator,
                    rows,
                    log_size,
                    relations,
                );
                defer expected.deinit(allocator);
                if (!actual.claims.eql(expected.claims)) return error.ClaimMismatch;
                for (actual.columns, expected.columns) |got, wanted| {
                    for (got, wanted) |got_value, wanted_value| {
                        if (!got_value.eql(wanted_value))
                            return error.InteractionColumnMismatch;
                    }
                }
            }
        };

        pub const Claims = struct {
            sums: [BATCH_COUNT]QM31,

            pub fn total(self: Claims) QM31 {
                var result = QM31.zero();
                for (self.sums) |sum| result = result.add(sum);
                return result;
            }

            pub fn eql(self: Claims, other: Claims) bool {
                for (self.sums, other.sums) |lhs, rhs| {
                    if (!lhs.eql(rhs)) return false;
                }
                return true;
            }

            pub fn verifyClosure(self: Claims, counterpart: QM31) Error!void {
                if (!self.total().add(counterpart).isZero())
                    return error.RelationSumNonZero;
            }
        };

        pub const Interaction = struct {
            columns: [INTERACTION_COLUMN_COUNT][]M31,
            claims: Claims,
            storage: []M31,

            pub fn deinit(self: *Interaction, allocator: std.mem.Allocator) void {
                allocator.free(self.storage);
                self.* = undefined;
            }
        };

        pub fn authenticate(
            arena: *const ir.Arena,
            expected_digest: digest.Digest,
            event_ids: [EVENT_COUNT]types.EffectId,
        ) AuthenticationError!Plan {
            return compilePlan(arena, expected_digest, event_ids);
        }

        fn compilePlan(
            arena: *const ir.Arena,
            expected_digest: digest.Digest,
            event_ids: [EVENT_COUNT]types.EffectId,
        ) AuthenticationError!Plan {
            const identity = try digest.computeIdentity(arena);
            if (identity.format_version != digest.typed_effect_format_version or
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
                if (event.kind != .component_call or
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
                    .second = if (BATCH_SIZE == 2 and first + 1 < EVENT_COUNT)
                        @intCast(first + 1)
                    else
                        null,
                    .interaction_column_start = @intCast(4 * ordinal),
                };
            }
            return .{
                .format_version = FORMAT_VERSION,
                .semantic_format_version = digest.typed_effect_format_version,
                .semantic_digest = expected_digest,
                .registry_order_digest = relation.registryOrderDigest(),
                .compiled_node_count = @intCast(compiled_count),
                .compiled_nodes = compiled_nodes,
                .events = events,
                .batches = batches,
            };
        }

        fn entriesUnchecked(plan: *const Plan, row: *const Row) [EVENT_COUNT]Entry {
            var slots: [slot_count]M31 = undefined;
            evaluate(plan, row, &slots);
            var result: [EVENT_COUNT]Entry = undefined;
            for (&result, plan.events) |*entry, event| {
                var values = [_]QM31{QM31.zero()} ** MAX_ARITY;
                for (values[0..event.arity], event.value_slots[0..event.arity]) |
                    *target,
                    slot,
                | target.* = QM31.fromBase(slots[slot]);
                const magnitude = QM31.fromBase(slots[event.numerator_slot]);
                entry.* = .{
                    .ordinal = event.ordinal,
                    .schema = event.schema,
                    .schema_version = event.schema_version,
                    .domain = event.domain,
                    .role = event.role,
                    .numerator = signedNumerator(event.role, magnitude),
                    .values = values,
                    .arity = event.arity,
                };
            }
            return result;
        }

        fn rowPairsUnchecked(
            plan: *const Plan,
            row: *const Row,
            relations: *const universal.UniversalRelations,
        ) universal.Error![BATCH_COUNT]logup.RowPair {
            var slots: [slot_count]M31 = undefined;
            evaluate(plan, row, &slots);
            var result: [BATCH_COUNT]logup.RowPair = undefined;
            for (&result, plan.batches) |*pair, batch| {
                const first = try fraction(plan.events[batch.first], &slots, relations);
                pair.* = if (batch.second) |second| blk: {
                    const next = try fraction(plan.events[second], &slots, relations);
                    break :blk .{
                        .n1 = first.numerator,
                        .d1 = first.denominator,
                        .n2 = next.numerator,
                        .d2 = next.denominator,
                    };
                } else logup.RowPair.single(first.numerator, first.denominator);
            }
            return result;
        }

        fn rowPairsSecureUnchecked(
            plan: *const Plan,
            row: *const SecureRow,
            relations: *const universal.UniversalRelations,
        ) universal.Error![BATCH_COUNT]logup.RowPair {
            var slots: [slot_count]QM31 = undefined;
            evaluateSecure(plan, row, &slots);
            var result: [BATCH_COUNT]logup.RowPair = undefined;
            for (&result, plan.batches) |*pair, batch| {
                const first = try fractionSecure(
                    plan.events[batch.first],
                    &slots,
                    relations,
                );
                pair.* = if (batch.second) |second| blk: {
                    const next = try fractionSecure(
                        plan.events[second],
                        &slots,
                        relations,
                    );
                    break :blk .{
                        .n1 = first.numerator,
                        .d1 = first.denominator,
                        .n2 = next.numerator,
                        .d2 = next.denominator,
                    };
                } else logup.RowPair.single(first.numerator, first.denominator);
            }
            return result;
        }

        const Fraction = struct {
            numerator: QM31,
            denominator: QM31,
        };

        fn fraction(
            event: EventPlan,
            slots: *const [slot_count]M31,
            relations: *const universal.UniversalRelations,
        ) universal.Error!Fraction {
            var values: [MAX_ARITY]M31 = undefined;
            for (values[0..event.arity], event.value_slots[0..event.arity]) |
                *target,
                slot,
            | target.* = slots[slot];
            const magnitude = QM31.fromBase(slots[event.numerator_slot]);
            return .{
                .numerator = signedNumerator(event.role, magnitude),
                .denominator = try relations.get(event.domain).combineBase(
                    values[0..event.arity],
                ),
            };
        }

        fn fractionSecure(
            event: EventPlan,
            slots: *const [slot_count]QM31,
            relations: *const universal.UniversalRelations,
        ) universal.Error!Fraction {
            var values: [MAX_ARITY]QM31 = undefined;
            for (values[0..event.arity], event.value_slots[0..event.arity]) |
                *target,
                slot,
            | target.* = slots[slot];
            const magnitude = slots[event.numerator_slot];
            return .{
                .numerator = signedNumerator(event.role, magnitude),
                .denominator = try relations.get(event.domain).combineSecure(
                    values[0..event.arity],
                ),
            };
        }

        fn evaluate(
            plan: *const Plan,
            row: *const Row,
            slots: *[slot_count]M31,
        ) void {
            @memcpy(slots[0..LOGICAL_INPUT_COUNT], row);
            for (plan.compiled_nodes[0..plan.compiled_node_count]) |node| {
                slots[node.destination] = evaluateOp(node.op, slots);
            }
        }

        fn evaluateSecure(
            plan: *const Plan,
            row: *const SecureRow,
            slots: *[slot_count]QM31,
        ) void {
            @memcpy(slots[0..LOGICAL_INPUT_COUNT], row);
            for (plan.compiled_nodes[0..plan.compiled_node_count]) |node| {
                slots[node.destination] = evaluateSecureOp(node.op, slots);
            }
        }

        inline fn evaluateOp(op: EvalOp, slots: *const [slot_count]M31) M31 {
            return switch (op) {
                .constant => |value| M31.fromU64(value),
                .add => |binary| slots[binary.lhs].add(slots[binary.rhs]),
                .sub => |binary| slots[binary.lhs].sub(slots[binary.rhs]),
                .mul => |binary| slots[binary.lhs].mul(slots[binary.rhs]),
                .neg => |operand| slots[operand].neg(),
                .select => |selection| slots[selection.selector]
                    .mul(slots[selection.when_true])
                    .add(M31.one().sub(slots[selection.selector])
                    .mul(slots[selection.when_false])),
            };
        }

        inline fn evaluateSecureOp(
            op: EvalOp,
            slots: *const [slot_count]QM31,
        ) QM31 {
            return switch (op) {
                .constant => |value| QM31.fromBase(M31.fromU64(value)),
                .add => |binary| slots[binary.lhs].add(slots[binary.rhs]),
                .sub => |binary| slots[binary.lhs].sub(slots[binary.rhs]),
                .mul => |binary| slots[binary.lhs].mul(slots[binary.rhs]),
                .neg => |operand| slots[operand].neg(),
                .select => |selection| slots[selection.selector]
                    .mul(slots[selection.when_true])
                    .add(QM31.one().sub(slots[selection.selector])
                    .mul(slots[selection.when_false])),
            };
        }

        fn generateInteractionUnchecked(
            plan: *const Plan,
            allocator: std.mem.Allocator,
            rows: []const Row,
            log_size: u32,
            relations: *const universal.UniversalRelations,
        ) (Error || logup.LogupError || universal.Error)!Interaction {
            const size = traceSize(log_size) catch
                return error.InvalidTraceShape;
            if (rows.len > size) return error.InvalidTraceShape;
            const pair_count = std.math.mul(usize, BATCH_COUNT, size) catch
                return error.InvalidTraceShape;
            const pairs = try allocator.alloc(logup.RowPair, pair_count);
            defer allocator.free(pairs);
            for (0..size) |row_index| {
                const row_pairs = if (row_index < rows.len)
                    try rowPairsUnchecked(plan, &rows[row_index], relations)
                else
                    paddingPairs();
                for (row_pairs, 0..) |pair, batch|
                    pairs[batch * size + row_index] = pair;
            }

            // One bulk Montgomery inversion replaces one scalar inversion per
            // row and one allocation per batch. Both scratch slabs are
            // contiguous in batch-major order, so allocation count is fixed
            // and the inversion kernel can use its packed QM31 path.
            const cumulative_sums = try allocator.alloc(QM31, pair_count);
            defer allocator.free(cumulative_sums);
            const denominator_inverses = try allocator.alloc(QM31, pair_count);
            defer allocator.free(denominator_inverses);
            for (pairs, cumulative_sums) |pair, *denominator| {
                denominator.* = pair.d1.mul(pair.d2);
            }
            fields.batchInverseInPlace(
                QM31,
                cumulative_sums,
                denominator_inverses,
            ) catch return error.ZeroDenominator;
            var claims: [BATCH_COUNT]QM31 = undefined;
            for (0..BATCH_COUNT) |batch| {
                var accumulator = QM31.zero();
                const offset = batch * size;
                for (0..size) |row_index| {
                    const pair = pairs[offset + row_index];
                    const numerator = pair.n1.mul(pair.d2)
                        .add(pair.n2.mul(pair.d1));
                    accumulator = accumulator.add(
                        numerator.mul(denominator_inverses[offset + row_index]),
                    );
                    cumulative_sums[offset + row_index] = accumulator;
                }
                claims[batch] = accumulator;
            }

            const storage_len = std.math.mul(
                usize,
                INTERACTION_COLUMN_COUNT,
                size,
            ) catch return error.InvalidTraceShape;
            const storage = try allocator.alloc(M31, storage_len);
            errdefer allocator.free(storage);
            var columns: [INTERACTION_COLUMN_COUNT][]M31 = undefined;
            for (&columns, 0..) |*column, index|
                column.* = storage[index * size ..][0..size];

            const placement = try permutation.BitReversalTable.init(allocator, log_size);
            defer placement.deinit(allocator);
            for (0..size) |row_index| {
                const destination = placement.map(row_index);
                for (plan.batches, 0..) |batch_plan, batch| {
                    const coordinates = cumulative_sums[
                        batch * size + row_index
                    ].toM31Array();
                    for (coordinates, 0..) |coordinate, coordinate_index| {
                        columns[batch_plan.interaction_column_start + coordinate_index][destination] =
                            coordinate;
                    }
                }
            }
            return .{
                .columns = columns,
                .claims = .{ .sums = claims },
                .storage = storage,
            };
        }

        fn validateInputs(arena: *const ir.Arena) Error!void {
            if (arena.nodesView().len < LOGICAL_INPUT_COUNT)
                return error.InvalidInputGeometry;
            for (arena.nodesView()[0..LOGICAL_INPUT_COUNT]) |node| {
                switch (node.key.op) {
                    .input => {},
                    else => return error.InvalidInputGeometry,
                }
                if (!node.key.ty.isFieldScalar())
                    return error.InvalidInputGeometry;
            }
            for (arena.nodesView()[LOGICAL_INPUT_COUNT..]) |node| switch (node.key.op) {
                .input => return error.InvalidInputGeometry,
                else => {},
            };
        }

        const Visit = enum(u8) { unseen, active, done };

        fn markExpression(
            arena: *const ir.Arena,
            value: types.ValueId,
            required: *[MAX_ARENA_NODES]bool,
            _: struct {},
        ) Error!void {
            var visiting = [_]Visit{.unseen} ** MAX_ARENA_NODES;
            return markRecursive(arena, value, required, &visiting);
        }

        fn markRecursive(
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

        fn compileOp(
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
                else => error.UnsupportedRelationExpression,
            };
        }

        fn compileBinary(
            binary: expr.Binary,
            mapping: *const [MAX_ARENA_NODES]u16,
        ) Error!BinarySlots {
            return .{
                .lhs = try mappedSlot(binary.lhs, mapping),
                .rhs = try mappedSlot(binary.rhs, mapping),
            };
        }

        fn mappedSlot(
            value: types.ValueId,
            mapping: *const [MAX_ARENA_NODES]u16,
        ) Error!u16 {
            const index = types.idIndex(value);
            if (index >= mapping.len or mapping[index] == NO_SLOT)
                return error.EventPlanMismatch;
            return mapping[index];
        }

        fn paddingPairs() [BATCH_COUNT]logup.RowPair {
            const zero = QM31.zero();
            const one = QM31.one();
            return [_]logup.RowPair{.{
                .n1 = zero,
                .d1 = one,
                .n2 = zero,
                .d2 = one,
            }} ** BATCH_COUNT;
        }
    };
}

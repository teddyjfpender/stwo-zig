//! Internal shard of relation_interaction.zig; use the facade.

const machine = @import("closed_machine_expression.zig");
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
const types = dependency_0.types;
const universal = dependency_0.universal;

pub fn Runtime(
    comptime logical_input_count: usize,
    comptime event_count: usize,
    comptime batch_size: u8,
) type {
    return RuntimeWithFixedAddresses(logical_input_count, event_count, batch_size, 0, &.{});
}

/// Fixed address/PC lowering is part of the runtime type and survives plan revalidation.
/// Verifier preprocessing must bound these coordinates below the field modulus.
pub fn RuntimeWithFixedAddresses(
    comptime logical_input_count: usize,
    comptime event_count: usize,
    comptime batch_size: u8,
    comptime main_column_count: usize,
    comptime fixed_addresses: []const usize,
) type {
    return RuntimeWithMachineInputs(logical_input_count, event_count, batch_size, main_column_count, fixed_addresses, &.{});
}

/// Program-bound PC inputs are bounded by the admitted VM program table. Every
/// use must share the request's liveness; declarations survive plan validation.
pub fn RuntimeWithMachineInputs(
    comptime logical_input_count: usize,
    comptime event_count: usize,
    comptime batch_size: u8,
    comptime main_column_count: usize,
    comptime fixed_addresses: []const usize,
    comptime program_pcs: []const usize,
) type {
    comptime {
        if (logical_input_count == 0 or
            logical_input_count > std.math.maxInt(u16))
        {
            @compileError("relation interaction logical input geometry must fit u16");
        }
        if (event_count == 0 or event_count > std.math.maxInt(u8))
            @compileError("relation interaction event geometry must fit u8");
        if (batch_size < 1 or batch_size > 4)
            @compileError("recursion LogUp batch size must be between one and four");
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
                if (!machine.supportedFormat(self.semantic_format_version) or
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

            /// Visit selected base-field events without materializing secure
            /// tuples for every relation. The authenticated DAG and event order
            /// are identical to preparedEntries; the consumer selects schemas.
            pub fn visitPreparedBaseEntries(self: *const Plan, row: Row, visitor: anytype) !void {
                var slots: [slot_count]M31 = undefined;
                evaluate(self, &row, &slots);
                for (self.events) |event| {
                    if (!visitor.accepts(event.schema)) continue;
                    const magnitude = slots[event.numerator_slot];
                    const numerator = switch (event.role) {
                        .request, .consume => magnitude.neg(),
                        .emit => magnitude,
                    };
                    var values: [MAX_ARITY]M31 = undefined;
                    for (values[0..event.arity], event.value_slots[0..event.arity]) |*value, slot| value.* = slots[slot];
                    try visitor.visit(event.schema, numerator, values[0..event.arity]);
                }
            }

            /// The same authenticated expression DAG at extension-field
            /// openings. A same-root projection selects schemas/ordinals;
            /// source expressions and signed roles remain owned by this plan.
            pub fn visitPreparedSecureEntries(self: *const Plan, row: SecureRow, visitor: anytype) !void {
                return self.visitPreparedEntriesFor(QM31, row, visitor);
            }

            /// The same authenticated DAG and signed event order for recursive
            /// scalar recording. Admission belongs to the original Plan owner.
            pub fn visitPreparedEntriesFor(self: *const Plan, comptime S: type, row: [LOGICAL_INPUT_COUNT]S, visitor: anytype) !void {
                var slots: [slot_count]S = undefined;
                evaluateFor(S, self, &row, &slots);
                for (self.events) |event| {
                    if (!visitor.accepts(event.schema)) continue;
                    const magnitude = slots[event.numerator_slot];
                    const numerator = switch (event.role) {
                        .request, .consume => magnitude.neg(),
                        .emit => magnitude,
                    };
                    var values: [MAX_ARITY]S = undefined;
                    for (values[0..event.arity], event.value_slots[0..event.arity]) |*value, slot| value.* = slots[slot];
                    try visitor.visit(event.ordinal, event.domain, numerator, values[0..event.arity]);
                }
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
                // Stream selected live tuples directly from the admitted
                // evaluator. The diagnostic entries API still materializes all
                // values; ledger ingestion never observes zero-weight tuples.
                for (rows) |row| {
                    var slots: [slot_count]M31 = undefined;
                    evaluate(self, &row, &slots);
                    for (self.events) |event| {
                        const bit = @as(u64, 1) << @as(u6, @intCast(@intFromEnum(event.domain)));
                        if (domain_mask & bit == 0) continue;
                        const weight = signedNumerator(event.role, QM31.fromBase(slots[event.numerator_slot]));
                        if (weight.isZero()) continue;
                        var values: [MAX_ARITY]QM31 = undefined;
                        for (values[0..event.arity], event.value_slots[0..event.arity]) |*value, slot|
                            value.* = QM31.fromBase(slots[slot]);
                        try ledger.append(event.domain, component, event.ordinal, event.role, weight, values[0..event.arity]);
                    }
                }
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

        const PlanCompiler = @import("relation_plan_compiler.zig").For(.{
            .machine = machine,
            .AuthenticationError = AuthenticationError,
            .BatchPlan = BatchPlan,
            .BinarySlots = BinarySlots,
            .Error = Error,
            .EvalNode = EvalNode,
            .EvalOp = EvalOp,
            .EventPlan = EventPlan,
            .FORMAT_VERSION = FORMAT_VERSION,
            .MAX_ARENA_NODES = MAX_ARENA_NODES,
            .MAX_ARITY = MAX_ARITY,
            .MAX_COMPILED_NODES = MAX_COMPILED_NODES,
            .NO_SLOT = NO_SLOT,
            .digest = digest,
            .emptyEvalNode = emptyEvalNode,
            .emptyEventPlan = emptyEventPlan,
            .expr = expr,
            .fields = fields,
            .ir = ir,
            .lower_effects = lower_effects,
            .relation = relation,
            .std = std,
            .types = types,
            .LOGICAL_INPUT_COUNT = LOGICAL_INPUT_COUNT,
            .EVENT_COUNT = EVENT_COUNT,
            .BATCH_COUNT = BATCH_COUNT,
            .BATCH_SIZE = BATCH_SIZE,
            .Plan = Plan,
            .fixed_addresses = fixed_addresses,
            .program_pcs = program_pcs,
            .main_column_count = main_column_count,
        });
        const compilePlan = PlanCompiler.compilePlan;
        const validateInputs = PlanCompiler.validateInputs;
        const markExpression = PlanCompiler.markExpression;
        const markRecursive = PlanCompiler.markRecursive;
        const compileOp = PlanCompiler.compileOp;
        const compileBinary = PlanCompiler.compileBinary;
        const mappedSlot = PlanCompiler.mappedSlot;

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
                if (BATCH_SIZE >= 3 and batch.third != null) {
                    const third = batch.third.?;
                    const next = try fraction(plan.events[third], &slots, relations);
                    pair.n1 = pair.n1.mul(next.denominator).add(next.numerator.mul(pair.d1));
                    pair.d1 = pair.d1.mul(next.denominator);
                }
                if (BATCH_SIZE >= 4 and batch.fourth != null) {
                    const fourth = batch.fourth.?;
                    const next = try fraction(plan.events[fourth], &slots, relations);
                    pair.n2 = pair.n2.mul(next.denominator).add(next.numerator.mul(pair.d2));
                    pair.d2 = pair.d2.mul(next.denominator);
                }
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
                if (BATCH_SIZE >= 3 and batch.third != null) {
                    const third = batch.third.?;
                    const next = try fractionSecure(plan.events[third], &slots, relations);
                    pair.n1 = pair.n1.mul(next.denominator).add(next.numerator.mul(pair.d1));
                    pair.d1 = pair.d1.mul(next.denominator);
                }
                if (BATCH_SIZE >= 4 and batch.fourth != null) {
                    const fourth = batch.fourth.?;
                    const next = try fractionSecure(plan.events[fourth], &slots, relations);
                    pair.n2 = pair.n2.mul(next.denominator).add(next.numerator.mul(pair.d2));
                    pair.d2 = pair.d2.mul(next.denominator);
                }
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

        fn evaluateSecure(plan: *const Plan, row: *const SecureRow, slots: *[slot_count]QM31) void {
            evaluateFor(QM31, plan, row, slots);
        }
        fn evaluateFor(comptime S: type, plan: *const Plan, row: *const [LOGICAL_INPUT_COUNT]S, slots: *[slot_count]S) void {
            @memcpy(slots[0..LOGICAL_INPUT_COUNT], row);
            for (plan.compiled_nodes[0..plan.compiled_node_count]) |node| slots[node.destination] = evaluateOpFor(S, node.op, slots);
        }

        inline fn evaluateOp(op: EvalOp, slots: *const [slot_count]M31) M31 {
            return switch (op) {
                .machine => |v| machine.evaluate(M31, v, slots),
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

        inline fn evaluateOpFor(
            comptime S: type,
            op: EvalOp,
            slots: *const [slot_count]S,
        ) S {
            return switch (op) {
                .machine => |v| machine.evaluate(S, v, slots),
                .constant => |value| S.fromBase(M31.fromU64(value)),
                .add => |binary| slots[binary.lhs].add(slots[binary.rhs]),
                .sub => |binary| slots[binary.lhs].sub(slots[binary.rhs]),
                .mul => |binary| slots[binary.lhs].mul(slots[binary.rhs]),
                .neg => |operand| slots[operand].neg(),
                .select => |selection| slots[selection.selector]
                    .mul(slots[selection.when_true])
                    .add(S.one().sub(slots[selection.selector])
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

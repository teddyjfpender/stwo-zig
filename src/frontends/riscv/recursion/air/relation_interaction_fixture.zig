//! Internal shard of relation_interaction.zig; use the facade.

const dependency_0 = @import("relation_interaction_tuple_ledger.zig");
const dependency_1 = @import("relation_interaction_runtime.zig");

const M31 = dependency_0.M31;
const MAX_ARITY = dependency_0.MAX_ARITY;
const QM31 = dependency_0.QM31;
const Runtime = dependency_1.Runtime;
const TupleLedger = dependency_0.TupleLedger;
const allDomainMask = dependency_0.allDomainMask;
const digest = dependency_0.digest;
const ir = dependency_0.ir;
const relation = dependency_0.relation;
const std = dependency_0.std;
const types = dependency_0.types;
const universal = dependency_0.universal;
const validate = dependency_0.validate;

test "R-012 multi-schema compiler authenticates nested weights and exact batching" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const RuntimeType = Runtime(Fixture.LOGICAL_INPUT_COUNT, 3, 2);
    const identity = try digest.computeIdentity(&fixture.arena);
    const plan = try RuntimeType.authenticate(
        &fixture.arena,
        identity.bytes,
        fixture.events,
    );
    try std.testing.expectEqual(@as(u16, 2), plan.compiled_node_count);
    try std.testing.expectEqual(@as(usize, 2), RuntimeType.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 8), RuntimeType.INTERACTION_COLUMN_COUNT);

    const row = Fixture.row();
    const entries = try plan.entries(
        &fixture.arena,
        identity.bytes,
        fixture.events,
        row,
    );
    try std.testing.expectEqual(relation.Domain.recursion_statement_word, entries[0].domain);
    try std.testing.expectEqual(relation.Role.emit, entries[0].role);
    try std.testing.expectEqual(relation.Domain.range_check_8_8, entries[1].domain);
    try std.testing.expectEqual(relation.Role.request, entries[1].role);
    try std.testing.expect(entries[1].numerator.eql(QM31.fromBase(row[5]).neg()));
    const expected_nested = row[2].add(row[1]).mul(row[5]);
    try std.testing.expect(entries[2].numerator.eql(QM31.fromBase(expected_nested).neg()));

    const relations = universal.UniversalRelations.dummy();
    const pairs = try plan.rowPairs(
        &fixture.arena,
        identity.bytes,
        fixture.events,
        row,
        &relations,
    );
    try std.testing.expect(pairs[0].d1.eql(try entries[0].denominator(&relations)));
    try std.testing.expect(pairs[0].d2.eql(try entries[1].denominator(&relations)));
    try std.testing.expect(pairs[1].d1.eql(try entries[2].denominator(&relations)));
    try std.testing.expect(pairs[1].n2.isZero());
    try std.testing.expect(pairs[1].d2.eql(QM31.one()));
}

test "R-012 cold domain audit preserves mixed-batch claim exactly" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const RuntimeType = Runtime(Fixture.LOGICAL_INPUT_COUNT, 3, 2);
    const identity = try digest.computeIdentity(&fixture.arena);
    const plan = try RuntimeType.authenticate(
        &fixture.arena,
        identity.bytes,
        fixture.events,
    );
    const rows = [_]RuntimeType.Row{ Fixture.row(), Fixture.row() };
    const relations = universal.UniversalRelations.dummy();
    var expected = QM31.zero();
    for (rows) |row| {
        const claims = try plan.rowClaims(
            &fixture.arena,
            identity.bytes,
            fixture.events,
            row,
            &relations,
        );
        expected = expected.add(claims.total());
    }

    var measured = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    const audit = try plan.auditPreparedDomainSums(
        measured.allocator(),
        &rows,
        &relations,
        expected,
    );
    try std.testing.expectEqual(@as(usize, 2), measured.alloc_index);
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.expect(audit.total.eql(expected));
    try std.testing.expectEqual(@as(usize, 2), audit.logical_rows);
    try std.testing.expectEqual(@as(usize, 6), audit.event_terms);

    var recomposed = QM31.zero();
    for (audit.values) |value| recomposed = recomposed.add(value);
    try std.testing.expect(recomposed.eql(expected));
    try std.testing.expect(!audit.values[
        @intFromEnum(relation.Domain.recursion_statement_word)
    ].isZero());
    try std.testing.expect(!audit.values[
        @intFromEnum(relation.Domain.range_check_8_8)
    ].isZero());
    try std.testing.expectError(
        error.ClaimMismatch,
        plan.auditPreparedDomainSums(
            std.testing.allocator,
            &rows,
            &relations,
            expected.add(QM31.one()),
        ),
    );

    var ledger = TupleLedger.init(std.testing.allocator);
    defer ledger.deinit();
    try plan.appendPreparedTupleContributions(
        &ledger,
        10,
        &rows,
        allDomainMask(),
    );
    try std.testing.expectEqual(@as(usize, 6), ledger.contributions.items.len);
    try std.testing.expectEqual(
        relation.Domain.recursion_statement_word,
        ledger.contributions.items[0].domain,
    );
    try std.testing.expectEqual(@as(u8, 10), ledger.contributions.items[0].component);
    try std.testing.expectEqualSlices(
        u8,
        &ledger.contributions.items[0].tuple_hash,
        &ledger.contributions.items[3].tuple_hash,
    );
}

test "R-012 multi-schema interaction uses one cache-bounded allocation shape" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const RuntimeType = Runtime(Fixture.LOGICAL_INPUT_COUNT, 3, 2);
    const identity = try digest.computeIdentity(&fixture.arena);
    const plan = try RuntimeType.authenticate(&fixture.arena, identity.bytes, fixture.events);
    const rows = [_]RuntimeType.Row{Fixture.row()};
    const relations = universal.UniversalRelations.dummy();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &fixture.arena,
            identity.bytes,
            fixture.events,
            &rows,
            2,
            &relations,
        );
        defer interaction.deinit(measured.allocator());
        try std.testing.expect(measured.alloc_index <= 5);
        try plan.validateInteraction(
            std.testing.allocator,
            &fixture.arena,
            identity.bytes,
            fixture.events,
            &rows,
            2,
            &relations,
            &interaction,
        );
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
}

test "R-012 tuple closure classifier is challenge independent and exact" {
    var ledger = TupleLedger.init(std.testing.allocator);
    defer ledger.deinit();
    const closed_tuple = [_]QM31{QM31.fromBase(M31.fromCanonical(7))};
    try ledger.append(
        .recursion_wire,
        11,
        0,
        .emit,
        QM31.one(),
        &closed_tuple,
    );
    try ledger.append(
        .recursion_wire,
        30,
        1,
        .consume,
        QM31.one().neg(),
        &closed_tuple,
    );
    const open_tuple = [_]QM31{QM31.fromBase(M31.fromCanonical(9))};
    try ledger.append(
        .recursion_statement_word,
        10,
        0,
        .emit,
        QM31.fromBase(M31.fromCanonical(3)),
        &open_tuple,
    );

    const report = ledger.classify();
    try std.testing.expectEqual(@as(usize, 3), report.contribution_count);
    try std.testing.expectEqual(@as(usize, 1), report.unmatched_tuple_count);
    try std.testing.expectEqual(@as(usize, 1), report.redDomainCount());
    try std.testing.expectEqual(
        @as(usize, 1),
        report.unmatched_by_domain[
            @intFromEnum(relation.Domain.recursion_statement_word)
        ],
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        report.unmatched_by_domain[@intFromEnum(relation.Domain.recursion_wire)],
    );
    try std.testing.expect(!report.isClosed());
}

test "R-012 multi-schema interaction releases every allocation failure" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const RuntimeType = Runtime(Fixture.LOGICAL_INPUT_COUNT, 3, 2);
    const identity = try digest.computeIdentity(&fixture.arena);
    const plan = try RuntimeType.authenticate(&fixture.arena, identity.bytes, fixture.events);
    const rows = [_]RuntimeType.Row{Fixture.row()};
    const relations = universal.UniversalRelations.dummy();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &fixture, &plan, identity.bytes, &rows, &relations },
    );
}

test "R-012 multi-schema plan rejects registry event and expression mutation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const RuntimeType = Runtime(Fixture.LOGICAL_INPUT_COUNT, 3, 2);
    const identity = try digest.computeIdentity(&fixture.arena);
    const honest = try RuntimeType.authenticate(&fixture.arena, identity.bytes, fixture.events);

    var malformed = honest;
    malformed.registry_order_digest[0] ^= 1;
    try std.testing.expectError(
        error.RegistryOrderMismatch,
        malformed.validateAgainst(&fixture.arena, identity.bytes, fixture.events),
    );
    malformed = honest;
    malformed.events[0].domain = .recursion_vm_public_claim_word;
    try std.testing.expectError(
        error.EventPlanMismatch,
        malformed.validateAgainst(&fixture.arena, identity.bytes, fixture.events),
    );
    malformed = honest;
    malformed.compiled_nodes[0].destination += 1;
    try std.testing.expectError(
        error.EventPlanMismatch,
        malformed.validateAgainst(&fixture.arena, identity.bytes, fixture.events),
    );
}

pub const Fixture = struct {
    pub const LOGICAL_INPUT_COUNT: usize = 6;
    arena: ir.Arena,
    events: [3]types.EffectId,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const relation_effect = @import("relation_effect.zig");
        var arena = ir.Arena.init(allocator);
        errdefer arena.deinit();
        const span = @import("../../air/lang/source.zig").SourceSpan.generated();
        const scope = try arena.input("scope", .felt, span);
        const index = try arena.input("index", .felt, span);
        const value = try arena.input("value", .felt, span);
        const low = try arena.input("low", .byte, span);
        const high = try arena.input("high", .byte, span);
        const active = try arena.input("active", .selector, span);
        const sum = try arena.add(value, index, span);
        const nested_weight = try arena.mul(sum, active, span);
        const statement = [_]types.ValueId{ scope, index, value };
        const bytes = [_]types.ValueId{ low, high };
        const events = try relation_effect.appendGroup(3, &arena, .{
            .{ .domain = .recursion_statement_word, .role = .emit, .values = &statement, .weight = active },
            .{ .domain = .range_check_8_8, .role = .request, .values = &bytes, .weight = active },
            .{ .domain = .recursion_statement_word, .role = .consume, .values = &statement, .weight = nested_weight },
        }, span);
        try validate.validate(&arena);
        return .{ .arena = arena, .events = events };
    }

    fn deinit(self: *Fixture) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn row() [LOGICAL_INPUT_COUNT]M31 {
        return .{
            M31.fromU64(7),
            M31.fromU64(11),
            M31.fromU64(13),
            M31.fromU64(17),
            M31.fromU64(19),
            M31.one(),
        };
    }
};

pub fn interactionFailureCase(
    allocator: std.mem.Allocator,
    fixture: *const Fixture,
    plan: *const Runtime(Fixture.LOGICAL_INPUT_COUNT, 3, 2).Plan,
    identity: digest.Digest,
    rows: []const Runtime(Fixture.LOGICAL_INPUT_COUNT, 3, 2).Row,
    relations: *const universal.UniversalRelations,
) !void {
    var interaction = try plan.generateInteraction(
        allocator,
        &fixture.arena,
        identity,
        fixture.events,
        rows,
        2,
        relations,
    );
    defer interaction.deinit(allocator);
}

comptime {
    if (MAX_ARITY != @import("../../air/lang/effects.zig").MAX_ARITY)
        @compileError("multi-schema interaction arity must track typed effects");
}

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const bundle_mod = @import("secp256k1_component_bundle.zig");
const component_mod = @import("secp256k1_component.zig");
const config = @import("secp256k1_component_config.zig");
const interaction_mod = @import("secp256k1_component_interaction.zig");
const linear = @import("secp256k1_linear_direct.zig");
const mul = @import("secp256k1_mul_direct.zig");
const relations_mod = @import("secp256k1_relations.zig");
const trace_mod = @import("secp256k1_component_trace.zig");
const work_pool = @import("stwo_prover_engine").work_pool;

const Sink = struct {
    count: usize = 0,
    failures: usize = 0,

    pub fn add(self: *Sink, value: anytype, degree: u8) void {
        _ = degree;
        const lifted = if (@TypeOf(value) == M31) QM31.fromBase(value) else value;
        self.count += 1;
        self.failures += @intFromBool(!lifted.isZero());
    }
};

test "secp256k1 component: product trace interaction and adapters agree" {
    const Config = config.Product(.base);
    const Trace = trace_mod.Trace(Config);
    const Component = component_mod.Component(Config);
    const lhs = @import("secp256k1_field.zig").bytesFromInteger(17);
    const rhs = @import("secp256k1_field.zig").bytesFromInteger(29);
    const witness = try @import("secp256k1_field.zig").create(
        lhs,
        rhs,
        @import("secp256k1_field.zig").base_modulus,
    );
    const rows = [_]Trace.Row{mul.rowFromWitness(&witness)};
    var trace = try Trace.init(std.testing.allocator, &rows, &.{}, &.{});
    defer trace.deinit();
    const relations = relations_mod.Relations.dummy();
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1 });
    defer pool.deinit();
    var interaction = try interaction_mod.generate(
        Config,
        std.testing.allocator,
        &trace,
        &relations,
        &pool,
    );
    defer interaction.deinit(std.testing.allocator);
    const claim = try component_mod.Claim(Config).canonical(&trace, interaction.claims);
    const component = try Component.init(
        claim,
        .{ .preprocessed_offset = 0, .main_offset = 0, .interaction_offset = 0 },
        &relations,
    );
    try std.testing.expectEqual(
        Config.direct_constraint_count + Config.batch_count,
        component.asProverComponent().nConstraints(),
    );
    try std.testing.expectEqual(
        component.maxConstraintLogDegreeBound(),
        component.asVerifierComponent().maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!claim.component_sum.eql(QM31.zero()));
}

test "secp256k1 component: every row family instantiates one protocol shape" {
    inline for (.{
        config.Product(affine.ModulusKind.base),
        config.Product(affine.ModulusKind.scalar),
        config.Linear(affine.ModulusKind.base),
        config.Linear(affine.ModulusKind.scalar),
        config.Point,
        config.Split,
        config.ScalarProgram,
        config.Table,
        config.Ecdsa,
        config.ByteTable,
    }) |Config| {
        const Component = component_mod.Component(Config);
        try std.testing.expect(Component.ClaimType == component_mod.Claim(Config));
        try std.testing.expect(Config.main_column_count != 0);
        try std.testing.expect(Config.direct_constraint_count != 0);
        try std.testing.expect(Config.batch_count != 0);
    }
}

test "secp256k1 component: full CSP bundle has exact rows and component claims" {
    const fixture = @import("secp256k1_affine_test.zig").csp_input;
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    if (!try @import("secp256k1_ecdsa.zig").verify(
        &tape,
        fixture[0..32].*,
        fixture[32..97].*,
        fixture[97..129].*,
        fixture[129..161].*,
    )) return error.InvalidFixture;
    try expectExactTapeCustody(&tape);
    var bundle = try bundle_mod.generate(std.testing.allocator, &tape);
    defer bundle.deinit();
    const relations = relations_mod.Relations.dummy();
    try expectLinearEmittersMatchTape(&bundle, &tape, &relations);
    try std.testing.expectEqual(@as(usize, 228), bundle.point.n_rows);
    try std.testing.expectEqual(@as(usize, 2), bundle.split.n_rows);
    try std.testing.expectEqual(@as(usize, 68), bundle.table.n_rows);
    try std.testing.expectEqual(@as(usize, 1), bundle.ecdsa.n_rows);
    try std.testing.expectEqual(@as(usize, 256), bundle.byte.n_rows);

    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1 });
    defer pool.deinit();
    var total = QM31.zero();
    inline for (.{
        .{ bundle_mod.ProductBase, &bundle.product_base },
        .{ bundle_mod.ProductScalar, &bundle.product_scalar },
        .{ bundle_mod.LinearBase, &bundle.linear_base },
        .{ bundle_mod.LinearScalar, &bundle.linear_scalar },
        .{ config.Point, &bundle.point },
        .{ config.Split, &bundle.split },
        .{ config.ScalarProgram, &bundle.scalar },
        .{ config.Table, &bundle.table },
        .{ config.Ecdsa, &bundle.ecdsa },
        .{ config.ByteTable, &bundle.byte },
    }) |entry| {
        total = total.add(try checkComponent(entry[0], entry[1], &relations, &pool));
    }
    const public_call = relations_mod.combineEcdsa(
        M31,
        relations.ecdsa,
        relations_mod.ecdsaTupleForRecord(&tape.ecdsa.items[0]),
    );
    total = total.sub(try public_call.inv());
    try std.testing.expect(total.isZero());
}

fn expectLinearEmittersMatchTape(
    bundle: *const bundle_mod.Bundle,
    tape: *const affine.Tape,
    relations: *const relations_mod.Relations,
) !void {
    var base_row: usize = 0;
    var scalar_row: usize = 0;
    for (tape.linears.items, 0..) |*record, record_index| {
        const pair = switch (record.modulus) {
            .base => blk: {
                const main = bundle.linear_base.mainRow(base_row);
                base_row += 1;
                break :blk bundle_mod.LinearBase.rowPairs(
                    M31,
                    &main,
                    &main,
                    &main,
                    relations,
                )[0];
            },
            .scalar => blk: {
                const main = bundle.linear_scalar.mainRow(scalar_row);
                scalar_row += 1;
                break :blk bundle_mod.LinearScalar.rowPairs(
                    M31,
                    &main,
                    &main,
                    &main,
                    relations,
                )[0];
            },
        };
        const expected = relations_mod.combineLinear(
            M31,
            relations.linear,
            relations_mod.linearTupleForRecord(record),
        );
        if (!pair.d1.eql(expected)) {
            const main: [linear.Layout.main_columns]M31 = switch (record.modulus) {
                .base => bundle.linear_base.mainRow(base_row - 1),
                .scalar => bundle.linear_scalar.mainRow(scalar_row - 1),
            };
            const lhs = main[linear.Layout.lhs..][0..32].*;
            const rhs = main[linear.Layout.rhs..][0..32].*;
            const result = main[linear.Layout.result..][0..32].*;
            const kind = main[linear.Layout.selector_subtract]
                .add(main[linear.Layout.selector_reduce_once].mul(M31.fromU64(2)));
            const actual_tuple = relations_mod.linearTuple(
                M31,
                kind,
                M31.fromU64(@intFromEnum(record.modulus)),
                &lhs,
                &rhs,
                &result,
            );
            const expected_tuple = relations_mod.linearTupleForRecord(record);
            for (actual_tuple, expected_tuple, 0..) |actual_value, expected_value, tuple_index| {
                if (!actual_value.eql(expected_value)) std.debug.print(
                    "secp linear tuple[{d}] actual={d} expected={d}\n",
                    .{ tuple_index, actual_value.toU32(), expected_value.toU32() },
                );
            }
            std.debug.print(
                "secp linear emitter mismatch record={d} kind={s} modulus={s} n1={any} actual={any} expected={any}\n",
                .{
                    record_index,
                    @tagName(record.kind),
                    @tagName(record.modulus),
                    pair.n1,
                    pair.d1,
                    expected,
                },
            );
            return error.InvalidLinearEmitter;
        }
    }
}

fn expectExactTapeCustody(tape: *const affine.Tape) !void {
    const allocator = std.testing.allocator;
    const products = try allocator.alloc(u8, tape.products.items.len);
    defer allocator.free(products);
    @memset(products, 0);
    const linears = try allocator.alloc(u8, tape.linears.items.len);
    defer allocator.free(linears);
    @memset(linears, 0);
    const points = try allocator.alloc(u8, tape.points.items.len);
    defer allocator.free(points);
    @memset(points, 0);
    const splits = try allocator.alloc(u8, tape.scalar_splits.items.len);
    defer allocator.free(splits);
    @memset(splits, 0);
    const programs = try allocator.alloc(u8, tape.scalar_programs.items.len);
    defer allocator.free(programs);
    @memset(programs, 0);

    for (tape.points.items) |record| {
        for (record.product_start..record.product_start + record.product_count) |index| {
            products[index] += 1;
        }
        for (record.linear_start..record.linear_start + record.linear_count) |index| {
            linears[index] += 1;
        }
    }
    for (tape.scalar_splits.items) |record| {
        for (record.product_start..record.product_start + record.product_count) |index| {
            products[index] += 1;
        }
        for (record.linear_start..record.linear_start + record.linear_count) |index| {
            linears[index] += 1;
        }
    }
    for (tape.tables.items) |record| switch (record.kind) {
        .generator, .generator_endomorphism => {},
        .public_key, .public_key_endomorphism => {
            for (record.point_start..record.point_start + record.point_count) |index| {
                points[index] += 1;
            }
            for (record.negation_linear_start..record.negation_linear_start + affine.odd_table_size) |index| {
                linears[index] += 1;
            }
            if (record.kind == .public_key_endomorphism) {
                products[record.root_product_index] += 1;
            }
        },
    };
    for (tape.scalar_programs.items) |program| {
        for (program.split_start..program.split_start + 2) |index| splits[index] += 1;
        for (tape.scalar_steps.items[program.step_start..][0..program.step_count]) |step| {
            points[step.point_record_indices[0]] += 1;
            for (step.digits, 0..) |digit, scalar_index| {
                if (digit != 0) points[step.point_record_indices[1 + scalar_index]] += 1;
            }
        }
    }
    for (tape.ecdsa.items) |record| {
        for (record.product_start..record.product_start + 6) |index| products[index] += 1;
        linears[record.linear_start] += 1;
        linears[record.linear_start + 1] += 1;
        linears[record.linear_start + record.linear_count - 1] += 1;
        programs[record.program_index] += 1;
    }
    try expectUnitCustody("product", products);
    try expectUnitCustody("linear", linears);
    try expectUnitCustody("point", points);
    try expectUnitCustody("split", splits);
    try expectUnitCustody("program", programs);
}

fn expectUnitCustody(label: []const u8, counts: []const u8) !void {
    for (counts, 0..) |count, index| {
        if (count != 1) {
            std.debug.print("secp custody {s}[{d}]={d}\n", .{ label, index, count });
            return error.InvalidTapeCustody;
        }
    }
}

fn checkComponent(
    comptime Config: type,
    trace: *const trace_mod.Trace(Config),
    relations: *const relations_mod.Relations,
    pool: *work_pool.WorkPool,
) !QM31 {
    var interaction = try interaction_mod.generate(
        Config,
        std.testing.allocator,
        trace,
        relations,
        pool,
    );
    defer interaction.deinit(std.testing.allocator);
    const claim = try component_mod.Claim(Config).canonical(trace, interaction.claims);
    var direct_sum = QM31.zero();
    for (0..trace.domainSize()) |logical_row| {
        const size = trace.domainSize();
        const main = trace.mainRow(logical_row);
        const previous = trace.mainRow((logical_row + size - 1) % size);
        const next = trace.mainRow((logical_row + 1) % size);
        for (Config.rowPairs(M31, &main, &previous, &next, relations)) |pair| {
            const contribution = pair.n1.mul(try pair.d1.inv())
                .add(pair.n2.mul(try pair.d2.inv()));
            direct_sum = direct_sum.add(contribution);
        }
    }
    try std.testing.expect(claim.component_sum.eql(direct_sum));
    const component = try component_mod.Component(Config).init(
        claim,
        .{ .preprocessed_offset = 0, .main_offset = 0, .interaction_offset = 0 },
        relations,
    );
    try std.testing.expectEqual(
        Config.direct_constraint_count + Config.batch_count,
        component.asProverComponent().nConstraints(),
    );
    const size = trace.domainSize();
    for (0..size) |logical_row| {
        const main = trace.mainRow(logical_row);
        const previous = trace.mainRow((logical_row + size - 1) % size);
        const next = trace.mainRow((logical_row + 1) % size);
        var sink = Sink{};
        Config.evaluate(
            M31,
            &main,
            &previous,
            &next,
            trace.groupFirst(logical_row),
            trace.groupLast(logical_row),
            relations,
            &sink,
        );
        try std.testing.expectEqual(Config.direct_constraint_count, sink.count);
        if (sink.failures != 0) std.debug.print(
            "secp direct {s} row={d} failures={d}\n",
            .{ Config.stable_name, logical_row, sink.failures },
        );
        try std.testing.expectEqual(@as(usize, 0), sink.failures);
    }
    return claim.component_sum;
}

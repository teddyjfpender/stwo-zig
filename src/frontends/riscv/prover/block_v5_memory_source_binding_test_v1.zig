//! Nonproving bindings, proposal-file replay, and metadata epoch contracts.
//! Synthetic roots never authorize source equations; no PCS/proof runs here.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const First = @import("block_v5_memory_source_first_protocol_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Stream = @import("block_v5_memory_source_stream_v1.zig");
const Columns = @import("block_v5_memory_source_first_columns_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
const Routing = @import("block_v5_memory_source_binding_plan_v1.zig");
const Air = @import("block_v5_memory_source_binding_air_v1.zig");
const Interaction = @import("block_v5_memory_source_binding_interaction_v1.zig");
const Component = @import("block_v5_memory_source_binding_component_v1.zig");
const Store = @import("block_v5_memory_source_page_store_v1.zig");
const Page = @import("block_v5_memory_source_page_protocol_v1.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Placement = @import("../air/block/memory_component_trace.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
fn challenges() Source.Challenges {
    return .{ .word = .{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() }, .bytes = .dummy(), .input = .dummy(), .insertion = .dummy(), .before = .dummy(), .after = .dummy(), .route = .dummy(), .roots = .dummy(), .ordering = .dummy(), .sha_chain = .dummy() };
}
fn admitted() !Source.Admitted {
    const sha = Initial.sha256("");
    return Source.make(.{ .initial = .{
        .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 256, .stack_bottom = 128, .stack_top = 512, .io_base = 256, .io_end = 768, .input_base = 32, .input_end = 64, .output_len_addr = 64, .output_data_addr = 68, .output_base = 64, .output_end = 256 },
        .initial_rw_root = @splat(1),
        .initial_registers = @splat(0),
        .public_input_sha256 = sha,
        .public_input_len = 3,
        .input_words = .{ .records = 1, .sha256 = sha },
        .rw_words = .{ .records = 1, .sha256 = sha },
        .first_touches = .{ .records = 1, .sha256 = sha },
    }, .memory_plan_digest = @splat(7), .expected_final_rw_root = @splat(2), .endpoints = .{ .records = 1, .sha256 = sha } }, @splat(8), .{});
}
fn firstPlan(a: *const Source.Admitted, log: u32) !First.Plan {
    return First.init(a, .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 2, 8) }, .{ .page_row_log = log });
}
fn pin(plan: First.Plan, at: u32) !First.Pin {
    return .{ .plan_id = plan.identity, .page = try plan.page(at), .roots = .{ @splat(20), @splat(30) }, .config = plan.config };
}
fn wire() Air.Algebra(Q).Challenge {
    const element = @import("../recursion/air/universal_challenges.zig").Elements.init(6, Q.fromU32Unchecked(91, 97, 103, 109), Q.fromU32Unchecked(3, 5, 7, 11));
    return .{ .z = element.z, .powers = element.alpha_powers[0..6].* };
}
fn routingContract(a: std.mem.Allocator) !void {
    const source = try admitted();
    const first = try firstPlan(&source, 1);
    const expected = try pin(first, first.pages - 1); // actual last root chunk
    const kind = try Stream.kindAt(&source, expected.page.first_chunk);
    try std.testing.expectEqual(std.meta.Tag(Eq.Kind).root, std.meta.activeTag(kind));
    var routing = try Routing.Plan.init(a, &source, first, expected, challenges(), .{ .page_row_log = 1 }, .{});
    defer routing.deinit();
    try std.testing.expect(routing.total_uses > 0 and routing.total_uses < core.fields.m31.Modulus);
    const physical = Placement.committedRow(0, 1);
    try std.testing.expectEqual(try Page.circuitId(expected.page.first_chunk), routing.column(0)[physical].toU32());
    const tail = Placement.committedRow(1, 1);
    for (0..Routing.ROUTING_COUNT) |column| try std.testing.expect(routing.column(column)[tail].isZero());
    var tiny = Routing.Limits{};
    tiny.max_routing_cells = 1;
    try std.testing.expectError(error.MemorySourceBindingResourceLimit, Routing.Plan.init(a, &source, first, expected, challenges(), .{ .page_row_log = 1 }, tiny));
}
test "source binding routing: actual independent kind graph exact private node fanout and canonical tail" {
    try routingContract(std.testing.allocator);
}
test "source binding routing faults: all independent graph and owner allocations unwind" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, routingContract, .{});
}
fn evaluateRow(cols: *const Columns.Columns, routing: *const Routing.Plan, generated: *const Interaction.Generated, logical: usize) ![Air.CONSTRAINT_COUNT]Q {
    const row = Placement.committedRow(logical, cols.page.row_log);
    const prior = Placement.committedRow((logical + cols.rows() - 1) % cols.rows(), cols.page.row_log);
    try std.testing.expectEqual(prior, core.utils.previousBitReversedCircleDomainIndex(row, cols.page.row_log, cols.page.row_log));
    var fixed: [Air.FIXED_COUNT]Q = undefined;
    var bits: [Air.MAIN_COUNT]Q = undefined;
    var current: [Air.INTERACTION_COUNT]Q = undefined;
    var previous: [Air.INTERACTION_COUNT]Q = undefined;
    for (0..First.FIXED_COUNT) |i| fixed[i] = Q.fromBase(cols.fixedColumn(i)[row]);
    for (0..Routing.ROUTING_COUNT) |i| fixed[First.FIXED_COUNT + i] = Q.fromBase(routing.column(i)[row]);
    for (&bits, 0..) |*out, i| out.* = Q.fromBase(cols.mainColumn(i)[row]);
    for (&current, &previous, 0..) |*out, *before, i| {
        out.* = Q.fromBase(generated.cells[i * cols.rows() + row]);
        before.* = Q.fromBase(generated.cells[i * cols.rows() + prior]);
    }
    return Air.Algebra(Q).constraints(fixed, bits, current, previous, try Interaction.normalize(generated.claim, routing), wire());
}
fn anyFailure(equations: [Air.CONSTRAINT_COUNT]Q) bool {
    for (equations) |q| if (!q.isZero()) return true;
    return false;
}
test "source binding equations: original cells prefix wire census value-use-clock tails and mutations" {
    const a = std.testing.allocator;
    const source = try admitted();
    const first = try firstPlan(&source, 1);
    const expected = try pin(first, first.pages - 1);
    var routing = try Routing.Plan.init(a, &source, first, expected, challenges(), .{ .page_row_log = 1 }, .{});
    defer routing.deinit();
    var cols = try Columns.Columns.init(a, &source, first, expected.page, .{ .page_row_log = 1 });
    defer cols.deinit();
    try cols.append(&source, .{ .kind = try Stream.kindAt(&source, expected.page.first_chunk), .witness = .{ .clock = 0xfedcba9876543210, .after_hash = @splat(0x80) } });
    var generated = try Interaction.generate(a, &cols, &routing, wire(), 1 << 20);
    defer generated.deinit();
    for (0..cols.rows()) |logical| try std.testing.expect(!anyFailure(try evaluateRow(&cols, &routing, &generated, logical)));
    const row = Placement.committedRow(0, 1);
    const saved = cols.main[row];
    cols.main[row] = M.one().sub(saved);
    try std.testing.expect(anyFailure(try evaluateRow(&cols, &routing, &generated, 0)));
    cols.main[row] = saved;
    const value = generated.cells[row];
    generated.cells[row] = value.add(M.one());
    try std.testing.expect(anyFailure(try evaluateRow(&cols, &routing, &generated, 0)));
    generated.cells[row] = value;
    const use = routing.routing[2 * cols.rows() + row];
    routing.routing[2 * cols.rows() + row] = use.add(M.one());
    try std.testing.expect(anyFailure(try evaluateRow(&cols, &routing, &generated, 0)));
    routing.routing[2 * cols.rows() + row] = use;
    const tail = Placement.committedRow(1, 1);
    cols.main[tail] = M.one();
    try std.testing.expect(anyFailure(try evaluateRow(&cols, &routing, &generated, 1)));
    var wrong_count = generated.claim;
    wrong_count.total_uses += 1;
    try std.testing.expectError(error.InvalidMemorySourceBindingClaim, Interaction.normalize(wrong_count, &routing));
}
const Degree = struct {
    n: u8,
    pub fn zero() Degree {
        return .{ .n = 0 };
    }
    pub fn one() Degree {
        return zero();
    }
    pub fn add(x: Degree, y: Degree) Degree {
        return .{ .n = @max(x.n, y.n) };
    }
    pub fn sub(x: Degree, y: Degree) Degree {
        return add(x, y);
    }
    pub fn mul(x: Degree, y: Degree) Degree {
        return .{ .n = x.n + y.n };
    }
    pub fn fromPartialEvals(v: [4]Degree) Degree {
        var result = zero();
        for (v) |d| result = add(result, d);
        return result;
    }
};
test "source binding degree: every original-main and two-fraction equation has declared degree2 or3" {
    const variable = Degree{ .n = 1 };
    const checks = Air.Algebra(Degree).constraints(@splat(variable), @splat(variable), @splat(variable), @splat(variable), @splat(Degree.zero()), .{ .z = .zero(), .powers = @splat(Degree.zero()) });
    for (checks, 0..) |value, i| try std.testing.expectEqual(try Air.degree(i), value.n);
}
fn loadContract(a: std.mem.Allocator, dir: std.fs.Dir, source: *const Source.Admitted, plan: First.Plan, expected: First.Pin, stored: Store.Pin) !void {
    var replayed = try Store.load(a, dir, "source.bits", source, plan, expected, stored, .{ .page_row_log = 7 }, .{});
    defer replayed.deinit();
    try std.testing.expectEqual(expected.page.chunks, replayed.written);
    try std.testing.expectEqual(@as(u64, 0xfedcba9876543210), (try replayed.witness(0)).clock);
}
test "source binding replay: streaming packed file scope hash length padding exclusive publication and load faults" {
    const a = std.testing.allocator;
    const source = try admitted();
    const plan = try firstPlan(&source, 7);
    const expected = try pin(plan, 0);
    var cols = try Columns.Columns.init(a, &source, plan, expected.page, .{ .page_row_log = 7 });
    defer cols.deinit();
    for (0..expected.page.chunks) |i| try cols.append(&source, .{ .kind = try Stream.kindAt(&source, i), .witness = .{ .clock = 0xfedcba9876543210, .raw = @splat(0xa5) } });
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const stored = try Store.write(tmp.dir, "source.bits", plan, expected, &cols, .{});
    try std.testing.expect(stored.bytes > 4096 and stored.bytes < cols.main.len * @sizeOf(M));
    try std.testing.expectError(error.ExistingMemorySourcePage, Store.write(tmp.dir, "source.bits", plan, expected, &cols, .{}));
    try loadContract(a, tmp.dir, &source, plan, expected, stored);
    try std.testing.checkAllAllocationFailures(a, loadContract, .{ tmp.dir, &source, plan, expected, stored });
    var hash = stored;
    hash.sha256[0] ^= 1;
    try std.testing.expectError(error.UntrustedMemorySourcePageHash, Store.load(a, tmp.dir, "source.bits", &source, plan, expected, hash, .{ .page_row_log = 7 }, .{}));
    var short = stored;
    short.bytes -= 1;
    try std.testing.expectError(error.InvalidMemorySourcePageLength, Store.load(a, tmp.dir, "source.bits", &source, plan, expected, short, .{ .page_row_log = 7 }, .{}));
    var swapped = expected;
    swapped.roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedMemorySourcePageHeader, Store.load(a, tmp.dir, "source.bits", &source, plan, swapped, stored, .{ .page_row_log = 7 }, .{}));
    const tail = Placement.committedRow(expected.page.chunks, 7);
    cols.main[tail] = M.one();
    try std.testing.expectError(error.NonCanonicalMemorySourcePageTail, Store.write(tmp.dir, "bad.bits", plan, expected, &cols, .{}));
}

test "source binding masks: four actual trees retain original source cells and only prefixes shift" {
    const a = std.testing.allocator;
    const source = try admitted();
    const first = try firstPlan(&source, 1);
    const expected = try pin(first, first.pages - 1);
    var routing = try Routing.Plan.init(a, &source, first, expected, challenges(), .{ .page_row_log = 1 }, .{});
    defer routing.deinit();
    const claim = Interaction.Claim{ .sums = @splat(Q.zero()), .total_uses = routing.total_uses };
    const component = try Component.Component.init(&routing, claim, wire());
    var logs = try component.traceLogDegreeBounds(a);
    defer logs.deinitDeep(a);
    const lengths = [_]usize{ First.FIXED_COUNT, Air.MAIN_COUNT, Routing.ROUTING_COUNT, Air.INTERACTION_COUNT };
    for (logs.items, lengths) |tree, length| try std.testing.expectEqual(length, tree.len);
    const seed = Q.fromU32Unchecked(13, 17, 19, 23);
    const square = seed.square();
    const inverse = try square.add(Q.one()).inv();
    const point = core.circle.CirclePointQM31{ .x = Q.one().sub(square).mul(inverse), .y = seed.add(seed).mul(inverse) };
    var masks = try component.maskPoints(a, point, 3);
    defer masks.deinitDeep(a);
    for (masks.items, lengths, 0..) |tree, length, index| {
        try std.testing.expectEqual(length, tree.len);
        for (tree) |points| {
            try std.testing.expectEqual(@as(usize, if (index == 3) 2 else 1), points.len);
            try std.testing.expectEqualDeep(point, points[0]);
        }
    }
    try std.testing.expectError(error.InvalidV5WordMask, component.maskPoints(a, point, 0));
}

test "source binding epoch: both request and supplier roots precede dedicated wire draw" {
    var proposal = try admitted();
    const template = try firstPlan(&proposal, 2);
    var counts: [Seal.family_count]u32 = @splat(0);
    const families = [_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory };
    for (families) |family| counts[@intFromEnum(family) - 1] = 1;
    const base_pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = proposal.pins.memory_plan_digest, .initial_source_plan_digest = try proposal.pins.initial.digest(), .expected_final_rw_root = proposal.pins.expected_final_rw_root, .rw_endpoint_plan_digest = try proposal.pins.digest(), .register_endpoint_plan_digest = @splat(6), .register_custody_mode = 1, .config = template.config, .counts = counts };
    var base_entries: [5]Seal.Entry = undefined;
    for (&base_entries, families) |*entry, family| entry.* = .{ .family = family, .index = 0, .instance_id = @splat(9), .roots = .{ @splat(10), @splat(11) } };
    const base = try Seal.seal(base_pins, &base_entries);
    proposal = try Source.admit(proposal.pins, base_pins, &base_entries, base, .{});
    const first = try firstPlan(&proposal, 2);
    const a = std.testing.allocator;
    const sources = try a.alloc(First.Pin, first.pages);
    defer a.free(sources);
    const arithmetic = try a.alloc(Page.ArithmeticPin, first.pages);
    defer a.free(arithmetic);
    for (sources, arithmetic, 0..) |*source_pin, *arith, i| {
        source_pin.* = try pin(first, @intCast(i));
        arith.* = .{ .page_index = @intCast(i), .source_pin_id = try source_pin.identity(first), .graph_roster_id = @splat(40), .roots = .{ @splat(50), @splat(60) } };
    }
    const sealed = try First.seal(&proposal, first, sources, .{ .page_row_log = 2 });
    const old = try Page.draw(a, &proposal, first, sources, sealed, sealed.digest, base, arithmetic, arithmetic, .{ .page_row_log = 2 });
    const epoch = try Page.sourceEpoch(a, &proposal, first, sources, sealed, sealed.digest, base, .{ .page_row_log = 2 });
    try std.testing.expectEqualDeep(epoch.source, old.source);
    arithmetic[arithmetic.len - 1].roots[1][0] ^= 1;
    const changed = try Page.draw(a, &proposal, first, sources, sealed, sealed.digest, base, arithmetic, arithmetic, .{ .page_row_log = 2 });
    try std.testing.expectEqualDeep(old.source, changed.source);
    try std.testing.expect(!old.arithmetic.get(.recursion_wire).z.eql(changed.arithmetic.get(.recursion_wire).z));
    try std.testing.expect(!old.arithmetic.get(.recursion_wire).z.eql(old.source.word.universal_prefix.get(.recursion_wire).z));
    const received = try a.dupe(Page.ArithmeticPin, arithmetic);
    defer a.free(received);
    received[0].roots[1][0] ^= 1;
    try std.testing.expectError(error.InvalidMemorySourceArithmeticRoster, Page.draw(a, &proposal, first, sources, sealed, sealed.digest, base, arithmetic, received, .{ .page_row_log = 2 }));
    try std.testing.expectError(error.InvalidMemorySourceArithmeticRoster, Page.draw(a, &proposal, first, sources, sealed, sealed.digest, base, arithmetic[0..1], arithmetic[0..1], .{ .page_row_log = 2 }));
    received[0] = arithmetic[0];
    received[0].source_pin_id[0] ^= 1;
    try std.testing.expectError(error.InvalidMemorySourceArithmeticRoster, Page.draw(a, &proposal, first, sources, sealed, sealed.digest, base, arithmetic, received, .{ .page_row_log = 2 }));
}

test "source binding packed: scalar and SIMD equations agree at nonzero extension-coordinate samples" {
    @setEvalBranchQuota(1_000_000);
    const P = core.fields.packed_qm31.PackedQM31;
    const a = std.testing.allocator;
    const source = try admitted();
    const first = try firstPlan(&source, 1);
    const expected = try pin(first, first.pages - 1);
    var routing = try Routing.Plan.init(a, &source, first, expected, challenges(), .{ .page_row_log = 1 }, .{});
    defer routing.deinit();
    const spec = Component.Spec{ .plan = &routing, .claim = .{ .sums = @splat(Q.fromU32Unchecked(31, 37, 41, 43)), .total_uses = routing.total_uses }, .challenge = wire() };
    const domain = try spec.prepareDomain(2);
    const fixed: [Air.FIXED_COUNT]Q = @splat(Q.fromU32Unchecked(17, 19, 23, 29));
    const main: [Air.MAIN_COUNT]Q = @splat(Q.fromU32Unchecked(47, 53, 59, 61));
    const current: [Air.INTERACTION_COUNT]Q = @splat(Q.fromU32Unchecked(67, 71, 73, 79));
    const previous: [Air.INTERACTION_COUNT]Q = @splat(Q.fromU32Unchecked(83, 89, 97, 101));
    const scalar = try domain.evaluate(fixed, main, @splat(Q.zero()), current, previous, 2);
    var fixed_packed: [Air.FIXED_COUNT]P = undefined;
    var main_packed: [Air.MAIN_COUNT]P = undefined;
    var current_packed: [Air.INTERACTION_COUNT]P = undefined;
    var previous_packed: [Air.INTERACTION_COUNT]P = undefined;
    for (&fixed_packed, fixed) |*out, value| out.* = P.splat(value);
    for (&main_packed, main) |*out, value| out.* = P.splat(value);
    for (&current_packed, current) |*out, value| out.* = P.splat(value);
    for (&previous_packed, previous) |*out, value| out.* = P.splat(value);
    const vector = domain.evaluatePacked(fixed_packed, main_packed, @splat(P.zero()), current_packed, previous_packed);
    for (scalar, vector) |expected_value, result| for (0..core.fields.m31.PACK_WIDTH) |lane| try std.testing.expectEqualDeep(expected_value, result.lane(lane));
}

test "source binding replay owner: live page prevents reader teardown and invalid phases fail closed" {
    const Reader = @import("block_v5_memory_source_page_replay_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).Reader;
    var reader = Reader{ .active = true };
    try std.testing.expectError(error.MemorySourceReplayOwnerLive, reader.deinit());
    try std.testing.expect(reader.live and reader.active);
    reader.active = false;
    try reader.deinit();
    try std.testing.expectError(error.MemorySourceReplayOwnerLive, reader.deinit());
}

//! Nonproving metadata/cell/ownership contracts. No PCS, proof, guest or device
//! operations are invoked; synthetic roots here are explicitly proposals.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const First = @import("block_v5_memory_source_first_protocol_v1.zig");
const Columns = @import("block_v5_memory_source_first_columns_v1.zig");
const Round = @import("block_v5_memory_source_first_round_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Stream = @import("block_v5_memory_source_stream_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Endpoint = @import("block_v5_rw_endpoint_sources_v1.zig");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const Placement = @import("../air/block/memory_component_trace.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const limits = First.Limits{ .page_row_log = 2 };
const Fixture = struct {
    admitted: Source.Admitted,
    base_pins: Seal.Pins,
    entries: [4]Seal.Entry,
    base: Seal.Sealed,
    plan: First.Plan,
    pins: [2]First.Pin,
    source_seal: First.Sealed,
    fn init() !Fixture {
        const empty = Initial.sha256("");
        const root = Tree.TreeHasher.init(.memory).defaults[0].bytes;
        const endpoint = Endpoint.Pins{ .initial = .{
            .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 256, .stack_bottom = 128, .stack_top = 512, .io_base = 256, .io_end = 768, .input_base = 32, .input_end = 64, .output_len_addr = 64, .output_data_addr = 68, .output_base = 64, .output_end = 256 },
            .initial_rw_root = root,
            .initial_registers = @splat(0),
            .public_input_sha256 = empty,
            .public_input_len = 0,
            .input_words = .{ .sha256 = empty, .records = 0 },
            .rw_words = .{ .sha256 = empty, .records = 0 },
            .first_touches = .{ .sha256 = empty, .records = 0 },
        }, .memory_plan_digest = @splat(7), .expected_final_rw_root = root, .endpoints = .{ .sha256 = empty, .records = 0 } };
        var counts: [Seal.family_count]u32 = @splat(0);
        const families = [_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request };
        for (families) |family| counts[@intFromEnum(family) - 1] = 1;
        const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 2, 8) };
        const base_pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = endpoint.memory_plan_digest, .initial_source_plan_digest = try endpoint.initial.digest(), .expected_final_rw_root = root, .rw_endpoint_plan_digest = try endpoint.digest(), .register_endpoint_plan_digest = @splat(6), .register_custody_mode = 1, .config = config, .counts = counts };
        var entries: [4]Seal.Entry = undefined;
        for (&entries, families) |*e, family| e.* = .{ .family = family, .index = 0, .instance_id = @splat(9), .roots = .{ @splat(10), @splat(11) } };
        const base = try Seal.seal(base_pins, &entries);
        const admitted = try Source.admit(endpoint, base_pins, &entries, base, .{});
        const plan = try First.init(&admitted, config, limits);
        var pins: [2]First.Pin = undefined;
        for (&pins, 0..) |*pin, i| pin.* = .{ .plan_id = plan.identity, .page = try plan.page(@intCast(i)), .roots = .{ @splat(@as(u8, @intCast(i + 20))), @splat(@as(u8, @intCast(i + 30))) }, .config = config };
        return .{ .admitted = admitted, .base_pins = base_pins, .entries = entries, .base = base, .plan = plan, .pins = pins, .source_seal = try First.seal(&admitted, plan, &pins, limits) };
    }
};
fn dummy() Source.Challenges {
    return .{ .word = .{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() }, .bytes = .dummy(), .input = .dummy(), .insertion = .dummy(), .before = .dummy(), .after = .dummy(), .route = .dummy(), .roots = .dummy(), .ordering = .dummy(), .sha_chain = .dummy() };
}
test "source first metadata: exact census tail roster source identity and configured caps" {
    const f = try Fixture.init();
    try std.testing.expectEqual(@as(u64, 5), f.plan.total_chunks);
    try std.testing.expectEqual(@as(u32, 2), f.plan.pages);
    try std.testing.expectEqual(@as(u32, 1), f.pins[1].page.chunks);
    _ = try First.admitPage(&f.admitted, f.plan, f.pins[1], &f.pins, f.source_seal, f.source_seal.digest, f.base_pins, &f.entries, f.base, limits);
    var missing = f.pins;
    std.mem.swap(First.Pin, &missing[0], &missing[1]);
    try std.testing.expectError(error.InvalidSourceFirstRoster, First.seal(&f.admitted, f.plan, &missing, limits));
    try std.testing.expectError(error.InvalidSourceFirstRoster, First.seal(&f.admitted, f.plan, f.pins[0..1], limits));
    var plan = f.plan;
    plan.total_chunks += 1;
    try std.testing.expectError(error.InvalidSourceFirstPlan, plan.require(&f.admitted, limits));
    var pin = f.pins[0];
    pin.page.first_chunk += 1;
    try std.testing.expectError(error.UntrustedSourceFirstPin, pin.require(f.plan));
    pin = f.pins[0];
    pin.roots[0] = @splat(0);
    try std.testing.expectError(error.UntrustedSourceFirstPin, pin.require(f.plan));
    pin = f.pins[0];
    pin.config.pow_bits = 1;
    try std.testing.expectError(error.UntrustedSourceFirstPin, pin.require(f.plan));
    var cap = limits;
    cap.max_private_cells = 1;
    try std.testing.expectError(error.SourceFirstResourceLimit, First.init(&f.admitted, f.plan.config, cap));
    cap = limits;
    cap.max_pages = 1;
    try std.testing.expectError(error.SourceFirstResourceLimit, First.init(&f.admitted, f.plan.config, cap));
    var edge = limits;
    edge.page_row_log = 1;
    const smallest = try First.init(&f.admitted, f.plan.config, edge);
    try std.testing.expectEqual(@as(u32, 3), smallest.pages);
    try std.testing.expectEqual(@as(u32, 1), (try smallest.page(2)).chunks);
    edge.page_row_log = 0;
    try std.testing.expectError(error.SourceFirstResourceLimit, First.init(&f.admitted, f.plan.config, edge));
    var wrong_seal = f.source_seal;
    wrong_seal.plan_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedSourceFirstSeal, wrong_seal.require(&f.admitted, f.plan, &f.pins, f.source_seal.digest, limits));
    var source = f.admitted;
    source.pins.expected_final_rw_root[0] ^= 1;
    source = try Source.make(source.pins, source.sealed_digest, source.limits);
    try std.testing.expectError(error.InvalidMemorySourceAdmission, First.admitPage(&source, f.plan, f.pins[0], &f.pins, f.source_seal, f.source_seal.digest, f.base_pins, &f.entries, f.base, limits));
}
test "source first transcript: full source roster precedes internal draws while word draws remain exact" {
    const f = try Fixture.init();
    const c = try First.draw(std.testing.allocator, &f.admitted, f.plan, &f.pins, f.source_seal, f.source_seal.digest, f.base, limits);
    try std.testing.expectEqualDeep(try Word.Challenges.draw(std.testing.allocator, f.base), c.word);
    var channel = f.base.sharedChannel();
    try std.testing.expectEqualDeep(c, try First.drawFromChannel(std.testing.allocator, &channel, f.source_seal));
    var changed = f.pins;
    changed[1].roots[1][0] ^= 1;
    const sealed = try First.seal(&f.admitted, f.plan, &changed, limits);
    const d = try First.draw(std.testing.allocator, &f.admitted, f.plan, &changed, sealed, sealed.digest, f.base, limits);
    try std.testing.expectEqualDeep(c.word, d.word);
    try std.testing.expect(!c.bytes.z.eql(d.bytes.z));
    try std.testing.expectError(error.UntrustedSourceFirstSeal, First.draw(std.testing.allocator, &f.admitted, f.plan, &changed, sealed, f.source_seal.digest, f.base, limits));
}
fn drawContract(a: std.mem.Allocator) !void {
    const f = try Fixture.init();
    _ = try First.draw(a, &f.admitted, f.plan, &f.pins, f.source_seal, f.source_seal.digest, f.base, limits);
}
test "source first draw allocations: every challenge allocation failure propagates without leaks" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, drawContract, .{});
}
fn columnsContract(a: std.mem.Allocator) !void {
    const f = try Fixture.init();
    const page = f.pins[1].page;
    var cols = try Columns.Columns.init(a, &f.admitted, f.plan, page, limits);
    defer cols.deinit();
    const kind = try Stream.kindAt(&f.admitted, page.first_chunk);
    var wrong_kind = kind;
    wrong_kind.sha.stream = .public_input;
    try std.testing.expectError(error.UntrustedSourceFirstChunk, cols.append(&f.admitted, .{ .kind = wrong_kind, .witness = .{} }));
    var witness = Eq.Witness{ .state = .{ 0, 1, 0x80000000, 0xffffffff, 3, 5, 7, 11 }, .address = 0xfffffffc, .previous_address = 0x80000000, .before = 0xffffffff, .after = 0x80000001, .clock = 0xfedcba9876543210, .before_hash = @splat(0x80), .after_hash = @splat(0xff), .sibling = @splat(0x55) };
    for (&witness.raw, 0..) |*b, i| b.* = @truncate(i * 17 + 3);
    try cols.append(&f.admitted, .{ .kind = kind, .witness = witness });
    try std.testing.expectEqualDeep(witness, try cols.witness(0));
    try std.testing.expectError(error.UntrustedSourceFirstChunk, cols.append(&f.admitted, .{ .kind = kind, .witness = witness }));
    var oracle: [Eq.INPUT_COUNT]Q = undefined;
    try Eq.writeInputs(witness, dummy(), .{}, &oracle);
    const physical = Placement.committedRow(0, page.row_log);
    for (0..Eq.BIT_COUNT) |i| try std.testing.expectEqualDeep(try oracle[i].tryIntoM31(), cols.mainColumn(i)[physical]);
    for (1..cols.rows()) |logical| {
        const row = Placement.committedRow(logical, page.row_log);
        for (0..First.MAIN_COUNT) |i| try std.testing.expect(cols.mainColumn(i)[row].isZero());
        const fixed = try Columns.fixedAt(&f.admitted, page, logical);
        for (fixed, 0..) |value, i| try std.testing.expectEqualDeep(value, cols.fixedColumn(i)[row]);
    }
    const digest = cols.snapshot();
    cols.main[physical] = M.fromCanonical(2);
    try std.testing.expect(!std.meta.eql(digest, cols.snapshot()));
    try std.testing.expectError(error.InvalidSourcePrivateBit, cols.witness(0));
    try std.testing.expectError(error.InvalidSourceFirstChunk, First.admitChunk(&f.admitted, f.plan, f.pins[1], 1, kind, limits));
    var invalid = page;
    invalid.first_chunk = std.math.maxInt(u64);
    invalid.chunks = 2;
    try std.testing.expectError(error.InvalidSourceFirstRow, Columns.fixedAt(&f.admitted, invalid, 1));
}
test "source first columns: all private graph inputs exact circle placement full clocks and canonical tail" {
    try columnsContract(std.testing.allocator);
}
test "source first allocations: every column-owner allocation failure cleans up" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, columnsContract, .{});
}
fn emptyRead(_: *anyopaque, _: Source.Stream, _: u64, dst: []u8) !void {
    if (dst.len != 0) return error.UnexpectedSourceRead;
}
fn emptyOpening(_: *anyopaque, _: u64, _: u32, _: u32, _: u32) !Stream.Opening {
    return error.UnexpectedSourceOpening;
}
test "source first collection phase: empty files require all five real SHA chunks and no synthetic absence" {
    const f = try Fixture.init();
    var marker: u8 = 0;
    var collector = try Round.Collector.init(f.admitted, .{ .context = &marker, .read = emptyRead, .opening = emptyOpening }, f.plan, limits);
    try std.testing.expectError(error.InvalidSourceFirstCollectionPhase, collector.requireFinished());
    for (0..f.plan.total_chunks) |i| {
        const chunk = (try collector.cursor.next()).?;
        try std.testing.expectEqualDeep(try Stream.kindAt(&f.admitted, i), chunk.kind);
    }
    collector.next_page = f.plan.pages;
    collector.active_page = true;
    try std.testing.expectError(error.InvalidSourceFirstCollectionPhase, collector.requireFinished());
    collector.active_page = false;
    try collector.requireFinished();
    collector.failed = true;
    try std.testing.expectError(error.InvalidSourceFirstCollectionPhase, collector.requireFinished());
}

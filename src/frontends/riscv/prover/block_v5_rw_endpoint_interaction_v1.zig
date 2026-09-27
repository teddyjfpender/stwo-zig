//! Exact final memory-space endpoints projected from committed sorted rows.
//! At each key change the predecessor's final value is emitted once, including
//! cross-instance predecessors; the global last row supplies the final key.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const component = @import("../air/block/memory_component.zig");
const trace = @import("../air/block/memory_component_trace.zig");
const order = @import("../air/block/memory_order.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const bus = @import("block_memory_relation_v2.zig");
const framework = @import("../recursion/air/framework_interaction.zig");
pub const WIDTH = 17; // space, address LE4, clock LE8, final value LE4
pub const COLUMN_COUNT = 16;
pub const Claim = struct { sum: Q, count: u64 };
pub const Point = struct { previous_select: Q, last_select: Q, previous: [WIDTH]Q, last: [WIDTH]Q };
pub fn draw(a: std.mem.Allocator, sealed: anytype) !universal.Elements {
    var channel = sealed.sharedChannel();
    _ = try bus.Challenges.drawFromChannel(a, &channel);
    channel.mixU32s(&.{ 0x42354550, 1, WIDTH }); // B5EP
    const z = channel.drawSecureFelt();
    const alpha = channel.drawSecureFelt();
    return universal.Elements.init(WIDTH, z, alpha);
}
pub fn point(fixed: []const Q, main: []const Q) !Point {
    if (fixed.len != trace.fixed_column_count or main.len != trace.main_column_count) return error.InvalidV5EndpointColumns;
    var result = Point{
        .previous_select = fixed[trace.fixed.active].sub(fixed[trace.fixed.global_first]).mul(Q.one().sub(main[order.Layout.same])).mul(main[component.Layout.linked_previous + 4]),
        .last_select = fixed[trace.fixed.global_last].mul(main[order.Layout.current_key + 4]),
        .previous = undefined,
        .last = undefined,
    };
    result.previous[0] = main[component.Layout.linked_previous + 4];
    @memcpy(result.previous[1..5], main[component.Layout.linked_previous..][0..4]);
    @memcpy(result.previous[5..13], main[component.Layout.linked_previous + 5 ..][0..8]);
    @memcpy(result.previous[13..17], main[component.Layout.linked_previous + 13 ..][0..4]);
    result.last[0] = main[order.Layout.current_key + 4];
    @memcpy(result.last[1..5], main[order.Layout.current_key..][0..4]);
    @memcpy(result.last[5..13], main[order.Layout.current_clock..][0..8]);
    @memcpy(result.last[13..17], main[component.Layout.after..][0..4]);
    return result;
}
pub fn constraints(elements: *const universal.Elements, p: Point, current: [COLUMN_COUNT]Q, previous: [COLUMN_COUNT]Q, claim: Claim, size: u32) ![4]Q {
    if (elements.arity != WIDTH or size == 0 or claim.count >= core.fields.m31.Modulus) return error.InvalidV5EndpointClaim;
    const before_term = secure(current, 0);
    const last_term = secure(current, 4);
    return .{
        (try elements.combineSecure(&p.previous)).mul(before_term).sub(p.previous_select),
        (try elements.combineSecure(&p.last)).mul(last_term).sub(p.last_select),
        secure(current, 8).sub(secure(previous, 8)).add(try claim.sum.divM31(M.fromCanonical(size))).sub(before_term).sub(last_term),
        secure(current, 12).sub(secure(previous, 12)).add(Q.fromBase(M.fromCanonical(@intCast(claim.count))).divM31(M.fromCanonical(size)) catch return error.InvalidV5EndpointClaim).sub(p.previous_select).sub(p.last_select),
    };
}
pub const Generated = struct {
    storage: []M,
    columns: [COLUMN_COUNT][]M,
    claim: Claim,
    pub fn deinit(self: *Generated, a: std.mem.Allocator) void {
        a.free(self.storage);
        self.* = undefined;
    }
};
pub fn generate(a: std.mem.Allocator, source: anytype, elements: *const universal.Elements) !Generated {
    if (!source.sealed or source.claim.total_rows >= core.fields.m31.Modulus) return error.InvalidV5EndpointSource;
    const size = source.domainSize();
    const storage = try a.alloc(M, size * COLUMN_COUNT);
    errdefer a.free(storage);
    var columns: [COLUMN_COUNT][]M = undefined;
    for (&columns, 0..) |*column, i| column.* = storage[i * size ..][0..size];
    var sum = Q.zero();
    var count: u64 = 0;
    for (0..size) |logical| {
        const physical = framework.committedRow(logical, source.claim.log_size);
        var fixed: [trace.fixed_column_count]Q = undefined;
        var main: [trace.main_column_count]Q = undefined;
        for (&fixed, 0..) |*value, i| value.* = Q.fromBase(source.fixedColumn(i)[physical]);
        const logical_row = source.inputRow(logical);
        for (&main, 0..) |*value, i| value.* = Q.fromBase(logical_row[i]);
        const p = try point(&fixed, &main);
        var terms: [2]Q = .{ Q.zero(), Q.zero() };
        for ([_]Q{ p.previous_select, p.last_select }, [_][WIDTH]Q{ p.previous, p.last }, &terms) |select, tuple, *term| {
            if (select.eql(Q.one())) {
                term.* = try (try elements.combineSecure(&tuple)).inv();
                count += 1;
            } else if (!select.isZero()) return error.InvalidV5EndpointSelector;
            sum = sum.add(term.*);
        }
        write(&columns, 0, physical, terms[0]);
        write(&columns, 4, physical, terms[1]);
        write(&columns, 12, physical, p.previous_select.add(p.last_select));
    }
    const sum_shift = try sum.divM31(M.fromCanonical(@intCast(size)));
    const count_shift = try Q.fromBase(M.fromCanonical(@intCast(count))).divM31(M.fromCanonical(@intCast(size)));
    var running_sum = Q.zero();
    var running_count = Q.zero();
    for (0..size) |logical| {
        const physical = framework.committedRow(logical, source.claim.log_size);
        running_sum = running_sum.add(read(&columns, 0, physical)).add(read(&columns, 4, physical)).sub(sum_shift);
        running_count = running_count.add(read(&columns, 12, physical)).sub(count_shift);
        write(&columns, 8, physical, running_sum);
        write(&columns, 12, physical, running_count);
    }
    if (!running_sum.isZero() or !running_count.isZero()) return error.InvalidV5EndpointPrefix;
    return .{ .storage = storage, .columns = columns, .claim = .{ .sum = sum, .count = count } };
}
fn secure(values: [COLUMN_COUNT]Q, at: usize) Q {
    return Q.fromPartialEvals(values[at..][0..4].*);
}
fn read(columns: *const [COLUMN_COUNT][]M, at: usize, row: usize) Q {
    return Q.fromM31Array(.{ columns[at][row], columns[at + 1][row], columns[at + 2][row], columns[at + 3][row] });
}
fn write(columns: *[COLUMN_COUNT][]M, at: usize, row: usize, value: Q) void {
    for (value.toM31Array(), 0..) |limb, i| columns[at + i][row] = limb;
}

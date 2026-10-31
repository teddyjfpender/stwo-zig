//! Shared concrete chunk arithmetic for the inactive byte and Word16 SHIFT
//! providers. Width selects pure arithmetic only; no machine/component factory.
const std = @import("std");
const E = @import("../evaluation.zig");
const Ops = @import("operations.zig");
fn leftIn(comptime F: type, r: anytype, destination: usize, offset: usize, width: usize) F {
    if (destination >= width or destination < offset) return F.zero();
    const source = destination - offset;
    var value = r.table_outputs[source][0];
    if (source > 0) value = value.add(r.table_outputs[source - 1][1]);
    return value;
}
fn rightIn(comptime F: type, r: anytype, destination: usize, offset: usize, width: usize) F {
    if (destination >= width) return F.zero();
    const source = destination + offset;
    var value = F.zero();
    if (source < width) value = value.add(r.table_outputs[source][2]);
    if (source + 1 < width) value = value.add(r.table_outputs[source + 1][3]);
    return value;
}
fn rightOutside(comptime F: type, r: anytype, destination: usize, offset: usize, width: usize, fill_index: usize) F {
    if (destination >= width) return F.zero();
    const source = destination + offset;
    var value = F.zero();
    if (source >= width) value = value.add(r.table_outputs[fill_index][2]);
    if (source + 1 >= width) value = value.add(r.table_outputs[fill_index][3]);
    return value;
}

pub fn emitHeadFor(comptime F: type, comptime chunk_bits: u5, r: anytype, sink: anytype) void {
    comptime std.debug.assert(chunk_bits == 8 or chunk_bits == 16);
    const chunks: usize = 64 / @as(usize, chunk_bits);
    const one = F.one();
    var active = F.zero();
    var bus_id = F.zero();
    for (r.selectors, 0..) |selector, i| {
        sink.emit(selector.mul(selector.sub(one)));
        active = active.add(selector);
        bus_id = bus_id.add(selector.mul(E.qFor(F, Ops.busIdFor(.shift, @intCast(i)))));
    }
    sink.emit(r.active.mul(r.active.sub(one)));
    sink.emit(active.sub(r.active));
    sink.emit(r.payload[0].sub(bus_id));
    var offset_sum = F.zero();
    var offset_index = F.zero();
    for (r.offset, 0..) |flag, i| {
        sink.emit(flag.mul(flag.sub(one)));
        offset_sum = offset_sum.add(flag);
        offset_index = offset_index.add(flag.mul(E.qFor(F, @intCast(i))));
    }
    sink.emit(offset_sum.sub(r.active));
    const word = r.selectors[3].add(r.selectors[4]).add(r.selectors[5]);
    var upper_offsets = F.zero();
    for (r.offset[chunks / 2 ..]) |flag| upper_offsets = upper_offsets.add(flag);
    sink.emit(word.mul(upper_offsets));
    sink.emit(r.ignored_w_bit.mul(r.ignored_w_bit.sub(one)));
    sink.emit(r.ignored_w_bit.mul(one.sub(word)));
    sink.emit(r.payload[5].sub(r.amount).sub(offset_index.mul(E.qFor(F, chunk_bits))).sub(r.ignored_w_bit.mul(E.qFor(F, 32))).sub(r.quotient.mul(E.qFor(F, 64))));
}
pub fn emitSignsFor(comptime F: type, r: anytype, sink: anytype) void {
    const one = F.one();
    for (r.sign) |sign| sink.emit(sign.mul(sign.sub(one)));
    sink.emit(r.fill[0].sub(r.selectors[2].mul(r.sign[1])));
    sink.emit(r.fill[1].sub(r.selectors[5].mul(r.sign[0])));
}
pub fn resultFor(comptime F: type, comptime chunk_bits: u5, r: anytype, i: usize) F {
    comptime std.debug.assert(chunk_bits == 8 or chunk_bits == 16);
    const chunks: usize = 64 / @as(usize, chunk_bits);
    const word = r.selectors[3].add(r.selectors[4]).add(r.selectors[5]);
    const right64 = r.selectors[1].add(r.selectors[2]);
    const right32 = r.selectors[4].add(r.selectors[5]);
    var result = F.zero();
    for (0..chunks) |k| {
        var term = r.selectors[0].mul(leftIn(F, r, i, k, chunks));
        term = term.add(r.selectors[3].mul(leftIn(F, r, i, k, chunks / 2)));
        term = term.add(right64.mul(rightIn(F, r, i, k, chunks)));
        term = term.add(right32.mul(rightIn(F, r, i, k, chunks / 2)));
        term = term.add(r.fill[0].mul(rightOutside(F, r, i, k, chunks, chunks)));
        term = term.add(r.fill[1].mul(rightOutside(F, r, i, k, chunks / 2, chunks)));
        result = result.add(r.offset[k].mul(term));
    }
    if (i >= chunks / 2) result = result.add(word.mul(r.sign[2]).mul(E.qFor(F, (@as(u32, 1) << chunk_bits) - 1)));
    return result;
}

pub fn nativeResult(op: Ops.Shift, a: u64, b: u64) u64 {
    const amount: u6 = @intCast(b & 63);
    const w_amount: u5 = @intCast(b & 31);
    return switch (op) {
        .sll => a << amount,
        .srl => a >> amount,
        .sra => @bitCast(@as(i64, @bitCast(a)) >> amount),
        .sllw => signExtend(@truncate(a << w_amount)),
        .srlw => signExtend(@as(u32, @truncate(a)) >> w_amount),
        .sraw => signExtend(@bitCast(@as(i32, @bitCast(@as(u32, @truncate(a)))) >> w_amount)),
    };
}
fn signExtend(word: u32) u64 {
    return @bitCast(@as(i64, @as(i32, @bitCast(word))));
}

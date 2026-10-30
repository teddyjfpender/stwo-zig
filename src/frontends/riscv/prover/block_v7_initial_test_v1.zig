const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = @import("block_v7_initial_intervals_v1.zig");
const A = @import("block_v7_initial_algebra_v1.zig");
const Loader = @import("../runner/elf_loader.zig");
const Memory = @import("../runner/memory.zig").Memory;
const Sources = @import("block_v5_initial_sources_v1.zig");
const Fixtures = @import("../runner/guest_precompile/test_elf.zig");
const base = Fixtures.buildReleaseProgram(1, &.{0x0000006f}, 16, .rv32im_zkvm_v1);
fn put(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}
fn symbol(bytes: []u8, index: usize, value: u32) void {
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    put(u32, bytes, table + (index + 1) * 16 + 4, value);
}
fn elfFixture() [base.len + 128]u8 {
    var elf: [base.len + 128]u8 = @splat(0);
    @memcpy(elf[0..base.len], &base);
    symbol(&elf, 2, 0x100100); // DATA including initial bytes and BSS.
    symbol(&elf, 3, 32);
    symbol(&elf, 7, 0x10010c); // Existential overlay hides a nonzero ELF word.
    symbol(&elf, 8, 0x100114);
    const headers = base.len;
    @memcpy(elf[headers..][0..64], base[52..116]);
    put(u32, &elf, 28, headers);
    put(u16, &elf, 44, 3);
    put(u32, &elf, headers + 32 + 20, 24); // Original segment's BSS suffix.
    const third = headers + 64;
    put(u32, &elf, third, 1);
    put(u32, &elf, third + 4, headers + 96);
    put(u32, &elf, third + 8, 0x100102); // Deliberately unaligned overlay.
    put(u32, &elf, third + 16, 4);
    put(u32, &elf, third + 20, 8); // Later zero-fill clears earlier bytes.
    @memcpy(elf[headers + 96 ..][0..4], &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd });
    return elf;
}
fn derive(a: std.mem.Allocator) !P.Owned {
    const elf = elfFixture();
    return P.Owned.derive(a, &elf, Sources.sha256(&elf), .rv32im_zkvm_v1, .{});
}
fn access(address: u32, before: u32, first: bool) A.Algebra(M).Access {
    return .{ .global_first = M.fromCanonical(@intFromBool(first)), .predecessor_active = M.fromCanonical(@intFromBool(!first)), .same_address = M.fromCanonical(@intFromBool(!first)), .address = .{ M.fromCanonical(address & 65535), M.fromCanonical(address >> 16) }, .before = .{ M.fromCanonical(before & 65535), M.fromCanonical(before >> 16) } };
}
fn directValid(input: A.Algebra(M).Access, row: [A.COLUMN_COUNT]M) bool {
    for (A.Algebra(M).constraints(input, row)) |residual| if (!residual.isZero()) return false;
    return true;
}
fn ranged(input: A.Algebra(M).Access, row: [A.COLUMN_COUNT]M) bool {
    for (A.Algebra(M).rangePoints(input, row)) |point| {
        if (point.weight.isZero()) continue;
        if (!point.weight.eql(M.one()) or point.value.toU32() >= 65536) return false;
    }
    return true;
}
/// Exact table-membership oracle for helper tests, not a substitute for the
/// eventual committed LogUp provider and source-complete receiver.
fn member(table: P.Owned, input: A.Algebra(M).Access, row: [A.COLUMN_COUNT]M) bool {
    const item = A.Algebra(M).membership(input, row);
    if (item.weight.isZero()) return true;
    if (!item.weight.eql(M.one())) return false;
    for (table.intervals) |interval| if (std.meta.eql(item.tuple, interval.tuple())) return true;
    return false;
}
fn valid(table: P.Owned, input: A.Algebra(M).Access, row: [A.COLUMN_COUNT]M) bool {
    return directValid(input, row) and ranged(input, row) and member(table, input, row);
}

test "v7 initialization compiler matches ordered ELF bytes BSS and private overlay" {
    var table = try derive(std.testing.allocator);
    defer table.deinit();
    const elf = elfFixture();
    try table.validateAgainst(std.testing.allocator, &elf, Sources.sha256(&elf), .rv32im_zkvm_v1, .{});
    try P.validatePartition(table.intervals);
    try std.testing.expectEqual(@as(u32, 0xbbaa0000), (try table.find(0x100100)).value);
    try std.testing.expectEqual(@as(u32, 0x0000ddcc), (try table.find(0x100104)).value);
    try std.testing.expectEqual(@as(u32, 0), (try table.find(0x100108)).value);
    try std.testing.expect((try table.find(0x10010c)).private);
    try std.testing.expect((try table.find(0x100110)).private);
    try std.testing.expect(!(try table.find(0x100114)).private);
    try std.testing.expectEqual(@as(u32, 0), (try table.find(0x100114)).value);
    try std.testing.expect(!(try table.find(0x1000)).allowed);
    try std.testing.expect(!(try table.find(0xffff_fffc)).allowed);

    var memory = try Memory.initFallible(std.testing.allocator);
    defer memory.deinit();
    const info = try Loader.loadElfForProfile(&elf, &memory, .rv32im_zkvm_v1);
    for (table.intervals) |interval| {
        for ([_]u32{ interval.lower, interval.upper - 1 }) |word| {
            const address = word * 4;
            const allowed = info.memory_layout.isRwAddr(address) and !info.memory_layout.isProgramAddr(address);
            try std.testing.expectEqual(allowed, interval.allowed);
            try std.testing.expectEqual(allowed and info.memory_layout.isInputAddr(address), interval.private);
            if (allowed and !interval.private) try std.testing.expectEqual(memory.readU32(address), interval.value);
        }
    }
}

test "v7 initialization independent reconstruction rejects false zero class and incomplete partition" {
    var table = try derive(std.testing.allocator);
    defer table.deinit();
    const elf = elfFixture();
    const hash = Sources.sha256(&elf);
    for (table.intervals) |*interval| {
        if (interval.value == 0) continue;
        const old = interval.*;
        interval.value = 0;
        try P.validatePartition(table.intervals); // Structural validity is not authority.
        try std.testing.expectError(error.UntrustedV7Initialization, table.validateAgainst(std.testing.allocator, &elf, hash, .rv32im_zkvm_v1, .{}));
        interval.* = old;
        interval.private = true;
        interval.value = 0;
        try std.testing.expectError(error.UntrustedV7Initialization, table.validateAgainst(std.testing.allocator, &elf, hash, .rv32im_zkvm_v1, .{}));
        interval.* = old;
        break;
    }
    table.intervals[0].lower = 1;
    try std.testing.expectError(error.InvalidV7InitializationPartition, P.validatePartition(table.intervals));
    table.intervals[0].lower = 0;
    try std.testing.expectError(error.InvalidV7InitializationPartition, P.validatePartition(table.intervals[0 .. table.intervals.len - 1]));
    var bad_hash = hash;
    bad_hash[0] ^= 1;
    try std.testing.expectError(error.UntrustedV7Elf, P.Owned.derive(std.testing.allocator, &elf, bad_hash, .rv32im_zkvm_v1, .{}));
}

test "v7 initialization first touch binds constant zero private values and every witness cell" {
    var table = try derive(std.testing.allocator);
    defer table.deinit();
    for ([_]u32{ 0x100100, 0x100104, 0x100108, 0x10010c, 0x100110, 0x100114, 0x10011c }) |address| {
        const interval = try table.find(address);
        const value: u32 = if (interval.private) 0xfedcba98 else interval.value;
        const input = access(address, value, true);
        const row = (try A.witness(interval, address, true)).columns();
        try std.testing.expect(valid(table, input, row));
        for (0..A.COLUMN_COUNT) |index| {
            var wrong = row;
            wrong[index] = wrong[index].add(M.one());
            try std.testing.expect(!valid(table, input, wrong));
        }
        if (!interval.private) try std.testing.expect(!valid(table, access(address, value ^ 1, true), row));
        var secure_input: A.Algebra(Q).Access = .{ .global_first = Q.one(), .predecessor_active = Q.zero(), .same_address = Q.zero(), .address = undefined, .before = undefined };
        for (&secure_input.address, input.address) |*out, cell| out.* = Q.fromBase(cell);
        for (&secure_input.before, input.before) |*out, cell| out.* = Q.fromBase(cell);
        var secure_row: [A.COLUMN_COUNT]Q = undefined;
        for (&secure_row, row) |*out, cell| out.* = Q.fromBase(cell);
        for (A.Algebra(Q).constraints(secure_input, secure_row)) |residual| try std.testing.expect(residual.isZero());
    }
    const forbidden = try table.find(0x1000);
    try std.testing.expect(!valid(table, access(0x1000, 0, true), (try A.witness(forbidden, 0x1000, true)).columns()));
}

test "v7 initialization range obligations reject field wrapped interval gap forgery" {
    var table = try derive(std.testing.allocator);
    defer table.deinit();
    const interval = try table.find(0x100100);
    var row = (try A.witness(interval, 0x100100, true)).columns();
    // w=0 is below this genuine interval; use d=p-lower to satisfy field
    // equality. Only the required 30-bit gap ranges rule out this forgery.
    const input = access(0, interval.value, true);
    row[6] = M.zero();
    const wrap = core.fields.m31.Modulus - interval.lower;
    row[7] = M.fromCanonical(wrap & 65535);
    row[8] = M.fromCanonical(wrap >> 16);
    const high = interval.upper - 1;
    row[9] = M.fromCanonical(high & 65535);
    row[10] = M.fromCanonical(high >> 16);
    try std.testing.expect(directValid(input, row));
    try std.testing.expect(member(table, input, row));
    try std.testing.expect(!ranged(input, row));
}

test "v7 initialization nonfirst rows emit no classification or range demand" {
    var table = try derive(std.testing.allocator);
    defer table.deinit();
    const input = access(0x100100, 123, false);
    const arbitrary: [A.COLUMN_COUNT]M = @splat(M.fromCanonical(12345));
    try std.testing.expect(valid(table, input, arbitrary));
    try std.testing.expect(A.Algebra(M).membership(input, arbitrary).weight.isZero());
    for (A.Algebra(M).rangePoints(input, arbitrary)) |point| try std.testing.expect(point.weight.isZero());
    var duplicated_gate = input;
    duplicated_gate.global_first = M.one();
    duplicated_gate.same_address = M.zero();
    try std.testing.expect(!directValid(duplicated_gate, arbitrary));
}

test "v7 initialization bounded compiler rejects oversized load and malformed private region" {
    const elf = elfFixture();
    try std.testing.expectError(error.V7InitializationResourceLimit, P.Owned.derive(std.testing.allocator, &elf, Sources.sha256(&elf), .rv32im_zkvm_v1, .{ .max_loaded_bytes = 1 }));
    try std.testing.expectError(error.V7InitializationResourceLimit, P.Owned.derive(std.testing.allocator, &elf, Sources.sha256(&elf), .rv32im_zkvm_v1, .{ .max_pages = 1 }));
    var unaligned = elf;
    symbol(&unaligned, 7, 0x10010d);
    try std.testing.expectError(error.InvalidV7PrivateInput, P.Owned.derive(std.testing.allocator, &unaligned, Sources.sha256(&unaligned), .rv32im_zkvm_v1, .{}));
    var overflow = elf;
    put(u32, &overflow, base.len + 64 + 8, 0xffff_fffc);
    try std.testing.expectError(error.InvalidProgramHeader, P.Owned.derive(std.testing.allocator, &overflow, Sources.sha256(&overflow), .rv32im_zkvm_v1, .{}));
}

test "v7 initialization compiler allocation failures unwind ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}
fn allocationCase(a: std.mem.Allocator) !void {
    var table = try derive(a);
    defer table.deinit();
}

test "v7 initialization provider index preserves boundary ownership and row identity" {
    var table = try derive(std.testing.allocator);
    defer table.deinit();
    // The provider is a canonical disjoint partition, so equal values in
    // adjacent regions never confuse their distinct multiplicity row IDs.
    try P.validatePartition(table.intervals);
    for (table.intervals, 0..) |interval, index| {
        for ([_]u32{ interval.lower, interval.upper - 1 }) |word| {
            const address = word * 4;
            try std.testing.expectEqual(index, try table.findIndex(address));
            try std.testing.expectEqualDeep(interval, try table.find(address));
        }
        if (index + 1 < table.intervals.len) {
            try std.testing.expectEqual(index + 1, try table.findIndex(interval.upper * 4));
        }
    }
    try std.testing.expectError(error.UnalignedV7InitializationAddress, table.findIndex(1));
    try std.testing.expectError(error.UnalignedV7InitializationAddress, table.find(1));
}

test "v7 indexed first-touch census preserves provider rows and rejects invalid partitions" {
    const T = @import("block_v7_memory_trace_v1.zig");
    const Original = @import("../air/block/word_memory_lanes_trace_v1.zig");
    const Word = @import("../air/block/word_memory_v5.zig");
    const Ram = @import("block_v7_ram_component_v1.zig");
    const a = std.testing.allocator;
    var table = try derive(a);
    defer table.deinit();
    const first = @import("../air/block/memory_transition.zig").Transition{ .space = 1, .address = 0x100100, .clock = 1, .before = (try table.find(0x100100)).value, .after = 19 };
    const last = @import("../air/block/memory_transition.zig").Transition{ .space = 1, .address = 0x100104, .clock = 2, .before = (try table.find(0x100104)).value, .after = 23 };
    const claim = @import("block_v5_ram_lanes_protocol_v1.zig").Claim{ .first_event = 0, .total_events = 2, .events = 2, .row_log = 4, .first = first, .last = last, .preceding = null };
    var original = try Original.Trace.init(a, claim, .{ .max_row_log = 4, .max_events = 2, .max_owned_bytes = 1 << 20 });
    defer original.deinit();
    try original.append(first);
    try original.append(last);
    try original.seal();
    var matrix = try T.ramWithHaltConstants(a, &original, &table, .{ .address = @splat(Q.zero()), .clocks = @splat(@splat(Q.zero())) }, 1 << 20);
    defer matrix.deinit();
    const counts = try a.alloc(u32, table.intervals.len);
    defer a.free(counts);
    @memset(counts, 0);
    const ranges = try a.alloc(u32, 65536);
    defer a.free(ranges);
    @memset(ranges, 0);
    try T.census(matrix, claim, &table, counts, ranges);
    // Reconstruct the former linear-search oracle only in this small fixture.
    const reference = try a.alloc(u32, counts.len);
    defer a.free(reference);
    @memset(reference, 0);
    for (0..matrix.size()) |logical| {
        const fixed = Original.fixedPoint(Q, matrix.row(24, 0, logical), claim);
        const rows = Ram.rows(Q, matrix.row(Ram.Spec.MAIN_COUNT, 24, logical));
        for (0..2) |lane| {
            if (Ram.access(Q, fixed, rows, lane).gate().isZero()) continue;
            const event = Word.Algebra(Q).tuple(rows[lane]);
            const address = try T.natural(event[1]) | (try T.natural(event[2])) << 16;
            const expected = try table.find(address);
            for (table.intervals, 0..) |interval, index| if (std.meta.eql(interval, expected)) {
                reference[index] += 1;
                break;
            };
        }
    }
    try std.testing.expectEqualSlices(u32, reference, counts);
    try std.testing.expectEqual(@as(u32, 1), counts[try table.findIndex(first.address)]);
    try std.testing.expectEqual(@as(u32, 1), counts[try table.findIndex(last.address)]);
    try std.testing.expectError(error.InvalidV7TableCensus, T.census(matrix, claim, &table, counts[0 .. counts.len - 1], ranges));
    try std.testing.expectError(error.InvalidV7TableCensus, T.census(matrix, claim, &table, counts, ranges[0 .. ranges.len - 1]));
    const original_lower = table.intervals[1].lower;
    table.intervals[1].lower = table.intervals[0].lower;
    defer table.intervals[1].lower = original_lower;
    try std.testing.expectError(error.InvalidV7InitializationPartition, T.census(matrix, claim, &table, counts, ranges));
}

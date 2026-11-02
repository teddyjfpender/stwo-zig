//! Allocation preflight only. Peeks qualified versioned inner-frame counts;
//! their full decoders independently validate every frame and graph equation.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const R = frontend.rv64_air.memory;
const H = @import("rv64_work_packet_header.zig");
const IO = @import("rv64_work_packet_io.zig");
const GraphWire = R.native_frontier_wire;
const TapeWire = rv.compact_tape_wire;
const EXTENSION_FLAG: u32 = 1 << 31;
const EXTENSION_BYTES = 8;
const ARITH256_RECORD = 32 + 160 + 160;
const CURVE_RECORD = 8 + 32 + 192 + 192;
pub fn check(file: std.fs.File, h: H.Header, steps: u32, limits: H.Limits) !void {
    if (steps == 0 or steps > limits.steps or steps >= 1 << 22) return error.WorkPacketResourceLimit;
    const graph_start = try std.math.add(usize, H.BYTES, try h.bodyBytes());
    const tape_start = try std.math.add(usize, graph_start, h.graph_bytes);
    var base = try std.math.mul(usize, h.cells, @sizeOf(rv.boundary_capture.Cell) + @sizeOf(@import("rv64_full_statement.zig").Cell) + 4);
    base = try std.math.add(usize, base, try std.math.mul(usize, h.chunks, @sizeOf(R.batch.Opening) + 64 * 21));
    var graph_bytes: usize = 0;
    var graph_temporary: usize = 0;
    if (h.graph_bytes != 0) {
        if (h.graph_bytes < GraphWire.HEADER_BYTES) return error.InvalidWorkPacketSection;
        try file.seekTo(graph_start);
        var raw: [GraphWire.HEADER_BYTES]u8 = undefined;
        try IO.exact(file, &raw);
        if (!std.mem.eql(u8, raw[0..8], GraphWire.MAGIC) or get32(raw[8..12]) != 9 or get32(raw[12..16]) != R.values.VERSION or get32(raw[108..112]) != 0) return error.InvalidWorkPacketSection;
        const c = R.batch.Counts{ .leaves = get32(raw[88..92]), .changed_leaves = get32(raw[92..96]), .before_nodes = get32(raw[96..100]), .after_nodes = get32(raw[100..104]), .sides = get32(raw[104..108]) };
        if (c.leaves != h.chunks or c.changed_leaves > c.leaves) return error.InvalidWorkPacketSection;
        const nodes = try std.math.add(usize, c.before_nodes, c.after_nodes);
        const patches = try std.math.add(usize, c.changed_leaves, c.after_nodes);
        const records = try std.math.add(usize, try std.math.add(usize, c.leaves, nodes), c.sides);
        const permutations = try c.permutations(.chunk512);
        if (records > 1 << 24 or permutations > R.native_frontier.MAX_IO) return error.WorkPacketResourceLimit;
        const Side = @typeInfo(@FieldType(R.batch.Witness, "sides")).pointer.child;
        graph_bytes = try sumWidths(&.{ c.leaves, nodes, c.sides, patches, permutations }, &.{ @sizeOf(R.batch.Leaf), @sizeOf(R.batch.Node), @sizeOf(Side), @sizeOf(R.values.Patch), @sizeOf(R.values.PermutationIO) });
        // Graph validation temporarily owns adapters and a map with at most
        // three child keys per node. Includes growth/padding of that map.
        graph_temporary = try std.math.add(usize, try std.math.mul(usize, records, 1024), 1 << 20);
        const encoded = try std.math.add(usize, GraphWire.HEADER_BYTES, try sumWidths(&.{ c.leaves, nodes, c.sides, patches, permutations }, &.{ 97, 122, 46, 81, 128 }));
        if (encoded != h.graph_bytes) return error.InvalidWorkPacketSection;
    }
    try file.seekTo(tape_start);
    var tape: [TapeWire.HEADER_BYTES]u8 = undefined;
    try IO.exact(file, &tape);
    // The formerly reserved word is the v3 SHA-256 record count (zero below
    // v3); its bit 31 announces the v3 extension (arith256_mod and curve records) that
    // follows the SHA-256 records (compact_tape_wire.zig).
    // Raw header word: compared against the v3 roster profiles without
    // casting an untrusted u32 to the enum (unknown values are simply not v3).
    const ExecutionProfile = @import("stwo_riscv_frontend").rv64.execution_profile.Profile;
    const raw_profile = get32(tape[8..12]);
    const v3 = raw_profile == @intFromEnum(ExecutionProfile.ethereum_services_v3) or raw_profile == @intFromEnum(ExecutionProfile.ethereum_services_v3_zbb);
    const sha_word = get32(tape[28..32]);
    const extended = sha_word & EXTENSION_FLAG != 0;
    const sha256 = sha_word & ~EXTENSION_FLAG;
    if (!std.mem.eql(u8, tape[0..8], TapeWire.MAGIC) or get32(tape[12..16]) != steps or (!v3 and sha_word != 0)) return error.InvalidWorkPacketSection;
    const memory = get32(tape[16..20]);
    const keccak = get32(tape[20..24]);
    const secp = get32(tape[24..28]);
    if (memory > steps or keccak > steps or secp > steps - keccak or sha256 > steps - keccak - secp) return error.WorkPacketResourceLimit;
    const base_tape = try std.math.add(usize, TapeWire.HEADER_BYTES, try sumWidths(&.{ steps, memory, keccak, secp, sha256 }, &.{ 48, 8, 432, 424, 224 }));
    var arith: usize = 0;
    var curves: usize = 0;
    if (extended) {
        // Extension: u32 arith256_mod count, u32 curve count (at least one
        // nonzero), then the arith256_mod records, then the curve records.
        if (h.tape_bytes < base_tape + EXTENSION_BYTES) return error.InvalidWorkPacketSection;
        var extension: [EXTENSION_BYTES]u8 = undefined;
        try file.seekTo(try std.math.add(usize, tape_start, base_tape));
        try IO.exact(file, &extension);
        arith = get32(extension[0..4]);
        curves = get32(extension[4..8]);
        if (arith == 0 and curves == 0) return error.InvalidWorkPacketSection;
        if (arith > steps - keccak - secp - sha256 or curves > steps - keccak - secp - sha256 - arith) return error.WorkPacketResourceLimit;
    }
    const encoded_tape = if (extended) try std.math.add(usize, base_tape, EXTENSION_BYTES + try sumWidths(&.{ arith, curves }, &.{ ARITH256_RECORD, CURVE_RECORD })) else base_tape;
    if (encoded_tape != h.tape_bytes) return error.InvalidWorkPacketSection;
    // Tape's sparse ordinary-memory ArrayList uses geometric growth; service
    // arrays use precise capacity. No unused native execution capacity is read.
    const memory_capacity: usize = if (memory == 0) 0 else @max(8, try std.math.mul(usize, memory, 2));
    const tape_bytes = try sumWidths(&.{ steps, memory_capacity, keccak, secp, sha256, arith, curves }, &.{ 48, 8, 432, 424, 224, @sizeOf(rv.ethereum_services.Arith256ModCall), @sizeOf(rv.ethereum_services.CurveCall) });
    const peak = try std.math.add(usize, try std.math.add(usize, base, graph_bytes), @max(graph_temporary, tape_bytes));
    if (try std.math.add(usize, peak, 512 * 1024) > limits.allocation_bytes) return error.WorkPacketResourceLimit;
}
fn sumWidths(counts: []const usize, widths: []const usize) !usize {
    var total: usize = 0;
    for (counts, widths) |count, width| total = try std.math.add(usize, total, try std.math.mul(usize, count, width));
    return total;
}
fn get32(raw: *const [4]u8) u32 {
    return std.mem.readInt(u32, raw, .little);
}

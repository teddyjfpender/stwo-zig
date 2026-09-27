//! Public initial-image custody for the v5 memory bus. The sums here acquire
//! proof authority only when a fresh sorted-memory receipt closes against them.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const transition = @import("../air/block/memory_transition.zig");
const bus = @import("block_memory_relation_v2.zig");
const sources = @import("block_v5_initial_sources_v1.zig");
const seal_mod = @import("block_v5_source_seal_v1.zig");
const Q = core.fields.qm31.QM31;
const INVERSE_CHUNK = 1024;

pub const SourceClaims = struct {
    initial_sum: Q,
    register_sum: Q,
    input_sum: Q,
    rw_sum: Q,
    register_touches: u64,
    input_touches: u64,
    rw_touches: u64,
    first_touch_count: u64,
    plan_digest: [32]u8,
    sealed_channel_digest: [32]u8,
};

/// `pins` and `v5_pins` must come from an independent trusted job/source
/// manifest. Exact first-round entries must have been reconstructed from
/// committed artifacts. This routine checks both the seal and all public files
/// before it draws the shared memory challenge.
pub fn check(
    a: std.mem.Allocator,
    pins: sources.Pins,
    public_input: []const u8,
    files: sources.Files,
    v5_pins: seal_mod.Pins,
    entries: []const seal_mod.Entry,
    sealed: seal_mod.Sealed,
) !SourceClaims {
    try pins.validate();
    const plan_digest = try pins.digest();
    if (!std.meta.eql(plan_digest, v5_pins.initial_source_plan_digest) or
        !std.meta.eql(plan_digest, sealed.initialSourcePlanDigest()))
        return error.UntrustedV5InitialSourcePlan;
    try sealed.require(v5_pins, entries);
    if (public_input.len != pins.public_input_len or
        !std.meta.eql(sources.sha256(public_input), pins.public_input_sha256))
        return error.UntrustedV5PublicInput;

    const input_bytes = try sources.readPinned(a, files.input_words, pins.input_words, sources.INPUT_RECORD_BYTES);
    defer a.free(input_bytes);
    const rw_bytes = try sources.readPinned(a, files.rw_words, pins.rw_words, sources.RW_RECORD_BYTES);
    defer a.free(rw_bytes);
    const touch_bytes = try sources.readPinned(a, files.first_touches, pins.first_touches, sources.TOUCH_RECORD_BYTES);
    defer a.free(touch_bytes);

    const leaves = try a.alloc(tree.Leaf, @intCast(pins.input_words.records + pins.rw_words.records));
    defer a.free(leaves);
    var leaf_count: usize = 0;
    var expected_input_records: u64 = 0;
    var input_at: usize = 0;
    var address = pins.layout.input_base;
    while (@as(u64, address) < @as(u64, pins.layout.input_base) + public_input.len) : (address += 4) {
        const value = try sources.inputWord(pins, public_input, address);
        if (value == 0) continue;
        expected_input_records += 1;
        if (input_at + 8 > input_bytes.len or
            sources.readWord(input_bytes[input_at..][0..4]) != address or
            sources.readWord(input_bytes[input_at + 4 ..][0..4]) != value)
            return error.InvalidV5InputWordRoster;
        leaves[leaf_count] = .{ .index = try tree.memoryIndex(address), .value = value };
        leaf_count += 1;
        input_at += 8;
    }
    if (input_at != input_bytes.len or expected_input_records != pins.input_words.records)
        return error.InvalidV5InputWordRoster;

    var previous_rw: ?u32 = null;
    for (0..@intCast(pins.rw_words.records)) |index| {
        const record = rw_bytes[index * 8 ..][0..8];
        const addr = sources.readWord(record[0..4]);
        const value = sources.readWord(record[4..8]);
        if (value == 0 or (previous_rw != null and addr <= previous_rw.?) or
            pins.layout.isInputAddr(addr) or pins.layout.isProgramAddr(addr) or
            !pins.layout.isRwAddr(addr))
            return error.InvalidV5RwWordRoster;
        leaves[leaf_count] = .{ .index = try tree.memoryIndex(addr), .value = value };
        leaf_count += 1;
        previous_rw = addr;
    }
    std.mem.sort(tree.Leaf, leaves[0..leaf_count], {}, lessLeaf);
    const hasher = tree.TreeHasher.init(.memory);
    const observed_root = try hasher.root(leaves[0..leaf_count]);
    if (!std.meta.eql(observed_root.bytes, pins.initial_rw_root))
        return error.InvalidV5InitialRwRoot;

    var channel = sealed.sharedChannel();
    const channel_digest = channel.digestBytes();
    const challenges = try bus.Challenges.draw(a, sealed);
    var result = SourceClaims{
        .initial_sum = Q.zero(),
        .register_sum = Q.zero(),
        .input_sum = Q.zero(),
        .rw_sum = Q.zero(),
        .register_touches = 0,
        .input_touches = 0,
        .rw_touches = 0,
        .first_touch_count = pins.first_touches.records,
        .plan_digest = plan_digest,
        .sealed_channel_digest = channel_digest,
    };
    var previous_space: ?u8 = null;
    var previous_address: u32 = 0;
    var denominators: [INVERSE_CHUNK]Q = undefined;
    var inverses: [INVERSE_CHUNK]Q = undefined;
    var kinds: [INVERSE_CHUNK]u8 = undefined;
    var pending: usize = 0;
    for (0..@intCast(pins.first_touches.records)) |index| {
        const record = touch_bytes[index * 9 ..][0..9];
        const space = record[0];
        const addr = sources.readWord(record[1..5]);
        const value = sources.readWord(record[5..9]);
        if (space > 1) return error.InvalidV5FirstTouchSpace;
        if (previous_space) |prior| {
            if (space < prior or (space == prior and addr <= previous_address))
                return error.DuplicateOrUnsortedV5FirstTouch;
        }
        previous_space = space;
        previous_address = addr;
        const kind: u8 = if (space == 0) blk: {
            if (addr >= pins.initial_registers.len or value != pins.initial_registers[addr])
                return error.InvalidV5RegisterFirstTouch;
            break :blk 0;
        } else blk: {
            _ = try tree.memoryIndex(addr);
            if (pins.layout.isProgramAddr(addr)) return error.ProgramTouchRequiresVerifiedRomReceipt;
            if (pins.layout.isInputAddr(addr)) break :blk 1;
            if (pins.layout.isRwAddr(addr)) break :blk 2;
            return error.UnclassifiedV5FirstTouch;
        };
        const wanted = if (kind == 0) pins.initial_registers[addr] else wordAt(leaves[0..leaf_count], addr / 4);
        if (value != wanted) return error.InvalidV5FirstTouchValue;
        const first = transition.Transition{ .space = @intCast(space), .address = addr, .clock = 0, .before = value, .after = 0 };
        denominators[pending] = challenges.initial.combineBase(bus.initialTuple(first));
        kinds[pending] = kind;
        pending += 1;
        if (pending == INVERSE_CHUNK) {
            try flush(&result, denominators[0..pending], inverses[0..pending], kinds[0..pending]);
            pending = 0;
        }
    }
    try flush(&result, denominators[0..pending], inverses[0..pending], kinds[0..pending]);
    return result;
}

fn lessLeaf(_: void, left: tree.Leaf, right: tree.Leaf) bool {
    return left.index < right.index;
}

fn wordAt(leaves: []const tree.Leaf, index: u32) u32 {
    var lo: usize = 0;
    var hi = leaves.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (leaves[mid].index < index) lo = mid + 1 else hi = mid;
    }
    return if (lo < leaves.len and leaves[lo].index == index) leaves[lo].value else 0;
}

fn flush(result: *SourceClaims, denominators: []Q, inverses: []Q, kinds: []const u8) !void {
    if (denominators.len == 0) return;
    try core.fields.batchInverseInPlace(Q, denominators, inverses);
    for (inverses, kinds) |inverse, kind| {
        result.initial_sum = result.initial_sum.add(inverse);
        switch (kind) {
            0 => {
                result.register_sum = result.register_sum.add(inverse);
                result.register_touches += 1;
            },
            1 => {
                result.input_sum = result.input_sum.add(inverse);
                result.input_touches += 1;
            },
            2 => {
                result.rw_sum = result.rw_sum.add(inverse);
                result.rw_touches += 1;
            },
            else => unreachable,
        }
    }
}

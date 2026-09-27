//! Verifier-visible fallback for initial RW first touches. A complete public
//! nonzero image is rehashed into the independently pinned sparse BLAKE3 root;
//! an ordered first-touch stream is checked against it and emits the positive
//! v2 initial relation claim. This direct SourceSeal-roster binding is scoped
//! to the fallback and is not complete-block admission.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const layout_mod = @import("../runner/memory_state.zig");
const replay = @import("block_memory_replay.zig");
const bus = @import("block_memory_relation_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const source_roster = @import("block_memory_source_roster_v2.zig");
const transition = @import("../air/block/memory_transition.zig");
const Q = core.fields.qm31.QM31;

pub const IMAGE_RECORD_BYTES: usize = 8; // address LE4, nonzero value LE4
pub const TOUCH_RECORD_BYTES: usize = 10; // space, address LE4, value LE4, source
pub const DEFAULT_MAX_IMAGE_WORDS: u64 = 4_000_000;
pub const DEFAULT_MAX_TOUCHES: u64 = 10_000_000;
const INVERSE_CHUNK: usize = 1024;

pub const Pin = struct {
    initial_rw_root: tree.Digest,
    layout: layout_mod.MemoryLayout,
    image_count: u64,
    first_touch_count: u64,
    max_image_count: u64 = DEFAULT_MAX_IMAGE_WORDS,
    max_first_touch_count: u64 = DEFAULT_MAX_TOUCHES,
    pub fn validate(self: Pin) !void {
        if (self.image_count > self.max_image_count or self.first_touch_count > self.max_first_touch_count or
            self.image_count > std.math.maxInt(usize))
            return error.InvalidPublicInitialRosterLimit;
    }
};
pub const Files = struct { nonzero_image: std.fs.File, first_touches: std.fs.File };
pub const Result = struct {
    initial_sum: Q,
    register_sum: Q,
    roster_digest: [32]u8,
    total_first_touches: u64,
    rw_first_touches: u64,
    rw_zero_first_touches: u64,
    register_first_touches: u64,
};

fn readWord(bytes: []const u8) u32 {
    var word: [4]u8 = undefined;
    @memcpy(&word, bytes[0..4]);
    return std.mem.readInt(u32, &word, .little);
}
fn putWord(bytes: *[4]u8, value: u32) void {
    std.mem.writeInt(u32, bytes, value, .little);
}
fn putWide(bytes: *[8]u8, value: u64) void {
    std.mem.writeInt(u64, bytes, value, .little);
}

fn RecordReader(comptime width: usize) type {
    return struct {
        file: std.fs.File,
        remaining: u64,
        offset: u64 = 0,
        buffer: [width * 1024]u8 = undefined,
        buffered: usize = 0,
        cursor: usize = 0,
        const Self = @This();
        fn init(file: std.fs.File, count: u64) !Self {
            const expected = try std.math.mul(u64, count, width);
            if (try file.getEndPos() != expected) return error.InvalidPublicInitialRosterLength;
            return .{ .file = file, .remaining = count };
        }
        fn next(self: *Self) !?[width]u8 {
            if (self.remaining == 0) return null;
            if (self.cursor == self.buffered) {
                const records: usize = @intCast(@min(self.remaining, 1024));
                const bytes = records * width;
                if (try self.file.preadAll(self.buffer[0..bytes], self.offset) != bytes)
                    return error.TruncatedPublicInitialRoster;
                self.offset += bytes;
                self.buffered = bytes;
                self.cursor = 0;
            }
            var result: [width]u8 = undefined;
            @memcpy(&result, self.buffer[self.cursor..][0..width]);
            self.cursor += width;
            self.remaining -= 1;
            return result;
        }
    };
}

fn digestStart(pin: Pin) std.crypto.hash.sha2.Sha256 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.block.public-rw-fallback.v2\x00");
    hash.update(&pin.initial_rw_root.bytes);
    var wide: [8]u8 = undefined;
    putWide(&wide, pin.image_count);
    hash.update(&wide);
    putWide(&wide, pin.first_touch_count);
    hash.update(&wide);
    var word: [4]u8 = undefined;
    inline for (std.meta.fields(layout_mod.MemoryLayout)) |field| {
        putWord(&word, @field(pin.layout, field.name));
        hash.update(&word);
    }
    return hash;
}

/// Prover-side pre-challenge digest. The verifier independently repeats this
/// scan and requires direct equality with `SourceSeal.roster_digest`.
pub fn digestRoster(pin: Pin, files: Files) ![32]u8 {
    try pin.validate();
    var image = try RecordReader(IMAGE_RECORD_BYTES).init(files.nonzero_image, pin.image_count);
    var touches = try RecordReader(TOUCH_RECORD_BYTES).init(files.first_touches, pin.first_touch_count);
    var hash = digestStart(pin);
    while (try image.next()) |record| hash.update(&record);
    while (try touches.next()) |record| hash.update(&record);
    return hash.finalResult();
}

fn classify(layout: layout_mod.MemoryLayout, space: u1, address: u32) !replay.InitialSource {
    if (space == 0) {
        if (address >= 32) return error.InvalidPublicFirstTouchAddress;
        return .register;
    }
    _ = try tree.memoryIndex(address);
    if (layout.isProgramAddr(address)) return .program_root;
    if (layout.isInputAddr(address)) return .public_input;
    if (layout.isRwAddr(address)) return .rw_root;
    return error.UnclassifiedPublicFirstTouchAddress;
}

fn flushInverses(denominators: []Q, inverses: []Q, sum: *Q) !void {
    if (denominators.len == 0) return;
    try core.fields.batchInverseInPlace(Q, denominators, inverses);
    for (inverses) |inverse| sum.* = sum.add(inverse);
}

/// Direct-bound fallback: the complete public roster digest must be exactly
/// the SourceSeal v3 source-roster digest before any v2 challenge is drawn.
/// Other source rosters need a separately specified sealed aggregation rule.
pub fn verifyDirectBound(a: std.mem.Allocator, pin: Pin, files: Files, sealed: seal_mod.SourceSeal) !Result {
    return verifyInternal(a, pin, files, sealed, null, .direct);
}

/// Scoped mainnet fallback: every register first touch is checked against an
/// independently pinned job-initial register image. Program first touches
/// require their own provider, so this mode rejects them outright.
pub fn verifyMainnetDirectBound(a: std.mem.Allocator, pin: Pin, files: Files, sealed: seal_mod.SourceSeal, initial_registers: [32]u32) !Result {
    return verifyInternal(a, pin, files, sealed, initial_registers, .direct);
}

/// Production binding variant. The caller must independently validate the
/// program/hash descriptor digests against its trusted job/capability pins.
pub fn verifyMainnetAggregated(a: std.mem.Allocator, pin: Pin, files: Files, sealed: seal_mod.SourceSeal, initial_registers: [32]u32, entries: []const source_roster.Entry) !Result {
    return verifyInternal(a, pin, files, sealed, initial_registers, .{ .aggregate = entries });
}

const Binding = union(enum) { direct, aggregate: []const source_roster.Entry };
fn checkBinding(sealed: seal_mod.SourceSeal, observed: [32]u8, binding: Binding) !void {
    if (!sealed.bound_rosters) return error.UnboundPublicInitialRoster;
    switch (binding) {
        .direct => if (!std.meta.eql(observed, sealed.roster_digest)) return error.UnboundPublicInitialRoster,
        .aggregate => |entries| try source_roster.admit(sealed, entries, observed),
    }
}

fn verifyInternal(a: std.mem.Allocator, pin: Pin, files: Files, sealed: seal_mod.SourceSeal, initial_registers: ?[32]u32, binding: Binding) !Result {
    try pin.validate();
    const observed_digest = try digestRoster(pin, files);
    try checkBinding(sealed, observed_digest, binding);
    // Bind the bytes actually validated below as well. The files are supplied
    // by the prover and may change between the digest and validation passes.
    var validated_hash = digestStart(pin);
    const leaves = try a.alloc(tree.Leaf, @intCast(pin.image_count));
    defer a.free(leaves);
    var image = try RecordReader(IMAGE_RECORD_BYTES).init(files.nonzero_image, pin.image_count);
    var previous_address: ?u32 = null;
    for (leaves) |*leaf| {
        const record = (try image.next()) orelse return error.TruncatedPublicInitialRoster;
        validated_hash.update(&record);
        const address = readWord(record[0..4]);
        const value = readWord(record[4..8]);
        const index = try tree.memoryIndex(address);
        if (value == 0 or (previous_address != null and address <= previous_address.?))
            return error.InvalidPublicNonzeroImageOrder;
        const source = try classify(pin.layout, 1, address);
        if (source != .rw_root and source != .public_input) return error.InvalidPublicNonzeroImageAddress;
        leaf.* = .{ .index = index, .value = value };
        previous_address = address;
    }
    const hasher = tree.TreeHasher.init(.memory);
    const computed_root = try hasher.root(leaves);
    if (!std.meta.eql(computed_root, pin.initial_rw_root)) return error.PublicInitialRwRootMismatch;

    const challenges = try bus.Challenges.draw(a, sealed);
    var touches = try RecordReader(TOUCH_RECORD_BYTES).init(files.first_touches, pin.first_touch_count);
    var previous_space: ?u1 = null;
    previous_address = null;
    var image_at: usize = 0;
    var sum = Q.zero();
    var register_sum = Q.zero();
    var rw_count: u64 = 0;
    var zero_count: u64 = 0;
    var register_count: u64 = 0;
    var denominators: [INVERSE_CHUNK]Q = undefined;
    var inverses: [INVERSE_CHUNK]Q = undefined;
    var pending: usize = 0;
    while (try touches.next()) |record| {
        validated_hash.update(&record);
        if (record[0] > 1) return error.InvalidPublicFirstTouchSpace;
        const space: u1 = @intCast(record[0]);
        const address = readWord(record[1..5]);
        const value = readWord(record[5..9]);
        if (record[9] > @intFromEnum(replay.InitialSource.program_root)) return error.InvalidPublicFirstTouchSource;
        const source: replay.InitialSource = @enumFromInt(record[9]);
        if (previous_space) |prior| {
            if (space < prior or (space == prior and address <= previous_address.?))
                return error.DuplicateOrUnsortedPublicFirstTouch;
        }
        previous_space = space;
        previous_address = address;
        if (source != try classify(pin.layout, space, address)) return error.PublicFirstTouchSourceMismatch;
        if (initial_registers) |registers| {
            if (source == .program_root) return error.ProgramFirstTouchNeedsAuthenticatedProvider;
            if (source == .register) {
                if (value != registers[address]) return error.PublicInitialRegisterValueMismatch;
                const first_register: transition.Transition = .{ .space = 0, .address = address, .clock = 0, .before = value, .after = 0 };
                register_sum = register_sum.add(try challenges.initial.combineBase(bus.initialTuple(first_register)).inv());
                register_count += 1;
            }
        }
        if (source != .rw_root and source != .public_input) continue;
        while (image_at < leaves.len and leaves[image_at].index < address / 4) : (image_at += 1) {}
        const expected = if (image_at < leaves.len and leaves[image_at].index == address / 4) leaves[image_at].value else 0;
        if (value != expected) return error.PublicFirstTouchValueMismatch;
        rw_count += 1;
        if (value == 0) zero_count += 1;
        const first: transition.Transition = .{ .space = 1, .address = address, .clock = 0, .before = value, .after = 0 };
        denominators[pending] = challenges.initial.combineBase(bus.initialTuple(first));
        pending += 1;
        if (pending == INVERSE_CHUNK) {
            try flushInverses(denominators[0..pending], inverses[0..pending], &sum);
            pending = 0;
        }
    }
    try flushInverses(denominators[0..pending], inverses[0..pending], &sum);
    if (!std.meta.eql(validated_hash.finalResult(), observed_digest))
        return error.PublicInitialRosterChangedDuringVerification;
    return .{ .initial_sum = sum, .register_sum = register_sum, .roster_digest = observed_digest, .total_first_touches = pin.first_touch_count, .rw_first_touches = rw_count, .rw_zero_first_touches = zero_count, .register_first_touches = register_count };
}

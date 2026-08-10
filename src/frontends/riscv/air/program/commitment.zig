//! Oracle-exact sparse program commitment rows.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const infra = @import("../../infra_trace.zig");
const memory_state = @import("../../runner/memory_state.zig");
const sparse_merkle = @import("../memory_commitment/sparse_merkle.zig");
const profile = @import("../../isa/profile.zig");
const decode = @import("decode.zig");
const table = @import("table.zig");

/// enabler, byte address, four decoded values, multiplicity, root,
/// `(address / 4) mod 2^20`, and `(address / 4) >> 20`.
pub const N_MAIN_COLUMNS: usize = 10;

pub const Row = struct {
    addr: u32,
    values: decode.ProgramValues,
    multiplicity: u32,
    root: u32,
};

pub const Commitment = struct {
    rows: []Row,
    tree: sparse_merkle.Tree,

    pub fn deinit(self: *Commitment, allocator: std.mem.Allocator) void {
        allocator.free(self.rows);
        self.tree.deinit(allocator);
        self.* = undefined;
    }

    pub fn validate(self: Commitment, allocator: std.mem.Allocator) !void {
        try self.tree.validate(allocator);
        if (self.rows.len * 4 != self.tree.leaves.len) return error.InvalidProgramCommitment;
        for (self.rows, 0..) |row, index| {
            profile.requireProgramWordAddress(row.addr) catch
                return error.InvalidProgramCommitment;
            if (row.root != self.tree.root) return error.InvalidProgramCommitment;
            for (row.values, 0..) |value, limb| {
                const leaf = self.tree.leaves[4 * index + limb];
                if (leaf.index != row.addr + limb or leaf.value != value)
                    return error.InvalidProgramCommitment;
            }
        }
    }
};

pub const Columns = struct {
    values: [N_MAIN_COLUMNS][]M31,

    pub fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
        for (&self.values) |column| allocator.free(column);
        self.* = undefined;
    }
};

/// Prefer the declared program-memory union. The fetch-only fallback exists
/// for synthetic proof tests that do not execute through the ELF loader.
pub fn build(
    allocator: std.mem.Allocator,
    fetches: []const table.Fetch,
    program_words: []const memory_state.WordState,
) !Commitment {
    var fetch_table = try table.generate(allocator, fetches);
    defer fetch_table.deinit();
    var fetch_by_addr = std.AutoHashMap(u32, table.Row).init(allocator);
    defer fetch_by_addr.deinit();
    for (fetch_table.rows) |row| try fetch_by_addr.put(row.pc, row);

    var pending: std.ArrayList(Row) = .{};
    defer pending.deinit(allocator);
    if (program_words.len != 0) {
        for (program_words) |word| {
            try profile.requireProgramWordAddress(word.addr);
            // Pinned Stark-V omits zero words from the declared program table.
            // Fetched words were decoded above, so an executed zero instruction
            // still fails closed before this source-level omission is applied.
            if (word.initial_word == 0) continue;
            const values = try decode.decodeProgramWord(word.initial_word);
            const multiplicity = if (fetch_by_addr.fetchRemove(word.addr)) |entry| blk: {
                if (!std.meta.eql(entry.value.values, values)) return error.ProgramWordChanged;
                break :blk entry.value.multiplicity;
            } else 0;
            try pending.append(allocator, .{
                .addr = word.addr,
                .values = values,
                .multiplicity = multiplicity,
                .root = 0,
            });
        }
        if (fetch_by_addr.count() != 0) return error.FetchedProgramWordMissing;
    } else {
        for (fetch_table.rows) |row| try pending.append(allocator, .{
            .addr = row.pc,
            .values = row.values,
            .multiplicity = row.multiplicity,
            .root = 0,
        });
    }
    if (pending.items.len == 0) return error.EmptyProgramCommitment;
    return finishCommitment(allocator, &pending);
}

/// Builds the declared-program commitment directly from execution rows.
///
/// `execution_rows` is any slice whose elements expose `pc` and `inst_word`.
/// The loaded program image already supplies the unique address/word set, so
/// copying millions of fetches and rediscovering that set with a hash table is
/// redundant. A bounded dense address index handles ordinary contiguous ELFs;
/// unusually sparse images retain the same fail-closed semantics through an
/// `AutoHashMap` fallback.
pub fn buildDeclared(
    allocator: std.mem.Allocator,
    execution_rows: anytype,
    program_words: []const memory_state.WordState,
    extra_fetch: ?table.Fetch,
) !Commitment {
    return buildDeclaredFromSources(
        allocator,
        .base,
        .{execution_rows},
        program_words,
        extra_fetch,
    );
}

/// Builds a declared-program commitment for an admitted extension profile.
///
/// `base_execution_rows` and `extension_execution_rows` are heterogeneous
/// slices whose elements expose `pc` and `inst_word`. They are consumed as two
/// borrowed streams by the same accumulator; no concatenated fetch buffer is
/// allocated. Declared words, including unfetched words, are decoded under the
/// selected profile before the Merkle tree is built.
pub fn buildDeclaredForProfile(
    allocator: std.mem.Allocator,
    selected_profile: decode.ExecutionProfile,
    base_execution_rows: anytype,
    extension_execution_rows: anytype,
    program_words: []const memory_state.WordState,
    extra_fetch: ?table.Fetch,
) !Commitment {
    return buildDeclaredFromSources(
        allocator,
        .{ .profile = selected_profile },
        .{ base_execution_rows, extension_execution_rows },
        program_words,
        extra_fetch,
    );
}

const DeclaredDecodeAuthority = union(enum) {
    base,
    profile: decode.ExecutionProfile,

    fn decodeWord(self: DeclaredDecodeAuthority, word: u32) !decode.ProgramValues {
        return switch (self) {
            .base => decode.decodeProgramWord(word),
            .profile => |selected_profile| decode.decodeProgramWordForProfile(
                selected_profile,
                word,
            ),
        };
    }
};

fn buildDeclaredFromSources(
    allocator: std.mem.Allocator,
    decoder: DeclaredDecodeAuthority,
    execution_sources: anytype,
    program_words: []const memory_state.WordState,
    extra_fetch: ?table.Fetch,
) !Commitment {
    if (program_words.len == 0) return error.EmptyProgramCommitment;
    var index = try DeclaredWordIndex.init(allocator, program_words);
    defer index.deinit(allocator);
    const multiplicities = try allocator.alloc(u32, program_words.len);
    defer allocator.free(multiplicities);
    @memset(multiplicities, 0);

    inline for (execution_sources) |execution_rows| {
        for (execution_rows) |row| {
            try registerDeclaredFetch(
                decoder,
                program_words,
                &index,
                multiplicities,
                .{ .pc = row.pc, .word = row.inst_word },
            );
        }
    }
    if (extra_fetch) |fetch| {
        try registerDeclaredFetch(decoder, program_words, &index, multiplicities, fetch);
    }

    var pending: std.ArrayList(Row) = .{};
    defer pending.deinit(allocator);
    try pending.ensureTotalCapacity(allocator, program_words.len);
    for (program_words, multiplicities) |word, multiplicity| {
        // Pinned Stark-V omits declared zero words. An attempted fetch of one
        // was rejected by `registerDeclaredFetch` above.
        if (word.initial_word == 0) continue;
        pending.appendAssumeCapacity(.{
            .addr = word.addr,
            .values = try decoder.decodeWord(word.initial_word),
            .multiplicity = multiplicity,
            .root = 0,
        });
    }
    if (pending.items.len == 0) return error.EmptyProgramCommitment;
    return finishCommitment(allocator, &pending);
}

const MAX_DENSE_PROGRAM_WORD_SLOTS: usize = 1 << 22;
const MISSING_WORD_INDEX: u32 = std.math.maxInt(u32);

const DeclaredWordIndex = union(enum) {
    dense: struct {
        base: u32,
        slots: []u32,
    },
    sparse: std.AutoHashMap(u32, u32),

    fn init(
        allocator: std.mem.Allocator,
        words: []const memory_state.WordState,
    ) !DeclaredWordIndex {
        var min_addr: u32 = std.math.maxInt(u32);
        var max_addr: u32 = 0;
        for (words) |word| {
            try profile.requireProgramWordAddress(word.addr);
            min_addr = @min(min_addr, word.addr);
            max_addr = @max(max_addr, word.addr);
        }
        const slot_count = (@as(usize, max_addr - min_addr) >> 2) + 1;
        if (slot_count <= MAX_DENSE_PROGRAM_WORD_SLOTS) {
            const slots = try allocator.alloc(u32, slot_count);
            errdefer allocator.free(slots);
            @memset(slots, MISSING_WORD_INDEX);
            for (words, 0..) |word, word_index| {
                const slot = @as(usize, word.addr - min_addr) >> 2;
                if (slots[slot] != MISSING_WORD_INDEX) return error.DuplicateLeaf;
                slots[slot] = @intCast(word_index);
            }
            return .{ .dense = .{ .base = min_addr, .slots = slots } };
        }

        var sparse = std.AutoHashMap(u32, u32).init(allocator);
        errdefer sparse.deinit();
        try sparse.ensureTotalCapacity(@intCast(words.len));
        for (words, 0..) |word, word_index| {
            const entry = try sparse.getOrPut(word.addr);
            if (entry.found_existing) return error.DuplicateLeaf;
            entry.value_ptr.* = @intCast(word_index);
        }
        return .{ .sparse = sparse };
    }

    fn deinit(self: *DeclaredWordIndex, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .dense => |dense| allocator.free(dense.slots),
            .sparse => |*sparse| sparse.deinit(),
        }
        self.* = undefined;
    }

    fn get(self: *const DeclaredWordIndex, address: u32) ?usize {
        const raw = switch (self.*) {
            .dense => |dense| blk: {
                if (address < dense.base) return null;
                const offset = address - dense.base;
                if ((offset & 3) != 0) return null;
                const slot = @as(usize, offset) >> 2;
                if (slot >= dense.slots.len) return null;
                break :blk dense.slots[slot];
            },
            .sparse => |sparse| sparse.get(address) orelse return null,
        };
        if (raw == MISSING_WORD_INDEX) return null;
        return @intCast(raw);
    }
};

fn registerDeclaredFetch(
    decoder: DeclaredDecodeAuthority,
    words: []const memory_state.WordState,
    index: *const DeclaredWordIndex,
    multiplicities: []u32,
    fetch: table.Fetch,
) !void {
    try profile.requireProgramWordAddress(fetch.pc);
    const word_index = index.get(fetch.pc) orelse return error.FetchedProgramWordMissing;
    const declared = words[word_index];
    if (declared.initial_word != fetch.word) return error.ProgramWordChanged;
    if (fetch.word == 0) {
        // Preserve the old fetch-table error surface for an executed zero
        // instruction instead of reporting it merely as an omitted ROM row.
        _ = try decoder.decodeWord(fetch.word);
        unreachable;
    }
    if (multiplicities[word_index] == std.math.maxInt(u32))
        return error.MultiplicityOverflow;
    multiplicities[word_index] += 1;
}

fn finishCommitment(
    allocator: std.mem.Allocator,
    pending: *std.ArrayList(Row),
) !Commitment {
    std.mem.sort(Row, pending.items, {}, lessRow);

    var leaves: std.ArrayList(sparse_merkle.Leaf) = .{};
    defer leaves.deinit(allocator);
    for (pending.items) |row| {
        for (row.values, 0..) |value, limb| try leaves.append(allocator, .{
            .index = row.addr + @as(u32, @intCast(limb)),
            .value = value,
        });
    }
    var tree = try sparse_merkle.build(allocator, leaves.items);
    errdefer tree.deinit(allocator);
    for (pending.items) |*row| row.root = tree.root;
    const rows = try pending.toOwnedSlice(allocator);
    errdefer allocator.free(rows);
    const result = Commitment{
        .rows = rows,
        .tree = tree,
    };
    try result.validate(allocator);
    return result;
}

pub fn generateMain(
    allocator: std.mem.Allocator,
    rows: []const Row,
    log_size: u32,
) !Columns {
    const size = @as(usize, 1) << @intCast(log_size);
    if (rows.len > size) return error.InvalidTraceShape;
    var columns: [N_MAIN_COLUMNS][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column);
    for (&columns) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    for (rows, 0..) |row, index| {
        try profile.requireProgramWordAddress(row.addr);
        const dst = placement.map(index);
        columns[0][dst] = M31.one();
        columns[1][dst] = M31.fromU64(row.addr);
        for (row.values, 0..) |value, limb| columns[2 + limb][dst] = M31.fromU64(value);
        columns[6][dst] = M31.fromU64(row.multiplicity);
        columns[7][dst] = M31.fromU64(row.root);
        const word_address = row.addr >> 2;
        columns[8][dst] = M31.fromU64(word_address & ((@as(u32, 1) << 20) - 1));
        columns[9][dst] = M31.fromU64(word_address >> 20);
    }
    return .{ .values = columns };
}

fn lessRow(_: void, lhs: Row, rhs: Row) bool {
    return lhs.addr < rhs.addr;
}

test "program commitment: declared but unfetched instructions remain root-bound" {
    const words = [_]memory_state.WordState{
        .{ .addr = 0x1000, .initial_word = 0x00100093, .final_word = 0x00100093, .final_clock = 0 },
        .{ .addr = 0x1004, .initial_word = 0x002081b3, .final_word = 0x002081b3, .final_clock = 0 },
    };
    const fetches = [_]table.Fetch{.{ .pc = 0x1000, .word = 0x00100093 }};
    var commitment = try build(std.testing.allocator, &fetches, &words);
    defer commitment.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), commitment.rows.len);
    try std.testing.expectEqual(@as(u32, 1), commitment.rows[0].multiplicity);
    try std.testing.expectEqual(@as(u32, 0), commitment.rows[1].multiplicity);
    try std.testing.expectEqual(commitment.tree.root, commitment.rows[1].root);
}

test "program commitment: fetched word must belong to declared program" {
    const words = [_]memory_state.WordState{
        .{ .addr = 0x1000, .initial_word = 0x00100093, .final_word = 0x00100093, .final_clock = 0 },
    };
    const fetches = [_]table.Fetch{.{ .pc = 0x1004, .word = 0x002081b3 }};
    try std.testing.expectError(
        error.FetchedProgramWordMissing,
        build(std.testing.allocator, &fetches, &words),
    );
}

test "program commitment: declared zero gaps do not affect rows roots or multiplicities" {
    const nonzero_words = [_]memory_state.WordState{
        .{ .addr = 0x1000, .initial_word = 0x00100093, .final_word = 0x00100093, .final_clock = 0 },
        .{ .addr = 0x1008, .initial_word = 0x002081b3, .final_word = 0x002081b3, .final_clock = 0 },
    };
    const words_with_gap = [_]memory_state.WordState{
        nonzero_words[0],
        .{ .addr = 0x1004, .initial_word = 0, .final_word = 0, .final_clock = 0 },
        nonzero_words[1],
    };
    const fetches = [_]table.Fetch{
        .{ .pc = 0x1000, .word = 0x00100093 },
        .{ .pc = 0x1000, .word = 0x00100093 },
    };

    var compact = try build(std.testing.allocator, &fetches, &nonzero_words);
    defer compact.deinit(std.testing.allocator);
    var gapped = try build(std.testing.allocator, &fetches, &words_with_gap);
    defer gapped.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), gapped.rows.len);
    try std.testing.expectEqual(@as(u32, 0x1000), gapped.rows[0].addr);
    try std.testing.expectEqual(@as(u32, 2), gapped.rows[0].multiplicity);
    try std.testing.expectEqual(@as(u32, 0x1008), gapped.rows[1].addr);
    try std.testing.expectEqual(@as(u32, 0), gapped.rows[1].multiplicity);
    try std.testing.expectEqual(compact.tree.root, gapped.tree.root);
    try std.testing.expectEqualSlices(sparse_merkle.Leaf, compact.tree.leaves, gapped.tree.leaves);
    try std.testing.expectEqualSlices(sparse_merkle.Node, compact.tree.nodes, gapped.tree.nodes);
}

test "program commitment: dense declared index matches fetch-table construction" {
    const words = [_]memory_state.WordState{
        .{ .addr = 0x1000, .initial_word = 0x00100093, .final_word = 0x00100093, .final_clock = 0 },
        .{ .addr = 0x1004, .initial_word = 0, .final_word = 0, .final_clock = 0 },
        .{ .addr = 0x1008, .initial_word = 0x002081b3, .final_word = 0x002081b3, .final_clock = 0 },
    };
    const fetches = [_]table.Fetch{
        .{ .pc = 0x1008, .word = 0x002081b3 },
        .{ .pc = 0x1000, .word = 0x00100093 },
        .{ .pc = 0x1000, .word = 0x00100093 },
    };
    const ExecutionRow = struct { pc: u32, inst_word: u32 };
    const execution = [_]ExecutionRow{
        .{ .pc = fetches[0].pc, .inst_word = fetches[0].word },
        .{ .pc = fetches[1].pc, .inst_word = fetches[1].word },
        .{ .pc = fetches[2].pc, .inst_word = fetches[2].word },
    };
    var expected = try build(std.testing.allocator, &fetches, &words);
    defer expected.deinit(std.testing.allocator);
    var actual = try buildDeclared(std.testing.allocator, &execution, &words, null);
    defer actual.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(Row, expected.rows, actual.rows);
    try std.testing.expectEqual(expected.tree.root, actual.tree.root);
    try std.testing.expectEqualSlices(sparse_merkle.Leaf, expected.tree.leaves, actual.tree.leaves);
    try std.testing.expectEqualSlices(sparse_merkle.Node, expected.tree.nodes, actual.tree.nodes);
}

test "program commitment: fetched zero instruction fails closed" {
    const words = [_]memory_state.WordState{
        .{ .addr = 0x1000, .initial_word = 0, .final_word = 0, .final_clock = 0 },
    };
    const fetches = [_]table.Fetch{.{ .pc = 0x1000, .word = 0 }};
    try std.testing.expectError(
        error.InvalidInstruction,
        build(std.testing.allocator, &fetches, &words),
    );
}

test "program commitment: declared and fetch-only addresses fail closed at protocol boundary" {
    const instruction: u32 = 0x00100093;
    try std.testing.expectError(
        error.MisalignedProgramWord,
        build(
            std.testing.allocator,
            &.{.{ .pc = 0x1002, .word = instruction }},
            &.{},
        ),
    );
    try std.testing.expectError(
        error.ProgramAddressOutOfRange,
        build(
            std.testing.allocator,
            &.{},
            &.{.{
                .addr = profile.program_commitment_size,
                .initial_word = instruction,
                .final_word = instruction,
                .final_clock = 0,
            }},
        ),
    );
}

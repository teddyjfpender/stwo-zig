//! Experimental architectural RAM commitment. No clocks, registers or execution
//! admission live here. A producer-selected root is never initial-image authority.
//! Reuses the qualified nine-lane Poseidon node arithmetic, not its RV32 tree.
const std = @import("std");
pub const node = @import("../../../air/memory_commitment/ethereum_node_v1.zig");
const core = @import("stwo_core");
pub const M31 = core.fields.m31.M31;
pub const Digest = node.Digest;
pub const PAGE_BITS = 12;
pub const CELL_BITS = 3;
pub const PAGE_CELLS = 512;
pub const PAGE_DEPTH = 52;
pub const SCHEMA_VERSION = 1;
pub const PAGE_WORDS = 3 + PAGE_CELLS * 5;
pub const PAGE_ABSORPTIONS = (PAGE_WORDS + 1 + node.RATE - 1) / node.RATE;
pub const PAGE_PERMUTATIONS = PAGE_ABSORPTIONS + 1;
pub const Page = [PAGE_CELLS]Cell;
const permutation = @import("../../../air/memory_commitment/poseidon2.zig");
pub const PAGE_DOMAIN: u32 = 0x5241_4d50; // RAMP, distinct from ETN0/ETN1 nodes.

pub const PermutationIO = struct { input: permutation.State, output: permutation.State };
pub const Recorder = struct {
    allocator: std.mem.Allocator,
    calls: std.ArrayList(PermutationIO) = .empty,
    replay: ?[]const permutation.State = null,
    replay_cursor: usize = 0,
    pub fn deinit(self: *Recorder) void {
        self.calls.deinit(self.allocator);
    }
    fn permute(self: ?*Recorder, state: *permutation.State) !void {
        const input = state.*;
        if (self) |recorder| {
            if (recorder.replay) |outputs| {
                if (recorder.replay_cursor >= outputs.len) return error.TruncatedRamHashLedger;
                state.* = outputs[recorder.replay_cursor];
                for (state) |word| if (word.v >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
                recorder.replay_cursor += 1;
            } else permutation.permute(state);
        } else permutation.permute(state);
        if (self) |recorder| try recorder.calls.append(recorder.allocator, .{ .input = input, .output = state.* });
    }
};

/// Flat page encoding avoids 511 four-permutation binary cell hashes. All
/// values/permissions are injected without modular reduction: four u16 limbs
/// plus one u24 permission lane per cell, preceded by version/length framing.
pub fn pageWords(page: *const Page) ![PAGE_WORDS]M31 {
    var words: [PAGE_WORDS]M31 = undefined;
    words[0] = M31.fromCanonical(SCHEMA_VERSION);
    words[1] = M31.fromCanonical(PAGE_CELLS);
    words[2] = M31.fromCanonical(5);
    for (page, 0..) |cell, i| {
        try cell.validate();
        for (0..4) |limb| words[3 + 5 * i + limb] = M31.fromCanonical(@intCast((cell.value >> @intCast(16 * limb)) & 65535));
        words[3 + 5 * i + 4] = M31.fromCanonical(cell.permissions);
    }
    return words;
}

pub fn hashPage(page: *const Page, recorder: ?*Recorder) !Digest {
    const words = try pageWords(page);
    var state: permutation.State = @splat(M31.zero());
    state[15] = M31.fromCanonical(PAGE_DOMAIN);
    var at: usize = 0;
    for (0..PAGE_ABSORPTIONS) |_| {
        for (0..node.RATE) |lane| {
            const word = if (at < words.len) words[at] else if (at == words.len) M31.one() else M31.zero();
            state[lane] = state[lane].add(word);
            at += 1;
        }
        try Recorder.permute(recorder, &state);
    }
    var result: Digest = undefined;
    for (0..node.RATE) |i| result[i] = state[i].toU32();
    try Recorder.permute(recorder, &state);
    for (node.RATE..node.DIGEST_WORDS) |i| result[i] = state[i - node.RATE].toU32();
    return result;
}

/// Per-byte R/W/X bits. Values in unmapped bytes must be canonical zero.
pub const Cell = struct {
    value: u64 = 0,
    permissions: u24 = 0,

    pub fn validate(self: Cell) !void {
        for (0..8) |i| {
            const shift: u6 = @intCast(8 * i);
            const permission: u5 = @intCast(3 * i);
            if ((self.permissions >> permission) & 7 == 0 and (self.value >> shift) & 255 != 0)
                return error.NonzeroUnmappedByte;
        }
    }

    /// Injective encoding: eight byte lanes and one 24-bit permission lane.
    pub fn digest(self: Cell) !Digest {
        try self.validate();
        var result: Digest = undefined;
        for (0..8) |i| result[i] = @intCast((self.value >> @intCast(8 * i)) & 255);
        result[8] = self.permissions;
        return result;
    }
};

pub const AddressedCell = struct { address: u64, cell: Cell };
pub const Entry = struct { index: u64, digest: Digest };
pub const Patch = struct { height: u6, index: u64, before: Digest, after: Digest };
const Layer = struct {
    storage: []Entry = &.{},
    used: usize = 0,
    fn values(self: Layer) []const Entry {
        return self.storage[0..self.used];
    }
};

pub fn equal(a: Digest, b: Digest) bool {
    return std.meta.eql(a, b);
}

/// This protocol interprets the existing kind bit as height bit five. Every
/// page-tree level 0..51 has its own constrained sponge domain/height pair.
pub fn hashRow(height: u6, left: Digest, right: Digest) !node.Row(M31) {
    if (height >= PAGE_DEPTH) return error.InvalidRamHeight;
    return node.build(@enumFromInt(height >> 5), @truncate(height), left, right);
}

pub fn rowDigest(row: *const node.Row(M31)) Digest {
    var digest: Digest = undefined;
    for (&digest, row.digest) |*out, value| out.* = value.toU32();
    return digest;
}

pub fn hash(height: u6, left: Digest, right: Digest) !Digest {
    const row = try hashRow(height, left, right);
    return rowDigest(&row);
}

pub fn hashRecorded(height: u6, left: Digest, right: Digest, recorder: ?*Recorder) !Digest {
    if (recorder == null or recorder.?.replay == null) {
        const row = try hashRow(height, left, right);
        if (recorder) |out| for (row.inputs, row.outputs) |input, output|
            try out.calls.append(out.allocator, .{ .input = input, .output = output });
        return rowDigest(&row);
    }
    if (height >= PAGE_DEPTH) return error.InvalidRamHeight;
    var row: node.Row(M31) = undefined;
    row.kind = M31.fromCanonical(height >> 5);
    for (&row.height_bits, 0..) |*bit, i| bit.* = M31.fromCanonical((@as(u32, height) >> @intCast(i)) & 1);
    for (&row.left, left, &row.right, right) |*l, x, *r, y| {
        if (x >= core.fields.m31.Modulus or y >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
        l.* = M31.fromCanonical(x);
        r.* = M31.fromCanonical(y);
    }
    const words = node.absorptionWords(M31, row);
    var state: permutation.State = @splat(M31.zero());
    state[15] = M31.fromCanonical(node.DOMAIN + (height >> 5));
    for (0..node.CALLS) |call| {
        if (call < 3) for (0..node.RATE) |lane| {
            state[lane] = state[lane].add(words[call * node.RATE + lane]);
        };
        row.inputs[call] = state;
        try Recorder.permute(recorder, &state);
        row.outputs[call] = state;
    }
    for (&row.digest, 0..) |*word, i| word.* = if (i < node.RATE) row.outputs[2][i] else row.outputs[3][i - node.RATE];
    // Existing caller equations are the framing authority for native and replay.
    for (node.evaluateGeneric(M31, row)) |residual| if (!residual.isZero()) return error.InvalidRamNodeFraming;
    return rowDigest(&row);
}

pub fn defaults() ![PAGE_DEPTH + 1]Digest {
    var result: [PAGE_DEPTH + 1]Digest = undefined;
    result[0] = try hashPage(&@as(Page, @splat(.{})), null);
    for (0..PAGE_DEPTH) |h| result[h + 1] = try hash(@intCast(h), result[h], result[h]);
    return result;
}

pub fn find(entries: []const Entry, index: u64) ?Digest {
    var low: usize = 0;
    var high = entries.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (entries[middle].index < index) low = middle + 1 else high = middle;
    }
    return if (low < entries.len and entries[low].index == index) entries[low].digest else null;
}

/// Canonical sparse snapshot for witness preparation. Initial snapshots must
/// come from an independently admitted ELF/mapping/input image; this constructor
/// accepts values and deliberately does not assert that authority.
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    layers: [PAGE_DEPTH + 1]Layer = @splat(.{}),
    zero: [PAGE_DEPTH + 1]Digest,

    pub fn init(a: std.mem.Allocator, cells: []const AddressedCell) !Snapshot {
        var self = Snapshot{ .allocator = a, .zero = try defaults() };
        errdefer self.deinit();
        self.layers[0].storage = try a.alloc(Entry, cells.len);
        for (cells, 0..) |cell, i| {
            if (cell.address & 7 != 0 or (i != 0 and cells[i - 1].address >= cell.address))
                return error.NoncanonicalRamCells;
            _ = try cell.cell.digest();
            if (cell.cell.value == 0 and cell.cell.permissions == 0) return error.ExplicitDefaultRamCell;
        }
        var read_cell: usize = 0;
        while (read_cell < cells.len) {
            const index = cells[read_cell].address >> PAGE_BITS;
            var page: Page = @splat(.{});
            while (read_cell < cells.len and cells[read_cell].address >> PAGE_BITS == index) : (read_cell += 1)
                page[@intCast((cells[read_cell].address & 4095) >> CELL_BITS)] = cells[read_cell].cell;
            self.layers[0].storage[self.layers[0].used] = .{ .index = index, .digest = try hashPage(&page, null) };
            self.layers[0].used += 1;
        }
        try self.complete();
        return self;
    }

    pub fn fromPages(a: std.mem.Allocator, pages: []const Entry) !Snapshot {
        var self = Snapshot{ .allocator = a, .zero = try defaults() };
        errdefer self.deinit();
        self.layers[0].storage = try a.dupe(Entry, pages);
        self.layers[0].used = pages.len;
        for (pages, 0..) |page, i| {
            if (page.index >= @as(u64, 1) << PAGE_DEPTH or (i > 0 and pages[i - 1].index >= page.index) or equal(page.digest, self.zero[0]))
                return error.NoncanonicalRamPages;
            for (page.digest) |word| if (word >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
        }
        try self.complete();
        return self;
    }

    fn complete(self: *Snapshot) !void {
        const a = self.allocator;
        for (0..PAGE_DEPTH) |h| {
            const source = self.layers[h].values();
            self.layers[h + 1].storage = try a.alloc(Entry, source.len);
            var read: usize = 0;
            while (read < source.len) {
                const parent = source[read].index >> 1;
                var left = self.zero[h];
                var right = self.zero[h];
                if (source[read].index & 1 == 0) left = source[read].digest else right = source[read].digest;
                read += 1;
                if (read < source.len and source[read].index >> 1 == parent) {
                    right = source[read].digest;
                    read += 1;
                }
                const at = self.layers[h + 1].used;
                self.layers[h + 1].storage[at] = .{ .index = parent, .digest = try hash(@intCast(h), left, right) };
                self.layers[h + 1].used += 1;
            }
        }
    }

    pub fn root(self: *const Snapshot) Digest {
        return if (self.layers[PAGE_DEPTH].used == 0) self.zero[PAGE_DEPTH] else self.layers[PAGE_DEPTH].storage[0].digest;
    }

    pub fn pageSiblings(self: *const Snapshot, height: usize) []const Entry {
        return self.layers[height].values();
    }

    /// All checks precede mutation; the immutable mapping policy means touched
    /// nodes already exist, except unchanged implicit-zero subtrees.
    pub fn applyPatch(self: *Snapshot, patches: []const Patch) !void {
        for (patches, 0..) |patch, i| {
            if (patch.height > PAGE_DEPTH or patch.index >= @as(u64, 1) << @intCast(PAGE_DEPTH - patch.height)) return error.InvalidRamPatch;
            for (patch.after) |word| if (word >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
            if (i > 0 and (patches[i - 1].height > patch.height or (patches[i - 1].height == patch.height and patches[i - 1].index >= patch.index))) return error.InvalidRamPatch;
            const old = find(self.layers[patch.height].values(), patch.index);
            if (!equal(old orelse self.zero[patch.height], patch.before)) return error.RamPatchBeforeMismatch;
            if (old == null and !equal(patch.after, self.zero[patch.height])) return error.UnsupportedRamMappingMutation;
        }
        for (patches) |patch| {
            var low: usize = 0;
            var high = self.layers[patch.height].used;
            const entries = self.layers[patch.height].storage;
            while (low < high) {
                const middle = low + (high - low) / 2;
                if (entries[middle].index < patch.index) low = middle + 1 else high = middle;
            }
            if (low < self.layers[patch.height].used and entries[low].index == patch.index) entries[low].digest = patch.after;
        }
    }

    pub fn deinit(self: *Snapshot) void {
        for (&self.layers) |*layer| {
            self.allocator.free(layer.storage);
            layer.* = .{};
        }
    }
};

//! Native reference/cache for the NEW value-only commitment. Permissions belong
//! to independently derived immutable policy. This is witness preparation, not
//! an initialization STARK or permission proof; never accept producer omission
//! of initial ELF/input chunks as receiver authority.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const permutation = @import("../../../air/memory_commitment/poseidon2.zig");
const node = @import("../../../air/memory_commitment/ethereum_node_v1.zig");
const provider = @import("../../../air/memory_commitment/poseidon2_universal_degree3_v1.zig");
const physical = @import("../witness.zig").physical;
const Memory = @import("../../memory.zig").Memory;
pub const Digest = node.Digest;
pub const VERSION: u32 = 2;
pub const DOMAIN: u32 = 0x5241_4d56; // RAMV; distinct from RAMP and ETN0/ETN1.
pub const MAX_DEPTH = 55;
pub const MAX_CELLS = 512;
pub const MAX_LEAVES = 65536 * 8;
pub const MAX_CACHED_NODES = 2 * MAX_LEAVES + 256 * MAX_DEPTH;
pub const Entry = struct { index: u64, digest: Digest };
pub const Patch = struct { height: u6, index: u64, before: Digest, after: Digest };
pub const Geometry = enum {
    chunk512,
    page4096,
    pub fn logBytes(self: Geometry) u6 {
        return if (self == .chunk512) 9 else 12;
    }
    pub fn bytes(self: Geometry) usize {
        return @as(usize, 1) << self.logBytes();
    }
    pub fn cells(self: Geometry) usize {
        return self.bytes() / 8;
    }
    pub fn depth(self: Geometry) u6 {
        return @intCast(64 - @as(u7, self.logBytes()));
    }
    pub fn absorptions(self: Geometry) usize {
        return (4 * self.cells() + 1 + node.RATE - 1) / node.RATE;
    }
    pub fn permutations(self: Geometry) usize {
        return self.absorptions() + 1;
    }
};
pub const PermutationIO = struct { input: permutation.State, output: permutation.State };
pub const Recorder = struct {
    allocator: std.mem.Allocator,
    calls: std.ArrayList(PermutationIO) = .empty,
    writer: ?*ProviderWriter = null,
    pub fn deinit(self: *Recorder) void {
        self.calls.deinit(self.allocator);
    }
};

/// Borrowed final provider-column arena. There is no allocator or independent
/// owner here; the coordinator retains/adopts its original backing allocation.
pub const ProviderWriter = struct {
    main: []M,
    log_size: u32,
    used: usize = 0,
    pub fn init(main: []M, log_size: u32) !ProviderWriter {
        if (log_size < 4 or log_size > 24) return error.InvalidRamProviderWriter;
        const size = @as(usize, 1) << @intCast(log_size);
        if (main.len != try std.math.mul(usize, provider.N_MAIN_COLUMNS, size)) return error.InvalidRamProviderWriter;
        return .{ .main = main, .log_size = log_size };
    }
    fn permute(self: *ProviderWriter, state: *permutation.State) !void {
        const size = @as(usize, 1) << @intCast(self.log_size);
        if (self.used >= size) return error.RamProviderWriterFull;
        var call = provider.Call{ .input = undefined, .io = true };
        for (&call.input, state) |*word, value| word.* = value.toU32();
        const row = try provider.fill(call);
        const at = physical(self.used, self.log_size);
        for (row, 0..) |value, column| self.main[column * size + at] = value;
        state.* = provider.outputGeneric(M, row);
        self.used += 1;
    }
    /// Expand one saved native I/O pair using the same provider fill authority.
    /// No second frontier/hash traversal or shadow wide matrix is constructed.
    pub fn writeRecorded(self: *ProviderWriter, call: PermutationIO) !void {
        var state = call.input;
        try self.permute(&state);
        if (!std.meta.eql(state, call.output)) return error.InvalidRamRecordedIO;
    }
    pub fn finishPadding(self: *ProviderWriter) !void {
        const size = @as(usize, 1) << @intCast(self.log_size);
        if (self.used > size) return error.InvalidRamProviderWriter;
        const padding = provider.paddingRow();
        for (self.used..size) |logical| {
            const at = physical(logical, self.log_size);
            for (padding, 0..) |value, column| self.main[column * size + at] = value;
        }
    }
};

fn permute(state: *permutation.State, recorder: ?*Recorder) !void {
    const input = state.*;
    if (recorder) |out| {
        if (out.writer) |writer| try writer.permute(state) else permutation.permute(state);
    } else permutation.permute(state);
    if (recorder) |out| try out.calls.append(out.allocator, .{ .input = input, .output = state.* });
}

pub fn equal(a: Digest, b: Digest) bool {
    return std.meta.eql(a, b);
}

/// Four u16 lanes inject each full u64 without reduction. Fixed schema/geometry
/// capacity framing replaces in-message headers; delimiter and zero padding are
/// still explicit. Private caller AIR must authenticate this exact schedule.
/// Shared native absorption/padding frame, also used to validate detached
/// prepared I/O against its owned words without re-running a permutation.
pub fn valueInput(geometry: Geometry, words: []const u64, phase: usize, previous: permutation.State) !permutation.State {
    if (words.len != geometry.cells() or phase > geometry.absorptions()) return error.InvalidRamValueChunk;
    var state = previous;
    if (phase == geometry.absorptions()) return state;
    if (phase == 0) {
        state[14] = state[14].add(M.fromCanonical(32 * VERSION + geometry.logBytes()));
        state[15] = state[15].add(M.fromCanonical(DOMAIN));
    }
    const length = 4 * words.len;
    for (0..node.RATE) |lane| {
        const position = phase * node.RATE + lane;
        const word: u32 = if (position < length) @intCast((words[position / 4] >> @intCast(16 * (position % 4))) & 65535) else if (position == length) 1 else 0;
        state[lane] = state[lane].add(M.fromCanonical(word));
    }
    return state;
}
pub fn hashValues(geometry: Geometry, values: []const u64, recorder: ?*Recorder) !Digest {
    if (values.len != geometry.cells()) return error.InvalidRamValueChunk;
    var state: permutation.State = @splat(M.zero());
    for (0..geometry.absorptions()) |phase| {
        state = try valueInput(geometry, values, phase, state);
        try permute(&state, recorder);
    }
    var result: Digest = undefined;
    for (0..node.RATE) |i| result[i] = state[i].toU32();
    try permute(&state, recorder);
    for (node.RATE..node.DIGEST_WORDS) |i| result[i] = state[i - node.RATE].toU32();
    return result;
}

pub fn hashNode(geometry: Geometry, height: u6, left: Digest, right: Digest, recorder: ?*Recorder) !Digest {
    if (height >= geometry.depth()) return error.InvalidRamValueHeight;
    if (recorder != null and recorder.?.writer != null) {
        var row: node.Row(M) = undefined;
        row.kind = M.fromCanonical(height >> 5);
        for (&row.height_bits, 0..) |*bit, i| bit.* = M.fromCanonical((@as(u32, height) >> @intCast(i)) & 1);
        for (left, &row.left, right, &row.right) |l, *x, r, *y| {
            if (l >= core.fields.m31.Modulus or r >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
            x.* = M.fromCanonical(l);
            y.* = M.fromCanonical(r);
        }
        const words = node.absorptionWords(M, row);
        var state: permutation.State = @splat(M.zero());
        state[15] = M.fromCanonical(node.DOMAIN + (height >> 5));
        for (0..4) |call| {
            if (call < 3) for (0..7) |lane| {
                state[lane] = state[lane].add(words[call * 7 + lane]);
            };
            row.inputs[call] = state;
            try permute(&state, recorder);
            row.outputs[call] = state;
        }
        for (&row.digest, 0..) |*word, i| word.* = if (i < 7) row.outputs[2][i] else row.outputs[3][i - 7];
        for (node.evaluateGeneric(M, row)) |constraint| if (!constraint.isZero()) return error.InvalidRamNodeFrame;
        var result: Digest = undefined;
        for (&result, row.digest) |*word, value| word.* = value.toU32();
        return result;
    }
    const row = try node.build(@enumFromInt(height >> 5), @truncate(height), left, right);
    if (recorder) |out| for (row.inputs, row.outputs) |input, output| try out.calls.append(out.allocator, .{ .input = input, .output = output });
    var result: Digest = undefined;
    for (&result, row.digest) |*word, value| word.* = value.toU32();
    return result;
}

pub fn defaults(geometry: Geometry) ![MAX_DEPTH + 1]Digest {
    var result: [MAX_DEPTH + 1]Digest = @splat(@splat(0));
    const empty: [MAX_CELLS]u64 = @splat(0);
    result[0] = try hashValues(geometry, empty[0..geometry.cells()], null);
    for (0..geometry.depth()) |height| result[height + 1] = try hashNode(geometry, @intCast(height), result[height], result[height], null);
    return result;
}

const Nodes = std.AutoHashMap(u64, Digest);
pub const Cache = struct {
    allocator: std.mem.Allocator,
    geometry: Geometry,
    zero: [MAX_DEPTH + 1]Digest,
    layers: [MAX_DEPTH + 1]Nodes,

    pub fn empty(a: std.mem.Allocator, geometry: Geometry) !Cache {
        var result = Cache{ .allocator = a, .geometry = geometry, .zero = try defaults(geometry), .layers = undefined };
        for (&result.layers) |*layer| layer.* = Nodes.init(a);
        return result;
    }

    /// Caller owns an independently initialized native image. Iterate only
    /// backing pages, not the entire mapped zero-filled heap; missing chunks
    /// have the SAME canonical zero digest regardless of mapping permissions.
    pub fn fromMemory(a: std.mem.Allocator, geometry: Geometry, memory: *const Memory) !Cache {
        if (memory.backing.table.count() > 65536) return error.RamValueResourceLimit;
        var result = try Cache.empty(a, geometry);
        errdefer result.deinit();
        var entries: std.ArrayList(Entry) = .empty;
        defer entries.deinit(a);
        var pages = memory.backing.table.iterator();
        while (pages.next()) |page| {
            if (page.key_ptr.* >= @as(u64, 1) << 52) return error.InvalidRamValuePosition;
            for (0..4096 / geometry.bytes()) |chunk| {
                var values: [MAX_CELLS]u64 = undefined;
                var nonzero = false;
                for (values[0..geometry.cells()], 0..) |*value, i| {
                    const offset = chunk * geometry.bytes() + i * 8;
                    value.* = std.mem.readInt(u64, page.value_ptr.*[offset..][0..8], .little);
                    nonzero = nonzero or value.* != 0;
                }
                if (!nonzero) continue;
                const index = (page.key_ptr.* << @intCast(12 - geometry.logBytes())) | chunk;
                try entries.append(a, .{ .index = index, .digest = try hashValues(geometry, values[0..geometry.cells()], null) });
            }
        }
        std.mem.sort(Entry, entries.items, {}, lessEntry);
        try result.buildFrontier(entries.items);
        return result;
    }

    /// Sparse digest preparation only, not initial-image authority.
    pub fn fromEntries(a: std.mem.Allocator, geometry: Geometry, entries: []const Entry) !Cache {
        if (entries.len > MAX_LEAVES) return error.RamValueResourceLimit;
        var result = try Cache.empty(a, geometry);
        errdefer result.deinit();
        const frontier = try a.dupe(Entry, entries);
        defer a.free(frontier);
        try result.buildFrontier(frontier);
        return result;
    }

    fn buildFrontier(self: *Cache, frontier: []Entry) !void {
        if (frontier.len > MAX_LEAVES) return error.RamValueResourceLimit;
        try self.layers[0].ensureTotalCapacity(@intCast(frontier.len));
        for (frontier, 0..) |entry, i| {
            if (entry.index >= @as(u64, 1) << self.geometry.depth() or (i > 0 and frontier[i - 1].index >= entry.index) or equal(entry.digest, self.zero[0])) return error.InvalidRamValuePosition;
            for (entry.digest) |word| if (word >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
            self.layers[0].putAssumeCapacity(entry.index, entry.digest);
        }
        var used = frontier.len;
        var total = used;
        for (0..self.geometry.depth()) |height| {
            var parents: u32 = 0;
            for (frontier[0..used], 0..) |entry, i| if (i == 0 or frontier[i - 1].index >> 1 != entry.index >> 1) {
                parents += 1;
            };
            total += parents;
            if (total > MAX_CACHED_NODES) return error.RamValueResourceLimit;
            try self.layers[height + 1].ensureTotalCapacity(parents);
            var read: usize = 0;
            var write: usize = 0;
            while (read < used) {
                const first = frontier[read];
                const parent = first.index >> 1;
                var left = self.zero[height];
                var right = self.zero[height];
                if (first.index & 1 == 0) left = first.digest else right = first.digest;
                read += 1;
                if (read < used and frontier[read].index >> 1 == parent) {
                    right = frontier[read].digest;
                    read += 1;
                }
                const digest = try hashNode(self.geometry, @intCast(height), left, right, null);
                frontier[write] = .{ .index = parent, .digest = digest };
                self.layers[height + 1].putAssumeCapacity(parent, digest);
                write += 1;
            }
            used = write;
        }
    }

    pub fn root(self: *const Cache) Digest {
        return self.layers[self.geometry.depth()].get(0) orelse self.zero[self.geometry.depth()];
    }
    pub fn get(self: *const Cache, height: u6, index: u64) !Digest {
        if (height > self.geometry.depth() or index >= @as(u64, 1) << (self.geometry.depth() - height)) return error.InvalidRamValuePosition;
        return self.layers[height].get(index) orelse self.zero[height];
    }
    pub fn count(self: *const Cache) usize {
        var total: usize = 0;
        for (self.layers) |layer| total += layer.count();
        return total;
    }

    /// Validate and reserve ALL levels before semantic mutation. New lazy-heap
    /// chunks and deletion back to zero are supported without copying the RAM.
    pub fn applyPatch(self: *Cache, patches: []const Patch) !void {
        var additions: [MAX_DEPTH + 1]u32 = @splat(0);
        var removals: [MAX_DEPTH + 1]u32 = @splat(0);
        for (patches, 0..) |patch, i| {
            const before = try self.get(patch.height, patch.index);
            if (i > 0 and (patches[i - 1].height > patch.height or (patches[i - 1].height == patch.height and patches[i - 1].index >= patch.index))) return error.NoncanonicalRamValuePatch;
            if (!equal(before, patch.before)) return error.RamValueBeforeMismatch;
            for (patch.after) |word| if (word >= core.fields.m31.Modulus) return error.NonCanonicalDigest;
            const exists = self.layers[patch.height].contains(patch.index);
            if (!equal(patch.after, self.zero[patch.height]) and !exists) additions[patch.height] += 1;
            if (equal(patch.after, self.zero[patch.height]) and exists) removals[patch.height] += 1;
        }
        var after_count = self.count();
        for (additions) |n| after_count += n;
        for (removals) |n| after_count -= n;
        if (after_count > MAX_CACHED_NODES or self.layers[0].count() + additions[0] - removals[0] > MAX_LEAVES) return error.RamValueResourceLimit;
        for (&self.layers, additions, removals) |*layer, added, removed| try layer.ensureTotalCapacity(layer.count() + added - removed);
        // Remove first so a replacement batch reserves only its final node
        // counts, rather than holding a second full cache during publication.
        for (patches) |patch| if (equal(patch.after, self.zero[patch.height])) {
            _ = self.layers[patch.height].remove(patch.index);
        };
        for (patches) |patch| {
            if (!equal(patch.after, self.zero[patch.height])) self.layers[patch.height].putAssumeCapacity(patch.index, patch.after);
        }
    }

    pub fn deinit(self: *Cache) void {
        for (&self.layers) |*layer| layer.deinit();
        self.* = undefined;
    }
};
fn lessEntry(_: void, a: Entry, b: Entry) bool {
    return a.index < b.index;
}

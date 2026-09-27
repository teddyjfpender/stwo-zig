//! Bounded simultaneous initial/final sparse-tree witness emission. A host
//! traversal is never root authority: the operation equations, authenticated
//! source-record buses, exact counts and tree-routing closure must be proved.
//! No whole image, endpoint list, node map or sibling-path owner is retained.
const std = @import("std");
const Defaults = @import("block_v5_memory_source_batch_defaults_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Tree = @import("../air/memory_commitment/blake3_state_tree.zig");
pub const VERSION: u32 = 1;
pub const Limits = struct { max_leaves: u64 = 15_000_000, max_operations: u64 = 1_000_000_000, max_compressions: u64 = 2_000_000_000 };
pub const Reader = struct {
    context: *anyopaque,
    /// Exact offset/length requests into independently pinned source streams.
    /// This provider is private witness, not a SHA verification receipt.
    read: *const fn (*anyopaque, Source.Stream, u64, []u8) anyerror!void,
};
pub const ImageKind = enum(u32) { absent = 0, input = 1, rw = 2 };
pub const Leaf = struct {
    address: u32,
    before: u32,
    after: u32,
    clock: u64,
    image: ImageKind,
    image_ordinal: u64 = 0,
    touched: bool,
    touch_ordinal: u64 = 0,
};
pub const Pair = struct {
    before: [32]u8,
    after: [32]u8,
    pub fn equal(self: Pair) bool {
        return std.mem.eql(u8, &self.before, &self.after);
    }
};
pub const Coordinate = struct {
    /// Height above leaves. Root=(30,0), leaf=(0,address/4).
    height: u32,
    index: u32,
    pub fn validate(self: Coordinate) !void {
        if (self.height > Tree.DEPTH or self.index >= (@as(u32, 1) << @intCast(Tree.DEPTH - self.height))) return error.InvalidSourceFoldCoordinate;
    }
    pub fn start(self: Coordinate) u32 {
        return self.index << @intCast(self.height);
    }
    pub fn width(self: Coordinate) u32 {
        return @as(u32, 1) << @intCast(self.height);
    }
};
pub const Kind = enum(u32) { empty = 0, leaf = 1, branch = 2, root = 3 };
pub const Operation = struct {
    ordinal: u64,
    kind: Kind,
    coordinate: Coordinate,
    value: Pair,
    leaf: Leaf = .{ .address = 0, .before = 0, .after = 0, .clock = 0, .image = .absent, .touched = false },
    left: Pair = .{ .before = @splat(0), .after = @splat(0) },
    right: Pair = .{ .before = @splat(0), .after = @splat(0) },
};
pub const Census = struct {
    input: u64 = 0,
    rw: u64 = 0,
    touches: u64 = 0,
    leaves: u64 = 0,
    branches: u64 = 0,
    empty: u64 = 0,
    roots: u64 = 0,
    /// Actual non-default/non-shared canonical BLAKE3 compressions, not
    /// generic bit-circuit arithmetic operations or a performance estimate.
    compressions: u64 = 0,
    pub fn operations(self: Census) !u64 {
        return std.math.add(u64, try std.math.add(u64, self.leaves, self.branches), try std.math.add(u64, self.empty, self.roots));
    }
    pub fn require(self: Census, admitted: *const Source.Admitted, limits: Limits) !void {
        if (self.input != admitted.records(.input_words) or self.rw != admitted.records(.rw_words) or self.touches != admitted.records(.endpoints) or self.roots != 1 or self.leaves > limits.max_leaves or try self.operations() > limits.max_operations or self.compressions > limits.max_compressions) return error.InvalidSourceFoldCensus;
        // A finite rooted full binary tree has one more terminal than branch.
        // This host check is only the corresponding proof's candidate census.
        if (try std.math.add(u64, self.leaves, self.empty) != try std.math.add(u64, self.branches, 1)) return error.InvalidSourceFoldCensus;
    }
};
const Word = struct { address: u32, value: u32, ordinal: u64 };
const Touch = struct { address: u32, before: u32, after: u32, clock: u64, ordinal: u64 };
/// A merge owns at most one peek from each image stream and one touch pair.
/// Strict order, space/classification, exact byte offsets and counts use the
/// same source grammar as the original scalar equation oracle.
pub const Merge = struct {
    admitted: Source.Admitted,
    reader: Reader,
    input: ?Word = null,
    rw: ?Word = null,
    touch: ?Touch = null,
    loaded: bool = false,
    input_at: u64 = 0,
    rw_at: u64 = 0,
    touch_at: u64 = 0,
    previous_input: ?u32 = null,
    previous_rw: ?u32 = null,
    previous_touch: ?u32 = null,
    previous_union: ?u32 = null,
    pub fn init(admitted: Source.Admitted, reader: Reader) !Merge {
        try admitted.require();
        return .{ .admitted = admitted, .reader = reader };
    }
    fn word(self: *Merge, stream: Source.Stream, ordinal: u64, previous: *?u32) !?Word {
        if (ordinal == self.admitted.records(stream)) return null;
        var raw: [8]u8 = undefined;
        try self.reader.read(self.reader.context, stream, try std.math.mul(u64, ordinal, 8), &raw);
        const address = std.mem.readInt(u32, raw[0..4], .little);
        const value = std.mem.readInt(u32, raw[4..8], .little);
        _ = try Tree.memoryIndex(address);
        const layout = self.admitted.pins.initial.layout;
        if (value == 0 or (previous.* != null and previous.*.? >= address) or layout.isProgramAddr(address) or !layout.isRwAddr(address) or layout.isInputAddr(address) != (stream == .input_words)) return error.InvalidSourceFoldImage;
        previous.* = address;
        return .{ .address = address, .value = value, .ordinal = ordinal };
    }
    fn touchedWord(self: *Merge) !?Touch {
        if (self.touch_at == self.admitted.records(.endpoints)) return null;
        var first: [9]u8 = undefined;
        var last: [16]u8 = undefined;
        try self.reader.read(self.reader.context, .first_touches, try std.math.mul(u64, self.touch_at, 9), &first);
        try self.reader.read(self.reader.context, .endpoints, try std.math.mul(u64, self.touch_at, 16), &last);
        const address = std.mem.readInt(u32, last[0..4], .little);
        _ = try Tree.memoryIndex(address);
        const layout = self.admitted.pins.initial.layout;
        if (first[0] != 1 or std.mem.readInt(u32, first[1..5], .little) != address or (self.previous_touch != null and self.previous_touch.? >= address) or layout.isProgramAddr(address) or !layout.isRwAddr(address)) return error.InvalidSourceFoldTouch;
        self.previous_touch = address;
        return .{ .address = address, .before = std.mem.readInt(u32, first[5..9], .little), .after = std.mem.readInt(u32, last[12..16], .little), .clock = std.mem.readInt(u64, last[4..12], .little), .ordinal = self.touch_at };
    }
    pub fn next(self: *Merge) !?Leaf {
        if (!self.loaded) {
            self.input = try self.word(.input_words, self.input_at, &self.previous_input);
            self.rw = try self.word(.rw_words, self.rw_at, &self.previous_rw);
            self.touch = try self.touchedWord();
            self.loaded = true;
        }
        var address: ?u32 = null;
        if (self.input) |v| address = v.address;
        if (self.rw) |v| address = if (address) |a| @min(a, v.address) else v.address;
        if (self.touch) |v| address = if (address) |a| @min(a, v.address) else v.address;
        const at = address orelse return null;
        if (self.previous_union != null and self.previous_union.? >= at) return error.InvalidSourceFoldImage;
        self.previous_union = at;
        var result = Leaf{ .address = at, .before = 0, .after = 0, .clock = 0, .image = .absent, .touched = false };
        if (self.input) |v| if (v.address == at) {
            result.image = .input;
            result.image_ordinal = v.ordinal;
            result.before = v.value;
            self.input_at += 1;
            self.input = try self.word(.input_words, self.input_at, &self.previous_input);
        };
        if (self.rw) |v| if (v.address == at) {
            if (result.image != .absent) return error.InvalidSourceFoldImage;
            result.image = .rw;
            result.image_ordinal = v.ordinal;
            result.before = v.value;
            self.rw_at += 1;
            self.rw = try self.word(.rw_words, self.rw_at, &self.previous_rw);
        };
        result.after = result.before;
        if (self.touch) |v| if (v.address == at) {
            if (v.before != result.before) return error.InvalidSourceFoldBeforeValue;
            result.touched = true;
            result.touch_ordinal = v.ordinal;
            result.clock = v.clock;
            result.after = v.after;
            self.touch_at += 1;
            self.touch = try self.touchedWord();
        };
        return result;
    }
};
const Frame = struct { coordinate: Coordinate, phase: enum { enter, left, right } = .enter, left: Pair = undefined };
/// Resumable postorder fold. Each invocation emits exactly one operation;
/// working memory is a depth+1 stack, three record peeks and cached defaults.
pub const Cursor = struct {
    merge: Merge,
    peek: ?Leaf = null,
    stack: [Tree.DEPTH + 1]Frame = undefined,
    stack_len: usize = 0,
    hasher: Tree.TreeHasher,
    census: Census = .{},
    limits: Limits,
    result: ?Pair = null,
    ordinal: u64 = 0,
    done: bool = false,
    pub fn init(admitted: Source.Admitted, reader: Reader, limits: Limits) !Cursor {
        if (limits.max_leaves == 0 or limits.max_operations == 0 or limits.max_compressions == 0 or limits.max_operations >= @import("stwo_core").fields.m31.Modulus or limits.max_compressions >= @import("stwo_core").fields.m31.Modulus) return error.InvalidSourceFoldLimits;
        var out = Cursor{ .merge = try Merge.init(admitted, reader), .hasher = Defaults.get().*, .limits = limits };
        out.peek = try out.merge.next();
        out.stack[0] = .{ .coordinate = .{ .height = Tree.DEPTH, .index = 0 } };
        out.stack_len = 1;
        return out;
    }
    fn hashLeaf(self: *Cursor, value: u32) ![32]u8 {
        if (value == 0) return self.hasher.defaults[Tree.DEPTH].bytes;
        self.census.compressions = try std.math.add(u64, self.census.compressions, 1);
        return self.hasher.leaf(value).bytes;
    }
    fn hashNode(self: *Cursor, height: u32, left: [32]u8, right: [32]u8) ![32]u8 {
        const child = self.hasher.defaults[Tree.DEPTH - height + 1].bytes;
        if (std.mem.eql(u8, &left, &child) and std.mem.eql(u8, &right, &child)) return self.hasher.defaults[Tree.DEPTH - height].bytes;
        self.census.compressions = try std.math.add(u64, self.census.compressions, 2);
        return self.hasher.pair(.{ .bytes = left }, .{ .bytes = right }).bytes;
    }
    fn publish(self: *Cursor, operation: Operation) !Operation {
        if (self.ordinal >= self.limits.max_operations or self.census.leaves > self.limits.max_leaves or self.census.compressions > self.limits.max_compressions) return error.SourceFoldResourceLimit;
        self.ordinal += 1;
        return operation;
    }
    fn finishChild(self: *Cursor, pair: Pair) !void {
        self.stack_len -= 1;
        if (self.stack_len == 0) {
            self.result = pair;
            return;
        }
        const parent = &self.stack[self.stack_len - 1];
        if (parent.phase == .left) {
            parent.left = pair;
            parent.phase = .right;
        } else if (parent.phase == .right) self.result = pair else return error.InvalidSourceFoldTraversal;
    }
    pub fn next(self: *Cursor) !?Operation {
        if (self.done) return null;
        while (self.stack_len != 0) {
            const frame = &self.stack[self.stack_len - 1];
            const coordinate = frame.coordinate;
            switch (frame.phase) {
                .enter => {
                    const outside = self.peek == null or self.peek.?.address / 4 >= @as(u64, coordinate.start()) + coordinate.width();
                    if (outside) {
                        const digest = self.hasher.defaults[Tree.DEPTH - coordinate.height].bytes;
                        const value = Pair{ .before = digest, .after = digest };
                        self.census.empty += 1;
                        try self.finishChild(value);
                        return try self.publish(.{ .ordinal = self.ordinal, .kind = .empty, .coordinate = coordinate, .value = value });
                    }
                    if (self.peek.?.address / 4 < coordinate.start()) return error.InvalidSourceFoldTraversal;
                    if (coordinate.height == 0) {
                        const leaf = self.peek.?;
                        var value = Pair{ .before = try self.hashLeaf(leaf.before), .after = undefined };
                        value.after = if (leaf.before == leaf.after) value.before else try self.hashLeaf(leaf.after);
                        self.census.leaves += 1;
                        switch (leaf.image) {
                            .absent => {},
                            .input => self.census.input += 1,
                            .rw => self.census.rw += 1,
                        }
                        if (leaf.touched) self.census.touches += 1;
                        self.peek = try self.merge.next();
                        try self.finishChild(value);
                        return try self.publish(.{ .ordinal = self.ordinal, .kind = .leaf, .coordinate = coordinate, .value = value, .leaf = leaf });
                    }
                    frame.phase = .left;
                    self.stack[self.stack_len] = .{ .coordinate = .{ .height = coordinate.height - 1, .index = coordinate.index * 2 } };
                    self.stack_len += 1;
                },
                .left => return error.InvalidSourceFoldTraversal,
                .right => {
                    // The first visit opens the right child; the second has its
                    // completed pair in result. A child completion cannot
                    // overwrite a borrowed parent frame beyond this stack.
                    if (self.result) |right| {
                        self.result = null;
                        const left = frame.left;
                        var value = Pair{ .before = try self.hashNode(coordinate.height, left.before, right.before), .after = undefined };
                        value.after = if (left.equal() and right.equal()) value.before else try self.hashNode(coordinate.height, left.after, right.after);
                        self.census.branches += 1;
                        try self.finishChild(value);
                        return try self.publish(.{ .ordinal = self.ordinal, .kind = .branch, .coordinate = coordinate, .value = value, .left = left, .right = right });
                    }
                    self.stack[self.stack_len] = .{ .coordinate = .{ .height = coordinate.height - 1, .index = coordinate.index * 2 + 1 } };
                    self.stack_len += 1;
                },
            }
        }
        if (self.peek != null or self.result == null) return error.InvalidSourceFoldTraversal;
        self.census.roots = 1;
        try self.census.require(&self.merge.admitted, self.limits);
        const value = self.result.?;
        // Candidate consistency only; actual circuit root checks and complete
        // routing/source closure grant authority, never this host comparison.
        if (!std.mem.eql(u8, &value.before, &self.merge.admitted.pins.initial.initial_rw_root) or !std.mem.eql(u8, &value.after, &self.merge.admitted.pins.expected_final_rw_root)) return error.InvalidSourceFoldRoot;
        self.done = true;
        return try self.publish(.{ .ordinal = self.ordinal, .kind = .root, .coordinate = .{ .height = Tree.DEPTH, .index = 0 }, .value = value });
    }
};

//! Authenticated, allocation-free witness generation for Merkle-path row 33.
//!
//! Callers provide only a child digest, its sibling, and path coordinates.
//! The writer chooses the left/right preimage and computes the full Poseidon2
//! output itself before writing final column-major storage.  `PreparedPath`
//! additionally turns a top-to-bottom authentication path into relation-linked
//! rows with one exact cold allocation and a sealed allocation-free hot path.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const digest = @import("../../air/lang/digest.zig");
const direct = @import("../../air/lang/direct_witness_executor.zig");
const types = @import("../../air/lang/types.zig");
const poseidon2 = @import("../../air/memory_commitment/poseidon2.zig");
const component = @import("merkle_path.zig");

pub const MAIN_COLUMN_COUNT = component.PHYSICAL_MAIN_COLUMN_COUNT;
pub const DIGEST_WORD_COUNT = component.DIGEST_WORD_COUNT;
pub const STATE_WIDTH = component.STATE_WIDTH;
pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-merkle-path-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "08fc97876b52a5889ce3138c8b030266faaf3773b32ed60afd4850b51b351f9f";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion Merkle-path witness-binding digest",
);
pub const PATH_FORMAT_VERSION: u16 = 1;
pub const PATH_DOMAIN = "stwo-zig/typed-air/recursion-merkle-path-plan/v1\x00";

pub const Error = direct.Error || std.mem.Allocator.Error || error{
    ArithmeticOverflow,
    AuthorityMismatch,
    InvalidPath,
    InvalidWitness,
    InvalidWitnessBinding,
};

pub const PathStep = struct {
    /// Zero selects the on-path child as the left preimage; one selects right.
    direction: u32,
    sibling: [DIGEST_WORD_COUNT]u32,
};

pub const Invocation = struct {
    tree_id: u32,
    depth: u32,
    index: u32,
    child: [DIGEST_WORD_COUNT]u32,
    step: PathStep,
    is_leaf: bool,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    tree_id = 1,
    depth = 2,
    index = 3,
    direction = 4,
    is_leaf = 5,
    left_0 = 6,
    left_1 = 7,
    left_2 = 8,
    left_3 = 9,
    left_4 = 10,
    left_5 = 11,
    left_6 = 12,
    left_7 = 13,
    right_0 = 14,
    right_1 = 15,
    right_2 = 16,
    right_3 = 17,
    right_4 = 18,
    right_5 = 19,
    right_6 = 20,
    right_7 = 21,
    parent_0 = 22,
    parent_1 = 23,
    parent_2 = 24,
    parent_3 = 25,
    parent_4 = 26,
    parent_5 = 27,
    parent_6 = 28,
    parent_7 = 29,
    output_8 = 30,
    output_9 = 31,
    output_10 = 32,
    output_11 = 33,
    output_12 = 34,
    output_13 = 35,
    output_14 = 36,
    output_15 = 37,
    child_0 = 38,
    child_1 = 39,
    child_2 = 40,
    child_3 = 41,
    child_4 = 42,
    child_5 = 43,
    child_6 = 44,
    child_7 = 45,
};

pub const CANONICAL_RECIPE = std.enums.values(MainSource);

pub const Slot = struct {
    column: u8,
    value: types.ValueId,
    source: MainSource,
};

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    slots: [MAIN_COLUMN_COUNT]Slot,

    pub fn canonical(definition: *const component.Definition) !Binding {
        try definition.validate();
        var slots: [MAIN_COLUMN_COUNT]Slot = undefined;
        for (&slots, definition.main.physical(), CANONICAL_RECIPE, 0..) |
            *slot,
            value,
            source_value,
            column,
        | slot.* = .{
            .column = @intCast(column),
            .value = value,
            .source = source_value,
        };
        return .{
            .format_version = BINDING_FORMAT_VERSION,
            .semantic_format_version = digest.typed_effect_format_version,
            .semantic_digest = component.SEMANTIC_DIGEST,
            .slots = slots,
        };
    }

    pub fn identityDigest(self: *const Binding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(BINDING_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hash.update(&self.semantic_digest);
        hashInt(&hash, u16, self.slots.len);
        for (self.slots) |slot| {
            hashInt(&hash, u8, slot.column);
            hashInt(&hash, u32, @intFromEnum(slot.value));
            hashInt(&hash, u8, @intFromEnum(slot.source));
        }
        return hash.finalResult();
    }
};

pub const Executor = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const component.Definition,
        supplied: *const Binding,
    ) !Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*))
            return error.InvalidWitnessBinding;
        const binding_digest = supplied.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{ .binding = supplied.*, .binding_digest = binding_digest };
    }

    /// Materialize independent path rows. Relation closure may join rows from
    /// distinct paths; `PreparedPath` is the stricter convenience for one path.
    pub fn generateMainInto(
        self: *const Executor,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        invocations: []const Invocation,
        log_size: u32,
    ) Error!void {
        return direct.generateMainInto(
            M31,
            Invocation,
            MAIN_COLUMN_COUNT,
            columns,
            invocations,
            log_size,
            M31.zero(),
            self,
            validateInvocationDirect,
            writeActiveRow,
        );
    }

    pub fn generatePreparedPathInto(
        self: *const Executor,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        path: *const PreparedPath,
        log_size: u32,
    ) Error!void {
        try path.validate();
        try rejectDestinationOverlapWithPath(columns, path);
        return self.generateMainInto(columns, path.rows, log_size);
    }
};

pub const MainRow = struct {
    enabler: M31,
    tree_id: M31,
    depth: M31,
    index: M31,
    direction: M31,
    is_leaf: M31,
    left: [DIGEST_WORD_COUNT]M31,
    right: [DIGEST_WORD_COUNT]M31,
    parent: [DIGEST_WORD_COUNT]M31,
    output_tail: [DIGEST_WORD_COUNT]M31,
    child: [DIGEST_WORD_COUNT]M31,

    pub fn values(self: MainRow) [MAIN_COLUMN_COUNT]M31 {
        return .{
            self.enabler,
            self.tree_id,
            self.depth,
            self.index,
            self.direction,
            self.is_leaf,
        } ++ self.left ++ self.right ++ self.parent ++ self.output_tail ++ self.child;
    }

    pub fn parentU32(self: MainRow) [DIGEST_WORD_COUNT]u32 {
        var result: [DIGEST_WORD_COUNT]u32 = undefined;
        for (&result, self.parent) |*target, value| target.* = value.toU32();
        return result;
    }
};

/// A sealed, top-to-bottom relation chain built from a leaf digest and path
/// steps listed from root side to leaf side.
pub const PreparedPath = struct {
    allocator: std.mem.Allocator,
    tree_id: u32,
    root_depth: u32,
    root_index: u32,
    leaf: [DIGEST_WORD_COUNT]u32,
    rows: []Invocation,
    root: [DIGEST_WORD_COUNT]u32,
    authority_digest: digest.Digest,

    pub fn init(
        allocator: std.mem.Allocator,
        tree_id: u32,
        root_depth: u32,
        root_index: u32,
        leaf: [DIGEST_WORD_COUNT]u32,
        steps: []const PathStep,
    ) Error!PreparedPath {
        try validateCoordinate(tree_id);
        try validateCoordinate(root_depth);
        try validateCoordinate(root_index);
        try validateDigest(leaf);
        for (steps) |step| try validateStep(step);

        const rows = try allocator.alloc(Invocation, steps.len);
        errdefer allocator.free(rows);
        var depth = root_depth;
        var index = root_index;
        for (rows, steps, 0..) |*row, step, row_index| {
            row.* = .{
                .tree_id = tree_id,
                .depth = depth,
                .index = index,
                .child = [_]u32{0} ** DIGEST_WORD_COUNT,
                .step = step,
                .is_leaf = row_index + 1 == rows.len,
            };
            if (row_index + 1 < rows.len) {
                depth = try nextDepth(depth);
                index = try nextIndex(index, step.direction);
            }
        }

        var current = leaf;
        var cursor = rows.len;
        while (cursor > 0) {
            cursor -= 1;
            rows[cursor].child = current;
            current = (materializeAssumeValid(rows[cursor])).parentU32();
        }
        const authority_digest = pathDigest(
            tree_id,
            root_depth,
            root_index,
            leaf,
            rows,
            current,
        );
        return .{
            .allocator = allocator,
            .tree_id = tree_id,
            .root_depth = root_depth,
            .root_index = root_index,
            .leaf = leaf,
            .rows = rows,
            .root = current,
            .authority_digest = authority_digest,
        };
    }

    pub fn deinit(self: *PreparedPath) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    /// Hot integrity gate: allocation-free and linear byte hashing only.
    pub fn validate(self: *const PreparedPath) Error!void {
        if (!std.mem.eql(u8, &self.authority_digest, &pathDigest(
            self.tree_id,
            self.root_depth,
            self.root_index,
            self.leaf,
            self.rows,
            self.root,
        ))) return error.AuthorityMismatch;
    }

    /// Cold audit: independently replays coordinates, selections, and every
    /// Poseidon2 step from leaf to root without allocating.
    pub fn validateAgainstAuthority(self: *const PreparedPath) Error!void {
        try self.validate();
        try validateCoordinate(self.tree_id);
        try validateCoordinate(self.root_depth);
        try validateCoordinate(self.root_index);
        try validateDigest(self.leaf);
        var depth = self.root_depth;
        var index = self.root_index;
        for (self.rows, 0..) |row, row_index| {
            try validateInvocation(row);
            if (row.tree_id != self.tree_id or row.depth != depth or row.index != index or
                row.is_leaf != (row_index + 1 == self.rows.len))
            {
                return error.InvalidPath;
            }
            if (row_index + 1 < self.rows.len) {
                depth = try nextDepth(depth);
                index = try nextIndex(index, row.step.direction);
            }
        }
        var current = self.leaf;
        var cursor = self.rows.len;
        while (cursor > 0) {
            cursor -= 1;
            if (!std.mem.eql(u32, &self.rows[cursor].child, &current))
                return error.InvalidPath;
            current = (materializeAssumeValid(self.rows[cursor])).parentU32();
        }
        if (!std.mem.eql(u32, &current, &self.root))
            return error.InvalidPath;
    }
};

pub fn logicalRow(invocation: Invocation) Error![component.LOGICAL_INPUT_COUNT]M31 {
    try validateInvocation(invocation);
    return materializeAssumeValid(invocation).values();
}

pub fn parentDigest(invocation: Invocation) Error![DIGEST_WORD_COUNT]u32 {
    try validateInvocation(invocation);
    return materializeAssumeValid(invocation).parentU32();
}

/// Exact 16-word permutation preimage used by the shared Poseidon2 provider.
/// This avoids recomputing the permutation when only provider work is being
/// scheduled while retaining the same canonicality and direction authority.
pub fn poseidonInput(invocation: Invocation) Error![STATE_WIDTH]u32 {
    try validateInvocation(invocation);
    return if (invocation.step.direction == 0)
        invocation.child ++ invocation.step.sibling
    else
        invocation.step.sibling ++ invocation.child;
}

pub inline fn writeActiveRow(
    columns: *[MAIN_COLUMN_COUNT][]M31,
    row_index: usize,
    invocation: Invocation,
) void {
    const values = materializeAssumeValid(invocation).values();
    inline for (0..MAIN_COLUMN_COUNT) |column|
        columns[column][row_index] = values[column];
}

fn materializeAssumeValid(invocation: Invocation) MainRow {
    var child: [DIGEST_WORD_COUNT]M31 = undefined;
    var sibling: [DIGEST_WORD_COUNT]M31 = undefined;
    for (&child, invocation.child) |*target, value|
        target.* = M31.fromCanonical(value);
    for (&sibling, invocation.step.sibling) |*target, value|
        target.* = M31.fromCanonical(value);
    const left = if (invocation.step.direction == 0) child else sibling;
    const right = if (invocation.step.direction == 0) sibling else child;
    var state: poseidon2.State = left ++ right;
    poseidon2.permute(&state);
    return .{
        .enabler = M31.one(),
        .tree_id = M31.fromCanonical(invocation.tree_id),
        .depth = M31.fromCanonical(invocation.depth),
        .index = M31.fromCanonical(invocation.index),
        .direction = M31.fromCanonical(invocation.step.direction),
        .is_leaf = M31.fromCanonical(@intFromBool(invocation.is_leaf)),
        .left = left,
        .right = right,
        .parent = state[0..DIGEST_WORD_COUNT].*,
        .output_tail = state[DIGEST_WORD_COUNT..STATE_WIDTH].*,
        .child = child,
    };
}

pub fn validateInvocation(invocation: Invocation) Error!void {
    try validateCoordinate(invocation.tree_id);
    try validateCoordinate(invocation.depth);
    try validateCoordinate(invocation.index);
    try validateDigest(invocation.child);
    try validateStep(invocation.step);
    _ = try nextDepth(invocation.depth);
    _ = try nextIndex(invocation.index, invocation.step.direction);
}

fn validateInvocationDirect(invocation: Invocation) direct.Error!void {
    validateInvocation(invocation) catch return error.InvalidTraceRow;
}

fn validateStep(step: PathStep) Error!void {
    if (step.direction > 1) return error.InvalidWitness;
    try validateDigest(step.sibling);
}

fn validateDigest(value: [DIGEST_WORD_COUNT]u32) Error!void {
    for (value) |word| try validateCoordinate(word);
}

fn validateCoordinate(value: u32) Error!void {
    if (value >= m31.Modulus) return error.InvalidWitness;
}

fn nextDepth(depth: u32) Error!u32 {
    const result = std.math.add(u32, depth, 1) catch
        return error.ArithmeticOverflow;
    if (result >= m31.Modulus) return error.InvalidWitness;
    return result;
}

fn nextIndex(index: u32, direction: u32) Error!u32 {
    const doubled = std.math.mul(u32, index, 2) catch
        return error.ArithmeticOverflow;
    const result = std.math.add(u32, doubled, direction) catch
        return error.ArithmeticOverflow;
    if (result >= m31.Modulus) return error.InvalidWitness;
    return result;
}

fn pathDigest(
    tree_id: u32,
    root_depth: u32,
    root_index: u32,
    leaf: [DIGEST_WORD_COUNT]u32,
    rows: []const Invocation,
    root: [DIGEST_WORD_COUNT]u32,
) digest.Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PATH_DOMAIN);
    hashInt(&hash, u16, PATH_FORMAT_VERSION);
    hashInt(&hash, u32, tree_id);
    hashInt(&hash, u32, root_depth);
    hashInt(&hash, u32, root_index);
    for (leaf) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u64, rows.len);
    for (rows) |row| {
        hashInt(&hash, u32, row.tree_id);
        hashInt(&hash, u32, row.depth);
        hashInt(&hash, u32, row.index);
        for (row.child) |word| hashInt(&hash, u32, word);
        hashInt(&hash, u32, row.step.direction);
        for (row.step.sibling) |word| hashInt(&hash, u32, word);
        hashInt(&hash, u8, @intFromBool(row.is_leaf));
    }
    for (root) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}

const AddressRange = struct {
    start: usize,
    end: usize,

    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn rejectDestinationOverlapWithPath(
    columns: *const [MAIN_COLUMN_COUNT][]M31,
    path: *const PreparedPath,
) direct.Error!void {
    const protected = try objectRange(path);
    for (columns) |column| {
        const destination = try sliceRange(M31, column);
        if (destination.overlaps(protected)) return error.AliasedDestination;
    }
}

fn sliceRange(comptime T: type, values: []const T) direct.Error!AddressRange {
    const byte_len = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, byte_len) catch return error.AddressOverflow,
    };
}

fn objectRange(value: anytype) direct.Error!AddressRange {
    const T = @TypeOf(value.*);
    const start = @intFromPtr(value);
    return .{
        .start = start,
        .end = std.math.add(usize, start, @sizeOf(T)) catch return error.AddressOverflow,
    };
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

comptime {
    if (CANONICAL_RECIPE.len != MAIN_COLUMN_COUNT or
        @sizeOf(MainSource) != @sizeOf(u8))
    {
        @compileError("Merkle-path witness recipe drifted");
    }
}

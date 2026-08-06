//! Canonical fixed direct-polynomial programs for materialization cost models.
//!
//! A materialization search changes equality boundaries, but a component may
//! also own direct constraints which are independent of that cut. Counting
//! those roots without lowering their expressions makes global DAG, committed
//! read, and live-value costs internally inconsistent. This module represents
//! the fixed expressions as a small validated SSA program and lowers them
//! lazily on either side of the caller-owned materialization equalities.
//!
//! The representation is intentionally independent of the typed semantic
//! arena. A column may explicitly bind to the materialization gate, allowing a
//! target arena to reuse that committed leaf, or name a stable component role.
//! Fixed nodes therefore never enter the semantic witness closure.

const std = @import("std");

pub const Digest = [32]u8;
pub const format_version: u16 = 1;
pub const digest_domain = "stwo-zig/typed-air/fixed-direct-program-v1";
pub const m31_modulus: u32 = 0x7fff_ffff;

pub const max_scope_id_bytes: usize = 128;
pub const max_role_bytes: usize = 96;
pub const max_columns: usize = 4_096;
pub const max_nodes: usize = 65_536;
pub const max_roots_per_phase: usize = 16_384;

pub const NodeId = enum(u32) { _ };

pub const CommitmentTree = enum(u8) {
    preprocessed = 0,
    main = 1,
    interaction = 2,
};

/// How a fixed-program leaf joins the caller's target direct arena.
pub const ColumnBinding = enum(u8) {
    /// The semantic activation value supplied as the materialization gate.
    gate = 0,
    /// A component-owned committed column identified by scope, role and place.
    component = 1,
};

/// Candidate-relative component-local placement in one commitment tree.
pub const Placement = union(enum(u8)) {
    absolute: u32,
    after_materializations: struct {
        /// Number of main columns preceding the candidate materialization block.
        prefix_columns: u32,
        /// Stable offset within the fixed suffix following that block.
        trailing_offset: u32,
    },

    pub fn resolve(self: Placement, materialization_count: u64) Error!u64 {
        return switch (self) {
            .absolute => |index| index,
            .after_materializations => |relative| blk: {
                const after_prefix = std.math.add(
                    u64,
                    relative.prefix_columns,
                    materialization_count,
                ) catch return error.PlacementOverflow;
                break :blk std.math.add(
                    u64,
                    after_prefix,
                    relative.trailing_offset,
                ) catch return error.PlacementOverflow;
            },
        };
    }
};

pub const Column = struct {
    /// Stable, human-reviewable identity within `Program.scope_id`.
    role: []const u8,
    binding: ColumnBinding,
    tree: CommitmentTree,
    placement: Placement,
};

pub const Op = enum(u8) {
    constant = 0,
    column = 1,
    add = 2,
    sub = 3,
    neg = 4,
    mul = 5,
};

pub const BinaryOp = enum(u8) { add, sub, mul };

/// Canonical flat SSA node. Operands must precede their consumer. `value` is
/// the canonical M31 representative for `constant` and a column-table index
/// for `column`; it is zero for arithmetic nodes.
pub const Node = struct {
    op: Op,
    lhs: u32 = 0,
    rhs: u32 = 0,
    value: u32 = 0,
};

pub const Identity = struct {
    format_version: u16,
    scope_id: []const u8,
    scope_version: u16,
    materialization_tree: CommitmentTree,
    materialization_column_start: u32,
    column_count: u32,
    node_count: u32,
    fixed_root_count: u32,
    digest: Digest,
};

pub const ValidationError = error{
    DegreeOverflow,
    DuplicateColumnPlacement,
    DuplicateColumnRole,
    DuplicateGateColumn,
    DuplicateNode,
    EmptyFixedRoots,
    EmptyRole,
    EmptyScopeId,
    InvalidColumn,
    InvalidConstant,
    InvalidNode,
    InvalidRelativePlacement,
    InvalidRoot,
    InvalidScopeVersion,
    NonCanonicalNode,
    PlacementOverflow,
    RoleTooLong,
    ScopeIdTooLong,
    TooManyColumns,
    TooManyNodes,
    TooManyRoots,
    UnsupportedMaterializationTree,
    UnusedColumn,
    UnusedNode,
};

pub const LoweringError = error{
    InvalidDestinationLength,
    InvalidLoweringEmitter,
    InvalidLoweringPhase,
    MissingLoweredOperand,
};

pub const Error = std.mem.Allocator.Error || ValidationError || LoweringError;

/// Borrowed canonical fixed program. Root order is semantic: prefix roots are
/// consumed before caller-owned materialization equalities and suffix roots
/// afterward. Nodes shared by both phases remain mapped in one target arena.
pub const Program = struct {
    scope_id: []const u8,
    scope_version: u16,
    /// Candidate materializations occupy this tree starting at this physical
    /// column. The pair is authenticated even when no fixed column is relative.
    materialization_tree: CommitmentTree,
    materialization_column_start: u32,
    columns: []const Column,
    nodes: []const Node,
    prefix_roots: []const NodeId,
    suffix_roots: []const NodeId,

    pub fn validate(self: Program, allocator: std.mem.Allocator) Error!void {
        if (self.scope_id.len == 0) return error.EmptyScopeId;
        if (self.scope_id.len > max_scope_id_bytes) return error.ScopeIdTooLong;
        if (self.scope_version == 0) return error.InvalidScopeVersion;
        // Cost-frontier v1 accounts candidate materializations as main-trace
        // columns. Keep the tree in the authenticated representation so a
        // later format can extend the model without silently reinterpreting
        // v1 receipts, but reject unsupported trees before authenticating one.
        if (self.materialization_tree != .main)
            return error.UnsupportedMaterializationTree;
        if (self.columns.len > max_columns) return error.TooManyColumns;
        if (self.nodes.len > max_nodes) return error.TooManyNodes;
        if (self.prefix_roots.len > max_roots_per_phase or
            self.suffix_roots.len > max_roots_per_phase)
        {
            return error.TooManyRoots;
        }
        if (self.prefix_roots.len + self.suffix_roots.len == 0)
            return error.EmptyFixedRoots;

        var gate_seen = false;
        for (self.columns, 0..) |column, index| {
            if (column.role.len == 0) return error.EmptyRole;
            if (column.role.len > max_role_bytes) return error.RoleTooLong;
            if (column.binding == .gate) {
                if (gate_seen) return error.DuplicateGateColumn;
                gate_seen = true;
            }
            for (self.columns[0..index]) |prior| {
                if (std.mem.eql(u8, prior.role, column.role))
                    return error.DuplicateColumnRole;
            }
            _ = try column.placement.resolve(0);
            switch (column.placement) {
                .absolute => {},
                .after_materializations => |relative| {
                    if (column.tree != self.materialization_tree or
                        relative.prefix_columns != self.materialization_column_start)
                    {
                        return error.InvalidRelativePlacement;
                    }
                },
            }
        }

        for (self.nodes, 0..) |node, index| {
            try validateNode(node, index, self.columns.len);
            for (self.nodes[0..index]) |prior| {
                if (std.meta.eql(prior, node)) return error.DuplicateNode;
            }
        }

        try validateRoots(self.prefix_roots, self.nodes.len);
        try validateRoots(self.suffix_roots, self.nodes.len);

        const reachable = try allocator.alloc(bool, self.nodes.len);
        defer allocator.free(reachable);
        @memset(reachable, false);
        markRoots(reachable, self.prefix_roots);
        markRoots(reachable, self.suffix_roots);
        var reverse = self.nodes.len;
        while (reverse > 0) {
            reverse -= 1;
            if (!reachable[reverse]) continue;
            markOperands(reachable, self.nodes[reverse]);
        }
        for (reachable) |needed| if (!needed) return error.UnusedNode;

        const used_columns = try allocator.alloc(bool, self.columns.len);
        defer allocator.free(used_columns);
        @memset(used_columns, false);
        for (self.nodes) |node| if (node.op == .column) {
            used_columns[node.value] = true;
        };
        for (used_columns) |used| if (!used) return error.UnusedColumn;
    }

    /// Validates candidate-dependent physical placement in addition to the
    /// canonical program. Equal indices in different commitment trees are
    /// distinct; equal indices in one tree are rejected.
    pub fn validateFor(
        self: Program,
        allocator: std.mem.Allocator,
        materialization_count: u64,
    ) Error!void {
        try self.validate(allocator);
        for (self.columns, 0..) |column, index| {
            const resolved = try column.placement.resolve(materialization_count);
            for (self.columns[0..index]) |prior| {
                if (prior.tree != column.tree) continue;
                if (try prior.placement.resolve(materialization_count) == resolved)
                    return error.DuplicateColumnPlacement;
            }
        }
    }

    pub fn fixedRootCount(self: Program) Error!u32 {
        const count = std.math.add(
            usize,
            self.prefix_roots.len,
            self.suffix_roots.len,
        ) catch return error.TooManyRoots;
        return std.math.cast(u32, count) orelse error.TooManyRoots;
    }

    pub fn totalRootCount(
        self: Program,
        candidate_materialization_roots: u64,
    ) Error!u64 {
        return std.math.add(
            u64,
            candidate_materialization_roots,
            try self.fixedRootCount(),
        ) catch error.TooManyRoots;
    }

    /// Maximum polynomial degree of any ordered fixed root when committed
    /// columns are degree one and constants are degree zero.
    pub fn maximumRootDegree(
        self: Program,
        allocator: std.mem.Allocator,
    ) Error!u64 {
        try self.validate(allocator);
        const degrees = try allocator.alloc(u64, self.nodes.len);
        defer allocator.free(degrees);
        for (self.nodes, degrees) |node, *degree| degree.* = switch (node.op) {
            .constant => 0,
            .column => 1,
            .add, .sub => @max(degrees[node.lhs], degrees[node.rhs]),
            .neg => degrees[node.lhs],
            .mul => std.math.add(u64, degrees[node.lhs], degrees[node.rhs]) catch
                return error.DegreeOverflow,
        };
        var result: u64 = 0;
        for (self.prefix_roots) |root| result = @max(result, degrees[@intFromEnum(root)]);
        for (self.suffix_roots) |root| result = @max(result, degrees[@intFromEnum(root)]);
        return result;
    }

    /// Canonical identity after full validation. Slice contents, never pointer
    /// values or host padding, enter the digest.
    pub fn digestValue(
        self: Program,
        allocator: std.mem.Allocator,
    ) Error!Digest {
        try self.validate(allocator);
        return self.digestValidated();
    }

    pub fn identity(
        self: Program,
        allocator: std.mem.Allocator,
    ) Error!Identity {
        const digest = try self.digestValue(allocator);
        return .{
            .format_version = format_version,
            .scope_id = self.scope_id,
            .scope_version = self.scope_version,
            .materialization_tree = self.materialization_tree,
            .materialization_column_start = self.materialization_column_start,
            .column_count = std.math.cast(u32, self.columns.len) orelse
                return error.TooManyColumns,
            .node_count = std.math.cast(u32, self.nodes.len) orelse
                return error.TooManyNodes,
            .fixed_root_count = try self.fixedRootCount(),
            .digest = digest,
        };
    }

    fn digestValidated(self: Program) Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(digest_domain);
        hashInt(&hash, u16, format_version);
        hashString(&hash, self.scope_id);
        hashInt(&hash, u16, self.scope_version);
        hashInt(&hash, u8, @intFromEnum(self.materialization_tree));
        hashInt(&hash, u32, self.materialization_column_start);
        hashInt(&hash, u32, @intCast(self.columns.len));
        for (self.columns) |column| {
            hashString(&hash, column.role);
            hashInt(&hash, u8, @intFromEnum(column.binding));
            hashInt(&hash, u8, @intFromEnum(column.tree));
            hashInt(&hash, u8, @intFromEnum(std.meta.activeTag(column.placement)));
            switch (column.placement) {
                .absolute => |index| hashInt(&hash, u32, index),
                .after_materializations => |relative| {
                    hashInt(&hash, u32, relative.prefix_columns);
                    hashInt(&hash, u32, relative.trailing_offset);
                },
            }
        }
        hashInt(&hash, u32, @intCast(self.nodes.len));
        for (self.nodes) |node| {
            hashInt(&hash, u8, @intFromEnum(node.op));
            hashInt(&hash, u32, node.lhs);
            hashInt(&hash, u32, node.rhs);
            hashInt(&hash, u32, node.value);
        }
        hashRoots(&hash, self.prefix_roots);
        hashRoots(&hash, self.suffix_roots);
        return hash.finalResult();
    }
};

pub const LoweringPhase = enum {
    initial,
    lowering_prefix,
    prefix_complete,
    lowering_suffix,
    complete,
    poisoned,
};

/// Candidate-specific lazy lowering state. The emitter must remain the same
/// target arena for both calls and provide:
///
/// - `constant(u32) !u32`
/// - `column(*const Digest, *const Column, u64) !u32`
/// - `binary(BinaryOp, u32, u32) !u32`
/// - `neg(u32) !u32`
///
/// Destination entries are target node IDs in the declared root order.
pub const Lowering = struct {
    allocator: std.mem.Allocator,
    program: Program,
    materialization_count: u64,
    digest: Digest,
    mapped: []u32,
    needed: []bool,
    emitter_address: ?usize = null,
    phase: LoweringPhase = .initial,

    const no_node = std.math.maxInt(u32);

    pub fn init(
        allocator: std.mem.Allocator,
        program: Program,
        materialization_count: u64,
    ) Error!Lowering {
        try program.validateFor(allocator, materialization_count);
        const mapped = try allocator.alloc(u32, program.nodes.len);
        errdefer allocator.free(mapped);
        @memset(mapped, no_node);
        const needed = try allocator.alloc(bool, program.nodes.len);
        errdefer allocator.free(needed);
        return .{
            .allocator = allocator,
            .program = program,
            .materialization_count = materialization_count,
            .digest = program.digestValidated(),
            .mapped = mapped,
            .needed = needed,
        };
    }

    pub fn deinit(self: *Lowering) void {
        self.allocator.free(self.needed);
        self.allocator.free(self.mapped);
        self.* = undefined;
    }

    pub fn programDigest(self: *const Lowering) Digest {
        return self.digest;
    }

    pub fn lowerPrefix(
        self: *Lowering,
        emitter: anytype,
        destination: []u32,
    ) !void {
        if (self.phase != .initial) return error.InvalidLoweringPhase;
        if (destination.len != self.program.prefix_roots.len)
            return error.InvalidDestinationLength;
        try self.bindEmitter(emitter);
        self.phase = .lowering_prefix;
        errdefer self.phase = .poisoned;
        try self.lowerRoots(emitter, self.program.prefix_roots, destination);
        self.phase = .prefix_complete;
    }

    pub fn lowerSuffix(
        self: *Lowering,
        emitter: anytype,
        destination: []u32,
    ) !void {
        if (self.phase != .prefix_complete) return error.InvalidLoweringPhase;
        if (destination.len != self.program.suffix_roots.len)
            return error.InvalidDestinationLength;
        try self.bindEmitter(emitter);
        self.phase = .lowering_suffix;
        errdefer self.phase = .poisoned;
        try self.lowerRoots(emitter, self.program.suffix_roots, destination);
        self.phase = .complete;
    }

    fn lowerRoots(
        self: *Lowering,
        emitter: anytype,
        roots: []const NodeId,
        destination: []u32,
    ) !void {
        for (roots, destination) |root, *lowered| {
            lowered.* = try self.lowerRoot(emitter, root);
        }
    }

    fn lowerRoot(self: *Lowering, emitter: anytype, root: NodeId) !u32 {
        const root_index: usize = @intFromEnum(root);
        if (self.mapped[root_index] != no_node) return self.mapped[root_index];
        @memset(self.needed, false);
        self.needed[root_index] = true;
        var reverse = root_index + 1;
        while (reverse > 0) {
            reverse -= 1;
            if (!self.needed[reverse] or self.mapped[reverse] != no_node) continue;
            markOperands(self.needed, self.program.nodes[reverse]);
        }

        for (self.program.nodes[0 .. root_index + 1], 0..) |node, index| {
            if (!self.needed[index] or self.mapped[index] != no_node) continue;
            self.mapped[index] = switch (node.op) {
                .constant => try emitter.constant(node.value),
                .column => blk: {
                    const column = &self.program.columns[node.value];
                    break :blk try emitter.column(
                        &self.digest,
                        column,
                        try column.placement.resolve(self.materialization_count),
                    );
                },
                .add => try emitter.binary(
                    .add,
                    try operand(self.mapped, node.lhs),
                    try operand(self.mapped, node.rhs),
                ),
                .sub => try emitter.binary(
                    .sub,
                    try operand(self.mapped, node.lhs),
                    try operand(self.mapped, node.rhs),
                ),
                .neg => try emitter.neg(try operand(self.mapped, node.lhs)),
                .mul => try emitter.binary(
                    .mul,
                    try operand(self.mapped, node.lhs),
                    try operand(self.mapped, node.rhs),
                ),
            };
        }
        return operand(self.mapped, @intFromEnum(root));
    }

    fn bindEmitter(self: *Lowering, emitter: anytype) LoweringError!void {
        const address = @intFromPtr(emitter);
        if (self.emitter_address) |bound| {
            if (bound != address) return error.InvalidLoweringEmitter;
        } else {
            self.emitter_address = address;
        }
    }
};

fn validateNode(node: Node, index: usize, column_count: usize) ValidationError!void {
    switch (node.op) {
        .constant => {
            if (node.lhs != 0 or node.rhs != 0) return error.NonCanonicalNode;
            if (node.value >= m31_modulus) return error.InvalidConstant;
        },
        .column => {
            if (node.lhs != 0 or node.rhs != 0) return error.NonCanonicalNode;
            if (node.value >= column_count) return error.InvalidColumn;
        },
        .add, .mul => {
            if (node.value != 0) return error.NonCanonicalNode;
            if (node.lhs >= index or node.rhs >= index) return error.InvalidNode;
            if (node.rhs < node.lhs) return error.NonCanonicalNode;
        },
        .sub => {
            if (node.value != 0) return error.NonCanonicalNode;
            if (node.lhs >= index or node.rhs >= index) return error.InvalidNode;
        },
        .neg => {
            if (node.rhs != 0 or node.value != 0) return error.NonCanonicalNode;
            if (node.lhs >= index) return error.InvalidNode;
        },
    }
}

fn validateRoots(
    roots: []const NodeId,
    node_count: usize,
) ValidationError!void {
    for (roots) |root| {
        if (@intFromEnum(root) >= node_count) return error.InvalidRoot;
    }
}

fn markRoots(reachable: []bool, roots: []const NodeId) void {
    for (roots) |root| reachable[@intFromEnum(root)] = true;
}

fn markOperands(reachable: []bool, node: Node) void {
    switch (node.op) {
        .constant, .column => {},
        .add, .sub, .mul => {
            reachable[node.lhs] = true;
            reachable[node.rhs] = true;
        },
        .neg => reachable[node.lhs] = true,
    }
}

fn operand(mapped: []const u32, raw: u32) LoweringError!u32 {
    if (raw >= mapped.len or mapped[raw] == Lowering.no_node)
        return error.MissingLoweredOperand;
    return mapped[raw];
}

fn hashRoots(hash: anytype, roots: []const NodeId) void {
    hashInt(hash, u32, @intCast(roots.len));
    for (roots) |root| hashInt(hash, u32, @intFromEnum(root));
}

fn hashString(hash: anytype, value: []const u8) void {
    hashInt(hash, u16, @intCast(value.len));
    hash.update(value);
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

//! Process-local custody for the immutable Ethereum program prefix.
//!
//! Construction independently opens the exact ELF bytes, derives the
//! canonical program image, builds the declared-program sparse commitment
//! with zero execution multiplicities, and records the ordered narrow
//! Poseidon calls emitted by that tree.  The heap-stable owner may then lend
//! this fixed material to a later prepared-witness transaction without
//! rebuilding the tree for every leaf.
//!
//! This is deliberately not a proof, transcript, or serialization authority.
//! Per-leaf fetch multiplicities, completion fetches, witness columns,
//! transcript state, PoW, queries, and proof bytes must still be produced and
//! verified independently.  Safe borrowers receive const slices only; the
//! process-local token binds those slices to the exact live owner.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const replay_producer =
    @import("ethereum_incremental_full_leaf_replay_producer_v4.zig");

const memory_state = frontend.runner.memory_state;
const merkle_node = frontend.air.memory_commitment.merkle_node;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const sparse_merkle = frontend.air.memory_commitment.sparse_merkle;
const program_commitment = frontend.air.program.commitment;
const program_decode = frontend.air.program.decode;
const program_table = frontend.air.program.table;
const commitment_witness = frontend.testing.commitment_witness;

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA_VERSION: u16 = 1;
pub const PROCESS_LOCAL_ONLY = true;
pub const SERIALIZABLE = false;
pub const PROOF_AUTHORITY = false;
pub const TRANSCRIPT_REUSE_ALLOWED = false;
pub const PREPARED_WITNESS_INTEGRATED = true;

pub const Error = error{
    InvalidPreparedProgramCommitmentInventoryV1,
    InvalidPreparedProgramCommitmentContentV1,
    InvalidPreparedProgramCommitmentTokenV1,
    InvalidPreparedProgramCommitmentBorrowV1,
};

/// Content identities for the exact immutable prefix.  This is diagnostic
/// and custody metadata, not a durable artifact: there is intentionally no
/// encode/decode function, and the process-local token below is indispensable
/// for admission of any borrowed buffers.
pub const InventoryV1 = struct {
    schema_version: u16 = SCHEMA_VERSION,
    source_byte_count: u64,
    source_bytes_sha256: [32]u8,
    program_source_identity_sha256: [32]u8,
    layout_identity_sha256: [32]u8,
    program_base: u32,
    program_end: u32,
    declared_row_count: u64,
    declared_rows_identity_sha256: [32]u8,
    committed_row_count: u64,
    committed_rows_identity_sha256: [32]u8,
    sparse_leaf_count: u64,
    sparse_node_count: u64,
    sparse_tree_root: u32,
    sparse_tree_identity_sha256: [32]u8,
    ordered_poseidon_call_count: u64,
    ordered_poseidon_calls_identity_sha256: [32]u8,
    multiplicity_index_slot_count: u64,
    multiplicity_index_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    pub fn validate(self: InventoryV1) !void {
        if (self.schema_version != SCHEMA_VERSION or
            self.source_byte_count == 0 or
            self.program_base >= self.program_end or
            self.declared_row_count == 0 or
            self.committed_row_count == 0 or
            self.committed_row_count > self.declared_row_count or
            self.sparse_leaf_count != (std.math.mul(
                u64,
                self.committed_row_count,
                4,
            ) catch return error.InvalidPreparedProgramCommitmentInventoryV1) or
            self.sparse_node_count == 0 or
            self.ordered_poseidon_call_count != self.sparse_node_count or
            self.multiplicity_index_slot_count != self.declared_row_count or
            allZero(&self.source_bytes_sha256) or
            allZero(&self.program_source_identity_sha256) or
            allZero(&self.layout_identity_sha256) or
            allZero(&self.declared_rows_identity_sha256) or
            allZero(&self.committed_rows_identity_sha256) or
            allZero(&self.sparse_tree_identity_sha256) or
            allZero(&self.ordered_poseidon_calls_identity_sha256) or
            allZero(&self.multiplicity_index_identity_sha256) or
            allZero(&self.identity_sha256))
        {
            return error.InvalidPreparedProgramCommitmentInventoryV1;
        }
        const expected_identity = inventoryIdentity(self);
        if (!std.mem.eql(u8, &self.identity_sha256, &expected_identity))
            return error.InvalidPreparedProgramCommitmentInventoryV1;
    }
};

const MISSING_INDEX = std.math.maxInt(u32);

const MultiplicityIndexSlotV1 = struct {
    declared_index: u32 = MISSING_INDEX,
    committed_index: u32 = MISSING_INDEX,
};

const StorageV1 = struct {
    source_bytes: []u8,
    program: replay_producer.ProgramV4,
    commitment: program_commitment.Commitment,
    ordered_poseidon_calls: []poseidon2_air.Call,
    multiplicity_index: []MultiplicityIndexSlotV1,
    inventory: InventoryV1,
};

pub const TokenV1 = struct {
    schema_version: u16,
    owner_ptr: usize,
    storage_ptr: usize,
    source_ptr: usize,
    source_len: usize,
    minimal_rows_ptr: usize,
    minimal_rows_len: usize,
    declared_rows_ptr: usize,
    declared_rows_len: usize,
    committed_rows_ptr: usize,
    committed_rows_len: usize,
    sparse_leaves_ptr: usize,
    sparse_leaves_len: usize,
    sparse_nodes_ptr: usize,
    sparse_nodes_len: usize,
    ordered_calls_ptr: usize,
    ordered_calls_len: usize,
    multiplicity_index_ptr: usize,
    multiplicity_index_len: usize,
    inventory_identity_sha256: [32]u8,
    identity_sha256: [32]u8,

    fn init(
        owner: *const PreparedProgramCommitmentV1,
        storage: *const StorageV1,
    ) TokenV1 {
        var token = TokenV1{
            .schema_version = SCHEMA_VERSION,
            .owner_ptr = @intFromPtr(owner),
            .storage_ptr = @intFromPtr(storage),
            .source_ptr = @intFromPtr(storage.source_bytes.ptr),
            .source_len = storage.source_bytes.len,
            .minimal_rows_ptr = @intFromPtr(storage.program.minimal_words.ptr),
            .minimal_rows_len = storage.program.minimal_words.len,
            .declared_rows_ptr = @intFromPtr(storage.program.statement_words.ptr),
            .declared_rows_len = storage.program.statement_words.len,
            .committed_rows_ptr = @intFromPtr(storage.commitment.rows.ptr),
            .committed_rows_len = storage.commitment.rows.len,
            .sparse_leaves_ptr = @intFromPtr(storage.commitment.tree.leaves.ptr),
            .sparse_leaves_len = storage.commitment.tree.leaves.len,
            .sparse_nodes_ptr = @intFromPtr(storage.commitment.tree.nodes.ptr),
            .sparse_nodes_len = storage.commitment.tree.nodes.len,
            .ordered_calls_ptr = @intFromPtr(storage.ordered_poseidon_calls.ptr),
            .ordered_calls_len = storage.ordered_poseidon_calls.len,
            .multiplicity_index_ptr = @intFromPtr(storage.multiplicity_index.ptr),
            .multiplicity_index_len = storage.multiplicity_index.len,
            .inventory_identity_sha256 = storage.inventory.identity_sha256,
            .identity_sha256 = undefined,
        };
        token.identity_sha256 = tokenIdentity(token);
        return token;
    }

    fn validate(
        self: TokenV1,
        owner: *const PreparedProgramCommitmentV1,
        storage: *const StorageV1,
    ) !void {
        const expected_identity = tokenIdentity(self);
        if (self.schema_version != SCHEMA_VERSION or
            self.owner_ptr == 0 or self.owner_ptr != @intFromPtr(owner) or
            self.storage_ptr == 0 or self.storage_ptr != @intFromPtr(storage) or
            self.source_ptr != @intFromPtr(storage.source_bytes.ptr) or
            self.source_len != storage.source_bytes.len or
            self.minimal_rows_ptr != @intFromPtr(storage.program.minimal_words.ptr) or
            self.minimal_rows_len != storage.program.minimal_words.len or
            self.declared_rows_ptr != @intFromPtr(storage.program.statement_words.ptr) or
            self.declared_rows_len != storage.program.statement_words.len or
            self.committed_rows_ptr != @intFromPtr(storage.commitment.rows.ptr) or
            self.committed_rows_len != storage.commitment.rows.len or
            self.sparse_leaves_ptr != @intFromPtr(storage.commitment.tree.leaves.ptr) or
            self.sparse_leaves_len != storage.commitment.tree.leaves.len or
            self.sparse_nodes_ptr != @intFromPtr(storage.commitment.tree.nodes.ptr) or
            self.sparse_nodes_len != storage.commitment.tree.nodes.len or
            self.ordered_calls_ptr != @intFromPtr(storage.ordered_poseidon_calls.ptr) or
            self.ordered_calls_len != storage.ordered_poseidon_calls.len or
            self.multiplicity_index_ptr != @intFromPtr(storage.multiplicity_index.ptr) or
            self.multiplicity_index_len != storage.multiplicity_index.len or
            !std.mem.eql(
                u8,
                &self.inventory_identity_sha256,
                &storage.inventory.identity_sha256,
            ) or allZero(&self.identity_sha256) or
            !std.mem.eql(u8, &self.identity_sha256, &expected_identity))
        {
            return error.InvalidPreparedProgramCommitmentTokenV1;
        }
    }
};

/// Heap-stable, nonserializable owner for the immutable program prefix.
pub const PreparedProgramCommitmentV1 = struct {
    allocator: std.mem.Allocator,
    storage: *StorageV1,
    token: TokenV1,

    const Self = @This();

    /// Copies `source_bytes`; no caller-owned byte or parsed-program pointer
    /// survives construction.  The declared commitment deliberately has zero
    /// fetch multiplicities: execution and completion multiplicities belong
    /// to each independently prepared leaf.
    pub fn create(
        allocator: std.mem.Allocator,
        source_bytes: []const u8,
    ) !*Self {
        if (source_bytes.len == 0)
            return error.InvalidPreparedProgramCommitmentContentV1;
        const owned_source = try allocator.dupe(u8, source_bytes);
        errdefer allocator.free(owned_source);

        var program = try replay_producer.ProgramV4.init(
            allocator,
            owned_source,
        );
        errdefer program.deinit();

        const NoExecutionRow = struct { pc: u32, inst_word: u32 };
        const no_execution_rows: []const NoExecutionRow = &.{};
        var commitment = try program_commitment.buildDeclaredForProfileSources(
            allocator,
            .rv32im_zkvm_ethereum_v1,
            .{no_execution_rows},
            program.statement_words,
            null,
        );
        errdefer commitment.deinit(allocator);

        const calls = try allocator.alloc(
            poseidon2_air.Call,
            commitment.tree.nodes.len,
        );
        errdefer allocator.free(calls);
        for (commitment.tree.nodes, calls) |node, *call| {
            call.* = merkle_node.NodeRow.fromNode(
                node,
                commitment.tree.root,
            ).poseidonCall();
        }

        const multiplicity_index = try buildMultiplicityIndex(
            allocator,
            &program,
            &commitment,
        );
        errdefer allocator.free(multiplicity_index);

        const inventory = try inventoryFromContent(
            owned_source,
            &program,
            &commitment,
            calls,
            multiplicity_index,
        );
        const storage = try allocator.create(StorageV1);
        errdefer allocator.destroy(storage);
        storage.* = .{
            .source_bytes = owned_source,
            .program = program,
            .commitment = commitment,
            .ordered_poseidon_calls = calls,
            .multiplicity_index = multiplicity_index,
            .inventory = inventory,
        };

        const owner = try allocator.create(Self);
        errdefer allocator.destroy(owner);
        owner.* = .{
            .allocator = allocator,
            .storage = storage,
            .token = undefined,
        };
        owner.token = TokenV1.init(owner, storage);
        try owner.validateColdContent();
        return owner;
    }

    /// O(1) process-local validation for repeated prepared-witness borrows.
    /// Exact content was hashed and the sparse tree was independently rebuilt
    /// during `create`; all subsequently exposed buffers are const.  Call
    /// `validateColdContent` at a new hostile process boundary when a complete
    /// content-seal recheck is required.
    pub fn validateBorrowed(self: *const Self) !void {
        const storage = self.storage;
        try storage.inventory.validate();
        try self.token.validate(self, storage);
        try validateCheapShape(storage);
    }

    /// Rehashes every retained byte, row, sparse node, and ordered call and
    /// rechecks the node-to-call projection.  This does not reuse or mint a
    /// proof/transcript and deliberately performs no per-leaf work.
    pub fn validateColdContent(self: *const Self) !void {
        try self.validateBorrowed();
        try self.storage.commitment.validate(self.allocator);
        try validateCanonicalContent(self.storage);
        const actual = try inventoryFromContent(
            self.storage.source_bytes,
            &self.storage.program,
            &self.storage.commitment,
            self.storage.ordered_poseidon_calls,
            self.storage.multiplicity_index,
        );
        if (!std.meta.eql(actual, self.storage.inventory))
            return error.InvalidPreparedProgramCommitmentContentV1;
    }

    pub fn borrow(self: *const Self) !BorrowedProgramCommitmentV1 {
        try self.validateBorrowed();
        return self.borrowUnchecked();
    }

    fn prepareLeafRows(
        self: *const Self,
        allocator: std.mem.Allocator,
        execution_sources: anytype,
        extra_fetch: ?program_table.Fetch,
    ) !PreparedLeafProgramRowsV1 {
        try self.validateBorrowed();
        const multiplicities = try allocator.alloc(
            u32,
            self.storage.commitment.rows.len,
        );
        defer allocator.free(multiplicities);
        @memset(multiplicities, 0);

        var execution_fetches: u64 = 0;
        inline for (execution_sources) |execution_rows| {
            for (execution_rows) |row| {
                try registerLeafFetch(
                    self.storage,
                    multiplicities,
                    .{ .pc = row.pc, .word = row.inst_word },
                );
                execution_fetches = std.math.add(
                    u64,
                    execution_fetches,
                    1,
                ) catch return error.PreparedProgramMultiplicityOverflowV1;
            }
        }
        if (execution_fetches == 0)
            return error.InvalidPreparedProgramLeafRowsV1;
        var completion_fetches: u8 = 0;
        if (extra_fetch) |fetch| {
            try registerLeafFetch(self.storage, multiplicities, fetch);
            completion_fetches = 1;
        }

        const rows = try allocator.dupe(
            program_commitment.Row,
            self.storage.commitment.rows,
        );
        errdefer allocator.free(rows);
        for (rows, multiplicities) |*row, multiplicity|
            row.multiplicity = multiplicity;
        var result = PreparedLeafProgramRowsV1{
            .allocator = allocator,
            .owner = self,
            .token = &self.token,
            .rows = rows,
            .receipt = .{
                .execution_fetch_rows_scanned = execution_fetches,
                .completion_fetch_rows_scanned = completion_fetches,
                .fixed_declared_rows = self.storage.inventory.declared_row_count,
                .fixed_committed_rows = self.storage.inventory.committed_row_count,
                .fixed_sparse_leaves = self.storage.inventory.sparse_leaf_count,
                .fixed_sparse_nodes = self.storage.inventory.sparse_node_count,
                .sparse_tree_builds_elided = 1,
                .sparse_tree_validation_rebuilds_elided = 1,
                .declared_row_decodes_elided = self.storage.inventory.committed_row_count,
                .node_poseidon_call_derivations_elided = self.storage.inventory.sparse_node_count,
            },
        };
        try result.validate();
        return result;
    }

    fn borrowUnchecked(self: *const Self) BorrowedProgramCommitmentV1 {
        return .{
            .owner = self,
            .token = &self.token,
            .source_bytes = self.storage.source_bytes,
            .layout = &self.storage.program.layout,
            .declared_rows = self.storage.program.statement_words,
            .commitment = &self.storage.commitment,
            .ordered_poseidon_calls = self.storage.ordered_poseidon_calls,
            .inventory = self.storage.inventory,
        };
    }

    pub fn deinit(self: *Self) void {
        const allocator = self.allocator;
        const storage = self.storage;
        self.token = undefined;
        storage.commitment.deinit(allocator);
        allocator.free(storage.ordered_poseidon_calls);
        allocator.free(storage.multiplicity_index);
        storage.program.deinit();
        allocator.free(storage.source_bytes);
        storage.* = undefined;
        allocator.destroy(storage);
        self.* = undefined;
        allocator.destroy(self);
    }
};

/// Leaf-specific program rows derived from the fixed owner. Only
/// multiplicities vary. `takeRows` transfers the allocation to a
/// `CommitmentWitness`; no fixed owner allocation is transferred.
pub const PreparedLeafProgramRowsV1 = struct {
    allocator: std.mem.Allocator,
    owner: *const PreparedProgramCommitmentV1,
    token: *const TokenV1,
    rows: []program_commitment.Row,
    receipt: commitment_witness.PreparedProgramWorkReceiptV1,

    const Self = @This();

    pub fn validate(self: *const Self) !void {
        try self.owner.validateBorrowed();
        try self.receipt.validate();
        const fixed = self.owner.storage.commitment.rows;
        if (self.token != &self.owner.token or self.rows.len != fixed.len or
            self.receipt.fixed_declared_rows !=
                self.owner.storage.inventory.declared_row_count or
            self.receipt.fixed_committed_rows != @as(u64, @intCast(fixed.len)) or
            self.receipt.fixed_sparse_leaves !=
                @as(u64, @intCast(self.owner.storage.commitment.tree.leaves.len)) or
            self.receipt.fixed_sparse_nodes !=
                @as(u64, @intCast(self.owner.storage.commitment.tree.nodes.len)))
        {
            return error.InvalidPreparedProgramLeafRowsV1;
        }
        var multiplicity_sum: u64 = 0;
        for (self.rows, fixed) |actual, expected| {
            if (actual.addr != expected.addr or
                !std.meta.eql(actual.values, expected.values) or
                actual.root != expected.root or expected.multiplicity != 0)
            {
                return error.InvalidPreparedProgramLeafRowsV1;
            }
            multiplicity_sum = std.math.add(
                u64,
                multiplicity_sum,
                actual.multiplicity,
            ) catch return error.PreparedProgramMultiplicityOverflowV1;
        }
        const expected_sum = std.math.add(
            u64,
            self.receipt.execution_fetch_rows_scanned,
            self.receipt.completion_fetch_rows_scanned,
        ) catch return error.PreparedProgramMultiplicityOverflowV1;
        if (multiplicity_sum != expected_sum)
            return error.InvalidPreparedProgramLeafRowsV1;
    }

    pub fn workReceipt(
        self: *const Self,
    ) commitment_witness.PreparedProgramWorkReceiptV1 {
        return self.receipt;
    }

    pub fn takeRows(self: *Self) ![]program_commitment.Row {
        try self.validate();
        const result = self.rows;
        self.* = undefined;
        return result;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }
};

/// Borrowed fixed-prefix projection for the prepared-witness API.  The
/// inventory alone is not authority: validation requires the exact token and
/// heap-stable owner pointers, plus every retained buffer pointer and length.
pub const BorrowedProgramCommitmentV1 = struct {
    owner: *const PreparedProgramCommitmentV1,
    token: *const TokenV1,
    source_bytes: []const u8,
    layout: *const memory_state.MemoryLayout,
    declared_rows: []const memory_state.WordState,
    commitment: *const program_commitment.Commitment,
    ordered_poseidon_calls: []const poseidon2_air.Call,
    inventory: InventoryV1,

    pub fn validate(self: BorrowedProgramCommitmentV1) !void {
        try self.owner.validateBorrowed();
        const expected = self.owner.borrowUnchecked();
        if (self.token != expected.token or
            self.source_bytes.ptr != expected.source_bytes.ptr or
            self.source_bytes.len != expected.source_bytes.len or
            self.layout != expected.layout or
            self.declared_rows.ptr != expected.declared_rows.ptr or
            self.declared_rows.len != expected.declared_rows.len or
            self.commitment != expected.commitment or
            self.ordered_poseidon_calls.ptr != expected.ordered_poseidon_calls.ptr or
            self.ordered_poseidon_calls.len != expected.ordered_poseidon_calls.len or
            !std.meta.eql(self.inventory, expected.inventory))
        {
            return error.InvalidPreparedProgramCommitmentBorrowV1;
        }
    }

    pub fn prepareLeafRows(
        self: BorrowedProgramCommitmentV1,
        allocator: std.mem.Allocator,
        execution_sources: anytype,
        extra_fetch: ?program_table.Fetch,
    ) !PreparedLeafProgramRowsV1 {
        try self.validate();
        return self.owner.prepareLeafRows(
            allocator,
            execution_sources,
            extra_fetch,
        );
    }
};

fn validateCheapShape(storage: *const StorageV1) !void {
    const inventory = storage.inventory;
    const actual_layout_identity = layoutIdentity(storage.program.layout);
    const expected_leaf_count = std.math.mul(
        usize,
        storage.commitment.rows.len,
        4,
    ) catch return error.InvalidPreparedProgramCommitmentContentV1;
    if (storage.program.layout.program_base >= storage.program.layout.program_end or
        storage.program.minimal_words.len != storage.program.statement_words.len or
        storage.program.program.words.ptr != storage.program.minimal_words.ptr or
        storage.program.program.words.len != storage.program.minimal_words.len or
        !std.mem.eql(
            u8,
            &storage.program.program.identity,
            &inventory.program_source_identity_sha256,
        ) or !std.mem.eql(
        u8,
        &actual_layout_identity,
        &inventory.layout_identity_sha256,
    ) or storage.program.layout.program_base != inventory.program_base or
        storage.program.layout.program_end != inventory.program_end or
        @as(u64, @intCast(storage.program.statement_words.len)) != inventory.declared_row_count or
        @as(u64, @intCast(storage.commitment.rows.len)) != inventory.committed_row_count or
        expected_leaf_count != storage.commitment.tree.leaves.len or
        @as(u64, @intCast(storage.commitment.tree.leaves.len)) != inventory.sparse_leaf_count or
        @as(u64, @intCast(storage.commitment.tree.nodes.len)) != inventory.sparse_node_count or
        storage.commitment.tree.root != inventory.sparse_tree_root or
        storage.ordered_poseidon_calls.len != storage.commitment.tree.nodes.len or
        @as(u64, @intCast(storage.ordered_poseidon_calls.len)) != inventory.ordered_poseidon_call_count or
        @as(u64, @intCast(storage.multiplicity_index.len)) != inventory.multiplicity_index_slot_count)
    {
        return error.InvalidPreparedProgramCommitmentContentV1;
    }
}

fn validateCanonicalContent(storage: *const StorageV1) !void {
    for (
        storage.program.minimal_words,
        storage.program.statement_words,
    ) |minimal, declared| {
        if (minimal.address != declared.addr or
            minimal.word != declared.initial_word or
            declared.initial_word != declared.final_word or
            declared.final_clock != 0 or
            !std.meta.eql(declared.role, memory_state.WordRole{}) or
            !storage.program.layout.isProgramAddr(declared.addr))
        {
            return error.InvalidPreparedProgramCommitmentContentV1;
        }
    }
    for (storage.commitment.rows) |row| {
        if (row.multiplicity != 0 or row.root != storage.commitment.tree.root)
            return error.InvalidPreparedProgramCommitmentContentV1;
    }
    for (
        storage.commitment.tree.nodes,
        storage.ordered_poseidon_calls,
    ) |node, call| {
        const expected = merkle_node.NodeRow.fromNode(
            node,
            storage.commitment.tree.root,
        ).poseidonCall();
        if (!std.meta.eql(call, expected) or call.wide or call.io or
            call.narrow_output == null)
        {
            return error.InvalidPreparedProgramCommitmentContentV1;
        }
    }
    try validateMultiplicityIndex(storage);
}

fn buildMultiplicityIndex(
    allocator: std.mem.Allocator,
    program: *const replay_producer.ProgramV4,
    commitment: *const program_commitment.Commitment,
) ![]MultiplicityIndexSlotV1 {
    if (program.layout.program_base >= program.layout.program_end or
        program.statement_words.len == 0 or
        program.statement_words.len != program.minimal_words.len)
    {
        return error.InvalidPreparedProgramMultiplicityIndexV1;
    }
    const slots = try allocator.alloc(
        MultiplicityIndexSlotV1,
        program.statement_words.len,
    );
    errdefer allocator.free(slots);
    for (
        program.statement_words,
        program.minimal_words,
        slots,
        0..,
    ) |declared, minimal, *slot, declared_index| {
        if (declared.addr != minimal.address or
            declared.addr < program.layout.program_base or
            declared.addr >= program.layout.program_end or
            (declared.addr & 3) != 0 or
            (declared_index != 0 and
                program.statement_words[declared_index - 1].addr >= declared.addr))
        {
            return error.InvalidPreparedProgramMultiplicityIndexV1;
        }
        slot.* = .{
            .declared_index = std.math.cast(u32, declared_index) orelse
                return error.InvalidPreparedProgramMultiplicityIndexV1,
        };
    }
    for (commitment.rows, 0..) |row, committed_index| {
        const declared_index = findDeclaredIndex(
            program.statement_words,
            row.addr,
        ) orelse
            return error.InvalidPreparedProgramMultiplicityIndexV1;
        if (slots[declared_index].committed_index != MISSING_INDEX) {
            return error.InvalidPreparedProgramMultiplicityIndexV1;
        }
        const declared = program.statement_words[declared_index];
        if (declared.initial_word == 0 or row.multiplicity != 0 or
            row.root != commitment.tree.root or
            !std.meta.eql(
                row.values,
                try program_decode.decodeDeclaredProgramWordForProfile(
                    .rv32im_zkvm_ethereum_v1,
                    declared.initial_word,
                ),
            ))
        {
            return error.InvalidPreparedProgramMultiplicityIndexV1;
        }
        slots[declared_index].committed_index = std.math.cast(
            u32,
            committed_index,
        ) orelse return error.InvalidPreparedProgramMultiplicityIndexV1;
    }
    return slots;
}

fn validateMultiplicityIndex(storage: *const StorageV1) !void {
    if (storage.multiplicity_index.len !=
        storage.program.statement_words.len or
        storage.program.statement_words.len != storage.program.minimal_words.len)
    {
        return error.InvalidPreparedProgramMultiplicityIndexV1;
    }
    var committed_count: usize = 0;
    for (storage.multiplicity_index, 0..) |slot, slot_index| {
        const declared_index: usize = @intCast(slot.declared_index);
        if (declared_index != slot_index) {
            return error.InvalidPreparedProgramMultiplicityIndexV1;
        }
        const declared = storage.program.statement_words[declared_index];
        if (declared.addr != storage.program.minimal_words[declared_index].address or
            declared.addr < storage.program.layout.program_base or
            declared.addr >= storage.program.layout.program_end or
            (declared.addr & 3) != 0 or
            (declared_index != 0 and
                storage.program.statement_words[declared_index - 1].addr >=
                    declared.addr))
        {
            return error.InvalidPreparedProgramMultiplicityIndexV1;
        }
        if (slot.committed_index == MISSING_INDEX) {
            if (declared.initial_word != 0)
                return error.InvalidPreparedProgramMultiplicityIndexV1;
            continue;
        }
        const committed_index: usize = @intCast(slot.committed_index);
        if (committed_index >= storage.commitment.rows.len or
            storage.commitment.rows[committed_index].addr != declared.addr or
            declared.initial_word == 0 or
            !std.meta.eql(
                storage.commitment.rows[committed_index].values,
                try program_decode.decodeDeclaredProgramWordForProfile(
                    .rv32im_zkvm_ethereum_v1,
                    declared.initial_word,
                ),
            ))
        {
            return error.InvalidPreparedProgramMultiplicityIndexV1;
        }
        committed_count += 1;
    }
    if (committed_count != storage.commitment.rows.len) {
        return error.InvalidPreparedProgramMultiplicityIndexV1;
    }
    const actual_identity = multiplicityIndexIdentity(
        storage.multiplicity_index,
    );
    if (!std.mem.eql(
        u8,
        &actual_identity,
        &storage.inventory.multiplicity_index_identity_sha256,
    )) return error.InvalidPreparedProgramMultiplicityIndexV1;
}

fn registerLeafFetch(
    storage: *const StorageV1,
    multiplicities: []u32,
    fetch: program_table.Fetch,
) !void {
    const declared_index = findDeclaredIndex(
        storage.program.statement_words,
        fetch.pc,
    ) orelse return error.FetchedProgramWordMissing;
    if (declared_index >= storage.multiplicity_index.len)
        return error.FetchedProgramWordMissing;
    const slot = storage.multiplicity_index[declared_index];
    if (@as(usize, @intCast(slot.declared_index)) != declared_index)
        return error.FetchedProgramWordMissing;
    const declared = storage.program.statement_words[declared_index];
    if (declared.initial_word != fetch.word) return error.ProgramWordChanged;
    if (program_decode.isDeclaredPaddingForProfile(
        .rv32im_zkvm_ethereum_v1,
        fetch.word,
    )) return error.FetchedDeclaredPadding;
    const decoded = try program_decode.decodeProgramWordForProfile(
        .rv32im_zkvm_ethereum_v1,
        fetch.word,
    );
    if (slot.committed_index == MISSING_INDEX)
        return error.FetchedProgramWordMissing;
    const committed_index: usize = @intCast(slot.committed_index);
    if (committed_index >= multiplicities.len or
        !std.meta.eql(
            decoded,
            storage.commitment.rows[committed_index].values,
        ))
    {
        return error.InvalidPreparedProgramLeafRowsV1;
    }
    if (multiplicities[committed_index] == std.math.maxInt(u32))
        return error.MultiplicityOverflow;
    multiplicities[committed_index] += 1;
}

fn findDeclaredIndex(
    rows: []const memory_state.WordState,
    address: u32,
) ?usize {
    var low: usize = 0;
    var high = rows.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        const candidate = rows[mid].addr;
        if (candidate < address) {
            low = mid + 1;
        } else if (candidate > address) {
            high = mid;
        } else {
            return mid;
        }
    }
    return null;
}

fn inventoryFromContent(
    source_bytes: []const u8,
    program: *const replay_producer.ProgramV4,
    commitment: *const program_commitment.Commitment,
    ordered_calls: []const poseidon2_air.Call,
    multiplicity_index: []const MultiplicityIndexSlotV1,
) !InventoryV1 {
    var inventory = InventoryV1{
        .source_byte_count = @intCast(source_bytes.len),
        .source_bytes_sha256 = hashBytes(source_bytes),
        .program_source_identity_sha256 = program.program.identity,
        .layout_identity_sha256 = layoutIdentity(program.layout),
        .program_base = program.layout.program_base,
        .program_end = program.layout.program_end,
        .declared_row_count = @intCast(program.statement_words.len),
        .declared_rows_identity_sha256 = declaredRowsIdentity(
            program.statement_words,
        ),
        .committed_row_count = @intCast(commitment.rows.len),
        .committed_rows_identity_sha256 = committedRowsIdentity(
            commitment.rows,
        ),
        .sparse_leaf_count = @intCast(commitment.tree.leaves.len),
        .sparse_node_count = @intCast(commitment.tree.nodes.len),
        .sparse_tree_root = commitment.tree.root,
        .sparse_tree_identity_sha256 = sparseTreeIdentity(&commitment.tree),
        .ordered_poseidon_call_count = @intCast(ordered_calls.len),
        .ordered_poseidon_calls_identity_sha256 = orderedCallsIdentity(
            ordered_calls,
        ),
        .multiplicity_index_slot_count = @intCast(multiplicity_index.len),
        .multiplicity_index_identity_sha256 = multiplicityIndexIdentity(
            multiplicity_index,
        ),
        .identity_sha256 = undefined,
    };
    inventory.identity_sha256 = inventoryIdentity(inventory);
    try inventory.validate();
    return inventory;
}

fn hashBytes(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn layoutIdentity(layout: memory_state.MemoryLayout) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/ethereum-prepared-program-layout/v1\x00");
    inline for (std.meta.fields(memory_state.MemoryLayout)) |field| {
        hashInt(&hash, u32, @field(layout, field.name));
    }
    return hash.finalResult();
}

fn declaredRowsIdentity(rows: []const memory_state.WordState) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/ethereum-prepared-program-declared-rows/v1\x00");
    hashInt(&hash, u64, @intCast(rows.len));
    for (rows) |row| {
        hashInt(&hash, u32, row.addr);
        hashInt(&hash, u32, row.initial_word);
        hashInt(&hash, u32, row.final_word);
        hashInt(&hash, u32, row.final_clock);
        hashInt(&hash, u8, @intFromBool(row.role.is_public_input));
        hashInt(&hash, u8, @intFromBool(row.role.is_public_output));
        hashInt(&hash, u8, @intFromBool(row.role.is_public_completion));
    }
    return hash.finalResult();
}

fn committedRowsIdentity(rows: []const program_commitment.Row) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/ethereum-prepared-program-committed-rows/v1\x00");
    hashInt(&hash, u64, @intCast(rows.len));
    for (rows) |row| {
        hashInt(&hash, u32, row.addr);
        for (row.values) |value| hashInt(&hash, u32, value);
        hashInt(&hash, u32, row.multiplicity);
        hashInt(&hash, u32, row.root);
    }
    return hash.finalResult();
}

fn sparseTreeIdentity(tree: *const sparse_merkle.Tree) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/ethereum-prepared-program-sparse-tree/v1\x00");
    hashInt(&hash, u32, tree.root);
    hashInt(&hash, u64, @intCast(tree.leaves.len));
    for (tree.leaves) |leaf| {
        hashInt(&hash, u32, leaf.index);
        hashInt(&hash, u32, leaf.value);
    }
    hashInt(&hash, u64, @intCast(tree.nodes.len));
    for (tree.nodes) |node| {
        hashInt(&hash, u32, node.index);
        hashInt(&hash, u32, node.depth);
        hashNodeValue(&hash, node.left);
        hashNodeValue(&hash, node.right);
        hashNodeValue(&hash, node.current);
    }
    return hash.finalResult();
}

fn hashNodeValue(hash: *Sha256, value: sparse_merkle.NodeValue) void {
    hashInt(hash, u32, value.value);
    hashInt(hash, u8, @intCast(value.multiplicity));
}

fn orderedCallsIdentity(calls: []const poseidon2_air.Call) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/ethereum-prepared-program-poseidon-calls/v1\x00");
    hashInt(&hash, u64, @intCast(calls.len));
    for (calls, 0..) |call, index| {
        hashInt(&hash, u64, @intCast(index));
        for (call.input) |value| hashInt(&hash, u32, value);
        hashInt(&hash, u8, @intFromBool(call.wide));
        hashInt(&hash, u8, @intFromBool(call.io));
        hashInt(&hash, u8, @intFromBool(call.narrow_output != null));
        hashInt(&hash, u32, call.narrow_output orelse 0);
    }
    return hash.finalResult();
}

fn multiplicityIndexIdentity(
    slots: []const MultiplicityIndexSlotV1,
) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/ethereum-prepared-program-multiplicity-index/v1\x00");
    hashInt(&hash, u64, @intCast(slots.len));
    for (slots, 0..) |slot, index| {
        hashInt(&hash, u64, @intCast(index));
        hashInt(&hash, u32, slot.declared_index);
        hashInt(&hash, u32, slot.committed_index);
    }
    return hash.finalResult();
}

fn inventoryIdentity(value: InventoryV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/ethereum-prepared-program-commitment-inventory/v1\x00");
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u64, value.source_byte_count);
    hash.update(&value.source_bytes_sha256);
    hash.update(&value.program_source_identity_sha256);
    hash.update(&value.layout_identity_sha256);
    hashInt(&hash, u32, value.program_base);
    hashInt(&hash, u32, value.program_end);
    hashInt(&hash, u64, value.declared_row_count);
    hash.update(&value.declared_rows_identity_sha256);
    hashInt(&hash, u64, value.committed_row_count);
    hash.update(&value.committed_rows_identity_sha256);
    hashInt(&hash, u64, value.sparse_leaf_count);
    hashInt(&hash, u64, value.sparse_node_count);
    hashInt(&hash, u32, value.sparse_tree_root);
    hash.update(&value.sparse_tree_identity_sha256);
    hashInt(&hash, u64, value.ordered_poseidon_call_count);
    hash.update(&value.ordered_poseidon_calls_identity_sha256);
    hashInt(&hash, u64, value.multiplicity_index_slot_count);
    hash.update(&value.multiplicity_index_identity_sha256);
    return hash.finalResult();
}

fn tokenIdentity(value: TokenV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update("stwo-zig/ethereum-prepared-program-process-token/v1\x00");
    hashInt(&hash, u16, value.schema_version);
    inline for (.{
        value.owner_ptr,
        value.storage_ptr,
        value.source_ptr,
        value.source_len,
        value.minimal_rows_ptr,
        value.minimal_rows_len,
        value.declared_rows_ptr,
        value.declared_rows_len,
        value.committed_rows_ptr,
        value.committed_rows_len,
        value.sparse_leaves_ptr,
        value.sparse_leaves_len,
        value.sparse_nodes_ptr,
        value.sparse_nodes_len,
        value.ordered_calls_ptr,
        value.ordered_calls_len,
        value.multiplicity_index_ptr,
        value.multiplicity_index_len,
    }) |item| hashInt(&hash, usize, item);
    hash.update(&value.inventory_identity_sha256);
    return hash.finalResult();
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn allZero(value: *const [32]u8) bool {
    return std.mem.allEqual(u8, value, 0);
}

comptime {
    if (SCHEMA_VERSION != 1 or !PROCESS_LOCAL_ONLY or SERIALIZABLE or
        PROOF_AUTHORITY or TRANSCRIPT_REUSE_ALLOWED or
        !PREPARED_WITNESS_INTEGRATED or
        @hasDecl(PreparedProgramCommitmentV1, "encode") or
        @hasDecl(PreparedProgramCommitmentV1, "decode") or
        @hasDecl(TokenV1, "encode") or
        @hasDecl(TokenV1, "decode"))
    {
        @compileError("prepared program commitment contract drifted");
    }
}

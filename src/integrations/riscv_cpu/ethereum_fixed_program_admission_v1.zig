//! Independent whole-ELF authority for the opt-in fixed-program Ethereum AIR.
//! Only this owner exposes the fixed decoded rows to Tree0 preparation. A
//! descriptor copied into a proof cannot reconstruct or admit this authority.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const prepared = @import("ethereum_incremental_prepared_program_commitment_v1.zig");
const program = frontend.air.program;
const witness = frontend.testing.commitment_witness;
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const completion = @import("ethereum_fixed_program_completion_v1.zig");

pub const DescriptorV1 = program.fixed_table_v1.DescriptorV1;

pub const OwnedV1 = opaque {
    const Storage = struct {
        allocator: std.mem.Allocator,
        program: *prepared.PreparedProgramCommitmentV1,
        descriptor: DescriptorV1,
        completion_tree: ?completion.Tree = null,
        halt_flag_address: u32,
    };
    pub fn createFromElf(allocator: std.mem.Allocator, elf: []const u8, expected_sha256: [32]u8) !*OwnedV1 {
        return create(allocator, elf, expected_sha256, false);
    }
    /// Explicit wrapper admission; the optional full-width completion tree is
    /// prepared from the same pinned image before the immutable owner escapes.
    pub fn createWithCompletionFromElf(allocator: std.mem.Allocator, elf: []const u8, expected_sha256: [32]u8) !*OwnedV1 {
        return create(allocator, elf, expected_sha256, true);
    }
    fn create(allocator: std.mem.Allocator, elf: []const u8, expected_sha256: [32]u8, with_completion: bool) !*OwnedV1 {
        var actual: [32]u8 = undefined;
        Sha256.hash(elf, &actual, .{});
        if (!std.meta.eql(actual, expected_sha256)) return error.EthereumFixedProgramSourceMismatch;
        const source = try prepared.PreparedProgramCommitmentV1.create(allocator, elf);
        errdefer source.deinit();
        const view = try source.borrow();
        const row_count = std.math.cast(u32, view.commitment.rows.len) orelse return error.EthereumFixedProgramTooLarge;
        var completion_tree: ?completion.Tree = if (with_completion) try completion.Tree.init(allocator, view.declared_rows) else null;
        errdefer if (completion_tree) |*tree| tree.deinit();
        if (completion_tree) |tree| {
            // The native ROM also commits LLVM's unreachable declared-only
            // padding. Completion membership includes executable rows only.
            // Compare the ordered projection exactly; never admit a padding
            // word as a fetched instruction or omit it from the ELF authority.
            const decoder = frontend.air.program.decode;
            const padding = try decoder.decodeDeclaredProgramWordForProfile(.rv32im_zkvm_ethereum_v1, decoder.llvm_unimp_padding_word);
            var executable: usize = 0;
            for (view.commitment.rows) |canonical| {
                if (canonical.values[0] == decoder.ethereum_declared_padding_program_opcode_id) {
                    if (!std.meta.eql(canonical.values, padding)) return error.InvalidCompletionProgramTable;
                    continue;
                }
                if (executable >= tree.rows.len) return error.InvalidCompletionProgramTable;
                const raw = tree.rows[executable];
                if (raw.pc != canonical.addr or !std.meta.eql(raw.decoded, canonical.values)) return error.InvalidCompletionProgramTable;
                executable += 1;
            }
            if (executable != tree.rows.len) return error.InvalidCompletionProgramTable;
        }
        const owned = try allocator.create(Storage);
        owned.* = .{ .allocator = allocator, .program = source, .completion_tree = completion_tree, .halt_flag_address = source.declaredHaltFlagAddress(), .descriptor = .{
            .elf_sha256 = actual,
            .decoded_table_sha256 = view.inventory.committed_rows_identity_sha256,
            .row_count = row_count,
            .compatibility_root = view.commitment.tree.root,
        } };
        return @ptrCast(owned);
    }
    fn storage(self: *const OwnedV1) *const Storage {
        return @ptrCast(@alignCast(self));
    }
    pub fn descriptor(self: *const OwnedV1) DescriptorV1 {
        return self.storage().descriptor;
    }
    pub fn completionRoot(self: *const OwnedV1) !completion.Digest {
        const tree = &(self.storage().completion_tree orelse return error.EthereumCompletionOpeningNotAdmitted);
        return tree.root();
    }
    pub fn hasCompletionOpening(self: *const OwnedV1) bool {
        return self.storage().completion_tree != null;
    }
    pub fn haltFlagAddress(self: *const OwnedV1) u32 {
        return self.storage().halt_flag_address;
    }
    pub fn completionDepth(self: *const OwnedV1) !u5 {
        return (self.storage().completion_tree orelse return error.EthereumCompletionOpeningNotAdmitted).depth;
    }
    pub fn completionRows(self: *const OwnedV1) ![]const completion.Row {
        return (self.storage().completion_tree orelse return error.EthereumCompletionOpeningNotAdmitted).rows;
    }
    pub fn completionOpening(self: *const OwnedV1, pc: u32) !completion.Opening {
        const tree = &(self.storage().completion_tree orelse return error.EthereumCompletionOpeningNotAdmitted);
        return tree.opening(pc);
    }
    pub fn validateDescriptor(self: *const OwnedV1, candidate: DescriptorV1) !void {
        if (!std.meta.eql(candidate, self.descriptor())) return error.EthereumFixedProgramAdmissionMismatch;
        try self.storage().program.validateBorrowed();
    }
    /// Shares the existing canonical prepared-snapshot check without exposing
    /// the legacy commitment's shallow-const mutable slices.
    pub fn validateSource(self: *const OwnedV1, source_identity: [32]u8, snapshot: *const frontend.runner.memory_state.Snapshot) !void {
        const view = try self.storage().program.borrow();
        if (!std.meta.eql(source_identity, view.inventory.program_source_identity_sha256)) return error.EthereumFixedProgramSourceMismatch;
        try witness.validatePreparedProgramSnapshot(snapshot, view);
    }
    pub fn rows(self: *const OwnedV1) ![]const program.commitment.Row {
        return (try self.storage().program.borrow()).commitment.rows;
    }
    pub fn fixedColumns(self: *const OwnedV1, allocator: std.mem.Allocator, log_size: u32) !program.fixed_table_v1.ColumnsV1 {
        try self.validateDescriptor(self.descriptor());
        const view = try self.storage().program.borrow();
        return program.fixed_table_v1.ColumnsV1.init(allocator, view.commitment.rows, log_size);
    }
    /// Dynamic fetch multiplicities are derived anew. Program nodes and hash
    /// calls are omitted only by the selected fixed-table witness builder.
    pub fn buildWitness(
        self: *const OwnedV1,
        allocator: std.mem.Allocator,
        execution_sources: anytype,
        snapshot: *const frontend.runner.memory_state.Snapshot,
        completion_value: frontend.air.public_data.Completion,
        boundary_rows: []const frontend.air.memory_commitment.boundary.Row,
        merkle_rows: []const frontend.air.memory_commitment.merkle_node.NodeRow,
        poseidon_calls: []const frontend.air.memory_commitment.poseidon2_air.Call,
        roots: witness.IncrementalRootsV3,
    ) !witness.CommitmentWitness {
        try self.validateDescriptor(self.descriptor());
        return witness.CommitmentWitness.buildExternalProfileWithFixedProgramAndIncrementalBoundaryV1(allocator, .rv32im_zkvm_ethereum_v1, execution_sources, snapshot, completion_value, try self.storage().program.borrow(), boundary_rows, merkle_rows, poseidon_calls, roots);
    }
    pub fn deinit(self: *OwnedV1) void {
        const owned: *Storage = @ptrCast(@alignCast(self));
        const allocator = owned.allocator;
        if (owned.completion_tree) |*tree| tree.deinit();
        owned.program.deinit();
        allocator.destroy(owned);
    }
};

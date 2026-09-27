//! Verifier-pinned commitment schedules. This is component admission, not a PCS
//! verification key: the complete proof key must additionally bind geometry,
//! preprocessing commitments and security parameters.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
const memory = @import("../recursion/air/blake3_memory_word.zig");
const program = @import("../recursion/air/blake3_program_word.zig");
const public = @import("../air/public_data.zig");
const Hash = core.vcs.blake3_hash.Blake3Hasher;
pub const VERSION: u32 = 6;
pub const DOMAIN = "stwo.riscv.blake3.commitment-plan.v6.paired-constant-memory";
pub const SPARSE_VERSION: u32 = 7;
pub const SPARSE_DOMAIN = "stwo.riscv.blake3.commitment-plan.v7.sparse-program-provider";
pub const ProgramSchedule = enum { full, sparse_active };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    roots: [3]tree.Digest,
    memories: []memory.Statement,
    programs: []program.Statement,
    /// Complete decoded ROM, authenticated against roots[0] before preprocessing.
    program_leaves: []tree.Leaf,
    program_schedule: ProgramSchedule = .full,
    pub fn init(a: std.mem.Allocator, roots: [3]tree.Digest, memories: []const memory.Statement, programs: []const program.Statement, program_leaves: []const tree.Leaf) !Plan {
        return initWithSchedule(a, roots, memories, programs, program_leaves, .full);
    }
    pub fn initSparse(a: std.mem.Allocator, roots: [3]tree.Digest, memories: []const memory.Statement, programs: []const program.Statement, program_leaves: []const tree.Leaf) !Plan {
        return initWithSchedule(a, roots, memories, programs, program_leaves, .sparse_active);
    }
    fn initWithSchedule(a: std.mem.Allocator, roots: [3]tree.Digest, memories: []const memory.Statement, programs: []const program.Statement, program_leaves: []const tree.Leaf, schedule: ProgramSchedule) !Plan {
        const owned_memories = try a.dupe(memory.Statement, memories);
        errdefer a.free(owned_memories);
        const owned_programs = try a.dupe(program.Statement, programs);
        errdefer a.free(owned_programs);
        const owned_leaves = try a.dupe(tree.Leaf, program_leaves);
        errdefer a.free(owned_leaves);
        const result = Plan{ .allocator = a, .roots = roots, .memories = owned_memories, .programs = owned_programs, .program_leaves = owned_leaves, .program_schedule = schedule };
        try result.validate();
        return result;
    }
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.memories);
        self.allocator.free(self.programs);
        self.allocator.free(self.program_leaves);
        self.* = undefined;
    }
    pub fn validate(self: *const Plan) !void {
        if (self.memories.len == 0 and !std.meta.eql(self.roots[1], self.roots[2])) return error.UnchangedMemoryRootMismatch;
        if (self.programs.len == 0) return error.EmptyProgramCommitment;
        if (self.program_leaves.len == 0 or self.program_leaves.len % 4 != 0) return error.InvalidProgramPreprocessing;
        if (self.program_schedule == .full and self.program_leaves.len != try std.math.mul(usize, self.programs.len, 4))
            return error.InvalidProgramPreprocessing;
        if (self.program_schedule == .sparse_active) {
            var previous: ?u32 = null;
            for (0..self.program_leaves.len / 4) |i| {
                const group = self.program_leaves[i * 4 ..][0..4];
                const address = group[0].index;
                if (address & 3 != 0 or (previous != null and address <= previous.?)) return error.InvalidProgramPreprocessing;
                for (group, 0..) |leaf, limb| {
                    if (leaf.index != try std.math.add(u32, address, @intCast(limb))) return error.InvalidProgramPreprocessing;
                }
                previous = address;
            }
        }
        // Verifier-owned authentication, not a witness assertion. Completeness
        // against the public ROM root prevents an arbitrary lookup provider.
        try @import("../air/program/blake3_root_cache.zig").validate(self.program_leaves, self.roots[0]);
        var namespace_end: u64 = 0;
        for (self.memories, 0..) |item, i| {
            try item.validate();
            if (item.direction == .initial and item.clock != 0) return error.InvalidCommitmentSchedule;
            if (item.source_circuit < namespace_end or item.path_namespace != @as(u64, item.source_circuit) + 1) return error.InvalidCommitmentSchedule;
            namespace_end = @as(u64, item.path_namespace) + (2 * tree.DEPTH + 1);
            const root = self.roots[if (item.direction == .initial) @as(usize, 1) else 2];
            if (!std.meta.eql(root, item.root)) return error.CommitmentRootMismatch;
            if (i != 0) {
                const previous = self.memories[i - 1];
                if (previous.direction == .final and item.direction == .initial) return error.InvalidCommitmentSchedule;
                if (previous.direction == item.direction and previous.address >= item.address) return error.InvalidCommitmentSchedule;
            }
        }
        for (self.programs, 0..) |item, i| {
            try item.validate();
            if (self.program_schedule == .sparse_active and item.multiplicity == 0) return error.InactiveSparseProgramRow;
            for (self.program_leaves[try self.programLeafOffset(i) ..][0..4], 0..) |leaf, limb| {
                if (leaf.index != item.address + @as(u32, @intCast(limb))) return error.InvalidProgramPreprocessing;
            }
            if (item.namespace < namespace_end) return error.InvalidCommitmentSchedule;
            namespace_end = @as(u64, item.namespace) + program.CIRCUIT_COUNT;
            if (!std.meta.eql(self.roots[0], item.root)) return error.CommitmentRootMismatch;
            if (i != 0 and self.programs[i - 1].address >= item.address) return error.InvalidCommitmentSchedule;
        }
    }
    /// The full decoded image is root-authenticated; sparse provider rows
    /// select values by address from that image, never from prover main data.
    pub fn programLeafOffset(self: *const Plan, program_index: usize) !usize {
        if (program_index >= self.programs.len) return error.InvalidProgramPreprocessing;
        if (self.program_schedule == .full) return program_index * 4;
        const address = self.programs[program_index].address;
        var low: usize = 0;
        var high: usize = self.program_leaves.len / 4;
        while (low < high) {
            const mid = low + (high - low) / 2;
            const candidate = self.program_leaves[mid * 4].index;
            if (candidate < address) low = mid + 1 else high = mid;
        }
        if (low >= self.program_leaves.len / 4 or self.program_leaves[low * 4].index != address)
            return error.MissingSparseProgramWord;
        return low * 4;
    }
    pub fn identity(self: *const Plan) ![32]u8 {
        try self.validate();
        var hash = Hash.init();
        hash.update(if (self.program_schedule == .full) DOMAIN else SPARSE_DOMAIN);
        word(&hash, if (self.program_schedule == .full) VERSION else SPARSE_VERSION);
        word(&hash, public.Blake3PublicData.transcript_version);
        word(&hash, tree.DEPTH);
        hash.update(tree.DOMAIN);
        for (self.roots) |root| hash.update(&root.bytes);
        inline for (@import("blake3_commitment_components.zig").Airs) |Air| {
            hash.update(&Air.SEMANTIC_DIGEST);
            word(&hash, Air.PHYSICAL_MAIN_COLUMN_COUNT);
            word(&hash, Air.PREPROCESSED_COLUMN_COUNT);
            word(&hash, Air.INTERACTION_COLUMN_COUNT);
        }
        word(&hash, std.math.cast(u32, self.memories.len) orelse return error.InvalidCommitmentSchedule);
        for (self.memories) |item| {
            word(&hash, item.address);
            word(&hash, item.clock);
            word(&hash, if (item.direction == .initial) 0 else 1);
            word(&hash, item.source_circuit);
            word(&hash, item.path_namespace);
        }
        word(&hash, std.math.cast(u32, self.programs.len) orelse return error.InvalidCommitmentSchedule);
        for (self.programs) |item| {
            word(&hash, item.namespace);
            word(&hash, item.address);
            word(&hash, item.multiplicity);
        }
        for (self.program_leaves) |leaf| {
            word(&hash, leaf.index);
            word(&hash, leaf.value);
        }
        return hash.finalize();
    }
};
pub const Admission = struct {
    plan: *const Plan,
    expected_id: [32]u8,
    pub fn init(plan: *const Plan, expected_id: [32]u8) !Admission {
        const result = Admission{ .plan = plan, .expected_id = expected_id };
        try result.validate();
        return result;
    }
    pub fn validate(self: Admission) !void {
        if (!std.mem.eql(u8, &try self.plan.identity(), &self.expected_id)) return error.UntrustedCommitmentPlan;
    }
    pub fn validatePublic(self: Admission, data: *const public.Blake3PublicData) !void {
        try self.validate();
        try data.validate();
        const roots = [_]?tree.Digest{ data.program_root, data.initial_rw_root, data.final_rw_root };
        for (roots, self.plan.roots) |claim, root| {
            if (claim == null or !std.meta.eql(claim.?, root)) return error.CommitmentRootMismatch;
        }
        // Public input owns its initial value. A scheduled exit establishes
        // that the word participated in the access chain; untouched inputs
        // are omitted and restored by the admitted public-custody conversion.
        const io = data.io_entries;
        for (self.plan.memories) |item| {
            if (item.address < io.input_start) continue;
            const offset = item.address - io.input_start;
            if (offset & 3 != 0 or offset / 4 >= io.input_words.len) continue;
            if (item.direction == .initial or item.clock == 0) return error.ConflictingPublicMemoryCustody;
        }
    }
};
fn word(hash: *Hash, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}

test "block-v3 sparse program plan authenticates full image and selected address" {
    const a = std.testing.allocator;
    const leaves = [_]tree.Leaf{
        .{ .index = 0, .value = 11 }, .{ .index = 1, .value = 12 },
        .{ .index = 2, .value = 13 }, .{ .index = 3, .value = 14 },
        .{ .index = 4, .value = 21 }, .{ .index = 5, .value = 22 },
        .{ .index = 6, .value = 23 }, .{ .index = 7, .value = 24 },
    };
    const root = try tree.TreeHasher.init(.program).root(&leaves);
    const program_rows = [_]program.Statement{.{ .namespace = 100, .address = 4, .multiplicity = 2, .root = root }};
    const roots = [3]tree.Digest{ root, root, root };
    var sparse = try Plan.initSparse(a, roots, &.{}, &program_rows, &leaves);
    defer sparse.deinit();
    try std.testing.expectEqual(@as(usize, 4), try sparse.programLeafOffset(0));
    try std.testing.expectEqualSlices(tree.Leaf, leaves[4..8], sparse.program_leaves[try sparse.programLeafOffset(0) ..][0..4]);
    const sparse_id = try sparse.identity();
    const full_rows = [_]program.Statement{
        .{ .namespace = 100, .address = 0, .multiplicity = 0, .root = root },
        .{ .namespace = 100 + program.CIRCUIT_COUNT, .address = 4, .multiplicity = 2, .root = root },
    };
    var full = try Plan.init(a, roots, &.{}, &full_rows, &leaves);
    defer full.deinit();
    try std.testing.expect(!std.meta.eql(sparse_id, try full.identity()));
    sparse.programs[0].address = 8;
    try std.testing.expectError(error.MissingSparseProgramWord, sparse.validate());
    sparse.programs[0].address = 4;
    sparse.programs[0].multiplicity = 0;
    try std.testing.expectError(error.InactiveSparseProgramRow, sparse.validate());
    sparse.programs[0].multiplicity = 2;
    sparse.program_leaves[4].value ^= 1;
    try std.testing.expectError(error.ProgramRootMismatch, sparse.validate());
    sparse.program_leaves[4].value ^= 1;
    sparse.program_leaves[4].index = 0;
    try std.testing.expectError(error.InvalidProgramPreprocessing, sparse.validate());
}

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
pub const VERSION: u32 = 4;
pub const DOMAIN = "stwo.riscv.blake3.commitment-plan.v4.word-memory";
pub const Plan = struct {
    allocator: std.mem.Allocator,
    roots: [3]tree.Digest,
    memories: []memory.Statement,
    programs: []program.Statement,
    /// Complete decoded ROM, authenticated against roots[0] before preprocessing.
    program_leaves: []tree.Leaf,
    pub fn init(a: std.mem.Allocator, roots: [3]tree.Digest, memories: []const memory.Statement, programs: []const program.Statement, program_leaves: []const tree.Leaf) !Plan {
        const owned_memories = try a.dupe(memory.Statement, memories);
        errdefer a.free(owned_memories);
        const owned_programs = try a.dupe(program.Statement, programs);
        errdefer a.free(owned_programs);
        const owned_leaves = try a.dupe(tree.Leaf, program_leaves);
        errdefer a.free(owned_leaves);
        const result = Plan{ .allocator = a, .roots = roots, .memories = owned_memories, .programs = owned_programs, .program_leaves = owned_leaves };
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
        if (self.programs.len == 0) return error.EmptyProgramCommitment;
        if (self.program_leaves.len != try std.math.mul(usize, self.programs.len, 4)) return error.InvalidProgramPreprocessing;
        // Verifier-owned authentication, not a witness assertion. Completeness
        // against the public ROM root prevents an arbitrary lookup provider.
        const hasher = tree.TreeHasher.init(.program);
        if (!std.meta.eql(try hasher.root(self.program_leaves), self.roots[0])) return error.ProgramRootMismatch;
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
            for (self.program_leaves[i * 4 ..][0..4], 0..) |leaf, limb| {
                if (leaf.index != item.address + @as(u32, @intCast(limb))) return error.InvalidProgramPreprocessing;
            }
            if (item.namespace < namespace_end) return error.InvalidCommitmentSchedule;
            namespace_end = @as(u64, item.namespace) + program.CIRCUIT_COUNT;
            if (!std.meta.eql(self.roots[0], item.root)) return error.CommitmentRootMismatch;
            if (i != 0 and self.programs[i - 1].address >= item.address) return error.InvalidCommitmentSchedule;
        }
    }
    pub fn identity(self: *const Plan) ![32]u8 {
        try self.validate();
        var hash = Hash.init();
        hash.update(DOMAIN);
        word(&hash, VERSION);
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
    }
};
fn word(hash: *Hash, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}

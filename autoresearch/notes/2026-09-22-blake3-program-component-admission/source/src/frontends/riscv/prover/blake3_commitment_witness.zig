//! Owned ordinary BLAKE3 commitment preparation. The public contract and all
//! boundary word schedules are derived together; no scalar-root conversion.
//! Component/key admission must authenticate the returned schedules before use.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31;
const public = @import("../air/public_data.zig");
const program = @import("../air/program/blake3_commitment.zig");
const state = @import("../runner/memory_state.zig");
const source = @import("../recursion/air/blake3_memory_snapshot.zig");
const word = @import("../recursion/air/blake3_memory_word.zig");
const program_word = @import("../recursion/air/blake3_program_word.zig");
const table = @import("../air/program/table.zig");
pub const Witness = struct {
    allocator: std.mem.Allocator,
    program: program.Commitment,
    initial: source.Source,
    final: source.Source,
    boundaries: []word.Statement,
    programs: []program_word.Statement,
    pub fn deinit(self: *Witness) void {
        self.allocator.free(self.programs);
        self.allocator.free(self.boundaries);
        self.final.deinit();
        self.initial.deinit();
        self.program.deinit();
        self.* = undefined;
    }
    /// Fail before mutating the caller's statement if a supplied root disagrees.
    pub fn bindPublic(self: *const Witness, data: *public.Blake3PublicData) !void {
        var bound = data.*;
        inline for (.{ "program_root", "initial_rw_root", "final_rw_root" }, .{ self.program.root, self.initial.root, self.final.root }) |name, root| {
            if (@field(bound, name)) |claimed| {
                if (!std.meta.eql(claimed, root)) return error.CommitmentRootMismatch;
            }
            @field(bound, name) = root;
        }
        try bound.validate();
        data.* = bound;
    }
    pub fn plan(self: *const Witness, a: std.mem.Allocator) !@import("blake3_commitment_plan.zig").Plan {
        return @import("blake3_commitment_plan.zig").Plan.init(a, .{ self.program.root, self.initial.root, self.final.root }, self.boundaries, self.programs);
    }
    pub fn prepareProgram(self: *const Witness, a: std.mem.Allocator, index: usize) !program_word.Prepared {
        if (index >= self.programs.len) return error.InvalidProgramBoundaryIndex;
        return program_word.prepare(a, self.programs[index], self.program.leaves);
    }
    /// Materialize only the scheduled word needed by the current work item.
    pub fn prepareBoundary(self: *const Witness, a: std.mem.Allocator, index: usize) !word.Prepared {
        if (index >= self.boundaries.len) return error.InvalidMemoryBoundaryIndex;
        const statement = self.boundaries[index];
        const snapshot = if (statement.direction == .initial) &self.initial else &self.final;
        return word.prepare(a, statement, snapshot.leaves);
    }
};
pub fn build(
    a: std.mem.Allocator,
    decoder: anytype,
    execution_sources: anytype,
    snapshot: *const state.Snapshot,
    extra_fetch: ?table.Fetch,
    namespace: u32,
) !Witness {
    var rom = try program.buildDeclared(a, decoder, execution_sources, snapshot.program_words, extra_fetch);
    errdefer rom.deinit();
    var initial = try source.fromSnapshot(a, snapshot, .entry, .ordinary_boundary);
    errdefer initial.deinit();
    var final = try source.fromSnapshot(a, snapshot, .exit, .ordinary_boundary);
    errdefer final.deinit();
    var count: usize = 0;
    for (snapshot.words) |entry| {
        count = try std.math.add(usize, count, @as(usize, @intFromBool(entry.includeInitial())) + @intFromBool(entry.includeFinal()));
    }
    // One byte-source circuit and four 61-circuit paths per boundary word.
    const stride = 1 + 4 * (2 * @import("../air/memory_commitment/blake3_byte_tree.zig").DEPTH + 1);
    const end = try std.math.add(u64, namespace, try std.math.mul(u64, count, stride));
    const total_end = try std.math.add(u64, end, try std.math.mul(u64, rom.rows.len, program_word.CIRCUIT_COUNT));
    if (namespace >= M31.Modulus or total_end > M31.Modulus) return error.InvalidMemoryBoundaryNamespace;
    const boundaries = try a.alloc(word.Statement, count);
    errdefer a.free(boundaries);
    var at: usize = 0;
    for ([_]*const source.Source{ &initial, &final }) |projection| {
        for (projection.words) |entry| {
            const include = if (projection.side == .entry) entry.includeInitial() else entry.includeFinal();
            if (!include) continue;
            const base = namespace + @as(u32, @intCast(at * stride));
            boundaries[at] = try projection.statement(entry.addr, base, base + 1);
            at += 1;
        }
    }
    std.debug.assert(at == count);
    const programs = try a.alloc(program_word.Statement, rom.rows.len);
    errdefer a.free(programs);
    for (programs, rom.rows, 0..) |*statement, entry, i| {
        statement.* = .{ .namespace = @intCast(end + i * program_word.CIRCUIT_COUNT), .address = entry.addr, .multiplicity = entry.multiplicity, .root = rom.root };
        try statement.validate();
    }
    return .{ .allocator = a, .program = rom, .initial = initial, .final = final, .boundaries = boundaries, .programs = programs };
}

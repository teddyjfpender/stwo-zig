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
const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
pub const Witness = struct {
    allocator: std.mem.Allocator,
    program: program.Commitment,
    initial: source.Source,
    final: source.Source,
    boundaries: []word.Statement,
    programs: []program_word.Statement,
    program_schedule: @import("blake3_commitment_plan.zig").ProgramSchedule = .full,
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
        const Plan = @import("blake3_commitment_plan.zig").Plan;
        const roots = [3]tree.Digest{ self.program.root, self.initial.root, self.final.root };
        return if (self.program_schedule == .sparse_active)
            Plan.initSparse(a, roots, self.boundaries, self.programs, self.program.leaves)
        else Plan.init(a, roots, self.boundaries, self.programs, self.program.leaves);
    }
    pub fn prepareProgram(self: *const Witness, a: std.mem.Allocator, index: usize) !program_word.Prepared {
        if (self.program_schedule == .sparse_active) return error.SparseProgramUsesFixedProvider;
        if (index >= self.programs.len) return error.InvalidProgramBoundaryIndex;
        return program_word.prepare(a, self.programs[index], self.program.leaves);
    }
    /// Prepare the public-I/O root conversion for a caller-admitted span endpoint.
    pub fn prepareContinuation(self: *const Witness, a: std.mem.Allocator, side: source.Side, data: *const public.Blake3PublicData, admission: @import("blake3_commitment_plan.zig").Admission, full_root: @import("../air/memory_commitment/blake3_state_tree.zig").Digest, namespace: u32, source_circuit: u32) !@import("../recursion/air/blake3_memory_custody.zig").Prepared {
        const snapshot = if (side == .entry) &self.initial else &self.final;
        return @import("../recursion/air/blake3_memory_custody.zig").prepare(a, side, data, admission, snapshot.leaves, full_root, namespace, source_circuit);
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
    return buildWithSchedule(a, decoder, execution_sources, snapshot, extra_fetch, namespace, .full);
}
pub fn buildSparse(
    a: std.mem.Allocator,
    decoder: anytype,
    execution_sources: anytype,
    snapshot: *const state.Snapshot,
    extra_fetch: ?table.Fetch,
    namespace: u32,
) !Witness {
    return buildWithSchedule(a, decoder, execution_sources, snapshot, extra_fetch, namespace, .sparse_active);
}
fn buildWithSchedule(
    a: std.mem.Allocator,
    decoder: anytype,
    execution_sources: anytype,
    snapshot: *const state.Snapshot,
    extra_fetch: ?table.Fetch,
    namespace: u32,
    schedule: @import("blake3_commitment_plan.zig").ProgramSchedule,
) !Witness {
    var rom = try program.buildDeclared(a, decoder, execution_sources, snapshot.program_words, extra_fetch);
    errdefer rom.deinit();
    var initial = try source.fromSnapshot(a, snapshot, .entry, .ordinary_boundary);
    errdefer initial.deinit();
    var final = try source.fromSnapshot(a, snapshot, .exit, .ordinary_boundary);
    errdefer final.deinit();
    var count: usize = 0;
    for (snapshot.words) |entry| {
        if (entry.final_clock == 0) continue;
        count = try std.math.add(usize, count, @as(usize, @intFromBool(entry.includeInitial())) + @intFromBool(entry.includeFinal()));
    }
    // One word-source circuit and one 61-circuit path per boundary word.
    const stride = 1 + (2 * @import("../air/memory_commitment/blake3_state_tree.zig").DEPTH + 1);
    const end = try std.math.add(u64, namespace, try std.math.mul(u64, count, stride));
    const program_count = if (schedule == .full) rom.rows.len else blk: {
        var active: usize = 0;
        for (rom.rows) |row| active += @intFromBool(row.multiplicity != 0);
        break :blk active;
    };
    const total_end = try std.math.add(u64, end, try std.math.mul(u64, program_count, program_word.CIRCUIT_COUNT));
    if (namespace >= M31.Modulus or total_end > M31.Modulus) return error.InvalidMemoryBoundaryNamespace;
    const boundaries = try a.alloc(word.Statement, count);
    errdefer a.free(boundaries);
    var at: usize = 0;
    for ([_]*const source.Source{ &initial, &final }) |projection| {
        for (projection.words) |entry| {
            if (entry.final_clock == 0) continue;
            const include = if (projection.side == .entry) entry.includeInitial() else entry.includeFinal();
            if (!include) continue;
            const base = namespace + @as(u32, @intCast(at * stride));
            boundaries[at] = try projection.statement(entry.addr, base, base + 1);
            at += 1;
        }
    }
    std.debug.assert(at == count);
    const programs = try a.alloc(program_word.Statement, program_count);
    errdefer a.free(programs);
    var program_at: usize = 0;
    for (rom.rows) |entry| {
        if (schedule == .sparse_active and entry.multiplicity == 0) continue;
        programs[program_at] = .{ .namespace = @intCast(end + program_at * program_word.CIRCUIT_COUNT), .address = entry.addr, .multiplicity = entry.multiplicity, .root = rom.root };
        try programs[program_at].validate();
        program_at += 1;
    }
    std.debug.assert(program_at == program_count);
    return .{ .allocator = a, .program = rom, .initial = initial, .final = final, .boundaries = boundaries, .programs = programs, .program_schedule = schedule };
}

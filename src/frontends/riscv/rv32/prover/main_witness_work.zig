//! Exact, source-bound logical field work for the production Tree-1 epoch.
//!
//! The ordinary proof path never constructs this authority and receives null
//! shard pointers, so its row loops retain no profiling branch. Profiled
//! requests derive fixed schedules directly from the generic typed programs;
//! workers then publish only completed, coordinator-owned shards.

const std = @import("std");
const prover_api = @import("stwo_prover_api");
const composition_manifest = @import("../air/lang/opcode_composition_manifest.zig");
const guest_manifest = @import("../air/guest_precompile/manifest.zig");
const statement_mod = @import("../air/statement.zig");
const trace = @import("../runner/trace.zig");
const measurement = @import("main_witness_measurement.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA_VERSION: u16 = 2;
pub const DIGEST_DOMAIN = "stwo-zig/riscv/main-witness-work/v2\x00";
pub const Digest = [Sha256.digest_length]u8;

/// The guest caller's canonicality witness uses one Montgomery batch inverse
/// over all 32 input/output words. Provider Poseidon permutations deliberately
/// remain outside this site: P-003 tracks them in the separate
/// `sparse_memory_and_guest_poseidon_witness` family.
const GUEST_CALLER_TRACE_ALGORITHM_VERSION: u16 = 1;
/// Caller lookup registration executes one checked pass and one mutation pass.
const GUEST_LOOKUP_REGISTRATION_ALGORITHM_VERSION: u16 = 1;

/// A stable name for each dynamic witness schedule. The corresponding typed
/// authority digest pins the executable recipe; this tag pins its tally rule.
pub const WitnessRule = enum(u8) {
    destination_inverse = 0,
    signed_immediate_destination_inverse = 1,
    branch_eq_first_difference_inverse = 2,
    branch_lt_comparison = 3,
    lt_imm_comparison_destination_inverse = 4,
    lt_reg_comparison_destination_inverse = 5,
    division_hints = 6,
    zero = 7,
};

pub const FamilySchedule = struct {
    witness_rule: WitnessRule,
    lookup_build: prover_api.work_profile.FieldOperations,
    lookup_counter_additions: u64,
    audit_row: prover_api.work_profile.FieldOperations,
};

/// Immutable schedule authority constructed before task dispatch.
pub const Authority = struct {
    source_digest: Digest,
    families: [trace.N_FAMILIES]FamilySchedule,
    program_entry_build: prover_api.work_profile.FieldOperations,
    memory_entry_build: prover_api.work_profile.FieldOperations,
    clock_entry_build: prover_api.work_profile.FieldOperations,
    guest_caller_trace_row: prover_api.work_profile.FieldOperations,
    guest_lookup_row: prover_api.work_profile.FieldOperations,
    guest_lookup_requests_per_row: u64,
    fixed_table_cells: u64,

    pub fn init() !Authority {
        var result = Authority{
            .source_digest = undefined,
            .families = undefined,
            .program_entry_build = try measurement.measureProgramEntryBuild(),
            .memory_entry_build = try measurement.measureMemoryEntryBuild(),
            .clock_entry_build = try measurement.measureClockEntryBuild(),
            .guest_caller_trace_row = measurement.guestCallerTraceRowWork(),
            .guest_lookup_row = try measurement.guestLookupRowWork(),
            .guest_lookup_requests_per_row = try measurement.guestLookupRequestsPerRow(),
            .fixed_table_cells = try measurement.fixedTableCells(),
        };
        for (&result.families, 0..) |*schedule, index| {
            const family: trace.OpcodeFamily = @enumFromInt(index);
            const lookup = try measurement.measureOpcodeLookupBuild(family);
            schedule.* = .{
                .witness_rule = witnessRule(family),
                .lookup_build = lookup.operations,
                .lookup_counter_additions = lookup.fixed_table_entries,
                .audit_row = try measurement.measureAuditRow(family),
            };
        }
        result.source_digest = computeSourceDigest(&result);
        return result;
    }

    pub fn validate(self: *const Authority) !void {
        const expected_digest = computeSourceDigest(self);
        if (!std.mem.eql(u8, &self.source_digest, &expected_digest))
            return error.MainWitnessWorkSourceMismatch;
        const cells = try measurement.fixedTableCells();
        if (self.fixed_table_cells != cells)
            return error.MainWitnessWorkSourceMismatch;
    }
};

pub const Shard = struct {
    operations: prover_api.work_profile.FieldOperations = .{},
    opcode_rows: [trace.N_FAMILIES]u64 = .{0} ** trace.N_FAMILIES,
    audit_rows: [trace.N_FAMILIES]u64 = .{0} ** trace.N_FAMILIES,
    program_rows: u64 = 0,
    memory_rows: u64 = 0,
    merkle_rows: u64 = 0,
    clock_rows: u64 = 0,
    program_seed_rows: u64 = 0,
    memory_seed_rows: u64 = 0,
    clock_seed_domain_rows: u64 = 0,
    clock_seed_active_rows: u64 = 0,
    guest_caller_trace_rows: u64 = 0,
    guest_lookup_rows: u64 = 0,
    counter_set_merges: u64 = 0,

    pub fn observeOpcodeRow(
        self: *Shard,
        authority: *const Authority,
        family: trace.OpcodeFamily,
        row: trace.TraceRow,
    ) !void {
        const schedule = authority.families[@intFromEnum(family)];
        var next = self.*;
        try next.addOperations(schedule.lookup_build, 1);
        try next.addOperations(.{
            .additions = schedule.lookup_counter_additions,
        }, 1);
        try next.addOperations(witnessOperations(schedule.witness_rule, row), 1);
        const index = @intFromEnum(family);
        next.opcode_rows[index] = try add(next.opcode_rows[index], 1);
        self.* = next;
    }

    pub fn observeInfrastructure(
        self: *Shard,
        kind: statement_mod.InfraKind,
        rows: usize,
    ) !void {
        var next = self.*;
        const count: u64 = @intCast(rows);
        switch (kind) {
            .program => next.program_rows = try add(next.program_rows, count),
            .memory => next.memory_rows = try add(next.memory_rows, count),
            .merkle => next.merkle_rows = try add(next.merkle_rows, count),
            .clock_update => next.clock_rows = try add(next.clock_rows, count),
            else => return error.InvalidMainWitnessInfrastructureKind,
        }
        self.* = next;
    }

    pub fn observeAudit(
        self: *Shard,
        authority: *const Authority,
        family: trace.OpcodeFamily,
        domain_rows: usize,
    ) !void {
        var next = self.*;
        const rows: u64 = @intCast(domain_rows);
        try next.addOperations(
            authority.families[@intFromEnum(family)].audit_row,
            rows,
        );
        const index = @intFromEnum(family);
        next.audit_rows[index] = try add(next.audit_rows[index], rows);
        self.* = next;
    }

    pub fn observeSeed(
        self: *Shard,
        authority: *const Authority,
        program_rows: usize,
        memory_rows: usize,
        clock_domain_rows: usize,
        clock_active_rows: usize,
    ) !void {
        var next = self.*;
        const programs: u64 = @intCast(program_rows);
        const memories: u64 = @intCast(memory_rows);
        const clock_domain: u64 = @intCast(clock_domain_rows);
        const clock_active: u64 = @intCast(clock_active_rows);
        if (clock_active > clock_domain) return error.InvalidMainWitnessWorkShape;

        // Program and memory expose two active fixed-table requests per row.
        try next.addOperations(authority.program_entry_build, programs);
        try next.addOperations(.{ .additions = 2 }, programs);
        try next.addOperations(authority.memory_entry_build, memories);
        try next.addOperations(.{ .additions = 2 }, memories);
        // Clock entry construction executes on padding too; counter::register
        // skips the two zero-numerator fixed-table requests on padding.
        try next.addOperations(authority.clock_entry_build, clock_domain);
        try next.addOperations(.{ .additions = 2 }, clock_active);

        next.program_seed_rows = try add(next.program_seed_rows, programs);
        next.memory_seed_rows = try add(next.memory_seed_rows, memories);
        next.clock_seed_domain_rows = try add(
            next.clock_seed_domain_rows,
            clock_domain,
        );
        next.clock_seed_active_rows = try add(
            next.clock_seed_active_rows,
            clock_active,
        );
        self.* = next;
    }

    pub fn observeCounterSetMerges(
        self: *Shard,
        authority: *const Authority,
        merges: usize,
    ) !void {
        var next = self.*;
        const count: u64 = @intCast(merges);
        try next.addOperations(.{
            .additions = authority.fixed_table_cells,
        }, count);
        next.counter_set_merges = try add(next.counter_set_merges, count);
        self.* = next;
    }

    /// Counts only the caller projection. The provider permutation trace is
    /// owned by the separate Poseidon witness work family.
    pub fn observeGuestCallerTraceRows(
        self: *Shard,
        authority: *const Authority,
        rows: usize,
    ) !void {
        var next = self.*;
        const count: u64 = @intCast(rows);
        try next.addOperations(authority.guest_caller_trace_row, count);
        next.guest_caller_trace_rows = try add(
            next.guest_caller_trace_rows,
            count,
        );
        self.* = next;
    }

    /// Counts both transactional lookup passes and the successful dense-table
    /// mutations issued by the authenticated caller rows.
    pub fn observeGuestLookupRows(
        self: *Shard,
        authority: *const Authority,
        rows: usize,
    ) !void {
        var next = self.*;
        const count: u64 = @intCast(rows);
        try next.addOperations(authority.guest_lookup_row, count);
        next.guest_lookup_rows = try add(next.guest_lookup_rows, count);
        self.* = next;
    }

    pub fn merge(self: *Shard, other: Shard) !void {
        var next = self.*;
        next.operations = try addOperationsValue(next.operations, other.operations);
        inline for (&next.opcode_rows, other.opcode_rows) |*dst, value|
            dst.* = try add(dst.*, value);
        inline for (&next.audit_rows, other.audit_rows) |*dst, value|
            dst.* = try add(dst.*, value);
        inline for (.{
            .{ &next.program_rows, other.program_rows },
            .{ &next.memory_rows, other.memory_rows },
            .{ &next.merkle_rows, other.merkle_rows },
            .{ &next.clock_rows, other.clock_rows },
            .{ &next.program_seed_rows, other.program_seed_rows },
            .{ &next.memory_seed_rows, other.memory_seed_rows },
            .{ &next.clock_seed_domain_rows, other.clock_seed_domain_rows },
            .{ &next.clock_seed_active_rows, other.clock_seed_active_rows },
            .{ &next.guest_caller_trace_rows, other.guest_caller_trace_rows },
            .{ &next.guest_lookup_rows, other.guest_lookup_rows },
            .{ &next.counter_set_merges, other.counter_set_merges },
        }) |pair| pair[0].* = try add(pair[0].*, pair[1]);
        self.* = next;
    }

    fn addOperations(
        self: *Shard,
        operations: prover_api.work_profile.FieldOperations,
        lanes: u64,
    ) !void {
        self.operations = try addOperationsValue(self.operations, .{
            .additions = try mul(operations.additions, lanes),
            .multiplications = try mul(operations.multiplications, lanes),
            .inversions = try mul(operations.inversions, lanes),
        });
    }
};

pub const Receipt = struct {
    schema_version: u16 = SCHEMA_VERSION,
    source_digest: Digest,
    completed: Shard,

    pub fn validate(self: *const Receipt, authority: *const Authority) !void {
        if (self.schema_version != SCHEMA_VERSION or
            !std.mem.eql(u8, &self.source_digest, &authority.source_digest))
        {
            return error.MainWitnessWorkSourceMismatch;
        }
        try authority.validate();
    }

    pub fn delta(self: *const Receipt) prover_api.work_profile.Delta {
        var result = self.completed.operations.delta();
        result.site = .main_witness_field;
        return result;
    }
};

pub fn seal(authority: *const Authority, completed: Shard) !Receipt {
    try authority.validate();
    const result = Receipt{
        .source_digest = authority.source_digest,
        .completed = completed,
    };
    try result.validate(authority);
    return result;
}

/// Producer-observed geometry that cannot be reconstructed reliably after a
/// legacy opcode epoch has returned. `opcode_trace.Columns` publishes these
/// values from the actual worker reduction and audit branch.
pub const LegacyEvidence = struct {
    counter_set_merges: usize,
    direct_semantic_audit_performed: bool,
};

/// Issues the exact base Tree-1 receipt for the predecessor producer. This is
/// a profiling-only second pass over immutable execution rows; normal proofs
/// never initialize the authority or enter this loop.
pub fn issueLegacyReceipt(
    statement: *const statement_mod.RiscVStatement,
    rows: []const trace.TraceRow,
    evidence: LegacyEvidence,
) !Receipt {
    const authority = try Authority.init();
    const completed = try captureLegacyBase(
        &authority,
        statement,
        rows,
        evidence,
    );
    return seal(&authority, completed);
}

/// Extension-aware predecessor receipt. The caller projection and its two-pass
/// fixed-table registration belong here; provider Poseidon permutations do not.
pub fn issueLegacyPoseidon2Receipt(
    statement: *const statement_mod.RiscVStatement,
    rows: []const trace.TraceRow,
    evidence: LegacyEvidence,
    guest_rows: u32,
) !Receipt {
    const authority = try Authority.init();
    var completed = try captureLegacyBase(
        &authority,
        statement,
        rows,
        evidence,
    );
    try completed.observeGuestCallerTraceRows(&authority, guest_rows);
    try completed.observeGuestLookupRows(&authority, guest_rows);
    return seal(&authority, completed);
}

fn captureLegacyBase(
    authority: *const Authority,
    statement: *const statement_mod.RiscVStatement,
    rows: []const trace.TraceRow,
    evidence: LegacyEvidence,
) !Shard {
    try authority.validate();
    var completed = Shard{};
    for (rows) |row| {
        const family = try trace.proofOpcodeFamily(row.opcode);
        try completed.observeOpcodeRow(authority, family, row);
    }

    var expected_opcode_rows = [_]u64{0} ** trace.N_FAMILIES;
    var program_rows: usize = 0;
    var memory_rows: usize = 0;
    var merkle_rows: usize = 0;
    var clock_rows: usize = 0;
    var clock_domain_rows: usize = 0;
    for (statement.component_descs[0..statement.n_components]) |desc| {
        const family_index = @intFromEnum(desc.family);
        expected_opcode_rows[family_index] = try add(
            expected_opcode_rows[family_index],
            desc.n_rows,
        );
        if (evidence.direct_semantic_audit_performed) {
            if (desc.log_size >= @bitSizeOf(usize))
                return error.InvalidMainWitnessWorkShape;
            try completed.observeAudit(
                authority,
                desc.family,
                @as(usize, 1) << @intCast(desc.log_size),
            );
        }
    }
    for (statement.infra_descs[0..statement.n_infra]) |desc| {
        const count: usize = @intCast(desc.n_rows);
        switch (desc.kind) {
            .program => {
                try completed.observeInfrastructure(.program, count);
                program_rows = try addUsize(program_rows, count);
            },
            .memory => {
                try completed.observeInfrastructure(.memory, count);
                memory_rows = try addUsize(memory_rows, count);
            },
            .merkle => {
                try completed.observeInfrastructure(.merkle, count);
                merkle_rows = try addUsize(merkle_rows, count);
            },
            .clock_update => {
                try completed.observeInfrastructure(.clock_update, count);
                clock_rows = try addUsize(clock_rows, count);
                if (desc.log_size >= @bitSizeOf(usize))
                    return error.InvalidMainWitnessWorkShape;
                clock_domain_rows = try addUsize(
                    clock_domain_rows,
                    @as(usize, 1) << @intCast(desc.log_size),
                );
            },
            else => {},
        }
    }
    try completed.observeSeed(
        authority,
        program_rows,
        memory_rows,
        clock_domain_rows,
        clock_rows,
    );
    try completed.observeCounterSetMerges(
        authority,
        evidence.counter_set_merges,
    );

    var described_rows: u64 = 0;
    for (expected_opcode_rows) |count| described_rows = try add(described_rows, count);
    if (described_rows != @as(u64, @intCast(rows.len)) or
        !std.meta.eql(expected_opcode_rows, completed.opcode_rows) or
        completed.program_rows != @as(u64, @intCast(program_rows)) or
        completed.memory_rows != @as(u64, @intCast(memory_rows)) or
        completed.merkle_rows != @as(u64, @intCast(merkle_rows)) or
        completed.clock_rows != @as(u64, @intCast(clock_rows)) or
        completed.program_seed_rows != @as(u64, @intCast(program_rows)) or
        completed.memory_seed_rows != @as(u64, @intCast(memory_rows)) or
        completed.clock_seed_domain_rows != @as(u64, @intCast(clock_domain_rows)) or
        completed.clock_seed_active_rows != @as(u64, @intCast(clock_rows)) or
        completed.counter_set_merges != @as(u64, @intCast(evidence.counter_set_merges)))
    {
        return error.InvalidMainWitnessWorkShape;
    }
    return completed;
}

fn witnessRule(family: trace.OpcodeFamily) WitnessRule {
    return switch (family) {
        .base_alu_reg, .base_alu_imm, .shifts_reg, .shifts_imm, .lui, .mul, .mulh => .destination_inverse,
        .auipc, .jal, .jalr, .load_store => .signed_immediate_destination_inverse,
        .branch_eq => .branch_eq_first_difference_inverse,
        .branch_lt => .branch_lt_comparison,
        .lt_imm => .lt_imm_comparison_destination_inverse,
        .lt_reg => .lt_reg_comparison_destination_inverse,
        .div => .division_hints,
        .fence => .zero,
    };
}

fn witnessOperations(
    rule: WitnessRule,
    row: trace.TraceRow,
) prover_api.work_profile.FieldOperations {
    const rd_inverse: u64 = @intFromBool(row.rd != 0);
    return switch (rule) {
        .destination_inverse => .{ .inversions = rd_inverse },
        .signed_immediate_destination_inverse => .{
            .additions = @intFromBool(row.imm < 0),
            .inversions = if (row.is_store)
                @intFromBool(row.rs2 != 0)
            else
                rd_inverse,
        },
        .branch_eq_first_difference_inverse => .{
            .additions = 4 + @as(u64, @intFromBool(row.imm < 0)),
            .inversions = @intFromBool(row.rs1_val != row.rs2_val),
        },
        .branch_lt_comparison => comparisonOperations(
            row,
            row.opcode == .BLT or row.opcode == .BGE,
            true,
            false,
        ),
        .lt_imm_comparison_destination_inverse => comparisonOperations(
            row,
            row.opcode == .SLTI,
            false,
            true,
        ),
        .lt_reg_comparison_destination_inverse => comparisonOperations(
            row,
            row.opcode == .SLT,
            false,
            true,
        ),
        .division_hints => .{
            .inversions = 4 +
                @as(u64, @intFromBool(row.rs2_val != 0)) +
                @as(u64, @intFromBool(divRemainder(row) != 0)) +
                rd_inverse,
        },
        .zero => .{},
    };
}

fn comparisonOperations(
    row: trace.TraceRow,
    signed_comparison: bool,
    signed_immediate: bool,
    destination: bool,
) prover_api.work_profile.FieldOperations {
    const rhs = if (row.opcode == .SLTI or row.opcode == .SLTIU)
        @as(u32, @bitCast(row.imm))
    else
        row.rs2_val;
    var additions: u64 = @intFromBool(row.rs1_val != rhs);
    if (signed_comparison) {
        additions += @intFromBool((row.rs1_val >> 31) != 0);
        additions += @intFromBool((rhs >> 31) != 0);
    }
    if (signed_immediate) additions += @intFromBool(row.imm < 0);
    return .{
        .additions = additions,
        .inversions = if (destination) @intFromBool(row.rd != 0) else 0,
    };
}

fn divRemainder(row: trace.TraceRow) u32 {
    if (row.rs2_val == 0) return row.rs1_val;
    return switch (row.opcode) {
        .DIV, .REM => blk: {
            const lhs: i32 = @bitCast(row.rs1_val);
            const rhs: i32 = @bitCast(row.rs2_val);
            if (lhs == std.math.minInt(i32) and rhs == -1) break :blk 0;
            break :blk @bitCast(@rem(lhs, rhs));
        },
        .DIVU, .REMU => row.rs1_val % row.rs2_val,
        else => 0,
    };
}

fn computeSourceDigest(authority: *const Authority) Digest {
    var hash = Sha256.init(.{});
    hash.update(DIGEST_DOMAIN);
    hashInt(&hash, u16, SCHEMA_VERSION);
    for (authority.families, composition_manifest.BY_FAMILY) |schedule, descriptor| {
        hashInt(&hash, u8, @intFromEnum(descriptor.family));
        hash.update(&descriptor.authority_digest);
        hashInt(&hash, u8, @intFromEnum(schedule.witness_rule));
        hashOperations(&hash, schedule.lookup_build);
        hashInt(&hash, u64, schedule.lookup_counter_additions);
        hashOperations(&hash, schedule.audit_row);
    }
    hashOperations(&hash, authority.program_entry_build);
    hashOperations(&hash, authority.memory_entry_build);
    hashOperations(&hash, authority.clock_entry_build);
    hashInt(&hash, u16, GUEST_CALLER_TRACE_ALGORITHM_VERSION);
    hashInt(&hash, u16, GUEST_LOOKUP_REGISTRATION_ALGORITHM_VERSION);
    const extension_manifest_digest = guest_manifest.canonicalDigest();
    hash.update(&extension_manifest_digest);
    hashOperations(&hash, authority.guest_caller_trace_row);
    hashOperations(&hash, authority.guest_lookup_row);
    hashInt(&hash, u64, authority.guest_lookup_requests_per_row);
    hashInt(&hash, u64, authority.fixed_table_cells);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn hashOperations(hash: *Sha256, value: prover_api.work_profile.FieldOperations) void {
    hashInt(hash, u64, value.additions);
    hashInt(hash, u64, value.multiplications);
    hashInt(hash, u64, value.inversions);
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn addOperationsValue(
    lhs: prover_api.work_profile.FieldOperations,
    rhs: prover_api.work_profile.FieldOperations,
) !prover_api.work_profile.FieldOperations {
    return .{
        .additions = try add(lhs.additions, rhs.additions),
        .multiplications = try add(lhs.multiplications, rhs.multiplications),
        .inversions = try add(lhs.inversions, rhs.inversions),
    };
}

fn add(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch error.MainWitnessWorkOverflow;
}

fn mul(lhs: u64, rhs: u64) !u64 {
    return std.math.mul(u64, lhs, rhs) catch error.MainWitnessWorkOverflow;
}

fn addUsize(lhs: usize, rhs: usize) !usize {
    return std.math.add(usize, lhs, rhs) catch error.MainWitnessWorkOverflow;
}

comptime {
    if (trace.N_FAMILIES != composition_manifest.FAMILY_COUNT)
        @compileError("main-witness work family authority count drifted");
}

test "main witness work authority derives exact typed infrastructure schedules" {
    const authority = try Authority.init();
    try authority.validate();
    try std.testing.expectEqual(
        prover_api.work_profile.FieldOperations{ .additions = 3 },
        authority.program_entry_build,
    );
    try std.testing.expectEqual(
        prover_api.work_profile.FieldOperations{ .additions = 3 },
        authority.memory_entry_build,
    );
    try std.testing.expectEqual(
        prover_api.work_profile.FieldOperations{
            .additions = 1,
            .multiplications = 1,
        },
        authority.clock_entry_build,
    );
    try std.testing.expectEqual(
        prover_api.work_profile.FieldOperations{
            .additions = 224,
            .multiplications = 288,
            .inversions = 1,
        },
        authority.guest_caller_trace_row,
    );
    try std.testing.expectEqual(
        prover_api.work_profile.FieldOperations{
            .additions = 251,
            .multiplications = 36,
        },
        authority.guest_lookup_row,
    );
    try std.testing.expectEqual(
        @as(u64, 115),
        authority.guest_lookup_requests_per_row,
    );
    try std.testing.expect(authority.fixed_table_cells != 0);
    for (authority.families) |schedule| {
        try std.testing.expect(
            schedule.lookup_counter_additions != 0 or
                !schedule.lookup_build.delta().counters.isZero(),
        );
        try std.testing.expect(!schedule.audit_row.delta().counters.isZero());
    }
}

test "main witness work shard is fail atomic and receipt rejects identity mutation" {
    const authority = try Authority.init();
    var row = std.mem.zeroes(trace.TraceRow);
    row.opcode = .ADDI;
    row.rd = 1;

    var shard = Shard{};
    try shard.observeOpcodeRow(&authority, .base_alu_imm, row);
    try std.testing.expectEqual(
        @as(u64, 1),
        shard.opcode_rows[@intFromEnum(trace.OpcodeFamily.base_alu_imm)],
    );
    try std.testing.expectEqual(@as(u64, 1), shard.operations.inversions);

    try shard.observeGuestCallerTraceRows(&authority, 2);
    try shard.observeGuestLookupRows(&authority, 2);
    try std.testing.expectEqual(@as(u64, 2), shard.guest_caller_trace_rows);
    try std.testing.expectEqual(@as(u64, 2), shard.guest_lookup_rows);

    var overflowing = Shard{};
    overflowing.operations.additions = std.math.maxInt(u64);
    const before = overflowing;
    try std.testing.expectError(
        error.MainWitnessWorkOverflow,
        overflowing.observeOpcodeRow(&authority, .base_alu_imm, row),
    );
    try std.testing.expectEqualDeep(before, overflowing);

    var receipt = try seal(&authority, shard);
    try receipt.validate(&authority);
    receipt.source_digest[0] ^= 1;
    try std.testing.expectError(
        error.MainWitnessWorkSourceMismatch,
        receipt.validate(&authority),
    );
}

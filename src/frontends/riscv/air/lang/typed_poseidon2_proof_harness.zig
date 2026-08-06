//! Test-only proof substitution harness for the typed Poseidon2 pilot.
//!
//! The prover builds its trace for discovery; authenticated H-005/H-006 output
//! overwrites both windows before commitment and typed claims enter the live
//! transcript/component. Backend, PCS, order, and verification remain unchanged.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const core_utils = @import("stwo_core").utils;
const pcs_core = @import("stwo_core").pcs;
const prover_engine = @import("stwo_prover_engine").engine;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const stage_profile = @import("stwo_prover_api").stage_profile;
const hash_component = @import("../memory_commitment/hash_component.zig");
const challenges = @import("../relation_challenges.zig");
const transcript_claims = @import("../transcript/claims.zig");
const proof_types = @import("../../prover/types.zig");
const compat = @import("typed_poseidon2_compat.zig");
const identity = @import("typed_poseidon2_identity.zig");
const proof_authority = @import("typed_poseidon2_proof_authority.zig");
const relations = @import("typed_poseidon2_relations.zig");
const witness = @import("typed_poseidon2_witness.zig");
const BaseChannel = proof_types.Channel;
const BaseMerkleChannel = proof_types.MerkleChannel;

pub const Error = error{
    AmbiguousPoseidonMainWindow,
    AmbiguousPoseidonInteractionWindow,
    CandidateClaimMixIncomplete,
    CandidateComponentMissing,
    CandidateInteractionNotReady,
    CandidateProofIncomplete,
    InvalidCandidateMutation,
    PoseidonClaimMismatch,
    PoseidonInteractionWindowMissing,
    PoseidonMainWindowMissing,
    PoseidonModePartitionInvalid,
    PoseidonProgramIdentityMismatch,
    UnexpectedCommitOrder,
};

pub const CANONICAL_PROGRAM_IDENTITY_DIGEST =
    identity.CANONICAL_COMBINED_DIGEST;

pub const Mutation = union(enum) {
    none,
    main_column: struct { column: usize, logical_row: usize, delta: u32 = 1 },
    interaction_column: struct { column: usize, logical_row: usize, delta: u32 = 1 },
    claim_sum: struct { sum: usize, delta: u32 = 1 },
};

pub const Receipt = struct {
    backend_name: []const u8,
    active_rows: usize,
    narrow_rows: usize,
    wide_rows: usize,
    io_rows: usize,
    main_column_offset: usize,
    interaction_column_offset: usize,
    main_columns: usize,
    interaction_columns: usize,
    main_matched_legacy: bool,
    interaction_matched_legacy: bool,
    transcript_claim_from_typed: bool,
    component_claims_from_typed: bool,
    output_claims_from_typed: bool,
    commits_seen: u8,
    typed_claims: [relations.N_SUMS]QM31,
    program_identity: identity.ProgramIdentity,
    pub fn validate(self: Receipt) Error!void {
        if (self.active_rows == 0 or self.narrow_rows > self.active_rows or
            self.wide_rows > self.active_rows - self.narrow_rows or
            self.io_rows != self.active_rows - self.narrow_rows - self.wide_rows or
            self.main_columns != compat.N_MAIN_COLUMNS or
            self.interaction_columns != relations.N_INTERACTION_COLUMNS or
            !self.main_matched_legacy or !self.interaction_matched_legacy or
            !self.transcript_claim_from_typed or !self.component_claims_from_typed or
            !self.output_claims_from_typed or self.commits_seen != 3)
        {
            return error.CandidateProofIncomplete;
        }
        self.program_identity.validate() catch
            return error.PoseidonProgramIdentityMismatch;
        if (!self.program_identity.isCanonical())
            return error.PoseidonProgramIdentityMismatch;
    }
};

/// Blake2s channel with one claim substitution; all else delegates byte-for-byte.
pub const CandidateChannel = struct {
    inner: BaseChannel = .{},
    context: ?*Context = null,
    pub fn digestBytes(self: CandidateChannel) [32]u8 {
        return self.inner.digestBytes();
    }
    pub fn mixU32s(self: *CandidateChannel, values: []const u32) void {
        self.inner.mixU32s(values);
    }
    pub fn mixU64(self: *CandidateChannel, value: u64) void {
        self.inner.mixU64(value);
    }
    pub fn mixFelts(self: *CandidateChannel, values: []const QM31) void {
        if (self.context) |context| {
            if (context.claimMixValue(values)) |candidate| {
                self.inner.mixFelts(&.{candidate});
                return;
            }
        }
        self.inner.mixFelts(values);
    }
    pub fn drawSecureFelt(self: *CandidateChannel) QM31 {
        return self.inner.drawSecureFelt();
    }
    pub fn drawSecureFelts(
        self: *CandidateChannel,
        allocator: std.mem.Allocator,
        count: usize,
    ) ![]QM31 {
        const values = try self.inner.drawSecureFelts(allocator, count);
        errdefer allocator.free(values);
        if (self.context) |context| try context.captureRelations(allocator, values);
        return values;
    }
    pub fn drawU32s(self: *CandidateChannel) [8]u32 {
        return self.inner.drawU32s();
    }
    pub fn grind(self: *CandidateChannel, bits: u32) u64 {
        return self.inner.grind(bits);
    }
    pub fn verifyPowNonce(self: *CandidateChannel, bits: u32, nonce: u64) bool {
        return self.inner.verifyPowNonce(bits, nonce);
    }
};

pub const CandidateMerkleChannel = struct {
    pub fn mixRoot(channel: *CandidateChannel, root: [32]u8) void {
        BaseMerkleChannel.mixRoot(&channel.inner, root);
    }
};

/// Real-backend engine wrapper for the three test-authorized boundaries above.
pub fn CandidateEngine(comptime BackendType: type) type {
    const Inner = prover_engine.ProverEngine(
        BackendType,
        proof_types.Hasher,
        CandidateMerkleChannel,
        CandidateChannel,
    );
    return struct {
        pub const Backend = BackendType;
        pub const Hasher = proof_types.Hasher;
        pub const MerkleChannel = CandidateMerkleChannel;
        pub const Channel = CandidateChannel;
        pub const Component = Inner.Component;
        pub const Scheme = Inner.Scheme;
        pub const ExtendedProof = Inner.ExtendedProof;
        pub fn init(allocator: std.mem.Allocator, config: pcs_core.PcsConfig) !Scheme {
            return Inner.init(allocator, config);
        }
        pub fn deinit(scheme: *Scheme, allocator: std.mem.Allocator) void {
            Inner.deinit(scheme, allocator);
        }
        pub fn commit(
            scheme: *Scheme,
            allocator: std.mem.Allocator,
            columns: []prover_pcs.ColumnEvaluation,
            recorder: ?*stage_profile.Recorder,
            channel: *Channel,
        ) !void {
            if (channel.context) |context| context.beforeCommit(allocator, columns) catch |err| {
                try Inner.commit(scheme, allocator, columns, recorder, channel);
                return err;
            };
            return Inner.commit(scheme, allocator, columns, recorder, channel);
        }
        pub fn commitWithBacking(
            scheme: *Scheme,
            allocator: std.mem.Allocator,
            columns: []prover_pcs.ColumnEvaluation,
            backing_buffers: ?[][]M31,
            recorder: ?*stage_profile.Recorder,
            channel: *Channel,
        ) !void {
            if (channel.context) |context| context.beforeCommit(allocator, columns) catch |err| {
                try Inner.commitWithBacking(
                    scheme,
                    allocator,
                    columns,
                    backing_buffers,
                    recorder,
                    channel,
                );
                return err;
            };
            return Inner.commitWithBacking(
                scheme,
                allocator,
                columns,
                backing_buffers,
                recorder,
                channel,
            );
        }
        pub fn prove(
            allocator: std.mem.Allocator,
            components: []const Component,
            channel: *Channel,
            scheme: Scheme,
            options: @import("stwo_prover_api").ProveOptions,
        ) !ExtendedProof {
            if (channel.context) |context| context.installComponentClaims(components) catch |err| {
                var owned_scheme = scheme;
                Inner.deinit(&owned_scheme, allocator);
                return err;
            };
            return Inner.prove(allocator, components, channel, scheme, options);
        }
    };
}
const Phase = enum { initial, main_committed, relations_ready, interaction_committed, proving };
pub const Context = struct {
    allocator: std.mem.Allocator,
    backend_name: []const u8,
    mutation: Mutation,
    authority: proof_authority.Authority,
    phase: Phase = .initial,
    commits_seen: u8 = 0,
    main_offset: usize = 0,
    interaction_offset: usize = 0,
    log_size: u32 = 0,
    rows: []relations.RelationRow = &.{},
    mode_counts: ModeCounts = .{},
    interaction: ?relations.Interaction = null,
    canonical_claims: relations.Claims = .{ .sums = .{ QM31.zero(), QM31.zero() } },
    typed_claims: relations.Claims = .{ .sums = .{ QM31.zero(), QM31.zero() } },
    claim_mix_index: usize = 0,
    main_matched: bool = false,
    interaction_matched: bool = false,
    transcript_claim_installed: bool = false,
    component_claims_installed: bool = false,
    output_claims_installed: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        backend_name: []const u8,
        mutation: Mutation,
    ) !Context {
        return .{
            .allocator = allocator,
            .backend_name = backend_name,
            .mutation = mutation,
            .authority = try proof_authority.Authority.init(allocator),
        };
    }
    pub fn deinit(self: *Context) void {
        if (self.interaction) |*interaction| interaction.deinit(self.allocator);
        if (self.rows.len != 0) self.allocator.free(self.rows);
        self.authority.deinit();
        self.* = undefined;
    }
    fn beforeCommit(
        self: *Context,
        allocator: std.mem.Allocator,
        columns: []prover_pcs.ColumnEvaluation,
    ) !void {
        if (self.commits_seen == 0) {
            if (self.phase != .initial) return error.UnexpectedCommitOrder;
        } else if (self.commits_seen == 1) {
            if (self.phase != .initial) return error.UnexpectedCommitOrder;
            try self.replaceMain(allocator, columns);
            self.phase = .main_committed;
        } else if (self.commits_seen == 2) {
            if (self.phase != .relations_ready) return error.CandidateInteractionNotReady;
            try self.replaceInteraction(columns);
            self.phase = .interaction_committed;
        } else return error.UnexpectedCommitOrder;
        self.commits_seen += 1;
    }
    fn replaceMain(
        self: *Context,
        allocator: std.mem.Allocator,
        columns: []prover_pcs.ColumnEvaluation,
    ) !void {
        var found: ?MainMatch = null;
        errdefer if (found) |match| allocator.free(match.calls);
        var start: usize = 0;
        while (start + compat.N_MAIN_COLUMNS <= columns.len) : (start += 1) {
            const candidate = columns[start..][0..compat.N_MAIN_COLUMNS];
            const calls = try parseCalls(allocator, candidate) orelse continue;
            var keep = false;
            defer if (!keep) allocator.free(calls);
            var probe = try MainStorage.init(allocator, candidate[0].values.len);
            defer probe.deinit();
            try self.authority.executor.generateMainInto(
                &probe.views,
                calls,
                candidate[0].log_size,
            );
            if (!columnsEqual(candidate, &probe.views)) continue;
            if (found != null) return error.AmbiguousPoseidonMainWindow;
            keep = true;
            found = .{ .offset = start, .log_size = candidate[0].log_size, .calls = calls };
        }
        const match = found orelse return error.PoseidonMainWindowMissing;
        found = null;
        defer allocator.free(match.calls);
        const selected = columns[match.offset..][0..compat.N_MAIN_COLUMNS];
        var destinations: [compat.N_MAIN_COLUMNS][]M31 = undefined;
        for (&destinations, selected) |*destination, column| {
            destination.* = @constCast(column.values);
        }
        try self.authority.executor.generateMainInto(
            &destinations,
            match.calls,
            match.log_size,
        );
        self.rows = try rowsFromMain(allocator, &destinations, match.calls.len, match.log_size);
        self.mode_counts = try countModes(self.rows);
        try applyMainMutation(self.mutation, &destinations, match.calls.len, match.log_size);
        self.main_offset = match.offset;
        self.log_size = match.log_size;
        self.main_matched = true;
    }
    fn captureRelations(
        self: *Context,
        allocator: std.mem.Allocator,
        draws: []const QM31,
    ) !void {
        if (self.phase != .main_committed or
            draws.len != 2 * challenges.RELATION_COUNT) return;
        const relation_values = relationsFromDraws(draws);
        const generated = try self.authority.relation_plan.generateInteraction(
            allocator,
            self.authority.relationAuthority(),
            self.rows,
            self.log_size,
            &relation_values,
        );
        self.interaction = generated;
        self.canonical_claims = generated.claims;
        self.typed_claims = generated.claims;
        try applyClaimMutation(self.mutation, &self.typed_claims);
        self.phase = .relations_ready;
    }

    fn claimMixValue(self: *Context, values: []const QM31) ?QM31 {
        if (self.phase != .relations_ready or values.len != 1 or
            self.claim_mix_index >= transcript_claims.COMPONENT_COUNT) return null;
        const index = self.claim_mix_index;
        self.claim_mix_index += 1;
        if (index != @intFromEnum(transcript_claims.Component.poseidon2)) return null;
        if (!values[0].eql(self.canonical_claims.total())) return null;
        self.transcript_claim_installed = true;
        return self.typed_claims.total();
    }

    fn replaceInteraction(
        self: *Context,
        columns: []prover_pcs.ColumnEvaluation,
    ) !void {
        if (self.claim_mix_index != transcript_claims.COMPONENT_COUNT or
            !self.transcript_claim_installed)
        {
            return error.CandidateClaimMixIncomplete;
        }
        const generated = if (self.interaction) |*value|
            value
        else
            return error.CandidateInteractionNotReady;
        var found: ?usize = null;
        var start: usize = 0;
        while (start + relations.N_INTERACTION_COLUMNS <= columns.len) : (start += 1) {
            const candidate = columns[start..][0..relations.N_INTERACTION_COLUMNS];
            if (candidate[0].log_size != self.log_size or
                !columnsEqual(candidate, &generated.columns)) continue;
            if (found != null) return error.AmbiguousPoseidonInteractionWindow;
            found = start;
        }
        const offset = found orelse return error.PoseidonInteractionWindowMissing;
        try applyInteractionMutation(self.mutation, &generated.columns, self.rows.len, self.log_size);
        for (columns[offset..][0..relations.N_INTERACTION_COLUMNS], generated.columns) |
            destination,
            typed_column,
        | @memcpy(@constCast(destination.values), typed_column);
        generated.deinit(self.allocator);
        self.interaction = null;
        self.interaction_offset = offset;
        self.interaction_matched = true;
    }

    fn installComponentClaims(
        self: *Context,
        components: []const prover_component.ComponentProver,
    ) !void {
        if (self.phase != .interaction_committed) return error.CandidateProofIncomplete;
        const vtable = hashComponentVtable();
        var found: usize = 0;
        for (components) |component| {
            if (component.vtable != vtable) continue;
            const value: *hash_component.HashComponent = @constCast(
                @as(*const hash_component.HashComponent, @ptrCast(@alignCast(component.ctx))),
            );
            if (value.kind != .poseidon2) continue;
            if (value.main_col_offset != self.main_offset or
                value.interaction_col_offset != self.interaction_offset)
            {
                return error.CandidateComponentMissing;
            }
            for (value.poseidon_claims, self.canonical_claims.sums) |actual, expected| {
                if (!actual.eql(expected)) return error.PoseidonClaimMismatch;
            }
            value.poseidon_claims = self.typed_claims.sums;
            found += 1;
        }
        if (found != 1) return error.CandidateComponentMissing;
        self.component_claims_installed = true;
        self.phase = .proving;
    }

    pub fn installOutputClaims(self: *Context, output: *proof_types.ProveOutput) !void {
        if (self.phase != .proving) return error.CandidateProofIncomplete;
        var found: usize = 0;
        for (output.statement.infra_descs[0..output.statement.n_infra], 0..) |desc, index| {
            if (desc.kind != .poseidon2) continue;
            for (output.interaction_claim.poseidon_claims[index], self.canonical_claims.sums) |
                actual,
                expected,
            | if (!actual.eql(expected)) return error.PoseidonClaimMismatch;
            output.interaction_claim.poseidon_claims[index] = self.typed_claims.sums;
            found += 1;
        }
        if (found != 1) return error.CandidateComponentMissing;
        self.output_claims_installed = true;
    }

    pub fn receipt(self: *const Context) !Receipt {
        const final_identity = try self.authority.programIdentity();
        if (!std.meta.eql(final_identity, self.authority.program_identity))
            return error.PoseidonProgramIdentityMismatch;
        return .{
            .backend_name = self.backend_name,
            .active_rows = self.rows.len,
            .narrow_rows = self.mode_counts.narrow,
            .wide_rows = self.mode_counts.wide,
            .io_rows = self.mode_counts.io,
            .main_column_offset = self.main_offset,
            .interaction_column_offset = self.interaction_offset,
            .main_columns = compat.N_MAIN_COLUMNS,
            .interaction_columns = relations.N_INTERACTION_COLUMNS,
            .main_matched_legacy = self.main_matched,
            .interaction_matched_legacy = self.interaction_matched,
            .transcript_claim_from_typed = self.transcript_claim_installed,
            .component_claims_from_typed = self.component_claims_installed,
            .output_claims_from_typed = self.output_claims_installed,
            .commits_seen = self.commits_seen,
            .typed_claims = self.typed_claims.sums,
            .program_identity = final_identity,
        };
    }
};

const MainMatch = struct { offset: usize, log_size: u32, calls: []witness.Call };
const ModeCounts = struct { narrow: usize = 0, wide: usize = 0, io: usize = 0 };
const MainStorage = struct {
    allocator: std.mem.Allocator,
    backing: []M31,
    views: [compat.N_MAIN_COLUMNS][]M31,
    fn init(allocator: std.mem.Allocator, len: usize) !MainStorage {
        const backing = try allocator.alloc(M31, compat.N_MAIN_COLUMNS * len);
        var views: [compat.N_MAIN_COLUMNS][]M31 = undefined;
        for (&views, 0..) |*view, column| view.* = backing[column * len ..][0..len];
        return .{ .allocator = allocator, .backing = backing, .views = views };
    }
    fn deinit(self: *MainStorage) void {
        self.allocator.free(self.backing);
        self.* = undefined;
    }
};

fn parseCalls(
    allocator: std.mem.Allocator,
    columns: []const prover_pcs.ColumnEvaluation,
) !?[]witness.Call {
    if (columns.len != compat.N_MAIN_COLUMNS) return null;
    const log_size = columns[0].log_size;
    if (log_size >= @bitSizeOf(usize)) return null;
    const size = @as(usize, 1) << @intCast(log_size);
    for (columns) |column| if (column.log_size != log_size or column.values.len != size) return null;
    var active: usize = 0;
    var padding_seen = false;
    for (0..size) |logical_row| {
        const enabled = columns[compat.ENABLER_COLUMN].values[committedRow(logical_row, log_size)];
        if (enabled.isOne()) {
            if (padding_seen) return null;
            active += 1;
        } else if (enabled.isZero()) {
            padding_seen = true;
        } else return null;
    }
    if (active == 0) return null;
    const calls = try allocator.alloc(witness.Call, active);
    var keep = false;
    defer if (!keep) allocator.free(calls);
    for (calls, 0..) |*call, logical_row| {
        const row = committedRow(logical_row, log_size);
        var input: [compat.WIDTH]u32 = undefined;
        for (&input, 0..) |*value, lane| {
            value.* = columns[compat.INPUT_START + lane].values[row].toU32();
        }
        const wide = columns[compat.WIDE_COLUMN].values[row];
        const io = columns[compat.IO_COLUMN].values[row];
        if ((!wide.isZero() and !wide.isOne()) or (!io.isZero() and !io.isOne())) return null;
        call.* = .{ .input = input, .wide = wide.isOne(), .io = io.isOne() };
    }
    keep = true;
    return calls;
}

fn rowsFromMain(
    allocator: std.mem.Allocator,
    columns: *const [compat.N_MAIN_COLUMNS][]M31,
    count: usize,
    log_size: u32,
) ![]relations.RelationRow {
    const rows = try allocator.alloc(relations.RelationRow, count);
    for (rows, 0..) |*result, logical_row| {
        const row = committedRow(logical_row, log_size);
        for (&result.input, 0..) |*value, lane| value.* = columns[compat.INPUT_START + lane][row];
        for (&result.output, 0..) |*value, lane| {
            value.* = columns[relations.OUTPUT_COLUMN_START + lane][row];
        }
        result.enabled = columns[compat.ENABLER_COLUMN][row];
        result.wide = columns[compat.WIDE_COLUMN][row];
        result.io = columns[compat.IO_COLUMN][row];
    }
    return rows;
}

fn countModes(rows: []const relations.RelationRow) Error!ModeCounts {
    var counts: ModeCounts = .{};
    for (rows) |row| {
        if (!row.enabled.isOne() or
            (!row.wide.isZero() and !row.wide.isOne()) or
            (!row.io.isZero() and !row.io.isOne()) or
            (row.wide.isOne() and row.io.isOne()))
        {
            return error.PoseidonModePartitionInvalid;
        }
        if (row.io.isOne()) counts.io += 1 else if (row.wide.isOne()) counts.wide += 1 else counts.narrow += 1;
    }
    return counts;
}

fn columnsEqual(expected: anytype, actual: anytype) bool {
    if (expected.len == 0 or expected.len != actual.len) return false;
    const log_size = expected[0].log_size;
    for (expected, actual) |lhs, rhs| {
        if (lhs.log_size != log_size or lhs.values.len != rhs.len or
            !std.mem.eql(u8, std.mem.sliceAsBytes(lhs.values), std.mem.sliceAsBytes(rhs)))
        {
            return false;
        }
    }
    return true;
}

fn applyMainMutation(
    mutation: Mutation,
    columns: *[compat.N_MAIN_COLUMNS][]M31,
    active_rows: usize,
    log_size: u32,
) !void {
    const spec = switch (mutation) {
        .main_column => |value| value,
        else => return,
    };
    if (spec.column >= columns.len or spec.logical_row >= active_rows or spec.delta == 0)
        return error.InvalidCandidateMutation;
    const row = committedRow(spec.logical_row, log_size);
    columns[spec.column][row] = columns[spec.column][row].add(M31.fromU64(spec.delta));
}

fn applyInteractionMutation(
    mutation: Mutation,
    columns: *[relations.N_INTERACTION_COLUMNS][]M31,
    active_rows: usize,
    log_size: u32,
) !void {
    const spec = switch (mutation) {
        .interaction_column => |value| value,
        else => return,
    };
    if (spec.column >= columns.len or spec.logical_row >= active_rows or spec.delta == 0)
        return error.InvalidCandidateMutation;
    const row = committedRow(spec.logical_row, log_size);
    columns[spec.column][row] = columns[spec.column][row].add(M31.fromU64(spec.delta));
}

fn applyClaimMutation(mutation: Mutation, claims_value: *relations.Claims) !void {
    const spec = switch (mutation) {
        .claim_sum => |value| value,
        else => return,
    };
    if (spec.sum >= relations.N_SUMS or spec.delta == 0)
        return error.InvalidCandidateMutation;
    claims_value.sums[spec.sum] = claims_value.sums[spec.sum].add(
        QM31.fromBase(M31.fromU64(spec.delta)),
    );
}

fn relationsFromDraws(values: []const QM31) challenges.Relations {
    return .{
        .registers_state = challenges.RelationElements(2).init(values[0], values[1]),
        .memory_access = challenges.RelationElements(7).init(values[2], values[3]),
        .program_access = challenges.RelationElements(5).init(values[4], values[5]),
        .merkle = challenges.RelationElements(4).init(values[6], values[7]),
        .poseidon2 = challenges.RelationElements(16).init(values[8], values[9]),
        .poseidon2_io = challenges.RelationElements(32).init(values[10], values[11]),
        .bitwise = challenges.RelationElements(4).init(values[12], values[13]),
        .range_check_20 = challenges.RelationElements(1).init(values[14], values[15]),
        .range_check_8_11 = challenges.RelationElements(2).init(values[16], values[17]),
        .range_check_8_8_4 = challenges.RelationElements(3).init(values[18], values[19]),
        .range_check_8_8 = challenges.RelationElements(2).init(values[20], values[21]),
        .range_check_m31 = challenges.RelationElements(2).init(values[22], values[23]),
    };
}

fn hashComponentVtable() *const prover_component.ComponentProverVTable {
    const marker = hash_component.HashComponent{
        .kind = .poseidon2,
        .log_size = 0,
        .n_rows = 0,
        .is_first_col_idx = 0,
        .is_active_col_idx = 0,
        .main_col_offset = 0,
        .interaction_col_offset = 0,
        .relations = undefined,
    };
    return marker.asProverComponent().vtable;
}

inline fn committedRow(logical_row: usize, log_size: u32) usize {
    return core_utils.bitReverseIndex(
        core_utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}

comptime {
    if (compat.N_MAIN_COLUMNS != 445 or relations.N_INTERACTION_COLUMNS != 8 or
        relations.N_SUMS != 2)
    {
        @compileError("typed Poseidon proof harness geometry drifted");
    }
}

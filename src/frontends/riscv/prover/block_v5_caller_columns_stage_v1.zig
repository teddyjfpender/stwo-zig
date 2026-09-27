//! Complete family11 witness-once storage. All arithmetic/private lookup/main
//! matrices are persisted; selected caller frames alone are insufficient. Files
//! are proposals and are freshly recommitted against first-pass roots on load.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Store = @import("block_v5_witness_columns_store_v1.zig");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Witness = @import("block_v5_precompile_witness_v1.zig").Witness;
const Frame = @import("../air/block/memory_event.zig").Frame;
const Tables = @import("../air/lookups/tables/mod.zig");
const KeccakTrace = @import("../air/guest_precompile/keccakf_trace.zig");
const KeccakCaller = @import("../air/guest_precompile/keccakf_caller.zig");
const KeccakTables = @import("../air/guest_precompile/keccakf_tables.zig");
const KeccakCounters = @import("../air/guest_precompile/keccakf_multiplicities.zig");
const Secp = @import("../air/guest_precompile/secp256k1_component_bundle.zig");
const SecpConfig = @import("../air/guest_precompile/secp256k1_component_config.zig");
const SecpTrace = @import("../air/guest_precompile/secp256k1_component_trace.zig");
const Signer = @import("../air/guest_precompile/secp256k1_recovery_caller.zig");
const ShaRows = @import("../air/guest_precompile/sha256_memory_rows.zig");
const local_zero = Protocol.circuit_profile.localZeroCustody();
const ShaAirs = @import("../air/guest_precompile/sha256_component_profile.zig").AirsForRecipe(local_zero);
const ShaProvider = @import("../air/guest_precompile/sha256_compression_rows.zig");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
pub const Pin = Store.Pin;
pub const MAIN_COLUMN_COUNT: usize = blk: {
    var count: usize = KeccakTrace.Layout.main_columns + @as(usize, if (local_zero) 2 else 0) + 2;
    for (.{ Secp.ProductBase, Secp.ProductScalar, Secp.LinearBase, Secp.LinearScalar, SecpConfig.Point, SecpConfig.Split, SecpConfig.ScalarProgram, SecpConfig.Table, SecpConfig.Recovery, SecpConfig.ByteTable, if (local_zero) SecpConfig.RecoveryCallerLocalZero else SecpConfig.RecoveryCaller }) |Config| count += Config.main_column_count;
    for (ShaAirs) |Air| count += Air.PHYSICAL_MAIN_COLUMN_COUNT;
    break :blk count;
};
pub const Limits = struct {
    columns: Store.Limits = .{ .max_columns = MAIN_COLUMN_COUNT, .max_log_size = 24, .max_file_bytes = 32 << 30, .max_loaded_bytes = 16 << 30 },
    /// Requested reconstructed matrices/rows/fixed selectors/counters; allocator
    /// and PCS overhead remains governed by the driver's tracked host budget.
    max_reconstruction_bytes: usize = 24 << 30,
};
pub const Descriptor = struct {
    statement: Profile.admission.Statement,
    total_steps: u32,
    index: u32,
    frame: Frame,
    config: core.pcs.PcsConfig,
    key_id: [32]u8,
    roots: [2][32]u8,
    pub fn fromProposal(proposal: anytype) Descriptor {
        return .{ .statement = proposal.statement, .total_steps = proposal.total_steps, .index = proposal.index, .frame = proposal.frame, .config = proposal.config, .key_id = proposal.key_id, .roots = proposal.roots };
    }
    pub fn require(self: *const Descriptor, a: std.mem.Allocator) !void {
        try Protocol.validate(&self.statement, self.total_steps, self.config);
        try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, &self.statement);
        if (self.frame.cycle_count != self.total_steps or self.frame.global_first_cycle == 0 or
            self.frame.clock_frame != .leaf_local or !std.meta.eql(self.key_id, try Protocol.keyId(&self.statement, self.total_steps, self.config, self.roots[0]))) return error.ChangedV5StagedCallerDescriptor;
    }
    fn scope(self: *const Descriptor) Store.Scope {
        return .{ .kind = .caller, .execution_index = self.index, .first_cycle = self.frame.global_first_cycle, .cycle_count = self.total_steps, .descriptor_digest = self.key_id, .first_roots = self.roots };
    }
};

fn committed(row: usize, log: u32) usize {
    return core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(row, log), log);
}
fn logical(row: usize, log: u32) usize {
    return core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(row, log), log);
}
fn locate(statement: *const Profile.admission.Statement, column: usize) !struct { component: usize, local: usize, log: u32 } {
    var at: usize = 0;
    for (Profile.descriptors(statement), 0..) |desc, component| {
        if (column >= at and column - at < desc.main_columns) return .{ .component = component, .local = column - at, .log = desc.log_size };
        at += desc.main_columns;
    }
    return error.InvalidV5StagedCallerColumn;
}
fn secpColumn(witness: *const Witness, component: usize, column: usize) ![]const M {
    return switch (component) {
        3 => witness.extension.secp.product_base.mainColumn(column),
        4 => witness.extension.secp.product_scalar.mainColumn(column),
        5 => witness.extension.secp.linear_base.mainColumn(column),
        6 => witness.extension.secp.linear_scalar.mainColumn(column),
        7 => witness.extension.secp.point.mainColumn(column),
        8 => witness.extension.secp.split.mainColumn(column),
        9 => witness.extension.secp.scalar.mainColumn(column),
        10 => witness.extension.secp.table.mainColumn(column),
        11 => witness.extension.secp.recovery.mainColumn(column),
        12 => witness.extension.secp.byte.mainColumn(column),
        13 => if (witness.extension.recovery_caller_local_zero) |*owned| owned.mainColumn(column) else witness.extension.recovery_caller.mainColumn(column),
        else => error.InvalidV5StagedCallerColumn,
    };
}
const Provider = struct {
    witness: *const Witness,
    fn get(raw: *const anyopaque, column: usize, offset: usize, out: []M) !void {
        const self: *const Provider = @ptrCast(@alignCast(raw));
        const info = try locate(&self.witness.statement, column);
        const size = @as(usize, 1) << @intCast(info.log);
        if (offset > size or out.len > size - offset) return error.InvalidV5StagedCallerColumn;
        if (info.component == 0) {
            @memcpy(out, self.witness.extension.keccak_shard.mainColumn(info.local)[offset..][0..out.len]);
        } else if (info.component == 1 or info.component == 2) {
            if (info.local != 0) return error.InvalidV5StagedCallerColumn;
            const values = self.witness.extension.keccak_counters.values(if (info.component == 1) .chi else .xor5);
            for (out, 0..) |*value, i| value.* = values[logical(offset + i, info.log)];
        } else if (info.component < 14) {
            @memcpy(out, (try secpColumn(self.witness, info.component, info.local))[offset..][0..out.len]);
        } else {
            const rows = self.witness.sha_rows.tuple();
            inline for (ShaAirs, 0..) |_, i| if (info.component == 14 + i) {
                for (out, 0..) |*value, index| value.* = rows[i][logical(offset + index, info.log)][info.local];
                return;
            };
            return error.InvalidV5StagedCallerColumn;
        }
    }
};
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, witness: *const Witness, descriptor: *const Descriptor, limits: Limits) !Pin {
    try descriptor.require(a);
    try requireWitness(witness, descriptor);
    const logs = try Protocol.columnLogs(a, &descriptor.statement, .main);
    defer a.free(logs);
    const provider = Provider{ .witness = witness };
    return Store.writeMapped(a, dir, name, descriptor.scope(), logs, limits.columns, .{ .context = &provider, .get = Provider.get });
}
fn requireWitness(witness: *const Witness, descriptor: *const Descriptor) !void {
    if (witness.total_steps != descriptor.total_steps or !std.meta.eql(witness.statement, descriptor.statement) or
        witness.extension.signerCount() != descriptor.statement.ethereum.counts.signer_calls or
        !std.meta.eql(witness.sha_rows.geometry, try ShaRows.Geometry.init(descriptor.statement.sha.call_count))) return error.ChangedV5StagedCallerWitness;
    const shapes = witness.extension.shapes();
    const k = &witness.extension.keccak_shard;
    const kd = descriptor.statement.ethereum.components[0];
    if (k.log_size != kd.log_size or k.n_rows != kd.n_rows or k.call_count != descriptor.statement.ethereum.counts.keccak_calls or
        k.first_call_index != 0 or k.x0_local_custody_version != @intFromBool(local_zero) or k.main_storage.len != try std.math.mul(usize, kd.main_columns, @as(usize, 1) << @intCast(kd.log_size)))
        return error.ChangedV5StagedCallerWitness;
    if (witness.extension.keccak_counters.slots != try std.math.divCeil(usize, k.call_count, 2) or
        witness.extension.keccak_counters.chi.len != KeccakTables.size(.chi) or witness.extension.keccak_counters.xor5.len != KeccakTables.size(.xor5))
        return error.ChangedV5StagedCallerWitness;
    try witness.extension.keccak_counters.validateTotals();
    inline for (std.meta.fields(@TypeOf(shapes)), 0..) |field, i| {
        const shape = @field(shapes, field.name);
        const expected = descriptor.statement.ethereum.components[3 + i];
        if (shape.log_size != expected.log_size or shape.n_rows != expected.n_rows) return error.ChangedV5StagedCallerWitness;
    }
    const trace_names = .{ "product_base", "product_scalar", "linear_base", "linear_scalar", "point", "split", "scalar", "table", "recovery", "byte" };
    inline for (trace_names, 0..) |name, i| {
        const trace = &@field(witness.extension.secp, name);
        const expected = descriptor.statement.ethereum.components[3 + i];
        if (trace.main_storage.len != try std.math.mul(usize, expected.main_columns, @as(usize, 1) << @intCast(expected.log_size))) return error.ChangedV5StagedCallerWitness;
    }
    const caller = descriptor.statement.ethereum.components[13];
    if (witness.extension.circuit_profile != Protocol.circuit_profile or (witness.extension.recovery_caller_local_zero != null) != local_zero) return error.ChangedV5StagedCallerWitness;
    const caller_storage = if (witness.extension.recovery_caller_local_zero) |owned| owned.main_storage else witness.extension.recovery_caller.main_storage;
    if (caller_storage.len != try std.math.mul(usize, caller.main_columns, @as(usize, 1) << @intCast(caller.log_size))) return error.ChangedV5StagedCallerWitness;
    const rows = witness.sha_rows.tuple();
    inline for (ShaAirs, 0..) |_, i| if (rows[i].len != @as(usize, 1) << @intCast(descriptor.statement.sha.descriptors[i].log_size)) return error.ChangedV5StagedCallerWitness;
}

pub const Owner = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    witness: Witness,
    counters: Tables.counter.Set,
    pub fn deinit(self: *Owner) void {
        // All nested structures alias this arena. Do not run witness.deinit:
        // staged matrices own no affine construction tape or duplicate arrays.
        const a = self.a;
        self.arena.deinit();
        a.destroy(self);
    }
    fn put(raw: *anyopaque, column: usize, offset: usize, values: []const M) !void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        const info = try locate(&self.witness.statement, column);
        const size = @as(usize, 1) << @intCast(info.log);
        if (offset > size or values.len > size - offset) return error.InvalidV5StagedCallerColumn;
        if (info.component == 0) {
            const out = @constCast(self.witness.extension.keccak_shard.mainColumn(info.local));
            @memcpy(out[offset..][0..values.len], values);
        } else if (info.component == 1 or info.component == 2) {
            if (info.local != 0) return error.InvalidV5StagedCallerColumn;
            const out = if (info.component == 1) self.witness.extension.keccak_counters.chi else self.witness.extension.keccak_counters.xor5;
            for (values, 0..) |value, i| out[logical(offset + i, info.log)] = value;
        } else if (info.component < 14) {
            @memcpy(@constCast(try secpColumn(&self.witness, info.component, info.local))[offset..][0..values.len], values);
        } else {
            const rows = self.witness.sha_rows.tuple();
            inline for (ShaAirs, 0..) |_, i| if (info.component == 14 + i) {
                for (values, 0..) |value, index| rows[i][logical(offset + index, info.log)][info.local] = value;
                return;
            };
            return error.InvalidV5StagedCallerColumn;
        }
    }
};

fn spanStorage(a: std.mem.Allocator, columns: []const Column, log: u32) ![]M {
    const size = @as(usize, 1) << @intCast(log);
    const result = try a.alloc(M, try std.math.mul(usize, columns.len, size));
    for (columns, 0..) |column, i| {
        if (column.log_size != log or column.values.len != size) return error.InvalidV5StagedCallerFixed;
        @memcpy(result[i * size ..][0..size], column.values);
    }
    return result;
}
fn secpTrace(comptime Config: type, a: std.mem.Allocator, desc: anytype, fixed: []const Column) !SecpTrace.Trace(Config) {
    if (desc.main_columns != Config.main_column_count or fixed.len != SecpTrace.preprocessed_column_count) return error.InvalidV5StagedCallerShape;
    return .{ .allocator = a, .log_size = desc.log_size, .n_rows = @max(1, desc.n_rows), .preprocessed_storage = try spanStorage(a, fixed, desc.log_size), .main_storage = try a.alloc(M, try std.math.mul(usize, Config.main_column_count, @as(usize, 1) << @intCast(desc.log_size))) };
}
fn emptyTrace(comptime T: type, a: std.mem.Allocator) T {
    return .{ .allocator = a, .log_size = 1, .n_rows = 0, .preprocessed_storage = &.{}, .main_storage = &.{} };
}
fn allocateRows(comptime T: type, a: std.mem.Allocator, log: u32) ![]T {
    const result = try a.alloc(T, @as(usize, 1) << @intCast(log));
    @memset(result, @splat(M.zero()));
    return result;
}
fn resourceBound(descriptor: *const Descriptor, limits: Limits) !void {
    var bytes: u64 = @sizeOf(Owner);
    for (Profile.descriptors(&descriptor.statement)) |desc| {
        if (desc.log_size > limits.columns.max_log_size or desc.log_size > 24) return error.V5StagedCallerReconstructionLimit;
        const rows = @as(u64, 1) << @intCast(desc.log_size);
        // Original deterministic selectors plus reconstructed contiguous views
        // or row metadata; no second complete main matrix is retained.
        bytes = try std.math.add(u64, bytes, try std.math.mul(u64, rows, try std.math.mul(u64, desc.main_columns + 2 * desc.preprocessed_columns, @sizeOf(M))));
    }
    for (0..Tables.schema.KIND_COUNT) |i| bytes = try std.math.add(u64, bytes, try std.math.mul(u64, Tables.schema.size(@enumFromInt(i)), @sizeOf(M)));
    if (bytes > limits.max_reconstruction_bytes) return error.V5StagedCallerReconstructionLimit;
}
fn reconstruct(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, descriptor: *const Descriptor, pin: Pin, limits: Limits) !*Owner {
    try descriptor.require(a);
    try resourceBound(descriptor, limits);
    const self = try a.create(Owner);
    self.* = .{ .a = a, .arena = std.heap.ArenaAllocator.init(a), .witness = undefined, .counters = undefined };
    errdefer self.deinit();
    const arena = self.arena.allocator();
    const descriptors = Profile.descriptors(&descriptor.statement);
    const fixed = try Profile.preprocessed(arena, &descriptor.statement);
    var blocks: [14][]const Column = undefined;
    var at: usize = 0;
    for (descriptors[0..14], &blocks) |desc, *block| {
        block.* = fixed[at..][0..desc.preprocessed_columns];
        at += desc.preprocessed_columns;
    }
    const ethereum = &descriptor.statement.ethereum;
    self.witness = .{ .statement = descriptor.statement, .total_steps = descriptor.total_steps, .extension = .{ .allocator = arena, .keccak_counters = try KeccakCounters.Counters.init(arena), .keccak_shard = .{ .allocator = arena, .log_size = descriptors[0].log_size, .n_rows = ethereum.components[0].n_rows, .first_call_index = 0, .call_count = ethereum.counts.keccak_calls, .x0_local_custody_version = @intFromBool(local_zero), .preprocessed_storage = try spanStorage(arena, blocks[0], descriptors[0].log_size), .main_storage = try arena.alloc(M, try std.math.mul(usize, descriptors[0].main_columns, @as(usize, 1) << @intCast(descriptors[0].log_size))) }, .secp_tape = @import("../air/guest_precompile/secp256k1_affine.zig").Tape.init(arena), .staged_signer_count = ethereum.counts.signer_calls, .circuit_profile = Protocol.circuit_profile, .secp = .{ .product_base = try secpTrace(Secp.ProductBase, arena, ethereum.components[3], blocks[3]), .product_scalar = try secpTrace(Secp.ProductScalar, arena, ethereum.components[4], blocks[4]), .linear_base = try secpTrace(Secp.LinearBase, arena, ethereum.components[5], blocks[5]), .linear_scalar = try secpTrace(Secp.LinearScalar, arena, ethereum.components[6], blocks[6]), .point = try secpTrace(SecpConfig.Point, arena, ethereum.components[7], blocks[7]), .split = try secpTrace(SecpConfig.Split, arena, ethereum.components[8], blocks[8]), .scalar = try secpTrace(SecpConfig.ScalarProgram, arena, ethereum.components[9], blocks[9]), .table = try secpTrace(SecpConfig.Table, arena, ethereum.components[10], blocks[10]), .ecdsa = emptyTrace(Secp.EcdsaTrace, arena), .recovery = try secpTrace(SecpConfig.Recovery, arena, ethereum.components[11], blocks[11]), .byte = try secpTrace(SecpConfig.ByteTable, arena, ethereum.components[12], blocks[12]) }, .recovery_caller = if (local_zero) emptyTrace(Secp.RecoveryCallerTrace, arena) else try secpTrace(SecpConfig.RecoveryCaller, arena, ethereum.components[13], blocks[13]), .recovery_caller_local_zero = if (local_zero) try secpTrace(SecpConfig.RecoveryCallerLocalZero, arena, ethereum.components[13], blocks[13]) else null }, .sha_rows = .{ .allocator = arena, .geometry = try ShaRows.Geometry.init(descriptor.statement.sha.call_count), .compression = .{ .allocator = arena, .geometry = try ShaProvider.Geometry.init(descriptor.statement.sha.call_count), .sources = try allocateRows(ShaAirs[0].Row, arena, descriptors[14].log_size), .schedule = try allocateRows(ShaAirs[1].Row, arena, descriptors[15].log_size), .rounds = try allocateRows(ShaAirs[2].Row, arena, descriptors[16].log_size), .feed_forward = try allocateRows(ShaAirs[3].Row, arena, descriptors[17].log_size) }, .callers = try allocateRows(ShaAirs[4].Row, arena, descriptors[18].log_size) } };
    self.witness.extension.keccak_counters.slots = try std.math.divCeil(usize, ethereum.counts.keccak_calls, 2);
    // SHA row arrays place main inputs first, deterministic fixed metadata last.
    // Reconstruct those tails from admitted topology, never source-file bytes.
    const sha_rows = self.witness.sha_rows.tuple();
    inline for (ShaAirs, 0..) |Air, i| {
        if (Air.LOGICAL_INPUT_COUNT != Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT) return error.InvalidV5StagedCallerShaShape;
        const columns = fixed[at..][0..Air.PREPROCESSED_COLUMN_COUNT];
        for (sha_rows[i], 0..) |*row, index| {
            for (columns, 0..) |column, c| row[Air.PHYSICAL_MAIN_COLUMN_COUNT + c] = column.values[committed(index, descriptors[14 + i].log_size)];
        }
        at += Air.PREPROCESSED_COLUMN_COUNT;
    }
    if (at != fixed.len) return error.InvalidV5StagedCallerFixed;
    const logs = try Protocol.columnLogs(arena, &descriptor.statement, .main);
    try Store.readMapped(dir, name, descriptor.scope(), logs, pin, limits.columns, .{ .context = self, .put = Owner.put });
    try self.witness.extension.keccak_counters.validateTotals();
    try requireWitness(&self.witness, descriptor);
    self.counters = try Tables.counter.Set.init(arena);
    try registerCounters(arena, &self.witness, &self.counters);
    return self;
}

/// Counter census from restored authenticated cells, including signed SHA DAG
/// effects. Keccak/signer formulas are the exact shipped caller range requests.
/// This function is transactional: scan all tuples before mutating any target.
pub fn registerCounters(a: std.mem.Allocator, witness: anytype, target: *Tables.counter.Set) !void {
    try visitCallerCounters(false, witness, target);
    try @import("../air/guest_precompile/sha256_lookup_registration.zig").register(a, &witness.sha_rows, target);
    try visitCallerCounters(true, witness, target);
}
fn registerOne(comptime apply: bool, target: *Tables.counter.Set, kind: Tables.schema.Kind, active: M, tuple: []const M) !void {
    const index = try Tables.schema.indexBase(kind, tuple);
    if (apply) target.get(kind).values[index] = target.get(kind).values[index].sub(active);
}
fn visitCallerRow(comptime apply: bool, target: *Tables.counter.Set, row: []const M, comptime Layout: type, comptime count: usize, comptime signer: bool, total_steps: u32, zero_enabled: bool) !bool {
    const active = row[0];
    if (active.isZero()) return false;
    if (!active.eql(M.one())) return error.InvalidV5StagedCallerActive;
    const clock = row[Layout.execution_clock].toU32();
    if (clock == 0 or clock > total_steps) return error.InvalidV5StagedCallerClock;
    const register_clock = try std.math.add(u64, try std.math.mul(u64, clock - 1, 4), 1);
    const rw_clock = register_clock + 1;
    const previous = row[Layout.pointer_previous_clock].toU32();
    if (previous >= register_clock) return error.InvalidV5StagedCallerClock;
    const keep_pointer = !zero_enabled or row[Layout.pointer_register].toU32() != 0;
    if (zero_enabled) {
        const kind: @import("../air/guest_precompile/x0_caller_envelope_v1.zig").Kind = if (signer) .signer else .keccak;
        const envelope = @import("../air/guest_precompile/x0_caller_envelope_v1.zig");
        if (row.len != envelope.mainWidth(kind)) return error.InvalidV5StagedCallerCounters;
        const hints = try @import("../air/x0_local_custody_v1.zig").Hint.forAddress(0, row[Layout.pointer_register].toU32());
        if (!row[envelope.oldWidth(kind)].eql(hints.nonzero) or !row[envelope.oldWidth(kind) + 1].eql(hints.inverse)) return error.InvalidV5StagedCallerCounters;
        if (!keep_pointer) {
            if (previous != 0) return error.NonzeroX0CustodyTransition;
            for (row[Layout.pointer_bytes..][0..4]) |byte| if (!byte.isZero()) return error.NonzeroX0CustodyTransition;
        }
    }
    if (keep_pointer) {
        if (register_clock - previous - 1 >= 1 << 20) return error.InvalidV5StagedCallerClock;
        try registerOne(apply, target, .range_check_20, active, &.{M.fromU64(register_clock - previous - 1)});
    }
    for (0..count) |word| {
        const old = row[if (signer) (if (word < Signer.input_word_count) Layout.input_previous_clocks + word else Layout.output_previous_clocks + word - Signer.input_word_count) else Layout.memory_previous_clocks + word].toU32();
        if (old >= rw_clock) return error.InvalidV5StagedCallerClock;
        if (rw_clock - old - 1 >= 1 << 20) return error.InvalidV5StagedCallerClock;
        try registerOne(apply, target, .range_check_20, active, &.{M.fromU64(rw_clock - old - 1)});
    }
    try registerOne(apply, target, .range_check_8_8, active, row[Layout.span_end_limbs..][0..2]);
    try registerOne(apply, target, .range_check_8_8_4, active, &.{ row[Layout.span_end_limbs + 2], row[Layout.pointer_bytes + 3].mul(M.fromCanonical(4)), row[Layout.span_end_limbs + 3] });
    return true;
}
fn visitCallerCounters(comptime apply: bool, witness: anytype, target: *Tables.counter.Set) !void {
    for (target.counters, 0..) |counter, i| if (counter.kind != @as(Tables.schema.Kind, @enumFromInt(i)) or counter.values.len != Tables.schema.size(counter.kind)) return error.InvalidV5StagedCallerCounters;
    const zero_enabled = witness.extension.circuit_profile.localZeroCustody();
    if ((witness.extension.recovery_caller_local_zero != null) != zero_enabled or witness.extension.keccak_shard.x0_local_custody_version != @intFromBool(zero_enabled)) return error.ChangedV5StagedCallerWitness;
    var k: usize = 0;
    const shard = &witness.extension.keccak_shard;
    for (0..shard.domainSize()) |physical| {
        var row: [KeccakCaller.Layout.main_columns + 2]M = undefined;
        const width = shard.mainColumnCount() - KeccakTrace.Layout.caller;
        for (row[0..width], 0..) |*value, col| value.* = shard.mainColumn(KeccakTrace.Layout.caller + col)[physical];
        if (try visitCallerRow(apply, target, row[0..width], KeccakCaller.Layout, KeccakCaller.word_count, false, witness.total_steps, zero_enabled)) k += 1;
    }
    var s: usize = 0;
    if (witness.extension.recovery_caller_local_zero) |*caller| {
        for (0..caller.domainSize()) |row| {
            const values = caller.mainRow(row);
            if (try visitCallerRow(apply, target, &values, Signer.Layout, Signer.memory_word_count, true, witness.total_steps, zero_enabled)) s += 1;
        }
    } else {
        const caller = &witness.extension.recovery_caller;
        for (0..caller.domainSize()) |row| {
            const values = caller.mainRow(row);
            if (try visitCallerRow(apply, target, &values, Signer.Layout, Signer.memory_word_count, true, witness.total_steps, zero_enabled)) s += 1;
        }
    }
    if (k != witness.statement.ethereum.counts.keccak_calls or s != witness.statement.ethereum.counts.signer_calls) return error.ChangedV5StagedCallerCensus;
}

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Api = Family.ForBackend(Backend);
        pub const Prepared = struct {
            owner: *Owner,
            first: Api.PhysicalFirstRound,
            pub fn deinit(self: *Prepared, a: std.mem.Allocator) void {
                self.first.deinit(a);
                self.owner.deinit();
                self.* = undefined;
            }
        };
        pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, descriptor: *const Descriptor, pin: Pin, limits: Limits) !Prepared {
            const owner = try reconstruct(a, dir, name, descriptor, pin, limits);
            errdefer owner.deinit();
            var first = try Api.commitPhysicalFirstRound(a, &owner.witness, descriptor.total_steps, descriptor.config);
            errdefer first.deinit(a);
            if (!std.meta.eql(first.roots, descriptor.roots) or !std.meta.eql(first.key_id, descriptor.key_id)) return error.V5StagedCallerRootMismatch;
            return .{ .owner = owner, .first = first };
        }
    };
}

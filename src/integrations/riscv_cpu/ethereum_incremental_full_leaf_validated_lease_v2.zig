//! Process-local ownership for one validated SegmentV2 leaf boundary.
//!
//! `PublicDataV2.OwnedValidatedLeaseV2` authenticates one copied canonical
//! wire with independently retained roots. This integration owner adds copied
//! role-aware public slices and runs exactly one outer authority validation.
//! Every later statement/profile/transcript check reuses the opaque frontend
//! lease; no mutable wire slice or serializable fresh capability escapes.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const M31 = stwo_core.fields.m31.M31;
const public_data = frontend.air.public_data;
const public_data_v2 = frontend.air.public_data_v2;
const statement_v2 = frontend.air.statement_v2;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const SERIALIZABLE = false;
pub const DIGEST_IS_ADMISSION = false;
pub const MUTABLE_BORROW_EXPOSED = false;

const IDENTITY_DOMAIN =
    "stwo-zig/ethereum-incremental-full-leaf-validated-lease/v2\x00";

pub const ValidationCountersV2 =
    public_data_v2.PublicDataV2.ValidationCountersV2;
pub const CounterSnapshotV2 =
    public_data_v2.PublicDataV2.ValidationCounterSnapshotV2;

const StorageV2 = struct {
    allocator: std.mem.Allocator,
    public_lease: public_data_v2.PublicDataV2.OwnedValidatedLeaseV2,
    input_words: []u32,
    output_words: []public_data.OutputWord,
    statement: statement_v2.RiscVStatementV2,
    role_aware_public: public_data.PublicData,
};

pub const ValidatedLeaseV2 = struct {
    storage: *StorageV2,
    retained_snapshots: public_data_v2.PublicDataV2.RetainedSnapshots,
    validation_binding_sha256: [32]u8,
    role_public_identity_sha256: [32]u8,
    lease_identity_sha256: [32]u8,
    counters: ?*ValidationCountersV2,

    const Self = @This();

    pub fn initOwned(
        allocator: std.mem.Allocator,
        source_statement: *const statement_v2.RiscVStatementV2,
        source_role_public: *const public_data.PublicData,
        retained_snapshots: public_data_v2.PublicDataV2.RetainedSnapshots,
        validator: anytype,
        counters: ?*ValidationCountersV2,
    ) !Self {
        var public_lease = try public_data_v2.PublicDataV2
            .OwnedValidatedLeaseV2.initRetained(
            allocator,
            &source_statement.public_data,
            retained_snapshots,
            counters,
        );
        errdefer public_lease.deinit();
        const input_words = try allocator.dupe(
            u32,
            source_role_public.io_entries.input_words,
        );
        errdefer allocator.free(input_words);
        const output_words = try allocator.dupe(
            public_data.OutputWord,
            source_role_public.io_entries.output_words,
        );
        errdefer allocator.free(output_words);
        const storage = try allocator.create(StorageV2);
        errdefer allocator.destroy(storage);

        var owned_statement = source_statement.*;
        owned_statement.public_data = public_lease.data().*;
        var owned_role_public = source_role_public.*;
        owned_role_public.io_entries.input_words = input_words;
        owned_role_public.io_entries.output_words = output_words;
        storage.* = .{
            .allocator = allocator,
            .public_lease = public_lease,
            .input_words = input_words,
            .output_words = output_words,
            .statement = owned_statement,
            .role_aware_public = owned_role_public,
        };
        const authority_start = if (counters != null)
            std.time.nanoTimestamp()
        else
            0;
        const validation_binding_sha256 =
            try validator.validateOwnedBoundary(
                &storage.statement,
                &storage.role_aware_public,
            );
        if (counters) |value| value.recordAuthorityValidation(
            elapsedNanoseconds(authority_start),
        );
        const role_identity = rolePublicIdentity(&storage.role_aware_public);
        var result = Self{
            .storage = storage,
            .retained_snapshots = retained_snapshots,
            .validation_binding_sha256 = validation_binding_sha256,
            .role_public_identity_sha256 = role_identity,
            .lease_identity_sha256 = undefined,
            .counters = counters,
        };
        result.lease_identity_sha256 = leaseIdentity(&result);
        try result.validateBorrowed();
        return result;
    }

    pub fn deinit(self: *Self) void {
        const storage = self.storage;
        const allocator = storage.allocator;
        storage.public_lease.deinit();
        allocator.free(storage.output_words);
        allocator.free(storage.input_words);
        allocator.destroy(storage);
        self.* = undefined;
    }

    pub fn validateBorrowed(self: *const Self) !void {
        const storage = self.storage;
        try storage.statement.public_data.validate();
        const role = &storage.role_aware_public;
        if (storage.statement.public_data.words().ptr !=
            storage.public_lease.ownedWords().ptr or
            storage.statement.public_data.words().len !=
                storage.public_lease.ownedWords().len or
            storage.statement.public_data.retained_snapshots == null or
            !std.meta.eql(
                storage.statement.public_data.retained_snapshots.?,
                self.retained_snapshots,
            ) or
            role.io_entries.input_words.ptr != storage.input_words.ptr or
            role.io_entries.input_words.len != storage.input_words.len or
            role.io_entries.output_words.ptr != storage.output_words.ptr or
            role.io_entries.output_words.len != storage.output_words.len or
            std.mem.allEqual(u8, &self.validation_binding_sha256, 0) or
            std.mem.allEqual(u8, &self.role_public_identity_sha256, 0) or
            !std.mem.eql(
                u8,
                &self.lease_identity_sha256,
                &leaseIdentity(self),
            ))
        {
            return error.InvalidIncrementalFullLeafValidatedLeaseV2;
        }
    }

    pub fn statement(
        self: *const Self,
    ) *const statement_v2.RiscVStatementV2 {
        return &self.storage.statement;
    }

    pub fn rolePublic(self: *const Self) *const public_data.PublicData {
        return &self.storage.role_aware_public;
    }

    pub fn canonicalWords(self: *const Self) []const M31 {
        return self.storage.public_lease.ownedWords();
    }
};

fn leaseIdentity(value: *const ValidatedLeaseV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hashInt(&hash, u64, value.canonicalWords().len);
    for (value.statement().public_data.wireId()) |word|
        hashInt(&hash, u32, word);
    for (value.statement().authority_id) |word| hashInt(&hash, u32, word);
    hashRetained(&hash, value.retained_snapshots.entry);
    hashRetained(&hash, value.retained_snapshots.exit);
    hash.update(&value.validation_binding_sha256);
    hash.update(&value.role_public_identity_sha256);
    return hash.finalResult();
}

fn rolePublicIdentity(value: *const public_data.PublicData) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/role-aware-public-owned-lease/v2\x00");
    hashInt(&hash, u32, value.initial_pc);
    hashInt(&hash, u32, value.final_pc);
    hashInt(&hash, u32, value.clock);
    for (value.initial_regs) |word| hashInt(&hash, u32, word);
    for (value.final_regs) |word| hashInt(&hash, u32, word);
    for (value.reg_last_clock) |word| hashInt(&hash, u32, word);
    inline for (.{
        value.program_root,
        value.initial_rw_root,
        value.final_rw_root,
    }) |optional| {
        hashInt(&hash, u8, @intFromBool(optional != null));
        hashInt(&hash, u32, optional orelse 0);
    }
    if (value.completion) |completion| {
        hashInt(&hash, u8, 1);
        hashInt(&hash, u32, @intFromEnum(completion.kind));
        hashInt(&hash, u32, completion.address);
        hashInt(&hash, u32, completion.value);
        hashInt(&hash, u32, completion.clock);
    } else hashInt(&hash, u8, 0);
    const io = value.io_entries;
    hashInt(&hash, u32, io.input_start);
    hashInt(&hash, u32, io.input_len);
    hashInt(&hash, u64, io.input_words.len);
    for (io.input_words) |word| hashInt(&hash, u32, word);
    hashInt(&hash, u32, io.output_len);
    hashInt(&hash, u32, io.output_len_addr);
    hashInt(&hash, u32, io.output_data_addr);
    hashInt(&hash, u64, io.output_words.len);
    for (io.output_words) |word| {
        hashInt(&hash, u32, word.addr);
        hashInt(&hash, u32, word.value);
        hashInt(&hash, u32, word.clock);
    }
    return hash.finalResult();
}

fn elapsedNanoseconds(start: i128) u64 {
    const elapsed = std.time.nanoTimestamp() - start;
    if (elapsed <= 0) return 0;
    return std.math.cast(u64, elapsed) orelse std.math.maxInt(u64);
}

fn hashRetained(
    hash: *std.crypto.hash.sha2.Sha256,
    value: frontend.recursion.segment_statement_v2.SnapshotIdentity,
) void {
    for (value.id) |word| hashInt(hash, u32, word);
    hashInt(hash, u32, value.count);
    hashInt(hash, u32, value.root);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or SERIALIZABLE or
        DIGEST_IS_ADMISSION or MUTABLE_BORROW_EXPOSED)
    {
        @compileError("validated SegmentV2 lease drifted");
    }
}

//! Exact 12-placement trace plan and live baseline materializer for Ethereum h1.
//!
//! `PlanV1` is custody-only and therefore never publishes a proof authority.
//! `MaterializedV1` is stronger: its only constructor revalidates the two live
//! default Poseidon V4 verifier capabilities and materializes every logical
//! row and shared-provider call.  A projected-candidate constructor is
//! intentionally absent until that verifier mints an equivalent live capture.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const ingress_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_ingress_v1.zig");
const manifest_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_manifest_v1.zig");
const leaf_witness_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_leaf_witness_v1.zig");

const recursion = frontend.recursion;
const link_program_mod = recursion.ethereum_leaf_link_program_v1;
const child_program_mod = recursion.ethereum_leaf_child_field_program_v1;
const source_air = recursion.air.ethereum_leaf_link_source_v1;
const projection_air = recursion.air.ethereum_leaf_link_projection_v1;
const router_air = recursion.air.ethereum_leaf_child_field_router_v1;
const hash_witness = recursion.air.vm_public_claim_hash_witness;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const M31 = stwo_core.fields.m31.M31;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const PLAN_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-materialization-plan/v1\x00";
pub const MATERIALIZED_DOMAIN =
    "stwo-zig/typed-air/ethereum-poseidon-h1-materialized/v1\x00";

pub const FreshnessKindV1 = enum(u8) {
    default_poseidon_v4 = 1,
    projected_candidate_v1 = 2,
};

/// Default verifier adapter.  The generic materializer below consumes this
/// method surface rather than the concrete V4 type; a projected candidate may
/// implement the same surface only after its own cold verifier has minted the
/// two capture views and matching h1 custody.
pub const DefaultPoseidonV4AdapterV1 = struct {
    fresh: *const ingress_mod.FreshIngressV1,
    input: ingress_mod.FreshMintInputV1,

    pub fn validateForH1(
        self: DefaultPoseidonV4AdapterV1,
        allocator: std.mem.Allocator,
    ) !void {
        try self.fresh.validateAgainst(allocator, self.input);
    }

    pub fn custody(
        self: DefaultPoseidonV4AdapterV1,
    ) *const ingress_mod.CustodyV1 {
        return &self.fresh.custody;
    }

    pub fn freshnessKind(_: DefaultPoseidonV4AdapterV1) FreshnessKindV1 {
        return .default_poseidon_v4;
    }

    pub fn captureViews(
        self: DefaultPoseidonV4AdapterV1,
    ) [2]leaf_witness_mod.FreshCaptureViewV1 {
        return .{
            leaf_witness_mod.captureViewFromDefault(self.input.left),
            leaf_witness_mod.captureViewFromDefault(self.input.right),
        };
    }
};

pub const PlanV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    production_activation: bool = PRODUCTION_ACTIVATION,
    freshness_kind: FreshnessKindV1,
    reserved: [2]u8 = .{ 0, 0 },
    ingress_authority_sha256: [32]u8,
    active_rows: [manifest_mod.COMPONENT_COUNT]u32,
    log_sizes: manifest_mod.LogSizes,
    manifest: manifest_mod.Manifest,
    identity_sha256: [32]u8,

    pub fn initDefault(
        custody: *const ingress_mod.CustodyV1,
    ) !PlanV1 {
        return initForFreshness(custody, .default_poseidon_v4);
    }

    fn initForFreshness(
        custody: *const ingress_mod.CustodyV1,
        freshness_kind: FreshnessKindV1,
    ) !PlanV1 {
        try custody.validate();
        const active_rows = try activeRows(custody);
        var log_sizes: manifest_mod.LogSizes = undefined;
        for (active_rows, &log_sizes) |count, *log_size|
            log_size.* = try traceLogSize(count);
        const manifest = try manifest_mod.build(
            log_sizes,
            custody.identity_sha256,
        );
        var result = PlanV1{
            .freshness_kind = freshness_kind,
            .ingress_authority_sha256 = custody.identity_sha256,
            .active_rows = active_rows,
            .log_sizes = log_sizes,
            .manifest = manifest,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = planIdentity(&result);
        try result.validateAgainst(custody);
        return result;
    }

    pub fn validate(self: *const PlanV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.production_activation or
            (self.freshness_kind != .default_poseidon_v4 and
                self.freshness_kind != .projected_candidate_v1) or
            !std.mem.allEqual(u8, &self.reserved, 0) or
            std.mem.allEqual(u8, &self.ingress_authority_sha256, 0))
        {
            return error.InvalidEthereumPoseidonH1MaterializationPlan;
        }
        try self.manifest.validate();
        if (!std.mem.eql(
            u8,
            &self.manifest.ingress_authority_sha256,
            &self.ingress_authority_sha256,
        ) or !std.meta.eql(self.log_sizes, self.manifest.log_sizes)) {
            return error.InvalidEthereumPoseidonH1MaterializationPlan;
        }
        for (self.active_rows, self.log_sizes, 0..) |count, log_size, row| {
            if (count == 0 or log_size != try traceLogSize(count) or
                count > (@as(u64, 1) << @intCast(log_size)) or
                self.manifest.roster_rows[row] != row)
            {
                return error.InvalidEthereumPoseidonH1MaterializationPlan;
            }
        }
        var provider_rows: u32 = 0;
        for (manifest_mod.keyIndex(.left_metadata_hash)..manifest_mod.keyIndex(.poseidon2)) |row| {
            provider_rows = try checkedAdd(provider_rows, self.active_rows[row]);
        }
        if (provider_rows != self.active_rows[
            manifest_mod.keyIndex(.poseidon2)
        ] or !std.mem.eql(u8, &self.identity_sha256, &planIdentity(self))) {
            return error.InvalidEthereumPoseidonH1MaterializationPlan;
        }
    }

    pub fn validateAgainst(
        self: *const PlanV1,
        custody: *const ingress_mod.CustodyV1,
    ) !void {
        try self.validate();
        try custody.validate();
        if (!std.mem.eql(
            u8,
            &self.ingress_authority_sha256,
            &custody.identity_sha256,
        ) or !std.meta.eql(self.active_rows, try activeRows(custody))) {
            return error.EthereumPoseidonH1MaterializationPlanMismatch;
        }
    }

    pub fn requireProduction(self: *const PlanV1) !void {
        try self.validate();
        if (!PRODUCTION_ACTIVATION)
            return error.EthereumPoseidonH1MaterializationUnavailable;
    }
};

pub const MaterializedV1 = struct {
    allocator: std.mem.Allocator,
    plan: PlanV1,
    link_program: link_program_mod.ProgramV1,
    left: leaf_witness_mod.WitnessV1,
    right: leaf_witness_mod.WitnessV1,
    source_rows: []source_air.Row,
    projection_rows: []projection_air.Row,
    child_router_rows: []router_air.Row,
    poseidon_calls: []poseidon2_air.Call,
    identity_sha256: [32]u8,

    pub fn initFromDefaultPoseidonV4(
        allocator: std.mem.Allocator,
        fresh: *const ingress_mod.FreshIngressV1,
        input: ingress_mod.FreshMintInputV1,
    ) !MaterializedV1 {
        return initFromVerifierMinted(allocator, DefaultPoseidonV4AdapterV1{
            .fresh = fresh,
            .input = input,
        });
    }

    /// Generic structural core. `verifier_minted` must expose
    /// `validateForH1`, `custody`, `freshnessKind`, and `captureViews`.  The
    /// materializer invokes the validation edge first and retains no borrowed
    /// digest as a substitute for it.
    pub fn initFromVerifierMinted(
        allocator: std.mem.Allocator,
        verifier_minted: anytype,
    ) !MaterializedV1 {
        try verifier_minted.validateForH1(allocator);
        const custody = verifier_minted.custody();
        const captures = verifier_minted.captureViews();
        const plan = try PlanV1.initForFreshness(
            custody,
            verifier_minted.freshnessKind(),
        );
        var link_program = try link_program_mod.ProgramV1.init(allocator);
        errdefer link_program.deinit();
        var left = try leaf_witness_mod.WitnessV1.initFromFreshCapture(
            allocator,
            &link_program,
            captures[0],
            &custody.children[0],
            &custody.h1_profile,
        );
        errdefer left.deinit();
        var right = try leaf_witness_mod.WitnessV1.initFromFreshCapture(
            allocator,
            &link_program,
            captures[1],
            &custody.children[1],
            &custody.h1_profile,
        );
        errdefer right.deinit();

        const source_rows = try concatRows(
            source_air.Row,
            allocator,
            left.source_rows,
            right.source_rows,
        );
        errdefer allocator.free(source_rows);
        const projection_rows = try concatRows(
            projection_air.Row,
            allocator,
            left.projection_rows,
            right.projection_rows,
        );
        errdefer allocator.free(projection_rows);
        const child_router_rows = try concatRows(
            router_air.Row,
            allocator,
            left.child_router_rows,
            right.child_router_rows,
        );
        errdefer allocator.free(child_router_rows);
        const poseidon_calls = try allocator.alloc(
            poseidon2_air.Call,
            left.poseidonCallCount() + right.poseidonCallCount(),
        );
        errdefer allocator.free(poseidon_calls);
        try left.appendPoseidonCallsInto(
            poseidon_calls[0..left.poseidonCallCount()],
        );
        try right.appendPoseidonCallsInto(
            poseidon_calls[left.poseidonCallCount()..],
        );

        var result = MaterializedV1{
            .allocator = allocator,
            .plan = plan,
            .link_program = link_program,
            .left = left,
            .right = right,
            .source_rows = source_rows,
            .projection_rows = projection_rows,
            .child_router_rows = child_router_rows,
            .poseidon_calls = poseidon_calls,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = materializedIdentity(&result);
        try result.validateAgainstVerifierMinted(verifier_minted);
        return result;
    }

    pub fn deinit(self: *MaterializedV1) void {
        self.allocator.free(self.poseidon_calls);
        self.allocator.free(self.child_router_rows);
        self.allocator.free(self.projection_rows);
        self.allocator.free(self.source_rows);
        self.right.deinit();
        self.left.deinit();
        self.link_program.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const MaterializedV1,
        fresh: *const ingress_mod.FreshIngressV1,
        input: ingress_mod.FreshMintInputV1,
    ) !void {
        return self.validateAgainstVerifierMinted(DefaultPoseidonV4AdapterV1{
            .fresh = fresh,
            .input = input,
        });
    }

    pub fn validateAgainstVerifierMinted(
        self: *const MaterializedV1,
        verifier_minted: anytype,
    ) !void {
        try verifier_minted.validateForH1(self.allocator);
        const custody = verifier_minted.custody();
        const captures = verifier_minted.captureViews();
        if (self.plan.freshness_kind != verifier_minted.freshnessKind())
            return error.EthereumPoseidonH1MaterializationMismatch;
        try self.validateStructural(custody);
        try self.link_program.validate();
        try self.left.validateAgainstFreshCapture(
            &self.link_program,
            captures[0],
            &custody.children[0],
            &custody.h1_profile,
        );
        try self.right.validateAgainstFreshCapture(
            &self.link_program,
            captures[1],
            &custody.children[1],
            &custody.h1_profile,
        );
    }

    /// Revalidates the owned post-freshness snapshot without pretending to
    /// recreate the verifier capability. Proof entrypoints must call the
    /// generic verifier-minted method immediately before this structural path.
    pub fn validateStructural(
        self: *const MaterializedV1,
        custody: *const ingress_mod.CustodyV1,
    ) !void {
        try self.plan.validateAgainst(custody);
        try self.link_program.validate();
        if (!isConcatenation(
            source_air.Row,
            self.source_rows,
            self.left.source_rows,
            self.right.source_rows,
        ) or !isConcatenation(
            projection_air.Row,
            self.projection_rows,
            self.left.projection_rows,
            self.right.projection_rows,
        ) or !isConcatenation(
            router_air.Row,
            self.child_router_rows,
            self.left.child_router_rows,
            self.right.child_router_rows,
        )) return error.EthereumPoseidonH1MaterializationMismatch;
        var expected_calls = try self.allocator.alloc(
            poseidon2_air.Call,
            self.poseidon_calls.len,
        );
        defer self.allocator.free(expected_calls);
        try self.left.appendPoseidonCallsInto(
            expected_calls[0..self.left.poseidonCallCount()],
        );
        try self.right.appendPoseidonCallsInto(
            expected_calls[self.left.poseidonCallCount()..],
        );
        if (!sliceEqual(
            poseidon2_air.Call,
            self.poseidon_calls,
            expected_calls,
        ) or !countsMatch(self) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &materializedIdentity(self),
        )) return error.EthereumPoseidonH1MaterializationMismatch;
    }
};

fn activeRows(custody: *const ingress_mod.CustodyV1) ![12]u32 {
    const metadata = try hashRowCount(
        recursion.segment_leaf_local_authority_v3.METADATA_IDENTITY_WORDS,
    );
    const link = try hashRowCount(
        recursion.segment_leaf_local_verified_link_v3.IDENTITY_WORDS,
    );
    const left_authority = try hashRowCount(
        custody.children[0].child_authority_word_count,
    );
    const right_authority = try hashRowCount(
        custody.children[1].child_authority_word_count,
    );
    const receipt = try hashRowCount(child_program_mod.RECEIPT_WORD_COUNT);
    const source = try checkedMul(2, link_program_mod.SOURCE_ROW_COUNT);
    const projection = try checkedMul(2, link_program_mod.PROJECTION_ROW_COUNT);
    const router = try checkedAdd(
        custody.children[0].child_router_row_count,
        custody.children[1].child_router_row_count,
    );
    var result = [12]u32{
        source,
        projection,
        router,
        metadata,
        link,
        left_authority,
        receipt,
        metadata,
        link,
        right_authority,
        receipt,
        0,
    };
    for (result[3..11]) |count| result[11] = try checkedAdd(result[11], count);
    return result;
}

fn countsMatch(value: *const MaterializedV1) bool {
    const expected = value.plan.active_rows;
    const actual = [12]usize{
        value.source_rows.len,
        value.projection_rows.len,
        value.child_router_rows.len,
        value.left.metadata_hash.logical_rows.len,
        value.left.link_hash.logical_rows.len,
        value.left.authority_hash.len,
        value.left.receipt_hash.len,
        value.right.metadata_hash.logical_rows.len,
        value.right.link_hash.logical_rows.len,
        value.right.authority_hash.len,
        value.right.receipt_hash.len,
        value.poseidon_calls.len,
    };
    for (actual, expected) |actual_count, expected_count|
        if (actual_count != expected_count) return false;
    return true;
}

fn planIdentity(value: *const PlanV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PLAN_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.production_activation));
    hashInt(&hash, u8, @intFromEnum(value.freshness_kind));
    hash.update(&value.reserved);
    hash.update(&value.ingress_authority_sha256);
    for (value.active_rows) |count| hashInt(&hash, u32, count);
    for (value.log_sizes) |log_size| hashInt(&hash, u32, log_size);
    hash.update(&value.manifest.seal);
    return hash.finalResult();
}

fn materializedIdentity(value: *const MaterializedV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(MATERIALIZED_DOMAIN);
    hash.update(&value.plan.identity_sha256);
    hashRows(&hash, value.source_rows);
    hashRows(&hash, value.projection_rows);
    hashRows(&hash, value.child_router_rows);
    hashRows(&hash, value.left.metadata_hash.logical_rows);
    hashRows(&hash, value.left.link_hash.logical_rows);
    hashRows(&hash, value.left.authority_hash);
    hashRows(&hash, value.left.receipt_hash);
    hashRows(&hash, value.right.metadata_hash.logical_rows);
    hashRows(&hash, value.right.link_hash.logical_rows);
    hashRows(&hash, value.right.authority_hash);
    hashRows(&hash, value.right.receipt_hash);
    for (value.poseidon_calls) |call| {
        for (call.input) |word| hashInt(&hash, u32, word);
        hashInt(&hash, u8, @intFromBool(call.wide));
        hashInt(&hash, u8, @intFromBool(call.io));
        hashInt(&hash, u8, @intFromBool(call.narrow_output != null));
        hashInt(&hash, u32, call.narrow_output orelse 0);
    }
    return hash.finalResult();
}

fn hashRows(hash: *Sha256, rows: anytype) void {
    hashInt(hash, u64, rows.len);
    for (rows) |row| for (row) |word| hashInt(hash, u32, word.toU32());
}

fn concatRows(
    comptime T: type,
    allocator: std.mem.Allocator,
    left: []const T,
    right: []const T,
) ![]T {
    const count = std.math.add(usize, left.len, right.len) catch
        return error.ArithmeticOverflow;
    const result = try allocator.alloc(T, count);
    @memcpy(result[0..left.len], left);
    @memcpy(result[left.len..], right);
    return result;
}

fn isConcatenation(
    comptime T: type,
    actual: []const T,
    left: []const T,
    right: []const T,
) bool {
    return actual.len == left.len + right.len and
        sliceEqual(T, actual[0..left.len], left) and
        sliceEqual(T, actual[left.len..], right);
}

fn sliceEqual(comptime T: type, left: []const T, right: []const T) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!std.meta.eql(lhs, rhs)) return false;
    return true;
}

fn hashRowCount(word_count: anytype) !u32 {
    const with_padding = std.math.add(usize, @intCast(word_count), 1) catch
        return error.ArithmeticOverflow;
    return @intCast(std.math.divCeil(usize, with_padding, hash_witness.RATE) catch
        return error.ArithmeticOverflow);
}

fn traceLogSize(active_rows: anytype) !u32 {
    const rows: usize = @intCast(active_rows);
    if (rows == 0) return error.InvalidEthereumPoseidonH1MaterializationPlan;
    const padded = std.math.ceilPowerOfTwo(usize, rows) catch
        return error.ArithmeticOverflow;
    const log_size: u32 = @intCast(std.math.log2_int(usize, padded));
    if (log_size == 0 or log_size >= 31)
        return error.InvalidEthereumPoseidonH1MaterializationPlan;
    return log_size;
}

fn checkedAdd(left: anytype, right: anytype) !u32 {
    return std.math.add(u32, @intCast(left), @intCast(right)) catch
        error.ArithmeticOverflow;
}

fn checkedMul(left: anytype, right: anytype) !u32 {
    return std.math.mul(u32, @intCast(left), @intCast(right)) catch
        error.ArithmeticOverflow;
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub const testing = struct {
    pub fn resealPlan(value: *PlanV1) void {
        value.identity_sha256 = planIdentity(value);
    }
};

comptime {
    if (manifest_mod.COMPONENT_COUNT != 12 or
        manifest_mod.HASH_PLACEMENT_COUNT != 8 or
        link_program_mod.SOURCE_ROW_COUNT != 842 or
        link_program_mod.PROJECTION_ROW_COUNT != 930 or
        child_program_mod.RECEIPT_WORD_COUNT != 64 or PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum Poseidon h1 materializer geometry drifted");
    }
}

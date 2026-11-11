//! Backend-neutral exact-work receipts for OODS component execution.
//!
//! OODS mask construction and point composition dispatch through frontend-
//! owned dynamic component vtables. Each owner therefore publishes a cold
//! profile derived from the same one-row evaluator it executes. The prover
//! records that profile only after the corresponding vtable call succeeds,
//! and publishes one aggregate receipt only after the whole operation has
//! completed. Ordinary proving never enters this module.

const std = @import("std");
const circle = @import("stwo_core").circle;
const verifier_types = @import("stwo_core").verifier_types;
const composition_work = @import("composition_work.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA_VERSION: u16 = 1;
pub const DIGEST_DOMAIN = "stwo-zig/prover/oods-work/v1\x00";
pub const COMPONENT_DOMAIN = "stwo-zig/prover/oods-component-work/v1\x00";

pub const Digest = [Sha256.digest_length]u8;
pub const FieldOperations = composition_work.FieldOperations;

pub const Error = error{
    CountOverflow,
    DuplicateCompletion,
    InvalidComponentProfile,
    InvalidReceipt,
};

pub const Site = enum(u8) {
    mask_points = 1,
    constraint_evaluation = 2,
};

/// Owner-produced exact work for both OODS vtable methods of one component.
/// `formula_operations` is the source-identical one-row evaluator profile;
/// point folding, secure-coordinate reconstruction, quotient division, and
/// global random-root accumulation are bound explicitly below.
pub const ComponentProfile = struct {
    schema_version: u16 = SCHEMA_VERSION,
    kind: composition_work.ComponentKind,
    composition_profile_digest: composition_work.Digest,
    trace_log_size: u32,
    component_log_degree_bound: u32,
    max_log_degree_bound: u32,
    constraint_count: u64,
    partial_evaluation_count: u64,
    uses_previous_row: bool,
    formula_operations: FieldOperations,
    mask_operations: FieldOperations,
    constraint_operations: FieldOperations,
    profile_digest: Digest,

    pub fn init(
        source: *const composition_work.ComponentProfile,
        trace_log_size: u32,
        max_log_degree_bound: u32,
        partial_evaluation_count: usize,
        uses_previous_row: bool,
    ) (Error || composition_work.Error)!ComponentProfile {
        try source.validate();
        if (trace_log_size == 0 or
            trace_log_size >= circle.M31_CIRCLE_LOG_ORDER or
            source.evaluation_log_size <= trace_log_size or
            max_log_degree_bound < trace_log_size or
            max_log_degree_bound >= circle.M31_CIRCLE_LOG_ORDER or
            !std.meta.eql(source.setup, FieldOperations{}))
        {
            return error.InvalidComponentProfile;
        }
        const formula_operations = try composition_work.addOperations(
            .{
                .additions = source.expression_additions_per_row,
                .multiplications = source.expression_multiplications_per_row,
            },
            .{
                .additions = source.constraint_additions_per_row,
                .multiplications = source.constraint_multiplications_per_row,
            },
        );
        const partial_count = std.math.cast(u64, partial_evaluation_count) orelse
            return error.CountOverflow;
        var result = ComponentProfile{
            .kind = source.kind,
            .composition_profile_digest = source.profile_digest,
            .trace_log_size = trace_log_size,
            .component_log_degree_bound = source.evaluation_log_size,
            .max_log_degree_bound = max_log_degree_bound,
            .constraint_count = source.constraint_count,
            .partial_evaluation_count = partial_count,
            .uses_previous_row = uses_previous_row,
            .formula_operations = formula_operations,
            .mask_operations = try maskPointWork(
                max_log_degree_bound,
                uses_previous_row,
            ),
            .constraint_operations = try constraintPointWork(
                formula_operations,
                trace_log_size,
                max_log_degree_bound,
                source.constraint_count,
                partial_count,
            ),
            .profile_digest = undefined,
        };
        try result.validateShape();
        result.profile_digest = componentDigest(&result);
        return result;
    }

    pub fn validate(self: *const ComponentProfile) Error!void {
        try self.validateShape();
        const expected_mask = try maskPointWork(
            self.max_log_degree_bound,
            self.uses_previous_row,
        );
        const expected_constraints = try constraintPointWork(
            self.formula_operations,
            self.trace_log_size,
            self.max_log_degree_bound,
            self.constraint_count,
            self.partial_evaluation_count,
        );
        if (!std.meta.eql(expected_mask, self.mask_operations) or
            !std.meta.eql(expected_constraints, self.constraint_operations) or
            !std.mem.eql(u8, &self.profile_digest, &componentDigest(self)))
        {
            return error.InvalidComponentProfile;
        }
    }

    fn validateShape(self: *const ComponentProfile) Error!void {
        if (self.schema_version != SCHEMA_VERSION or
            digestIsZero(self.composition_profile_digest) or
            self.trace_log_size == 0 or
            self.trace_log_size >= circle.M31_CIRCLE_LOG_ORDER or
            self.component_log_degree_bound <= self.trace_log_size or
            self.max_log_degree_bound < self.trace_log_size or
            self.max_log_degree_bound >= circle.M31_CIRCLE_LOG_ORDER or
            self.constraint_count == 0 or
            self.formula_operations.inversions != 0)
        {
            return error.InvalidComponentProfile;
        }
    }
};

/// Pointer-free proof-boundary receipt. Component and coordinator work remain
/// separate so a source mutation cannot move arithmetic across trust owners.
pub const Receipt = struct {
    schema_version: u16 = SCHEMA_VERSION,
    site: Site,
    component_count: u32,
    constraint_count: u64,
    component_operations: FieldOperations,
    coordinator_operations: FieldOperations,
    operations: FieldOperations,
    authority_digest: Digest,
    receipt_digest: Digest,

    pub fn validate(self: *const Receipt) Error!void {
        if (self.schema_version != SCHEMA_VERSION or self.component_count == 0 or
            self.constraint_count == 0 or digestIsZero(self.authority_digest))
        {
            return error.InvalidReceipt;
        }
        if (self.site == .mask_points and
            !std.meta.eql(self.coordinator_operations, FieldOperations{}))
        {
            return error.InvalidReceipt;
        }
        const expected = try addOperations(
            self.component_operations,
            self.coordinator_operations,
        );
        if (!std.meta.eql(expected, self.operations) or
            !std.mem.eql(u8, &self.receipt_digest, &receiptDigest(self)))
        {
            return error.InvalidReceipt;
        }
    }
};

pub const Builder = struct {
    site: Site,
    component_count: u32 = 0,
    constraint_count: u64 = 0,
    component_operations: FieldOperations = .{},
    coordinator_operations: FieldOperations = .{},
    authority: Sha256,

    pub fn init(site: Site) Builder {
        var authority = Sha256.init(.{});
        authority.update(DIGEST_DOMAIN);
        hashInt(&authority, u16, SCHEMA_VERSION);
        hashInt(&authority, u8, @intFromEnum(site));
        return .{ .site = site, .authority = authority };
    }

    pub fn addComponent(
        self: *Builder,
        ordinal: usize,
        profile: *const ComponentProfile,
    ) Error!void {
        try profile.validate();
        const encoded_ordinal = std.math.cast(u32, ordinal) orelse
            return error.CountOverflow;
        if (encoded_ordinal != self.component_count)
            return error.InvalidComponentProfile;
        const operations = switch (self.site) {
            .mask_points => profile.mask_operations,
            .constraint_evaluation => profile.constraint_operations,
        };
        const next_component_count = std.math.add(u32, self.component_count, 1) catch
            return error.CountOverflow;
        const next_constraint_count = try add(
            self.constraint_count,
            profile.constraint_count,
        );
        const next_component_operations = try addOperations(
            self.component_operations,
            operations,
        );
        self.component_count = next_component_count;
        self.constraint_count = next_constraint_count;
        self.component_operations = next_component_operations;
        hashInt(&self.authority, u32, encoded_ordinal);
        self.authority.update(&profile.profile_digest);
    }

    /// Adds non-component arithmetic only after the named coordinator path
    /// has completed. Mask construction has no field-arithmetic coordinator
    /// contribution and rejects one categorically.
    pub fn addCoordinator(
        self: *Builder,
        label: []const u8,
        operations: FieldOperations,
        geometry: []const u64,
    ) Error!void {
        if (self.site != .constraint_evaluation)
            return error.InvalidReceipt;
        const next_operations = try addOperations(
            self.coordinator_operations,
            operations,
        );
        self.coordinator_operations = next_operations;
        hashBytes(&self.authority, label);
        hashInt(&self.authority, u32, std.math.cast(u32, geometry.len) orelse
            return error.CountOverflow);
        for (geometry) |value| hashInt(&self.authority, u64, value);
        hashOperations(&self.authority, operations);
    }

    pub fn finish(self: *Builder) Error!Receipt {
        if (self.component_count == 0 or self.constraint_count == 0)
            return error.InvalidReceipt;
        var authority_digest: Digest = undefined;
        self.authority.final(&authority_digest);
        var result = Receipt{
            .site = self.site,
            .component_count = self.component_count,
            .constraint_count = self.constraint_count,
            .component_operations = self.component_operations,
            .coordinator_operations = self.coordinator_operations,
            .operations = try addOperations(
                self.component_operations,
                self.coordinator_operations,
            ),
            .authority_digest = authority_digest,
            .receipt_digest = undefined,
        };
        result.receipt_digest = receiptDigest(&result);
        try result.validate();
        return result;
    }
};

/// Fail-atomic one-call handoff. Missing or malformed owner authority leaves
/// this empty; a duplicate publication is always an error.
pub const Capture = struct {
    receipt: ?Receipt = null,

    pub fn publish(self: *Capture, receipt: Receipt) Error!void {
        try receipt.validate();
        if (self.receipt != null) return error.DuplicateCompletion;
        self.receipt = receipt;
    }
};

/// Exact coordinator work executed by `extractCompositionOodsEvalWithSplit`:
/// one four-coordinate reconstruction per chunk, followed by the binary
/// split-reconstruction tree and its point-doubling factors.
pub fn compositionExtractionWork(
    composition_log_size: u32,
    split_depth: u32,
) Error!FieldOperations {
    if (split_depth == 0 or
        split_depth > verifier_types.MAX_COMPOSITION_LOG_SPLIT or
        composition_log_size <= split_depth)
    {
        return error.InvalidReceipt;
    }
    const chunk_count = @as(u64, 1) << @intCast(split_depth);
    var result = try partialEvaluationWork(chunk_count);
    var active = chunk_count;
    var parent_log = composition_log_size - split_depth + 1;
    while (active > 1) {
        result = try addOperations(
            result,
            try pointDoublingWork(parent_log - 2),
        );
        const pairs = active / 2;
        result = try addOperations(result, .{
            .additions = pairs,
            .multiplications = pairs,
        });
        active = pairs;
        parent_log = std.math.add(u32, parent_log, 1) catch
            return error.CountOverflow;
    }
    return result;
}

fn maskPointWork(
    max_log_degree_bound: u32,
    uses_previous_row: bool,
) Error!FieldOperations {
    if (!uses_previous_row) return .{};
    return addOperations(
        try canonicCosetMaterializationWork(max_log_degree_bound),
        pointAdditionWork(1),
    );
}

fn constraintPointWork(
    formula_operations: FieldOperations,
    trace_log_size: u32,
    max_log_degree_bound: u32,
    constraint_count: u64,
    partial_evaluation_count: u64,
) Error!FieldOperations {
    if (trace_log_size == 0 or
        trace_log_size >= circle.M31_CIRCLE_LOG_ORDER or
        max_log_degree_bound < trace_log_size or
        max_log_degree_bound >= circle.M31_CIRCLE_LOG_ORDER or
        constraint_count == 0 or formula_operations.inversions != 0)
    {
        return error.InvalidComponentProfile;
    }
    var result = try partialEvaluationWork(partial_evaluation_count);
    result = try addOperations(
        result,
        try pointDoublingWork(max_log_degree_bound - trace_log_size),
    );
    result = try addOperations(
        result,
        try canonicCosetMaterializationWork(trace_log_size),
    );
    // `cosetVanishing`: two circle additions, then log_size-1 doubleX calls.
    result = try addOperations(result, pointAdditionWork(2));
    result = try addOperations(result, .{
        .additions = try mul(trace_log_size - 1, 2),
        .multiplications = trace_log_size - 1,
        .inversions = 1,
    });
    result = try addOperations(result, formula_operations);
    // Each constraint is multiplied by the shared denominator before the
    // formula profile's already-counted random-root accumulation.
    result = try addOperations(result, .{
        .multiplications = constraint_count,
    });
    return result;
}

fn partialEvaluationWork(count: u64) Error!FieldOperations {
    return .{
        .additions = try mul(count, 3),
        .multiplications = try mul(count, 3),
    };
}

fn pointDoublingWork(count: u32) Error!FieldOperations {
    return .{
        .additions = try mul(count, 2),
        .multiplications = try mul(count, 4),
    };
}

fn pointAdditionWork(count: u64) FieldOperations {
    return .{
        .additions = count * 2,
        .multiplications = count * 4,
    };
}

/// `CanonicCoset.new` materializes initial, step, and half-step through
/// `CirclePointIndex.toPoint`. For canonical odds cosets all three indices are
/// powers of two, hence each executes exactly one circle addition. Keep this
/// cold tally integer-only: constructing a coset here would repeat the field
/// arithmetic being attributed and perturb profiled stage timings.
fn canonicCosetMaterializationWork(log_size: u32) Error!FieldOperations {
    if (log_size == 0 or log_size >= circle.M31_CIRCLE_LOG_ORDER)
        return error.InvalidComponentProfile;
    return pointAdditionWork(3);
}

fn addOperations(lhs: FieldOperations, rhs: FieldOperations) Error!FieldOperations {
    return .{
        .additions = try add(lhs.additions, rhs.additions),
        .multiplications = try add(lhs.multiplications, rhs.multiplications),
        .inversions = try add(lhs.inversions, rhs.inversions),
    };
}

fn componentDigest(profile: *const ComponentProfile) Digest {
    var hash = Sha256.init(.{});
    hash.update(COMPONENT_DOMAIN);
    hashInt(&hash, u16, profile.schema_version);
    hashInt(&hash, u8, @intFromEnum(profile.kind));
    hash.update(&profile.composition_profile_digest);
    hashInt(&hash, u32, profile.trace_log_size);
    hashInt(&hash, u32, profile.component_log_degree_bound);
    hashInt(&hash, u32, profile.max_log_degree_bound);
    hashInt(&hash, u64, profile.constraint_count);
    hashInt(&hash, u64, profile.partial_evaluation_count);
    hashInt(&hash, u8, @intFromBool(profile.uses_previous_row));
    hashOperations(&hash, profile.formula_operations);
    hashOperations(&hash, profile.mask_operations);
    hashOperations(&hash, profile.constraint_operations);
    return hash.finalResult();
}

fn receiptDigest(receipt: *const Receipt) Digest {
    var hash = Sha256.init(.{});
    hash.update(DIGEST_DOMAIN);
    hashInt(&hash, u16, receipt.schema_version);
    hashInt(&hash, u8, @intFromEnum(receipt.site));
    hashInt(&hash, u32, receipt.component_count);
    hashInt(&hash, u64, receipt.constraint_count);
    hashOperations(&hash, receipt.component_operations);
    hashOperations(&hash, receipt.coordinator_operations);
    hashOperations(&hash, receipt.operations);
    hash.update(&receipt.authority_digest);
    return hash.finalResult();
}

fn hashOperations(hash: *Sha256, operations: FieldOperations) void {
    hashInt(hash, u64, operations.additions);
    hashInt(hash, u64, operations.multiplications);
    hashInt(hash, u64, operations.inversions);
}

fn hashBytes(hash: *Sha256, value: []const u8) void {
    hashInt(hash, u64, value.len);
    hash.update(value);
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn digestIsZero(value: Digest) bool {
    for (value) |byte| if (byte != 0) return false;
    return true;
}

fn add(lhs: anytype, rhs: @TypeOf(lhs)) Error!@TypeOf(lhs) {
    return std.math.add(@TypeOf(lhs), lhs, rhs) catch error.CountOverflow;
}

fn mul(lhs: anytype, rhs: @TypeOf(lhs)) Error!@TypeOf(lhs) {
    return std.math.mul(@TypeOf(lhs), lhs, rhs) catch error.CountOverflow;
}

fn testSourceProfile() !composition_work.ComponentProfile {
    const expression = FieldOperations{ .additions = 4, .multiplications = 5 };
    const constraint = FieldOperations{ .additions = 2, .multiplications = 2 };
    return composition_work.ComponentProfile.init(
        .program,
        composition_work.sourceAuthority(
            "oods-test-source",
            &.{ 5, 2 },
            expression,
            constraint,
        ),
        5,
        2,
        expression,
        constraint,
        .{},
    );
}

test "OODS component profile binds mask and point execution geometry" {
    const source = try testSourceProfile();
    const profile = try ComponentProfile.init(&source, 4, 5, 4, true);
    try profile.validate();
    try std.testing.expectEqual(
        FieldOperations{ .additions = 8, .multiplications = 16 },
        profile.mask_operations,
    );
    // 4 partial reconstructions, one point double, coset materialization,
    // vanishing, formula replay, denominator products, and one inversion.
    try std.testing.expectEqual(
        FieldOperations{ .additions = 36, .multiplications = 48, .inversions = 1 },
        profile.constraint_operations,
    );
}

test "OODS receipt rejects profile and aggregate mutations" {
    const source = try testSourceProfile();
    var profile = try ComponentProfile.init(&source, 4, 5, 4, true);
    profile.constraint_operations.additions += 1;
    try std.testing.expectError(error.InvalidComponentProfile, profile.validate());
    profile.constraint_operations.additions -= 1;

    var builder = Builder.init(.constraint_evaluation);
    try builder.addComponent(0, &profile);
    const extraction = try compositionExtractionWork(7, 2);
    try builder.addCoordinator("composition-chunk-extraction", extraction, &.{ 7, 2 });
    var receipt = try builder.finish();
    receipt.operations.multiplications += 1;
    try std.testing.expectError(error.InvalidReceipt, receipt.validate());
    receipt.operations.multiplications -= 1;
    receipt.authority_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidReceipt, receipt.validate());
}

test "OODS capture is fail-atomic and duplicate-safe" {
    const source = try testSourceProfile();
    const profile = try ComponentProfile.init(&source, 4, 5, 0, false);
    var builder = Builder.init(.mask_points);
    try builder.addComponent(0, &profile);
    const receipt = try builder.finish();
    var capture = Capture{};
    try capture.publish(receipt);
    try std.testing.expectError(error.DuplicateCompletion, capture.publish(receipt));
    try std.testing.expect(std.meta.eql(receipt, capture.receipt.?));
}

test "OODS aggregation overflow cannot publish" {
    const source = try testSourceProfile();
    const profile = try ComponentProfile.init(&source, 4, 5, 0, false);
    var builder = Builder.init(.constraint_evaluation);
    builder.component_operations.additions = std.math.maxInt(u64);
    try std.testing.expectError(
        error.CountOverflow,
        builder.addComponent(0, &profile),
    );
    try std.testing.expectEqual(@as(u32, 0), builder.component_count);
    try std.testing.expectEqual(@as(u64, 0), builder.constraint_count);
    const capture = Capture{};
    try std.testing.expect(capture.receipt == null);
}

test "OODS extraction counts the executed split tree" {
    try std.testing.expectEqual(
        FieldOperations{ .additions = 33, .multiplications = 51 },
        try compositionExtractionWork(7, 2),
    );
    try std.testing.expectError(
        error.InvalidReceipt,
        compositionExtractionWork(2, 2),
    );
}

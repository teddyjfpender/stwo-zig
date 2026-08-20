//! Authenticated exact-work receipts for AIR composition on its evaluation domain.
//!
//! Constraint owners publish one row-formula profile derived from the evaluator
//! they actually execute. Backend owners then add route-specific aggregation,
//! merge, and lifting work. Nothing in this module enters a scalar/SIMD/device
//! hot loop: profiled requests build one checked receipt after useful work has
//! completed, while ordinary proving retains the existing call graph.

const std = @import("std");
const builtin = @import("builtin");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const work_profile = @import("stwo_prover_api").work_profile;

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA_VERSION: u16 = 1;
pub const DIGEST_DOMAIN = "stwo-zig/prover/air-composition-work/v1\x00";
pub const COMPONENT_DOMAIN =
    "stwo-zig/prover/air-composition-component-work/v1\x00";

pub const Digest = [Sha256.digest_length]u8;
pub const FieldOperations = work_profile.FieldOperations;

pub const Error = error{
    CountOverflow,
    DuplicateCompletion,
    InvalidAuthority,
    InvalidComponentProfile,
    InvalidReceipt,
    NestedMeasurement,
};

pub const Route = enum(u8) {
    cpu_riscv_packed = 1,
    metal_riscv_resident = 2,
    cpu_generic_prepared = 3,
    cpu_generic_legacy = 4,
    metal_hybrid_resident = 5,
};

pub const ComponentKind = enum(u8) {
    base_polynomial = 1,
    lookup_polynomial_v1 = 2,
    lookup_polynomial_v2 = 3,
    program = 4,
    memory = 5,
    merkle = 6,
    poseidon2 = 7,
    clock_update = 8,
    lookup_table = 9,
    guest_caller = 10,
    guest_provider = 11,
};

/// Exact work executed once for every scalar row of one component. It includes
/// expression replay, constraint construction, and random-root weighting. It
/// deliberately excludes both the final vanishing-denominator multiplication
/// and the shared accumulator store/add: those operations depend on the
/// backend route (one denominator per generic component, but one per packed
/// CPU bucket).
pub const ComponentProfile = struct {
    schema_version: u16 = SCHEMA_VERSION,
    kind: ComponentKind,
    authority_digest: Digest,
    evaluation_log_size: u32,
    row_count: u64,
    constraint_count: u64,
    expression_additions_per_row: u64,
    expression_multiplications_per_row: u64,
    constraint_additions_per_row: u64,
    constraint_multiplications_per_row: u64,
    setup: FieldOperations = .{},
    profile_digest: Digest,

    pub fn init(
        kind: ComponentKind,
        source_authority: Digest,
        evaluation_log_size: u32,
        constraint_count: usize,
        expression: FieldOperations,
        constraint: FieldOperations,
        setup: FieldOperations,
    ) Error!ComponentProfile {
        if (evaluation_log_size >= @bitSizeOf(u64) or constraint_count == 0 or
            expression.inversions != 0 or constraint.inversions != 0)
        {
            return error.InvalidComponentProfile;
        }
        const constraints = std.math.cast(u64, constraint_count) orelse
            return error.CountOverflow;
        var result = ComponentProfile{
            .kind = kind,
            .authority_digest = source_authority,
            .evaluation_log_size = evaluation_log_size,
            .row_count = @as(u64, 1) << @intCast(evaluation_log_size),
            .constraint_count = constraints,
            .expression_additions_per_row = expression.additions,
            .expression_multiplications_per_row = expression.multiplications,
            .constraint_additions_per_row = constraint.additions,
            .constraint_multiplications_per_row = constraint.multiplications,
            .setup = setup,
            .profile_digest = undefined,
        };
        try result.validateShape();
        result.profile_digest = componentDigest(&result);
        return result;
    }

    pub fn validate(self: *const ComponentProfile) Error!void {
        try self.validateShape();
        if (!std.mem.eql(u8, &self.profile_digest, &componentDigest(self)))
            return error.InvalidComponentProfile;
    }

    pub fn exactWork(self: *const ComponentProfile) Error!FieldOperations {
        try self.validate();
        const additions_per_row = try add(
            self.expression_additions_per_row,
            self.constraint_additions_per_row,
        );
        const multiplications_per_row = try add(
            self.expression_multiplications_per_row,
            self.constraint_multiplications_per_row,
        );
        return addOperations(self.setup, .{
            .additions = try mul(additions_per_row, self.row_count),
            .multiplications = try mul(
                multiplications_per_row,
                self.row_count,
            ),
        });
    }

    fn validateShape(self: *const ComponentProfile) Error!void {
        if (self.schema_version != SCHEMA_VERSION or
            digestIsZero(self.authority_digest) or
            self.evaluation_log_size >= @bitSizeOf(u64) or
            self.row_count != @as(u64, 1) << @intCast(self.evaluation_log_size) or
            self.constraint_count == 0)
        {
            return error.InvalidComponentProfile;
        }
    }
};

/// Pointer-free aggregate that can be copied into a proof-stage receipt. The
/// authority digest commits to every ordered component profile and every
/// backend-owned aggregation contribution; the profile counters only receive
/// `operations` after validation succeeds.
pub const Receipt = struct {
    schema_version: u16 = SCHEMA_VERSION,
    route: Route,
    component_count: u32,
    evaluation_row_count: u64,
    constraint_count: u64,
    expression_operations: FieldOperations,
    constraint_operations: FieldOperations,
    accumulator_operations: FieldOperations,
    operations: FieldOperations,
    authority_digest: Digest,
    receipt_digest: Digest,

    pub fn validate(self: *const Receipt) Error!void {
        if (self.schema_version != SCHEMA_VERSION or self.component_count == 0 or
            self.evaluation_row_count == 0 or self.constraint_count == 0 or
            digestIsZero(self.authority_digest))
        {
            return error.InvalidReceipt;
        }
        const expected = try addOperations(
            try addOperations(
                self.expression_operations,
                self.constraint_operations,
            ),
            self.accumulator_operations,
        );
        if (!std.meta.eql(expected, self.operations) or
            !std.mem.eql(u8, &self.receipt_digest, &receiptDigest(self)))
        {
            return error.InvalidReceipt;
        }
    }
};

pub const Builder = struct {
    route: Route,
    component_count: u32 = 0,
    evaluation_row_count: u64 = 0,
    constraint_count: u64 = 0,
    expression_operations: FieldOperations = .{},
    constraint_operations: FieldOperations = .{},
    accumulator_operations: FieldOperations = .{},
    authority: Sha256,

    pub fn init(route: Route) Builder {
        var authority = Sha256.init(.{});
        authority.update(DIGEST_DOMAIN);
        hashInt(&authority, u16, SCHEMA_VERSION);
        hashInt(&authority, u8, @intFromEnum(route));
        return .{ .route = route, .authority = authority };
    }

    pub fn addComponent(
        self: *Builder,
        ordinal: usize,
        profile: *const ComponentProfile,
    ) Error!void {
        try profile.validate();
        const ordinal_u32 = std.math.cast(u32, ordinal) orelse
            return error.CountOverflow;
        if (ordinal_u32 != self.component_count)
            return error.InvalidComponentProfile;
        const rows = profile.row_count;
        self.component_count = std.math.add(u32, self.component_count, 1) catch
            return error.CountOverflow;
        self.evaluation_row_count = try add(self.evaluation_row_count, rows);
        self.constraint_count = try add(
            self.constraint_count,
            profile.constraint_count,
        );
        self.expression_operations = try addOperations(
            self.expression_operations,
            .{
                .additions = try mul(
                    profile.expression_additions_per_row,
                    rows,
                ),
                .multiplications = try mul(
                    profile.expression_multiplications_per_row,
                    rows,
                ),
            },
        );
        self.constraint_operations = try addOperations(
            self.constraint_operations,
            try addOperations(profile.setup, .{
                .additions = try mul(
                    profile.constraint_additions_per_row,
                    rows,
                ),
                .multiplications = try mul(
                    profile.constraint_multiplications_per_row,
                    rows,
                ),
            }),
        );
        hashInt(&self.authority, u32, ordinal_u32);
        self.authority.update(&profile.profile_digest);
    }

    /// Adds a backend-owned contribution only after that work has completed.
    /// `label` is a stable schema term, not diagnostic prose.
    pub fn addAccumulator(
        self: *Builder,
        label: []const u8,
        operations: FieldOperations,
        geometry: []const u64,
    ) Error!void {
        self.accumulator_operations = try addOperations(
            self.accumulator_operations,
            operations,
        );
        hashBytes(&self.authority, label);
        hashInt(&self.authority, u32, std.math.cast(u32, geometry.len) orelse
            return error.CountOverflow);
        for (geometry) |value| hashInt(&self.authority, u64, value);
        hashOperations(&self.authority, operations);
    }

    pub fn finish(self: *Builder) Error!Receipt {
        if (self.component_count == 0) return error.InvalidReceipt;
        const operations = try addOperations(
            try addOperations(
                self.expression_operations,
                self.constraint_operations,
            ),
            self.accumulator_operations,
        );
        var authority_digest: Digest = undefined;
        self.authority.final(&authority_digest);
        var result = Receipt{
            .route = self.route,
            .component_count = self.component_count,
            .evaluation_row_count = self.evaluation_row_count,
            .constraint_count = self.constraint_count,
            .expression_operations = self.expression_operations,
            .constraint_operations = self.constraint_operations,
            .accumulator_operations = self.accumulator_operations,
            .operations = operations,
            .authority_digest = authority_digest,
            .receipt_digest = undefined,
        };
        result.receipt_digest = receiptDigest(&result);
        try result.validate();
        return result;
    }
};

/// One-call fail-atomic handoff from a backend to the proof-level recorder.
pub const Capture = struct {
    receipt: ?Receipt = null,

    pub fn publish(self: *Capture, receipt: Receipt) Error!void {
        try receipt.validate();
        if (self.receipt != null) return error.DuplicateCompletion;
        self.receipt = receipt;
    }
};

/// Test-only observation of the receipt accepted by the proof boundary. The
/// binding is coordinator-thread-local: composition workers have already joined
/// before the proof boundary validates and records the receipt. Production
/// builds erase the observation call at compile time.
const TestReceiptAuditState = struct {
    receipt: ?Receipt = null,
    observation_count: usize = 0,

    fn observe(self: *TestReceiptAuditState, receipt: Receipt) void {
        self.observation_count += 1;
        if (self.receipt == null) self.receipt = receipt;
    }

    pub fn snapshot(self: *const TestReceiptAuditState) TestReceiptAuditSnapshot {
        return .{
            .receipt = self.receipt,
            .observation_count = self.observation_count,
        };
    }
};

const TestReceiptAuditSnapshot = struct {
    receipt: ?Receipt,
    observation_count: usize,
};

const TestReceiptAuditThread = if (builtin.is_test) struct {
    threadlocal var active: ?*TestReceiptAuditState = null;
} else struct {};

const TestReceiptAuditBindingState = struct {
    audit: *TestReceiptAuditState,
    active: bool = true,

    pub fn init(audit: *TestReceiptAuditState) !TestReceiptAuditBindingState {
        if (comptime !builtin.is_test) return error.TestOnly;
        if (TestReceiptAuditThread.active != null)
            return error.TestReceiptAuditAlreadyBound;
        TestReceiptAuditThread.active = audit;
        return .{ .audit = audit };
    }

    pub fn deinit(self: *TestReceiptAuditBindingState) void {
        if (comptime !builtin.is_test) unreachable;
        std.debug.assert(self.active);
        std.debug.assert(TestReceiptAuditThread.active == self.audit);
        TestReceiptAuditThread.active = null;
        self.active = false;
    }
};

/// Called only after the proof boundary has independently validated and
/// recorded the receipt. Non-test builds retain no branch, storage access, or
/// callback from this observation seam.
inline fn observeAcceptedReceiptForTest(receipt: Receipt) void {
    if (comptime !builtin.is_test) return;
    const audit = TestReceiptAuditThread.active orelse return;
    audit.observe(receipt);
}

/// Narrow access for owned integration tests. The namespace is empty in
/// production builds.
pub const testing = if (builtin.is_test) struct {
    pub const ReceiptAudit = TestReceiptAuditState;
    pub const ReceiptAuditBinding = TestReceiptAuditBindingState;
    pub const ReceiptAuditSnapshot = TestReceiptAuditSnapshot;

    pub inline fn observeAcceptedReceipt(receipt: Receipt) void {
        observeAcceptedReceiptForTest(receipt);
    }
} else struct {};

/// Counting secure scalar used only while deriving a component's one-row
/// formula. It carries a real QM31 value so structural branches take the same
/// path as production, while a thread-local sink observes field operations.
pub const CountingScalar = struct {
    value: QM31,

    pub fn zero() CountingScalar {
        return fromValue(QM31.zero());
    }
    pub fn one() CountingScalar {
        return fromValue(QM31.one());
    }
    pub fn fromBase(value: M31) CountingScalar {
        return fromValue(QM31.fromBase(value));
    }
    pub fn fromValue(value: QM31) CountingScalar {
        return .{ .value = value };
    }
    pub fn isZero(self: CountingScalar) bool {
        return self.value.isZero();
    }
    pub fn eql(lhs: CountingScalar, rhs: CountingScalar) bool {
        return lhs.value.eql(rhs.value);
    }
    pub fn add(lhs: CountingScalar, rhs: CountingScalar) CountingScalar {
        active_measurement.?.additions += 1;
        return fromValue(lhs.value.add(rhs.value));
    }
    pub fn sub(lhs: CountingScalar, rhs: CountingScalar) CountingScalar {
        active_measurement.?.additions += 1;
        return fromValue(lhs.value.sub(rhs.value));
    }
    pub fn neg(self: CountingScalar) CountingScalar {
        return fromValue(self.value.neg());
    }
    pub fn mul(lhs: CountingScalar, rhs: CountingScalar) CountingScalar {
        active_measurement.?.multiplications += 1;
        return fromValue(lhs.value.mul(rhs.value));
    }
    pub fn square(self: CountingScalar) CountingScalar {
        active_measurement.?.multiplications += 1;
        return fromValue(self.value.square());
    }
};

threadlocal var active_measurement: ?*FieldOperations = null;

pub fn beginMeasurement(operations: *FieldOperations) Error!void {
    if (active_measurement != null) return error.NestedMeasurement;
    operations.* = .{};
    active_measurement = operations;
}

pub fn endMeasurement() void {
    std.debug.assert(active_measurement != null);
    active_measurement = null;
}

pub fn dummyScalar(index: usize) CountingScalar {
    return .fromValue(QM31.fromU32Unchecked(
        std.math.cast(u32, index + 1) orelse 1,
        0,
        0,
        0,
    ));
}

/// Per-row work for root weighting after the expression DAG has been replayed.
pub fn rootFoldWork(root_count: usize) Error!FieldOperations {
    const roots = std.math.cast(u64, root_count) orelse return error.CountOverflow;
    return .{ .additions = roots, .multiplications = roots };
}

/// Cold setup executed by the current quotient-denominator owners. Circle
/// points are materialized through `CirclePointIndex.toPoint`; one set-bit
/// executes one circle addition (`A=2, M=4`). `cosetVanishing` then performs
/// two circle additions and `log_size-1` x-doublings (`A=2, M=1`), followed by
/// one logical inversion. Inversion internals are not expanded, matching the
/// global work-profile convention.
pub fn denominatorSetupWork(
    trace_log_size: u32,
    evaluation_log_size: u32,
) Error!FieldOperations {
    if (trace_log_size == 0 or evaluation_log_size <= trace_log_size or
        evaluation_log_size >= @bitSizeOf(usize))
    {
        return error.InvalidComponentProfile;
    }
    const extension_bits = evaluation_log_size - trace_log_size;
    if (extension_bits >= @bitSizeOf(usize))
        return error.InvalidComponentProfile;
    const denominator_count = @as(usize, 1) << @intCast(extension_bits);

    var point_additions: u64 = 0;
    // `CanonicCoset.new(eval).circleDomain()` constructs both the temporary
    // canonic coset and its half-coset. The trace coset is constructed once.
    const eval_canonic = canonic.CanonicCoset.new(evaluation_log_size);
    const eval_domain = eval_canonic.circleDomain();
    const trace_coset = canonic.CanonicCoset.new(trace_log_size).coset();
    inline for (.{ eval_canonic.coset_value, eval_domain.half_coset, trace_coset }) |coset| {
        point_additions = try add(
            point_additions,
            @popCount(coset.initial_index.v),
        );
        point_additions = try add(
            point_additions,
            @popCount(coset.step_size.v),
        );
        point_additions = try add(
            point_additions,
            @popCount(coset.step_size.half().v),
        );
    }

    var index: usize = 0;
    while (index < denominator_count) : (index += 1) {
        const bit_reversed = @bitReverse(index) >>
            @intCast(@bitSizeOf(usize) - extension_bits);
        point_additions = try add(
            point_additions,
            @popCount(eval_domain.indexAt(bit_reversed).v),
        );
    }

    const denominator_count_u64 = std.math.cast(u64, denominator_count) orelse
        return error.CountOverflow;
    const double_count = try mul(
        denominator_count_u64,
        trace_log_size - 1,
    );
    return .{
        .additions = try add(
            try mul(point_additions, 2),
            try add(
                try mul(denominator_count_u64, 4),
                try mul(double_count, 2),
            ),
        ),
        .multiplications = try add(
            try mul(point_additions, 4),
            try add(
                try mul(denominator_count_u64, 8),
                double_count,
            ),
        ),
        .inversions = denominator_count_u64,
    };
}

pub fn randomPowersWork(constraint_count: usize) Error!FieldOperations {
    return .{
        .multiplications = std.math.cast(u64, constraint_count) orelse
            return error.CountOverflow,
    };
}

pub fn nodeWork(nodes: anytype, reachable: []const bool) Error!FieldOperations {
    if (nodes.len != reachable.len) return error.InvalidComponentProfile;
    var result = FieldOperations{};
    for (nodes, reachable) |node, is_reachable| {
        if (!is_reachable) continue;
        switch (node.op) {
            .add, .sub => result.additions = try add(result.additions, 1),
            .mul => result.multiplications = try add(result.multiplications, 1),
            .constant, .column, .neg => {},
        }
    }
    return result;
}

/// Relation-combine and transition work shared by CPU and Metal V1 lookup
/// programs. Expression-node work is supplied separately through `nodeWork`.
pub fn lookupConstraintWork(program: anytype) Error!FieldOperations {
    var result = FieldOperations{};
    for (program.entries) |entry| {
        const arity = @as(u64, entry.arity);
        result.additions = try add(result.additions, try add(arity, 1));
        result.multiplications = try add(result.multiplications, arity);
    }
    var batch: usize = 0;
    while (batch < program.batchCount()) : (batch += 1) {
        const first = batch * program.batch_size;
        const paired = program.batch_size == 2 and first + 1 < program.entries.len;
        // delta: current - previous + claim * selector.
        result.additions = try add(result.additions, 2);
        result.multiplications = try add(result.multiplications, 1);
        if (paired) {
            // delta*d1*d2 - n1*d2 - n2*d1.
            result.additions = try add(result.additions, 2);
            result.multiplications = try add(result.multiplications, 4);
        } else {
            // delta*d1 - n1.
            result.additions = try add(result.additions, 1);
            result.multiplications = try add(result.multiplications, 1);
        }
        // Random-root weighting and accumulation into the component fold.
        result.additions = try add(result.additions, 1);
        result.multiplications = try add(result.multiplications, 1);
    }
    return result;
}

pub fn lookupConstraintWorkV2(program: anytype) Error!FieldOperations {
    var result = FieldOperations{};
    for (program.entries) |entry| {
        const arity = @as(u64, entry.arity);
        result.additions = try add(result.additions, try add(arity, 1));
        result.multiplications = try add(result.multiplications, arity);
    }
    for (program.batches) |batch| {
        result.additions = try add(result.additions, 2);
        result.multiplications = try add(result.multiplications, 1);
        if (batch.entry_count == 2) {
            result.additions = try add(result.additions, 2);
            result.multiplications = try add(result.multiplications, 4);
        } else if (batch.entry_count == 1) {
            result.additions = try add(result.additions, 1);
            result.multiplications = try add(result.multiplications, 1);
        } else return error.InvalidComponentProfile;
        result.additions = try add(result.additions, 1);
        result.multiplications = try add(result.multiplications, 1);
    }
    return result;
}

pub fn sourceAuthority(
    label: []const u8,
    geometry: []const u64,
    expression: FieldOperations,
    constraint: FieldOperations,
) Digest {
    var hash = Sha256.init(.{});
    hash.update(COMPONENT_DOMAIN);
    hashBytes(&hash, label);
    for (geometry) |value| hashInt(&hash, u64, value);
    hashOperations(&hash, expression);
    hashOperations(&hash, constraint);
    return hash.finalResult();
}

pub fn addOperations(
    lhs: FieldOperations,
    rhs: FieldOperations,
) Error!FieldOperations {
    return .{
        .additions = try add(lhs.additions, rhs.additions),
        .multiplications = try add(lhs.multiplications, rhs.multiplications),
        .inversions = try add(lhs.inversions, rhs.inversions),
    };
}

pub fn scaleOperations(
    operations: FieldOperations,
    factor: u64,
) Error!FieldOperations {
    return .{
        .additions = try mul(operations.additions, factor),
        .multiplications = try mul(operations.multiplications, factor),
        .inversions = try mul(operations.inversions, factor),
    };
}

fn componentDigest(profile: *const ComponentProfile) Digest {
    var hash = Sha256.init(.{});
    hash.update(COMPONENT_DOMAIN);
    hashInt(&hash, u16, profile.schema_version);
    hashInt(&hash, u8, @intFromEnum(profile.kind));
    hash.update(&profile.authority_digest);
    hashInt(&hash, u32, profile.evaluation_log_size);
    hashInt(&hash, u64, profile.row_count);
    hashInt(&hash, u64, profile.constraint_count);
    hashInt(&hash, u64, profile.expression_additions_per_row);
    hashInt(&hash, u64, profile.expression_multiplications_per_row);
    hashInt(&hash, u64, profile.constraint_additions_per_row);
    hashInt(&hash, u64, profile.constraint_multiplications_per_row);
    hashOperations(&hash, profile.setup);
    return hash.finalResult();
}

fn receiptDigest(receipt: *const Receipt) Digest {
    var hash = Sha256.init(.{});
    hash.update(DIGEST_DOMAIN);
    hashInt(&hash, u16, receipt.schema_version);
    hashInt(&hash, u8, @intFromEnum(receipt.route));
    hashInt(&hash, u32, receipt.component_count);
    hashInt(&hash, u64, receipt.evaluation_row_count);
    hashInt(&hash, u64, receipt.constraint_count);
    hashOperations(&hash, receipt.expression_operations);
    hashOperations(&hash, receipt.constraint_operations);
    hashOperations(&hash, receipt.accumulator_operations);
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

fn add(lhs: u64, rhs: u64) Error!u64 {
    return std.math.add(u64, lhs, rhs) catch error.CountOverflow;
}

fn mul(lhs: u64, rhs: u64) Error!u64 {
    return std.math.mul(u64, lhs, rhs) catch error.CountOverflow;
}

test "AIR composition receipt binds ordered profiles and backend work" {
    const expression = FieldOperations{ .additions = 3, .multiplications = 2 };
    const constraint = FieldOperations{ .additions = 5, .multiplications = 7 };
    const authority = sourceAuthority("test-component", &.{ 4, 2 }, expression, constraint);
    const profile = try ComponentProfile.init(
        .base_polynomial,
        authority,
        4,
        2,
        expression,
        constraint,
        .{ .additions = 9, .inversions = 2 },
    );
    var builder = Builder.init(.cpu_riscv_packed);
    try builder.addComponent(0, &profile);
    try builder.addAccumulator(
        "random-powers",
        .{ .multiplications = 2 },
        &.{2},
    );
    const receipt = try builder.finish();
    try receipt.validate();
    try std.testing.expectEqual(@as(u64, 16 * (3 + 5) + 9), receipt.operations.additions);
    try std.testing.expectEqual(@as(u64, 16 * (2 + 7) + 2), receipt.operations.multiplications);
    try std.testing.expectEqual(@as(u64, 2), receipt.operations.inversions);
}

test "AIR composition receipt rejects counter and authority mutations" {
    const authority = sourceAuthority("mutation", &.{8}, .{}, .{ .multiplications = 1 });
    const profile = try ComponentProfile.init(
        .program,
        authority,
        3,
        1,
        .{},
        .{ .multiplications = 1 },
        .{},
    );
    var builder = Builder.init(.cpu_generic_prepared);
    try builder.addComponent(0, &profile);
    var receipt = try builder.finish();
    receipt.operations.additions += 1;
    try std.testing.expectError(error.InvalidReceipt, receipt.validate());
    receipt.operations.additions -= 1;
    receipt.authority_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidReceipt, receipt.validate());
}

test "AIR composition accepted-receipt audit is scoped and preserves first receipt" {
    const authority = sourceAuthority(
        "accepted-receipt-audit",
        &.{8},
        .{ .additions = 1 },
        .{ .multiplications = 1 },
    );
    const profile = try ComponentProfile.init(
        .program,
        authority,
        3,
        1,
        .{ .additions = 1 },
        .{ .multiplications = 1 },
        .{},
    );
    var builder = Builder.init(.cpu_riscv_packed);
    try builder.addComponent(0, &profile);
    const receipt = try builder.finish();

    var audit: TestReceiptAuditState = .{};
    var nested: TestReceiptAuditState = .{};
    {
        var binding = try TestReceiptAuditBindingState.init(&audit);
        defer binding.deinit();
        try std.testing.expectError(
            error.TestReceiptAuditAlreadyBound,
            TestReceiptAuditBindingState.init(&nested),
        );
        observeAcceptedReceiptForTest(receipt);
        observeAcceptedReceiptForTest(receipt);
    }
    observeAcceptedReceiptForTest(receipt);

    const snapshot = audit.snapshot();
    try std.testing.expectEqual(@as(usize, 2), snapshot.observation_count);
    try std.testing.expect(std.meta.eql(receipt, snapshot.receipt.?));
    try std.testing.expectEqual(@as(usize, 0), nested.observation_count);
}

test "AIR composition counting scalar observes executed field methods" {
    var operations: FieldOperations = undefined;
    try beginMeasurement(&operations);
    defer endMeasurement();
    const a = dummyScalar(0);
    const b = dummyScalar(1);
    _ = a.add(b).sub(a).mul(b).square().neg();
    try std.testing.expectEqual(@as(u64, 2), operations.additions);
    try std.testing.expectEqual(@as(u64, 2), operations.multiplications);
    try std.testing.expectEqual(@as(u64, 0), operations.inversions);
}

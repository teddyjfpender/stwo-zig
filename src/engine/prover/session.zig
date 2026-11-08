//! Backend-neutral ownership for immutable prover-wide resources.

const std = @import("std");
const pcs = @import("stwo_core").pcs;
const TwiddleSource = @import("poly/twiddle_source.zig").TwiddleSource;
const M31TwiddleTower = @import("poly/twiddle_tower.zig").M31TwiddleTower;

const PcsConfig = pcs.PcsConfig;

pub const ProverSession = struct {
    pcs_config: PcsConfig,
    max_circle_log: u32,
    host_byte_budget: usize,
    twiddle_tower: M31TwiddleTower,
    construction_telemetry: ConstructionTelemetry,

    const Self = @This();

    pub const ConstructionTelemetry = struct {
        tower_build_count: u64,
        retained_twiddle_bytes: usize,
    };

    pub const RequestError = error{
        PcsConfigMismatch,
        InvalidCircleLog,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        pcs_config: PcsConfig,
        max_circle_log: u32,
        host_byte_budget: usize,
    ) M31TwiddleTower.InitError!Self {
        var tower = try M31TwiddleTower.init(
            allocator,
            max_circle_log,
            host_byte_budget,
        );
        errdefer tower.deinit(allocator);

        return .{
            .pcs_config = pcs_config,
            .max_circle_log = max_circle_log,
            .host_byte_budget = host_byte_budget,
            .twiddle_tower = tower,
            .construction_telemetry = .{
                .tower_build_count = 1,
                .retained_twiddle_bytes = tower.retainedBytes(),
            },
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.twiddle_tower.deinit(allocator);
        self.* = undefined;
    }

    /// Checks protocol and geometry compatibility before a caller transfers
    /// proof-request ownership to a scheme.
    pub fn validateRequest(
        self: *const Self,
        request_config: PcsConfig,
        required_circle_log: u32,
    ) RequestError!void {
        if (!pcsConfigsEqual(self.pcs_config, request_config)) {
            return error.PcsConfigMismatch;
        }
        if (required_circle_log == 0 or required_circle_log > self.max_circle_log) {
            return error.InvalidCircleLog;
        }
    }

    pub fn twiddleSource(self: *const Self) TwiddleSource {
        return TwiddleSource.initBorrowed(&self.twiddle_tower);
    }

    pub inline fn constructionTelemetry(self: *const Self) ConstructionTelemetry {
        return self.construction_telemetry;
    }
};

fn pcsConfigsEqual(lhs: PcsConfig, rhs: PcsConfig) bool {
    return lhs.pow_bits == rhs.pow_bits and
        lhs.fri_config.log_blowup_factor == rhs.fri_config.log_blowup_factor and
        lhs.fri_config.log_last_layer_degree_bound == rhs.fri_config.log_last_layer_degree_bound and
        lhs.fri_config.n_queries == rhs.fri_config.n_queries and
        lhs.fri_config.fold_step == rhs.fri_config.fold_step and
        lhs.lifting_log_size == rhs.lifting_log_size;
}

fn testConfig() PcsConfig {
    var fri_config = @import("stwo_core").fri.FriConfig.init(2, 3, 17) catch unreachable;
    fri_config.fold_step = 2;
    return .{
        .pow_bits = 7,
        .fri_config = fri_config,
        .lifting_log_size = 6,
    };
}

test "prover session: accepts only the exact pcs configuration" {
    const allocator = std.testing.allocator;
    const config = testConfig();
    var session = try ProverSession.init(allocator, config, 9, 1 << 20);
    defer session.deinit(allocator);

    try session.validateRequest(config, 7);

    var mismatch = config;
    mismatch.pow_bits += 1;
    try std.testing.expectError(error.PcsConfigMismatch, session.validateRequest(mismatch, 7));

    mismatch = config;
    mismatch.fri_config.log_blowup_factor += 1;
    try std.testing.expectError(error.PcsConfigMismatch, session.validateRequest(mismatch, 7));

    mismatch = config;
    mismatch.fri_config.log_last_layer_degree_bound += 1;
    try std.testing.expectError(error.PcsConfigMismatch, session.validateRequest(mismatch, 7));

    mismatch = config;
    mismatch.fri_config.n_queries += 1;
    try std.testing.expectError(error.PcsConfigMismatch, session.validateRequest(mismatch, 7));

    mismatch = config;
    mismatch.fri_config.fold_step += 1;
    try std.testing.expectError(error.PcsConfigMismatch, session.validateRequest(mismatch, 7));

    mismatch = config;
    mismatch.lifting_log_size = null;
    try std.testing.expectError(error.PcsConfigMismatch, session.validateRequest(mismatch, 7));
}

test "prover session: validates request circle log bounds" {
    const allocator = std.testing.allocator;
    const config = testConfig();
    var session = try ProverSession.init(allocator, config, 9, 1 << 20);
    defer session.deinit(allocator);

    try session.validateRequest(config, 1);
    try session.validateRequest(config, 9);
    try std.testing.expectError(error.InvalidCircleLog, session.validateRequest(config, 0));
    try std.testing.expectError(error.InvalidCircleLog, session.validateRequest(config, 10));
}

test "prover session: records one immutable tower construction" {
    const allocator = std.testing.allocator;
    var session = try ProverSession.init(allocator, testConfig(), 9, 1 << 20);
    defer session.deinit(allocator);

    const initial = session.constructionTelemetry();
    try std.testing.expectEqual(@as(u64, 1), initial.tower_build_count);
    try std.testing.expectEqual(session.twiddle_tower.retainedBytes(), initial.retained_twiddle_bytes);

    var source = session.twiddleSource();
    defer source.deinit(allocator);
    _ = try source.get(allocator, 7);
    try std.testing.expectEqualDeep(initial, session.constructionTelemetry());
    try std.testing.expectEqual(@as(u64, 0), source.telemetry().tree_build_count);
}

test "prover session: sequential sources borrow one live tower" {
    const allocator = std.testing.allocator;
    var session = try ProverSession.init(allocator, testConfig(), 9, 1 << 20);
    defer session.deinit(allocator);

    var first = session.twiddleSource();
    _ = try first.get(allocator, 5);
    _ = try first.get(allocator, 8);
    try std.testing.expectEqual(@as(u64, 0), first.telemetry().tree_build_count);
    first.deinit(allocator);

    var second = session.twiddleSource();
    defer second.deinit(allocator);
    const tree = try second.get(allocator, 5);
    try std.testing.expectEqual(@as(usize, 1 << 4), tree.twiddles.len);
    try std.testing.expectEqual(@as(u64, 0), second.telemetry().tree_build_count);
    try std.testing.expectEqual(@as(u64, 1), session.constructionTelemetry().tower_build_count);
}

test "prover session: rejects insufficient budget before allocation" {
    const allocator = std.testing.allocator;
    const required_bytes: usize = 2 * (1 << (9 - 1)) * @sizeOf(u32);
    var fail_first_allocation = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    try std.testing.expectError(
        error.HostByteBudgetExceeded,
        ProverSession.init(
            fail_first_allocation.allocator(),
            testConfig(),
            9,
            required_bytes - 1,
        ),
    );
    try std.testing.expect(!fail_first_allocation.has_induced_failure);
}

fn checkSessionAllocationFailures(allocator: std.mem.Allocator) !void {
    var session = try ProverSession.init(allocator, testConfig(), 8, 1 << 20);
    defer session.deinit(allocator);

    var source = session.twiddleSource();
    defer source.deinit(allocator);
    _ = try source.get(allocator, 6);
}

test "prover session: init cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkSessionAllocationFailures,
        .{},
    );
}

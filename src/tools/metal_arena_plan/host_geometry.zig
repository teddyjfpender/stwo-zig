const std = @import("std");
const stwo = @import("stwo");
const composition_bundle_mod = stwo.frontends.cairo.witness.composition_bundle;
const feed_bundle_mod = stwo.frontends.cairo.witness.feed_bundle;
const fixed_table_bundle_mod = stwo.frontends.cairo.witness.fixed_table_bundle;
const relation_bundle_mod = stwo.frontends.cairo.witness.relation_bundle;
const witness_bundle_mod = stwo.frontends.cairo.witness.bundle;
const resident_verifier = stwo.frontends.cairo.witness.resident_verifier;
const canonical_protocol = @import("canonical_protocol.zig").canonical_protocol;
const nanosecondsToSeconds = @import("timing.zig").nanosecondsToSeconds;

pub fn runtimeVerifierGeometry(
    config_words: []const u32,
    composition: composition_bundle_mod.Bundle,
) !resident_verifier.ProtocolGeometry {
    const max_log_degree_bound = composition.verifierMaxLogDegreeBound() catch
        return error.InvalidProtocolGeometry;
    return resident_verifier.ProtocolGeometry.fromConfigWords(
        config_words,
        canonical_protocol.interaction_pow_bits,
        4,
        max_log_degree_bound,
    );
}

pub const PreparedStateKey = [32]u8;

pub const HostGeometryPreparationTiming = struct {
    schedule_read_and_hash_wall_s: f64 = 0,
    schedule_json_parse_wall_s: f64 = 0,
    bundle_read_wall_s: f64 = 0,
};

/// Heap-stable owner for immutable host inputs shared by repeated proofs of the
/// same admitted geometry. Proof plans and bindings are deliberately excluded:
/// they still contain per-input geometry and schedule-borrowed names.
pub const PreparedHostGeometry = struct {
    allocator: std.mem.Allocator,
    schedule_bytes: []u8,
    parsed_schedule: std.json.Parsed(std.json.Value),
    schedule_sha256: [64]u8,
    witness_bundle: ?witness_bundle_mod.Bundle,
    feed_bundle: ?feed_bundle_mod.Bundle,
    relation_bundle: ?relation_bundle_mod.Bundle,
    fixed_table_bundle: ?fixed_table_bundle_mod.Bundle,
    composition_bundle: ?composition_bundle_mod.Bundle,
    preparation_timing: HostGeometryPreparationTiming,

    pub fn init(
        allocator: std.mem.Allocator,
        args: []const []const u8,
    ) !*PreparedHostGeometry {
        if (args.len < 3 or args.len > 8) return error.InvalidArguments;
        var timer = try std.time.Timer.start();
        var timing = HostGeometryPreparationTiming{};
        var started_ns = timer.read();
        const schedule_bytes = try std.fs.cwd().readFileAlloc(allocator, args[1], 64 * 1024 * 1024);
        errdefer allocator.free(schedule_bytes);
        var input_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(schedule_bytes, &input_digest, .{});
        const schedule_sha256 = std.fmt.bytesToHex(input_digest, .lower);
        timing.schedule_read_and_hash_wall_s = nanosecondsToSeconds(timer.read() - started_ns);

        started_ns = timer.read();
        var parsed_schedule = try std.json.parseFromSlice(std.json.Value, allocator, schedule_bytes, .{});
        errdefer parsed_schedule.deinit();
        const root = switch (parsed_schedule.value) {
            .object => |object| object,
            else => return error.InvalidSchedule,
        };
        const arena_object = switch (root.get("arena") orelse return error.InvalidSchedule) {
            .object => |object| object,
            else => return error.InvalidSchedule,
        };
        const logical_schedule = arena_object.get("logical_buffer_schedule") orelse
            return error.InvalidSchedule;
        if (logical_schedule != .array) return error.InvalidSchedule;
        if (root.get("compacted_consumer_rows")) |rows| {
            if (rows != .array) return error.InvalidSchedule;
        }
        timing.schedule_json_parse_wall_s = nanosecondsToSeconds(timer.read() - started_ns);

        started_ns = timer.read();
        var witness_bundle: ?witness_bundle_mod.Bundle = if (args.len >= 4)
            try witness_bundle_mod.Bundle.readFile(allocator, args[3])
        else
            null;
        errdefer if (witness_bundle) |*bundle| bundle.deinit();
        var feed_bundle: ?feed_bundle_mod.Bundle = if (args.len >= 5)
            try feed_bundle_mod.Bundle.readFile(allocator, args[4])
        else
            null;
        errdefer if (feed_bundle) |*bundle| bundle.deinit();
        var relation_bundle: ?relation_bundle_mod.Bundle = if (args.len >= 6)
            try relation_bundle_mod.Bundle.readFile(allocator, args[5])
        else
            null;
        errdefer if (relation_bundle) |*bundle| bundle.deinit();
        var fixed_table_bundle: ?fixed_table_bundle_mod.Bundle = if (args.len >= 7)
            try fixed_table_bundle_mod.Bundle.readFile(allocator, args[6])
        else
            null;
        errdefer if (fixed_table_bundle) |*bundle| bundle.deinit();
        var composition_bundle: ?composition_bundle_mod.Bundle = if (args.len == 8)
            try composition_bundle_mod.Bundle.readFile(allocator, args[7])
        else
            null;
        errdefer if (composition_bundle) |*bundle| bundle.deinit();
        timing.bundle_read_wall_s = nanosecondsToSeconds(timer.read() - started_ns);

        const result = try allocator.create(PreparedHostGeometry);
        result.* = .{
            .allocator = allocator,
            .schedule_bytes = schedule_bytes,
            .parsed_schedule = parsed_schedule,
            .schedule_sha256 = schedule_sha256,
            .witness_bundle = witness_bundle,
            .feed_bundle = feed_bundle,
            .relation_bundle = relation_bundle,
            .fixed_table_bundle = fixed_table_bundle,
            .composition_bundle = composition_bundle,
            .preparation_timing = timing,
        };
        return result;
    }

    pub fn deinit(self: *PreparedHostGeometry) void {
        const allocator = self.allocator;
        if (self.composition_bundle) |*bundle| bundle.deinit();
        if (self.fixed_table_bundle) |*bundle| bundle.deinit();
        if (self.relation_bundle) |*bundle| bundle.deinit();
        if (self.feed_bundle) |*bundle| bundle.deinit();
        if (self.witness_bundle) |*bundle| bundle.deinit();
        self.parsed_schedule.deinit();
        allocator.free(self.schedule_bytes);
        allocator.destroy(self);
    }

    pub fn schedule(self: *const PreparedHostGeometry) []const std.json.Value {
        return self.parsed_schedule.value.object.get("arena").?.object
            .get("logical_buffer_schedule").?.array.items;
    }

    pub fn compactedConsumerRows(self: *const PreparedHostGeometry) []const std.json.Value {
        return if (self.parsed_schedule.value.object.get("compacted_consumer_rows")) |value|
            value.array.items
        else
            &.{};
    }
};

//! `ProverParameters`: how a Cairo run is proved (not what is proved).
//!
//! The serde JSON of `crates/common/src/prover_params.rs` at
//! https://github.com/starkware-libs/proving 5a7c5ede4299c91a61df19a07cba4f7502c14230,
//! as carried by a circuit registry's `cairo_prover_params`. This file is the
//! one definition: the Cairo leaf lane consumes it and the circuit-recursion
//! registry loader embeds it. It depends on `std` only, so a registry reader
//! can take it without the Cairo frontend.
//!
//! Encoding: snake_case field names; `channel_hash` and `preprocessed_trace`
//! are unit-variant strings; `lifting_size_policy` is `"auto"`,
//! `"at_least_preprocessed"` or `{"fixed": n}`; `opt_n_id_to_big_components`
//! is `null` or a number.

const std = @import("std");

pub const ChannelHash = enum { blake2s, blake2s_m31, poseidon252 };

pub const PreprocessedTrace = enum { canonical, canonical_small, canonical_without_pedersen };

pub const FriConfig = struct {
    pow_bits: u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: u32,
    fold_step: u32,
};

pub const LiftingSizePolicy = union(enum) {
    /// Trace trees at the trace domain, the preprocessed tree at its own.
    auto,
    /// Every tree at the given height (which includes the blowup).
    fixed: u32,
    /// Every tree at `max(trace domain, preprocessed domain)`.
    at_least_preprocessed,
};

pub const ProverParameters = struct {
    /// Accepted and ignored by the leaf lane, as by upstream `prove_cairo`,
    /// whose channel is the caller's type parameter.
    channel_hash: ChannelHash,
    channel_salt: u32,
    fri_config: FriConfig,
    preprocessed_trace: PreprocessedTrace,
    store_polynomials_coefficients: bool,
    include_all_preprocessed_columns: bool,
    opt_n_id_to_big_components: ?u32,
    lifting_size_policy: LiftingSizePolicy,
};

pub const Error = error{InvalidProverParameters};

const Wire = struct {
    channel_hash: ChannelHash,
    channel_salt: u32,
    fri_config: FriConfig,
    preprocessed_trace: PreprocessedTrace,
    store_polynomials_coefficients: bool,
    include_all_preprocessed_columns: bool,
    opt_n_id_to_big_components: ?u32,
    lifting_size_policy: std.json.Value,
};

/// Parses one `ProverParameters` document.
pub fn parse(allocator: std.mem.Allocator, json: []const u8) !ProverParameters {
    const parsed = try std.json.parseFromSlice(Wire, allocator, json, .{});
    defer parsed.deinit();
    return fromWire(parsed.value);
}

/// Converts an already-parsed JSON value, e.g. a registry's
/// `cairo_prover_params` member.
pub fn fromValue(allocator: std.mem.Allocator, value: std.json.Value) !ProverParameters {
    const parsed = try std.json.parseFromValue(Wire, allocator, value, .{});
    defer parsed.deinit();
    return fromWire(parsed.value);
}

fn fromWire(wire: Wire) Error!ProverParameters {
    return .{
        .channel_hash = wire.channel_hash,
        .channel_salt = wire.channel_salt,
        .fri_config = wire.fri_config,
        .preprocessed_trace = wire.preprocessed_trace,
        .store_polynomials_coefficients = wire.store_polynomials_coefficients,
        .include_all_preprocessed_columns = wire.include_all_preprocessed_columns,
        .opt_n_id_to_big_components = wire.opt_n_id_to_big_components,
        .lifting_size_policy = try policyFromValue(wire.lifting_size_policy),
    };
}

fn policyFromValue(value: std.json.Value) Error!LiftingSizePolicy {
    switch (value) {
        .string => |name| {
            if (std.mem.eql(u8, name, "auto")) return .auto;
            if (std.mem.eql(u8, name, "at_least_preprocessed")) return .at_least_preprocessed;
            return Error.InvalidProverParameters;
        },
        .object => |object| {
            if (object.count() != 1) return Error.InvalidProverParameters;
            const fixed = object.get("fixed") orelse return Error.InvalidProverParameters;
            if (fixed != .integer or fixed.integer < 0 or fixed.integer > std.math.maxInt(u32))
                return Error.InvalidProverParameters;
            return .{ .fixed = @intCast(fixed.integer) };
        },
        else => return Error.InvalidProverParameters,
    }
}

test "prover parameters: the canonical_small leaf registry entry" {
    // `cairo_prover_params` of proving@5a7c5ed
    // crates/leaf_prover/tests/data/circuit_registry_canonical_small.json.
    const json =
        \\{"channel_hash": "blake2s", "channel_salt": 0, "fri_config": {"pow_bits": 16,
        \\ "log_blowup_factor": 1, "log_last_layer_degree_bound": 0, "n_queries": 70,
        \\ "fold_step": 1}, "preprocessed_trace": "canonical_small",
        \\ "store_polynomials_coefficients": false, "include_all_preprocessed_columns": true,
        \\ "opt_n_id_to_big_components": 16, "lifting_size_policy": "at_least_preprocessed"}
    ;
    const params = try parse(std.testing.allocator, json);
    try std.testing.expectEqual(ChannelHash.blake2s, params.channel_hash);
    try std.testing.expectEqual(@as(u32, 16), params.fri_config.pow_bits);
    try std.testing.expectEqual(@as(u32, 70), params.fri_config.n_queries);
    try std.testing.expectEqual(PreprocessedTrace.canonical_small, params.preprocessed_trace);
    try std.testing.expect(params.include_all_preprocessed_columns);
    try std.testing.expectEqual(@as(?u32, 16), params.opt_n_id_to_big_components);
    try std.testing.expectEqual(LiftingSizePolicy.at_least_preprocessed, params.lifting_size_policy);
}

test "prover parameters: every lifting policy encoding" {
    const allocator = std.testing.allocator;
    const base =
        \\{{"channel_hash": "blake2s_m31", "channel_salt": 7, "fri_config": {{"pow_bits": 26,
        \\ "log_blowup_factor": 1, "log_last_layer_degree_bound": 0, "n_queries": 70,
        \\ "fold_step": 1}}, "preprocessed_trace": "canonical",
        \\ "store_polynomials_coefficients": true, "include_all_preprocessed_columns": false,
        \\ "opt_n_id_to_big_components": null, "lifting_size_policy": {s}}}
    ;
    var buffer: [512]u8 = undefined;
    const fixed = try parse(allocator, try std.fmt.bufPrint(&buffer, base, .{"{\"fixed\": 25}"}));
    try std.testing.expectEqual(LiftingSizePolicy{ .fixed = 25 }, fixed.lifting_size_policy);
    try std.testing.expectEqual(@as(?u32, null), fixed.opt_n_id_to_big_components);
    try std.testing.expectEqual(ChannelHash.blake2s_m31, fixed.channel_hash);
    const auto = try parse(allocator, try std.fmt.bufPrint(&buffer, base, .{"\"auto\""}));
    try std.testing.expectEqual(LiftingSizePolicy.auto, auto.lifting_size_policy);
    try std.testing.expectError(
        Error.InvalidProverParameters,
        parse(allocator, try std.fmt.bufPrint(&buffer, base, .{"\"tallest\""})),
    );
    try std.testing.expectError(
        Error.InvalidProverParameters,
        parse(allocator, try std.fmt.bufPrint(&buffer, base, .{"{\"fixed\": -1}"})),
    );
}

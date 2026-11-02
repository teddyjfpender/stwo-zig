const std = @import("std");
const core = @import("stwo_core");
const W = @import("worker_protocol.zig");
const E = @import("execution.zig");
fn control() !W.PcsConfig {
    var config = W.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.ForField(W.O).FriConfig.init(0, 1, 70) };
    config.fri_config.fold_step = 4;
    return config;
}
fn reject(config: W.PcsConfig) !void {
    try std.testing.expectError(error.UnsupportedWideServicesConfig, W.validateConfig(config));
    try std.testing.expectError(error.UnsupportedWideServicesConfig, E.validateConfig(config));
}
test "wide worker and execution share exact supported profile boundaries" {
    for ([_]u32{ 0, 26, 32 }) |pow| for ([_]usize{ 1, 12, 70, 1024 }) |queries| for ([_]u32{ 1, 4 }) |fold| {
        var config = try control();
        config.pow_bits = pow;
        config.fri_config.n_queries = queries;
        config.fri_config.fold_step = fold;
        try W.validateConfig(config);
        try E.validateConfig(config);
    };
    for ([_]u32{ 33, 64, std.math.maxInt(u32) }) |pow| {
        var config = try control();
        config.pow_bits = pow;
        try reject(config);
    }
    for ([_]usize{ 0, 1025 }) |queries| {
        var config = try control();
        config.fri_config.n_queries = queries;
        try reject(config);
    }
    for ([_]u32{ 0, 2, 3 }) |rate| {
        var config = try control();
        config.fri_config.log_blowup_factor = rate;
        try reject(config);
    }
    for ([_]u32{ 0, 2, 8 }) |fold| {
        var config = try control();
        config.fri_config.fold_step = fold;
        try reject(config);
    }
    var config = try control();
    config.fri_config.log_last_layer_degree_bound = 1;
    try reject(config);
    config = try control();
    config.lifting_log_size = 22;
    try reject(config);
}
test "wide control validation neither changes parameters nor advances transcript" {
    const config = try control();
    const before = config;
    var channel = W.Channel.init();
    config.mixInto(&channel);
    var reference = channel;
    try W.validateConfig(config);
    try std.testing.expectEqualDeep(before, config);
    try std.testing.expectEqualDeep(reference.digestBytes(), channel.digestBytes());
    try std.testing.expect(reference.drawSecureFelt().eql(channel.drawSecureFelt()));
}

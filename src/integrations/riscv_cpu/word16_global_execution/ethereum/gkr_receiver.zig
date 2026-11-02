//! Ethereum acceptance for the explicitly selected experimental OM/GKR lane.
//! Whole-execution proof validity and Ethereum completion are distinct checks.
const std = @import("std");
const Image = @import("../../word16_execution/expected_image.zig");
const Program = @import("../../word16_execution/program.zig").Program;
const C = @import("../services/gkr_local/coordinator.zig");
const W = @import("../services/gkr_local/worker_protocol.zig");
const Keys = @import("keys.zig");
const Receiver = @import("receiver.zig");
const Terminal = @import("terminal.zig");
const FixedSet = @import("../services/gkr_local/fixed_authority_set.zig").Set;
pub fn verify(a: std.mem.Allocator, image: *const Image.Owner, keys: *const Keys.Owner, bundle: *const C.Bundle, max_steps: u64, batch_steps: u32, completed: bool, config: W.PcsConfig) !?[43]u8 {
    return verifyWithAuthority(a, image, keys, bundle, max_steps, batch_steps, completed, config, null);
}
/// Explicit engineering candidate authority is independently reconstructed by
/// this receiver. Bundle declarations cannot supply its keys or configuration.
pub fn verifyWithAuthority(a: std.mem.Allocator, image: *const Image.Owner, keys: *const Keys.Owner, bundle: *const C.Bundle, max_steps: u64, batch_steps: u32, completed: bool, config: W.PcsConfig, fixed: ?*const FixedSet) !?[43]u8 {
    var program = try Program.initWithAuthority(a, &image.authority);
    defer program.deinit();
    const statement = try Receiver.expectedFromRequests(image, program.identity, bundle.requests, max_steps, batch_steps, completed);
    const accepted = if (fixed) |authority| try bundle.verifyWithAuthority(a, keys.cpus, keys.truths, statement, config, authority) else try bundle.verify(a, keys.cpus, keys.truths, statement, config);
    if (!accepted.completed or accepted.total_steps != statement.total_steps) return error.IncompleteWideExecution;
    // A proved prefix is never an Ethereum block, even when its producer reports
    // the same endpoint in both the request and manifest.
    if (!completed) return null;
    const last = bundle.requests[bundle.requests.len - 1].base;
    return try Terminal.require(image, last.cpu, last.memory.terminal);
}

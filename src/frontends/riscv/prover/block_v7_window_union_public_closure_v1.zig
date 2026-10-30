//! Pure public algebra. A successful result confers no proof authority: the
//! receiver must authenticate every physical claim with the joined verifier.
const std = @import("std");
const Multi = @import("block_v7_multi_union_proof_v1.zig").ForMode(true);
pub const Summary = @import("block_v7_global_public_closure_v1.zig").Summary;
pub fn close(a: std.mem.Allocator, components: *const Multi.AdmittedComponents, input: Multi.Input, claims: *const Multi.Claims) !Summary {
    const ctx = components.context;
    const scope = components.scope;
    const memory = try @import("block_v7_window_memory_joint_protocol_v1.zig").closeVerifiedClaims(scope.policy, ctx.drawn.word.initial, claims.memory());
    var closure = try @import("block_v7_execution_claim_closure_v1.zig").Accumulator.init(a, input.natives.len, input.callers.len, claims.program, input.program_plan.expected_fetches, claims.lookup, memory);
    defer closure.deinit();
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    for (claims.native, input.natives, 0..) |claim, pin, index| try closure.addNative(index, try @import("block_v7_native_source_v1.zig").exportsFromClaims(scratch.allocator(), pin, claim.claims, claim.access, &ctx.drawn));
    for (claims.callers, input.callers, ctx.callers) |claim, pin, *caller| try closure.addCaller(pin.execution_index, try @import("block_v7_caller_active_source_v1.zig").exports(&caller.schedule, &claim.arithmetic, &claim.relations));
    const totals = try closure.finish();
    return .{ .statement = try scope.policy.digest(), .epoch = input.epoch.digest, .cycles = scope.policy.finalCycle(), .segments = @intCast(input.natives.len), .ram_events = totals.events, .program_fetches = totals.fetches, .output = @splat(0), .scope = .declared_window };
}

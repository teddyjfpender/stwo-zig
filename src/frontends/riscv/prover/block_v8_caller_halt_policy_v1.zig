//! Nonterminal first-halt constraints over the SAME authenticated caller tuples
//! used by the RAM relation. Endpoint equality cannot erase write-one/clear-zero.
//! This module alone is not caller or complete-window proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Halt = @import("block_v8_native_halt_policy_v1.zig");
const Access = @import("block_execution_access_bridge_v2.zig");
const Samples = @import("block_v8_caller_ram_component_v1.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const production_active = false;
pub const COLUMN_COUNT = Halt.COLUMN_COUNT;
pub const CONSTRAINT_COUNT = Halt.CONSTRAINT_COUNT;
pub const DEGREE: u8 = 2;
pub const Policy = Halt.Policy;
pub fn validate(policy: Policy) !void {
    try policy.validate();
    // Caller terminal windows need a separate reviewed final-retirement policy.
    if (policy.permitted_final_instruction_cycle != null) return error.UnqualifiedCallerTerminalHaltPolicy;
}
pub fn constraints(comptime S: type, policy: Policy, pair: Access.Pair(S), instruction_cycle: S, aux: [2]S) ![CONSTRAINT_COUNT]S {
    try validate(policy);
    if (pair.address_unit != .byte_address or pair.consume_clock == null) return error.InvalidCallerHaltAccess;
    return Halt.constraints(S, policy, pair.active, pair.source_address, instruction_cycle, pair.after, aux);
}
pub fn witness(pair: Access.Pair(Q), policy: Policy) ![2]M {
    try validate(policy);
    if (pair.address_unit != .byte_address or pair.consume_clock == null) return error.InvalidCallerHaltAccess;
    if (!pair.active.eql(Q.zero()) and !pair.active.eql(Q.one())) return error.InvalidCallerHaltActive;
    return Halt.witness(pair.active.eql(Q.one()), try pair.source_address.tryIntoM31(), policy);
}
/// Point evaluations must keep active and the original current/+27 tuples
/// algebraic. No branch on an OODS enabler and no producer-built zero pair.
pub fn fromSamples(descriptor: @import("block_v8_caller_ram_projection_v1.zig").Descriptor, policy: Policy, samples: anytype, aux: [2]Q) ![CONSTRAINT_COUNT]Q {
    const access = try Samples.accessFromSamples(descriptor, samples);
    return constraints(Q, policy, access.pair, access.instruction_cycle, aux);
}

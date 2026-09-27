//! Joint job/statement identities with one authenticated scalar and byte producer.
const std = @import("std");
const core = @import("stwo_core");
const identity = @import("../span_identity_blake3.zig");
const graph = @import("../statement_semantics_circuit_blake3.zig");
const parent = @import("blake3_span_identity_binding.zig");
const inputs = @import("blake3_span_identity_inputs.zig");
const routing = @import("blake3_span_identity_route.zig");
const hashing = @import("blake3_span_identity_hash.zig");
pub const Claims = struct { statement: identity.Digest, job: identity.Digest };
pub const Prepared = struct {
    statement: parent.Prepared,
    job: hashing.Prepared,
    pub fn deinit(self: *Prepared) void {
        self.job.deinit();
        self.statement.deinit();
        self.* = undefined;
    }
};
pub const Plan = struct {
    statement: parent.Plan,
    job_routes: routing.Plan,
    job_circuit: u32,
    pub fn deinit(self: *Plan) void {
        self.job_routes.deinit();
        self.statement.deinit();
        self.* = undefined;
    }
    pub fn prepare(self: *const Plan, a: std.mem.Allocator, words: *const identity.StatementWords, claims: Claims) !Prepared {
        var statement = try self.statement.prepare(a, words, claims.statement);
        errdefer statement.deinit();
        return .{ .statement = statement, .job = try hashing.prepare(a, .job, .{ .circuit = self.statement.circuits.bytes, .first_wire = 0 }, self.job_circuit, words, claims.job) };
    }
};
pub fn buildParent(a: std.mem.Allocator, circuit: *const graph.Circuit, ids: inputs.Circuits, job_circuit: u32) !Plan {
    if (job_circuit >= core.fields.m31.Modulus) return error.InvalidSpanIdentityCircuits;
    for ([_]u32{ ids.scalar, ids.packing, ids.bytes, ids.hash }) |id| if (id == job_circuit) return error.InvalidSpanIdentityCircuits;
    var statement = try parent.buildParent(a, circuit, .statement, ids);
    errdefer statement.deinit();
    var job = try routing.build(a, .job, .{ .circuit = ids.bytes, .first_wire = 0 }, job_circuit);
    errdefer job.deinit();
    // Packing consumes each scalar only once. Only the byte producers fan out
    // to a second hash; parent row-11 multiplicities therefore stay unchanged.
    for (job.statement_uses, 0..) |uses, index| {
        const destination = &statement.inputs.encoding[index / 4].uses[index % 4];
        destination.* = try std.math.add(u32, destination.*, uses);
    }
    return .{ .statement = statement, .job_routes = job, .job_circuit = job_circuit };
}

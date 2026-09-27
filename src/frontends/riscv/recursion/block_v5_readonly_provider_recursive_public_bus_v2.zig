//! Exact original claims and authenticated group coordinates. All actual
//! source/provider joins remain open beyond this genuine recursive leaf.
const std = @import("std");
const core = @import("stwo_core");
const Policy = struct {
    pub const Admission = @import("../prover/block_v5_readonly_provider_recursive_admission_v2.zig");
    pub const Capture = @import("../prover/block_v5_readonly_provider_recursive_capture_v2.zig").VerifiedCapture;
    pub const Claims = @import("../prover/block_v5_readonly_input_provider_component_v2.zig").Claim;
    pub const Statement = @import("air/block_v5_readonly_provider_statement_v2.zig");
    pub const IDENTITY_TAG: u32 = 0x42355049;
    pub const SCHEDULE_TAG: u32 = 0x42355057;
    pub fn rootsCount(_: *const Admission.Prepared) usize {
        return 2;
    }
    pub fn claims(capture: *const Capture) Claims {
        return capture.receipt.claim;
    }
    pub fn validateClaims(admitted: *const Admission.Prepared, proposed: Claims) !void {
        var channel = core.proof_suites.Blake3.Channel{};
        try @import("../prover/block_v5_readonly_input_provider_proof_v2.zig").mixPcsSuffix(&channel, admitted.pin, proposed);
    }
    pub fn statement(a: std.mem.Allocator, admitted: *const Admission.Prepared, proposed: Claims) !Statement.Statement {
        return Statement.initClaims(a, admitted, proposed);
    }
    pub fn publicInputs(a: std.mem.Allocator, admitted: *const Admission.Prepared, proposed: Claims) ![]core.fields.qm31.QM31 {
        try validateClaims(admitted, proposed);
        const Q = core.fields.qm31.QM31;
        const M = core.fields.m31.M31;
        const values = try a.alloc(Q, 20);
        values[0..11].* = .{ proposed.classification_sum, proposed.read_sum } ++ proposed.range_sums;
        for (0..4) |i| {
            values[11 + i] = Q.fromBase(M.fromCanonical(@intCast((proposed.counts.events >> @as(u6, @intCast(16 * i))) & 65535)));
            values[15 + i] = Q.fromBase(M.fromCanonical(@intCast((proposed.counts.readonly >> @as(u6, @intCast(16 * i))) & 65535)));
        }
        values[19] = Q.fromBase(M.fromCanonical(admitted.pin.shape.group_id));
        return values;
    }
};
pub const API = @import("block_v5_recursive_fused_public_bus_v1.zig").ForFamily(Policy);
pub const VERSION = API.VERSION;
pub const PUBLIC_CIRCUIT = API.PUBLIC_CIRCUIT;
pub const MAX_WIRES = API.MAX_WIRES;
pub const Source = API.Source;
pub const Wire = API.Wire;
pub const Values = API.Values;
pub const Prepared = API.Prepared;
pub const scheduleDigest = API.scheduleDigest;
pub const supply = API.supply;
pub const prepare = API.prepare;

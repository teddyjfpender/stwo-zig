//! Exact original claims and authenticated group coordinates. All actual
//! source/provider joins remain open beyond this genuine recursive leaf.
const std = @import("std");
const core = @import("stwo_core");
const Policy = struct {
    pub const Admission = @import("../prover/block_v5_native_readonly_source_recursive_admission_v2.zig");
    pub const Capture = @import("../prover/block_v5_native_readonly_source_recursive_capture_v2.zig").VerifiedCapture;
    pub const Claims = @import("../prover/block_v5_readonly_input_protocol_v1.zig").Claim;
    pub const Statement = @import("air/block_v5_native_readonly_source_statement_v2.zig");
    pub const IDENTITY_TAG: u32 = 0x42354e49;
    pub const SCHEDULE_TAG: u32 = 0x42354e57;
    pub fn rootsCount(_: *const Admission.Prepared) usize {
        return 2;
    }
    pub fn claims(capture: *const Capture) Claims {
        return capture.receipt.claim;
    }
    pub fn validateClaims(admitted: *const Admission.Prepared, proposed: Claims) !void {
        var channel = core.proof_suites.Blake3.Channel{};
        try @import("../prover/block_v5_native_readonly_source_proof_v2.zig").mixPcsSuffix(&channel, admitted.pin, proposed);
    }
    pub fn statement(a: std.mem.Allocator, admitted: *const Admission.Prepared, proposed: Claims) !Statement.Statement {
        return Statement.initClaims(a, admitted, proposed);
    }
    pub fn publicInputs(a: std.mem.Allocator, admitted: *const Admission.Prepared, proposed: Claims) ![]core.fields.qm31.QM31 {
        try validateClaims(admitted, proposed);
        const Q = core.fields.qm31.QM31;
        const M = core.fields.m31.M31;
        const values = try a.alloc(Q, 6);
        values[0..4].* = .{ proposed.source_sum, proposed.mutable_sum, proposed.classification_sum, proposed.read_sum };
        values[4] = Q.fromBase(M.fromCanonical(@intCast(proposed.readonly_count)));
        values[5] = Q.fromBase(M.fromCanonical(admitted.pin.group_id));
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

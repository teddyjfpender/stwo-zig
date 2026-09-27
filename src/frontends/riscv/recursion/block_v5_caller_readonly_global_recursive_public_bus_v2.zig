//! Typed caller-fused public inputs. An arithmetic companion and complete
//! global closure remain necessary after this recursive verifier leaf.
const std = @import("std");
const Policy = struct {
    pub const Admission = @import("../prover/block_v5_caller_readonly_global_recursive_admission_v2.zig");
    pub const Capture = @import("../prover/block_v5_caller_readonly_global_recursive_capture_v2.zig").VerifiedCapture;
    pub const Claims = Admission.Fused.ClaimFrames;
    pub const Statement = @import("air/block_v5_caller_readonly_global_statement_v2.zig");
    pub const IDENTITY_TAG: u32 = 0x42354a49;
    pub const SCHEDULE_TAG: u32 = 0x42354a57;
    pub fn rootsCount(_: *const Admission.Prepared) usize {
        return 3;
    }
    pub fn claims(capture: *const Capture) Claims {
        return capture.original.claims;
    }
    pub fn validateClaims(admitted: *const Admission.Prepared, proposed: Claims) !void {
        var channel = @import("stwo_core").proof_suites.Blake3.Channel{};
        const classification = try Admission.Fused.classification(admitted.allocator, admitted.sealed, admitted.plan, admitted.binding, admitted.witness_root, admitted.frame, &admitted.schedule, admitted.readonly);
        try Admission.Fused.mixClaims(&channel, admitted.binding, &admitted.schedule, &proposed, admitted.plan, &classification, admitted.readonly);
    }
    pub fn statement(a: std.mem.Allocator, admitted: *const Admission.Prepared, proposed: Claims) !Statement.Statement {
        return Statement.initClaims(a, admitted, proposed);
    }
    pub fn publicInputs(a: std.mem.Allocator, admitted: *const Admission.Prepared, proposed: Claims) ![]@import("stwo_core").fields.qm31.QM31 {
        return @import("air/block_v5_caller_readonly_global_composition_v2.zig").publicInputs(a, admitted, proposed);
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

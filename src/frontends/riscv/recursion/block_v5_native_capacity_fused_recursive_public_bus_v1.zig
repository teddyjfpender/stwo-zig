//! Typed complete native B5CF public statement; base-native verification
//! remains a genuine companion-child obligation for final block closure.
const std = @import("std");
const Fused = @import("../prover/block_v5_native_capacity_fused_proof_v1.zig");
const Memory = @import("../prover/block_v5_opcode_memory_sidecar_proof_v1.zig");
const ClaimInput = struct { projection: []const Fused.Claim, memory: []const Memory.Claim };
pub const Claims = ClaimInput;
const Policy = struct {
    pub const Admission = @import("../prover/block_v5_native_capacity_fused_recursive_admission_v1.zig");
    pub const Capture = @import("../prover/block_v5_native_capacity_fused_recursive_capture_v1.zig").VerifiedCapture;
    pub const Claims = ClaimInput;
    pub const Statement = @import("air/block_v5_native_capacity_fused_statement_v1.zig");
    pub const IDENTITY_TAG: u32 = 0x42355949; // B5YI
    pub const SCHEDULE_TAG: u32 = 0x42355957; // B5YW
    pub fn rootsCount(admitted: *const Admission.Prepared) usize {
        return admitted.tree_count - 1;
    }
    pub fn claims(capture: *const Capture) ClaimInput {
        return .{ .projection = capture.metadata.claims, .memory = capture.metadata.memory_claims };
    }
    pub fn validateClaims(admitted: *const Admission.Prepared, proposed: ClaimInput) !void {
        var channel = @import("stwo_core").proof_suites.Blake3.Channel{};
        try Fused.mixClaims(&channel, admitted.binding.template_id, admitted.binding.instance_id, admitted.native.index, admitted.projections, admitted.slots, proposed.projection, proposed.memory);
    }
    pub fn statement(a: std.mem.Allocator, admitted: *const Admission.Prepared, proposed: ClaimInput) !Statement.Statement {
        // The original native statement owns exact pre-allocation extent
        // admission and every first/claim invocation boundary unchanged.
        return Statement.Statement.initClaims(a, admitted, proposed.projection, proposed.memory);
    }
    pub fn publicInputs(a: std.mem.Allocator, admitted: *const Admission.Prepared, proposed: ClaimInput) ![]@import("stwo_core").fields.qm31.QM31 {
        return @import("air/block_v5_native_capacity_fused_composition_v1.zig").publicInputsFromClaims(a, admitted, proposed.projection, proposed.memory);
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

//! Independent metadata and proof-loading contract for the first block-v5
//! orchestration slice. Expected policy is supplied outside produced proofs.
//! No legacy recursive admission or preverified receipt appears in this DTO.
const std = @import("std");
const Seal = @import("block_v5_source_seal_v1.zig");
const Program = @import("block_v5_program_table_v1.zig");
const ProgramsV2 = @import("block_v5_program_native_batch_receiver_v1.zig");
const ProgramsV3 = @import("block_v5_program_native_batch_receiver_v3.zig");
const Catalog = @import("block_v5_native_template_catalog_v1.zig");
const Memory = @import("block_v5_memory_batch_receiver_v1.zig");
const Sources = @import("block_v5_initial_sources_v1.zig");
const Endpoints = @import("block_v5_rw_endpoint_sources_v1.zig");
const EndpointReceiver = @import("block_v5_rw_endpoint_receiver_v1.zig");

pub const VERSION: u32 = 1;
pub const Pins = PinsFor(false);
pub const LightweightPins = PinsFor(true);
pub const Inputs = InputsFor(false);
pub const LightweightInputs = InputsFor(true);
fn ProgramsFor(comptime lightweight: bool) type {
    return if (lightweight) ProgramsV3 else ProgramsV2;
}
fn PinsFor(comptime lightweight: bool) type {
    const Programs = ProgramsFor(lightweight);
    return struct {
        const Self = @This();
        seal: Seal.Pins,
        expected_seal_digest: [32]u8,
        roster: []const Seal.Entry,
        program: Program.Plan,
        executions: []const Programs.InstancePin,
        extensions: []const Programs.ExtensionPin = &.{},
        catalog: Catalog.Admission,
        memory: Memory.Pins,
        endpoints: ?Endpoints.Pins = null,

        pub fn validate(self: Self) !Seal.Sealed {
            const sealed = try Seal.seal(self.seal, self.roster);
            if (!std.meta.eql(sealed.digest, self.expected_seal_digest) or
                !std.meta.eql(self.memory.seal, self.seal) or
                !std.meta.eql(self.memory.expected_seal_digest, self.expected_seal_digest) or
                !sameRoster(self.memory.first_round, self.roster) or
                !std.meta.eql(try self.memory.source.digest(), self.seal.initial_source_plan_digest) or
                !std.meta.eql(try self.program.digest(), self.seal.program_plan_digest) or
                !std.meta.eql(self.program.program_root.bytes, self.seal.program_root) or
                !std.meta.eql(try self.catalog.digest(), self.seal.native_template_catalog_digest))
                return error.UntrustedV5BlockArtifactPins;
            if (self.endpoints) |endpoint| {
                if (!std.meta.eql(endpoint.initial, self.memory.source) or
                    !std.meta.eql(try endpoint.digest(), self.seal.rw_endpoint_plan_digest) or
                    !std.meta.eql(endpoint.expected_final_rw_root, self.seal.expected_final_rw_root))
                    return error.UntrustedV5BlockEndpointPins;
            } else if (!std.mem.allEqual(u8, &self.seal.rw_endpoint_plan_digest, 0) or
                !std.mem.allEqual(u8, &self.seal.expected_final_rw_root, 0))
                return error.MissingV5BlockEndpointPins;
            return sealed;
        }
    };
}

fn sameRoster(left: []const Seal.Entry, right: []const Seal.Entry) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| if (!std.meta.eql(a, b)) return false;
    return true;
}

/// Proofs remain file-backed or caller-staged; loaders transfer them one at a
/// time for fresh verification. No raw proof array or open receipt is retained.
fn InputsFor(comptime lightweight: bool) type {
    return struct {
        program: ProgramsFor(lightweight).Loader,
        memory: Memory.ProofLoader,
        public_input: []const u8,
        initial_sources: Sources.Files,
        endpoints: ?EndpointInputs = null,
    };
}
pub const EndpointInputs = struct {
    file: std.fs.File,
    loader: EndpointReceiver.Loader,
};

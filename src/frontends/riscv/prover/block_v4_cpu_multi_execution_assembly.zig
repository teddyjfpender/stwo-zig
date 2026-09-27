//! One prepared Ethereum-SHA execution leaf and optional sparse caller AIR.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Native = @import("blake3_ethereum_sha_proof.zig").ForBackend(Cpu);
const Opcode = @import("block_execution_sha_artifact_v2.zig");
const External = @import("block_execution_sha_external_artifact_v2.zig");
const external_trace = @import("block_execution_external_trace_v2.zig");
const counter = @import("../air/lookups/tables/counter.zig").Counter;
const seal = @import("block_memory_source_seal_v2.zig").SourceSeal;
const Segment = @import("../runner/result.zig").EthereumShaSegmentResult;

pub const Execution = struct {
    a: std.mem.Allocator,
    owner: *Profile.Witness,
    prepared: *Native.PreparedVerifier,
    artifact: union(enum) {
        opcode: Opcode.ForBackend(Cpu),
        external: External.ForBackend(Cpu),
    },
    serialized: ?union(enum) {
        opcode: Opcode.Serialized,
        external: External.Serialized,
    } = null,

    pub fn init(a: std.mem.Allocator, segment: *Segment, index: u32, config: core.pcs.PcsConfig, trusted_key: [32]u8) !Execution {
        return initInternal(a, segment, index, config, trusted_key);
    }

    /// Test scaffolding derives a key from its just-created native statement;
    /// public assembly always calls `init` with an independent key pin.
    pub fn initForFixture(a: std.mem.Allocator, segment: *Segment, index: u32, config: core.pcs.PcsConfig) !Execution {
        return initInternal(a, segment, index, config, null);
    }

    fn initInternal(a: std.mem.Allocator, segment: *Segment, index: u32, config: core.pcs.PcsConfig, trusted_key: ?[32]u8) !Execution {
        const owner = try a.create(Profile.Witness);
        errdefer a.destroy(owner);
        owner.* = try Profile.Witness.initCompactSegment(a, segment);
        errdefer owner.deinit();
        const prepared = try Native.PreparedVerifier.initCompact(a, &owner.native.statement, owner.statement, try owner.admission(), config, owner.native.compact_ranges.?.plan);
        errdefer prepared.deinit();
        try prepared.validate(trusted_key orelse prepared.id);
        const frame = @import("../air/block/memory_event.zig").Frame{
            .clock_frame = segment.base.clock_frame,
            .global_first_cycle = segment.base.global_first_cycle,
            .cycle_count = @intCast(segment.base.cycle_count),
        };
        const calls = try external_trace.expectedEventCount(&owner.statement);
        const artifact: @FieldType(Execution, "artifact") = if (calls == 0)
            .{ .opcode = try Opcode.ForBackend(Cpu).init(a, owner, prepared, frame, index, config) }
        else
            .{ .external = try External.ForBackend(Cpu).init(a, owner, prepared, frame, index, config) };
        return .{ .a = a, .owner = owner, .prepared = prepared, .artifact = artifact };
    }

    pub fn opcode(self: *Execution) *Opcode.ForBackend(Cpu) {
        return switch (self.artifact) {
            .opcode => |*value| value,
            .external => |*value| &value.opcode,
        };
    }
    pub fn external(self: *Execution) ?*External.ForBackend(Cpu) {
        return switch (self.artifact) {
            .opcode => null,
            .external => |*value| value,
        };
    }
    pub fn opcodeCount(self: *Execution) u64 {
        return self.opcode().event_count;
    }
    pub fn externalCount(self: *Execution) !u64 {
        return if (self.external()) |value| try value.externalEventCount() else 0;
    }
    pub fn nativeRoots(self: *Execution) [2][32]u8 {
        return self.opcode().native_roots;
    }
    pub fn opcodeWitnessRoot(self: *Execution) [32]u8 {
        return self.opcode().witnessRoot();
    }
    pub fn externalWitnessRoot(self: *Execution) ?[32]u8 {
        return if (self.external()) |value| value.externalWitnessRoot() else null;
    }
    pub fn opcodeCounter(self: *Execution) *const counter {
        return &self.opcode().counter;
    }
    pub fn externalCounter(self: *Execution) ?*const counter {
        return if (self.external()) |value| value.externalCounter() else null;
    }

    pub fn prove(self: *Execution, bound: seal, pool: *engine.work_pool.WorkPool) !void {
        if (self.serialized != null) return error.ExecutionAlreadyProved;
        self.serialized = switch (self.artifact) {
            .opcode => |*value| .{ .opcode = try value.proveAndSerialize(self.owner, self.prepared, bound, pool) },
            .external => |*value| .{ .external = try value.proveAndSerialize(self.owner, self.prepared, bound, pool) },
        };
    }
    pub fn opcodeWire(self: *Execution) @import("block_execution_batch_receiver_v2.zig").Wire {
        return switch (self.serialized.?) {
            .opcode => |*value| value.wire(),
            .external => |*value| value.opcodeWire(),
        };
    }
    pub fn externalWire(self: *Execution, index: u32) ?@import("block_memory_batch_wire_v3.zig").SerializedExternalProof {
        return switch (self.serialized.?) {
            .opcode => null,
            .external => |*value| .{ .instance_index = index, .stark_bytes = value.external_stark, .claims = value.external_claims },
        };
    }
    /// The proof was durably staged; release transient serialized bytes while
    /// keeping first-round columns and prepared verifier for the current core.
    pub fn releaseSerialized(self: *Execution) void {
        if (self.serialized) |*value| switch (value.*) {
            .opcode => |*item| item.deinit(self.a),
            .external => |*item| item.deinit(self.a),
        };
        self.serialized = null;
    }
    pub fn deinit(self: *Execution) void {
        self.releaseSerialized();
        switch (self.artifact) {
            .opcode => |*value| value.deinit(),
            .external => |*value| value.deinit(),
        }
        self.prepared.deinit();
        self.owner.deinit();
        self.a.destroy(self.owner);
        self.* = undefined;
    }
};

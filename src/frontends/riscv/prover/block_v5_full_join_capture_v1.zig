//! Owned test proof transport plus real private fresh hooks.
const std = @import("std");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Programs = @import("block_v5_program_native_batch_receiver_v3.zig");
const Request = @import("block_v5_program_request_proof_v1.zig");
const Table = @import("block_v5_program_table_proof_v1.zig");
const Projection = @import("block_v5_native_lookup_request_proof_v1.zig");
const Provider = @import("block_v5_native_lookup_proof_v1.zig");
const Opcode = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Tables = @import("block_v5_native_table_join_v1.zig");
const Memory = @import("block_v5_word_memory_join_v1.zig");
const Caller = @import("block_v5_precompile_family_proof_v1.zig");
const CallerProgram = @import("block_v5_program_extension_proof_v1.zig");
const CallerState = @import("block_v5_precompile_state_request_proof_v1.zig");
const CallerTables = @import("block_v5_precompile_lookup_proof_v1.zig");
const External = @import("block_v5_external_memory_sidecar_proof_v1.zig");
pub const Capture = struct {
    native: ?Native.Proof = null,
    request: ?Request.Proof = null,
    table: ?Table.Proof = null,
    projection: ?Projection.Proof = null,
    provider: ?Provider.Proof = null,
    opcode: ?Opcode.Proof = null,
    caller: ?Caller.Proof = null,
    caller_program: ?CallerProgram.Proof = null,
    caller_state: ?CallerState.Proof = null,
    caller_tables: ?CallerTables.Proof = null,
    external: ?External.Proof = null,
    request_loads: u32 = 0,
    projection_loads: u32 = 0,
    opcode_loads: u32 = 0,
    pub fn deinit(self: *Capture, a: std.mem.Allocator) void {
        inline for (.{ "native", "request", "table", "projection", "provider", "opcode", "caller", "caller_program", "caller_state", "caller_tables", "external" }) |field|
            if (@field(self, field)) |*proof| proof.deinit(a);
    }
    fn take(comptime field: []const u8, ctx: *anyopaque, index: u32) !@typeInfo(@FieldType(Capture, field)).optional.child {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        if (index != 0) return error.InvalidFullJoinFixtureIndex;
        const proof = @field(self, field) orelse return error.MissingFullJoinFixtureProof;
        @field(self, field) = null;
        return proof;
    }
    fn nativeProof(ctx: *anyopaque, index: u32) anyerror!Native.Proof {
        return take("native", ctx, index);
    }
    fn requestProof(ctx: *anyopaque, index: u32) anyerror!Request.Proof {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        self.request_loads += 1;
        return take("request", ctx, index);
    }
    fn tableProof(ctx: *anyopaque) anyerror!Table.Proof {
        return take("table", ctx, 0);
    }
    fn projectionProof(ctx: *anyopaque, index: u32) anyerror!Projection.Proof {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        self.projection_loads += 1;
        return take("projection", ctx, index);
    }
    fn providerProof(ctx: *anyopaque, index: u32) anyerror!Provider.Proof {
        return take("provider", ctx, index);
    }
    fn opcodeProof(ctx: *anyopaque, index: u32) anyerror!Opcode.Proof {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        self.opcode_loads += 1;
        return take("opcode", ctx, index);
    }
    fn callerProof(ctx: *anyopaque, index: u32) anyerror!Caller.Proof {
        return take("caller", ctx, index);
    }
    fn callerProgramProof(ctx: *anyopaque, index: u32) anyerror!CallerProgram.Proof {
        return take("caller_program", ctx, index);
    }
    fn callerStateProof(ctx: *anyopaque, index: u32) anyerror!CallerState.Proof {
        return take("caller_state", ctx, index);
    }
    fn callerTablesProof(ctx: *anyopaque, index: u32) anyerror!CallerTables.Proof {
        return take("caller_tables", ctx, index);
    }
    fn externalProof(ctx: *anyopaque, index: u32) anyerror!External.Proof {
        return take("external", ctx, index);
    }
    pub fn programLoader(self: *Capture) Programs.Loader {
        return .{ .context = self, .take_native = nativeProof, .take_request = requestProof, .take_table = tableProof, .take_precompile = callerProof, .take_extension_request = callerProgramProof };
    }
    pub fn tableLoader(self: *Capture) Tables.Loader {
        return .{ .context = self, .take_provider = providerProof, .take_projection = projectionProof, .take_caller_state = callerStateProof, .take_caller_tables = callerTablesProof };
    }
    pub fn memoryLoader(self: *Capture) Memory.Loader {
        return .{ .context = self, .take_opcode = opcodeProof, .take_external = externalProof };
    }
};

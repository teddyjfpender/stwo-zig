//! One original STARK from the streaming driver's real first rounds. This
//! omits separate-original publication, never their equations or global buses.
//! Returned material remains a candidate until independent union verification.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Multi = @import("block_v7_multi_union_proof_v1.zig").ForMode(true);
const Statement = @import("block_v7_multi_union_statement_v1.zig").ForMode(true);
const Driver = @import("block_v7_streaming_execution_mode_v1.zig").ForMode(true);
const N = @import("block_v7_native_checkpoint_v1.zig");
const C = @import("block_v7_caller_active_checkpoint_v1.zig");
pub const Options = struct {
    limits: Multi.Limits,
    proving: Multi.ProveOptions = .{},
};
pub const Artifact = struct {
    allocator: std.mem.Allocator,
    statement: *Statement.Owned,
    proof: Multi.Proof,
    proof_live: bool = true,
    stats: Multi.ProducerStats,
    pub fn releaseProof(self: *Artifact) void {
        if (self.proof_live) {
            self.proof.deinit(self.allocator);
            self.proof_live = false;
        }
    }
    pub fn deinit(self: *Artifact) void {
        const a = self.allocator;
        self.releaseProof();
        self.statement.deinit();
        a.destroy(self);
    }
    /// Invoke only after the streaming driver has returned: all original
    /// producer owners and checkpoint files are then gone.
    pub fn verify(self: *const Artifact, limits: Multi.Limits) !@import("block_v7_execution_receiver_v1.zig").Verified {
        if (!self.proof_live) return error.ReleasedUnionProof;
        return Multi.verify(self.allocator, self.statement.trusted, self.statement.input, &self.proof, limits);
    }
};
pub fn produce(f: Driver.StagedWindowFixture, options: Options) !*Artifact {
    const a = f.allocator;
    const count = if (f.resident_natives) |stages| stages.len else f.natives.len;
    if (count == 0 or f.natives.len != f.native_names.len or f.callers.len != f.caller_names.len) return error.InvalidWindowUnionStages;
    if (f.resident_natives != null and (f.natives.len != 0 or f.callers.len != 0)) return error.UnsupportedResidentNativeCaller;
    const natives = try a.alloc(N.Loaded, if (f.resident_natives != null) 0 else count);
    defer a.free(natives);
    var native_ready: usize = 0;
    defer for (natives[0..native_ready]) |*loaded| loaded.deinit(a);
    const native_pins = try a.alloc(@import("block_v7_native_source_v1.zig").Pin, count);
    defer a.free(native_pins);
    const native_stages = try a.alloc(Multi.NativeStage, count);
    defer a.free(native_stages);
    if (f.resident_natives) |resident| {
        for (resident, native_pins, native_stages) |prepared, *pin, *stage| {
            pin.* = prepared.pin();
            // Match the durable path: the original owner supplies the exact
            // public-slice identity expected by interaction preparation. Its
            // semantic shape/template and epoch entry are still re-admitted.
            pin.shape = &prepared.owner.statement;
            stage.* = .{ .allocator = prepared.allocator, .first = &prepared.first, .owner = prepared.owner, .inputs = prepared.access.source.inputs };
        }
    } else for (f.natives, f.native_names, natives, native_pins, native_stages) |*record, name, *loaded, *pin, *stage| {
        loaded.* = try N.load(a, f.directory, name, record, f.native_limits);
        native_ready += 1;
        pin.* = record.pin();
        pin.shape = &loaded.native.owner.statement;
        stage.* = .{ .allocator = a, .first = &loaded.first, .owner = loaded.native.owner, .inputs = if (loaded.access) |*access| access.source.inputs else &.{} };
    }
    const callers = try a.alloc(C.Loaded, f.callers.len);
    defer a.free(callers);
    var caller_ready: usize = 0;
    defer for (callers[0..caller_ready]) |*loaded| loaded.deinit();
    const caller_pins = try a.alloc(@import("block_v7_caller_active_source_v1.zig").Pin, f.callers.len);
    defer a.free(caller_pins);
    const CallerStage = @import("block_v7_caller_active_proof_v1.zig").ForBackend(Cpu).Stage;
    const caller_stages = try a.alloc(*CallerStage, f.callers.len);
    defer a.free(caller_stages);
    for (f.callers, f.caller_names, callers, caller_pins, caller_stages) |*record, name, *loaded, *pin, *stage| {
        loaded.* = try C.load(a, f.directory, name, record, f.caller_limits);
        caller_ready += 1;
        pin.* = record.pin();
        stage.* = loaded.stage;
    }
    const geometry = try a.alloc(@import("block_v5_ram_lanes_protocol_v1.zig").Claim, f.memory.witness.ram.len);
    defer a.free(geometry);
    for (geometry, f.memory.witness.ram) |*claim, ram| claim.* = ram.geometry;
    const input = Multi.Input{ .epoch = f.epoch, .entries = f.entries, .natives = native_pins, .callers = caller_pins, .program_plan = f.program_plan, .program_roots = f.program.roots, .lookup_plan = f.lookup_plan, .lookup_layout = f.lookup.layout, .lookup_roots = f.lookup.roots, .memory_roots = f.memory.roots, .memory_geometry = geometry, .interval_log = f.memory.witness.interval.log };
    const statement = try Statement.Owned.init(a, f.trusted, input);
    errdefer statement.deinit();
    const out = try a.create(Artifact);
    errdefer a.destroy(out);
    var stats: Multi.ProducerStats = .{};
    var selected = options.proving;
    selected.stats = &stats;
    const proof = try Multi.proveWithOptions(a, f.trusted, input, .{ .natives = native_stages, .callers = caller_stages, .program = f.program, .program_allocator = a, .lookup = f.lookup, .memory = f.memory }, f.pool, options.limits, selected);
    out.* = .{ .allocator = a, .statement = statement, .proof = proof, .stats = stats };
    return out;
}

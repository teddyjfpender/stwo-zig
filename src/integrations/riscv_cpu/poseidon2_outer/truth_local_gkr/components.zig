//! Three independently sized original truth components under one physical PCS.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("../../word16_global_execution/services/roster.zig");
const Manifest = @import("../../word16_global_execution/services/gkr_local/manifest.zig");
const C = @import("component.zig");
const Shapes = @import("authority.zig");
const N = @import("native.zig");
const GW = @import("../../word16_global_execution/services/gkr_local/truth_global_witness.zig");
const GM = @import("../../word16_global_execution/services/gkr_local/truth_global_metadata.zig");
const BindingWitness = @import("witness.zig").Witness;
const Commit = @import("../../word16_execution/main_ownership.zig").Commit;
const O = core.fields.om31.OM31;
pub const Components = struct {
    allocator: std.mem.Allocator,
    data: []C.Data,
    items: [3]C.Component,
    pub fn init(a: std.mem.Allocator, truth: R.Truth, pending: N.Terminal, shared: Manifest.Shared, claims: [2]O) !Components {
        const shapes = try Shapes.shapes(truth);
        if (truth == .keccak and !claims[1].isZero()) return error.NonzeroAbsentWideTruthClaim;
        for (claims) |claim| for (claim.toM31Array()) |coordinate| if (coordinate.v >= core.fields.m31.Modulus) return error.NoncanonicalWideTruthClaim;
        const data = try a.alloc(C.Data, 3);
        errdefer a.free(data);
        var done: usize = 0;
        errdefer for (data[0..done]) |*item| item.deinit();
        var out = Components{ .allocator = a, .data = data, .items = undefined };
        var offsets: [3]usize = .{ 0, 0, 0 };
        for (shapes, 0..) |shape, index| {
            data[index] = try C.Data.init(a, shape, pending, index);
            done += 1;
            const crypto = index == 0 or (index == 1 and truth == .secp);
            out.items[index] = .{ .original = .{ .kind = shape.original.kind, .log_size = shape.original.log_size, .calls = if (crypto) truth.count() else 0, .first_id = if (crypto) truth.first() else 1, .program = if (truth == .secp) A.crypto.secp256k1.program.get(truth.secp.setup.kind) else null, .keccak_policy = shape.original.keccak_policy, .byte_policy = shape.original.byte_policy, .local = pending.challenges, .shared = shared, .claim = O.zero(), .global_claim = if (crypto) claims[index] else O.zero(), .split = if (truth == .keccak) 2 else 1 }, .data = &data[index], .offsets = offsets };
            try out.items[index].validate();
            for (out.items[index].widths(), 0..) |width, tree| offsets[tree] += width;
        }
        return out;
    }
    pub fn deinit(self: *Components) void {
        for (self.data) |*d| d.deinit();
        self.allocator.free(self.data);
        self.* = undefined;
    }
    pub fn logs(self: *const Components, a: std.mem.Allocator, tree: usize) ![]u32 {
        if (tree > 2) return error.InvalidLocalGkrTruthShape;
        var count: usize = 0;
        for (self.items) |component| count += component.widths()[tree];
        const out = try a.alloc(u32, count);
        var at: usize = 0;
        for (self.items) |component| {
            const width = component.widths()[tree];
            @memset(out[at..][0..width], component.original.log_size);
            at += width;
        }
        return out;
    }
    pub fn provers(self: *const Components) [3]engine.air.component_prover.ForField(O).ComponentProver {
        return .{ self.items[0].asProverComponent(), self.items[1].asProverComponent(), self.items[2].asProverComponent() };
    }
    pub fn verifiers(self: *const Components) [3]core.air.components.ForField(O).Component {
        return .{ self.items[0].asVerifierComponent(), self.items[1].asVerifierComponent(), self.items[2].asVerifierComponent() };
    }
};
pub const Generated = struct { commit: Commit, claims: [2]O };
pub fn generate(a: std.mem.Allocator, source: *const R.TruthSource, shapes: [3]Shapes.Shape, metadata: anytype, pending: N.Terminal, shared: Manifest.Shared, budget: usize) !Generated {
    var binding = try BindingWitness.init(a, shapes, &pending.challenges, metadata, pending.artifact, pending.eta);
    defer binding.deinit();
    var global_metadata = try GM.Provider.init(a, source, budget);
    defer global_metadata.deinit();
    const challenges = GW.Challenges{ .io = shared.kio, .wire = shared.wire };
    var globals: [2]GW.Witness = undefined;
    var done: usize = 0;
    defer for (globals[0..done]) |*global| global.deinit();
    globals[0] = try GW.generate(a, &global_metadata, shapes[0].instance().role, &challenges, budget);
    done = 1;
    if (source.* == .secp) {
        globals[1] = try GW.generate(a, &global_metadata, shapes[1].instance().role, &challenges, budget);
        done = 2;
    }
    const claims = [_]O{ globals[0].claims[0], if (done == 2) globals[1].claims[0] else O.zero() };
    const commit = try take(a, shapes, &binding, globals[0..done]);
    return .{ .commit = commit, .claims = claims };
}
/// Every fallible allocation precedes ownership transfer; no witness rebuild.
pub fn take(a: std.mem.Allocator, shapes: [3]Shapes.Shape, binding: *BindingWitness, globals: []GW.Witness) !Commit {
    if (globals.len != 1 and globals.len != 2) return error.LocalGkrProjectionShape;
    var width: usize = 48;
    for (globals) |global| width += global.width();
    const columns = try a.alloc(engine.pcs.ColumnEvaluation, width);
    errdefer a.free(columns);
    const backings = try a.alloc([]core.fields.m31.M31, 3 + globals.len);
    errdefer a.free(backings);
    var at: usize = 0;
    var owner: usize = 0;
    for (shapes, 0..) |shape, index| {
        const rows = try shape.instance().rows();
        if (binding.columns[index].len != 16 * rows) return error.LocalGkrProjectionShape;
        for (0..16) |column| {
            columns[at] = .{ .log_size = shape.original.log_size, .values = binding.columns[index][column * rows ..][0..rows] };
            at += 1;
        }
        backings[owner] = binding.columns[index];
        owner += 1;
        if (index < globals.len) {
            const global = &globals[index];
            if (global.log_size != shape.original.log_size) return error.LocalGkrProjectionShape;
            for (0..global.width()) |column| {
                columns[at] = .{ .log_size = global.log_size, .values = global.data[column * rows ..][0..rows] };
                at += 1;
            }
            backings[owner] = global.data;
            owner += 1;
        }
    }
    for (&binding.columns) |*data| data.* = &.{};
    for (globals) |*global| global.data = &.{};
    return .{ .columns = columns, .backings = backings };
}

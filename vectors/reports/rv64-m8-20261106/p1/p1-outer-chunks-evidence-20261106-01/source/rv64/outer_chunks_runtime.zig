//! Cold source binding for bounded full-domain outer composition groups.
const std = @import("std");
const C = @import("composition_codegen.zig");
const P = @import("composition_sparse.zig");
const Abi = @import("abi.zig");
pub const GroupCall = *const fn (*anyopaque, u32, u32, *const Abi.CompositionRole, *u32) callconv(.c) c_int;
pub const Runtime = struct {
    allocator: std.mem.Allocator,
    role: u32,
    plan: P.Plan,
    cache: P.Cache,
    library: std.DynLib,
    group: GroupCall,
    pub fn init(a: std.mem.Allocator, role: u32, program: *const C.Program) !?Runtime {
        const flag = std.posix.getenv("STWO_RV64_RC_OUTER_CHUNKS") orelse return null;
        if (!std.mem.eql(u8, flag, "1") or (role != 4 and role != 5)) return null;
        const path = std.posix.getenv("STWO_RV64_RC_OUTER_CHUNKS_LIBRARY") orelse return error.MissingOuterChunksLibrary;
        var plan = try P.init(a, program, 32);
        errdefer plan.deinit(a);
        try plan.validate(a, program);
        if (plan.terms.len != program.roots.len) return error.OuterChunkRootSplit;
        for (plan.terms, program.roots, 0..) |term, node, i| {
            if (term.negative or term.root != i or term.node != node) return error.OuterChunkRootCoverMismatch;
        }
        var cache = try P.cache(a, &plan, 32);
        errdefer cache.deinit(a);
        try cache.validate(a, &plan);
        var library = try std.DynLib.open(path);
        errdefer library.close();
        const Identity = *const fn (u32, *[96]u8) callconv(.c) c_int;
        const identity = library.lookup(Identity, "stwo_outer_chunks_identity") orelse return error.MissingOuterChunksSymbol;
        var got: [96]u8 = undefined;
        if (identity(role, &got) != 0 or !std.mem.eql(u8, got[0..32], &program.identity) or !std.mem.eql(u8, got[32..64], &plan.identity) or !std.mem.eql(u8, got[64..96], &(try C.identity(program)))) return error.OuterChunksIdentityMismatch;
        return .{ .allocator = a, .role = role, .plan = plan, .cache = cache, .library = library, .group = library.lookup(GroupCall, "stwo_outer_chunks_group_on") orelse return error.MissingOuterChunksSymbol };
    }
    pub fn bytes(self: *const Runtime) usize {
        var n = self.plan.columns.len * @sizeOf(P.Column) + self.plan.input_columns.len * 4 + self.plan.terms.len * @sizeOf(P.Term) + self.plan.groups.len * @sizeOf(P.Group) + self.cache.steps.len * @sizeOf(P.Step);
        for (self.plan.groups) |g| n += g.columns.len * 4;
        for (self.cache.steps) |s| n += s.loads.len * @sizeOf(P.Load) + s.column_slots.len * 4;
        return n;
    }
    pub fn deinit(self: *Runtime) void {
        self.library.close();
        self.cache.deinit(self.allocator);
        self.plan.deinit(self.allocator);
    }
};

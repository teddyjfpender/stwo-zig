pub fn ForMode(comptime window: bool) type {
    return struct {
        //! Own the actual original component instances for the finite joint roster.
        const std = @import("std");
        const core = @import("stwo_core");
        const Engine = @import("stwo_prover_engine");
        const R = @import("block_v7_memory_relations_v1.zig");
        const Ram = if (window) @import("block_v7_window_ram_component_v1.zig") else @import("block_v7_ram_component_v1.zig");
        const Provider = @import("block_v7_provider_component_v1.zig");
        const Layout = @import("block_v7_memory_joint_layout_mode_v1.zig").ForMode(window);
        const Mapped = @import("block_v7_memory_joint_component_v1.zig");
        const Halt = @import("block_v7_halt_algebra_v1.zig");
        const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
        pub const RamClaim = if (window) struct { geometry: Geometry.Claim, sums: [31]R.Q } else @import("block_v7_memory_claim_closure_v1.zig").RamClaim;
        pub const Claims = if (window) struct { ram: []const RamClaim, interval: [2]R.Q, range16: [2]R.Q, terminal: void = {} } else @import("block_v7_memory_claim_closure_v1.zig").Claims;
        pub const Owner = struct {
            const RC = Mapped.ForPlacement(Ram.Spec, Layout.Part);
            const IC = Mapped.ForPlacement(Provider.For(.interval), Layout.Part);
            const GC = Mapped.ForPlacement(Provider.For(.range16), Layout.Part);
            const TC = Mapped.ForPlacement(Provider.For(.terminal), Layout.Part);
            allocator: std.mem.Allocator,
            ram: []RC,
            interval: IC,
            range16: GC,
            terminal: if (window) void else TC,
            provers: []Engine.air.component_prover.ComponentProver,
            verifiers: []core.air.components.Component,
            pub fn initWithDelta(a: std.mem.Allocator, layout: *const Layout.Layout, claims: Claims, challenges: R.Challenges(R.Q), delta: if (window) R.Relation(R.Q, 5) else void, halt: Halt.Constants(R.Q)) !*Owner {
                if (layout.parts.len != claims.ram.len + (if (window) @as(usize, 2) else 3)) return error.InvalidV7JointClaims;
                const self = try a.create(Owner);
                errdefer a.destroy(self);
                const ram = try a.alloc(RC, claims.ram.len);
                errdefer a.free(ram);
                for (ram, claims.ram, layout.parts[0..ram.len], 0..) |*component, claim, part, i| {
                    if (part.family != .ram or part.index != i or part.log != claim.geometry.row_log) return error.InvalidV7JointPlacement;
                    const spec: Ram.Spec = if (window) .{ .claim = claim.geometry, .sums = claim.sums, .challenges = challenges, .delta = delta, .halt = halt } else .{ .claim = claim.geometry, .sums = claim.sums, .challenges = challenges, .halt = halt };
                    component.* = try RC.init(spec, part);
                }
                const provers = try a.alloc(Engine.air.component_prover.ComponentProver, layout.parts.len);
                errdefer a.free(provers);
                const verifiers = try a.alloc(core.air.components.Component, layout.parts.len);
                errdefer a.free(verifiers);
                self.* = .{ .allocator = a, .ram = ram, .interval = try IC.init(.{ .challenges = challenges, .sums = claims.interval }, layout.parts[ram.len]), .range16 = try GC.init(.{ .challenges = challenges, .sums = claims.range16 }, layout.parts[ram.len + 1]), .terminal = if (window) {} else try TC.init(.{ .challenges = challenges, .sums = claims.terminal }, layout.parts[ram.len + 2]), .provers = provers, .verifiers = verifiers };
                for (ram, provers[0..ram.len], verifiers[0..ram.len]) |*component, *p, *v| {
                    p.* = component.asProverComponent();
                    v.* = component.asVerifierComponent();
                }
                inline for ((if (window) .{ "interval", "range16" } else .{ "interval", "range16", "terminal" }), 0..) |name, i| {
                    if (layout.parts[ram.len + i].family != @field(Layout.Family, name)) return error.InvalidV7JointPlacement;
                    const component = &@field(self, name);
                    provers[ram.len + i] = component.asProverComponent();
                    verifiers[ram.len + i] = component.asVerifierComponent();
                }
                return self;
            }
            pub const init = if (window) initWithDelta else initLegacy;
            fn initLegacy(a: std.mem.Allocator, layout: *const Layout.Layout, claims: Claims, challenges: R.Challenges(R.Q), halt: Halt.Constants(R.Q)) !*Owner {
                return initWithDelta(a, layout, claims, challenges, {}, halt);
            }
            /// Producer-only evaluation storage. Component addresses and all verifier
            /// methods remain unchanged; no key or transcript accepts this as authority.
            pub fn configureRamQuotient(self: *Owner, policy: @import("block_v7_ram_quotient_policy_v1.zig").Policy, request_cap: usize) !void {
                try policy.validate();
                for (self.ram) |*component| component.inner.tile_options = try policy.select(component.inner.log_size, request_cap);
            }
            pub fn deinit(self: *Owner) void {
                const a = self.allocator;
                a.free(self.verifiers);
                a.free(self.provers);
                a.free(self.ram);
                a.destroy(self);
            }
        };
    };
}

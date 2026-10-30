//! Independent six-tree v7 caller profile. Owns only metadata and proposed
//! public claims; neither captures nor candidate keys select its equations.
//! Shared implementation: default and finite active caller families.
pub fn For(comptime Policy: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const A = Policy.Admission;
        const Source = Policy.Source;
        const E = @import("../prover/block_v7_execution_epoch_v1.zig");
        const Family = @import("../prover/blake3_ethereum_sha_profile.zig");
        const Fused = @import("../prover/block_v5_caller_fused_proof_v1.zig");
        const Shape = @import("block_v6_original_fixed_shape_v1.zig");
        pub const Input = struct { pin: Source.Pin, epoch: E.Epoch, entries: []const E.Entry, arithmetic: Family.ExtensionClaim, claims: Fused.ClaimFrames };
        pub const Owned = struct {
            pub const commitment_trees = 6;
            allocator: std.mem.Allocator,
            admitted: A.Prepared,
            arithmetic: Family.ExtensionClaim,
            claims: Fused.ClaimFrames,
            shape: Shape.Owned,
            config: core.pcs.PcsConfig,
            columns: [6][]const u32,
            widths: []u32,
            mask_log: u32,
            max_log: u32,
            lifting_log: u32,
            composition_log: u32,
            split: u32,
            seal: [32]u8,
            pub fn derive(a: std.mem.Allocator, proposal: Input, limits: A.Limits) !*Owned {
                const self = try a.create(Owned);
                errdefer a.destroy(self);
                var admitted = try A.Prepared.init(a, proposal.pin, proposal.epoch, proposal.entries, limits);
                errdefer admitted.deinit();
                const entry = try admitted.pin().require(a, admitted.epoch, admitted.entries);
                const drawn = try Source.draw(a, admitted.epoch, entry);
                _ = try Source.channel(&drawn, admitted.pin(), entry, &admitted.relations.schedule, &proposal.arithmetic, &proposal.claims);
                var claims = try Fused.ClaimFrames.clone(a, &proposal.claims);
                errdefer claims.deinit(a);
                var shape = try Policy.Shape.derive(a, &admitted);
                errdefer shape.deinit();
                self.* = .{ .allocator = a, .admitted = admitted, .arithmetic = proposal.arithmetic, .claims = claims, .shape = shape, .config = proposal.pin.config, .columns = shape.columns[0..6].*, .widths = shape.widths, .mask_log = shape.mask_log, .max_log = shape.mask_log, .lifting_log = shape.lifting_log, .composition_log = shape.composition_log, .split = shape.split, .seal = admitted.template_id };
                return self;
            }
            pub fn input(self: *const Owned) Input {
                return .{ .pin = self.admitted.pin(), .epoch = self.admitted.epoch, .entries = self.admitted.entries, .arithmetic = self.arithmetic, .claims = self.claims };
            }
            pub fn validate(self: *const Owned) !void {
                try self.admitted.validate();
                var shape = try Policy.Shape.derive(self.allocator, &self.admitted);
                defer shape.deinit();
                if (!std.meta.eql(self.seal, self.admitted.template_id) or !std.meta.eql(self.config, self.admitted.arithmetic.config) or self.mask_log != shape.mask_log or self.max_log != shape.mask_log or self.lifting_log != shape.lifting_log or self.composition_log != shape.composition_log or self.split != shape.split or !std.mem.eql(u32, self.widths, shape.widths) or !std.meta.eql(self.deepProfile().identityDigest(), shape.deepProfile().identityDigest()) or !std.meta.eql(self.friProfile().identityDigest(), shape.friProfile().identityDigest())) return error.UntrustedV7CallerFixedProfile;
                for (self.columns, shape.columns) |got, expected| if (!std.mem.eql(u32, got, expected)) return error.UntrustedV7CallerFixedProfile;
                const entry = try self.admitted.pin().require(self.allocator, self.admitted.epoch, self.admitted.entries);
                const drawn = try Source.draw(self.allocator, self.admitted.epoch, entry);
                _ = try Source.channel(&drawn, self.admitted.pin(), entry, &self.admitted.relations.schedule, &self.arithmetic, &self.claims);
            }
            pub fn deepProfile(self: *const Owned) @import("air/pcs_deep_circuit.zig").Profile {
                return self.shape.deepProfile();
            }
            pub fn friProfile(self: *const Owned) @import("air/fri_verifier_circuit.zig").Profile {
                return self.shape.friProfile();
            }
            pub fn deinit(self: *Owned) void {
                const a = self.allocator;
                self.shape.deinit();
                self.claims.deinit(a);
                self.admitted.deinit();
                a.destroy(self);
            }
        };
    };
}

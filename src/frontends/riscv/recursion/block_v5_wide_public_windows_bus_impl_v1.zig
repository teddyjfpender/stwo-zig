//! Explicit B5WM public supply, reusing the admitted coordinate vocabulary and
//! schedule rules. Neither original proofs nor public data are relabeled as H.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Original = @import("block_v5_global_public_export_bus_v1.zig");
pub fn ForModules(comptime Public: type) type {
    return struct {
        pub const VERSION = Public.VERSION;
        pub const Source = Original.Source;
        pub const Wire = Original.Wire;
        pub const scheduleDigest = Original.scheduleDigest;
        pub const Values = struct {
            public: *const Public.Owner,
            pub fn validate(self: Values) !void {
                try self.public.validate();
            }
            pub fn requireConfig(self: Values, config: core.pcs.PcsConfig) !void {
                for (self.public.policy.instances) |child| {
                    if (!@import("std").meta.eql(config, child.key.config) or !@import("std").meta.eql(config, child.key.context.child_config)) return error.WidePublicWindowsSecurityMismatch;
                }
            }
            pub fn at(self: Values, wire: Wire) ![4]M {
                return switch (wire.source) {
                    .original => |s| block: {
                        if (s.child >= self.public.sources.len) return error.InvalidWidePublicCell;
                        if (s.kind == .child_supply_packed and s.part == 0) {
                            if (s.coordinate >= self.public.sources[s.child].terms.len) return error.InvalidWidePublicCell;
                            break :block self.public.sources[s.child].terms[s.coordinate].coordinates;
                        }
                        const value = try self.public.sources[s.child].cell(s.coordinate);
                        break :block if (s.kind == .pairing_coordinate) .{ value[s.part], M.zero(), M.zero(), M.zero() } else if (s.kind == .frame_cell and s.part == 0) value else error.InvalidWidePublicCell;
                    },
                    .public_word => |s| self.public.cell(try self.public.publicWord(s.window, s.word)),
                    .public_byte => |s| .{ (try self.public.cell(try self.public.publicWord(s.window, s.word)))[s.part], M.zero(), M.zero(), M.zero() },
                    .public_digest => |s| block: {
                        const local = try self.public.localIndex(s.window);
                        break :block .{ (try self.public.cell(self.public.layouts[local].digest_first + s.word))[s.part], M.zero(), M.zero(), M.zero() };
                    },
                    .outer_register_byte => |s| .{ (try self.public.cell(self.public.outer_first + @as(u32, s.register) + @as(u32, if (s.final) 32 else 0)))[s.part], M.zero(), M.zero(), M.zero() },
                    .term_byte => |s| block: {
                        const terms = try self.public.exportTerms(s.window);
                        break :block .{ (try self.public.cell(terms[@intFromEnum(s.kind)].first_cell + s.limb))[s.part], M.zero(), M.zero(), M.zero() };
                    },
                };
            }
            pub fn mix(self: Values, channel: anytype) !void {
                try self.public.mix(channel);
            }
        };
        pub fn supply(wires: []const Wire, values: Values, relations: @import("air/universal_challenges.zig").UniversalRelations) !Q {
            _ = try scheduleDigest(wires);
            try values.validate();
            const relation = try relations.getExact(.recursion_wire);
            var total = Q.zero();
            for (wires) |wire| {
                const denominator = try relation.combineBase(&(.{ M.fromCanonical(wire.circuit), M.fromCanonical(wire.wire) } ++ try values.at(wire)));
                if (denominator.isZero()) return error.RecursivePublicDenominatorZero;
                const term = Q.fromBase(M.fromCanonical(wire.uses)).mul(try denominator.inv());
                total = if (wire.negative) total.sub(term) else total.add(term);
            }
            return total;
        }
    };
}

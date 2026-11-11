//! Two concrete existing backend authorities. No frontend or AIR is retargeted.
const std = @import("std");
const A = @import("../../authority.zig");
const R6 = @import("../../native_omul/authority.zig");
const R7 = @import("../../native_dot/outer_authority.zig");
const Engine = @import("stwo_prover_engine");
const Core = @import("stwo_core");
const Legacy = @import("stwo_circuit_cpu_integration").om31.component.Component;
const P2 = @import("../../component.zig").Component;
const Mul = @import("../../native_omul/component.zig").Component;
const Dot = @import("../../native_dot/outer_component.zig").Component;
const Input = @import("../../native_dot/input_component.zig").Component;
pub const Kind = enum { r6, r7 };
pub const Mutation = enum { none, balanced_claims, dot_accumulator, input_value };
pub fn For(comptime kind: Kind) type {
    return struct {
        pub const SourceKey = if (kind == .r6) R6.Key else R7.Key;
        pub const W = if (kind == .r6) @import("../../native_omul/witness.zig") else @import("../../native_dot/outer_witness.zig");
        pub const COUNT = if (kind == .r6) 6 else 8;
        pub const FIXED_COUNT = if (kind == .r6) R6.FIXED_COUNT else R7.FIXED_COUNT;
        pub fn base(key: *const SourceKey) *const A.Authority {
            return if (kind == .r6) &key.base else &key.core.base;
        }
        pub fn baseMut(key: *SourceKey) *A.Authority {
            return if (kind == .r6) &key.base else &key.core.base;
        }
        pub fn core(key: *const SourceKey) *const R6.Key {
            return if (kind == .r6) key else &key.core;
        }
        pub fn coreMut(key: *SourceKey) *R6.Key {
            return if (kind == .r6) key else &key.core;
        }
        pub fn mutateMainForTest(main: *A.Columns, key: *const SourceKey, mutation: Mutation) !void {
            if (!@import("builtin").is_test) return error.TerminalBlakeTestOnly;
            if (mutation == .none or mutation == .balanced_claims) return;
            if (kind != .r7) return error.TerminalBlakeMutationNamespace;
            const column: usize = if (mutation == .dot_accumulator) R7.MAIN_START + @import("../../native_dot/row.zig").ACC else R7.INPUT_MAIN_START;
            const row = if (mutation == .dot_accumulator) R7.physical(1, key.dot_log) else R7.physical(0, key.input_log);
            main.put(column, row, main.values[column].values[row].add(A.M.one()));
        }
        pub const Components = struct {
            ls: [4]Legacy,
            p2: P2,
            mul: Mul,
            dot: if (kind == .r7) Dot else void,
            input: if (kind == .r7) Input else void,
            pub fn init(a: std.mem.Allocator, key: *const SourceKey, elements: W.Elements, claims: W.Claims, logs: []const u32) !@This() {
                var ls: [4]Legacy = undefined;
                for (&ls, A.OLD_SLOTS, A.NEW_SLOTS) |*component, old, new| {
                    component.* = .{ .allocator = a, .captured = &base(key).bound.components[old], .preprocessed_logs = logs, .z = elements.z, .alpha = elements.powers[1], .claim = claims[new] };
                    try component.validate();
                }
                return .{ .ls = ls, .p2 = .{ .key = base(key), .elements = elements, .claim = claims[3] }, .mul = .{ .key = core(key), .elements = elements, .claim = claims[5] }, .dot = if (kind == .r7) .{ .key = key, .elements = elements, .claim = claims[6] } else {}, .input = if (kind == .r7) .{ .key = key, .elements = elements, .claim = claims[7] } else {} };
            }
            pub fn provers(self: *const @This()) [COUNT]Engine.air.component_prover.ForField(A.O).ComponentProver {
                if (kind == .r6) return .{ self.ls[0].asProverComponent(), self.ls[1].asProverComponent(), self.ls[2].asProverComponent(), @import("../../native_omul/p2_domain.zig").adapter(&self.p2), self.ls[3].asProverComponent(), Mul.Adapter.asProverComponent(&self.mul) };
                return .{ self.ls[0].asProverComponent(), self.ls[1].asProverComponent(), self.ls[2].asProverComponent(), @import("../../native_omul/p2_domain.zig").adapter(&self.p2), self.ls[3].asProverComponent(), Mul.Adapter.asProverComponent(&self.mul), Dot.Adapter.asProverComponent(&self.dot), Input.Adapter.asProverComponent(&self.input) };
            }
            pub fn verifiers(self: *const @This()) [COUNT]Core.air.components.ForField(A.O).Component {
                if (kind == .r6) return .{ self.ls[0].asVerifierComponent(), self.ls[1].asVerifierComponent(), self.ls[2].asVerifierComponent(), P2.Adapter.asVerifierComponent(&self.p2), self.ls[3].asVerifierComponent(), Mul.Adapter.asVerifierComponent(&self.mul) };
                return .{ self.ls[0].asVerifierComponent(), self.ls[1].asVerifierComponent(), self.ls[2].asVerifierComponent(), P2.Adapter.asVerifierComponent(&self.p2), self.ls[3].asVerifierComponent(), Mul.Adapter.asVerifierComponent(&self.mul), Dot.Adapter.asVerifierComponent(&self.dot), Input.Adapter.asVerifierComponent(&self.input) };
            }
        };
    };
}

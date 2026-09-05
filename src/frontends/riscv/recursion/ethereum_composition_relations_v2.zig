//! Proof-independent relation compiler for the recursive Ethereum VM program.
//!
//! The legacy VM recorder caches at most 32 powers because every base
//! relation fits that bound. Ethereum adds relations as wide as the 196-field
//! affine-point bus. Keeping this compiler disjoint preserves the V1 graph
//! identity while replaying the exact same `sum(alpha^i * value_i) - z`
//! polynomial for the appended profile.

const base_relations_mod = @import("../air/relation_challenges.zig");
const keccak_relations_mod =
    @import("../air/guest_precompile/keccakf_relations.zig");
const secp_relations_mod =
    @import("../air/guest_precompile/secp256k1_relations.zig");
const circuit = @import("vm_air_composition_circuit.zig");

pub const BASE_RELATION_COUNT: usize = base_relations_mod.RELATION_COUNT;
pub const EXTENSION_RELATION_COUNT: usize = 13;
pub const RELATION_COUNT: usize = BASE_RELATION_COUNT +
    EXTENSION_RELATION_COUNT;
pub const MAX_RELATION_ARITY: usize = secp_relations_mod.point_arity;

const Scalar = circuit.Scalar;

pub const WideGraphRelation = struct {
    z: Scalar,
    alpha: Scalar,
    arity: usize,

    pub fn init(z: Scalar, alpha: Scalar, arity: usize) WideGraphRelation {
        return .{ .z = z, .alpha = alpha, .arity = arity };
    }

    pub fn alphaValue(self: WideGraphRelation) Scalar {
        return self.alpha;
    }

    pub fn combine(self: WideGraphRelation, values: anytype) Scalar {
        if (values.len != self.arity or values.len > MAX_RELATION_ARITY)
            @panic("invalid Ethereum relation arity");
        var result = Scalar.zero();
        var power = Scalar.one();
        inline for (values) |value| {
            result = result.add(power.mul(value));
            power = power.mul(self.alpha);
        }
        return result.sub(self.z);
    }
};

pub const KeccakRelations = struct {
    base: circuit.GraphRelations,
    io: WideGraphRelation,
    chi: WideGraphRelation,
    xor5: WideGraphRelation,
};

pub const SecpRelations = struct {
    base: circuit.GraphRelations,
    product: WideGraphRelation,
    linear: WideGraphRelation,
    point: WideGraphRelation,
    split: WideGraphRelation,
    table: WideGraphRelation,
    program: WideGraphRelation,
    table_root: WideGraphRelation,
    ecdsa: WideGraphRelation,
    byte: WideGraphRelation,
    recovery: WideGraphRelation,
};

pub const RelationsV2 = struct {
    base: circuit.GraphRelations,
    keccak: KeccakRelations,
    secp: SecpRelations,

    /// Draw order is the exact Ethereum transcript order: twelve base pairs,
    /// then Keccak io/chi/xor5 and the ten secp256k1 relation pairs.
    pub fn init(
        base_draws: [BASE_RELATION_COUNT][2]Scalar,
        extension_draws: [EXTENSION_RELATION_COUNT][2]Scalar,
    ) RelationsV2 {
        const base = circuit.GraphRelations.init(base_draws);
        return .{
            .base = base,
            .keccak = .{
                .base = base,
                .io = wide(extension_draws[0], keccak_relations_mod.io_arity),
                .chi = wide(extension_draws[1], keccak_relations_mod.chi_arity),
                .xor5 = wide(extension_draws[2], keccak_relations_mod.xor5_arity),
            },
            .secp = .{
                .base = base,
                .product = wide(extension_draws[3], secp_relations_mod.product_arity),
                .linear = wide(extension_draws[4], secp_relations_mod.linear_arity),
                .point = wide(extension_draws[5], secp_relations_mod.point_arity),
                .split = wide(extension_draws[6], secp_relations_mod.split_arity),
                .table = wide(extension_draws[7], secp_relations_mod.table_arity),
                .program = wide(extension_draws[8], secp_relations_mod.program_arity),
                .table_root = wide(extension_draws[9], secp_relations_mod.table_root_arity),
                .ecdsa = wide(extension_draws[10], secp_relations_mod.ecdsa_arity),
                .byte = wide(extension_draws[11], secp_relations_mod.byte_arity),
                .recovery = wide(extension_draws[12], secp_relations_mod.recovery_arity),
            },
        };
    }
};

fn wide(draw: [2]Scalar, arity: usize) WideGraphRelation {
    return .init(draw[0], draw[1], arity);
}

comptime {
    if (BASE_RELATION_COUNT != 12 or EXTENSION_RELATION_COUNT != 13 or
        RELATION_COUNT != 25 or MAX_RELATION_ARITY != 196)
    {
        @compileError("Ethereum recursive relation inventory drifted");
    }
}

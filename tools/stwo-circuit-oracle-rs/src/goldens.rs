//! Upstream in-tree goldens that the oracle re-derives and asserts. Each item names the file of
//! `proving@5a7c5ed` it is copied from.

use circuit_verifier::circuit_components::PerComponent;

/// `WORDS` of `crates/stwo/src/core/vcs_lifted/hasher_test.rs`.
pub const HASHER_TEST: &str = "crates/stwo/src/core/vcs_lifted/hasher_test.rs";
pub const HASHER_TEST_WORDS: [u32; 9] = [0, 1, 2, 3, 0x1234_5678, u32::MAX, 7, 8, 9];
pub const HASHER_TEST_HASH_U32S: &str =
    "efee1538e0216d3a09ce742ce768c44a7db004d801c40f66040994353f55fe85";
pub const HASHER_TEST_FOLLOWED_BY_DIGEST: &str =
    "18a60268d189dccf5065ddd361d280474fbc2b08d75a7e4e1c20e57a67f2f7fa";

/// `compute_circuit_hash_matches_golden` of `crates/circuit_verifier/src/circuit_hash_test.rs`:
/// log blowup 3, preprocessed root words `0..8`.
pub const CIRCUIT_HASH_TEST: &str = "crates/circuit_verifier/src/circuit_hash_test.rs";
pub const CIRCUIT_HASH_TEST_LOG_BLOWUP: u32 = 3;
pub const CIRCUIT_HASH_TEST_WORDS: [u32; 8] = [
    0xa881_0641,
    0x5239_1285,
    0x90b3_7fd2,
    0x905b_887a,
    0x7db7_dc81,
    0xa7c3_a731,
    0xd0d4_6b34,
    0x8fa6_a471,
];

/// Gate component log sizes `[eq, qm31_ops, triple_xor, m_31_to_u_32, blake_g_gate]`, completed
/// with the fixed table sizes (xor 8/12/4/7/9: 16/20/8/14/18, range_check_16: 16).
pub fn component_sizes(gates: [u32; 5]) -> PerComponent<u32> {
    let [eq, qm31_ops, triple_xor, m_31_to_u_32, blake_g_gate] = gates;
    PerComponent {
        eq,
        qm31_ops,
        triple_xor,
        m_31_to_u_32,
        blake_g_gate,
        verify_bitwise_xor_8: 16,
        verify_bitwise_xor_12: 20,
        verify_bitwise_xor_4: 8,
        verify_bitwise_xor_7: 14,
        verify_bitwise_xor_9: 18,
        range_check_16: 16,
    }
}

pub const CIRCUIT_HASH_TEST_GATES: [u32; 5] = [17, 21, 17, 18, 20];

/// `poseidon252_root` of `crates/circuit_prover/src/circuit_hash.rs`: log blowup 1.
pub const POSEIDON_TEST: &str = "crates/circuit_prover/src/circuit_hash.rs";
pub const POSEIDON_TEST_GATES: [u32; 5] = [20, 23, 20, 21, 23];
pub const POSEIDON_TEST_ROOT: &str =
    "0x0172b6763ef45133e1d1d1a507f14fe24702c221cdbbc7ca7c0e5d654b008d27";
pub const POSEIDON_TEST_HASH: &str =
    "1e153175973f9466ee2f662e1f782c10a3d0b6bfa92d64c2b78c53fd35195ca";

/// A leaf verifier or multiverifier entry of a checked-in circuit registry. The gate sizes are
/// the `component_log_sizes` of its `default` circuit proof config; the log blowup is 1.
pub struct RegistryEntry {
    pub registry: &'static str,
    pub name: &'static str,
    pub gates: [u32; 5],
    pub preprocessed_root: [u32; 8],
    pub circuit_hash: [u32; 8],
}

const LEAF_PROVER_REGISTRY: &str =
    "crates/leaf_prover/tests/data/circuit_registry_canonical_small.json";
const RECURSIVE_TREE_REGISTRY: &str =
    "crates/stwo_run_and_prove_recursive_tree/test_data/circuit_registry.json";

pub const REGISTRY_ENTRIES: [RegistryEntry; 4] = [
    RegistryEntry {
        registry: LEAF_PROVER_REGISTRY,
        name: "leaf_prover_leaf_verifier",
        gates: [20, 23, 19, 20, 23],
        preprocessed_root: [
            0xadaf_43d6,
            0xbee3_9095,
            0x90ce_b891,
            0x73c8_a22d,
            0x4c06_753c,
            0xd546_9618,
            0x6cb5_a946,
            0x5425_c597,
        ],
        circuit_hash: [
            0xf2c6_d668,
            0xd27d_dadb,
            0x668f_252d,
            0xdf6a_6ed3,
            0x85dd_1ceb,
            0x8595_43da,
            0x468f_3d35,
            0xb6f8_071f,
        ],
    },
    RegistryEntry {
        registry: LEAF_PROVER_REGISTRY,
        name: "leaf_prover_multiverifier",
        gates: [20, 23, 19, 20, 23],
        preprocessed_root: [
            0xd139_53cf,
            0x661c_cf76,
            0x7be6_fe0a,
            0x0a3d_b569,
            0x4eba_4e91,
            0xc2a2_1617,
            0xba2e_43b6,
            0x9da8_7a91,
        ],
        circuit_hash: [
            0x4d01_3787,
            0x4d13_cf6e,
            0xba17_c793,
            0xb799_3eb3,
            0x42ee_429e,
            0xe38d_d7e5,
            0xf542_9b6d,
            0x520e_ca69,
        ],
    },
    RegistryEntry {
        registry: RECURSIVE_TREE_REGISTRY,
        name: "recursive_tree_leaf_verifier",
        gates: [20, 23, 20, 21, 23],
        preprocessed_root: [
            0x591e_f324,
            0x3a8c_f9f1,
            0x0e48_640a,
            0x9932_2136,
            0xa1ca_ae97,
            0xa5ad_41d3,
            0x3dd9_b19b,
            0x8745_f2a1,
        ],
        circuit_hash: [
            0xd2d8_5a42,
            0x7969_7b22,
            0x3a41_a061,
            0x011c_b393,
            0x7a04_0ec9,
            0x4508_f4ca,
            0x4223_9409,
            0x60f3_baea,
        ],
    },
    RegistryEntry {
        registry: RECURSIVE_TREE_REGISTRY,
        name: "recursive_tree_multiverifier",
        gates: [20, 23, 20, 21, 23],
        preprocessed_root: [
            0xe479_ab39,
            0xc55b_e4ac,
            0x9f98_c322,
            0xd73b_0254,
            0xb7ae_54fb,
            0xe78a_54c5,
            0xb048_6f13,
            0x66e9_1045,
        ],
        circuit_hash: [
            0xa598_9715,
            0x2377_c07a,
            0xc6d1_e844,
            0x54f0_a04d,
            0x8be6_5a7d,
            0xfd73_c261,
            0x9078_e728,
            0x973f_680f,
        ],
    },
];

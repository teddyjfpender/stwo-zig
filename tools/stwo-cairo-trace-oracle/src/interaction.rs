use anyhow::{Context, Result, ensure};
use cairo_air::claims::{CairoClaim, CairoInteractionClaim};
use cairo_air::relations::CommonLookupElements;
use serde::Serialize;
use sha2::{Digest, Sha256};
use stwo::core::channel::{Blake2sChannel, Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::prover::backend::Column;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::circle::CircleEvaluation;

use crate::checkpoint::Authority;

const CHALLENGE_DOMAIN: &[u8] = b"STWO_CAIRO_INTERACTION_DIAGNOSTIC_CHALLENGE_V1\0";
const LOOKUP_ELEMENTS_DOMAIN: &[u8] = b"STWO_CAIRO_INTERACTION_LOOKUP_ELEMENTS_V1\0";
const COLUMN_DOMAIN: &[u8] = b"STWO_CAIRO_INTERACTION_COLUMN_V1\0";
const ACCUMULATOR_DOMAIN: &[u8] = b"STWO_CAIRO_INTERACTION_ACCUMULATOR_V1\0";

#[derive(Serialize)]
pub struct ChallengeProvenance {
    pub purpose: &'static str,
    pub is_proof_transcript: bool,
    pub warning: &'static str,
    pub derivation: &'static str,
    pub domain_hex: String,
    pub seed_sha256: String,
    pub z_m31: [u32; 4],
    pub alpha_m31: [u32; 4],
    pub alpha_powers_m31: Vec<[u32; 4]>,
    pub lookup_elements_sha256: String,
}

#[derive(Serialize)]
pub struct ColumnCheckpoint {
    pub ordinal: u32,
    pub row_count: u64,
    pub sha256: String,
}

#[derive(Serialize)]
pub struct ComponentCheckpoint {
    pub ordinal: u32,
    pub label: String,
    pub claimed_sum_m31: [u32; 4],
    pub columns: Vec<ColumnCheckpoint>,
    pub accumulator_sha256: String,
}

#[derive(Serialize)]
pub struct Checkpoint {
    pub schema: &'static str,
    pub input_sha256: String,
    pub authority: Authority,
    pub challenge: ChallengeProvenance,
    pub components: Vec<ComponentCheckpoint>,
    pub final_accumulator_sha256: String,
}

struct ComponentLayout {
    label: String,
    log_sizes: Vec<u32>,
}

fn layouts(claim: &CairoClaim) -> Result<Vec<ComponentLayout>> {
    let mut result = Vec::new();
    macro_rules! add {
        ($field:ident) => {
            if let Some(component) = claim.$field.as_ref() {
                result.push(ComponentLayout {
                    label: stringify!($field).to_owned(),
                    log_sizes: component.log_sizes().0[1].clone(),
                });
            }
        };
    }

    add!(add_opcode);
    add!(add_opcode_small);
    add!(add_ap_opcode);
    add!(assert_eq_opcode);
    add!(assert_eq_opcode_imm);
    add!(assert_eq_opcode_double_deref);
    add!(blake_compress_opcode);
    add!(call_opcode_abs);
    add!(call_opcode_rel_imm);
    add!(generic_opcode);
    add!(jnz_opcode_non_taken);
    add!(jnz_opcode_taken);
    add!(jump_opcode_abs);
    add!(jump_opcode_double_deref);
    add!(jump_opcode_rel);
    add!(jump_opcode_rel_imm);
    add!(mul_opcode);
    add!(mul_opcode_small);
    add!(qm_31_add_mul_opcode);
    add!(ret_opcode);
    add!(verify_instruction);
    add!(blake_round);
    add!(blake_g);
    add!(blake_round_sigma);
    add!(triple_xor_32);
    add!(verify_bitwise_xor_12);
    add!(add_mod_builtin);
    add!(bitwise_builtin);
    add!(mul_mod_builtin);
    add!(pedersen_builtin);
    add!(pedersen_builtin_narrow_windows);
    add!(poseidon_builtin);
    add!(range_check96_builtin);
    add!(range_check_builtin);
    add!(ec_op_builtin);
    add!(partial_ec_mul_generic);
    add!(pedersen_aggregator_window_bits_18);
    add!(partial_ec_mul_window_bits_18);
    add!(pedersen_points_table_window_bits_18);
    add!(pedersen_aggregator_window_bits_9);
    add!(partial_ec_mul_window_bits_9);
    add!(pedersen_points_table_window_bits_9);
    add!(poseidon_aggregator);
    add!(poseidon_3_partial_rounds_chain);
    add!(poseidon_full_round_chain);
    add!(cube_252);
    add!(poseidon_round_keys);
    add!(range_check_252_width_27);
    add!(memory_address_to_id);
    if let Some(component) = claim.memory_id_to_big.as_ref() {
        ensure!(
            !component.big_log_sizes.is_empty(),
            "memory_id_to_big has no segments"
        );
        let all_log_sizes = &component.log_sizes().0[1];
        ensure!(
            all_log_sizes.len() % component.big_log_sizes.len() == 0,
            "memory_id_to_big interaction geometry is not segment-aligned"
        );
        let width = all_log_sizes.len() / component.big_log_sizes.len();
        for (index, log_sizes) in all_log_sizes.chunks_exact(width).enumerate() {
            result.push(ComponentLayout {
                label: format!("memory_id_to_big[{index}]"),
                log_sizes: log_sizes.to_vec(),
            });
        }
    }
    add!(memory_id_to_small);
    add!(range_check_6);
    add!(range_check_8);
    add!(range_check_11);
    add!(range_check_12);
    add!(range_check_18);
    add!(range_check_20);
    add!(range_check_4_3);
    add!(range_check_4_4);
    add!(range_check_9_9);
    add!(range_check_7_2_5);
    add!(range_check_3_6_6_3);
    add!(range_check_4_4_4_4);
    add!(range_check_3_3_3_3_3);
    add!(verify_bitwise_xor_4);
    add!(verify_bitwise_xor_7);
    add!(verify_bitwise_xor_8);
    add!(verify_bitwise_xor_9);
    Ok(result)
}

fn limbs(value: SecureField) -> [u32; 4] {
    value.to_m31_array().map(|felt| felt.0)
}

fn lookup_elements_digest(z: [u32; 4], powers: &[[u32; 4]]) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(LOOKUP_ELEMENTS_DOMAIN);
    for limb in z {
        hasher.update(limb.to_le_bytes());
    }
    hasher.update(u32::try_from(powers.len())?.to_le_bytes());
    for (ordinal, power) in powers.iter().enumerate() {
        hasher.update(u32::try_from(ordinal)?.to_le_bytes());
        for limb in power {
            hasher.update(limb.to_le_bytes());
        }
    }
    Ok(hasher.finalize().into())
}

pub fn diagnostic_lookup_elements() -> Result<(CommonLookupElements, ChallengeProvenance)> {
    let seed: [u8; 32] = Sha256::digest(CHALLENGE_DOMAIN).into();
    let seed_words = seed
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .collect::<Vec<_>>();

    let mut channel = Blake2sChannel::default();
    channel.mix_u32s(&seed_words);
    let elements = CommonLookupElements::draw(&mut channel);

    // The relation macro deliberately hides its LookupElements field. Replay
    // the same two channel draws independently so the receipt exposes the
    // challenge without relying on non-upstream accessors.
    let mut audit_channel = Blake2sChannel::default();
    audit_channel.mix_u32s(&seed_words);
    let [z, alpha]: [SecureField; 2] = audit_channel.draw_secure_felts(2).try_into().unwrap();
    let mut current = SecureField::from_u32_unchecked(1, 0, 0, 0);
    let powers = (0..128)
        .map(|_| {
            let value = current;
            current *= alpha;
            limbs(value)
        })
        .collect::<Vec<_>>();
    let z_m31 = limbs(z);
    let alpha_m31 = limbs(alpha);
    let digest = lookup_elements_digest(z_m31, &powers)?;
    let provenance = ChallengeProvenance {
        purpose: "deterministic_cross_backend_interaction_trace_diagnostics",
        is_proof_transcript: false,
        warning: "fixed diagnostic lookup elements; not Fiat-Shamir proof-transcript challenges",
        derivation: "sha256(domain) -> eight little-endian u32 -> Blake2sChannel::default().mix_u32s -> CommonLookupElements::draw; independent channel replay exposes z and alpha",
        domain_hex: hex::encode(CHALLENGE_DOMAIN),
        seed_sha256: hex::encode(seed),
        z_m31,
        alpha_m31,
        alpha_powers_m31: powers,
        lookup_elements_sha256: hex::encode(digest),
    };
    Ok((elements, provenance))
}

fn update_label(hasher: &mut Sha256, label: &str) -> Result<()> {
    hasher.update(u32::try_from(label.len())?.to_le_bytes());
    hasher.update(label.as_bytes());
    Ok(())
}

fn column_digest(
    component_ordinal: u32,
    label: &str,
    column_ordinal: u32,
    values: &[BaseField],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(COLUMN_DOMAIN);
    hasher.update(component_ordinal.to_le_bytes());
    update_label(&mut hasher, label)?;
    hasher.update(column_ordinal.to_le_bytes());
    hasher.update(u64::try_from(values.len())?.to_le_bytes());
    for value in values {
        hasher.update(value.0.to_le_bytes());
    }
    Ok(hasher.finalize().into())
}

fn accumulator_digest(
    previous: [u8; 32],
    lookup_digest: [u8; 32],
    component_ordinal: u32,
    label: &str,
    claimed_sum: [u32; 4],
    columns: &[(u64, [u8; 32])],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(ACCUMULATOR_DOMAIN);
    hasher.update(previous);
    hasher.update(lookup_digest);
    hasher.update(component_ordinal.to_le_bytes());
    update_label(&mut hasher, label)?;
    for limb in claimed_sum {
        hasher.update(limb.to_le_bytes());
    }
    hasher.update(u32::try_from(columns.len())?.to_le_bytes());
    for (ordinal, (row_count, digest)) in columns.iter().enumerate() {
        hasher.update(u32::try_from(ordinal)?.to_le_bytes());
        hasher.update(row_count.to_le_bytes());
        hasher.update(digest);
    }
    Ok(hasher.finalize().into())
}

fn ensure_component_counts(layouts: usize, sums: usize) -> Result<()> {
    ensure!(
        layouts == sums,
        "interaction component layout and claimed sums diverge"
    );
    Ok(())
}

pub fn build(
    input_sha256: [u8; 32],
    claim: &CairoClaim,
    interaction_claim: &CairoInteractionClaim,
    evals: Vec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    challenge: ChallengeProvenance,
) -> Result<Checkpoint> {
    let layouts = layouts(claim)?;
    let claimed_sums = interaction_claim.flatten_interaction_claim();
    ensure_component_counts(layouts.len(), claimed_sums.len())?;
    let expected_log_sizes = claim.log_sizes().0[1].clone();
    let layout_log_sizes = layouts
        .iter()
        .flat_map(|layout| layout.log_sizes.iter().copied())
        .collect::<Vec<_>>();
    ensure!(
        layout_log_sizes == expected_log_sizes,
        "interaction component layout diverges from CairoClaim::log_sizes"
    );
    ensure!(
        evals.len() == expected_log_sizes.len(),
        "interaction trace column count does not match CairoClaim"
    );
    let lookup_digest: [u8; 32] = hex::decode(&challenge.lookup_elements_sha256)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid lookup element digest length"))?;

    let mut evals = evals.into_iter();
    let mut accumulator = [0; 32];
    let mut components = Vec::with_capacity(layouts.len());
    for (component_index, (layout, sum)) in layouts.into_iter().zip(claimed_sums).enumerate() {
        let component_ordinal = u32::try_from(component_index)?;
        let claimed_sum = limbs(sum);
        let mut columns = Vec::with_capacity(layout.log_sizes.len());
        let mut digest_inputs = Vec::with_capacity(layout.log_sizes.len());
        for (column_index, log_size) in layout.log_sizes.into_iter().enumerate() {
            let eval = evals
                .next()
                .context("interaction trace ended within component")?;
            ensure!(
                eval.domain.log_size() == log_size,
                "interaction trace log size mismatch"
            );
            let values = eval.values.to_cpu();
            ensure!(
                values.len() == 1usize << log_size,
                "interaction trace row count mismatch"
            );
            let column_ordinal = u32::try_from(column_index)?;
            let digest = column_digest(component_ordinal, &layout.label, column_ordinal, &values)?;
            let row_count = u64::try_from(values.len())?;
            digest_inputs.push((row_count, digest));
            columns.push(ColumnCheckpoint {
                ordinal: column_ordinal,
                row_count,
                sha256: hex::encode(digest),
            });
        }
        accumulator = accumulator_digest(
            accumulator,
            lookup_digest,
            component_ordinal,
            &layout.label,
            claimed_sum,
            &digest_inputs,
        )?;
        components.push(ComponentCheckpoint {
            ordinal: component_ordinal,
            label: layout.label,
            claimed_sum_m31: claimed_sum,
            columns,
            accumulator_sha256: hex::encode(accumulator),
        });
    }
    ensure!(
        evals.next().is_none(),
        "unassigned interaction trace columns"
    );

    Ok(Checkpoint {
        schema: "stwo-cairo-interaction-trace-checkpoint-v1",
        input_sha256: hex::encode(input_sha256),
        authority: Authority {
            stwo_cairo_revision: "82f21252a68ec006d73e299f5bf1ce6d4db0ee78",
            stwo_revision: "7b211edde786775016ef3eecb837a6240d8fe792",
        },
        challenge,
        components,
        final_accumulator_sha256: hex::encode(accumulator),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_lookup_elements_are_stable_and_explicit() {
        let (_, first) = diagnostic_lookup_elements().unwrap();
        let (_, second) = diagnostic_lookup_elements().unwrap();
        assert!(!first.is_proof_transcript);
        assert_eq!(first.alpha_m31, first.alpha_powers_m31[1]);
        assert_eq!(first.alpha_powers_m31.len(), 128);
        assert_eq!(
            first.seed_sha256,
            "610912ca9008cd5b27a3f101341922c74ff8793f85d61fae238fb73df0fea4c0"
        );
        assert_eq!(first.z_m31, [2059688338, 2092506771, 453015876, 1425491019]);
        assert_eq!(
            first.alpha_m31,
            [2020915545, 1141263798, 2012552380, 612327232]
        );
        assert_eq!(
            first.lookup_elements_sha256,
            "c74885eaf1a19905938559496c6fa73ff21776abc2c5bc578307c1c7f4d7e319"
        );
        assert_eq!(first.seed_sha256, second.seed_sha256);
        assert_eq!(first.z_m31, second.z_m31);
        assert_eq!(first.alpha_powers_m31, second.alpha_powers_m31);
        assert_eq!(first.lookup_elements_sha256, second.lookup_elements_sha256);
    }

    #[test]
    fn accumulator_binds_claim_and_lookup_elements() {
        let values = [BaseField::from(1), BaseField::from(2)];
        let column = column_digest(3, "ret_opcode", 0, &values).unwrap();
        let first = accumulator_digest(
            [0; 32],
            [1; 32],
            3,
            "ret_opcode",
            [4, 3, 2, 1],
            &[(2, column)],
        )
        .unwrap();
        assert_ne!(
            first,
            accumulator_digest(
                [0; 32],
                [2; 32],
                3,
                "ret_opcode",
                [4, 3, 2, 1],
                &[(2, column)]
            )
            .unwrap()
        );
        assert_ne!(
            first,
            accumulator_digest(
                [0; 32],
                [1; 32],
                3,
                "ret_opcode",
                [4, 3, 2, 0],
                &[(2, column)]
            )
            .unwrap()
        );
    }

    #[test]
    fn rejects_component_claim_count_mismatch() {
        assert!(ensure_component_counts(2, 1).is_err());
    }
}

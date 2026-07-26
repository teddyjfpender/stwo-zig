use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, ensure};
use cairo_air::CairoProofForRustVerifier;
use cairo_air::cairo_components::CairoComponents;
use cairo_air::utils::{ProofFormat, deserialize_proof_from_file};
use stwo::core::air::Component;
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval};

mod bundle;
mod encoding;
mod parameters;
mod program;
mod recording;

use program::lower_framework_eval_to_v1_with_logup;

#[derive(Default)]
struct Summary {
    components: usize,
    constraints: usize,
    base_instructions: usize,
    extension_instructions: usize,
    extension_parameters: usize,
}

fn lower_component<E: FrameworkEval>(
    name: &str,
    instance: u32,
    component: &FrameworkComponent<E>,
    probe_component: &FrameworkComponent<E>,
    lookup: &parameters::LookupProbe,
    probe_lookup: &parameters::LookupProbe,
    summary: &mut Summary,
) -> Result<bundle::CapturedComponent> {
    let random_coefficient_offset = summary.constraints;
    let concrete_program = lower_framework_eval_to_v1_with_logup(
        component.evaluator(),
        component.trace_locations().len() as u32,
        0,
        0,
        component.claimed_sum(),
        component.evaluator().log_size(),
    )
    .map_err(|error| anyhow!("{name}: {error:?}"))?;
    let probe = lower_framework_eval_to_v1_with_logup(
        probe_component.evaluator(),
        probe_component.trace_locations().len() as u32,
        0,
        0,
        PROBE_CLAIMED_SUM,
        probe_component.evaluator().log_size(),
    )
    .map_err(|error| anyhow!("{name} probe: {error:?}"))?;
    let (program, parameter_pairs) = concrete_program
        .parameterize_extension_constants(&probe)
        .map_err(|error| anyhow!("{name}: {error:?}"))?;
    let rebound = program
        .bind_extension_parameters(
            &parameter_pairs
                .iter()
                .map(|parameter| parameter.primary)
                .collect::<Vec<_>>(),
        )
        .map_err(|error| anyhow!("{name} rebound: {error:?}"))?;
    ensure!(
        rebound == concrete_program,
        "{name}: parameterized AIR does not reconstruct its concrete recording"
    );
    let sources = parameters::classify(
        name,
        component.evaluator().log_size(),
        component.claimed_sum(),
        PROBE_CLAIMED_SUM,
        lookup,
        probe_lookup,
        &parameter_pairs,
    )?;
    ensure!(
        program.constraint_roots().len() == component.n_constraints(),
        "{name}: recorded {} constraints, official component reports {}",
        program.constraint_roots().len(),
        component.n_constraints()
    );
    summary.components += 1;
    summary.constraints += component.n_constraints();
    summary.base_instructions += program.base_insts().len();
    summary.extension_instructions += program.ext_insts().len();
    summary.extension_parameters += sources.len();
    let semantic_hash = program.header().semantic_hash;
    let base_instruction_count = program.base_insts().len();
    let extension_instruction_count = program.ext_insts().len();
    let extension_parameter_count = sources.len();
    let captured = bundle::CapturedComponent::new(
        name,
        instance,
        component,
        random_coefficient_offset,
        program,
        sources,
    )?;
    println!(
        "{name}: log={} constraints={} base_insts={} ext_insts={} ext_params={} hash={:016x}",
        component.evaluator().log_size(),
        component.n_constraints(),
        base_instruction_count,
        extension_instruction_count,
        extension_parameter_count,
        semantic_hash
    );
    Ok(captured)
}

const PROBE_CLAIMED_SUM: SecureField = SecureField::from_u32_unchecked(257, 263, 269, 271);

fn main() -> Result<()> {
    let mut arguments = std::env::args_os().skip(1);
    let proof_path = arguments
        .next()
        .map(PathBuf::from)
        .context("usage: stwo-cairo-air-compiler <official-binary-proof> [output-bundle]")?;
    let output_path = arguments.next().map(PathBuf::from);
    ensure!(arguments.next().is_none(), "too many arguments");
    let proof: CairoProofForRustVerifier<Blake2sMerkleHasher> =
        deserialize_proof_from_file(&proof_path, ProofFormat::Binary)
            .with_context(|| format!("failed to read {}", proof_path.display()))?;
    let preprocessed = proof
        .preprocessed_trace_variant
        .to_preprocessed_trace()
        .ids();
    let lookup = parameters::LookupProbe::from_seed(&[11, 13, 17, 19])?;
    let probe_lookup = parameters::LookupProbe::from_seed(&[23, 29, 31, 37])?;
    let components = CairoComponents::new(
        &proof.claim,
        &lookup.elements,
        &proof.interaction_claim,
        &preprocessed,
    );
    let probe_components = CairoComponents::new(
        &proof.claim,
        &probe_lookup.elements,
        &proof.interaction_claim,
        &preprocessed,
    );
    let expected_components = components.components().len();
    let mut summary = Summary::default();
    let mut captured = Vec::with_capacity(expected_components);

    macro_rules! lower_optional {
        ($( $field:ident ),+ $(,)?) => {
            $(
                if let Some(component) = &components.$field {
                    let probe_component = probe_components.$field.as_ref()
                        .context(concat!("probe missing ", stringify!($field)))?;
                    captured.push(lower_component(
                        stringify!($field),
                        0,
                        component,
                        probe_component,
                        &lookup,
                        &probe_lookup,
                        &mut summary,
                    )?);
                }
            )+
        };
    }

    lower_optional!(
        add_opcode,
        add_opcode_small,
        add_ap_opcode,
        assert_eq_opcode,
        assert_eq_opcode_imm,
        assert_eq_opcode_double_deref,
        blake_compress_opcode,
        call_opcode_abs,
        call_opcode_rel_imm,
        generic_opcode,
        jnz_opcode_non_taken,
        jnz_opcode_taken,
        jump_opcode_abs,
        jump_opcode_double_deref,
        jump_opcode_rel,
        jump_opcode_rel_imm,
        mul_opcode,
        mul_opcode_small,
        qm_31_add_mul_opcode,
        ret_opcode,
        verify_instruction,
        blake_round,
        blake_g,
        blake_round_sigma,
        triple_xor_32,
        verify_bitwise_xor_12,
        add_mod_builtin,
        bitwise_builtin,
        mul_mod_builtin,
        pedersen_builtin,
        pedersen_builtin_narrow_windows,
        poseidon_builtin,
        range_check96_builtin,
        range_check_builtin,
        ec_op_builtin,
        partial_ec_mul_generic,
        pedersen_aggregator_window_bits_18,
        partial_ec_mul_window_bits_18,
        pedersen_points_table_window_bits_18,
        pedersen_aggregator_window_bits_9,
        partial_ec_mul_window_bits_9,
        pedersen_points_table_window_bits_9,
        poseidon_aggregator,
        poseidon_3_partial_rounds_chain,
        poseidon_full_round_chain,
        cube_252,
        poseidon_round_keys,
        range_check_252_width_27,
        memory_address_to_id,
    );
    ensure!(
        components.memory_id_to_big.len() == probe_components.memory_id_to_big.len(),
        "memory_id_to_big probe count differs"
    );
    for (instance, (component, probe_component)) in components
        .memory_id_to_big
        .iter()
        .zip(&probe_components.memory_id_to_big)
        .enumerate()
    {
        captured.push(lower_component(
            &format!("memory_id_to_big[{instance}]"),
            u32::try_from(instance)?,
            component,
            probe_component,
            &lookup,
            &probe_lookup,
            &mut summary,
        )?);
    }
    lower_optional!(
        memory_id_to_small,
        range_check_6,
        range_check_8,
        range_check_11,
        range_check_12,
        range_check_18,
        range_check_20,
        range_check_4_3,
        range_check_4_4,
        range_check_9_9,
        range_check_7_2_5,
        range_check_3_6_6_3,
        range_check_4_4_4_4,
        range_check_3_3_3_3_3,
        verify_bitwise_xor_4,
        verify_bitwise_xor_7,
        verify_bitwise_xor_8,
        verify_bitwise_xor_9,
    );
    ensure!(
        summary.components == expected_components,
        "typed component order covered {}, erased order reports {}",
        summary.components,
        expected_components
    );
    println!(
        "complete: components={} constraints={} base_insts={} ext_insts={} ext_params={}",
        summary.components,
        summary.constraints,
        summary.base_instructions,
        summary.extension_instructions,
        summary.extension_parameters
    );
    let encoded = bundle::encode(&captured)?;
    println!("bundle_bytes={}", encoded.len());
    if let Some(output_path) = output_path {
        bundle::write_new(&output_path, &encoded)?;
        println!("wrote={}", output_path.display());
    }
    Ok(())
}

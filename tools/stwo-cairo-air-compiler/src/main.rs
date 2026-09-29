use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};
use cairo_air::CairoProofForRustVerifier;
use cairo_air::cairo_components::CairoComponents;
use cairo_air::claims::{CairoClaim, CairoInteractionClaim};
use cairo_air::relations::CommonLookupElements;
use cairo_air::utils::{ProofFormat, deserialize_proof_from_file};
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use stwo_cairo_adapter::ProverInput;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;
use stwo_cairo_prover::witness::cairo::create_cairo_claim_generator;

#[path = "../../stwo-eval-program-abi/src/lib.rs"]
mod eval_program_abi;

use eval_program_abi::capture::{Summary, lower_component};
use eval_program_abi::{abi_fixture, bundle, parameters};

enum Source {
    Proof(PathBuf),
    ProverInput {
        path: PathBuf,
        variant: PreProcessedTraceVariant,
    },
}

struct Arguments {
    source: Source,
    output: Option<PathBuf>,
}

fn arguments() -> Result<Arguments> {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments
        .next()
        .map(PathBuf::from)
        .context(
            "usage: stwo-cairo-air-compiler <official-binary-proof> [output-bundle]\n       stwo-cairo-air-compiler --prover-input <input.json> [--preprocessed-variant canonical|canonical-small|canonical-without-pedersen] [output-bundle]",
        )?;
    let source = if first == std::path::Path::new("--prover-input") {
        let path = arguments
            .next()
            .map(PathBuf::from)
            .context("--prover-input requires an input path")?;
        let mut variant = PreProcessedTraceVariant::Canonical;
        let mut next = arguments.next().map(PathBuf::from);
        if next.as_deref() == Some(std::path::Path::new("--preprocessed-variant")) {
            let value = arguments
                .next()
                .context("--preprocessed-variant requires a value")?;
            variant = match value.to_str() {
                Some("canonical") => PreProcessedTraceVariant::Canonical,
                Some("canonical-small") => PreProcessedTraceVariant::CanonicalSmall,
                Some("canonical-without-pedersen") => {
                    PreProcessedTraceVariant::CanonicalWithoutPedersen
                }
                _ => return Err(anyhow!("unsupported preprocessed variant")),
            };
            next = arguments.next().map(PathBuf::from);
        }
        return Ok(Arguments {
            source: Source::ProverInput { path, variant },
            output: next,
        });
    } else {
        Source::Proof(first)
    };
    let output_path = arguments.next().map(PathBuf::from);
    ensure!(arguments.next().is_none(), "too many arguments");
    Ok(Arguments {
        source,
        output: output_path,
    })
}

fn proof_source(
    proof_path: &PathBuf,
) -> Result<(
    CairoClaim,
    CairoInteractionClaim,
    Vec<stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId>,
)> {
    let proof: CairoProofForRustVerifier<Blake2sMerkleHasher> =
        deserialize_proof_from_file(&proof_path, ProofFormat::Binary)
            .with_context(|| format!("failed to read {}", proof_path.display()))?;
    let preprocessed = proof
        .preprocessed_trace_variant
        .to_preprocessed_trace()
        .ids();
    Ok((proof.claim, proof.interaction_claim, preprocessed))
}

fn prover_input_source(
    input_path: &PathBuf,
    variant: PreProcessedTraceVariant,
    lookup: &parameters::LookupProbe<CommonLookupElements>,
) -> Result<(
    CairoClaim,
    CairoInteractionClaim,
    Vec<stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId>,
)> {
    let bytes = std::fs::read(input_path)
        .with_context(|| format!("failed to read {}", input_path.display()))?;
    let input: ProverInput =
        serde_json::from_slice(&bytes).context("failed to decode official ProverInput JSON")?;
    let preprocessed_trace = Arc::new(variant.to_preprocessed_trace());
    let preprocessed = preprocessed_trace.ids();
    let generator = create_cairo_claim_generator(input, preprocessed_trace);
    let (base_evaluations, claim, interaction_generator) = generator.write_trace(None);
    drop(base_evaluations);
    let (interaction_evaluations, interaction_claim) =
        interaction_generator.write_interaction_trace(&lookup.elements);
    drop(interaction_evaluations);
    Ok((claim, interaction_claim, preprocessed))
}

fn main() -> Result<()> {
    abi_fixture::check()?;
    let arguments = arguments()?;
    let lookup = parameters::LookupProbe::from_seed(&[11, 13, 17, 19], CommonLookupElements::draw)?;
    let probe_lookup =
        parameters::LookupProbe::from_seed(&[23, 29, 31, 37], CommonLookupElements::draw)?;
    let (claim, interaction_claim, preprocessed) = match &arguments.source {
        Source::Proof(path) => proof_source(path)?,
        Source::ProverInput { path, variant } => prover_input_source(path, *variant, &lookup)?,
    };
    let components =
        CairoComponents::new(&claim, &lookup.elements, &interaction_claim, &preprocessed);
    let probe_components = CairoComponents::new(
        &claim,
        &probe_lookup.elements,
        &interaction_claim,
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
                    let (component, report) = lower_component(
                        stringify!($field),
                        0,
                        component,
                        probe_component,
                        &lookup,
                        &probe_lookup,
                        &mut summary,
                    )?;
                    println!("{report}");
                    captured.push(component);
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
        let (component, report) = lower_component(
            &format!("memory_id_to_big[{instance}]"),
            u32::try_from(instance)?,
            component,
            probe_component,
            &lookup,
            &probe_lookup,
            &mut summary,
        )?;
        println!("{report}");
        captured.push(component);
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
    if let Some(output_path) = arguments.output {
        bundle::write_new(&output_path, &encoded)?;
        println!("wrote={}", output_path.display());
    }
    Ok(())
}

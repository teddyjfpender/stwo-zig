//! Rung R6 (leaf): the host-side facts of `CairoStatement` and the leaf topology inputs.
//!
//! Everything here is read from pinned upstream code or data, never restated:
//!
//! - the statement constants (`AUX_DATA_FIXED_LEN`, builtin memory-cell sizes in
//!   `verify_builtins` order, relation ids, memory constants);
//! - the leaf disabled-component lists, parsed from `crates/leaf_prover/src/consts.rs`, and the
//!   `enabled_bits` they induce over `all_components()`;
//! - the ordered preprocessed column ids of every `PreProcessedTraceVariant`;
//! - `get_preprocessed_root(21 | 22 | 23)` of `crates/cairo_verifier/src/verify.rs`;
//! - the program limbs and program hash of the leaf test program
//!   (`crates/leaf_prover/tests/data/use_all_opcodes_and_builtins_compiled.json`), through
//!   `cairo_verifier::utils::load_program` and `claims_to_mix`'s hash;
//! - a synthetic `FlatClaim` with all eleven segments present, with its `serialize_aux_data`
//!   vector, `PublicData::pack_into_u32s`, and the channel digest after `FlatClaim::mix_into`
//!   under both `Blake2sM31MerkleChannel` and `Blake2sMerkleChannel`.

use std::path::Path;

use anyhow::{Context as _, Result, bail, ensure};
use cairo_air::air::{
    MemorySmallValue, PublicData, PublicMemory, PublicSegmentRanges, SegmentRange,
};
use cairo_air::components::memory_address_to_id::MEMORY_ADDRESS_TO_ID_SPLIT;
use cairo_air::flat_claims::FlatClaim;
use cairo_air::relations::{
    MEMORY_ADDRESS_TO_ID_RELATION_ID, MEMORY_ID_TO_BIG_RELATION_ID, OPCODES_RELATION_ID,
};
use circuit_cairo_verifier::all_components::all_components;
use circuit_cairo_verifier::statement::{
    AUX_DATA_FIXED_LEN, MEMORY_VALUES_LIMBS, N_OUTPUTS, N_WORDS_PER_OUTPUT_CELL, serialize_aux_data,
};
use circuit_cairo_verifier::utils::load_program;
use circuit_cairo_verifier::verify::{INTERACTION_POW_BITS, get_preprocessed_root};
use circuits::blake::HashValue;
use circuits::ivalue::{IValue, NoValue};
use circuits_stark_verifier::proof_from_stark_proof::pack_into_qm31s;
use circuits_stark_verifier::verify::RELATION_USES_NUM_ROWS_SHIFT;
use serde::Serialize;
use sha2::{Digest, Sha256};
use stwo::core::channel::Blake2sChannelGeneric;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleChannel};
use stwo_cairo_common::builtins::{
    ADD_MOD_BUILTIN_MEMORY_CELLS, BITWISE_BUILTIN_MEMORY_CELLS, EC_OP_BUILTIN_MEMORY_CELLS,
    ECDSA_MEMORY_CELLS, KECCAK_MEMORY_CELLS, MUL_MOD_BUILTIN_MEMORY_CELLS,
    PEDERSEN_BUILTIN_MEMORY_CELLS, POSEIDON_BUILTIN_MEMORY_CELLS,
    RANGE_CHECK_96_BUILTIN_MEMORY_CELLS, RANGE_CHECK_BUILTIN_MEMORY_CELLS,
};
use stwo_cairo_common::memory::LARGE_MEMORY_VALUE_ID_BASE;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::{
    MAX_SEQUENCE_LOG_SIZE, PreProcessedTraceVariant,
};
use stwo_cairo_common::prover_types::cpu::CasmState;

use crate::checkpoint::{Envelope, hex32};
use crate::upstream::ProvingRoot;

/// Aggregate digest of the two upstream files this subcommand reads at `proving@5a7c5ed`.
const PINNED_INPUTS_SHA256: &str =
    "e1dbcdbb9372c5c68aba0ea186804bd4c0aaa36944da9a077b991ca437193297";

const CONSTS_PATH: &str = "crates/leaf_prover/src/consts.rs";
const PROGRAM_PATH: &str =
    "crates/leaf_prover/tests/data/use_all_opcodes_and_builtins_compiled.json";
const LIFTING_LOG_SIZES: [u32; 3] = [21, 22, 23];

#[derive(Serialize)]
struct Constants {
    aux_data_fixed_len: usize,
    n_outputs: usize,
    n_words_per_output_cell: usize,
    memory_values_limbs: usize,
    large_memory_value_id_base: u32,
    memory_address_to_id_split: usize,
    max_sequence_log_size: u32,
    interaction_pow_bits: u32,
    relation_uses_num_rows_shift: usize,
    opcodes_relation_id: u32,
    memory_address_to_id_relation_id: u32,
    memory_id_to_big_relation_id: u32,
    /// `(name, memory cells)` in `CairoStatement::verify_builtins` order; the pedersen entry is
    /// named by its segment, since the component name depends on the variant.
    builtin_memory_cells: Vec<(&'static str, usize)>,
}

#[derive(Serialize)]
struct VariantRecord {
    variant: &'static str,
    /// The leaf disabled components, or `null` where `disabled_components` panics.
    disabled_components: Option<Vec<String>>,
    enabled_bits: Option<Vec<bool>>,
    n_enabled_components: Option<usize>,
    n_preprocessed_columns: usize,
    preprocessed_column_ids: Vec<String>,
}

#[derive(Serialize)]
struct ProgramRecord {
    path: &'static str,
    n_felts: usize,
    /// SHA-256 over the flattened limbs as LE u32 words.
    limbs_sha256: String,
    first_felt_limbs: Vec<u32>,
    last_felt_limbs: Vec<u32>,
    /// `claims_to_mix`: Blake2s over `pack_into_qm31s(limbs)` as LE u32 words.
    program_hash: [u32; 8],
}

#[derive(Serialize)]
struct SegmentRecord {
    start_id: u32,
    start_value: u32,
    stop_id: u32,
    stop_value: u32,
}

#[derive(Serialize)]
struct MemoryRecord {
    id: u32,
    value: [u32; 8],
}

#[derive(Serialize)]
struct SyntheticClaim {
    initial_state: [u32; 3],
    final_state: [u32; 3],
    /// All eleven segments, in `PublicSegmentRanges` field order.
    segments: Vec<SegmentRecord>,
    safe_call_ids: [u32; 2],
    output: Vec<MemoryRecord>,
    program: Vec<MemoryRecord>,
    component_enable_bits: Vec<bool>,
    component_log_sizes: Vec<u32>,
    serialized_aux_data: Vec<u32>,
    public_claim: Vec<u32>,
    output_claim: Vec<u32>,
    program_claim: Vec<u32>,
    /// Channel digest after `FlatClaim::mix_into` from a default channel.
    mix_digest_blake2s_m31: String,
    mix_digest_blake2s: String,
}

#[derive(Serialize)]
pub struct Body {
    constants: Constants,
    all_components: Vec<&'static str>,
    variants: Vec<VariantRecord>,
    /// `get_preprocessed_root(lifting_log_size)` as eight u32 words.
    preprocessed_roots: Vec<(u32, [u32; 8])>,
    program: ProgramRecord,
    synthetic_claim: SyntheticClaim,
}

pub fn run(proving_root: &Path) -> Result<Envelope<Body>> {
    let mut root = ProvingRoot::open(proving_root)?;
    let consts = String::from_utf8(root.read(CONSTS_PATH)?).context("consts.rs is not UTF-8")?;
    root.read(PROGRAM_PATH)?;

    let names: Vec<&'static str> = all_components::<NoValue>().keys().copied().collect();
    ensure!(
        names.len() == 83,
        "all_components has {} slots",
        names.len()
    );

    let canonical = parse_str_array(&consts, "DISABLED_COMPONENTS_CANONICAL_PREPROCESSED")?;
    let small = parse_str_array(&consts, "DISABLED_COMPONENTS_SMALL_PREPROCESSED")?;
    let variants = vec![
        variant_record(
            "canonical",
            PreProcessedTraceVariant::Canonical,
            Some(canonical),
            &names,
        )?,
        variant_record(
            "canonical_without_pedersen",
            PreProcessedTraceVariant::CanonicalWithoutPedersen,
            None,
            &names,
        )?,
        variant_record(
            "canonical_small",
            PreProcessedTraceVariant::CanonicalSmall,
            Some(small),
            &names,
        )?,
    ];

    let preprocessed_roots = LIFTING_LOG_SIZES
        .iter()
        .map(|&log| (log, hash_words(&get_preprocessed_root(log))))
        .collect();

    let program = program_record(&proving_root.join(PROGRAM_PATH))?;
    let small_bits = variants[2]
        .enabled_bits
        .clone()
        .context("canonical_small bits")?;
    let synthetic_claim = synthetic_claim(small_bits)?;

    let inputs = root.finish(PINNED_INPUTS_SHA256)?;
    Ok(Envelope::new(
        "r6",
        "cairo-statement",
        inputs,
        Body {
            constants: constants(),
            all_components: names,
            variants,
            preprocessed_roots,
            program,
            synthetic_claim,
        },
    ))
}

fn constants() -> Constants {
    Constants {
        aux_data_fixed_len: AUX_DATA_FIXED_LEN,
        n_outputs: N_OUTPUTS,
        n_words_per_output_cell: N_WORDS_PER_OUTPUT_CELL,
        memory_values_limbs: MEMORY_VALUES_LIMBS,
        large_memory_value_id_base: LARGE_MEMORY_VALUE_ID_BASE,
        memory_address_to_id_split: MEMORY_ADDRESS_TO_ID_SPLIT,
        max_sequence_log_size: MAX_SEQUENCE_LOG_SIZE,
        interaction_pow_bits: INTERACTION_POW_BITS,
        relation_uses_num_rows_shift: RELATION_USES_NUM_ROWS_SHIFT,
        opcodes_relation_id: OPCODES_RELATION_ID.0,
        memory_address_to_id_relation_id: MEMORY_ADDRESS_TO_ID_RELATION_ID.0,
        memory_id_to_big_relation_id: MEMORY_ID_TO_BIG_RELATION_ID.0,
        builtin_memory_cells: vec![
            ("pedersen", PEDERSEN_BUILTIN_MEMORY_CELLS),
            ("range_check_builtin", RANGE_CHECK_BUILTIN_MEMORY_CELLS),
            ("bitwise_builtin", BITWISE_BUILTIN_MEMORY_CELLS),
            ("poseidon_builtin", POSEIDON_BUILTIN_MEMORY_CELLS),
            ("ec_op_builtin", EC_OP_BUILTIN_MEMORY_CELLS),
            ("ecdsa_builtin", ECDSA_MEMORY_CELLS),
            ("keccak_builtin", KECCAK_MEMORY_CELLS),
            ("range_check96_builtin", RANGE_CHECK_96_BUILTIN_MEMORY_CELLS),
            ("add_mod_builtin", ADD_MOD_BUILTIN_MEMORY_CELLS),
            ("mul_mod_builtin", MUL_MOD_BUILTIN_MEMORY_CELLS),
        ],
    }
}

/// Parses `pub const NAME: [&str; N] = ["a", ...];` from upstream source text.
fn parse_str_array(source: &str, name: &str) -> Result<Vec<String>> {
    let start = source
        .find(&format!("pub const {name}:"))
        .with_context(|| format!("{name} not found in {CONSTS_PATH}"))?;
    let rest = &source[start..];
    let open = rest.find("= [").context("array literal")? + 3;
    let close = rest[open..].find("];").context("array end")? + open;
    let names: Vec<String> = rest[open..close]
        .split(',')
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(|item| {
            item.strip_prefix('"')
                .and_then(|item| item.strip_suffix('"'))
                .map(str::to_owned)
                .with_context(|| format!("unexpected item {item:?} in {name}"))
        })
        .collect::<Result<_>>()?;
    // The declared type is `[&str; N]`: N sits between the first `;` and the next `]`.
    let header = &rest[..open];
    let semicolon = header.find(';').context("array length")? + 1;
    let bracket = header[semicolon..].find(']').context("array length")? + semicolon;
    let declared: usize = header[semicolon..bracket]
        .trim()
        .parse()
        .context("array length")?;
    ensure!(
        names.len() == declared,
        "{name}: {} items, declared {declared}",
        names.len()
    );
    Ok(names)
}

fn variant_record(
    label: &'static str,
    variant: PreProcessedTraceVariant,
    disabled: Option<Vec<String>>,
    names: &[&'static str],
) -> Result<VariantRecord> {
    let trace = variant.to_preprocessed_trace();
    let ids: Vec<String> = trace.ids().into_iter().map(|id| id.id).collect();
    ensure!(
        ids.len() == variant.n_columns(),
        "{label}: id count differs from n_columns"
    );
    let enabled_bits = match &disabled {
        Some(disabled) => {
            for name in disabled {
                ensure!(
                    names.contains(&name.as_str()),
                    "{label}: unknown component {name}"
                );
            }
            // `leaf_verifier_components` in `crates/leaf_prover/src/prove_leaf.rs`.
            Some(
                names
                    .iter()
                    .map(|name| !disabled.iter().any(|d| d == name))
                    .collect::<Vec<_>>(),
            )
        }
        None => None,
    };
    Ok(VariantRecord {
        variant: label,
        n_enabled_components: enabled_bits
            .as_ref()
            .map(|bits| bits.iter().filter(|b| **b).count()),
        disabled_components: disabled,
        enabled_bits,
        n_preprocessed_columns: ids.len(),
        preprocessed_column_ids: ids,
    })
}

fn hash_words(hash: &HashValue<QM31>) -> [u32; 8] {
    hash.0.clone().map(|word| word.get().unpack_u32())
}

fn program_record(path: &Path) -> Result<ProgramRecord> {
    let program = load_program(path);
    ensure!(!program.is_empty(), "empty program");
    let flat: Vec<M31> = program.iter().flatten().copied().collect();
    let mut hasher = Sha256::new();
    for limb in &flat {
        hasher.update(limb.0.to_le_bytes());
    }
    let packed = pack_into_qm31s(flat.iter().copied());
    let program_hash = <QM31 as IValue>::blake2s(&packed, packed.len() * 16);
    Ok(ProgramRecord {
        path: PROGRAM_PATH,
        n_felts: program.len(),
        limbs_sha256: hex::encode(hasher.finalize()),
        first_felt_limbs: program[0].iter().map(|m| m.0).collect(),
        last_felt_limbs: program[program.len() - 1].iter().map(|m| m.0).collect(),
        program_hash: hash_words(&program_hash),
    })
}

fn felt_words(seed: u32) -> [u32; 8] {
    std::array::from_fn(|i| {
        let word =
            seed.wrapping_mul(0x9e37_79b9).rotate_left(i as u32 * 5) ^ (i as u32 * 0x0101_0101);
        // Keep the felt below 2^251 (a canonical felt252 top word) and the output cells below
        // 2^128 where the caller clears the high words.
        if i == 7 { word & 0x03ff_ffff } else { word }
    })
}

fn synthetic_claim(component_enable_bits: Vec<bool>) -> Result<SyntheticClaim> {
    let state = |[pc, ap, fp]: [u32; 3]| CasmState {
        pc: M31::from(pc),
        ap: M31::from(ap),
        fp: M31::from(fp),
    };
    let initial_state = [1, 300, 300];
    let final_state = [5, 420, 300];
    let segment = |i: u32| SegmentRange {
        start_ptr: MemorySmallValue {
            id: 1000 + 4 * i,
            value: 2000 + 64 * i,
        },
        stop_ptr: MemorySmallValue {
            id: 1001 + 4 * i,
            value: 2000 + 64 * i + 7 * (i + 1),
        },
    };
    let public_segments = PublicSegmentRanges {
        output: segment(0),
        pedersen: Some(segment(1)),
        range_check_128: Some(segment(2)),
        ecdsa: Some(segment(3)),
        bitwise: Some(segment(4)),
        ec_op: Some(segment(5)),
        keccak: Some(segment(6)),
        poseidon: Some(segment(7)),
        range_check_96: Some(segment(8)),
        add_mod: Some(segment(9)),
        mul_mod: Some(segment(10)),
    };
    let output: Vec<(u32, [u32; 8])> = (0..N_OUTPUTS as u32)
        .map(|k| {
            let mut value = felt_words(0x51 + k);
            value[4..].fill(0);
            (50 + k, value)
        })
        .collect();
    let program: Vec<(u32, [u32; 8])> = (0..5).map(|k| (60 + k, felt_words(0x77 + k))).collect();
    let safe_call_ids = [7, 8];
    let n_enabled = component_enable_bits.iter().filter(|b| **b).count();
    let component_log_sizes: Vec<u32> = (0..n_enabled as u32).map(|i| 4 + i % 20).collect();

    let claim = FlatClaim {
        component_enable_bits: component_enable_bits.clone(),
        component_log_sizes: component_log_sizes.clone(),
        public_data: PublicData {
            public_memory: PublicMemory {
                program: program.clone(),
                public_segments,
                output: output.clone(),
                safe_call_ids,
            },
            initial_state: state(initial_state),
            final_state: state(final_state),
        },
    };
    let serialized: Vec<u32> = serialize_aux_data(&claim)
        .into_iter()
        .map(|m| m.0)
        .collect();
    let expected_len = AUX_DATA_FIXED_LEN + program.len() + n_enabled;
    if serialized.len() != expected_len {
        bail!(
            "serialize_aux_data has {} words, expected {expected_len}",
            serialized.len()
        );
    }
    let (public_claim, output_claim, program_claim) = claim.public_data.pack_into_u32s();

    let mut m31_channel = Blake2sChannelGeneric::<true>::default();
    claim.mix_into::<Blake2sM31MerkleChannel>(&mut m31_channel);
    let mut plain_channel = Blake2sChannelGeneric::<false>::default();
    claim.mix_into::<Blake2sMerkleChannel>(&mut plain_channel);

    let segments = (0..11)
        .map(|i| {
            let range = segment(i);
            SegmentRecord {
                start_id: range.start_ptr.id,
                start_value: range.start_ptr.value,
                stop_id: range.stop_ptr.id,
                stop_value: range.stop_ptr.value,
            }
        })
        .collect();
    let memory = |section: &[(u32, [u32; 8])]| {
        section
            .iter()
            .map(|&(id, value)| MemoryRecord { id, value })
            .collect()
    };
    Ok(SyntheticClaim {
        initial_state,
        final_state,
        segments,
        safe_call_ids,
        output: memory(&output),
        program: memory(&program),
        component_enable_bits,
        component_log_sizes,
        serialized_aux_data: serialized,
        public_claim,
        output_claim,
        program_claim,
        mix_digest_blake2s_m31: hex32(m31_channel.digest().0),
        mix_digest_blake2s: hex32(plain_channel.digest().0),
    })
}

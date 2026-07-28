//! Stable summaries of the official Cairo claim and interaction claim.

use cairo_air::claims::{CairoClaim, CairoInteractionClaim};
use serde::Serialize;
use sha2::{Digest, Sha256};
use stwo::core::channel::Blake2sChannel;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;

pub const SUMMARY_SCHEMA: &str = "stwo_cairo_official_claim_summary_v1";

#[derive(Debug, Serialize)]
pub struct WordDigest {
    count: usize,
    sha256_le: String,
}

#[derive(Debug, Serialize)]
pub struct FlatClaimSummary {
    component_enable_bits: Vec<bool>,
    component_enable_words: WordDigest,
    component_log_sizes: Vec<u32>,
    component_log_sizes_words: WordDigest,
    blake2s_mix_digest: String,
}

#[derive(Debug, Serialize)]
pub struct InteractionSummary {
    pow: u64,
    claimed_sums_m31: Vec<[u32; 4]>,
    claimed_sum_words: WordDigest,
    blake2s_mix_digest: String,
}

#[derive(Debug, Serialize)]
pub struct ProofClaimSummary {
    schema: &'static str,
    preprocessed_trace_variant: PreProcessedTraceVariant,
    flat_claim: FlatClaimSummary,
    tree_log_sizes: Vec<Vec<u32>>,
    interaction: InteractionSummary,
}

pub fn summarize(
    claim: &CairoClaim,
    interaction_pow: u64,
    interaction_claim: &CairoInteractionClaim,
    preprocessed_trace_variant: PreProcessedTraceVariant,
) -> ProofClaimSummary {
    let flat = claim.flatten_claim();
    let enable_words = flat
        .component_enable_bits
        .iter()
        .map(|enabled| u32::from(*enabled))
        .collect::<Vec<_>>();
    let claimed_sums_m31 = interaction_claim
        .flatten_interaction_claim()
        .into_iter()
        .map(|value| value.to_m31_array().map(|word| word.0))
        .collect::<Vec<_>>();
    let claimed_sum_words = claimed_sums_m31
        .iter()
        .flat_map(|value| value.iter().copied())
        .collect::<Vec<_>>();

    let mut claim_channel = Blake2sChannel::default();
    claim.mix_into::<Blake2sMerkleChannel>(&mut claim_channel);
    let mut interaction_channel = Blake2sChannel::default();
    interaction_claim.mix_into(&mut interaction_channel);

    ProofClaimSummary {
        schema: SUMMARY_SCHEMA,
        preprocessed_trace_variant,
        flat_claim: FlatClaimSummary {
            component_enable_words: word_digest(&enable_words),
            component_log_sizes_words: word_digest(&flat.component_log_sizes),
            component_enable_bits: flat.component_enable_bits,
            component_log_sizes: flat.component_log_sizes,
            blake2s_mix_digest: hex(&claim_channel.digest().0),
        },
        tree_log_sizes: claim.log_sizes().0,
        interaction: InteractionSummary {
            pow: interaction_pow,
            claimed_sum_words: word_digest(&claimed_sum_words),
            claimed_sums_m31,
            blake2s_mix_digest: hex(&interaction_channel.digest().0),
        },
    }
}

fn word_digest(words: &[u32]) -> WordDigest {
    let mut hasher = Sha256::new();
    for word in words {
        hasher.update(word.to_le_bytes());
    }
    WordDigest {
        count: words.len(),
        sha256_le: format!("{:x}", hasher.finalize()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

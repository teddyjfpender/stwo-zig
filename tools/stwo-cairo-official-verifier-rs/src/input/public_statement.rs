//! Official Cairo `PublicData` extraction and transcript-facing summary.
//!
//! Stwo-Cairo keeps input-to-statement extraction private to its prover crate.
//! This adapter reproduces that small extraction boundary and delegates all
//! packing and Blake2s leaf hashing to the pinned official public types.

use anyhow::{Context, Result, ensure};
use cairo_air::air::{
    MemorySmallValue, PublicData, PublicMemory, PublicSegmentRanges, SegmentRange,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use stwo::core::fields::m31::M31;
use stwo::core::vcs_lifted::MerkleHasherLifted;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use stwo_cairo_adapter::ProverInput;
use stwo_cairo_adapter::memory::{DEFAULT_ID, Memory};

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct WordDigest {
    count: usize,
    sha256_le: String,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct PublicStatementSummary {
    pub program_len: usize,
    pub output_len: usize,
    public_claim_words: WordDigest,
    public_claim_padded_words: WordDigest,
    output_claim_words: WordDigest,
    program_claim_words: WordDigest,
    output_root_blake2s: String,
    program_root_blake2s: String,
}

pub fn derive(input: &ProverInput) -> Result<(PublicData, PublicStatementSummary)> {
    let initial_state = input.state_transitions.initial_state;
    let final_state = input.state_transitions.final_state;
    let public_memory = extract_public_memory(input)?;
    let public_data = PublicData {
        public_memory,
        initial_state,
        final_state,
    };
    let summary = summarize(&public_data);
    Ok((public_data, summary))
}

pub fn summarize(public_data: &PublicData) -> PublicStatementSummary {
    let (public_claim, output_claim, program_claim) = public_data.pack_into_u32s();
    let mut padded_public_claim = public_claim.clone();
    padded_public_claim.resize(public_claim.len().div_ceil(4) * 4, 0);
    PublicStatementSummary {
        program_len: public_data.public_memory.program.len(),
        output_len: public_data.public_memory.output.len(),
        public_claim_words: word_digest(&public_claim),
        public_claim_padded_words: word_digest(&padded_public_claim),
        output_claim_words: word_digest(&output_claim),
        program_claim_words: word_digest(&program_claim),
        output_root_blake2s: blake2s_leaf_root(&output_claim),
        program_root_blake2s: blake2s_leaf_root(&program_claim),
    }
}

fn extract_public_memory(input: &ProverInput) -> Result<PublicMemory> {
    let initial_pc = input.state_transitions.initial_state.pc.0;
    let initial_ap = input.state_transitions.initial_state.ap.0;
    let final_ap = input.state_transitions.final_state.ap.0;
    let public_segments = extract_public_segments(
        &input.memory,
        initial_ap,
        final_ap,
        &input.public_segment_context,
    )?;

    let program_stop = initial_ap
        .checked_sub(2)
        .context("initial AP does not leave a safe-call area")?;
    ensure!(
        initial_pc <= program_stop,
        "initial PC is beyond the program stop"
    );
    let program = memory_section(&input.memory, initial_pc, program_stop)?;

    let safe_call = memory_section(&input.memory, program_stop, initial_ap)?;
    ensure!(
        safe_call.len() == 2,
        "safe-call area must contain two cells"
    );
    ensure!(
        safe_call[0].1 == [initial_ap, 0, 0, 0, 0, 0, 0, 0],
        "safe-call frame cell does not equal initial AP"
    );
    ensure!(
        safe_call[1].1 == [0; 8],
        "safe-call return-PC cell is not zero"
    );

    let output_start = public_segments.output.start_ptr.value;
    let output_stop = public_segments.output.stop_ptr.value;
    ensure!(
        output_start <= output_stop,
        "output segment stop precedes start"
    );
    let output = memory_section(&input.memory, output_start, output_stop)?;

    Ok(PublicMemory {
        program,
        public_segments,
        output,
        safe_call_ids: [safe_call[0].0, safe_call[1].0],
    })
}

fn extract_public_segments(
    memory: &Memory,
    initial_ap: u32,
    final_ap: u32,
    context: &[bool; 11],
) -> Result<PublicSegmentRanges> {
    let count: u32 = context
        .iter()
        .filter(|present| **present)
        .count()
        .try_into()
        .context("public segment count does not fit u32")?;
    ensure!(count > 0, "at least the output segment must be public");
    ensure!(context[0], "the output segment must be public");
    let start_stop = initial_ap
        .checked_add(count)
        .context("public segment start-pointer area overflows")?;
    let stop_start = final_ap
        .checked_sub(count)
        .context("public segment stop-pointer area underflows")?;

    let mut ranges = Vec::with_capacity(count as usize);
    for offset in 0..count {
        ranges.push(SegmentRange {
            start_ptr: memory_pointer(memory, initial_ap + offset)?,
            stop_ptr: memory_pointer(memory, stop_start + offset)?,
        });
    }
    ensure!(
        start_stop <= memory.address_to_id.len().try_into().unwrap_or(u32::MAX),
        "public segment start-pointer area exceeds memory"
    );

    let mut by_slot = [None; 11];
    let mut range_index = 0;
    for (slot, present) in context.iter().copied().enumerate() {
        if present {
            by_slot[slot] = Some(ranges[range_index]);
            range_index += 1;
        }
    }
    let [
        output,
        pedersen,
        range_check_128,
        ecdsa,
        bitwise,
        ec_op,
        keccak,
        poseidon,
        range_check_96,
        add_mod,
        mul_mod,
    ] = by_slot;

    Ok(PublicSegmentRanges {
        output: output.context("missing output segment range")?,
        pedersen,
        range_check_128,
        ecdsa,
        bitwise,
        ec_op,
        keccak,
        poseidon,
        range_check_96,
        add_mod,
        mul_mod,
    })
}

fn memory_section(memory: &Memory, start: u32, stop: u32) -> Result<Vec<(u32, [u32; 8])>> {
    let capacity: usize = stop
        .checked_sub(start)
        .context("memory section stop precedes start")?
        .try_into()
        .context("memory section length does not fit usize")?;
    let mut section = Vec::with_capacity(capacity);
    for address in start..stop {
        section.push(memory_entry(memory, address)?);
    }
    Ok(section)
}

fn memory_pointer(memory: &Memory, address: u32) -> Result<MemorySmallValue> {
    let (id, words) = memory_entry(memory, address)?;
    ensure!(
        words[1..].iter().all(|word| *word == 0),
        "segment pointer at address {address} does not fit u32"
    );
    ensure!(
        words[0] < 0x7fff_ffff,
        "segment pointer at address {address} is not an M31"
    );
    Ok(MemorySmallValue {
        id,
        value: words[0],
    })
}

fn memory_entry(memory: &Memory, address: u32) -> Result<(u32, [u32; 8])> {
    let encoded = memory
        .address_to_id
        .get(address as usize)
        .with_context(|| format!("memory address {address} is out of range"))?
        .0;
    ensure!(encoded != DEFAULT_ID, "memory address {address} is empty");
    let index = (encoded & 0x3fff_ffff) as usize;
    let words = match encoded >> 30 {
        0 => {
            let value = *memory
                .small_values
                .get(index)
                .with_context(|| format!("small memory ID {index} is out of range"))?;
            [
                value as u32,
                (value >> 32) as u32,
                (value >> 64) as u32,
                (value >> 96) as u32,
                0,
                0,
                0,
                0,
            ]
        }
        1 => *memory
            .f252_values
            .get(index)
            .with_context(|| format!("felt252 memory ID {index} is out of range"))?,
        tag => anyhow::bail!("memory address {address} has invalid ID tag {tag}"),
    };
    Ok((encoded, words))
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

fn blake2s_leaf_root(words: &[u32]) -> String {
    let mut hasher = Blake2sMerkleHasher::default();
    let values = words
        .iter()
        .map(|word| M31::from_u32_unchecked(*word))
        .collect::<Vec<_>>();
    hasher.update_leaf(&values);
    hex(&MerkleHasherLifted::finalize(hasher).0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

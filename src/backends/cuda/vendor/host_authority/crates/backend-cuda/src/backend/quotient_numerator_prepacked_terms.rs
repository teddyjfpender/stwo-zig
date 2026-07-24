//! Address-free model for the prepacked quotient-numerator hot loop.
//!
//! The native candidate overwrites `term_points` only after group finalization,
//! its last reader. Each descriptor then occupies seven words:
//! `[source_pointer_lo, source_pointer_hi, four c words, source_log_size]`.
//! The tail stores one pre-summed `B_g = sum(b_t)` per group and one observable
//! status word. Production keeps the existing staged single-write path until
//! native differential gates pass.

use super::quotient_numerator_staged_single_write::{
    QuotientNumeratorStagedLde, QuotientNumeratorStagedOperation,
    QuotientNumeratorStagedSingleWritePlan, QuotientNumeratorStagedSource,
    QuotientNumeratorStagingRole,
};

pub const QUOTIENT_NUMERATOR_PREPACKED_TERM_WORDS: usize = 7;
pub const QUOTIENT_NUMERATOR_PREPACKED_GROUP_WORDS: usize = 4;
pub const QUOTIENT_NUMERATOR_PREPACKED_STATUS_WORDS: usize = 1;

const SOURCE_ORDINAL_WORD: usize = 0;
const TERM_ORDINAL_WORD: usize = 1;
const SOURCE_LOG_WORD: usize = 2;
const SOURCE_DESCRIPTOR_WORDS: usize = 3;
const M31_MODULUS: u32 = 0x7fff_ffff;

/// Stable device-status ABI. Zero means every preceding candidate operation
/// completed without detecting an invalid sealed descriptor or manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum QuotientNumeratorPrepackedStatusCode {
    Success = 0,
    PrepareGroupOffsetsNotCanonical = 1,
    PrepareSourceOutOfBounds = 2,
    PrepareTermOutOfBounds = 3,
    PrepareSourceLogOutOfBounds = 4,
    PrepareNullSource = 5,
    PrepareGroupRangeOutOfBounds = 6,
    PrepareGroupTermOutOfBounds = 7,
    HotRowOffsetsNotCanonical = 8,
    HotGroupRowShapeInvalid = 9,
    HotGroupTermRangeInvalid = 10,
    HotSourceLogOutOfBounds = 11,
    HotNullSource = 12,
}

impl QuotientNumeratorPrepackedStatusCode {
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorPrepackedTermLayout {
    pub term_count: usize,
    pub group_count: usize,
    pub term_words: usize,
    pub group_b_offset_words: usize,
    pub group_b_words: usize,
    pub status_offset_words: usize,
    pub status_words: usize,
    pub used_words: usize,
    pub term_point_capacity_words: usize,
}

impl QuotientNumeratorPrepackedTermLayout {
    pub fn spare_words(self) -> usize {
        self.term_point_capacity_words
            .saturating_sub(self.used_words)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorLineCoefficientsWords {
    pub b: [u32; 4],
    pub c: [u32; 4],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorPrepackedTerm {
    source_ordinal: u32,
    c: [u32; 4],
    source_log_size: u32,
}

impl QuotientNumeratorPrepackedTerm {
    pub fn source_ordinal(self) -> u32 {
        self.source_ordinal
    }

    pub fn c(self) -> [u32; 4] {
        self.c
    }

    pub fn source_log_size(self) -> u32 {
        self.source_log_size
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorPrepackedTermOracle {
    layout: QuotientNumeratorPrepackedTermLayout,
    plan_identity: [u8; 32],
    terms: Vec<QuotientNumeratorPrepackedTerm>,
    group_b: Vec<[u32; 4]>,
}

impl QuotientNumeratorPrepackedTermOracle {
    pub fn layout(&self) -> QuotientNumeratorPrepackedTermLayout {
        self.layout
    }

    /// Domain-separated BLAKE3 identity of the exact staged plan.
    pub fn plan_identity(&self) -> &[u8; 32] {
        &self.plan_identity
    }

    pub fn terms(&self) -> &[QuotientNumeratorPrepackedTerm] {
        &self.terms
    }

    pub fn group_b(&self) -> &[[u32; 4]] {
        &self.group_b
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuotientNumeratorPrepackedTermError {
    SizeOverflow,
    InsufficientDeadTermPointWords {
        required_words: usize,
        available_words: usize,
    },
    LineCoefficientCountMismatch {
        expected: usize,
        actual: usize,
    },
    DescriptorInvariant(&'static str),
    NonCanonicalWord {
        term: usize,
        coordinate: usize,
        value: u32,
    },
    MissingSource(usize),
    SourceRowOutOfBounds {
        source: usize,
        row: usize,
        len: usize,
    },
    GroupOutOfBounds(usize),
    RowOutOfBounds {
        group: usize,
        row: usize,
        rows: usize,
    },
}

impl core::fmt::Display for QuotientNumeratorPrepackedTermError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "invalid prepacked quotient-numerator terms: {self:?}"
        )
    }
}

impl std::error::Error for QuotientNumeratorPrepackedTermError {}

pub fn quotient_numerator_prepacked_term_layout(
    plan: &QuotientNumeratorStagedSingleWritePlan,
) -> Result<QuotientNumeratorPrepackedTermLayout, QuotientNumeratorPrepackedTermError> {
    let term_count = plan.requirements().term_count;
    let group_count = plan.requirements().groups.len();
    let term_words = term_count
        .checked_mul(QUOTIENT_NUMERATOR_PREPACKED_TERM_WORDS)
        .ok_or(QuotientNumeratorPrepackedTermError::SizeOverflow)?;
    let group_b_words = group_count
        .checked_mul(QUOTIENT_NUMERATOR_PREPACKED_GROUP_WORDS)
        .ok_or(QuotientNumeratorPrepackedTermError::SizeOverflow)?;
    let status_offset_words = term_words
        .checked_add(group_b_words)
        .ok_or(QuotientNumeratorPrepackedTermError::SizeOverflow)?;
    let used_words = status_offset_words
        .checked_add(QUOTIENT_NUMERATOR_PREPACKED_STATUS_WORDS)
        .ok_or(QuotientNumeratorPrepackedTermError::SizeOverflow)?;
    let available_words = plan.requirements().term_point_words;
    if used_words > available_words {
        return Err(
            QuotientNumeratorPrepackedTermError::InsufficientDeadTermPointWords {
                required_words: used_words,
                available_words,
            },
        );
    }
    Ok(QuotientNumeratorPrepackedTermLayout {
        term_count,
        group_count,
        term_words,
        group_b_offset_words: term_words,
        group_b_words,
        status_offset_words,
        status_words: QUOTIENT_NUMERATOR_PREPACKED_STATUS_WORDS,
        used_words,
        term_point_capacity_words: available_words,
    })
}

/// Pure setup oracle for the device pack kernel. Source ordinals stand in for
/// addresses; descriptor order and every field word are otherwise exact.
pub fn quotient_numerator_prepacked_term_oracle(
    plan: &QuotientNumeratorStagedSingleWritePlan,
    coefficients: &[QuotientNumeratorLineCoefficientsWords],
) -> Result<QuotientNumeratorPrepackedTermOracle, QuotientNumeratorPrepackedTermError> {
    let layout = quotient_numerator_prepacked_term_layout(plan)?;
    let plan_identity = quotient_numerator_prepacked_plan_identity(plan)?;
    if coefficients.len() != layout.term_count {
        return Err(
            QuotientNumeratorPrepackedTermError::LineCoefficientCountMismatch {
                expected: layout.term_count,
                actual: coefficients.len(),
            },
        );
    }
    for (term, coefficient) in coefficients.iter().enumerate() {
        for (coordinate, &value) in coefficient.b.iter().chain(&coefficient.c).enumerate() {
            if value > M31_MODULUS {
                return Err(QuotientNumeratorPrepackedTermError::NonCanonicalWord {
                    term,
                    coordinate,
                    value,
                });
            }
        }
    }

    let descriptors = plan.term_descriptors();
    if descriptors.len()
        != layout
            .term_count
            .checked_mul(SOURCE_DESCRIPTOR_WORDS)
            .ok_or(QuotientNumeratorPrepackedTermError::SizeOverflow)?
    {
        return Err(QuotientNumeratorPrepackedTermError::DescriptorInvariant(
            "descriptor words do not cover every term",
        ));
    }
    let mut terms = Vec::with_capacity(layout.term_count);
    for descriptor in descriptors.chunks_exact(SOURCE_DESCRIPTOR_WORDS) {
        let source = descriptor[SOURCE_ORDINAL_WORD];
        let term = descriptor[TERM_ORDINAL_WORD] as usize;
        if source as usize >= plan.sources().len() {
            return Err(QuotientNumeratorPrepackedTermError::DescriptorInvariant(
                "source ordinal is out of bounds",
            ));
        }
        let Some(coefficient) = coefficients.get(term) else {
            return Err(QuotientNumeratorPrepackedTermError::DescriptorInvariant(
                "term ordinal is out of bounds",
            ));
        };
        terms.push(QuotientNumeratorPrepackedTerm {
            source_ordinal: source,
            c: coefficient.c,
            source_log_size: descriptor[SOURCE_LOG_WORD],
        });
    }

    let offsets = plan.group_offsets();
    if offsets.len() != layout.group_count + 1
        || offsets.first().copied() != Some(0)
        || offsets.last().copied() != u32::try_from(layout.term_count).ok()
    {
        return Err(QuotientNumeratorPrepackedTermError::DescriptorInvariant(
            "group offsets do not cover every descriptor",
        ));
    }
    let mut group_b = Vec::with_capacity(layout.group_count);
    for group in 0..layout.group_count {
        let mut sum = [0; 4];
        for descriptor in descriptors[(offsets[group] as usize) * SOURCE_DESCRIPTOR_WORDS
            ..(offsets[group + 1] as usize) * SOURCE_DESCRIPTOR_WORDS]
            .chunks_exact(SOURCE_DESCRIPTOR_WORDS)
        {
            let term = descriptor[TERM_ORDINAL_WORD] as usize;
            for (coordinate, value) in sum.iter_mut().enumerate() {
                *value = m31_add(*value, coefficients[term].b[coordinate]);
            }
        }
        group_b.push(sum);
    }

    Ok(QuotientNumeratorPrepackedTermOracle {
        layout,
        plan_identity,
        terms,
        group_b,
    })
}

/// CPU oracle for the candidate hot formulation:
/// `sum(c_t * source_t[row]) - B_g`.
pub fn quotient_numerator_prepacked_row_oracle(
    plan: &QuotientNumeratorStagedSingleWritePlan,
    packed: &QuotientNumeratorPrepackedTermOracle,
    sources: &[Vec<u32>],
    group: usize,
    row: usize,
) -> Result<[u32; 4], QuotientNumeratorPrepackedTermError> {
    if packed.layout != quotient_numerator_prepacked_term_layout(plan)? {
        return Err(QuotientNumeratorPrepackedTermError::DescriptorInvariant(
            "packed layout differs from the staged plan",
        ));
    }
    if packed.plan_identity != quotient_numerator_prepacked_plan_identity(plan)? {
        return Err(QuotientNumeratorPrepackedTermError::DescriptorInvariant(
            "packed plan identity differs from the staged plan",
        ));
    }
    let Some(group_requirements) = plan.requirements().groups.get(group) else {
        return Err(QuotientNumeratorPrepackedTermError::GroupOutOfBounds(group));
    };
    if row >= group_requirements.value_words {
        return Err(QuotientNumeratorPrepackedTermError::RowOutOfBounds {
            group,
            row,
            rows: group_requirements.value_words,
        });
    }
    let begin = plan.group_offsets()[group] as usize;
    let end = plan.group_offsets()[group + 1] as usize;
    let mut numerator = [0; 4];
    for (term_index, term) in packed.terms[begin..end].iter().enumerate() {
        if term.source_log_size > group_requirements.log_size {
            return Err(QuotientNumeratorPrepackedTermError::DescriptorInvariant(
                "source log exceeds its output group log",
            ));
        }
        let source = term.source_ordinal as usize;
        let source_values = sources
            .get(source)
            .ok_or(QuotientNumeratorPrepackedTermError::MissingSource(source))?;
        let log_ratio = group_requirements.log_size - term.source_log_size;
        let source_row = (row >> (log_ratio + 1) << 1) + (row & 1);
        let scalar = *source_values.get(source_row).ok_or(
            QuotientNumeratorPrepackedTermError::SourceRowOutOfBounds {
                source,
                row: source_row,
                len: source_values.len(),
            },
        )?;
        if scalar > M31_MODULUS {
            return Err(QuotientNumeratorPrepackedTermError::NonCanonicalWord {
                term: begin + term_index,
                coordinate: 8,
                value: scalar,
            });
        }
        for (coordinate, value) in numerator.iter_mut().enumerate() {
            *value = m31_add(*value, m31_mul(term.c[coordinate], scalar));
        }
    }
    for (coordinate, value) in numerator.iter_mut().enumerate() {
        *value = m31_sub(*value, packed.group_b[group][coordinate]);
    }
    Ok(numerator)
}

/// Domain-separated identity of every address-free staged-plan field consumed
/// by the prepacked runtime.
#[doc(hidden)]
pub fn quotient_numerator_prepacked_plan_identity(
    plan: &QuotientNumeratorStagedSingleWritePlan,
) -> Result<[u8; 32], QuotientNumeratorPrepackedTermError> {
    let mut identity = blake3::Hasher::new();
    hash_bytes(&mut identity, b"stwo-prepacked-quotient-v1");

    let requirements = plan.requirements();
    hash_u32(&mut identity, requirements.config.lifting_log_size);
    hash_u32(&mut identity, requirements.config.log_blowup_factor);
    hash_usize(&mut identity, requirements.config.max_lde_tile_words)?;
    hash_usize(&mut identity, requirements.input_sample_count)?;
    hash_usize(&mut identity, requirements.term_count)?;
    hash_usize(&mut identity, requirements.groups.len())?;
    for group in &requirements.groups {
        for coordinate in group
            .shape_point
            .x
            .to_m31_array()
            .into_iter()
            .chain(group.shape_point.y.to_m31_array())
        {
            hash_u32(&mut identity, coordinate.0);
        }
        hash_u32(&mut identity, group.log_size);
        hash_usize(&mut identity, group.value_words)?;
        hash_usize(&mut identity, group.coefficient_source_count)?;
    }
    hash_usize(&mut identity, requirements.batches.len())?;
    for batch in &requirements.batches {
        hash_u32(&mut identity, batch.evaluation_log_size);
        hash_usize(&mut identity, batch.source_count)?;
        hash_usize(&mut identity, batch.coefficient_count)?;
        hash_usize(&mut identity, batch.term_count)?;
        hash_usize(&mut identity, batch.lde_words)?;
    }
    for words in [
        requirements.runtime_term_words,
        requirements.group_term_index_words,
        requirements.group_offset_words,
        requirements.line_coefficient_words,
        requirements.term_point_words,
        requirements.batch_term_words,
        requirements.batch_group_offset_words,
        requirements.batch_source_pointer_words,
        requirements.coefficient_pointer_words,
        requirements.coefficient_size_words,
        requirements.coefficient_output_pointer_words,
        requirements.output_pointer_words,
        requirements.output_log_size_words,
        requirements.lde_tile_words,
        requirements.forward_twiddle_words,
        requirements.max_output_size,
    ] {
        hash_usize(&mut identity, words)?;
    }

    hash_usize(&mut identity, plan.group_offsets().len())?;
    for &offset in plan.group_offsets() {
        hash_u32(&mut identity, offset);
    }
    hash_usize(&mut identity, plan.packed_group_row_offsets().len())?;
    for &offset in plan.packed_group_row_offsets() {
        hash_u64(&mut identity, offset);
    }

    hash_usize(&mut identity, plan.term_descriptors().len())?;
    for &word in plan.term_descriptors() {
        hash_u32(&mut identity, word);
    }
    hash_usize(&mut identity, plan.coefficient_ldes().len())?;
    for lde in plan.coefficient_ldes() {
        hash_staged_lde(&mut identity, *lde)?;
    }
    hash_usize(&mut identity, plan.operations().len())?;
    for operation in plan.operations() {
        match *operation {
            QuotientNumeratorStagedOperation::MaterializeLdes(launch) => {
                identity.update(&[0]);
                hash_u32(&mut identity, launch.evaluation_log_size());
                hash_usize(&mut identity, launch.first_lde())?;
                hash_usize(&mut identity, launch.lde_count())?;
            }
            QuotientNumeratorStagedOperation::AccumulatePackedRows {
                group_count,
                term_count,
                packed_output_rows,
            } => {
                identity.update(&[1]);
                hash_usize(&mut identity, group_count)?;
                hash_usize(&mut identity, term_count)?;
                hash_u64(&mut identity, packed_output_rows);
            }
        }
    }
    hash_usize(&mut identity, plan.sources().len())?;
    for source in plan.sources() {
        match *source {
            QuotientNumeratorStagedSource::Evaluation {
                column,
                evaluation_log_size,
            } => {
                identity.update(&[0]);
                hash_usize(&mut identity, column)?;
                hash_u32(&mut identity, evaluation_log_size);
            }
            QuotientNumeratorStagedSource::StagedCoefficient(lde) => {
                identity.update(&[1]);
                hash_staged_lde(&mut identity, lde)?;
            }
        }
    }

    let report = plan.report();
    for value in [
        report.group_count,
        report.term_count,
        report.source_count,
        report.coefficient_source_count,
        report.factor32_batch_count,
        report.factor32_accumulation_passes,
        report.factor32_total_output_passes,
        report.candidate_output_passes,
        report.output_rows,
        report.coefficient_output_rows,
    ] {
        hash_usize(&mut identity, value)?;
    }
    for value in [
        report.factor32_logical_output_bytes,
        report.candidate_logical_output_bytes,
        report.logical_output_bytes_saved,
        report.rectangular_launch_rows,
        report.inactive_rectangular_launch_rows,
        report.useful_row_terms,
        report.rectangular_row_term_capacity,
    ] {
        hash_u64(&mut identity, value);
    }
    hash_u32(
        &mut identity,
        report.packed_binary_search_comparisons_per_row_max,
    );
    hash_u64(&mut identity, report.packed_binary_search_comparisons_max);
    for value in [
        report.total_staging_words,
        report.factor32_staging_words,
        report.primary_staging_words,
        report.unused_factor32_staging_words,
        report.overflow_staging_words,
        report.overflow_staging_role_count,
        report.max_overflow_staging_role_words,
        report.incremental_staging_words_over_factor32,
    ] {
        hash_usize(&mut identity, value)?;
    }
    Ok(*identity.finalize().as_bytes())
}

fn hash_staged_lde(
    output: &mut blake3::Hasher,
    lde: QuotientNumeratorStagedLde,
) -> Result<(), QuotientNumeratorPrepackedTermError> {
    hash_usize(output, lde.column())?;
    hash_u32(output, lde.evaluation_log_size());
    match lde.staging_role() {
        QuotientNumeratorStagingRole::Primary => {
            output.update(&[0]);
            output.update(&0u16.to_le_bytes());
        }
        QuotientNumeratorStagingRole::Overflow(role) => {
            output.update(&[1]);
            output.update(&role.to_le_bytes());
        }
    }
    hash_usize(output, lde.role_offset_words())?;
    hash_usize(output, lde.offset_words())?;
    hash_usize(output, lde.len_words())?;
    Ok(())
}

fn hash_u32(output: &mut blake3::Hasher, value: u32) {
    output.update(&value.to_le_bytes());
}

fn hash_u64(output: &mut blake3::Hasher, value: u64) {
    output.update(&value.to_le_bytes());
}

fn hash_usize(
    output: &mut blake3::Hasher,
    value: usize,
) -> Result<(), QuotientNumeratorPrepackedTermError> {
    let value =
        u64::try_from(value).map_err(|_| QuotientNumeratorPrepackedTermError::SizeOverflow)?;
    output.update(&value.to_le_bytes());
    Ok(())
}

fn hash_bytes(output: &mut blake3::Hasher, value: &[u8]) {
    output.update(&(value.len() as u64).to_le_bytes());
    output.update(value);
}

fn m31_add(lhs: u32, rhs: u32) -> u32 {
    let lhs = normalize(lhs);
    let rhs = normalize(rhs);
    let sum = lhs + rhs;
    let folded = (sum & M31_MODULUS) + (sum >> 31);
    normalize(folded)
}

fn m31_sub(lhs: u32, rhs: u32) -> u32 {
    let lhs = normalize(lhs);
    let rhs = normalize(rhs);
    normalize(if lhs >= rhs {
        lhs - rhs
    } else {
        lhs + M31_MODULUS - rhs
    })
}

fn m31_mul(lhs: u32, rhs: u32) -> u32 {
    let product = u64::from(normalize(lhs)) * u64::from(normalize(rhs));
    (product % u64::from(M31_MODULUS)) as u32
}

fn normalize(value: u32) -> u32 {
    if value == M31_MODULUS {
        0
    } else {
        value
    }
}

#[cfg(test)]
#[path = "quotient_numerator_prepacked_terms_tests.rs"]
mod tests;

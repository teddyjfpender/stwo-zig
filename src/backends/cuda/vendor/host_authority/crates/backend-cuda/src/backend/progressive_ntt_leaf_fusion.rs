//! Pure topology and traffic model for progressive final-NTT-to-leaf fusion.
//!
//! The CUDA path consumes exactly one canonical, globally 16-aligned leaf
//! block. Keeping eligibility here makes preparation auditable and lets host
//! tests prove every descriptor slice and byte claim without a GPU.

use super::progressive_commit::{
    validate_progressive_plan, ProgressiveCommitError, ProgressiveCommitPlan, SameLogLdeBatch,
};

pub const PROGRESSIVE_NTT_LEAF_FUSED_COLUMNS: usize = 16;
pub const PROGRESSIVE_NTT_LEAF_FUSED_MIN_LOG_SIZE: u32 = 13;
const WORD_BYTES: u64 = core::mem::size_of::<u32>() as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressiveNttLeafFusionMode {
    Separate,
    Fused16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProgressiveNttLeafFusionTelemetry {
    pub fused_blocks: u64,
    pub fused_columns: u64,
    pub separate_columns: u64,
    /// Completed evaluation words no longer reread by progressive absorb.
    pub completed_lde_hash_read_bytes_avoided: u64,
    /// Dead final-stage writes omitted for unretained columns.
    pub completed_lde_write_bytes_avoided: u64,
    /// Final-stage writes deliberately preserved for retained columns.
    pub retained_completed_lde_write_bytes: u64,
    pub total_bytes_avoided: u64,
}

impl ProgressiveNttLeafFusionTelemetry {
    pub(crate) fn checked_add(self, rhs: Self) -> Result<Self, ProgressiveCommitError> {
        macro_rules! add {
            ($field:ident) => {
                self.$field
                    .checked_add(rhs.$field)
                    .ok_or(ProgressiveCommitError::SizeOverflow)?
            };
        }
        Ok(Self {
            fused_blocks: add!(fused_blocks),
            fused_columns: add!(fused_columns),
            separate_columns: add!(separate_columns),
            completed_lde_hash_read_bytes_avoided: add!(completed_lde_hash_read_bytes_avoided),
            completed_lde_write_bytes_avoided: add!(completed_lde_write_bytes_avoided),
            retained_completed_lde_write_bytes: add!(retained_completed_lde_write_bytes),
            total_bytes_avoided: add!(total_bytes_avoided),
        })
    }
}

/// Exact, GPU-free traffic forecast for a sealed progressive commitment plan.
/// This is the report/preflight entry point; preparation derives the same
/// totals while constructing its descriptor slices.
pub fn progressive_ntt_leaf_fusion_telemetry(
    plan: &ProgressiveCommitPlan,
    mode: ProgressiveNttLeafFusionMode,
) -> Result<ProgressiveNttLeafFusionTelemetry, ProgressiveCommitError> {
    validate_progressive_plan(plan)?;
    plan.lde_batches.iter().try_fold(
        ProgressiveNttLeafFusionTelemetry::default(),
        |total, batch| {
            let (_, batch_telemetry) = progressive_lde_segments(batch, mode)?;
            total.checked_add(batch_telemetry)
        },
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProgressiveLdeSegmentKind {
    Separate,
    Fused16 { retained_write_mask: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProgressiveLdeSegment {
    pub offset: usize,
    pub columns: usize,
    pub kind: ProgressiveLdeSegmentKind,
}

/// Split one already-canonical same-log descriptor table. Ineligible ranges
/// remain coalesced into the old two-launch path; eligible blocks never cross
/// a log boundary or a canonical 16-column leaf boundary.
pub(crate) fn progressive_lde_segments(
    batch: &SameLogLdeBatch,
    mode: ProgressiveNttLeafFusionMode,
) -> Result<
    (
        Vec<ProgressiveLdeSegment>,
        ProgressiveNttLeafFusionTelemetry,
    ),
    ProgressiveCommitError,
> {
    validate_batch(batch)?;
    if mode == ProgressiveNttLeafFusionMode::Separate {
        return Ok((
            vec![ProgressiveLdeSegment {
                offset: 0,
                columns: batch.columns.len(),
                kind: ProgressiveLdeSegmentKind::Separate,
            }],
            ProgressiveNttLeafFusionTelemetry {
                separate_columns: batch.columns.len() as u64,
                ..Default::default()
            },
        ));
    }

    let mut segments = Vec::new();
    let mut telemetry = ProgressiveNttLeafFusionTelemetry::default();
    let mut offset = 0usize;
    while offset < batch.columns.len() {
        if fused_at(batch, offset) {
            let retained_write_mask = batch.retained_columns
                [offset..offset + PROGRESSIVE_NTT_LEAF_FUSED_COLUMNS]
                .iter()
                .enumerate()
                .fold(0u32, |mask, (bit, output)| {
                    mask | (u32::from(output.is_some()) << bit)
                });
            segments.push(ProgressiveLdeSegment {
                offset,
                columns: PROGRESSIVE_NTT_LEAF_FUSED_COLUMNS,
                kind: ProgressiveLdeSegmentKind::Fused16 {
                    retained_write_mask,
                },
            });
            telemetry = telemetry.checked_add(fused_traffic(
                batch.evaluation_log_size,
                retained_write_mask,
            )?)?;
            offset += PROGRESSIVE_NTT_LEAF_FUSED_COLUMNS;
            continue;
        }

        let start = offset;
        offset += 1;
        while offset < batch.columns.len() && !fused_at(batch, offset) {
            offset += 1;
        }
        let columns = offset - start;
        segments.push(ProgressiveLdeSegment {
            offset: start,
            columns,
            kind: ProgressiveLdeSegmentKind::Separate,
        });
        telemetry.separate_columns = telemetry
            .separate_columns
            .checked_add(columns as u64)
            .ok_or(ProgressiveCommitError::SizeOverflow)?;
    }
    Ok((segments, telemetry))
}

fn validate_batch(batch: &SameLogLdeBatch) -> Result<(), ProgressiveCommitError> {
    if batch.columns.is_empty()
        || batch.columns.len() != batch.retained_columns.len()
        || batch
            .columns
            .windows(2)
            .any(|pair| pair[0].checked_add(1) != Some(pair[1]))
    {
        return Err(ProgressiveCommitError::InvalidLdeBatchPlan);
    }
    Ok(())
}

fn fused_at(batch: &SameLogLdeBatch, offset: usize) -> bool {
    batch.evaluation_log_size >= PROGRESSIVE_NTT_LEAF_FUSED_MIN_LOG_SIZE
        && batch.evaluation_log_size <= 30
        && offset + PROGRESSIVE_NTT_LEAF_FUSED_COLUMNS <= batch.columns.len()
        && batch.columns[offset] % PROGRESSIVE_NTT_LEAF_FUSED_COLUMNS == 0
        && batch.columns[offset..offset + PROGRESSIVE_NTT_LEAF_FUSED_COLUMNS]
            .iter()
            .enumerate()
            .all(|(local, &canonical)| canonical == batch.columns[offset] + local)
}

fn fused_traffic(
    log_size: u32,
    retained_write_mask: u32,
) -> Result<ProgressiveNttLeafFusionTelemetry, ProgressiveCommitError> {
    let rows = 1u64
        .checked_shl(log_size)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let retained = u64::from(retained_write_mask.count_ones());
    let unretained = PROGRESSIVE_NTT_LEAF_FUSED_COLUMNS as u64 - retained;
    let hash_read = rows
        .checked_mul(PROGRESSIVE_NTT_LEAF_FUSED_COLUMNS as u64 * WORD_BYTES)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let write_avoided = rows
        .checked_mul(unretained * WORD_BYTES)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    let retained_write = rows
        .checked_mul(retained * WORD_BYTES)
        .ok_or(ProgressiveCommitError::SizeOverflow)?;
    Ok(ProgressiveNttLeafFusionTelemetry {
        fused_blocks: 1,
        fused_columns: PROGRESSIVE_NTT_LEAF_FUSED_COLUMNS as u64,
        separate_columns: 0,
        completed_lde_hash_read_bytes_avoided: hash_read,
        completed_lde_write_bytes_avoided: write_avoided,
        retained_completed_lde_write_bytes: retained_write,
        total_bytes_avoided: hash_read
            .checked_add(write_avoided)
            .ok_or(ProgressiveCommitError::SizeOverflow)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::progressive_commit::{
        plan_progressive_commit, ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
        ProgressiveCommitMode,
    };

    fn batch(first: usize, columns: usize, log_size: u32, retained: &[usize]) -> SameLogLdeBatch {
        SameLogLdeBatch {
            evaluation_log_size: log_size,
            columns: (first..first + columns).collect(),
            retained_columns: (0..columns)
                .map(|column| retained.contains(&column).then_some((0, column)))
                .collect(),
            output_words: columns << log_size,
        }
    }

    #[test]
    fn aligned_blocks_fuse_and_tail_stays_coalesced() {
        let (segments, telemetry) = progressive_lde_segments(
            &batch(0, 40, 13, &(0..40).collect::<Vec<_>>()),
            ProgressiveNttLeafFusionMode::Fused16,
        )
        .unwrap();
        assert_eq!(
            segments,
            vec![
                ProgressiveLdeSegment {
                    offset: 0,
                    columns: 16,
                    kind: ProgressiveLdeSegmentKind::Fused16 {
                        retained_write_mask: 0xffff
                    },
                },
                ProgressiveLdeSegment {
                    offset: 16,
                    columns: 16,
                    kind: ProgressiveLdeSegmentKind::Fused16 {
                        retained_write_mask: 0xffff
                    },
                },
                ProgressiveLdeSegment {
                    offset: 32,
                    columns: 8,
                    kind: ProgressiveLdeSegmentKind::Separate,
                },
            ]
        );
        assert_eq!(telemetry.fused_blocks, 2);
        assert_eq!(telemetry.separate_columns, 8);
        assert_eq!(telemetry.completed_lde_hash_read_bytes_avoided, 1 << 20);
        assert_eq!(telemetry.completed_lde_write_bytes_avoided, 0);
        assert_eq!(telemetry.retained_completed_lde_write_bytes, 1 << 20);
    }

    #[test]
    fn unaligned_prefix_stops_at_the_next_global_leaf_boundary() {
        let (segments, _) = progressive_lde_segments(
            &batch(1, 31, 13, &[]),
            ProgressiveNttLeafFusionMode::Fused16,
        )
        .unwrap();
        assert_eq!(segments[0].offset, 0);
        assert_eq!(segments[0].columns, 15);
        assert_eq!(segments[1].offset, 15);
        assert_eq!(segments[1].columns, 16);
        assert_eq!(
            segments[1].kind,
            ProgressiveLdeSegmentKind::Fused16 {
                retained_write_mask: 0
            }
        );
    }

    #[test]
    fn mixed_retention_mask_and_traffic_are_exact() {
        let (segments, telemetry) = progressive_lde_segments(
            &batch(16, 16, 13, &[0, 3, 15]),
            ProgressiveNttLeafFusionMode::Fused16,
        )
        .unwrap();
        assert_eq!(
            segments[0].kind,
            ProgressiveLdeSegmentKind::Fused16 {
                retained_write_mask: 0x8009
            }
        );
        assert_eq!(telemetry.completed_lde_hash_read_bytes_avoided, 1 << 19);
        assert_eq!(telemetry.completed_lde_write_bytes_avoided, 13 * (1 << 15));
        assert_eq!(telemetry.retained_completed_lde_write_bytes, 3 * (1 << 15));
        assert_eq!(telemetry.total_bytes_avoided, (1 << 19) + 13 * (1 << 15));
    }

    #[test]
    fn disabled_or_small_log_shapes_remain_one_separate_segment() {
        for (mode, log_size) in [
            (ProgressiveNttLeafFusionMode::Separate, 13),
            (ProgressiveNttLeafFusionMode::Fused16, 12),
        ] {
            let (segments, telemetry) =
                progressive_lde_segments(&batch(0, 32, log_size, &[]), mode).unwrap();
            assert_eq!(segments.len(), 1);
            assert_eq!(segments[0].columns, 32);
            assert_eq!(segments[0].kind, ProgressiveLdeSegmentKind::Separate);
            assert_eq!(telemetry.fused_blocks, 0);
            assert_eq!(telemetry.separate_columns, 32);
        }
    }

    #[test]
    fn public_plan_forecast_revalidates_the_plan_and_matches_batch_totals() {
        let plan = plan_progressive_commit(
            ProgressiveCommitMode::DomainProgressive,
            ProgressiveCommitGeometry {
                lifting_log_size: 13,
                log_blowup_factor: 1,
                groups: vec![ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![12; 32],
                    retain_evaluations: true,
                }],
            },
        )
        .unwrap();
        let telemetry =
            progressive_ntt_leaf_fusion_telemetry(&plan, ProgressiveNttLeafFusionMode::Fused16)
                .unwrap();
        assert_eq!(telemetry.fused_blocks, 2);
        assert_eq!(telemetry.completed_lde_hash_read_bytes_avoided, 1 << 20);

        let mut malformed = plan;
        malformed.lde_batches[0].columns.swap(0, 1);
        assert_eq!(
            progressive_ntt_leaf_fusion_telemetry(
                &malformed,
                ProgressiveNttLeafFusionMode::Fused16
            ),
            Err(ProgressiveCommitError::InvalidLdeBatchPlan)
        );
    }
}

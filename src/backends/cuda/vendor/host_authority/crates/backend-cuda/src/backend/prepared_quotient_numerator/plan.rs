//! Address-free quotient-numerator topology and workspace compilation.

use super::*;

#[derive(Clone)]
pub(super) struct PlannedTerm {
    pub(super) sample_index: u32,
    pub(super) exponent: u32,
    pub(super) period: Option<CirclePoint<BaseField>>,
    pub(super) shape_point: CirclePoint<SecureField>,
    pub(super) column: usize,
    pub(super) group: usize,
}

pub(in crate::backend) struct PlannedBatch {
    pub(in crate::backend) evaluation_log_size: u32,
    pub(in crate::backend) columns: Vec<usize>,
    pub(in crate::backend) coefficient_columns: Vec<usize>,
    pub(in crate::backend) group_offsets: Vec<u32>,
    pub(in crate::backend) terms: Vec<u32>,
    lde_words: usize,
}

pub(in crate::backend) struct NumeratorPlan {
    pub(in crate::backend) requirements: QuotientNumeratorWorkspaceRequirements,
    pub(super) terms: Vec<PlannedTerm>,
    pub(super) group_term_indices: Vec<u32>,
    pub(in crate::backend) group_offsets: Vec<u32>,
    pub(in crate::backend) batches: Vec<PlannedBatch>,
}

pub fn quotient_numerator_workspace_requirements(
    config: QuotientNumeratorWorkspaceConfig,
    columns: &[QuotientNumeratorColumnTopology],
) -> Result<QuotientNumeratorWorkspaceRequirements, PreparedQuotientNumeratorError> {
    Ok(build_plan(config, columns)?.requirements)
}

impl QuotientNumeratorWorkspaceRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &QuotientNumeratorWorkspaceSlots,
    ) -> Result<Vec<QuotientNumeratorArenaSlotRequirement>, PreparedQuotientNumeratorError> {
        let mut requirements = vec![
            slot(slots.runtime_terms, self.runtime_term_words, 1),
            slot(slots.group_term_indices, self.group_term_index_words, 1),
            slot(slots.group_offsets, self.group_offset_words, 1),
            slot(slots.line_coefficients, self.line_coefficient_words, 1),
            slot(slots.term_points, self.term_point_words, 1),
            slot(slots.batch_terms, self.batch_term_words, 1),
            slot(slots.batch_group_offsets, self.batch_group_offset_words, 2),
            slot(
                slots.batch_source_ptrs,
                self.batch_source_pointer_words,
                QUOTIENT_NUMERATOR_POINTER_ALIGNMENT_WORDS,
            ),
            slot(
                slots.output_ptrs,
                self.output_pointer_words,
                QUOTIENT_NUMERATOR_POINTER_ALIGNMENT_WORDS,
            ),
            slot(slots.output_log_sizes, self.output_log_size_words, 1),
        ];
        let coefficient_slots = [
            slots.coefficient_ptrs,
            slots.coefficient_sizes,
            slots.coefficient_output_ptrs,
            slots.lde_tile,
        ];
        if self.coefficient_size_words == 0 {
            if coefficient_slots.iter().any(Option::is_some) {
                return Err(PreparedQuotientNumeratorError::OptionalSlotShapeMismatch);
            }
        } else {
            let [Some(coefficient_ptrs), Some(coefficient_sizes), Some(coefficient_output_ptrs), Some(lde_tile)] =
                coefficient_slots
            else {
                return Err(PreparedQuotientNumeratorError::OptionalSlotShapeMismatch);
            };
            requirements.extend([
                slot(
                    coefficient_ptrs,
                    self.coefficient_pointer_words,
                    QUOTIENT_NUMERATOR_POINTER_ALIGNMENT_WORDS,
                ),
                slot(coefficient_sizes, self.coefficient_size_words, 1),
                slot(
                    coefficient_output_ptrs,
                    self.coefficient_output_pointer_words,
                    QUOTIENT_NUMERATOR_POINTER_ALIGNMENT_WORDS,
                ),
                slot(lde_tile, self.lde_tile_words, 1),
            ]);
        }
        let mut seen = BTreeSet::new();
        for requirement in &requirements {
            if !seen.insert(requirement.id) {
                return Err(PreparedQuotientNumeratorError::DuplicateSlot(
                    requirement.id,
                ));
            }
        }
        Ok(requirements)
    }
}

fn slot(
    id: ArenaSlotId,
    len_words: usize,
    alignment_words: usize,
) -> QuotientNumeratorArenaSlotRequirement {
    QuotientNumeratorArenaSlotRequirement {
        id,
        len_words,
        alignment_words,
    }
}

pub(in crate::backend) fn build_plan(
    config: QuotientNumeratorWorkspaceConfig,
    columns: &[QuotientNumeratorColumnTopology],
) -> Result<NumeratorPlan, PreparedQuotientNumeratorError> {
    if !(2..=30).contains(&config.lifting_log_size) {
        return Err(PreparedQuotientNumeratorError::InvalidLiftingLogSize(
            config.lifting_log_size,
        ));
    }
    if config.log_blowup_factor == 0 || config.log_blowup_factor >= config.lifting_log_size {
        return Err(PreparedQuotientNumeratorError::InvalidBlowup {
            lifting_log_size: config.lifting_log_size,
            log_blowup_factor: config.log_blowup_factor,
        });
    }
    let max_coefficient_log = config.lifting_log_size - config.log_blowup_factor;
    let lifting_step = CanonicCoset::new(config.lifting_log_size).step();
    let mut terms = Vec::new();
    let mut column_terms = vec![Vec::new(); columns.len()];
    let mut next_exponent = 0usize;
    let mut max_input_index = 0usize;

    for (column_index, column) in columns.iter().enumerate() {
        if !column.samples.is_empty() && column.coefficient_log_size > max_coefficient_log {
            return Err(PreparedQuotientNumeratorError::ColumnLogTooLarge {
                column: column_index,
                log_size: column.coefficient_log_size,
                maximum: max_coefficient_log,
            });
        }
        let evaluation_log_size = column
            .coefficient_log_size
            .checked_add(config.log_blowup_factor)
            .ok_or(PreparedQuotientNumeratorError::SizeOverflow)?;
        let mut append = |sample: QuotientOodsSample,
                          period: Option<CirclePoint<BaseField>>|
         -> Result<(), PreparedQuotientNumeratorError> {
            let exponent = u32::try_from(next_exponent).map_err(|_| {
                PreparedQuotientNumeratorError::TooManyTerms(next_exponent.saturating_add(1))
            })?;
            let shape_point = match period {
                Some(period) => sample.shape_point + period.into_ef(),
                None => sample.shape_point,
            };
            let term_index = terms.len();
            terms.push(PlannedTerm {
                sample_index: sample.input_index,
                exponent,
                period,
                shape_point,
                column: column_index,
                group: 0,
            });
            column_terms[column_index].push(term_index);
            next_exponent = next_exponent
                .checked_add(1)
                .ok_or(PreparedQuotientNumeratorError::SizeOverflow)?;
            max_input_index = max_input_index.max(sample.input_index as usize);
            Ok(())
        };

        if let [_, second] = column.samples.as_slice() {
            append(
                *second,
                Some(lifting_step.repeated_double(evaluation_log_size)),
            )?;
        }
        for &sample in &column.samples {
            append(sample, None)?;
        }
    }
    if terms.is_empty() {
        return Err(PreparedQuotientNumeratorError::EmptyTerms);
    }

    let mut point_logs = BTreeMap::<(SecureField, SecureField), u32>::new();
    for term in &terms {
        let log = columns[term.column].coefficient_log_size;
        point_logs
            .entry((term.shape_point.x, term.shape_point.y))
            .and_modify(|current| *current = (*current).max(log))
            .or_insert(log);
    }
    if point_logs.len() > u16::MAX as usize {
        return Err(PreparedQuotientNumeratorError::TooManyGroups(
            point_logs.len(),
        ));
    }
    let group_indices: BTreeMap<_, _> = point_logs
        .keys()
        .copied()
        .enumerate()
        .map(|(index, point)| (point, index))
        .collect();
    for term in &mut terms {
        term.group = group_indices[&(term.shape_point.x, term.shape_point.y)];
    }
    let mut coefficient_sources_by_group = vec![BTreeSet::new(); point_logs.len()];
    for term in &terms {
        if columns[term.column].source_kind == QuotientNumeratorSourceKind::Coefficients {
            coefficient_sources_by_group[term.group].insert(term.column);
        }
    }
    let groups = point_logs
        .iter()
        .enumerate()
        .map(|(group, (&(x, y), &log_size))| {
            Ok(QuotientNumeratorGroupRequirements {
                shape_point: CirclePoint { x, y },
                log_size,
                value_words: pow2(log_size)?,
                coefficient_source_count: coefficient_sources_by_group[group].len(),
            })
        })
        .collect::<Result<Vec<_>, PreparedQuotientNumeratorError>>()?;

    let mut grouped_terms: Vec<_> = (0..terms.len()).collect();
    grouped_terms.sort_by_key(|&term| terms[term].group);
    let group_term_indices = grouped_terms
        .iter()
        .map(|&term| {
            u32::try_from(term)
                .map_err(|_| PreparedQuotientNumeratorError::TooManyTerms(terms.len()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let group_offsets = offsets_by_group(&grouped_terms, groups.len(), |&term| terms[term].group)?;

    let mut sorted_columns: Vec<_> = columns
        .iter()
        .enumerate()
        .filter(|(index, _)| !column_terms[*index].is_empty())
        .map(|(index, column)| {
            (
                column.coefficient_log_size + config.log_blowup_factor,
                index,
            )
        })
        .collect();
    sorted_columns.sort_by_key(|&(log, index)| (log, index));

    let mut column_batches = Vec::<Vec<usize>>::new();
    let mut current = Vec::new();
    let mut current_log = None;
    let mut current_tile_words = 0usize;
    for (evaluation_log_size, column_index) in sorted_columns {
        let cost = if columns[column_index].source_kind == QuotientNumeratorSourceKind::Coefficients
        {
            pow2(evaluation_log_size)?
        } else {
            0
        };
        if cost > config.max_lde_tile_words {
            return Err(PreparedQuotientNumeratorError::TileTooSmall {
                column: column_index,
                required_words: cost,
                available_words: config.max_lde_tile_words,
            });
        }
        let log_changed = current_log.is_some_and(|log| log != evaluation_log_size);
        let tile_full = !current.is_empty()
            && current_tile_words
                .checked_add(cost)
                .ok_or(PreparedQuotientNumeratorError::SizeOverflow)?
                > config.max_lde_tile_words;
        if log_changed || tile_full {
            column_batches.push(core::mem::take(&mut current));
            current_tile_words = 0;
        }
        current_log = Some(evaluation_log_size);
        current_tile_words = current_tile_words
            .checked_add(cost)
            .ok_or(PreparedQuotientNumeratorError::SizeOverflow)?;
        current.push(column_index);
    }
    if !current.is_empty() {
        column_batches.push(current);
    }

    let mut batches = Vec::with_capacity(column_batches.len());
    for batch_columns in column_batches {
        let evaluation_log_size =
            columns[batch_columns[0]].coefficient_log_size + config.log_blowup_factor;
        let coefficient_columns: Vec<_> = batch_columns
            .iter()
            .copied()
            .filter(|&column| {
                columns[column].source_kind == QuotientNumeratorSourceKind::Coefficients
            })
            .collect();
        let eval_words = pow2(evaluation_log_size)?;
        let lde_words = eval_words
            .checked_mul(coefficient_columns.len())
            .ok_or(PreparedQuotientNumeratorError::SizeOverflow)?;
        let source_local: BTreeMap<_, _> = batch_columns
            .iter()
            .copied()
            .enumerate()
            .map(|(local, column)| (column, local))
            .collect();
        let mut batch_terms = batch_columns
            .iter()
            .flat_map(|column| column_terms[*column].iter().copied())
            .collect::<Vec<_>>();
        batch_terms.sort_by_key(|&term| terms[term].group);
        let batch_offsets =
            offsets_by_group(&batch_terms, groups.len(), |&term| terms[term].group)?;
        let mut descriptors = Vec::with_capacity(batch_terms.len() * BATCH_TERM_WORDS);
        for term in batch_terms {
            descriptors.extend([
                u32::try_from(source_local[&terms[term].column])
                    .map_err(|_| PreparedQuotientNumeratorError::SizeOverflow)?,
                u32::try_from(term)
                    .map_err(|_| PreparedQuotientNumeratorError::TooManyTerms(terms.len()))?,
                columns[terms[term].column].coefficient_log_size,
            ]);
        }
        batches.push(PlannedBatch {
            evaluation_log_size,
            columns: batch_columns,
            coefficient_columns,
            group_offsets: batch_offsets,
            terms: descriptors,
            lde_words,
        });
    }

    let batch_requirements = batches
        .iter()
        .map(|batch| QuotientNumeratorBatchRequirements {
            evaluation_log_size: batch.evaluation_log_size,
            source_count: batch.columns.len(),
            coefficient_count: batch.coefficient_columns.len(),
            term_count: batch.terms.len() / BATCH_TERM_WORDS,
            lde_words: batch.lde_words,
        })
        .collect::<Vec<_>>();
    let coefficient_count = batches
        .iter()
        .map(|batch| batch.coefficient_columns.len())
        .sum::<usize>();
    let max_coefficient_eval_log = batches
        .iter()
        .filter(|batch| !batch.coefficient_columns.is_empty())
        .map(|batch| batch.evaluation_log_size)
        .max();
    let requirements = QuotientNumeratorWorkspaceRequirements {
        config,
        input_sample_count: max_input_index + 1,
        term_count: terms.len(),
        groups,
        batches: batch_requirements,
        runtime_term_words: checked_mul(terms.len(), RUNTIME_TERM_WORDS)?,
        group_term_index_words: terms.len(),
        group_offset_words: point_logs.len() + 1,
        line_coefficient_words: checked_mul(terms.len(), LINE_COEFFICIENT_WORDS)?,
        term_point_words: checked_mul(terms.len(), SECURE_POINT_WORDS)?,
        batch_term_words: checked_mul(terms.len(), BATCH_TERM_WORDS)?,
        batch_group_offset_words: checked_mul(batches.len(), point_logs.len() + 1)?
            .max(checked_mul(point_logs.len() + 1, 2)?),
        batch_source_pointer_words: checked_mul(
            batches.iter().map(|batch| batch.columns.len()).sum(),
            POINTER_WORDS,
        )?,
        coefficient_pointer_words: checked_mul(coefficient_count, POINTER_WORDS)?,
        coefficient_size_words: coefficient_count,
        coefficient_output_pointer_words: checked_mul(coefficient_count, POINTER_WORDS)?,
        output_pointer_words: checked_mul(point_logs.len() * 4, POINTER_WORDS)?,
        output_log_size_words: point_logs.len(),
        lde_tile_words: batches
            .iter()
            .map(|batch| batch.lde_words)
            .max()
            .unwrap_or(0),
        forward_twiddle_words: match max_coefficient_eval_log {
            Some(log) => pow2(log - 1)?,
            None => 0,
        },
        max_output_size: pow2(
            point_logs
                .values()
                .copied()
                .max()
                .ok_or(PreparedQuotientNumeratorError::EmptyTerms)?,
        )?,
    };
    Ok(NumeratorPlan {
        requirements,
        terms,
        group_term_indices,
        group_offsets,
        batches,
    })
}

fn offsets_by_group<T>(
    sorted: &[T],
    group_count: usize,
    group: impl Fn(&T) -> usize,
) -> Result<Vec<u32>, PreparedQuotientNumeratorError> {
    let mut offsets = Vec::with_capacity(group_count + 1);
    let mut cursor = 0usize;
    for target in 0..group_count {
        offsets.push(
            u32::try_from(cursor)
                .map_err(|_| PreparedQuotientNumeratorError::TooManyTerms(sorted.len()))?,
        );
        while cursor < sorted.len() && group(&sorted[cursor]) == target {
            cursor += 1;
        }
    }
    offsets.push(
        u32::try_from(cursor)
            .map_err(|_| PreparedQuotientNumeratorError::TooManyTerms(sorted.len()))?,
    );
    Ok(offsets)
}

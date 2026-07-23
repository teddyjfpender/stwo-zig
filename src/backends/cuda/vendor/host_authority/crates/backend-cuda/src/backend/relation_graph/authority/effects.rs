use super::*;

pub(super) fn fused_accesses(
    program: &RelationKernelProgram,
    requirements: &RelationGraphRequirements,
    instances: &[RelationExecutionInstance],
) -> Result<Vec<RelationAccess>, RelationExecutionAuthorityError> {
    let mut accesses = metadata_accesses(
        requirements,
        &[
            RelationPointerTableKind::Sources,
            RelationPointerTableKind::Descriptors,
            RelationPointerTableKind::Outputs,
        ],
    );
    accesses.extend([
        whole(
            RelationValueRole::AlphaPowers,
            RelationAccessKind::Read,
            requirements.alpha_words,
        ),
        whole(
            RelationValueRole::ChallengeZ,
            RelationAccessKind::Read,
            requirements.z_words,
        ),
    ]);
    for instance in instances {
        let key = (instance.batch_index, instance.instance_index);
        accesses.push(whole(
            RelationValueRole::InstanceSourcePointers {
                batch: key.0,
                instance: key.1,
            },
            RelationAccessKind::Read,
            usize::try_from(instance.source_pointer_count)
                .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?
                .checked_mul(POINTER_WORDS)
                .ok_or(RelationExecutionAuthorityError::SizeOverflow)?,
        ));
        accesses.push(whole(
            RelationValueRole::InstanceOutputPointers {
                batch: key.0,
                instance: key.1,
            },
            RelationAccessKind::Read,
            usize::try_from(instance.output_coordinate_count)
                .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?
                .checked_mul(POINTER_WORDS)
                .ok_or(RelationExecutionAuthorityError::SizeOverflow)?,
        ));
        let descriptor_words = usize::try_from(instance.columns)
            .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?
            .checked_mul(DESCRIPTOR_WORDS)
            .ok_or(RelationExecutionAuthorityError::SizeOverflow)?;
        accesses.push(RelationAccess {
            role: RelationValueRole::Descriptors,
            kind: RelationAccessKind::Read,
            start_word: instance.descriptor_word_offset as usize,
            words: descriptor_words,
        });
        for (source, words) in relation_source_word_extents(
            program.batches[instance.batch_index as usize].source_layout,
            instance.padded_rows,
        )?
        .into_iter()
        .enumerate()
        {
            accesses.push(whole(
                RelationValueRole::InstanceSource {
                    batch: key.0,
                    instance: key.1,
                    source: source as u32,
                },
                RelationAccessKind::Read,
                words,
            ));
        }
        for coordinate in 0..instance.output_coordinate_count {
            accesses.push(whole(
                RelationValueRole::OutputCoordinate {
                    batch: key.0,
                    instance: key.1,
                    coordinate,
                },
                RelationAccessKind::Write,
                instance.padded_rows as usize,
            ));
        }
    }
    Ok(accesses)
}

pub(super) fn reduce_accesses(
    requirements: &RelationGraphRequirements,
    instances: &[RelationExecutionInstance],
) -> Vec<RelationAccess> {
    let mut accesses = tail_metadata_accesses(requirements, instances, false);
    accesses.extend(last_coordinate_accesses(
        instances,
        RelationAccessKind::Read,
    ));
    accesses.push(whole(
        RelationValueRole::ReductionPartials,
        RelationAccessKind::Write,
        requirements.reduction_words,
    ));
    accesses
}

pub(super) fn finalize_accesses(
    requirements: &RelationGraphRequirements,
    instances: &[RelationExecutionInstance],
) -> Vec<RelationAccess> {
    let mut accesses = metadata_accesses(requirements, &[RelationPointerTableKind::ClaimedSums]);
    accesses.push(whole(
        RelationValueRole::ReductionPartials,
        RelationAccessKind::Read,
        requirements.reduction_words,
    ));
    accesses.extend(instances.iter().map(|instance| {
        whole(
            RelationValueRole::ClaimedSum {
                batch: instance.batch_index,
                instance: instance.instance_index,
            },
            RelationAccessKind::Write,
            SECURE_FIELD_WORDS,
        )
    }));
    accesses
}

pub(super) fn shift_accesses(
    requirements: &RelationGraphRequirements,
    instances: &[RelationExecutionInstance],
) -> Vec<RelationAccess> {
    let mut accesses = tail_metadata_accesses(requirements, instances, true);
    accesses.extend(instances.iter().map(|instance| {
        whole(
            RelationValueRole::ClaimedSum {
                batch: instance.batch_index,
                instance: instance.instance_index,
            },
            RelationAccessKind::Read,
            SECURE_FIELD_WORDS,
        )
    }));
    accesses.extend(last_coordinate_accesses(
        instances,
        RelationAccessKind::ReadWrite,
    ));
    accesses.push(whole(
        RelationValueRole::ScanBlockSums,
        RelationAccessKind::Write,
        requirements.reduction_words,
    ));
    accesses
}

pub(super) fn scan_accesses(requirements: &RelationGraphRequirements) -> Vec<RelationAccess> {
    vec![
        whole(
            RelationValueRole::Geometry,
            RelationAccessKind::Read,
            requirements.fraction_geometry_words,
        ),
        whole(
            RelationValueRole::ScanBlockSums,
            RelationAccessKind::ReadWrite,
            requirements.reduction_words,
        ),
    ]
}

pub(super) fn add_offset_accesses(
    requirements: &RelationGraphRequirements,
    instances: &[RelationExecutionInstance],
) -> Vec<RelationAccess> {
    let mut accesses = tail_metadata_accesses(requirements, instances, false);
    accesses.push(whole(
        RelationValueRole::ScanBlockSums,
        RelationAccessKind::Read,
        requirements.reduction_words,
    ));
    accesses.extend(last_coordinate_accesses(
        instances,
        RelationAccessKind::ReadWrite,
    ));
    accesses
}

fn metadata_accesses(
    requirements: &RelationGraphRequirements,
    tables: &[RelationPointerTableKind],
) -> Vec<RelationAccess> {
    let table_words = requirements.instances.len() * POINTER_WORDS;
    let mut output = tables
        .iter()
        .map(|&table| {
            whole(
                RelationValueRole::DispatchPointers(table),
                RelationAccessKind::Read,
                table_words,
            )
        })
        .collect::<Vec<_>>();
    output.push(whole(
        RelationValueRole::Geometry,
        RelationAccessKind::Read,
        requirements.fraction_geometry_words,
    ));
    output
}

fn tail_metadata_accesses(
    requirements: &RelationGraphRequirements,
    instances: &[RelationExecutionInstance],
    claimed: bool,
) -> Vec<RelationAccess> {
    let mut tables = vec![RelationPointerTableKind::Outputs];
    if claimed {
        tables.push(RelationPointerTableKind::ClaimedSums);
    }
    let mut output = metadata_accesses(requirements, &tables);
    output.extend(instances.iter().map(|instance| RelationAccess {
        role: RelationValueRole::InstanceOutputPointers {
            batch: instance.batch_index,
            instance: instance.instance_index,
        },
        kind: RelationAccessKind::Read,
        start_word: (instance.output_coordinate_count as usize - SECURE_FIELD_WORDS)
            * POINTER_WORDS,
        words: SECURE_FIELD_WORDS * POINTER_WORDS,
    }));
    output
}

fn last_coordinate_accesses(
    instances: &[RelationExecutionInstance],
    kind: RelationAccessKind,
) -> Vec<RelationAccess> {
    let mut output = Vec::with_capacity(instances.len() * SECURE_FIELD_WORDS);
    for instance in instances {
        for coordinate in instance.output_coordinate_count - SECURE_FIELD_WORDS as u32
            ..instance.output_coordinate_count
        {
            output.push(whole(
                RelationValueRole::OutputCoordinate {
                    batch: instance.batch_index,
                    instance: instance.instance_index,
                    coordinate,
                },
                kind,
                instance.padded_rows as usize,
            ));
        }
    }
    output
}

const fn whole(role: RelationValueRole, kind: RelationAccessKind, words: usize) -> RelationAccess {
    RelationAccess {
        role,
        kind,
        start_word: 0,
        words,
    }
}

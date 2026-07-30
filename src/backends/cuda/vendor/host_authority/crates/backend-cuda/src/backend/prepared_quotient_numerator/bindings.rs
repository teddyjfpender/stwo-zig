//! Setup-only descriptor uploads and checked arena binding helpers.

use super::*;

pub(super) enum HostDescriptor {
    U32(Vec<u32>),
    U64(Vec<u64>),
    Pointers(Vec<usize>),
}

impl HostDescriptor {
    fn bytes(&self) -> (*const c_void, usize) {
        match self {
            Self::U32(values) => (values.as_ptr().cast(), values.len() * WORD_BYTES),
            Self::U64(values) => (
                values.as_ptr().cast(),
                values.len() * core::mem::size_of::<u64>(),
            ),
            Self::Pointers(values) => (
                values.as_ptr().cast(),
                values.len() * core::mem::size_of::<usize>(),
            ),
        }
    }
}

pub(super) struct PendingUpload {
    destination: ArenaSlice,
    descriptor: HostDescriptor,
}

pub(super) fn upload_u32(destination: ArenaSlice, values: Vec<u32>) -> PendingUpload {
    PendingUpload {
        destination,
        descriptor: HostDescriptor::U32(values),
    }
}

pub(super) fn upload_u64(destination: ArenaSlice, values: Vec<u64>) -> PendingUpload {
    PendingUpload {
        destination,
        descriptor: HostDescriptor::U64(values),
    }
}

pub(super) fn upload_ptrs(destination: ArenaSlice, values: Vec<usize>) -> PendingUpload {
    PendingUpload {
        destination,
        descriptor: HostDescriptor::Pointers(values),
    }
}

pub(super) fn upload_and_sync(
    arena: &DeviceArena,
    uploads: &[PendingUpload],
) -> Result<(), PreparedQuotientNumeratorError> {
    for upload in uploads {
        let (source, bytes) = upload.descriptor.bytes();
        unsafe {
            arena
                .context()
                .memcpy_h2d_async(upload.destination.as_void_ptr(), source, bytes)?;
        }
    }
    arena.context().sync()?;
    Ok(())
}

pub(super) fn bind_optional(
    arena: &DeviceArena,
    id: Option<ArenaSlotId>,
    required_words: usize,
    alignment_words: usize,
) -> Result<Option<ArenaSlice>, PreparedQuotientNumeratorError> {
    match (id, required_words) {
        (Some(id), words) if words != 0 => Ok(Some(bind_slot(arena, id, words, alignment_words)?)),
        (None, 0) => Ok(None),
        _ => Err(PreparedQuotientNumeratorError::OptionalSlotShapeMismatch),
    }
}

pub(super) fn bind_slot(
    arena: &DeviceArena,
    id: ArenaSlotId,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, PreparedQuotientNumeratorError> {
    let slice = arena.bind(id)?;
    if slice.len_words() < required_words {
        return Err(PreparedQuotientNumeratorError::SlotTooSmall {
            slot: id,
            required_words,
            actual_words: slice.len_words(),
        });
    }
    if (slice.as_u32_ptr() as usize) % (alignment_words * WORD_BYTES) != 0 {
        return Err(PreparedQuotientNumeratorError::MisalignedSlot {
            slot: id,
            alignment_words,
        });
    }
    // Pooled slots may be larger than any single logical buffer; expose only
    // the logical extent so no consumer derives sizes from the pooled surplus.
    Ok(slice.truncated(required_words))
}

pub(super) fn require_words(
    slice: ArenaSlice,
    required_words: usize,
) -> Result<(), PreparedQuotientNumeratorError> {
    if slice.len_words() < required_words {
        return Err(PreparedQuotientNumeratorError::InputTooSmall {
            slot: slice.id(),
            required_words,
            actual_words: slice.len_words(),
        });
    }
    Ok(())
}

pub(super) fn checked_mul(lhs: usize, rhs: usize) -> Result<usize, PreparedQuotientNumeratorError> {
    lhs.checked_mul(rhs)
        .ok_or(PreparedQuotientNumeratorError::SizeOverflow)
}

pub(super) fn pow2(log_size: u32) -> Result<usize, PreparedQuotientNumeratorError> {
    1usize
        .checked_shl(log_size)
        .ok_or(PreparedQuotientNumeratorError::SizeOverflow)
}

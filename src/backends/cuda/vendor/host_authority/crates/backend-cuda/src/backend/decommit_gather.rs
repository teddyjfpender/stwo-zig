//! Multi-column sparse reads for Merkle decommitment.
//!
//! The host compatibility path performs one descriptor launch and one D2H for
//! an entire tree. [`PreparedColumnRowGather`] is the resident-proof primitive:
//! descriptor buffers and output live in a caller-owned [`DeviceArena`], and
//! [`PreparedColumnRowGather::launch`] only enqueues a kernel on that arena's
//! stream. It allocates, copies, and synchronizes only during `prepare`, outside
//! CUDA graph capture.

use core::ffi::c_void;

use stwo::core::fields::m31::BaseField;

use super::exec_context::{ArenaError, ArenaSlice, ArenaSlotId, CudaRuntimeError, DeviceArena};
use crate::columns::BaseFieldVec;

const CUDA_SUCCESS: i32 = 0;
const WORD_BYTES: usize = core::mem::size_of::<u32>();

/// Four non-overlapping arena slots used by a resident column-row gather.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColumnRowGatherSlots {
    /// Device array of device column pointers.
    pub column_ptrs: ArenaSlotId,
    /// Device array of `n_columns + 1` flattened row offsets.
    pub row_offsets: ArenaSlotId,
    /// Device array of flattened row indices.
    pub row_indices: ArenaSlotId,
    /// Device output in the same flattened, column-major descriptor order.
    pub output: ArenaSlotId,
}

/// Exact arena capacity required by a column-row descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColumnRowGatherRequirements {
    pub column_ptr_words: usize,
    pub row_offset_words: usize,
    pub row_index_words: usize,
    pub output_words: usize,
}

/// A rejected descriptor, arena binding, or CUDA operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ColumnRowGatherError {
    LengthMismatch {
        columns: usize,
        row_lists: usize,
    },
    CountOverflow {
        what: &'static str,
        value: usize,
    },
    RowOutOfBounds {
        column: usize,
        row: usize,
        len: usize,
    },
    NullDeviceColumn {
        column: usize,
    },
    AliasedArenaSlot(ArenaSlotId),
    SlotTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    MisalignedPointerSlot {
        slot: ArenaSlotId,
        required_bytes: usize,
    },
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for ColumnRowGatherError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LengthMismatch { columns, row_lists } => write!(
                f,
                "column-row gather has {columns} columns but {row_lists} row lists"
            ),
            Self::CountOverflow { what, value } => {
                write!(f, "column-row gather {what} count {value} exceeds u32")
            }
            Self::RowOutOfBounds { column, row, len } => write!(
                f,
                "column-row gather row {row} is outside column {column} of length {len}"
            ),
            Self::NullDeviceColumn { column } => {
                write!(
                    f,
                    "column-row gather column {column} has a null device pointer"
                )
            }
            Self::AliasedArenaSlot(slot) => {
                write!(
                    f,
                    "column-row gather arena slot {slot:?} is used more than once"
                )
            }
            Self::SlotTooSmall {
                slot,
                required_words,
                actual_words,
            } => write!(
                f,
                "column-row gather arena slot {slot:?} has {actual_words} words; {required_words} required"
            ),
            Self::MisalignedPointerSlot {
                slot,
                required_bytes,
            } => write!(
                f,
                "column-row gather pointer slot {slot:?} is not {required_bytes}-byte aligned"
            ),
            Self::Arena(error) => error.fmt(f),
            Self::Cuda(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ColumnRowGatherError {}

impl From<ArenaError> for ColumnRowGatherError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for ColumnRowGatherError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GatherPlan {
    column_lengths: Vec<u32>,
    row_offsets: Vec<u32>,
    row_indices: Vec<u32>,
}

impl GatherPlan {
    fn new(column_lengths: &[usize], rows: &[Vec<usize>]) -> Result<Self, ColumnRowGatherError> {
        if column_lengths.len() != rows.len() {
            return Err(ColumnRowGatherError::LengthMismatch {
                columns: column_lengths.len(),
                row_lists: rows.len(),
            });
        }
        u32::try_from(column_lengths.len()).map_err(|_| ColumnRowGatherError::CountOverflow {
            what: "column",
            value: column_lengths.len(),
        })?;

        let total_rows = rows.iter().try_fold(0_usize, |total, column_rows| {
            total
                .checked_add(column_rows.len())
                .ok_or(ColumnRowGatherError::CountOverflow {
                    what: "row",
                    value: usize::MAX,
                })
        })?;
        u32::try_from(total_rows).map_err(|_| ColumnRowGatherError::CountOverflow {
            what: "row",
            value: total_rows,
        })?;

        let column_lengths: Vec<u32> = column_lengths
            .iter()
            .map(|&len| {
                u32::try_from(len).map_err(|_| ColumnRowGatherError::CountOverflow {
                    what: "column length",
                    value: len,
                })
            })
            .collect::<Result<_, _>>()?;
        let mut row_offsets = Vec::with_capacity(rows.len() + 1);
        let mut row_indices = Vec::with_capacity(total_rows);
        row_offsets.push(0);
        for (column, (column_rows, &column_len)) in rows.iter().zip(&column_lengths).enumerate() {
            for &row in column_rows {
                if row >= column_len as usize {
                    return Err(ColumnRowGatherError::RowOutOfBounds {
                        column,
                        row,
                        len: column_len as usize,
                    });
                }
                row_indices.push(row as u32);
            }
            row_offsets.push(row_indices.len() as u32);
        }

        Ok(Self {
            column_lengths,
            row_offsets,
            row_indices,
        })
    }

    fn n_columns(&self) -> u32 {
        self.column_lengths.len() as u32
    }

    fn total_rows(&self) -> u32 {
        self.row_indices.len() as u32
    }

    fn requirements(&self) -> ColumnRowGatherRequirements {
        let pointer_bytes = self.column_lengths.len() * core::mem::size_of::<*const u32>();
        ColumnRowGatherRequirements {
            column_ptr_words: pointer_bytes.div_ceil(WORD_BYTES),
            row_offset_words: self.row_offsets.len(),
            row_index_words: self.row_indices.len(),
            output_words: self.row_indices.len(),
        }
    }

    fn reshape_raw(&self, flat: &[u32]) -> Vec<Vec<BaseField>> {
        assert_eq!(flat.len(), self.row_indices.len());
        self.row_offsets
            .windows(2)
            .map(|range| {
                flat[range[0] as usize..range[1] as usize]
                    .iter()
                    .map(|&value| BaseField::from_u32_unchecked(value))
                    .collect()
            })
            .collect()
    }
}

/// Computes the descriptor's exact arena requirements before an arena is built.
///
/// Arena slots themselves must be non-empty, so a zero-word requirement should
/// be provisioned as one unused word.
pub fn column_row_gather_requirements(
    column_lengths: &[usize],
    rows: &[Vec<usize>],
) -> Result<ColumnRowGatherRequirements, ColumnRowGatherError> {
    Ok(GatherPlan::new(column_lengths, rows)?.requirements())
}

/// Prepared device descriptors for a capture-safe multi-column gather.
///
/// The borrowed columns keep every device allocation alive. The arena borrow
/// keeps descriptor and output addresses stable through capture and replay.
pub struct PreparedColumnRowGather<'a> {
    arena: &'a DeviceArena,
    _columns: Vec<&'a BaseFieldVec>,
    column_ptrs: ArenaSlice,
    row_offsets_device: ArenaSlice,
    row_indices_device: ArenaSlice,
    output: ArenaSlice,
    row_offsets: Vec<u32>,
    n_columns: u32,
    total_rows: u32,
}

impl<'a> PreparedColumnRowGather<'a> {
    /// Validates the descriptor and uploads it into stable arena slots.
    ///
    /// This setup synchronizes once so its temporary host descriptor arrays can
    /// be dropped safely. Call it before graph capture. Column producers on other
    /// streams must already have established their own dependency on this arena's
    /// stream.
    pub fn prepare(
        arena: &'a DeviceArena,
        slots: ColumnRowGatherSlots,
        columns: &[&'a BaseFieldVec],
        rows: &[Vec<usize>],
    ) -> Result<Self, ColumnRowGatherError> {
        ensure_distinct_slots(slots)?;
        let column_lengths: Vec<_> = columns.iter().map(|column| column.size).collect();
        let plan = GatherPlan::new(&column_lengths, rows)?;
        let requirements = plan.requirements();

        for (column, (pointer, range)) in columns
            .iter()
            .map(|column| column.device_ptr)
            .zip(plan.row_offsets.windows(2))
            .enumerate()
        {
            if range[0] != range[1] && pointer.is_null() {
                return Err(ColumnRowGatherError::NullDeviceColumn { column });
            }
        }

        // Pooled slots may be larger than any single logical buffer; keep only
        // the logical extents so no consumer derives sizes from the surplus.
        let column_ptrs = ensure_capacity(
            arena.bind(slots.column_ptrs)?,
            requirements.column_ptr_words,
        )?;
        let row_offsets_device = ensure_capacity(
            arena.bind(slots.row_offsets)?,
            requirements.row_offset_words,
        )?;
        let row_indices_device =
            ensure_capacity(arena.bind(slots.row_indices)?, requirements.row_index_words)?;
        let output = ensure_capacity(arena.bind(slots.output)?, requirements.output_words)?;
        let context_token = arena.context().identity_token();
        debug_assert!(
            [column_ptrs, row_offsets_device, row_indices_device, output,]
                .iter()
                .all(|slice| slice.context_token() == context_token)
        );

        let pointer_alignment = core::mem::align_of::<*const u32>();
        if requirements.column_ptr_words != 0
            && column_ptrs.as_u32_ptr() as usize % pointer_alignment != 0
        {
            return Err(ColumnRowGatherError::MisalignedPointerSlot {
                slot: column_ptrs.id(),
                required_bytes: pointer_alignment,
            });
        }

        let device_columns: Vec<*const u32> =
            columns.iter().map(|column| column.device_ptr).collect();
        let context = arena.context();
        // If a later enqueue fails, still drain any earlier H2D operation before
        // these temporary host vectors leave scope.
        let upload_result = unsafe {
            context
                .memcpy_h2d_async(
                    column_ptrs.as_void_ptr(),
                    device_columns.as_ptr().cast::<c_void>(),
                    device_columns.len() * core::mem::size_of::<*const u32>(),
                )
                .and_then(|()| {
                    context.memcpy_h2d_async(
                        row_offsets_device.as_void_ptr(),
                        plan.row_offsets.as_ptr().cast::<c_void>(),
                        plan.row_offsets.len() * WORD_BYTES,
                    )
                })
                .and_then(|()| {
                    if plan.row_indices.is_empty() {
                        Ok(())
                    } else {
                        context.memcpy_h2d_async(
                            row_indices_device.as_void_ptr(),
                            plan.row_indices.as_ptr().cast::<c_void>(),
                            plan.row_indices.len() * WORD_BYTES,
                        )
                    }
                })
        };
        let sync_result = context.sync();
        upload_result?;
        sync_result?;
        let n_columns = plan.n_columns();
        let total_rows = plan.total_rows();

        Ok(Self {
            arena,
            _columns: columns.to_vec(),
            column_ptrs,
            row_offsets_device,
            row_indices_device,
            output,
            row_offsets: plan.row_offsets,
            n_columns,
            total_rows,
        })
    }

    /// Enqueues the allocation-free gather on the arena's explicit stream.
    ///
    /// This method performs no allocation, transfer, or synchronization and is
    /// therefore safe to invoke between `capture` and `finish`.
    pub fn launch(&self) -> Result<(), ColumnRowGatherError> {
        if self.total_rows == 0 {
            return Ok(());
        }
        let status = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_batch_gather_column_rows_launch(
                self.column_ptrs.as_u32_ptr().cast::<*const u32>(),
                self.row_offsets_device.as_u32_ptr(),
                self.row_indices_device.as_u32_ptr(),
                self.n_columns,
                self.total_rows,
                self.output.as_u32_ptr(),
                self.arena.context().stream_raw().as_ptr(),
            )
        };
        check_cuda("batch_gather_column_rows_launch", status)
    }

    pub fn output_slice(&self) -> ArenaSlice {
        self.output
    }

    pub fn flattened_len(&self) -> usize {
        self.total_rows as usize
    }

    pub fn row_offsets(&self) -> &[u32] {
        &self.row_offsets
    }
}

/// Host compatibility wrapper used by the current Merkle decommitment path.
///
/// The native side uploads explicit pointer/offset/index arrays, launches once,
/// and performs exactly one D2H for the flattened output. Values remain raw M31
/// words; no field reduction occurs before leaf rehashing.
pub fn gather_column_rows_host(
    columns: &[&BaseFieldVec],
    rows: &[Vec<usize>],
) -> Result<Vec<Vec<BaseField>>, ColumnRowGatherError> {
    let column_lengths: Vec<_> = columns.iter().map(|column| column.size).collect();
    let plan = GatherPlan::new(&column_lengths, rows)?;
    if plan.total_rows() == 0 {
        return Ok((0..columns.len()).map(|_| Vec::new()).collect());
    }
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return Err(CudaRuntimeError::Unavailable.into());
    }

    let device_columns: Vec<*const u32> = columns.iter().map(|column| column.device_ptr).collect();
    for (column, (&pointer, range)) in device_columns
        .iter()
        .zip(plan.row_offsets.windows(2))
        .enumerate()
    {
        if range[0] != range[1] && pointer.is_null() {
            return Err(ColumnRowGatherError::NullDeviceColumn { column });
        }
    }

    let mut output = vec![0_u32; plan.total_rows() as usize];
    let status = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_batch_gather_column_rows_host(
            device_columns.as_ptr(),
            plan.column_lengths.as_ptr(),
            plan.row_offsets.as_ptr(),
            plan.row_indices.as_ptr(),
            plan.n_columns(),
            plan.total_rows(),
            output.as_mut_ptr(),
        )
    };
    check_cuda("batch_gather_column_rows_host", status)?;
    Ok(plan.reshape_raw(&output))
}

fn ensure_distinct_slots(slots: ColumnRowGatherSlots) -> Result<(), ColumnRowGatherError> {
    let ids = [
        slots.column_ptrs,
        slots.row_offsets,
        slots.row_indices,
        slots.output,
    ];
    for (index, &id) in ids.iter().enumerate() {
        if ids[..index].contains(&id) {
            return Err(ColumnRowGatherError::AliasedArenaSlot(id));
        }
    }
    Ok(())
}

// Validates capacity and truncates the bound slot to the logical requirement
// so `len_words()` never exposes the pooled surplus.
fn ensure_capacity(
    slice: ArenaSlice,
    required_words: usize,
) -> Result<ArenaSlice, ColumnRowGatherError> {
    if slice.len_words() < required_words {
        return Err(ColumnRowGatherError::SlotTooSmall {
            slot: slice.id(),
            required_words,
            actual_words: slice.len_words(),
        });
    }
    Ok(slice.truncated(required_words))
}

fn check_cuda(operation: &'static str, status: i32) -> Result<(), ColumnRowGatherError> {
    if status == CUDA_SUCCESS {
        Ok(())
    } else {
        Err(CudaRuntimeError::Cuda {
            operation,
            code: status,
        }
        .into())
    }
}

#[cfg(test)]
mod tests {
    use stwo::core::fields::m31::P;

    use super::*;

    #[test]
    fn plan_preserves_column_and_row_order_including_empty_columns() {
        let plan = GatherPlan::new(&[4, 0, 5], &[vec![3, 1, 3], vec![], vec![4, 0]]).unwrap();
        assert_eq!(plan.column_lengths, vec![4, 0, 5]);
        assert_eq!(plan.row_offsets, vec![0, 3, 3, 5]);
        assert_eq!(plan.row_indices, vec![3, 1, 3, 4, 0]);
        assert_eq!(
            plan.requirements(),
            ColumnRowGatherRequirements {
                column_ptr_words: 3 * core::mem::size_of::<*const u32>() / WORD_BYTES,
                row_offset_words: 4,
                row_index_words: 5,
                output_words: 5,
            }
        );
    }

    #[test]
    fn plan_rejects_mismatches_and_out_of_bounds_rows() {
        assert_eq!(
            GatherPlan::new(&[2], &[]).unwrap_err(),
            ColumnRowGatherError::LengthMismatch {
                columns: 1,
                row_lists: 0,
            }
        );
        assert_eq!(
            GatherPlan::new(&[2], &[vec![2]]).unwrap_err(),
            ColumnRowGatherError::RowOutOfBounds {
                column: 0,
                row: 2,
                len: 2,
            }
        );
    }

    #[test]
    fn reshape_preserves_unreduced_m31_words() {
        let plan = GatherPlan::new(&[3, 2], &[vec![0, 2], vec![1]]).unwrap();
        let reshaped = plan.reshape_raw(&[P, 7, P]);
        assert_eq!(
            reshaped
                .iter()
                .map(|column| column.iter().map(|value| value.0).collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            vec![vec![P, 7], vec![P]]
        );
    }

    #[test]
    fn capacity_errors_name_the_bound_slot() {
        let slice = ArenaSlice::dangling_for_test(17, 2);
        assert_eq!(
            ensure_capacity(slice, 3).unwrap_err(),
            ColumnRowGatherError::SlotTooSmall {
                slot: ArenaSlotId(17),
                required_words: 3,
                actual_words: 2,
            }
        );
    }

    #[test]
    fn empty_host_descriptor_is_valid_on_the_stub_build() {
        assert_eq!(
            gather_column_rows_host(&[], &[]).unwrap(),
            Vec::<Vec<BaseField>>::new()
        );
    }

    #[cfg(stwo_cuda_link)]
    #[test]
    fn host_and_graph_captured_device_paths_match() {
        use super::super::exec_context::{ArenaLayout, ArenaSlotSpec, CudaExecContext};

        const PTRS: ArenaSlotId = ArenaSlotId(20);
        const OFFSETS: ArenaSlotId = ArenaSlotId(21);
        const INDICES: ArenaSlotId = ArenaSlotId(22);
        const OUTPUT: ArenaSlotId = ArenaSlotId(23);
        let slots = ColumnRowGatherSlots {
            column_ptrs: PTRS,
            row_offsets: OFFSETS,
            row_indices: INDICES,
            output: OUTPUT,
        };

        let columns = [
            BaseFieldVec::from_vec(vec![
                BaseField::from_u32_unchecked(P),
                BaseField::from_u32_unchecked(11),
                BaseField::from_u32_unchecked(12),
            ]),
            BaseFieldVec::from_vec(vec![BaseField::from_u32_unchecked(20)]),
            BaseFieldVec::from_vec(vec![
                BaseField::from_u32_unchecked(30),
                BaseField::from_u32_unchecked(31),
            ]),
        ];
        let refs: Vec<_> = columns.iter().collect();
        let rows = vec![vec![2, 0], vec![], vec![1, 0]];
        let host = gather_column_rows_host(&refs, &rows).unwrap();
        let expected = vec![vec![12, P], vec![], vec![31, 30]];
        assert_eq!(
            host.iter()
                .map(|column| column.iter().map(|value| value.0).collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            expected
        );

        let lengths: Vec<_> = columns.iter().map(|column| column.size).collect();
        let required = column_row_gather_requirements(&lengths, &rows).unwrap();
        let ptr_words = required.column_ptr_words.max(1);
        let offset_words = required.row_offset_words.max(1);
        let index_words = required.row_index_words.max(1);
        let output_words = required.output_words.max(1);
        let offset_start = ptr_words;
        let index_start = offset_start + offset_words;
        let output_start = index_start + index_words;
        let layout = ArenaLayout::new(
            output_start + output_words,
            &[
                ArenaSlotSpec {
                    id: PTRS,
                    offset_words: 0,
                    len_words: ptr_words,
                    alignment_words: core::mem::align_of::<*const u32>() / WORD_BYTES,
                },
                ArenaSlotSpec {
                    id: OFFSETS,
                    offset_words: offset_start,
                    len_words: offset_words,
                    alignment_words: 1,
                },
                ArenaSlotSpec {
                    id: INDICES,
                    offset_words: index_start,
                    len_words: index_words,
                    alignment_words: 1,
                },
                ArenaSlotSpec {
                    id: OUTPUT,
                    offset_words: output_start,
                    len_words: output_words,
                    alignment_words: 1,
                },
            ],
        )
        .unwrap();
        let arena = DeviceArena::new(CudaExecContext::new().unwrap(), layout).unwrap();
        let prepared = PreparedColumnRowGather::prepare(&arena, slots, &refs, &rows).unwrap();

        let capture = arena.context().capture().unwrap();
        prepared.launch().unwrap();
        let graph = capture.finish().unwrap();
        graph.launch(arena.context()).unwrap();

        let mut flat = vec![0_u32; prepared.flattened_len()];
        unsafe {
            arena
                .context()
                .memcpy_d2h_async(
                    flat.as_mut_ptr().cast(),
                    prepared.output_slice().as_void_ptr().cast_const(),
                    flat.len() * WORD_BYTES,
                )
                .unwrap();
        }
        arena.context().sync().unwrap();
        assert_eq!(flat, vec![12, P, 31, 30]);
        drop(graph);
    }
}

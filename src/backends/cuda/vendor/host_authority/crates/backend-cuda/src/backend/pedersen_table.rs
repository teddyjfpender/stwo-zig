//! Device registration of the HOST-BUILT pedersen points table (borrowed mode).
//!
//! The deduce-gate oracle falsified the GPU-generated table: 144/256 sampled
//! rows — including section boundaries — differ from the host
//! `PEDERSEN_TABLE_18` (run 20260705T113615Z). Until that generator is fixed
//! and re-gated, the ONLY table the witness-deduce lane may read is the host
//! table itself, uploaded column-for-column: byte-identical by construction.
//!
//! The caller (stwo-cairo, which owns `PEDERSEN_TABLE_18`) supplies columns
//! through a fill closure — one column at a time into a reusable buffer, so the
//! host-side overhead peaks at one padded column (~33MB), not the whole ~1.9GB
//! table. Columns are padded to a power of two (the deduce functions mask row
//! indices with `n_rows - 1`) and registered via the checked borrowed-table
//! publication boundary. The pointers publish to the precompiled module's
//! device globals; JIT modules' per-module globals fill from the same
//! registration at module load.

use std::sync::OnceLock;

use crate::columns::bindings;

#[path = "pedersen_table_digest.rs"]
mod digest;
pub use digest::compute_borrowed_pedersen_table_digest;
use digest::{finish_pedersen_digest, hash_pedersen_column, pedersen_content_hasher};

/// Column count of the pedersen points table (28 x-limbs + 28 y-limbs).
pub const PEDERSEN_TABLE_N_COLUMNS: usize = 56;

/// The borrowed table is installed once and retained for the process lifetime.
/// Generation zero means absent; the sole successful `OnceLock` publication is
/// generation one. A future replaceable table must increment this value instead
/// of reusing the process-local module receipts introduced for generation one.
pub const PEDERSEN_TABLE_REGISTRATION_GENERATION: u64 = 1;

/// BLAKE3 identity of the exact padded bytes uploaded for all 56 columns.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PedersenTableContentDigest([u8; 32]);

impl PedersenTableContentDigest {
    pub const fn new(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// One immutable, process-lifetime device column from the registered host table.
///
/// The address is intentionally not publicly constructible: callers may borrow
/// only columns whose backing allocation was installed by
/// [`register_borrowed_pedersen_table`] and deliberately retained for the
/// process lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredPedersenColumn {
    index: usize,
    device_address: usize,
    len_words: usize,
}

impl RegisteredPedersenColumn {
    pub const fn index(self) -> usize {
        self.index
    }

    pub fn as_u32_ptr(self) -> *mut u32 {
        self.device_address as *mut u32
    }

    pub const fn len_words(self) -> usize {
        self.len_words
    }
}

/// Exact process-lifetime registration published to precompiled and AOT/JIT
/// witness modules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisteredPedersenTable {
    columns: [RegisteredPedersenColumn; PEDERSEN_TABLE_N_COLUMNS],
    content_digest: PedersenTableContentDigest,
    source_n_rows: usize,
    n_rows: usize,
    registration_generation: u64,
}

/// A registered table failed the exact geometry required by a borrower.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisteredPedersenTableError {
    ContentDigest {
        expected: PedersenTableContentDigest,
        actual: PedersenTableContentDigest,
    },
    SourceRowCount {
        expected: usize,
        actual: usize,
    },
    RowCount {
        expected: usize,
        actual: usize,
    },
    ColumnIndex {
        position: usize,
        actual: usize,
    },
    ColumnLength {
        column: usize,
        expected: usize,
        actual: usize,
    },
    NullColumnPointer {
        column: usize,
    },
    RegistrationGeneration {
        expected: u64,
        actual: u64,
    },
}

/// A recoverable, host-visible failure while constructing the process table.
///
/// Once one of these failures is observed, registration is poisoned for the
/// process. Returning the same cause on every later call prevents a second
/// builder from mixing a new allocation set with partially initialized state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PedersenTableRegistrationError {
    CudaUnavailable,
    EmptyTable,
    RowCountOverflow {
        requested_rows: usize,
    },
    NativeRowCountLimit {
        padded_rows: usize,
        max_rows: usize,
    },
    HostAllocationFailed {
        allocation: &'static str,
    },
    FillPanicked {
        column: usize,
    },
    ColumnLength {
        column: usize,
        expected: usize,
        actual: usize,
    },
    PoolInitialization(crate::CudaRuntimeError),
    DeviceUploadReturnedNull {
        column: usize,
    },
    InvalidReadyGeometry(RegisteredPedersenTableError),
    RequestGeometryMismatch {
        requested_padded_rows: usize,
        registered_padded_rows: usize,
    },
    RequestSourceRowCountMismatch {
        requested_source_rows: usize,
        registered_source_rows: usize,
        padded_rows: usize,
    },
    RequestContentDigestMismatch {
        requested: PedersenTableContentDigest,
        registered: PedersenTableContentDigest,
    },
    ContentDigestMismatch {
        expected: PedersenTableContentDigest,
        actual: PedersenTableContentDigest,
    },
    Cuda {
        operation: &'static str,
        column: Option<usize>,
        code: i32,
    },
    Rollback {
        primary: Box<PedersenTableRegistrationError>,
        cleanup: Box<PedersenTableRegistrationError>,
    },
}

impl core::fmt::Display for PedersenTableRegistrationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CudaUnavailable => f.write_str("CUDA kernels are not available in this build"),
            Self::EmptyTable => f.write_str("the pedersen table has no rows"),
            Self::RowCountOverflow { requested_rows } => write!(
                f,
                "pedersen row count {requested_rows} overflows power-of-two padding"
            ),
            Self::NativeRowCountLimit {
                padded_rows,
                max_rows,
            } => write!(
                f,
                "padded pedersen row count {padded_rows} exceeds native upload limit {max_rows}"
            ),
            Self::HostAllocationFailed { allocation } => {
                write!(f, "host allocation failed for {allocation}")
            }
            Self::FillPanicked { column } => {
                write!(f, "pedersen column builder panicked at column {column}")
            }
            Self::ColumnLength {
                column,
                expected,
                actual,
            } => write!(
                f,
                "pedersen column {column} has {actual} rows, expected {expected}"
            ),
            Self::PoolInitialization(error) => {
                write!(f, "CUDA pool initialization failed: {error}")
            }
            Self::DeviceUploadReturnedNull { column } => {
                write!(f, "device upload returned null at pedersen column {column}")
            }
            Self::InvalidReadyGeometry(error) => {
                write!(
                    f,
                    "constructed pedersen table has invalid geometry: {error:?}"
                )
            }
            Self::RequestGeometryMismatch {
                requested_padded_rows,
                registered_padded_rows,
            } => write!(
                f,
                "requested pedersen geometry has {requested_padded_rows} padded rows, but the \
                 registered table has {registered_padded_rows}"
            ),
            Self::RequestSourceRowCountMismatch {
                requested_source_rows,
                registered_source_rows,
                padded_rows,
            } => write!(
                f,
                "requested pedersen source has {requested_source_rows} rows, but the registered \
                 source has {registered_source_rows} rows (both pad to {padded_rows})"
            ),
            Self::RequestContentDigestMismatch {
                requested,
                registered,
            } => write!(
                f,
                "requested pedersen content digest {requested:?} differs from registered \
                 content digest {registered:?}"
            ),
            Self::ContentDigestMismatch { expected, actual } => write!(
                f,
                "filled pedersen bytes have digest {actual:?}, expected {expected:?}"
            ),
            Self::Cuda {
                operation,
                column,
                code,
            } => match column {
                Some(column) => write!(
                    f,
                    "CUDA operation {operation} failed for pedersen column {column} with status \
                     {code}"
                ),
                None => write!(f, "CUDA operation {operation} failed with status {code}"),
            },
            Self::Rollback { primary, cleanup } => write!(
                f,
                "pedersen registration failed ({primary}); unpublished-column rollback also \
                 failed ({cleanup})"
            ),
        }
    }
}

impl std::error::Error for PedersenTableRegistrationError {}

/// Snapshot of the process-wide registration state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PedersenTableRegistrationState {
    Uninitialized,
    Ready(RegisteredPedersenTable),
    Poisoned(PedersenTableRegistrationError),
}

impl RegisteredPedersenTable {
    pub const fn content_digest(self) -> PedersenTableContentDigest {
        self.content_digest
    }

    pub const fn source_n_rows(self) -> usize {
        self.source_n_rows
    }

    pub const fn n_rows(self) -> usize {
        self.n_rows
    }

    pub const fn registration_generation(self) -> u64 {
        self.registration_generation
    }

    pub const fn columns(self) -> [RegisteredPedersenColumn; PEDERSEN_TABLE_N_COLUMNS] {
        self.columns
    }

    pub fn column(self, index: usize) -> Option<RegisteredPedersenColumn> {
        self.columns.get(index).copied()
    }

    pub const fn has_exact_rows(self, expected_rows: usize) -> bool {
        self.n_rows == expected_rows
    }

    /// Validate every borrowed pointer before exposing the table to another
    /// execution context. A single malformed column rejects the whole table;
    /// callers must never mix registered and regenerated columns silently.
    pub fn validate_exact_geometry(
        self,
        expected_rows: usize,
    ) -> Result<(), RegisteredPedersenTableError> {
        if self.registration_generation != PEDERSEN_TABLE_REGISTRATION_GENERATION {
            return Err(RegisteredPedersenTableError::RegistrationGeneration {
                expected: PEDERSEN_TABLE_REGISTRATION_GENERATION,
                actual: self.registration_generation,
            });
        }
        if self.n_rows != expected_rows {
            return Err(RegisteredPedersenTableError::RowCount {
                expected: expected_rows,
                actual: self.n_rows,
            });
        }
        for (position, column) in self.columns.iter().copied().enumerate() {
            if column.index != position {
                return Err(RegisteredPedersenTableError::ColumnIndex {
                    position,
                    actual: column.index,
                });
            }
            if column.len_words != expected_rows {
                return Err(RegisteredPedersenTableError::ColumnLength {
                    column: position,
                    expected: expected_rows,
                    actual: column.len_words,
                });
            }
            if column.as_u32_ptr().is_null() {
                return Err(RegisteredPedersenTableError::NullColumnPointer { column: position });
            }
        }
        Ok(())
    }

    /// Validate both the host source identity and its padded device geometry.
    pub fn validate_exact_registration_geometry(
        self,
        expected_content_digest: PedersenTableContentDigest,
        expected_source_rows: usize,
        expected_padded_rows: usize,
    ) -> Result<(), RegisteredPedersenTableError> {
        if self.content_digest != expected_content_digest {
            return Err(RegisteredPedersenTableError::ContentDigest {
                expected: expected_content_digest,
                actual: self.content_digest,
            });
        }
        if self.source_n_rows != expected_source_rows {
            return Err(RegisteredPedersenTableError::SourceRowCount {
                expected: expected_source_rows,
                actual: self.source_n_rows,
            });
        }
        self.validate_exact_geometry(expected_padded_rows)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegistrationGeometry {
    content_digest: PedersenTableContentDigest,
    source_rows: usize,
    padded_rows: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StoredRegistrationState {
    Ready(RegisteredPedersenTable),
    Poisoned(PedersenTableRegistrationError),
}

struct RegistrationSlot {
    state: OnceLock<StoredRegistrationState>,
}

impl RegistrationSlot {
    const fn new() -> Self {
        Self {
            state: OnceLock::new(),
        }
    }

    fn try_register(
        &self,
        requested_geometry: Result<RegistrationGeometry, PedersenTableRegistrationError>,
        build: impl FnOnce(
            RegistrationGeometry,
        ) -> Result<RegisteredPedersenTable, PedersenTableRegistrationError>,
    ) -> Result<RegisteredPedersenTable, PedersenTableRegistrationError> {
        let state = self.state.get_or_init(|| {
            let result = requested_geometry.clone().and_then(|geometry| {
                let table = build(geometry)?;
                table
                    .validate_exact_registration_geometry(
                        geometry.content_digest,
                        geometry.source_rows,
                        geometry.padded_rows,
                    )
                    .map_err(PedersenTableRegistrationError::InvalidReadyGeometry)?;
                Ok(table)
            });
            match result {
                Ok(table) => StoredRegistrationState::Ready(table),
                Err(error) => StoredRegistrationState::Poisoned(error),
            }
        });

        match state {
            StoredRegistrationState::Poisoned(error) => Err(error.clone()),
            StoredRegistrationState::Ready(table) => {
                let requested = requested_geometry?;
                if table.n_rows != requested.padded_rows {
                    return Err(PedersenTableRegistrationError::RequestGeometryMismatch {
                        requested_padded_rows: requested.padded_rows,
                        registered_padded_rows: table.n_rows,
                    });
                }
                if table.source_n_rows != requested.source_rows {
                    return Err(
                        PedersenTableRegistrationError::RequestSourceRowCountMismatch {
                            requested_source_rows: requested.source_rows,
                            registered_source_rows: table.source_n_rows,
                            padded_rows: requested.padded_rows,
                        },
                    );
                }
                if table.content_digest != requested.content_digest {
                    return Err(
                        PedersenTableRegistrationError::RequestContentDigestMismatch {
                            requested: requested.content_digest,
                            registered: table.content_digest,
                        },
                    );
                }
                Ok(*table)
            }
        }
    }

    fn snapshot(&self) -> PedersenTableRegistrationState {
        match self.state.get() {
            None => PedersenTableRegistrationState::Uninitialized,
            Some(StoredRegistrationState::Ready(table)) => {
                PedersenTableRegistrationState::Ready(*table)
            }
            Some(StoredRegistrationState::Poisoned(error)) => {
                PedersenTableRegistrationState::Poisoned(error.clone())
            }
        }
    }

    fn ready(&self) -> Option<RegisteredPedersenTable> {
        match self.state.get() {
            Some(StoredRegistrationState::Ready(table)) => Some(*table),
            None | Some(StoredRegistrationState::Poisoned(_)) => None,
        }
    }
}

struct PendingDeviceColumns {
    pointers: Vec<*mut u32>,
    published: bool,
}

impl PendingDeviceColumns {
    fn new() -> Result<Self, PedersenTableRegistrationError> {
        let mut pointers = Vec::new();
        pointers
            .try_reserve_exact(PEDERSEN_TABLE_N_COLUMNS)
            .map_err(|_| PedersenTableRegistrationError::HostAllocationFailed {
                allocation: "pedersen device-pointer list",
            })?;
        Ok(Self {
            pointers,
            published: false,
        })
    }

    fn mark_published(&mut self) {
        self.published = true;
    }

    fn release_unpublished(&mut self) -> Result<(), PedersenTableRegistrationError> {
        if self.pointers.is_empty() {
            return Ok(());
        }
        let mut first_error = None;
        for (column, pointer) in self.pointers.drain(..).enumerate() {
            let code = unsafe {
                stwo_backend_cuda_kernels::raw::cuda_default_pool_free_checked(pointer.cast())
            };
            if code != 0 && first_error.is_none() {
                first_error = Some(PedersenTableRegistrationError::Cuda {
                    operation: "pedersen_unpublished_free",
                    column: Some(column),
                    code,
                });
            }
        }
        let code =
            unsafe { stwo_backend_cuda_kernels::raw::cuda_default_pool_stream_sync_checked() };
        if code != 0 && first_error.is_none() {
            first_error = Some(PedersenTableRegistrationError::Cuda {
                operation: "pedersen_unpublished_free_sync",
                column: None,
                code,
            });
        }
        first_error.map_or(Ok(()), Err)
    }

    fn rollback(
        mut self,
        primary: PedersenTableRegistrationError,
    ) -> PedersenTableRegistrationError {
        match self.release_unpublished() {
            Ok(()) => primary,
            Err(cleanup) => PedersenTableRegistrationError::Rollback {
                primary: Box::new(primary),
                cleanup: Box::new(cleanup),
            },
        }
    }
}

impl Drop for PendingDeviceColumns {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        if !self.pointers.is_empty() {
            // Unexpected unwinding still uses only checked, no-fallback CUDA
            // calls. Normal error paths call `rollback` and return exact status.
            let _ = self.release_unpublished();
        }
    }
}

static REGISTERED: RegistrationSlot = RegistrationSlot::new();

fn requested_padded_rows(n_rows: usize) -> Result<usize, PedersenTableRegistrationError> {
    if n_rows == 0 {
        return Err(PedersenTableRegistrationError::EmptyTable);
    }
    let padded_rows = n_rows.checked_next_power_of_two().ok_or(
        PedersenTableRegistrationError::RowCountOverflow {
            requested_rows: n_rows,
        },
    )?;
    // Native publication records the padded geometry in a u32 device symbol.
    let max_rows = u32::MAX as usize;
    if padded_rows > max_rows {
        return Err(PedersenTableRegistrationError::NativeRowCountLimit {
            padded_rows,
            max_rows,
        });
    }
    Ok(padded_rows)
}

fn requested_geometry(
    n_rows: usize,
    content_digest: PedersenTableContentDigest,
) -> Result<RegistrationGeometry, PedersenTableRegistrationError> {
    let padded_rows = requested_padded_rows(n_rows)?;
    Ok(RegistrationGeometry {
        content_digest,
        source_rows: n_rows,
        padded_rows,
    })
}

fn build_borrowed_pedersen_table(
    geometry: RegistrationGeometry,
    fill_column: &mut impl FnMut(usize, &mut Vec<u32>),
) -> Result<RegisteredPedersenTable, PedersenTableRegistrationError> {
    let RegistrationGeometry {
        content_digest,
        source_rows,
        padded_rows,
    } = geometry;
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return Err(PedersenTableRegistrationError::CudaUnavailable);
    }
    bindings::try_ensure_mem_pool_init()
        .map_err(PedersenTableRegistrationError::PoolInitialization)?;
    let byte_count = padded_rows.checked_mul(core::mem::size_of::<u32>()).ok_or(
        PedersenTableRegistrationError::RowCountOverflow {
            requested_rows: source_rows,
        },
    )?;

    let mut pending = PendingDeviceColumns::new()?;
    let mut hasher = pedersen_content_hasher(source_rows, padded_rows);
    let mut buf = Vec::new();
    buf.try_reserve_exact(padded_rows).map_err(|_| {
        PedersenTableRegistrationError::HostAllocationFailed {
            allocation: "padded pedersen column buffer",
        }
    })?;

    for column in 0..PEDERSEN_TABLE_N_COLUMNS {
        buf.clear();
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fill_column(column, &mut buf);
        }))
        .is_err()
        {
            let error = PedersenTableRegistrationError::FillPanicked { column };
            return Err(pending.rollback(error));
        }
        if buf.len() != source_rows {
            let error = PedersenTableRegistrationError::ColumnLength {
                column,
                expected: source_rows,
                actual: buf.len(),
            };
            return Err(pending.rollback(error));
        }

        // Padding rows are 0. Real deduce indices never reach them, and raw
        // words must not be canonicalized during transport.
        if buf.try_reserve_exact(padded_rows - buf.len()).is_err() {
            let error = PedersenTableRegistrationError::HostAllocationFailed {
                allocation: "padded pedersen column buffer",
            };
            return Err(pending.rollback(error));
        }
        buf.resize(padded_rows, 0);
        hash_pedersen_column(&mut hasher, column, &buf);
        let mut allocation = core::ptr::null_mut();
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::cuda_default_pool_alloc_checked(
                byte_count,
                &mut allocation,
            )
        };
        if code != 0 {
            let error = PedersenTableRegistrationError::Cuda {
                operation: "pedersen_default_pool_allocate",
                column: Some(column),
                code,
            };
            return Err(pending.rollback(error));
        }
        if allocation.is_null() {
            let error = PedersenTableRegistrationError::DeviceUploadReturnedNull { column };
            return Err(pending.rollback(error));
        }
        let device_pointer = allocation.cast::<u32>();
        pending.pointers.push(device_pointer);
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::cuda_default_pool_copy_h2d_checked(
                buf.as_ptr().cast(),
                allocation,
                byte_count,
            )
        };
        if code != 0 {
            let error = PedersenTableRegistrationError::Cuda {
                operation: "pedersen_host_to_device_copy",
                column: Some(column),
                code,
            };
            return Err(pending.rollback(error));
        }
    }

    let actual_digest = finish_pedersen_digest(hasher);
    if actual_digest != content_digest {
        let error = PedersenTableRegistrationError::ContentDigestMismatch {
            expected: content_digest,
            actual: actual_digest,
        };
        return Err(pending.rollback(error));
    }

    let columns = std::array::from_fn(|index| RegisteredPedersenColumn {
        index,
        device_address: pending.pointers[index] as usize,
        len_words: padded_rows,
    });
    let table = RegisteredPedersenTable {
        columns,
        content_digest,
        source_n_rows: source_rows,
        n_rows: padded_rows,
        registration_generation: PEDERSEN_TABLE_REGISTRATION_GENERATION,
    };
    if let Err(error) =
        table.validate_exact_registration_geometry(content_digest, source_rows, padded_rows)
    {
        return Err(pending.rollback(PedersenTableRegistrationError::InvalidReadyGeometry(error)));
    }

    // Checked native publication validates every pointer, rejects a different
    // active table, fences the device-global write, and commits host runtime
    // state only after that fence succeeds. This is the sole `Ready` boundary.
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_pedersen_table_init_borrowed_checked(
            pending.pointers.as_ptr(),
            padded_rows as u32,
        )
    };
    if code != 0 {
        let error = PedersenTableRegistrationError::Cuda {
            operation: "pedersen_borrowed_publication",
            column: None,
            code,
        };
        return Err(pending.rollback(error));
    }
    pending.mark_published();
    Ok(table)
}

/// Checked, one-shot upload and publication of the host pedersen table.
///
/// `n_rows` is the unpadded host row count. The fill closure must append exactly
/// that many raw words for each column. A recoverable failure poisons this slot,
/// frees every uploaded but unpublished prefix, and is returned unchanged on
/// later calls without invoking their builders. A ready slot is reusable only
/// for the same content digest, unpadded source rows, and padded geometry. The
/// upload pass hashes its exact padded bytes and rejects a false expected digest
/// before native publication.
///
/// Every CUDA operation on this formal path returns an exact status and uses the
/// admitted default pool without a `cudaMalloc` fallback. Only the separate
/// legacy `pedersen_table_init` native wrapper retains abort-on-error behavior.
pub fn try_register_borrowed_pedersen_table_with_content_digest(
    n_rows: usize,
    content_digest: PedersenTableContentDigest,
    mut fill_column: impl FnMut(usize, &mut Vec<u32>),
) -> Result<RegisteredPedersenTable, PedersenTableRegistrationError> {
    REGISTERED.try_register(requested_geometry(n_rows, content_digest), |geometry| {
        build_borrowed_pedersen_table(geometry, &mut fill_column)
    })
}

/// Compatibility checked registration. It derives the actual content digest in
/// a host-only pass, then uploads a second byte-checked pass. Formal callers
/// should cache a canonical digest and call
/// [`try_register_borrowed_pedersen_table_with_content_digest`] directly so
/// ready reuse never invokes their fill closure.
pub fn try_register_borrowed_pedersen_table(
    n_rows: usize,
    mut fill_column: impl FnMut(usize, &mut Vec<u32>),
) -> Result<RegisteredPedersenTable, PedersenTableRegistrationError> {
    let content_digest = compute_borrowed_pedersen_table_digest(n_rows, &mut fill_column)?;
    try_register_borrowed_pedersen_table_with_content_digest(n_rows, content_digest, fill_column)
}

/// Compatibility wrapper for callers that only distinguish device-ready from
/// host fallback.
pub fn register_borrowed_pedersen_table(
    n_rows: usize,
    fill_column: impl FnMut(usize, &mut Vec<u32>),
) -> bool {
    try_register_borrowed_pedersen_table(n_rows, fill_column).is_ok()
}

/// Whether a (successful) registration happened this process.
pub fn pedersen_table_registered() -> bool {
    registered_borrowed_pedersen_table().is_some()
}

/// Borrow the exact process-lifetime table without allocating or copying.
pub fn registered_borrowed_pedersen_table() -> Option<RegisteredPedersenTable> {
    REGISTERED.ready()
}

/// Inspect whether registration has not run, is ready, or is deterministically
/// poisoned by the first recoverable failure.
pub fn pedersen_table_registration_state() -> PedersenTableRegistrationState {
    REGISTERED.snapshot()
}

#[cfg(test)]
#[path = "pedersen_table_tests.rs"]
mod tests;

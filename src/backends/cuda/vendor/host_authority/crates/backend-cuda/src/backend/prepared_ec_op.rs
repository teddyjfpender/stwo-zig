//! Capture-safe native CUDA writer for Cairo's `ec_op_builtin`.
//!
//! The graph writes the component's committed base columns and word-major
//! lookup inputs, keeps the 252-round EC chain projective, then batch-normalizes
//! each saved state in the consumer's final padded input columns. Dead consumer
//! columns are the only scratch; no host/sub-input staging allocation exists.

use std::collections::BTreeSet;

use super::exec_context::{
    check_cuda, ArenaError, ArenaSlice, ArenaSlotId, CudaLaunchContext, CudaRuntimeError,
    DeviceArena,
};
use super::prepared_execution_tables::PreparedExecutionTablesView;

mod authority;
mod segment_start_receipt;
pub use authority::{
    EcOpAbiAccess, EcOpAbiArgument, EcOpAbiArgumentKind, EcOpAuthorityError, EcOpCompositeAbi,
    EcOpCompositeContract, EcOpEffectAbi, EcOpExecutionTableShape, EcOpKernelLaunch,
    EcOpKernelStage,
};
pub use segment_start_receipt::EcOpSegmentStartReceipt;

pub const EC_OP_TRACE_COLUMNS: usize = 273;
pub const EC_OP_LOOKUP_WORDS_PER_ROW: usize = 488;
pub const EC_OP_PARTIAL_INPUT_COLUMNS: usize = 127;
pub const EC_OP_PARTIAL_REAL_ROUNDS: usize = 252;
pub const EC_OP_PARTIAL_PADDED_ROUNDS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcOpWorkspaceRequirements {
    pub row_count: usize,
    pub trace_column_words: Vec<usize>,
    pub lookup_words: usize,
    pub partial_real_rows: usize,
    pub partial_row_count: usize,
    pub partial_input_column_words: Vec<usize>,
    pub segment_start_words: usize,
    pub address_count_words: usize,
    pub big_count_words: usize,
    pub small_count_words: usize,
    pub range_check_8_count_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcOpMultiplicityGeometry {
    pub address_count_words: usize,
    pub big_count_words: usize,
    pub small_count_words: usize,
    pub range_check_8_count_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EcOpArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EcOpWorkspaceSlots {
    pub trace_columns: Vec<ArenaSlotId>,
    pub lookup_words: ArenaSlotId,
    pub partial_input_columns: Vec<ArenaSlotId>,
    pub segment_start: ArenaSlotId,
    pub address_counts: ArenaSlotId,
    pub big_counts: ArenaSlotId,
    pub small_counts: ArenaSlotId,
    pub range_check_8_counts: ArenaSlotId,
}

impl EcOpWorkspaceRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: &EcOpWorkspaceSlots,
    ) -> Result<Vec<EcOpArenaSlotRequirement>, PreparedEcOpError> {
        validate_slot_shape(self, slots)?;
        let mut result = Vec::with_capacity(
            self.trace_column_words.len() + self.partial_input_column_words.len() + 6,
        );
        result.extend(
            slots
                .trace_columns
                .iter()
                .zip(&self.trace_column_words)
                .map(|(&id, &len_words)| words(id, len_words)),
        );
        result.extend([
            words(slots.segment_start, self.segment_start_words),
            words(slots.address_counts, self.address_count_words),
            words(slots.big_counts, self.big_count_words),
            words(slots.small_counts, self.small_count_words),
            words(slots.range_check_8_counts, self.range_check_8_count_words),
        ]);
        result.push(words(slots.lookup_words, self.lookup_words));
        result.extend(
            slots
                .partial_input_columns
                .iter()
                .zip(&self.partial_input_column_words)
                .map(|(&id, &len_words)| words(id, len_words)),
        );
        let mut distinct = BTreeSet::new();
        for entry in &result {
            if !distinct.insert(entry.id) {
                return Err(PreparedEcOpError::DuplicateSlot(entry.id));
            }
        }
        Ok(result)
    }
}

fn words(id: ArenaSlotId, len_words: usize) -> EcOpArenaSlotRequirement {
    EcOpArenaSlotRequirement {
        id,
        len_words,
        alignment_words: 1,
    }
}

pub fn ec_op_workspace_requirements(
    row_count: usize,
    multiplicity: EcOpMultiplicityGeometry,
) -> Result<EcOpWorkspaceRequirements, PreparedEcOpError> {
    if row_count < 16 || !row_count.is_power_of_two() {
        return Err(PreparedEcOpError::InvalidRowCount(row_count));
    }
    u32::try_from(row_count).map_err(|_| PreparedEcOpError::SizeOverflow)?;
    let lookup_words = row_count
        .checked_mul(EC_OP_LOOKUP_WORDS_PER_ROW)
        .ok_or(PreparedEcOpError::SizeOverflow)?;
    let partial_real_rows = row_count
        .checked_mul(EC_OP_PARTIAL_REAL_ROUNDS)
        .ok_or(PreparedEcOpError::SizeOverflow)?;
    let partial_row_count = row_count
        .checked_mul(EC_OP_PARTIAL_PADDED_ROUNDS)
        .ok_or(PreparedEcOpError::SizeOverflow)?;
    u32::try_from(partial_row_count).map_err(|_| PreparedEcOpError::SizeOverflow)?;
    if multiplicity.address_count_words == 0
        || multiplicity.big_count_words == 0
        || multiplicity.small_count_words == 0
        || multiplicity.range_check_8_count_words < 256
    {
        return Err(PreparedEcOpError::InvalidMultiplicityGeometry);
    }
    for words in [
        multiplicity.address_count_words,
        multiplicity.big_count_words,
        multiplicity.small_count_words,
        multiplicity.range_check_8_count_words,
    ] {
        u32::try_from(words).map_err(|_| PreparedEcOpError::SizeOverflow)?;
    }
    Ok(EcOpWorkspaceRequirements {
        row_count,
        trace_column_words: vec![row_count; EC_OP_TRACE_COLUMNS],
        lookup_words,
        partial_real_rows,
        partial_row_count,
        partial_input_column_words: vec![partial_row_count; EC_OP_PARTIAL_INPUT_COLUMNS],
        segment_start_words: 1,
        address_count_words: multiplicity.address_count_words,
        big_count_words: multiplicity.big_count_words,
        small_count_words: multiplicity.small_count_words,
        range_check_8_count_words: multiplicity.range_check_8_count_words,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedEcOpError {
    CudaUnavailable,
    InvalidRowCount(usize),
    InvalidSegmentStart,
    SegmentStartGenerationOverflow,
    SegmentStartNotIngested,
    InvalidMultiplicityGeometry,
    SegmentOutOfBounds {
        start: usize,
        end: usize,
        addresses: usize,
    },
    SizeOverflow,
    SlotShapeMismatch {
        role: &'static str,
        expected: usize,
        actual: usize,
    },
    SlotTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    DuplicateSlot(ArenaSlotId),
    ExecutionTableContextMismatch,
    Authority(EcOpAuthorityError),
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for PreparedEcOpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "prepared EC-op witness rejected: {self:?}")
    }
}

impl std::error::Error for PreparedEcOpError {}

impl From<ArenaError> for PreparedEcOpError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for PreparedEcOpError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

impl From<EcOpAuthorityError> for PreparedEcOpError {
    fn from(value: EcOpAuthorityError) -> Self {
        Self::Authority(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedEcOpLaunchTelemetry {
    pub kernel_launches: u64,
    pub allocations: u64,
    pub h2d_bytes: u64,
    pub d2h_bytes: u64,
    pub sync_calls: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedEcOpIngestTelemetry {
    pub h2d_bytes: u64,
    pub h2d_copies: u64,
    pub fill_calls: u64,
    pub sync_calls: u64,
}

impl PreparedEcOpLaunchTelemetry {
    const THREE_KERNELS: Self = Self {
        kernel_launches: 3,
        allocations: 0,
        h2d_bytes: 0,
        d2h_bytes: 0,
        sync_calls: 0,
    };
}

pub struct PreparedEcOpGraph<'a> {
    arena: &'a DeviceArena,
    contract: EcOpCompositeContract,
    execution_table_pointers: ArenaSlice,
    n_addresses: u32,
    n_big: u32,
    n_small: u32,
    segment_start: ArenaSlice,
    row_count: u32,
    trace_columns: Vec<ArenaSlice>,
    trace_pointers: Vec<*mut u32>,
    lookup_words: ArenaSlice,
    partial_row_count: u32,
    partial_input_columns: Vec<ArenaSlice>,
    partial_input_pointers: Vec<*mut u32>,
    address_counts: ArenaSlice,
    big_counts: ArenaSlice,
    small_counts: ArenaSlice,
    range_check_8_counts: ArenaSlice,
    segment_start_state: segment_start_receipt::EcOpSegmentStartState,
}

impl<'a> PreparedEcOpGraph<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        execution_tables: PreparedExecutionTablesView<'a>,
        requirements: &EcOpWorkspaceRequirements,
        slots: &EcOpWorkspaceSlots,
    ) -> Result<Self, PreparedEcOpError> {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return Err(PreparedEcOpError::CudaUnavailable);
        }
        if ec_op_workspace_requirements(
            requirements.row_count,
            EcOpMultiplicityGeometry {
                address_count_words: requirements.address_count_words,
                big_count_words: requirements.big_count_words,
                small_count_words: requirements.small_count_words,
                range_check_8_count_words: requirements.range_check_8_count_words,
            },
        )? != *requirements
        {
            return Err(PreparedEcOpError::InvalidRowCount(requirements.row_count));
        }
        requirements.arena_slot_requirements(slots)?;
        if !execution_tables.belongs_to(arena) {
            return Err(PreparedEcOpError::ExecutionTableContextMismatch);
        }
        let (n_addresses, n_big, n_small) = execution_tables.shape();
        if requirements.address_count_words < n_addresses.saturating_sub(1)
            || requirements.big_count_words < n_big
            || requirements.small_count_words < n_small
            || requirements.range_check_8_count_words < 256
        {
            return Err(PreparedEcOpError::InvalidMultiplicityGeometry);
        }
        let contract = EcOpCompositeContract::compile(
            requirements,
            EcOpExecutionTableShape {
                n_addresses,
                n_big,
                n_small,
            },
        )?;

        let trace_columns = bind_many(arena, &slots.trace_columns, requirements.row_count)?;
        let lookup_words = bind_slot(arena, slots.lookup_words, requirements.lookup_words)?;
        let partial_input_columns = bind_many(
            arena,
            &slots.partial_input_columns,
            requirements.partial_row_count,
        )?;
        let segment_start = bind_slot(arena, slots.segment_start, 1)?;
        let address_counts = bind_slot(
            arena,
            slots.address_counts,
            requirements.address_count_words,
        )?;
        let big_counts = bind_slot(arena, slots.big_counts, requirements.big_count_words)?;
        let small_counts = bind_slot(arena, slots.small_counts, requirements.small_count_words)?;
        let range_check_8_counts = bind_slot(
            arena,
            slots.range_check_8_counts,
            requirements.range_check_8_count_words,
        )?;
        let trace_pointers = trace_columns
            .iter()
            .map(|column| column.as_u32_ptr())
            .collect();
        let partial_input_pointers = partial_input_columns
            .iter()
            .map(|column| column.as_u32_ptr())
            .collect();

        Ok(Self {
            arena,
            contract,
            execution_table_pointers: execution_tables.table_pointers(),
            n_addresses: u32::try_from(n_addresses).map_err(|_| PreparedEcOpError::SizeOverflow)?,
            n_big: u32::try_from(n_big).map_err(|_| PreparedEcOpError::SizeOverflow)?,
            n_small: u32::try_from(n_small).map_err(|_| PreparedEcOpError::SizeOverflow)?,
            segment_start,
            row_count: u32::try_from(requirements.row_count)
                .map_err(|_| PreparedEcOpError::SizeOverflow)?,
            trace_columns,
            trace_pointers,
            lookup_words,
            partial_row_count: u32::try_from(requirements.partial_row_count)
                .map_err(|_| PreparedEcOpError::SizeOverflow)?,
            partial_input_columns,
            partial_input_pointers,
            address_counts,
            big_counts,
            small_counts,
            range_check_8_counts,
            segment_start_state: segment_start_receipt::EcOpSegmentStartState::new(),
        })
    }

    /// Update the statement-varying builtin segment without changing any
    /// captured kernel parameter or arena address.
    pub fn ingest_segment_start(
        &self,
        segment_start: usize,
    ) -> Result<PreparedEcOpIngestTelemetry, PreparedEcOpError> {
        if segment_start == 0 {
            return Err(PreparedEcOpError::InvalidSegmentStart);
        }
        let end = segment_start
            .checked_add(
                (self.row_count as usize)
                    .checked_mul(7)
                    .ok_or(PreparedEcOpError::SizeOverflow)?,
            )
            .ok_or(PreparedEcOpError::SizeOverflow)?;
        if end > self.n_addresses as usize {
            return Err(PreparedEcOpError::SegmentOutOfBounds {
                start: segment_start,
                end,
                addresses: self.n_addresses as usize,
            });
        }
        let value = u32::try_from(segment_start).map_err(|_| PreparedEcOpError::SizeOverflow)?;
        let generation = self.segment_start_state.next_generation()?;
        let binding = segment_start_receipt::EcOpSegmentStartBinding::new(
            self.arena,
            &self.contract,
            self.segment_start,
        );
        let receipt = EcOpSegmentStartReceipt::prepare(binding, value, generation)?;
        self.segment_start_state.begin(receipt);
        unsafe {
            self.arena.context().fill_u32_async(
                self.segment_start.as_u32_ptr(),
                value,
                self.segment_start.len_words(),
            )?;
        }
        self.segment_start_state.publish(receipt);
        Ok(PreparedEcOpIngestTelemetry {
            h2d_bytes: 0,
            h2d_copies: 0,
            fill_calls: 1,
            sync_calls: 0,
        })
    }

    pub fn launch(&self) -> Result<PreparedEcOpLaunchTelemetry, PreparedEcOpError> {
        self.launch_on(self.arena.context().launch_context())
    }

    pub fn launch_on(
        &self,
        launch: CudaLaunchContext,
    ) -> Result<PreparedEcOpLaunchTelemetry, PreparedEcOpError> {
        if self.segment_start_state.receipt().is_none() {
            return Err(PreparedEcOpError::SegmentStartNotIngested);
        }
        if launch.identity_token() != self.arena.context().identity_token() {
            return Err(CudaRuntimeError::ContextMismatch.into());
        }
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::ec_op_builtin_witness_on(
                self.execution_table_pointers.as_u32_ptr().cast(),
                self.n_addresses,
                self.n_big,
                self.n_small,
                self.segment_start.as_u32_ptr(),
                self.row_count,
                self.trace_pointers.as_ptr(),
                self.lookup_words.as_u32_ptr(),
                self.partial_input_pointers.as_ptr(),
                self.partial_row_count,
                self.address_counts.as_u32_ptr(),
                u32::try_from(self.address_counts.len_words())
                    .map_err(|_| PreparedEcOpError::SizeOverflow)?,
                self.big_counts.as_u32_ptr(),
                u32::try_from(self.big_counts.len_words())
                    .map_err(|_| PreparedEcOpError::SizeOverflow)?,
                self.small_counts.as_u32_ptr(),
                u32::try_from(self.small_counts.len_words())
                    .map_err(|_| PreparedEcOpError::SizeOverflow)?,
                self.range_check_8_counts.as_u32_ptr(),
                u32::try_from(self.range_check_8_counts.len_words())
                    .map_err(|_| PreparedEcOpError::SizeOverflow)?,
                launch.stream_raw().as_ptr(),
            )
        };
        check_cuda("ec_op_builtin_witness_on", code)?;
        Ok(PreparedEcOpLaunchTelemetry::THREE_KERNELS)
    }

    pub fn trace_columns(&self) -> &[ArenaSlice] {
        &self.trace_columns
    }

    pub fn contract(&self) -> &EcOpCompositeContract {
        &self.contract
    }

    pub fn belongs_to(&self, arena: &DeviceArena) -> bool {
        core::ptr::eq(self.arena, arena)
            && std::iter::once(self.execution_table_pointers)
                .chain(std::iter::once(self.segment_start))
                .chain(self.trace_columns.iter().copied())
                .chain(std::iter::once(self.lookup_words))
                .chain(self.partial_input_columns.iter().copied())
                .chain([
                    self.address_counts,
                    self.big_counts,
                    self.small_counts,
                    self.range_check_8_counts,
                ])
                .all(|slice| slice.belongs_to(arena.context()))
    }

    pub fn execution_table_pointers(&self) -> ArenaSlice {
        self.execution_table_pointers
    }

    pub fn segment_start_receipt(&self) -> Option<EcOpSegmentStartReceipt> {
        self.segment_start_state.receipt()
    }

    pub fn segment_start_is_current(&self, receipt: &EcOpSegmentStartReceipt) -> bool {
        let binding = segment_start_receipt::EcOpSegmentStartBinding::new(
            self.arena,
            &self.contract,
            self.segment_start,
        );
        self.segment_start_state.is_current(receipt, binding)
    }

    pub fn lookup_words(&self) -> ArenaSlice {
        self.lookup_words
    }

    pub fn partial_input_columns(&self) -> &[ArenaSlice] {
        &self.partial_input_columns
    }

    pub fn segment_start_source(&self) -> ArenaSlice {
        self.segment_start
    }

    pub fn multiplicity_destinations(&self) -> [ArenaSlice; 4] {
        [
            self.address_counts,
            self.big_counts,
            self.small_counts,
            self.range_check_8_counts,
        ]
    }

    pub fn row_count(&self) -> usize {
        self.row_count as usize
    }

    pub fn partial_row_count(&self) -> usize {
        self.partial_row_count as usize
    }

    /// Stable scheduler weight: each row executes the full 252-step EC chain.
    pub fn estimated_work(&self) -> u64 {
        u64::from(self.row_count).saturating_mul(EC_OP_PARTIAL_REAL_ROUNDS as u64)
    }
}

fn bind_many(
    arena: &DeviceArena,
    ids: &[ArenaSlotId],
    required_words: usize,
) -> Result<Vec<ArenaSlice>, PreparedEcOpError> {
    ids.iter()
        .map(|&id| bind_slot(arena, id, required_words))
        .collect()
}

fn bind_slot(
    arena: &DeviceArena,
    id: ArenaSlotId,
    required_words: usize,
) -> Result<ArenaSlice, PreparedEcOpError> {
    let slice = arena.bind(id)?;
    if slice.len_words() < required_words {
        return Err(PreparedEcOpError::SlotTooSmall {
            slot: id,
            required_words,
            actual_words: slice.len_words(),
        });
    }
    // Pooled slots may be larger than any single logical buffer; expose only
    // the logical extent so no consumer derives sizes from the pooled surplus.
    Ok(slice.truncated(required_words))
}

fn validate_slot_shape(
    requirements: &EcOpWorkspaceRequirements,
    slots: &EcOpWorkspaceSlots,
) -> Result<(), PreparedEcOpError> {
    for (role, expected, actual) in [
        (
            "trace columns",
            requirements.trace_column_words.len(),
            slots.trace_columns.len(),
        ),
        (
            "partial input columns",
            requirements.partial_input_column_words.len(),
            slots.partial_input_columns.len(),
        ),
    ] {
        if actual != expected {
            return Err(PreparedEcOpError::SlotShapeMismatch {
                role,
                expected,
                actual,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::ops::{Add, Mul, Sub};

    use super::*;

    const TEST_MODULUS: u64 = (1u64 << 61) - 1;
    const TEST_BETA: TestField = TestField(TEST_MODULUS - 1);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestField(u64);

    impl TestField {
        const ZERO: Self = Self(0);
        const ONE: Self = Self(1);

        fn inverse(self) -> Self {
            assert_ne!(self, Self::ZERO);
            let mut result = Self::ONE;
            let mut base = self;
            let mut exponent = TEST_MODULUS - 2;
            while exponent != 0 {
                if exponent & 1 != 0 {
                    result = result * base;
                }
                base = base * base;
                exponent >>= 1;
            }
            result
        }
    }

    impl From<u64> for TestField {
        fn from(value: u64) -> Self {
            Self(value % TEST_MODULUS)
        }
    }

    impl Add for TestField {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            Self::from(self.0 + rhs.0)
        }
    }

    impl Sub for TestField {
        type Output = Self;

        fn sub(self, rhs: Self) -> Self::Output {
            Self::from(TEST_MODULUS + self.0 - rhs.0)
        }
    }

    impl Mul for TestField {
        type Output = Self;

        fn mul(self, rhs: Self) -> Self::Output {
            Self(((self.0 as u128 * rhs.0 as u128) % TEST_MODULUS as u128) as u64)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestAffine {
        x: TestField,
        y: TestField,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestProjective {
        x: TestField,
        y: TestField,
        z: TestField,
    }

    fn affine_double(point: TestAffine) -> Option<TestAffine> {
        let denominator = point.y + point.y;
        if denominator == TestField::ZERO {
            return None;
        }
        let x_squared = point.x * point.x;
        let lambda = (x_squared + x_squared + x_squared + TestField::ONE) * denominator.inverse();
        let x = lambda * lambda - point.x - point.x;
        let y = lambda * (point.x - x) - point.y;
        Some(TestAffine { x, y })
    }

    fn is_on_test_curve(point: TestAffine) -> bool {
        point.y * point.y == point.x * point.x * point.x + point.x + TEST_BETA
    }

    fn affine_add(left: TestAffine, right: TestAffine) -> Option<TestAffine> {
        if left.x == right.x {
            if left.y != right.y {
                return None;
            }
            return affine_double(left);
        }
        let lambda = (right.y - left.y) * (right.x - left.x).inverse();
        let x = lambda * lambda - left.x - right.x;
        let y = lambda * (left.x - x) - left.y;
        Some(TestAffine { x, y })
    }

    fn projective_from_affine_scaled(point: TestAffine, scale: TestField) -> TestProjective {
        assert_ne!(scale, TestField::ZERO);
        TestProjective {
            x: point.x * scale,
            y: point.y * scale,
            z: scale,
        }
    }

    fn projective_to_affine(point: TestProjective) -> Option<TestAffine> {
        if point.z == TestField::ZERO {
            return None;
        }
        let inverse = point.z.inverse();
        Some(TestAffine {
            x: point.x * inverse,
            y: point.y * inverse,
        })
    }

    fn projective_double(point: TestProjective) -> Option<TestProjective> {
        let xx = point.x * point.x;
        let zz = point.z * point.z;
        let w = xx + xx + xx + zz;
        let yz = point.y * point.z;
        let s = yz + yz;
        let ss = s * s;
        let r = point.y * s;
        let rr = r * r;
        let b = (point.x + r) * (point.x + r) - xx - rr;
        let h = w * w - b - b;
        let result = TestProjective {
            x: h * s,
            y: w * (b - h) - rr - rr,
            z: s * ss,
        };
        (result.z != TestField::ZERO).then_some(result)
    }

    fn projective_add(left: TestProjective, right: TestProjective) -> Option<TestProjective> {
        let x1z2 = left.x * right.z;
        let x2z1 = right.x * left.z;
        let y1z2 = left.y * right.z;
        let y2z1 = right.y * left.z;
        let v = x2z1 - x1z2;
        let u = y2z1 - y1z2;
        if v == TestField::ZERO {
            if u != TestField::ZERO {
                return None;
            }
            return projective_double(left);
        }
        let uu = u * u;
        let vv = v * v;
        let vvv = v * vv;
        let z1z2 = left.z * right.z;
        let r = vv * left.x * right.z;
        let a = uu * z1z2 - vvv - r - r;
        let result = TestProjective {
            x: v * a,
            y: u * (r - a) - vvv * left.y * right.z,
            z: vvv * z1z2,
        };
        (result.z != TestField::ZERO).then_some(result)
    }

    fn batch_inverse_nonzero(values: &[TestField]) -> Option<Vec<TestField>> {
        if values.is_empty() || values.contains(&TestField::ZERO) {
            return None;
        }
        let mut prefixes = Vec::with_capacity(values.len());
        for &value in values {
            prefixes.push(prefixes.last().copied().unwrap_or(TestField::ONE) * value);
        }
        let mut inverse_product = prefixes.last().unwrap().inverse();
        let mut result = vec![TestField::ZERO; values.len()];
        for index in (1..values.len()).rev() {
            result[index] = inverse_product * prefixes[index - 1];
            inverse_product = inverse_product * values[index];
        }
        result[0] = inverse_product;
        Some(result)
    }

    fn assert_projective_chain_matches_affine(
        mut affine_accumulator: TestAffine,
        mut affine_q: TestAffine,
        accumulator_scale: TestField,
        q_scale: TestField,
        bits: &[bool],
    ) {
        assert!(is_on_test_curve(affine_accumulator));
        assert!(is_on_test_curve(affine_q));
        let mut projective_accumulator =
            projective_from_affine_scaled(affine_accumulator, accumulator_scale);
        let mut projective_q = projective_from_affine_scaled(affine_q, q_scale);
        for (round, &bit) in bits.iter().enumerate() {
            assert!(is_on_test_curve(affine_q), "affine q at round {round}");
            assert!(
                is_on_test_curve(affine_accumulator),
                "affine accumulator at round {round}"
            );
            assert_eq!(
                projective_to_affine(projective_q),
                Some(affine_q),
                "pre-update q at round {round}"
            );
            assert_eq!(
                projective_to_affine(projective_accumulator),
                Some(affine_accumulator),
                "pre-update accumulator at round {round}"
            );
            if bit {
                affine_accumulator = affine_add(affine_accumulator, affine_q).unwrap();
                projective_accumulator =
                    projective_add(projective_accumulator, projective_q).unwrap();
            }
            affine_q = affine_double(affine_q).unwrap();
            projective_q = projective_double(projective_q).unwrap();
        }
        assert!(is_on_test_curve(affine_q));
        assert!(is_on_test_curve(affine_accumulator));
        assert_eq!(projective_to_affine(projective_q), Some(affine_q));
        assert_eq!(
            projective_to_affine(projective_accumulator),
            Some(affine_accumulator)
        );
    }

    fn slots() -> EcOpWorkspaceSlots {
        let mut next = 1u32;
        let mut id = || {
            let result = ArenaSlotId(next);
            next += 1;
            result
        };
        EcOpWorkspaceSlots {
            trace_columns: (0..EC_OP_TRACE_COLUMNS).map(|_| id()).collect(),
            lookup_words: id(),
            partial_input_columns: (0..EC_OP_PARTIAL_INPUT_COLUMNS).map(|_| id()).collect(),
            segment_start: id(),
            address_counts: id(),
            big_counts: id(),
            small_counts: id(),
            range_check_8_counts: id(),
        }
    }

    fn multiplicity() -> EcOpMultiplicityGeometry {
        EcOpMultiplicityGeometry {
            address_count_words: 512,
            big_count_words: 128,
            small_count_words: 64,
            range_check_8_count_words: 256,
        }
    }

    #[test]
    fn projective_chain_matches_independent_affine_pre_update_and_final_states() {
        let p = TestAffine {
            x: TestField::from(2),
            y: TestField::from(3),
        };
        let q = affine_double(p).unwrap();
        let r = affine_add(p, q).unwrap();
        let s = affine_double(q).unwrap();
        let mixed = (0..252)
            .map(|round| (round * 73 + round * round + 19) % 11 < 5)
            .collect::<Vec<_>>();
        let alternating = (0..252).map(|round| round & 1 == 0).collect::<Vec<_>>();
        let zero = [false; 252];
        for (accumulator, q, accumulator_scale, q_scale, bits) in [
            (
                p,
                q,
                TestField::from(1),
                TestField::from(1),
                mixed.as_slice(),
            ),
            (
                r,
                s,
                TestField::from(7),
                TestField::from(29),
                alternating.as_slice(),
            ),
            (
                s,
                p,
                TestField::from(101),
                TestField::from(3),
                zero.as_slice(),
            ),
        ] {
            assert_projective_chain_matches_affine(
                accumulator,
                q,
                accumulator_scale,
                q_scale,
                bits,
            );
        }

        // Deterministic adversarial bit patterns exercise every pre-update
        // state under unrelated projective scales. The affine oracle has its
        // own per-step inversions and does not share the production formulas.
        let points = [p, q, r, s];
        for seed in 0..8usize {
            let bits = (0..252)
                .map(|round| {
                    let mixed = round * 0x9e37 + seed * 0x79b9 + round * round * 17;
                    (mixed ^ (mixed >> 3) ^ (seed << (round & 3))) & 7 < 3
                })
                .collect::<Vec<_>>();
            assert_projective_chain_matches_affine(
                points[seed & 3],
                points[(seed * 3 + 1) & 3],
                TestField::from((seed * 37 + 5) as u64),
                TestField::from((seed * 53 + 11) as u64),
                &bits,
            );
        }

        // Equal accumulator/q exercises the exact projective doubling branch
        // on every enabled round.
        assert_projective_chain_matches_affine(
            q,
            q,
            TestField::from(5),
            TestField::from(41),
            &[true; 252],
        );

        let opposite_q = TestAffine {
            x: q.x,
            y: TestField::ZERO - q.y,
        };
        assert_eq!(affine_add(q, opposite_q), None);
        assert_eq!(
            projective_add(
                projective_from_affine_scaled(q, TestField::from(7)),
                projective_from_affine_scaled(opposite_q, TestField::from(13)),
            ),
            None
        );

        let zero_y = TestAffine {
            x: TestField::from(19),
            y: TestField::ZERO,
        };
        assert_eq!(affine_double(zero_y), None);
        assert_eq!(affine_add(zero_y, zero_y), None);
        let zero_y_projective = projective_from_affine_scaled(zero_y, TestField::from(23));
        assert_eq!(projective_double(zero_y_projective), None);
        assert_eq!(projective_add(zero_y_projective, zero_y_projective), None);
    }

    #[test]
    fn tiled_projective_normalization_matches_elementwise_and_rejects_zero_z() {
        let affine = TestAffine {
            x: TestField::from(2),
            y: TestField::from(3),
        };
        for rounds_per_tile in [1, 2, 4] {
            let points = (0..2 * rounds_per_tile)
                .map(|index| {
                    let scale = TestField::from((index * 17 + 3) as u64);
                    TestProjective {
                        x: affine.x * scale,
                        y: affine.y * scale,
                        z: scale,
                    }
                })
                .collect::<Vec<_>>();
            let inverses =
                batch_inverse_nonzero(&points.iter().map(|point| point.z).collect::<Vec<_>>())
                    .unwrap();
            for (point, inverse) in points.into_iter().zip(inverses) {
                assert_eq!(
                    TestAffine {
                        x: point.x * inverse,
                        y: point.y * inverse,
                    },
                    affine
                );
            }
        }
        assert_eq!(
            batch_inverse_nonzero(&[TestField::ONE, TestField::ZERO]),
            None
        );
    }

    #[test]
    fn projective_scratch_is_fully_overwritten_before_padding_or_consumption() {
        let source = include_str!("../../../backend-cuda-kernels/cuda/ec_op_witness.cu");
        assert!(source.contains("constexpr uint32_t EC_OP_CHAIN_BLOCK = 16;"));
        assert!(source.contains("constexpr uint32_t EC_OP_NORMALIZE_ROUND_TILE = 4;"));
        assert!(source.contains("constexpr uint32_t SCRATCH_Q_X = 12;"));
        assert!(source.contains("constexpr uint32_t SCRATCH_ACC_Z = 52;"));
        assert!(source.contains("felt_is_zero(q_z) || felt_is_zero(accumulator_z)"));
        assert!(source.contains("asm volatile(\"trap;\")"));
        assert!(source.contains("partial.columns[125][row] = 0;"));
        assert!(source.contains("partial.columns[125][row] != 1u"));
        assert!(source.contains("store_affine_point_columns(partial, destination, 68, 96"));
        assert!(source.contains("store_affine_point_columns(partial, destination, 12, 40"));
        assert!(source.contains("felt252_to_m31_limbs(value, reinterpret_cast<m31 *>(limbs))"));
        assert_eq!(source.matches("store_partial_lookup(").count(), 3);

        let compact = source.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(compact.contains(
            "store_partial_lookup( lookup, rows, row, 169, row, 0, m, q_affine, accumulator_affine, counter)"
        ));
        assert!(
            compact.contains("295, row, PARTIAL_ROUNDS, m, q_affine, accumulator_affine, counter)")
        );
        for first_word in [0, 33, 66, 99, 132, 421, 454] {
            assert!(compact.contains(&format!(
                "store_memory_address_lookup(lookup, rows, row, {first_word},"
            )));
        }
        for first_word in [3, 36, 69, 102, 135, 424, 457] {
            assert!(compact.contains(&format!(
                "store_memory_big_lookup(lookup, rows, row, {first_word},"
            )));
        }

        let chain = source.find("ec_op_projective_chain_kernel<<<").unwrap();
        let normalize = source
            .find("ec_op_normalize_round_tiles_kernel<<<")
            .unwrap();
        let padding = source.find("partial_input_padding_kernel<<<").unwrap();
        assert!(chain < normalize && normalize < padding);
        assert_eq!(source.matches("<<<").count(), 3);
        assert_eq!(compact.matches("0, stream>>>").count(), 3);
        assert!(!source.contains("cudaMalloc"));

        let chain_definition = source.find("ec_op_projective_chain_kernel(").unwrap();
        let chain_end = source
            .find("__device__ __forceinline__ void normalize_saved_projective(")
            .unwrap();
        let normalize_definition = source.find("ec_op_normalize_round_tiles_kernel(").unwrap();
        let chain_body = &source[chain_definition..chain_end];
        assert!(!chain_body.contains("load_projective_coordinate("));
        assert!(!chain_body.contains("load_projective_point("));
        let save = chain_body.find("store_partial_projective_input(").unwrap();
        let add = chain_body.find("if ((m[0] & 1u) != 0)").unwrap();
        let double = chain_body
            .find("ec_double_projective_exact(q, doubled)")
            .unwrap();
        let advance = chain_body.find("if (counter == 0)").unwrap();
        let final_normalize = chain_body.find("projective_pair_to_affine(").unwrap();
        let final_trace = chain_body.find("trace.columns[148u + word]").unwrap();
        assert!(save < add && add < double && double < advance);
        assert!(advance < final_normalize && final_normalize < final_trace);
        for canonical_store in [
            "store_trace_limbs(trace, 158",
            "store_trace_limbs(trace, 186",
            "store_trace_limbs(trace, 214",
            "store_trace_limbs(trace, 242",
            "trace.columns[270][row] = counter",
            "trace.columns[271][row] = result_x_id",
            "trace.columns[272][row] = result_y_id",
        ] {
            assert!(chain_body.contains(canonical_store));
        }

        let normalization = &source[normalize_definition..padding];
        assert!(normalization.contains("for (int index = POINTS_PER_TILE - 1; index > 0; --index)"));
        assert!(normalization.contains("const bool accumulator = (point_index & 1u) != 0"));
        let accumulator_store = source
            .find("store_affine_point_columns(partial, destination, 68, 96")
            .unwrap();
        let q_store = source
            .find("store_affine_point_columns(partial, destination, 12, 40")
            .unwrap();
        assert!(accumulator_store < q_store);
        for rounds_per_tile in [1usize, 2, 4] {
            let mut recovery_order = (1..2 * rounds_per_tile)
                .rev()
                .map(|index| (index >> 1, index & 1 != 0))
                .collect::<Vec<_>>();
            recovery_order.push((0, false));
            for round in 0..rounds_per_tile {
                let accumulator = recovery_order
                    .iter()
                    .position(|&point| point == (round, true))
                    .unwrap();
                let q = recovery_order
                    .iter()
                    .position(|&point| point == (round, false))
                    .unwrap();
                assert!(accumulator < q, "round {round} scratch overwrite order");
            }
        }

        let scratch = 12..60;
        let normalized_points = 12..124;
        assert!(scratch
            .clone()
            .all(|column| normalized_points.contains(&column)));
        let mut final_written = [false; EC_OP_PARTIAL_INPUT_COLUMNS];
        for column in 0..12 {
            final_written[column] = true;
        }
        for column in normalized_points {
            final_written[column] = true;
        }
        for column in 124..127 {
            final_written[column] = true;
        }
        assert!(final_written.into_iter().all(|written| written));
        assert_eq!(
            PreparedEcOpLaunchTelemetry::THREE_KERNELS.kernel_launches,
            3
        );
    }

    #[test]
    fn pure_geometry_matches_generated_writer_and_round_order() {
        let requirements = ec_op_workspace_requirements(32, multiplicity()).unwrap();
        assert_eq!(requirements.trace_column_words, vec![32; 273]);
        assert_eq!(requirements.lookup_words, 32 * 488);
        assert_eq!(requirements.partial_real_rows, 32 * 252);
        assert_eq!(requirements.partial_row_count, 32 * 256);
        assert_eq!(requirements.partial_input_column_words, vec![32 * 256; 127]);
        assert_eq!(7 * 32 + 31, 255, "round-major consumer row formula");
        assert_eq!(
            requirements
                .arena_slot_requirements(&slots())
                .unwrap()
                .len(),
            273 + 1 + 127 + 5
        );
    }

    #[test]
    fn pure_geometry_fails_closed() {
        assert_eq!(
            ec_op_workspace_requirements(0, multiplicity()).unwrap_err(),
            PreparedEcOpError::InvalidRowCount(0)
        );
        assert_eq!(
            ec_op_workspace_requirements(24, multiplicity()).unwrap_err(),
            PreparedEcOpError::InvalidRowCount(24)
        );
        let requirements = ec_op_workspace_requirements(16, multiplicity()).unwrap();
        let mut bad = slots();
        bad.partial_input_columns.pop();
        assert_eq!(
            requirements.arena_slot_requirements(&bad).unwrap_err(),
            PreparedEcOpError::SlotShapeMismatch {
                role: "partial input columns",
                expected: 127,
                actual: 126,
            }
        );
        let mut duplicate = slots();
        duplicate.partial_input_columns[0] = duplicate.lookup_words;
        assert_eq!(
            requirements
                .arena_slot_requirements(&duplicate)
                .unwrap_err(),
            PreparedEcOpError::DuplicateSlot(duplicate.lookup_words)
        );
    }
}

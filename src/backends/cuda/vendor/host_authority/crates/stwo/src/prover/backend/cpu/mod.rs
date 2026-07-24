pub mod accumulation;
mod blake2s;
pub mod circle;
mod fri;
mod grind;
pub mod lookups;
mod merkle_lifted;
#[cfg(not(target_arch = "wasm32"))]
mod poseidon252;
pub mod quotients;

use std::fmt::Debug;

pub use fri::{fold_circle_into_line_cpu, fold_line_cpu};
use serde::{Deserialize, Serialize};

use super::{Backend, BackendForChannel, Column, ColumnOps};
use crate::core::utils::bit_reverse;
use crate::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sMerkleChannel};
use crate::core::vcs_lifted::keccak256_merkle::Keccak256MerkleChannel;
#[cfg(not(target_arch = "wasm32"))]
use crate::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
use crate::prover::lookups::mle::Mle;
use crate::prover::poly::circle::{CircleCoefficients, CircleEvaluation};

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct CpuBackend;

impl Backend for CpuBackend {}
#[cfg(not(test))]
impl BackendForChannel<Blake2sMerkleChannel> for CpuBackend {}
#[cfg(test)]
impl BackendForChannel<Blake2sMerkleChannel> for CpuBackend {
    fn prove_values_driver<'a>(
        commitment_scheme: crate::prover::pcs::CommitmentSchemeProver<
            'a,
            Self,
            Blake2sMerkleChannel,
        >,
        sampled_points: crate::core::pcs::TreeVec<
            crate::core::ColumnVec<
                Vec<crate::core::circle::CirclePoint<crate::core::fields::qm31::SecureField>>,
            >,
        >,
        channel: &mut crate::core::channel::Blake2sChannel,
    ) -> crate::core::pcs::quotients::ExtendedCommitmentSchemeProof<
        <Blake2sMerkleChannel as crate::core::channel::MerkleChannel>::H,
    > {
        PROVE_VALUES_DRIVER_CALLED.with(|called| called.set(true));
        let mut observer = CpuTestStageObserver;
        commitment_scheme.prove_values_with_stage_observer(sampled_points, channel, &mut observer)
    }
}
impl BackendForChannel<Blake2sM31MerkleChannel> for CpuBackend {}
impl BackendForChannel<Keccak256MerkleChannel> for CpuBackend {}
#[cfg(not(target_arch = "wasm32"))]
impl BackendForChannel<Poseidon252MerkleChannel> for CpuBackend {}

impl<T: Debug + Clone + Default + Send + Sync> ColumnOps<T> for CpuBackend {
    type Column = Vec<T>;

    fn bit_reverse_column(column: &mut Self::Column) {
        bit_reverse(column)
    }
}

impl<T: Debug + Clone + Default + Send + Sync> Column<T> for Vec<T> {
    fn zeros(len: usize) -> Self {
        vec![T::default(); len]
    }
    #[allow(clippy::uninit_vec)]
    unsafe fn uninitialized(length: usize) -> Self {
        let mut data = Vec::with_capacity(length);
        data.set_len(length);
        data
    }
    fn to_cpu(&self) -> Vec<T> {
        self.clone()
    }
    fn len(&self) -> usize {
        self.len()
    }
    fn at(&self, index: usize) -> T {
        self[index].clone()
    }
    fn set(&mut self, index: usize, value: T) {
        self[index] = value;
    }
    fn split_at_mid(mut self) -> (Self, Self) {
        let second = self.split_off(self.len() / 2);
        (self, second)
    }
    fn shrink_to_fit(&mut self) {
        Vec::shrink_to_fit(self);
    }
}

#[cfg(test)]
std::thread_local! {
    static PROVE_VALUES_DRIVER_CALLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static PROVE_VALUES_DRIVER_STAGES: std::cell::RefCell<Vec<crate::prover::pcs::proof_driver::PcsProofStage>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
struct CpuTestStageObserver;

#[cfg(test)]
impl crate::prover::pcs::proof_driver::PcsProofStageObserver for CpuTestStageObserver {
    fn stage_finished(&mut self, stage: crate::prover::pcs::proof_driver::PcsProofStage) {
        PROVE_VALUES_DRIVER_STAGES.with(|stages| stages.borrow_mut().push(stage));
    }
}

#[cfg(test)]
pub(crate) fn take_prove_values_driver_called() -> bool {
    PROVE_VALUES_DRIVER_CALLED.with(|called| called.replace(false))
}

#[cfg(test)]
pub(crate) fn take_prove_values_driver_stages(
) -> Vec<crate::prover::pcs::proof_driver::PcsProofStage> {
    PROVE_VALUES_DRIVER_STAGES.with(|stages| std::mem::take(&mut *stages.borrow_mut()))
}

pub type CpuCirclePoly = CircleCoefficients<CpuBackend>;
pub type CpuCircleEvaluation<F, EvalOrder> = CircleEvaluation<CpuBackend, F, EvalOrder>;
pub type CpuMle<F> = Mle<CpuBackend, F>;

#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use rand::prelude::*;
    use rand::rngs::SmallRng;

    use crate::core::fields::qm31::QM31;
    use crate::core::fields::{batch_inverse_in_place, FieldExpOps};
    use crate::prover::backend::cpu::bit_reverse;
    use crate::prover::backend::Column;

    #[test]
    fn bit_reverse_works() {
        let mut data = [0, 1, 2, 3, 4, 5, 6, 7];
        bit_reverse(&mut data);
        assert_eq!(data, [0, 4, 2, 6, 1, 5, 3, 7]);
    }

    #[test]
    #[should_panic]
    fn bit_reverse_non_power_of_two_size_fails() {
        let mut data = [0, 1, 2, 3, 4, 5];
        bit_reverse(&mut data);
    }

    // TODO(Ohad): remove.
    #[test]
    fn batch_inverse_in_place_test() {
        let mut rng = SmallRng::seed_from_u64(0);
        let column = rng.gen::<[QM31; 16]>().to_vec();
        let expected = column.iter().map(|e| e.inverse()).collect_vec();
        let mut dst = Vec::zeros(column.len());

        batch_inverse_in_place(&column, &mut dst);

        assert_eq!(expected, dst);
    }

    #[test]
    fn test_split_at_mid_cpu_column() {
        let values = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let col: Vec<_> = values.into_iter().collect();
        let (lhs, rhs) = col.split_at_mid();
        assert_eq!(lhs, vec![1, 2, 3, 4]);
        assert_eq!(rhs, vec![5, 6, 7, 8]);
    }
}

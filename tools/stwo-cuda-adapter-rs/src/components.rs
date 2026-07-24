use crate::model::{
    BlakeComponent, PlonkComponent, PoseidonComponent, StateMachineComponent,
    WideFibonacciComponent, XorComponent, POSEIDON_COLUMNS,
};
use crate::statements::{
    blake_composition_eval, plonk_composition_eval, poseidon_composition_eval, xor_composition_eval,
};
use crate::traces::{blake_n_columns, poseidon_log_n_rows};
use num_traits::Zero;
use stwo::core::air::accumulation::PointEvaluationAccumulator;
use stwo::core::air::Component;
use stwo::core::circle::CirclePoint;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse;
use stwo::prover::backend::{Backend, Column};
use stwo::prover::{ColumnAccumulator, ComponentProver, DomainEvaluationAccumulator, Trace};

impl Component for StateMachineComponent {
    fn n_constraints(&self) -> usize {
        1
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.trace_log_size + 1
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<Vec<u32>> {
        TreeVec::new(vec![
            vec![self.trace_log_size],
            vec![self.trace_log_size, self.trace_log_size],
        ])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        _max_log_degree_bound: u32,
    ) -> TreeVec<Vec<Vec<CirclePoint<SecureField>>>> {
        TreeVec::new(vec![vec![vec![]], vec![vec![point], vec![point]]])
    }

    fn preprocessed_column_indices(&self) -> Vec<usize> {
        vec![0]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        _point: CirclePoint<SecureField>,
        _mask: &TreeVec<Vec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        _max_log_degree_bound: u32,
    ) {
        evaluation_accumulator.accumulate(self.composition_eval);
    }
}

fn accumulate<B: Backend>(
    column: &mut ColumnAccumulator<'_, B>,
    index: usize,
    evaluation: SecureField,
) {
    let value = column.col.at(index) + evaluation;
    column.col.set(index, value);
}

impl<B: Backend> ComponentProver<B> for StateMachineComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        _trace: &Trace<'_, B>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<B>,
    ) {
        let [mut col] = evaluation_accumulator.columns([(self.trace_log_size + 1, 1)]);
        let domain_size = 1usize << (self.trace_log_size + 1);
        for i in 0..domain_size {
            accumulate(&mut col, i, self.composition_eval);
        }
    }
}

impl Component for WideFibonacciComponent {
    fn n_constraints(&self) -> usize {
        self.statement.sequence_len as usize - 2
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.statement.log_n_rows + 1
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<Vec<u32>> {
        TreeVec::new(vec![
            vec![],
            vec![self.statement.log_n_rows; self.statement.sequence_len as usize],
        ])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        _max_log_degree_bound: u32,
    ) -> TreeVec<Vec<Vec<CirclePoint<SecureField>>>> {
        TreeVec::new(vec![
            vec![],
            vec![vec![point]; self.statement.sequence_len as usize],
        ])
    }

    fn preprocessed_column_indices(&self) -> Vec<usize> {
        vec![]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        point: CirclePoint<SecureField>,
        mask: &TreeVec<Vec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        _max_log_degree_bound: u32,
    ) {
        let main = &mask[1];
        assert_eq!(main.len(), self.statement.sequence_len as usize);
        assert!(main.iter().all(|column| column.len() == 1));

        let denominator_inv =
            coset_vanishing(CanonicCoset::new(self.statement.log_n_rows).coset, point).inverse();

        let mut a = main[0][0];
        let mut b = main[1][0];
        for column in &main[2..] {
            let c = column[0];
            evaluation_accumulator.accumulate((c - (a.square() + b.square())) * denominator_inv);
            a = b;
            b = c;
        }
    }
}

impl<B: Backend> ComponentProver<B> for WideFibonacciComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        trace: &Trace<'_, B>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<B>,
    ) {
        let n_constraints = self.n_constraints();
        let trace_domain = CanonicCoset::new(self.statement.log_n_rows);
        let eval_domain = CanonicCoset::new(self.statement.log_n_rows + 1).circle_domain();
        let twiddles = B::precompute_twiddles(eval_domain.half_coset);
        let trace_cols = trace.polys[1]
            .iter()
            .map(|poly| poly.get_evaluation_on_domain(eval_domain, &twiddles))
            .collect::<Vec<_>>();
        assert_eq!(trace_cols.len(), self.statement.sequence_len as usize);

        let mut denominator_inv = (0..2)
            .map(|i| coset_vanishing(trace_domain.coset, eval_domain.at(i)).inverse())
            .collect::<Vec<_>>();
        bit_reverse(&mut denominator_inv);

        let [mut col] =
            evaluation_accumulator.columns([(self.statement.log_n_rows + 1, n_constraints)]);
        for row in 0..eval_domain.size() {
            let mut a = trace_cols[0].at(row);
            let mut b = trace_cols[1].at(row);
            let mut row_evaluation = SecureField::zero();
            for (constraint_index, column) in trace_cols[2..].iter().enumerate() {
                let c = column.at(row);
                let constraint = c - (a.square() + b.square());
                row_evaluation +=
                    col.random_coeff_powers[n_constraints - 1 - constraint_index] * constraint;
                a = b;
                b = c;
            }
            accumulate(
                &mut col,
                row,
                row_evaluation * denominator_inv[row >> self.statement.log_n_rows],
            );
        }
    }
}

impl Component for PlonkComponent {
    fn n_constraints(&self) -> usize {
        1
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.statement.log_n_rows + 1
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<Vec<u32>> {
        TreeVec::new(vec![
            vec![self.statement.log_n_rows; 4],
            vec![self.statement.log_n_rows; 4],
        ])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        _max_log_degree_bound: u32,
    ) -> TreeVec<Vec<Vec<CirclePoint<SecureField>>>> {
        TreeVec::new(vec![vec![vec![point]; 4], vec![vec![point]; 4]])
    }

    fn preprocessed_column_indices(&self) -> Vec<usize> {
        vec![0, 1, 2, 3]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        _point: CirclePoint<SecureField>,
        _mask: &TreeVec<Vec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        _max_log_degree_bound: u32,
    ) {
        evaluation_accumulator.accumulate(plonk_composition_eval(self.statement));
    }
}

impl<B: Backend> ComponentProver<B> for PlonkComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        _trace: &Trace<'_, B>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<B>,
    ) {
        let composition_eval = plonk_composition_eval(self.statement);
        let [mut col] = evaluation_accumulator.columns([(self.statement.log_n_rows + 1, 1)]);
        let domain_size = 1usize << (self.statement.log_n_rows + 1);
        for i in 0..domain_size {
            accumulate(&mut col, i, composition_eval);
        }
    }
}

impl Component for PoseidonComponent {
    fn n_constraints(&self) -> usize {
        1
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        poseidon_log_n_rows(self.statement).unwrap_or(0) + 1
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<Vec<u32>> {
        let log_n_rows = poseidon_log_n_rows(self.statement).unwrap_or(0);
        TreeVec::new(vec![vec![], vec![log_n_rows; POSEIDON_COLUMNS]])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        _max_log_degree_bound: u32,
    ) -> TreeVec<Vec<Vec<CirclePoint<SecureField>>>> {
        TreeVec::new(vec![vec![], vec![vec![point]; POSEIDON_COLUMNS]])
    }

    fn preprocessed_column_indices(&self) -> Vec<usize> {
        vec![]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        _point: CirclePoint<SecureField>,
        _mask: &TreeVec<Vec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        _max_log_degree_bound: u32,
    ) {
        evaluation_accumulator.accumulate(poseidon_composition_eval(self.statement));
    }
}

impl<B: Backend> ComponentProver<B> for PoseidonComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        _trace: &Trace<'_, B>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<B>,
    ) {
        let log_n_rows = poseidon_log_n_rows(self.statement).unwrap_or(0);
        let composition_eval = poseidon_composition_eval(self.statement);
        let [mut col] = evaluation_accumulator.columns([(log_n_rows + 1, 1)]);
        let domain_size = 1usize << (log_n_rows + 1);
        for i in 0..domain_size {
            accumulate(&mut col, i, composition_eval);
        }
    }
}

impl Component for BlakeComponent {
    fn n_constraints(&self) -> usize {
        1
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.statement.log_n_rows + 1
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<Vec<u32>> {
        let n_columns = blake_n_columns(self.statement).unwrap_or(0);
        TreeVec::new(vec![vec![], vec![self.statement.log_n_rows; n_columns]])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        _max_log_degree_bound: u32,
    ) -> TreeVec<Vec<Vec<CirclePoint<SecureField>>>> {
        let n_columns = blake_n_columns(self.statement).unwrap_or(0);
        TreeVec::new(vec![vec![], vec![vec![point]; n_columns]])
    }

    fn preprocessed_column_indices(&self) -> Vec<usize> {
        vec![]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        _point: CirclePoint<SecureField>,
        _mask: &TreeVec<Vec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        _max_log_degree_bound: u32,
    ) {
        evaluation_accumulator.accumulate(blake_composition_eval(self.statement));
    }
}

impl<B: Backend> ComponentProver<B> for BlakeComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        _trace: &Trace<'_, B>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<B>,
    ) {
        let composition_eval = blake_composition_eval(self.statement);
        let [mut col] = evaluation_accumulator.columns([(self.statement.log_n_rows + 1, 1)]);
        let domain_size = 1usize << (self.statement.log_n_rows + 1);
        for i in 0..domain_size {
            accumulate(&mut col, i, composition_eval);
        }
    }
}

impl Component for XorComponent {
    fn n_constraints(&self) -> usize {
        1
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.statement.log_size + 1
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<Vec<u32>> {
        TreeVec::new(vec![
            vec![self.statement.log_size, self.statement.log_size],
            vec![self.statement.log_size],
        ])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        _max_log_degree_bound: u32,
    ) -> TreeVec<Vec<Vec<CirclePoint<SecureField>>>> {
        TreeVec::new(vec![vec![vec![], vec![]], vec![vec![point]]])
    }

    fn preprocessed_column_indices(&self) -> Vec<usize> {
        vec![0, 1]
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        _point: CirclePoint<SecureField>,
        _mask: &TreeVec<Vec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        _max_log_degree_bound: u32,
    ) {
        evaluation_accumulator.accumulate(xor_composition_eval(self.statement));
    }
}

impl<B: Backend> ComponentProver<B> for XorComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        _trace: &Trace<'_, B>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<B>,
    ) {
        let composition_eval = xor_composition_eval(self.statement);
        let [mut col] = evaluation_accumulator.columns([(self.statement.log_size + 1, 1)]);
        let domain_size = 1usize << (self.statement.log_size + 1);
        for i in 0..domain_size {
            accumulate(&mut col, i, composition_eval);
        }
    }
}

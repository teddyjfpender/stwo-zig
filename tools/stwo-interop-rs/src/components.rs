use crate::model::{BlakeComponent, PlonkComponent, WideFibonacciComponent, XorComponent};
use crate::statements::{blake_composition_eval, plonk_composition_eval, xor_combine};
use crate::traces::blake_n_columns;
use num_traits::{One, Zero};
use stwo::core::air::accumulation::PointEvaluationAccumulator;
use stwo::core::air::Component;
use stwo::core::circle::CirclePoint;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::{bit_reverse, previous_bit_reversed_circle_domain_index};
use stwo::prover::backend::{Backend, Column};
use stwo::prover::{ColumnAccumulator, ComponentProver, DomainEvaluationAccumulator, Trace};

fn accumulate<B: Backend>(
    column: &mut ColumnAccumulator<'_, B>,
    index: usize,
    evaluation: SecureField,
) {
    let value = column.col.at(index) + evaluation;
    column.col.set(index, value);
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
        14
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.statement.log_size + 1
    }

    fn trace_log_degree_bounds(&self) -> TreeVec<Vec<u32>> {
        TreeVec::new(vec![
            vec![self.statement.log_size; 7],
            vec![self.statement.log_size; 4],
            vec![self.statement.log_size; 4],
        ])
    }

    fn mask_points(
        &self,
        point: CirclePoint<SecureField>,
        max_log_degree_bound: u32,
    ) -> TreeVec<Vec<Vec<CirclePoint<SecureField>>>> {
        let previous = point
            - CanonicCoset::new(max_log_degree_bound)
                .step()
                .into_ef::<SecureField>();
        TreeVec::new(vec![
            vec![vec![point]; 7],
            vec![vec![point]; 4],
            vec![vec![point, previous]; 4],
        ])
    }

    fn preprocessed_column_indices(&self) -> Vec<usize> {
        (0..7).collect()
    }

    fn evaluate_constraint_quotients_at_point(
        &self,
        point: CirclePoint<SecureField>,
        mask: &TreeVec<Vec<Vec<SecureField>>>,
        evaluation_accumulator: &mut PointEvaluationAccumulator,
        max_log_degree_bound: u32,
    ) {
        assert!(mask.len() >= 3);
        assert_eq!(mask[0].len(), 7);
        assert_eq!(mask[1].len(), 4);
        assert_eq!(mask[2].len(), 4);
        let preprocessed = std::array::from_fn(|i| mask[0][i][0]);
        let main = std::array::from_fn(|i| mask[1][i][0]);
        let current = SecureField::from_partial_evals(std::array::from_fn(|i| mask[2][i][0]));
        let previous = SecureField::from_partial_evals(std::array::from_fn(|i| mask[2][i][1]));
        let folded_point = point.repeated_double(max_log_degree_bound - self.statement.log_size);
        let denominator_inv = coset_vanishing(
            CanonicCoset::new(self.statement.log_size).coset,
            folded_point,
        )
        .inverse();
        for constraint in xor_constraints(self, preprocessed, main, current, previous) {
            evaluation_accumulator.accumulate(constraint * denominator_inv);
        }
    }
}

impl<B: Backend> ComponentProver<B> for XorComponent {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        trace: &Trace<'_, B>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<B>,
    ) {
        assert_eq!(trace.polys.len(), 3);
        assert_eq!(trace.polys[0].len(), 7);
        assert_eq!(trace.polys[1].len(), 4);
        assert_eq!(trace.polys[2].len(), 4);

        let eval_log_size = self.statement.log_size + 1;
        let eval_domain = CanonicCoset::new(eval_log_size).circle_domain();
        let twiddles = B::precompute_twiddles(eval_domain.half_coset);
        let preprocessed = trace.polys[0]
            .iter()
            .map(|poly| poly.get_evaluation_on_domain(eval_domain, &twiddles))
            .collect::<Vec<_>>();
        let main = trace.polys[1]
            .iter()
            .map(|poly| poly.get_evaluation_on_domain(eval_domain, &twiddles))
            .collect::<Vec<_>>();
        let secure = trace.polys[2]
            .iter()
            .map(|poly| poly.get_evaluation_on_domain(eval_domain, &twiddles))
            .collect::<Vec<_>>();

        let trace_coset = CanonicCoset::new(self.statement.log_size);
        let denominator_inv = [
            coset_vanishing(trace_coset.coset, eval_domain.at(0)).inverse(),
            coset_vanishing(trace_coset.coset, eval_domain.at(1)).inverse(),
        ];
        let [mut col] = evaluation_accumulator.columns([(eval_log_size, 14)]);
        for row in 0..eval_domain.size() {
            let previous_row = previous_bit_reversed_circle_domain_index(
                row,
                self.statement.log_size,
                eval_log_size,
            );
            let pre_values = std::array::from_fn(|i| preprocessed[i].at(row).into());
            let main_values = std::array::from_fn(|i| main[i].at(row).into());
            let current = SecureField::from_m31_array(std::array::from_fn(|i| secure[i].at(row)));
            let previous =
                SecureField::from_m31_array(std::array::from_fn(|i| secure[i].at(previous_row)));
            let constraints = xor_constraints(self, pre_values, main_values, current, previous);
            let mut combined = SecureField::zero();
            for (constraint_index, constraint) in constraints.into_iter().enumerate() {
                combined += col.random_coeff_powers[13 - constraint_index] * constraint;
            }
            accumulate(
                &mut col,
                row,
                combined * denominator_inv[row >> self.statement.log_size],
            );
        }
    }
}

fn xor_constraints(
    component: &XorComponent,
    preprocessed: [SecureField; 7],
    main: [SecureField; 4],
    current: SecureField,
    previous: SecureField,
) -> [SecureField; 14] {
    let [is_first, is_step, row_bit, table_selector, table_a, table_b, table_c] = preprocessed;
    let [a, b, c, multiplicity] = main;
    let table_denominator = xor_combine(component.lookup_elements, table_a, table_b, table_c);
    let execution_denominator = xor_combine(component.lookup_elements, a, b, c);
    let delta = current - previous + is_first * component.statement.claimed_sum;
    let logup = delta * table_denominator * execution_denominator
        - multiplicity * execution_denominator
        + table_denominator;
    [
        boolean_constraint(is_first),
        boolean_constraint(a),
        boolean_constraint(b),
        boolean_constraint(c),
        xor_constraint(a, b, c),
        a - row_bit,
        b - is_step,
        boolean_constraint(table_selector),
        boolean_constraint(table_a),
        boolean_constraint(table_b),
        boolean_constraint(table_c),
        xor_constraint(table_a, table_b, table_c),
        multiplicity * (SecureField::one() - table_selector),
        logup,
    ]
}

fn boolean_constraint(value: SecureField) -> SecureField {
    value * (value - SecureField::one())
}

fn xor_constraint(a: SecureField, b: SecureField, c: SecureField) -> SecureField {
    c - a - b + SecureField::from(2u32) * a * b
}

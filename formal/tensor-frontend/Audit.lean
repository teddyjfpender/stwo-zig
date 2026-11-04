import TensorFrontend
-- Axiom audit: every headline theorem must depend on at most
-- propext, Classical.choice, Quot.sound (checked by scripts/check.sh).
#print axioms TensorFrontend.roots_le
#print axioms TensorFrontend.agree_count
#print axioms TensorFrontend.sumcheck_sound
#print axioms TensorFrontend.LogUp.num_allZero_iff
#print axioms TensorFrontend.LogUp.fsum_group
#print axioms TensorFrontend.LogUp.ncast_inj
#print axioms TensorFrontend.LogUp.logup_identity_sound
#print axioms TensorFrontend.LogUp.multisetOK_mem
#print axioms TensorFrontend.LogUp.logup_random_sound
#print axioms TensorFrontend.Kernel.fieldZero_small
#print axioms TensorFrontend.Kernel.requant_unique
#print axioms TensorFrontend.Kernel.matmul_sound
#print axioms TensorFrontend.Kernel.hadamard_sound
#print axioms TensorFrontend.Kernel.requant_einsum_sound
#print axioms TensorFrontend.Kernel.exact_einsum_sound
#print axioms TensorFrontend.Kernel.onehot_bound
#print axioms TensorFrontend.Kernel.lineq_sound
#print axioms TensorFrontend.Kernel.softmax_div_unique
#print axioms TensorFrontend.Kernel.softmax_div_err
#print axioms TensorFrontend.Kernel.softmax_div_sound
#print axioms TensorFrontend.Security.union_le
#print axioms TensorFrontend.Security.dyadic_union_sound
#print axioms TensorFrontend.Data.toy20Johnson_with_bits
#print axioms TensorFrontend.Data.toy20Johnson_without_bits
#print axioms TensorFrontend.Instance.gf2Field
#print axioms TensorFrontend.Instance.indDeg_zero
#print axioms TensorFrontend.Instance.gf2_char

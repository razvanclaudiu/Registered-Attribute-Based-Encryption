use ark_bls12_381::Fr;
use ark_ff::FftField;
use ark_std::vec::Vec;

/// Generates the M-th roots of unity: Ω = {ω^1, ω^2, ..., ω^M}
pub fn generate_omega(m: usize) -> Vec<Fr> {
    let omega_gen = Fr::get_root_of_unity(m as u64).expect(
        "Field does not contain a root of unity for this order. Ensure m divides (p-1)."
    );

    let mut omega = Vec::with_capacity(m);
    let mut current_power = omega_gen;

    for _ in 0..m {
        omega.push(current_power);
        // Step through powers: ω^1, ω^2, ..., ω^m 
        // ω^m = 1
        current_power *= omega_gen; 
    }

    omega
}
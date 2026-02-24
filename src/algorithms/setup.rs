use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use ark_std::vec::Vec;
use rand::thread_rng; 

use crate::entities::crs::CRS;

pub fn setup(m: usize) -> CRS {
    let mut rng = thread_rng();
    let tau: Fr = Fr::rand(&mut rng);

    // crs = ([tau^1]_1, ..., [tau^m]_1, [tau^1]_2, ..., [tau^m]_2) 
    let mut g1_powers = Vec::with_capacity(m);
    let mut g2_powers = Vec::with_capacity(m);

    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();

    let mut current_tau_pow = tau;

    for _ in 1..=m {
        // Compute [tau^i]_1 and [tau^i]_2 
        g1_powers.push(g1 * current_tau_pow);
        g2_powers.push(g2 * current_tau_pow);

        // Update power for next iteration: tau^{i+1}
        current_tau_pow *= tau;
    }

    let gt = ark_ec::pairing::Pairing::pairing(g1, g2);

    CRS {
        tau, 
        g1,
        g2,
        g1_powers,
        g2_powers,
        gt,
    }
}
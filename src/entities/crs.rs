use ark_bls12_381::{Bls12_381, G1Projective, G2Projective};
use ark_std::vec::Vec;
 
pub struct CRS {
    pub tau: ark_bls12_381::Fr,
    pub g1: G1Projective,
    pub g2: G2Projective,
    pub g1_powers: Vec<G1Projective>,
    pub g2_powers: Vec<G2Projective>,
    pub gt: ark_ec::pairing::PairingOutput<Bls12_381>,
}
use ark_bls12_381::{G1Projective, G2Projective};
use ark_std::vec::Vec;
use ark_std::Zero;
pub struct MasterPublicKey {
    pub c: G1Projective,
    pub u: G2Projective,
    pub u_list_1: Vec<G1Projective>,
    pub u_list_0: Vec<G1Projective>,
    pub u_eff: Vec<String>,
}

impl MasterPublicKey {
    pub fn new(c: G1Projective, u: G2Projective, u_list_1: Vec<G1Projective>, u_list_0: Vec<G1Projective>, u_eff: Vec<String>) -> Self {
        MasterPublicKey {
            c,
            u,
            u_list_1,
            u_list_0,
            u_eff,
        }
    }
    pub fn new_empty() -> Self {
        MasterPublicKey {
            c: G1Projective::zero(),
            u: G2Projective::zero(),
            u_list_1: vec![],
            u_list_0: vec![],
            u_eff: vec![],
        }
    }
    
}